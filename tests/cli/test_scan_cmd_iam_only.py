from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import boto3
import botocore.client
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from typer.testing import CliRunner

from aws_graph_builder.cli.app import app
from aws_graph_builder.session import NoCredentialsFoundError

runner = CliRunner()

PERM_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _build_fixture(iam: Any) -> None:
    """Minimal IAM fixture: a user in a group with an attached managed
    policy, and a role -- enough to exercise the full scan -> graph -> export
    path with real node/edge data.
    """
    iam.create_group(GroupName="admins")
    iam.create_user(UserName="alice")
    iam.add_user_to_group(GroupName="admins", UserName="alice")

    policy = iam.create_policy(PolicyName="CustomPolicy", PolicyDocument=json.dumps(PERM_DOC))
    iam.attach_user_policy(UserName="alice", PolicyArn=policy["Policy"]["Arn"])

    iam.create_role(RoleName="deploy-role", AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))


@mock_aws
def test_scan_writes_graph_document_and_cache_files(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    _build_fixture(iam)
    account_id = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]

    output_path = tmp_path / "graph.json"
    cache_dir = tmp_path / "cache"

    result = runner.invoke(
        app,
        [
            "scan",
            "--output",
            str(output_path),
            "--cache-dir",
            str(cache_dir),
            "--region",
            "us-east-1",
            "--regions",
            "us-east-1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Scan complete" in result.output

    assert output_path.exists()
    document = json.loads(output_path.read_text())

    assert document["account_id"] == account_id
    assert document["regions_scanned"] == ["us-east-1"]
    assert "nodes" in document
    assert "edges" in document

    node_names_by_type: dict[str, set[str]] = {}
    for node in document["nodes"]:
        node_names_by_type.setdefault(node["type"], set()).add(node["name"])

    assert "alice" in node_names_by_type.get("IamUser", set())
    assert "admins" in node_names_by_type.get("IamGroup", set())
    assert "deploy-role" in node_names_by_type.get("IamRole", set())
    # moto's GetAccountAuthorizationDetails omits `PolicyName` from the
    # `Policies` list, so the builder falls back to the ARN as the node name
    # -- confirm the customer-managed policy node is present via its
    # properties instead of asserting on the (moto-dependent) name.
    managed_policy_nodes = [n for n in document["nodes"] if n["type"] == "ManagedPolicy"]
    assert any(n["properties"].get("managed_by") == "customer" for n in managed_policy_nodes)

    edge_types = {edge["type"] for edge in document["edges"]}
    assert "MemberOf" in edge_types
    assert "AttachedPolicy" in edge_types

    # Cache files were actually written under <cache-dir>/<account_id>/global/iam/.
    cache_iam_dir = cache_dir / account_id / "global" / "iam"
    assert cache_iam_dir.is_dir()
    cached_files = list(cache_iam_dir.glob("*.json"))
    assert cached_files, "expected cache files to be written under the iam cache dir"
    assert any("get_account_authorization_details" in f.name for f in cached_files)


@mock_aws
def test_scan_reports_gaps_without_failing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    _build_fixture(iam)

    # The CLI builds its own boto3 client internally (from its own session),
    # so monkeypatching a method on this test's `iam` client instance
    # wouldn't affect it -- patch `BaseClient._make_api_call` instead, which
    # every client instance for every service routes through.
    original_make_api_call = botocore.client.BaseClient._make_api_call

    def patched_make_api_call(self: Any, operation_name: str, kwargs: Any) -> Any:
        if operation_name == "ListSAMLProviders":
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, operation_name
            )
        return original_make_api_call(self, operation_name, kwargs)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", patched_make_api_call)

    output_path = tmp_path / "graph.json"
    cache_dir = tmp_path / "cache"

    result = runner.invoke(
        app,
        [
            "scan",
            "--output",
            str(output_path),
            "--cache-dir",
            str(cache_dir),
            "--region",
            "us-east-1",
            "--regions",
            "us-east-1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_path.exists()
    # The gap warning should be surfaced somewhere in the CLI output, and the
    # rest of the scan should have still succeeded.
    assert "AccessDenied" in result.output
    document = json.loads(output_path.read_text())
    assert any(n["type"] == "IamUser" for n in document["nodes"])


@mock_aws
def test_scan_verbose_reports_calls_and_findings(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    _build_fixture(iam)

    result = runner.invoke(
        app,
        [
            "scan",
            "--output",
            str(tmp_path / "graph.json"),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--region",
            "us-east-1",
            "--regions",
            "us-east-1",
            "--verbose",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Authenticated as" in result.output
    assert "iam:get_account_authorization_details" in result.output
    assert "found 1 user(s), 1 group(s), 1 role(s)" in result.output
    assert "iam:list_saml_providers" in result.output
    assert "found 0 SAML provider(s)" in result.output
    assert "Building graph from scan results" in result.output


@mock_aws
def test_scan_without_verbose_omits_progress_output(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    _build_fixture(iam)

    result = runner.invoke(
        app,
        [
            "scan",
            "--output",
            str(tmp_path / "graph.json"),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--region",
            "us-east-1",
            "--regions",
            "us-east-1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "iam:get_account_authorization_details" not in result.output
    assert "Authenticated as" not in result.output


def test_scan_exits_cleanly_on_credential_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A credential-validation failure should exit non-zero with a clean
    message, never a raw traceback reaching the user.
    """

    def raise_no_credentials(session: Any) -> Any:
        raise NoCredentialsFoundError("No AWS credentials found.")

    monkeypatch.setattr("aws_graph_builder.cli.scan_cmd.validate_credentials", raise_no_credentials)

    result = runner.invoke(
        app,
        [
            "scan",
            "--output",
            str(tmp_path / "graph.json"),
            "--cache-dir",
            str(tmp_path / "cache"),
        ],
    )

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "No AWS credentials found" in result.output
    assert not (tmp_path / "graph.json").exists()
