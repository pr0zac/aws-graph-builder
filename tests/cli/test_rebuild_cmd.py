from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import boto3
from moto import mock_aws
from typer.testing import CliRunner

from aws_graph_builder.cli.app import app

runner = CliRunner()

PERM_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _build_fixture(iam: Any) -> None:
    iam.create_group(GroupName="admins")
    iam.create_user(UserName="alice")
    iam.add_user_to_group(GroupName="admins", UserName="alice")

    policy = iam.create_policy(PolicyName="CustomPolicy", PolicyDocument=json.dumps(PERM_DOC))
    iam.attach_user_policy(UserName="alice", PolicyArn=policy["Policy"]["Arn"])

    iam.create_role(RoleName="deploy-role", AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))


@mock_aws
def test_rebuild_reproduces_scan_output_with_zero_aws_calls(tmp_path: Path, monkeypatch: Any) -> None:
    """The real end-to-end proof: `scan` populates a cache under mocked AWS,
    then `rebuild` is invoked with `botocore`'s API-call path itself blocked
    (not just un-mocked) -- if `rebuild` reached AWS at all, this would raise.
    """
    iam = boto3.client("iam", region_name="us-east-1")
    _build_fixture(iam)
    account_id = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]

    scan_output = tmp_path / "graph.json"
    cache_dir = tmp_path / "cache"

    scan_result = runner.invoke(
        app,
        [
            "scan",
            "--output",
            str(scan_output),
            "--cache-dir",
            str(cache_dir),
            "--region",
            "us-east-1",
            "--regions",
            "us-east-1",
        ],
    )
    assert scan_result.exit_code == 0, scan_result.output
    scan_document = json.loads(scan_output.read_text())

    # Block every botocore API call at the source -- if `rebuild` ever tried
    # to reach AWS, this makes the test fail loudly instead of silently
    # succeeding against the still-active moto mock.
    import botocore.client

    def blocked_make_api_call(self: Any, operation_name: str, kwargs: Any) -> Any:
        raise AssertionError(f"rebuild must never make a live AWS call, but tried: {operation_name}")

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", blocked_make_api_call)

    rebuild_output = tmp_path / "rebuilt.json"
    rebuild_result = runner.invoke(
        app,
        [
            "rebuild",
            "--account-id",
            account_id,
            "--output",
            str(rebuild_output),
            "--cache-dir",
            str(cache_dir),
        ],
    )

    assert rebuild_result.exit_code == 0, rebuild_result.output
    assert "Rebuild complete" in rebuild_result.output

    rebuild_document = json.loads(rebuild_output.read_text())
    assert rebuild_document["account_id"] == scan_document["account_id"]
    assert rebuild_document["regions_scanned"] == scan_document["regions_scanned"]
    assert len(rebuild_document["nodes"]) == len(scan_document["nodes"])
    assert len(rebuild_document["edges"]) == len(scan_document["edges"])
    assert len(rebuild_document["findings"]) == len(scan_document["findings"])
    assert {n["id"] for n in rebuild_document["nodes"]} == {n["id"] for n in scan_document["nodes"]}

    # The companion report also gets written by rebuild, same as scan.
    report_path = rebuild_output.with_name("rebuilt.report.json")
    assert report_path.exists()
    report = json.loads(report_path.read_text())
    assert report["account_id"] == account_id
    assert report["gaps"] == []


def test_rebuild_exits_cleanly_when_no_cache_exists(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "rebuild",
            "--account-id",
            "123456789012",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output",
            str(tmp_path / "graph.json"),
        ],
    )

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "no cache found" in result.output.lower()
    assert not (tmp_path / "graph.json").exists()


def test_rebuild_records_gap_for_a_never_scanned_operation(tmp_path: Path) -> None:
    """A cache directory that exists but is missing an expected entry (e.g.
    an interrupted scan) should surface as a NoCachedData gap, not crash.
    """
    account_id = "123456789012"
    cache_root = tmp_path / "cache" / account_id
    cache_root.mkdir(parents=True)
    # No IAM cache files at all -- get_account_authorization_details etc.
    # were simply never scanned into this cache.

    result = runner.invoke(
        app,
        [
            "rebuild",
            "--account-id",
            account_id,
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output",
            str(tmp_path / "graph.json"),
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads((tmp_path / "graph.json").read_text())
    # Only the Account node exists -- nothing else was ever scanned.
    assert len(document["nodes"]) == 1
    assert document["nodes"][0]["type"] == "Account"

    report = json.loads((tmp_path / "graph.report.json").read_text())
    assert report["gaps"]
    assert any(gap["error_code"] == "NoCachedData" for gap in report["gaps"])


@mock_aws
def test_rebuild_verbose_reports_replayed_calls(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    _build_fixture(iam)
    account_id = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]

    cache_dir = tmp_path / "cache"
    scan_result = runner.invoke(
        app,
        [
            "scan",
            "--output",
            str(tmp_path / "graph.json"),
            "--cache-dir",
            str(cache_dir),
            "--region",
            "us-east-1",
            "--regions",
            "us-east-1",
        ],
    )
    assert scan_result.exit_code == 0, scan_result.output

    rebuild_result = runner.invoke(
        app,
        [
            "rebuild",
            "--account-id",
            account_id,
            "--output",
            str(tmp_path / "rebuilt.json"),
            "--cache-dir",
            str(cache_dir),
            "--verbose",
        ],
    )

    assert rebuild_result.exit_code == 0, rebuild_result.output
    assert "Rebuilding from cache" in rebuild_result.output
    assert "iam:get_account_authorization_details" in rebuild_result.output
    assert "Building graph from cached scan results" in rebuild_result.output
