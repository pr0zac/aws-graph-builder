from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from aws_graph_builder.cache.store import CacheStore
from aws_graph_builder.scan.base import CachedClient
from aws_graph_builder.scan.lambda_ import LambdaScanner, LambdaScanResult

LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}

RESOURCE_POLICY_STATEMENT = {
    "Sid": "AllowInvoke",
    "Effect": "Allow",
    "Principal": {"Service": "s3.amazonaws.com"},
    "Action": "lambda:InvokeFunction",
}


def _client_error(code: str, message: str = "boom", operation: str = "SomeOperation") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def _zip_bytes() -> bytes:
    handler_source = "def lambda_handler(event, context):\n    return event\n"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("lambda_function.py", handler_source)
    return buffer.getvalue()


def _build_fixture(lambda_client: Any) -> dict[str, str]:
    """Creates, via real boto3 calls against moto: an IAM execution role
    (moto's Lambda backend requires the role to actually exist in IAM, not
    just be a plausibly-shaped ARN) and two Lambda functions using it -- one
    with a resource policy attached (via `add_permission`) and one without,
    so the scanner's `get_policy`/`ResourceNotFoundException` handling is
    exercised against a real moto-generated error rather than a hand-mocked
    one.
    """
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(RoleName="lambda-role", AssumeRolePolicyDocument=json.dumps(LAMBDA_TRUST_POLICY))
    role_arn = role["Role"]["Arn"]

    code = {"ZipFile": _zip_bytes()}

    with_policy = lambda_client.create_function(
        FunctionName="with-policy",
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.lambda_handler",
        Code=code,
        Publish=True,
    )
    lambda_client.add_permission(
        FunctionName="with-policy",
        StatementId=RESOURCE_POLICY_STATEMENT["Sid"],
        Action=RESOURCE_POLICY_STATEMENT["Action"],
        Principal=RESOURCE_POLICY_STATEMENT["Principal"]["Service"],
    )

    without_policy = lambda_client.create_function(
        FunctionName="without-policy",
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.lambda_handler",
        Code=code,
        Publish=True,
    )

    return {
        "role_arn": role_arn,
        "with_policy_arn": with_policy["FunctionArn"],
        "without_policy_arn": without_policy["FunctionArn"],
    }


def _make_scanner(lambda_client: Any, tmp_path: Path, region: str = "us-east-1") -> tuple[LambdaScanner, CachedClient]:
    cache_store = CacheStore(tmp_path)
    cached_client = CachedClient(lambda_client, cache_store, scope=region, service="lambda")
    return LambdaScanner(cached_client, region=region), cached_client


@mock_aws
def test_scan_reflects_created_lambda_fixtures_and_resource_policies(tmp_path: Path) -> None:
    lambda_client = boto3.client("lambda", region_name="us-east-1")
    arns = _build_fixture(lambda_client)
    scanner, _ = _make_scanner(lambda_client, tmp_path)

    result = scanner.scan()

    assert isinstance(result, LambdaScanResult)
    assert result.region == "us-east-1"
    assert result.gaps == []

    assert len(result.functions) == 2
    function_names = {f["FunctionName"] for f in result.functions}
    assert function_names == {"with-policy", "without-policy"}
    for function in result.functions:
        assert function["Role"] == arns["role_arn"]
        assert "FunctionArn" in function

    with_policy_doc = result.resource_policies[arns["with_policy_arn"]]
    assert with_policy_doc is not None
    assert isinstance(with_policy_doc, dict)
    statement_sids = {s["Sid"] for s in with_policy_doc["Statement"]}
    assert RESOURCE_POLICY_STATEMENT["Sid"] in statement_sids

    assert result.resource_policies[arns["without_policy_arn"]] is None


@mock_aws
def test_scan_records_gap_and_continues_on_access_denied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lambda_client = boto3.client("lambda", region_name="us-east-1")
    _build_fixture(lambda_client)
    scanner, cached_client = _make_scanner(lambda_client, tmp_path)

    def raise_access_denied(**kwargs: Any) -> None:
        raise _client_error("AccessDenied", "not authorized", operation="ListFunctions")

    monkeypatch.setattr(lambda_client, "list_functions", raise_access_denied)

    result = scanner.scan()

    assert result.functions == []
    assert result.resource_policies == {}
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.service == "lambda"
    assert gap.operation == "list_functions"
    assert gap.scope == "us-east-1"
    assert gap.error_code == "AccessDenied"

    cached = cached_client._cache_store.get("us-east-1", "lambda", "list_functions")
    assert cached is not None
    assert cached.error == {"code": "AccessDenied", "message": "not authorized"}
