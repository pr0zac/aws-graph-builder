from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from aws_graph_builder.cache.store import CacheStore
from aws_graph_builder.scan.base import CachedClient
from aws_graph_builder.scan.ec2 import Ec2Scanner, Ec2ScanResult

REGION = "us-east-1"
AMI_ID = "ami-12345678"

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _client_error(code: str, message: str = "boom", operation: str = "DescribeInstances") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def _make_scanner(ec2: Any, tmp_path: Path) -> tuple[Ec2Scanner, CachedClient]:
    cache_store = CacheStore(tmp_path)
    cached_client = CachedClient(ec2, cache_store, scope=REGION, service="ec2")
    return Ec2Scanner(cached_client, region=REGION), cached_client


@mock_aws
def test_scan_flattens_reservations_and_reflects_instance_profile(tmp_path: Path) -> None:
    ec2 = boto3.client("ec2", region_name=REGION)
    iam = boto3.client("iam", region_name=REGION)

    iam.create_role(RoleName="ec2-role", AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))
    profile = iam.create_instance_profile(InstanceProfileName="ec2-profile")
    profile_arn = profile["InstanceProfile"]["Arn"]
    iam.add_role_to_instance_profile(InstanceProfileName="ec2-profile", RoleName="ec2-role")

    with_profile = ec2.run_instances(
        ImageId=AMI_ID,
        MinCount=1,
        MaxCount=1,
        IamInstanceProfile={"Arn": profile_arn},
    )
    with_profile_id = with_profile["Instances"][0]["InstanceId"]

    without_profile = ec2.run_instances(ImageId=AMI_ID, MinCount=1, MaxCount=1)
    without_profile_id = without_profile["Instances"][0]["InstanceId"]

    scanner, _ = _make_scanner(ec2, tmp_path)

    result = scanner.scan()

    assert isinstance(result, Ec2ScanResult)
    assert result.region == REGION
    assert result.gaps == []

    instance_ids = {i["InstanceId"] for i in result.instances}
    assert instance_ids == {with_profile_id, without_profile_id}

    instance_with_profile = next(i for i in result.instances if i["InstanceId"] == with_profile_id)
    assert instance_with_profile["IamInstanceProfile"]["Arn"] == profile_arn

    instance_without_profile = next(i for i in result.instances if i["InstanceId"] == without_profile_id)
    assert "IamInstanceProfile" not in instance_without_profile


@mock_aws
def test_scan_records_gap_and_continues_on_access_denied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ec2 = boto3.client("ec2", region_name=REGION)
    ec2.run_instances(ImageId=AMI_ID, MinCount=1, MaxCount=1)
    scanner, cached_client = _make_scanner(ec2, tmp_path)

    def raise_access_denied(**kwargs: Any) -> None:
        raise _client_error("AccessDenied", "not authorized", operation="DescribeInstances")

    monkeypatch.setattr(ec2, "describe_instances", raise_access_denied)

    result = scanner.scan()

    assert result.instances == []
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.service == "ec2"
    assert gap.operation == "describe_instances"
    assert gap.scope == REGION
    assert gap.error_code == "AccessDenied"

    cached = cached_client._cache_store.get(REGION, "ec2", "describe_instances")
    assert cached is not None
    assert cached.error == {"code": "AccessDenied", "message": "not authorized"}
