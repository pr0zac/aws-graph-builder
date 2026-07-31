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
from aws_graph_builder.scan.s3 import S3Scanner, S3ScanResult

BUCKET_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::policy-bucket/*",
        }
    ],
}


def _client_error(code: str, message: str = "boom", operation: str = "ListBuckets") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def _make_scanner(s3: Any, tmp_path: Path) -> tuple[S3Scanner, CachedClient]:
    cache_store = CacheStore(tmp_path)
    cached_client = CachedClient(s3, cache_store, scope="global", service="s3")
    return S3Scanner(cached_client), cached_client


@mock_aws
def test_scan_reflects_created_buckets_location_policy_and_acl(tmp_path: Path) -> None:
    s3 = boto3.client("s3", region_name="us-east-1")

    # Bucket in us-east-1 (the AWS quirk case), no explicit bucket policy.
    s3.create_bucket(Bucket="plain-bucket")

    # Bucket with an explicit bucket policy attached.
    s3.create_bucket(Bucket="policy-bucket")
    s3.put_bucket_policy(Bucket="policy-bucket", Policy=json.dumps(BUCKET_POLICY))

    scanner, _ = _make_scanner(s3, tmp_path)

    result = scanner.scan()

    assert isinstance(result, S3ScanResult)
    assert result.gaps == []

    bucket_names = {b["Name"] for b in result.buckets}
    assert bucket_names == {"plain-bucket", "policy-bucket"}

    # us-east-1 quirk: LocationConstraint comes back None/empty for
    # us-east-1 buckets -- must be normalized to the literal string.
    assert result.bucket_locations["plain-bucket"] == "us-east-1"
    assert result.bucket_locations["policy-bucket"] == "us-east-1"

    # No explicit policy -> NoSuchBucketPolicy is ignored, collapses to None.
    assert result.bucket_policies["plain-bucket"] is None
    # Explicit policy -> parsed JSON document.
    assert result.bucket_policies["policy-bucket"] == BUCKET_POLICY

    # Every bucket always has an ACL (defaults to private-owner-only).
    assert result.bucket_acls["plain-bucket"] is not None
    assert "Owner" in result.bucket_acls["plain-bucket"]
    assert "Grants" in result.bucket_acls["plain-bucket"]
    assert result.bucket_acls["policy-bucket"] is not None
    assert "Owner" in result.bucket_acls["policy-bucket"]


@mock_aws
def test_scan_records_gap_and_returns_empty_buckets_on_access_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="some-bucket")
    scanner, cached_client = _make_scanner(s3, tmp_path)

    def raise_access_denied(**kwargs: Any) -> None:
        raise _client_error("AccessDenied", "not authorized", operation="ListBuckets")

    monkeypatch.setattr(s3, "list_buckets", raise_access_denied)

    result = scanner.scan()

    assert result.buckets == []
    assert result.bucket_locations == {}
    assert result.bucket_policies == {}
    assert result.bucket_acls == {}
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.service == "s3"
    assert gap.operation == "list_buckets"
    assert gap.scope == "global"
    assert gap.error_code == "AccessDenied"

    cached = cached_client._cache_store.get("global", "s3", "list_buckets")
    assert cached is not None
    assert cached.error == {"code": "AccessDenied", "message": "not authorized"}
