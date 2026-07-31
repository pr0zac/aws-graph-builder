from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws

from aws_graph_builder.cache.store import CacheStore
from aws_graph_builder.scan.base import CachedClient
from aws_graph_builder.scan.organizations import (
    OrganizationsScanner,
    OrganizationsScanResult,
)

SCP_DOCUMENT = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def _make_scanner(client: Any, tmp_path: Path, *, account_id: str) -> tuple[OrganizationsScanner, CachedClient]:
    cache_store = CacheStore(tmp_path)
    cached_client = CachedClient(client, cache_store, scope="global", service="organizations")
    return OrganizationsScanner(cached_client, account_id=account_id), cached_client


@mock_aws
def test_scan_skips_gracefully_when_not_in_an_organization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """moto's default behaviour (no `create_organization()` call) is to raise
    `AWSOrganizationsNotInUseException` from `describe_organization` -- the
    same real AWS behaviour a non-Organization account would produce.
    """
    org = boto3.client("organizations", region_name="us-east-1")
    scanner, cached_client = _make_scanner(org, tmp_path, account_id="123456789012")

    calls_made = []
    real_get_paginator = org.get_paginator

    def spy_get_paginator(operation_name: str, *args: Any, **kwargs: Any) -> Any:
        calls_made.append(operation_name)
        return real_get_paginator(operation_name, *args, **kwargs)

    monkeypatch.setattr(org, "get_paginator", spy_get_paginator)

    result = scanner.scan()

    assert isinstance(result, OrganizationsScanResult)
    assert result.in_organization is False
    assert result.policies == []
    assert result.policy_documents == {}
    # The ignored error code produces no gap, and list_policies_for_target is
    # never even attempted.
    assert result.gaps == []
    assert cached_client.gaps == []
    assert calls_made == []

    cached = cached_client._cache_store.get("global", "organizations", "describe_organization")
    assert cached is not None
    assert cached.error == {
        "code": "AWSOrganizationsNotInUseException",
        "message": "Your account is not a member of an organization.",
    }


@mock_aws
def test_scan_fetches_scps_when_in_an_organization(tmp_path: Path) -> None:
    org = boto3.client("organizations", region_name="us-east-1")
    created = org.create_organization(FeatureSet="ALL")
    account_id = created["Organization"]["MasterAccountId"]

    policy = org.create_policy(
        Content=json.dumps(SCP_DOCUMENT),
        Description="test scp",
        Name="TestSCP",
        Type="SERVICE_CONTROL_POLICY",
    )
    policy_id = policy["Policy"]["PolicySummary"]["Id"]
    org.attach_policy(PolicyId=policy_id, TargetId=account_id)

    scanner, _ = _make_scanner(org, tmp_path, account_id=account_id)

    result = scanner.scan()

    assert result.in_organization is True
    assert result.gaps == []

    policy_ids = {p["Id"] for p in result.policies}
    assert policy_id in policy_ids
    matching = next(p for p in result.policies if p["Id"] == policy_id)
    assert matching["Name"] == "TestSCP"
    assert matching["Type"] == "SERVICE_CONTROL_POLICY"

    assert result.policy_documents[policy_id] == SCP_DOCUMENT
