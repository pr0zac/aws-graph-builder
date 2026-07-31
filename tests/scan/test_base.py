from __future__ import annotations

from pathlib import Path

import boto3
from moto import mock_aws

from aws_graph_builder.cache.store import CacheStore
from aws_graph_builder.scan.base import CachedClient


@mock_aws
def test_call_and_paginate_invoke_reporter(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    cache_store = CacheStore(tmp_path)
    messages: list[str] = []
    client = CachedClient(iam, cache_store, scope="global", service="iam", reporter=messages.append)

    client.call("list_saml_providers")
    client.paginate("get_account_authorization_details", ["UserDetailList"])

    assert "iam:list_saml_providers" in messages
    assert "iam:get_account_authorization_details (paginated)" in messages


@mock_aws
def test_call_includes_disambiguator_in_report(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    saml_metadata = (
        '<?xml version="1.0"?>'
        '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/saml">'
        '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing"></KeyDescriptor>'
        "</IDPSSODescriptor>"
        "<!-- padding " + ("x" * 900) + " -->"
        "</EntityDescriptor>"
    )
    provider_arn = iam.create_saml_provider(SAMLMetadataDocument=saml_metadata, Name="MySaml")["SAMLProviderArn"]

    cache_store = CacheStore(tmp_path)
    messages: list[str] = []
    client = CachedClient(iam, cache_store, scope="global", service="iam", reporter=messages.append)

    client.call("get_saml_provider", {"SAMLProviderArn": provider_arn}, disambiguator=provider_arn)

    assert f"iam:get_saml_provider ({provider_arn})" in messages


@mock_aws
def test_call_with_ignore_error_codes_suppresses_gap_but_still_caches(tmp_path: Path) -> None:
    """A real, common case: `lambda:GetPolicy` raises `ResourceNotFoundException`
    for the (very common) function with no resource policy at all -- that's a
    valid empty state, not a failure, and shouldn't clutter gap reporting.
    """
    lambda_client = boto3.client("lambda", region_name="us-east-1")
    cache_store = CacheStore(tmp_path)
    client = CachedClient(lambda_client, cache_store, scope="us-east-1", service="lambda")

    response = client.call(
        "get_policy",
        {"FunctionName": "does-not-exist"},
        ignore_error_codes=frozenset({"ResourceNotFoundException"}),
    )

    assert response is None
    assert client.gaps == []  # suppressed, not recorded as a gap

    cached = cache_store.get("us-east-1", "lambda", "get_policy")
    assert cached is not None
    assert cached.error is not None
    assert cached.error["code"] == "ResourceNotFoundException"


@mock_aws
def test_call_without_ignore_error_codes_still_records_gap_for_same_error(tmp_path: Path) -> None:
    """Confirm `ignore_error_codes` is opt-in per call -- omitting it keeps
    the existing gap-recording behavior for the exact same error.
    """
    lambda_client = boto3.client("lambda", region_name="us-east-1")
    cache_store = CacheStore(tmp_path)
    client = CachedClient(lambda_client, cache_store, scope="us-east-1", service="lambda")

    response = client.call("get_policy", {"FunctionName": "does-not-exist"})

    assert response is None
    assert len(client.gaps) == 1
    assert client.gaps[0].error_code == "ResourceNotFoundException"


@mock_aws
def test_report_is_a_no_op_without_a_configured_reporter(tmp_path: Path) -> None:
    """No `reporter` given (the default, non-verbose path) must not raise --
    `report()` calls throughout `call()`/`paginate()` should just no-op.
    """
    iam = boto3.client("iam", region_name="us-east-1")
    cache_store = CacheStore(tmp_path)
    client = CachedClient(iam, cache_store, scope="global", service="iam")

    client.report("this should be silently dropped")
    response = client.call("list_saml_providers")

    assert response is not None
