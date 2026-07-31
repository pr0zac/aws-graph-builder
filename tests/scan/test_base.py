from __future__ import annotations

from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws

from aws_graph_builder.cache.store import CacheEntry, CacheStore
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
def test_read_only_replays_cached_success_without_calling_aws(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_saml_provider(
        SAMLMetadataDocument=(
            '<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
            'entityID="https://example.com/saml"><IDPSSODescriptor '
            'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<KeyDescriptor use="signing"></KeyDescriptor></IDPSSODescriptor>'
            "<!-- padding " + ("x" * 900) + " --></EntityDescriptor>"
        ),
        Name="MySaml",
    )
    cache_store = CacheStore(tmp_path)
    live_client = CachedClient(iam, cache_store, scope="global", service="iam")
    live_response = live_client.call("list_saml_providers")
    assert live_response is not None

    # A `client=None` read_only CachedClient must be able to answer purely
    # from what the live client above already cached -- no AWS client
    # instance at all, matching `rebuild`'s "no credentials needed" design.
    replay_client = CachedClient(None, cache_store, scope="global", service="iam", read_only=True)
    replay_response = replay_client.call("list_saml_providers")

    assert replay_response is not None
    assert replay_client.gaps == []
    # Same data, modulo the documented cache asymmetry: live responses carry
    # real `datetime` objects, replayed responses carry the ISO strings the
    # cache round-tripped them through (cache/store.py deliberately doesn't
    # convert back -- see its module docstring).
    live_provider = live_response["SAMLProviderList"][0]
    replay_provider = replay_response["SAMLProviderList"][0]
    assert replay_provider["Arn"] == live_provider["Arn"]
    assert replay_provider["CreateDate"] == live_provider["CreateDate"].isoformat()


@mock_aws
def test_read_only_replays_cached_error_as_gap_not_credential_error(tmp_path: Path) -> None:
    """Even a cached error that was originally a credentials-expiry code
    must replay as an ordinary ScanGap, never a raised CredentialsExpiredError
    -- there's no live credential session to protect during cache replay.
    """
    cache_store = CacheStore(tmp_path)
    cache_store.put(
        "us-east-1",
        "lambda",
        "list_functions",
        CacheEntry(
            fetched_at="2026-01-01T00:00:00Z",
            operation="list_functions",
            params={},
            response=None,
            error={"code": "ExpiredToken", "message": "the security token included in the request is expired"},
        ),
    )
    replay_client = CachedClient(None, cache_store, scope="us-east-1", service="lambda", read_only=True)

    response = replay_client.call("list_functions")

    assert response is None
    assert len(replay_client.gaps) == 1
    assert replay_client.gaps[0].error_code == "ExpiredToken"


def test_read_only_missing_cache_entry_records_gap(tmp_path: Path) -> None:
    cache_store = CacheStore(tmp_path)
    replay_client = CachedClient(None, cache_store, scope="global", service="iam", read_only=True)

    response = replay_client.call("list_saml_providers")

    assert response is None
    assert len(replay_client.gaps) == 1
    assert replay_client.gaps[0].error_code == "NoCachedData"


def test_read_only_paginate_replays_cached_merged_result(tmp_path: Path) -> None:
    cache_store = CacheStore(tmp_path)
    cache_store.put(
        "global",
        "iam",
        "get_account_authorization_details",
        CacheEntry(
            fetched_at="2026-01-01T00:00:00Z",
            operation="get_account_authorization_details",
            params={},
            response={"UserDetailList": [{"UserName": "alice"}]},
            error=None,
        ),
    )
    replay_client = CachedClient(None, cache_store, scope="global", service="iam", read_only=True)

    response = replay_client.paginate("get_account_authorization_details", ["UserDetailList"])

    assert response == {"UserDetailList": [{"UserName": "alice"}]}
    assert replay_client.gaps == []


@mock_aws
def test_use_cache_returns_cached_value_without_calling_aws(tmp_path: Path) -> None:
    cache_store = CacheStore(tmp_path)
    cache_store.put(
        "global",
        "iam",
        "list_saml_providers",
        CacheEntry(
            fetched_at="2026-01-01T00:00:00Z",
            operation="list_saml_providers",
            params={},
            response={"SAMLProviderList": []},
            error=None,
        ),
    )

    class _ExplodingClient:
        def list_saml_providers(self, **kwargs: Any) -> None:
            raise AssertionError("use_cache should not have called the live client on a cache hit")

    client = CachedClient(_ExplodingClient(), cache_store, scope="global", service="iam", use_cache=True)

    response = client.call("list_saml_providers")

    assert response == {"SAMLProviderList": []}
    assert client.gaps == []


@mock_aws
def test_use_cache_falls_through_to_live_call_on_miss(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    cache_store = CacheStore(tmp_path)
    client = CachedClient(iam, cache_store, scope="global", service="iam", use_cache=True)

    response = client.call("list_saml_providers")

    assert response is not None  # real moto response, live call was made
    cached = cache_store.get("global", "iam", "list_saml_providers")
    assert cached is not None  # and it got cached normally, like a plain live call


@mock_aws
def test_use_cache_replays_cached_error_as_gap_not_raised(tmp_path: Path) -> None:
    """A stale cached expiry error must not abort a `--use-cache` resume --
    the current live session's credentials may be perfectly fine now.
    """
    cache_store = CacheStore(tmp_path)
    cache_store.put(
        "global",
        "iam",
        "list_saml_providers",
        CacheEntry(
            fetched_at="2026-01-01T00:00:00Z",
            operation="list_saml_providers",
            params={},
            response=None,
            error={"code": "ExpiredToken", "message": "stale cached expiry"},
        ),
    )
    iam = boto3.client("iam", region_name="us-east-1")
    client = CachedClient(iam, cache_store, scope="global", service="iam", use_cache=True)

    response = client.call("list_saml_providers")

    assert response is None
    assert len(client.gaps) == 1
    assert client.gaps[0].error_code == "ExpiredToken"


@pytest.mark.parametrize("mode_kwargs", [{"read_only": True}, {"use_cache": True}])
def test_replay_modes_respect_ignore_error_codes(tmp_path: Path, mode_kwargs: dict[str, bool]) -> None:
    cache_store = CacheStore(tmp_path)
    cache_store.put(
        "us-east-1",
        "lambda",
        "get_policy",
        CacheEntry(
            fetched_at="2026-01-01T00:00:00Z",
            operation="get_policy",
            params={},
            response=None,
            error={"code": "ResourceNotFoundException", "message": "no policy"},
        ),
        disambiguator="my-function",
    )
    client = CachedClient(None, cache_store, scope="us-east-1", service="lambda", **mode_kwargs)

    response = client.call(
        "get_policy",
        disambiguator="my-function",
        ignore_error_codes=frozenset({"ResourceNotFoundException"}),
    )

    assert response is None
    assert client.gaps == []


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
