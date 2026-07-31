from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from aws_graph_builder.cache.store import CacheEntry, CacheStore


def make_entry(**overrides: object) -> CacheEntry:
    defaults: dict[str, object] = {
        "fetched_at": "2026-07-31T20:00:00+00:00",
        "operation": "get_account_authorization_details",
        "params": {},
        "response": {"Users": []},
        "error": None,
    }
    defaults.update(overrides)
    return CacheEntry(**defaults)  # type: ignore[arg-type]


def test_put_then_get_round_trip_global(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    entry = make_entry()

    store.put("global", "iam", "get_account_authorization_details", entry)
    result = store.get("global", "iam", "get_account_authorization_details")

    assert result == entry


def test_put_then_get_round_trip_region(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    entry = make_entry(operation="describe_instances", response={"Reservations": []})

    store.put("us-east-1", "ec2", "describe_instances", entry)
    result = store.get("us-east-1", "ec2", "describe_instances")

    assert result == entry


def test_global_scope_file_layout(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    entry = make_entry()

    store.put("global", "iam", "get_account_authorization_details", entry)

    expected_path = (
        tmp_path / "global" / "iam" / "get_account_authorization_details.json"
    )
    assert expected_path.exists()


def test_region_scope_file_layout(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    entry = make_entry(operation="describe_instances")

    store.put("us-west-2", "ec2", "describe_instances", entry)

    expected_path = tmp_path / "regions" / "us-west-2" / "ec2" / "describe_instances.json"
    assert expected_path.exists()


def test_disambiguator_produces_expected_path(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    entry = make_entry(operation="get_bucket_policy", response={"Policy": "{}"})

    store.put("global", "s3", "get_bucket_policy", entry, disambiguator="my-bucket")

    expected_path = tmp_path / "global" / "s3" / "get_bucket_policy__my-bucket.json"
    assert expected_path.exists()

    result = store.get("global", "s3", "get_bucket_policy", disambiguator="my-bucket")
    assert result == entry


def test_get_missing_key_returns_none(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)

    result = store.get("global", "iam", "get_account_authorization_details")

    assert result is None


def test_get_missing_key_with_disambiguator_returns_none(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)

    result = store.get("global", "s3", "get_bucket_policy", disambiguator="nope")

    assert result is None


def test_get_corrupt_json_raises(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    path = tmp_path / "global" / "iam" / "get_account_authorization_details.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not valid json")

    with pytest.raises(ValueError, match="invalid JSON"):
        store.get("global", "iam", "get_account_authorization_details")


def test_datetime_in_response_serializes_without_raising(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    fetched = datetime(2026, 7, 31, 20, 0, 0, tzinfo=UTC)
    entry = make_entry(
        response={"CreateDate": fetched, "Users": [{"CreateDate": fetched}]},
    )

    store.put("global", "iam", "get_account_authorization_details", entry)
    result = store.get("global", "iam", "get_account_authorization_details")

    assert result is not None
    assert result.response is not None
    # Deserialization does NOT convert ISO strings back to datetimes -- they
    # stay as plain strings, since cached JSON is meant to be inspected/
    # rebuilt-from as JSON, not round-tripped into live boto3-typed objects.
    assert result.response["CreateDate"] == fetched.isoformat()
    assert isinstance(result.response["CreateDate"], str)


def test_datetime_in_params_serializes_without_raising(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    marker = datetime(2026, 1, 1, tzinfo=UTC)
    entry = make_entry(params={"Marker": marker}, response=None)

    store.put("global", "iam", "get_account_authorization_details", entry)
    result = store.get("global", "iam", "get_account_authorization_details")

    assert result is not None
    assert result.params["Marker"] == marker.isoformat()


def test_error_entry_round_trip(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    entry = make_entry(
        operation="get_bucket_policy",
        response=None,
        error={"code": "AccessDenied", "message": "not authorized"},
    )

    store.put("global", "s3", "get_bucket_policy", entry, disambiguator="locked-bucket")
    result = store.get("global", "s3", "get_bucket_policy", disambiguator="locked-bucket")

    assert result == entry
    assert result is not None
    assert result.response is None
    assert result.error == {"code": "AccessDenied", "message": "not authorized"}


def test_manifest_read_returns_none_when_absent(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)

    assert store.read_manifest() is None


def test_manifest_write_then_read_round_trip(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    manifest = {
        "tool_version": "0.1.0",
        "caller_identity_arn": "arn:aws:iam::111111111111:user/alice",
        "generated_at": "2026-07-31T20:00:00+00:00",
        "regions": ["us-east-1", "us-west-2"],
    }

    store.write_manifest(manifest)
    result = store.read_manifest()

    assert result == manifest


def test_manifest_stored_at_root(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)

    store.write_manifest({"tool_version": "0.1.0"})

    assert (tmp_path / "manifest.json").exists()


def test_manifest_corrupt_json_raises(tmp_path: Path) -> None:
    store = CacheStore(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "manifest.json").write_text("{not valid json")

    with pytest.raises(ValueError, match="invalid JSON"):
        store.read_manifest()
