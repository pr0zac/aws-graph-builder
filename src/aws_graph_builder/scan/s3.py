"""S3 scanner: fetches raw bucket inventory via `s3:ListAllMyBuckets` plus each
bucket's location, bucket policy, and ACL.

Global-scoped -- bucket listing is account/partition-level, not region-scoped,
so a separate caller constructs one `CachedClient`/one `S3Scanner` for this,
scope `"global"`. Although `aws-graph-builder.md` phrases per-bucket calls as
"per-bucket region", this scanner calls every operation (including
`GetBucketLocation`/`GetBucketPolicy`/`GetBucketAcl`) through a single global
S3 client rather than constructing per-bucket regional clients -- these
particular read calls work correctly against any regional S3 endpoint for an
existing bucket regardless of where the bucket actually lives, so a single
global client keeps this scanner simple without sacrificing correctness.

`S3ScanResult.buckets` holds raw boto3 `Bucket` dicts exactly as AWS returns
them (PascalCase keys, e.g. `Name`, `CreationDate`) -- no renaming or
filtering -- so `graph.builder` works directly against real, well-documented
AWS API response shapes rather than an invented intermediate format.

Note the real, documented AWS API/IAM-action-naming mismatch: the boto3
*client method* for listing buckets is `list_buckets`, but the corresponding
*IAM action name* is `s3:ListAllMyBuckets` -- `required_actions()` reports the
latter (it feeds the `permissions` CLI command's generated least-privilege
policy, so it must be the real IAM action name) while `scan()` still calls
`self._client.call("list_buckets")` (the real boto3 method name).

`GetBucketPolicyStatus`/`GetPublicAccessBlock` are explicitly out of scope
here (per `aws-graph-builder.md`, they're a phase-2/exposure-analysis
concern, not this scanner's job).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aws_graph_builder.scan.base import CachedClient, ScanGap, Scanner

SERVICE = "s3"
SCOPE = "global"

_IGNORED_GET_BUCKET_POLICY_ERRORS = frozenset({"NoSuchBucketPolicy"})


@dataclass
class S3ScanResult:
    buckets: list[dict[str, Any]] = field(default_factory=list)
    # Keyed by bucket Name; value is the region string from
    # GetBucketLocation's LocationConstraint, normalized (see
    # _normalize_location) so us-east-1 buckets -- which AWS reports as a
    # None/empty LocationConstraint -- read as the literal string
    # "us-east-1" rather than that quirk leaking into callers.
    bucket_locations: dict[str, str] = field(default_factory=dict)
    # Keyed by bucket Name; value is the parsed policy document, or None if
    # the bucket has no explicit bucket policy (or the GetBucketPolicy call
    # failed for some other reason -- both cases collapse to None here, and a
    # genuine denial is still recorded as a ScanGap via self._client.gaps).
    bucket_policies: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    # Keyed by bucket Name; value is the raw GetBucketAcl response (Owner +
    # Grants), or None if that specific call failed/was denied -- unlike
    # bucket policies, every bucket always has an ACL, so a failure here is a
    # genuine gap, not an expected empty state.
    bucket_acls: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    gaps: list[ScanGap] = field(default_factory=list)


class S3Scanner(Scanner):
    """Scans S3 buckets and their location/policy/ACL for a single account.
    Global-scoped -- bucket listing and the per-bucket read calls used here
    all work through a single global client regardless of bucket region.
    """

    def __init__(self, client: CachedClient) -> None:
        self._client = client

    @staticmethod
    def required_actions() -> list[str]:
        return [
            "s3:ListAllMyBuckets",
            "s3:GetBucketLocation",
            "s3:GetBucketPolicy",
            "s3:GetBucketAcl",
        ]

    def scan(self) -> S3ScanResult:
        self._client.report("Fetching S3 buckets...")
        list_response = self._client.call("list_buckets")
        buckets = list_response.get("Buckets", []) if list_response else []
        self._client.report(f"  found {len(buckets)} bucket(s)")

        bucket_locations = self._scan_bucket_locations(buckets)
        bucket_policies = self._scan_bucket_policies(buckets)
        bucket_acls = self._scan_bucket_acls(buckets)

        return S3ScanResult(
            buckets=buckets,
            bucket_locations=bucket_locations,
            bucket_policies=bucket_policies,
            bucket_acls=bucket_acls,
            # `self._client.gaps` accumulates across every call made above --
            # collect it once at the end rather than threading a list through.
            gaps=list(self._client.gaps),
        )

    def _scan_bucket_locations(self, buckets: list[dict[str, Any]]) -> dict[str, str]:
        bucket_locations: dict[str, str] = {}
        for bucket in buckets:
            name = bucket["Name"]
            response = self._client.call("get_bucket_location", {"Bucket": name}, disambiguator=name)
            if response is None:
                continue
            bucket_locations[name] = _normalize_location(response.get("LocationConstraint"))
        return bucket_locations

    def _scan_bucket_policies(self, buckets: list[dict[str, Any]]) -> dict[str, dict[str, Any] | None]:
        bucket_policies: dict[str, dict[str, Any] | None] = {}
        for bucket in buckets:
            name = bucket["Name"]
            response = self._client.call(
                "get_bucket_policy",
                {"Bucket": name},
                disambiguator=name,
                ignore_error_codes=_IGNORED_GET_BUCKET_POLICY_ERRORS,
            )
            if response is None:
                bucket_policies[name] = None
                continue
            # GetBucketPolicy's `Policy` field is a JSON-encoded string, not a dict.
            bucket_policies[name] = json.loads(response["Policy"])
        return bucket_policies

    def _scan_bucket_acls(self, buckets: list[dict[str, Any]]) -> dict[str, dict[str, Any] | None]:
        bucket_acls: dict[str, dict[str, Any] | None] = {}
        for bucket in buckets:
            name = bucket["Name"]
            response = self._client.call("get_bucket_acl", {"Bucket": name}, disambiguator=name)
            bucket_acls[name] = response
        return bucket_acls


def _normalize_location(location_constraint: str | None) -> str:
    """GetBucketLocation's LocationConstraint comes back as None/empty string
    for buckets in us-east-1 (AWS's original, unnamed default region) rather
    than the literal string "us-east-1" -- normalize that specific case; every
    other region's string is already correct as-is.
    """
    if not location_constraint:
        return "us-east-1"
    return location_constraint
