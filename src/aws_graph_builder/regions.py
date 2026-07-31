"""Enabled-region discovery for region-scoped scanners (EC2, Lambda -- IAM,
S3's bucket listing, and Organizations are global/single-call services and
don't need this).

Not routed through the disk cache: like `session.validate_credentials`, this
is a small, one-shot call made once before per-region scanning begins, not
part of any particular resource `Scanner`.
"""

from __future__ import annotations

import boto3

#: Region opt-in statuses that mean "usable without extra account setup".
#: `not-opted-in` regions exist in the API response but would fail every
#: region-scoped call, so they're excluded even though `DescribeRegions`
#: without `AllRegions=True` should already omit them -- this is a cheap,
#: explicit belt-and-suspenders filter, not a workaround for an observed bug.
_USABLE_OPT_IN_STATUSES = frozenset({"opt-in-not-required", "opted-in"})


def discover_enabled_regions(session: boto3.Session) -> list[str]:
    """Return the sorted list of region names enabled for this account.

    Calls `ec2:DescribeRegions` (no `AllRegions` argument, i.e. `False`,
    which restricts the response to regions already enabled for the
    account rather than every region AWS offers).
    """
    client = session.client("ec2")
    response = client.describe_regions()
    return sorted(
        region["RegionName"]
        for region in response["Regions"]
        if region.get("OptInStatus") in _USABLE_OPT_IN_STATUSES
    )
