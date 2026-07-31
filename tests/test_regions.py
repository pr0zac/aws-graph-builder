from __future__ import annotations

import boto3
from moto import mock_aws

from aws_graph_builder.regions import discover_enabled_regions


@mock_aws
def test_discover_enabled_regions_returns_sorted_region_names() -> None:
    session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1")

    regions = discover_enabled_regions(session)

    assert isinstance(regions, list)
    assert regions == sorted(regions)
    assert "us-east-1" in regions


@mock_aws
def test_discover_enabled_regions_excludes_not_opted_in() -> None:
    session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1")

    regions = discover_enabled_regions(session)

    # moto's default DescribeRegions response marks every region either
    # "opt-in-not-required" or "not-opted-in" -- confirm the filter actually
    # excludes at least one real not-opted-in region (e.g. af-south-1).
    ec2 = session.client("ec2")
    all_regions = {r["RegionName"]: r.get("OptInStatus") for r in ec2.describe_regions(AllRegions=True)["Regions"]}
    not_opted_in = [name for name, status in all_regions.items() if status == "not-opted-in"]
    assert not_opted_in, "test assumption: moto should include at least one not-opted-in region"
    assert not any(r in regions for r in not_opted_in)
