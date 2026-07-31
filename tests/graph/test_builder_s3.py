from __future__ import annotations

from aws_graph_builder.graph.builder import add_s3_buckets_to_graph
from aws_graph_builder.graph.export import new_graph
from aws_graph_builder.graph.schema import NodeType
from aws_graph_builder.scan.s3 import S3ScanResult

WITH_POLICY_ARN = "arn:aws:s3:::with-policy-bucket"
NO_POLICY_ARN = "arn:aws:s3:::no-policy-bucket"

BUCKET_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "PublicRead", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}],
}
ACL = {"Owner": {"ID": "abc123"}, "Grants": []}


def test_bucket_node_created_with_no_account_or_region_in_arn() -> None:
    graph = new_graph()
    scan_result = S3ScanResult(
        buckets=[{"Name": "with-policy-bucket", "CreationDate": "2026-01-01T00:00:00+00:00"}],
        bucket_locations={"with-policy-bucket": "us-west-2"},
        bucket_policies={"with-policy-bucket": BUCKET_POLICY},
        bucket_acls={"with-policy-bucket": ACL},
    )

    add_s3_buckets_to_graph(graph, scan_result)

    assert WITH_POLICY_ARN in graph.nodes
    node = graph.nodes[WITH_POLICY_ARN]
    assert node["type"] == NodeType.S3_BUCKET.value
    assert node["name"] == "with-policy-bucket"
    assert node["arn"] == WITH_POLICY_ARN
    assert node["properties"]["CreationDate"] == "2026-01-01T00:00:00+00:00"
    assert node["properties"]["region"] == "us-west-2"
    assert node["properties"]["bucket_policy"] == BUCKET_POLICY
    assert node["properties"]["acl"] == ACL
    # Name is promoted to name/arn, so not duplicated in properties.
    assert "Name" not in node["properties"]


def test_bucket_policy_and_acl_default_to_none_when_missing() -> None:
    graph = new_graph()
    scan_result = S3ScanResult(
        buckets=[{"Name": "no-policy-bucket"}],
        bucket_locations={"no-policy-bucket": "us-east-1"},
        bucket_policies={"no-policy-bucket": None},
        bucket_acls={"no-policy-bucket": None},
    )

    add_s3_buckets_to_graph(graph, scan_result)

    node = graph.nodes[NO_POLICY_ARN]
    assert node["properties"]["bucket_policy"] is None
    assert node["properties"]["acl"] is None
    assert node["properties"]["region"] == "us-east-1"


def test_no_edges_created_for_buckets() -> None:
    graph = new_graph()
    scan_result = S3ScanResult(
        buckets=[{"Name": "with-policy-bucket"}, {"Name": "no-policy-bucket"}],
    )

    add_s3_buckets_to_graph(graph, scan_result)

    assert graph.number_of_edges() == 0
