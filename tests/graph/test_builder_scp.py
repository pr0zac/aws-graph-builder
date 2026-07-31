from __future__ import annotations

import networkx as nx

from aws_graph_builder.graph.builder import add_scp_policies_to_graph, build_iam_graph
from aws_graph_builder.graph.schema import EdgeType, NodeType, make_edge_id
from aws_graph_builder.scan.iam import IamScanResult
from aws_graph_builder.scan.organizations import OrganizationsScanResult

ACCOUNT_ID = "111111111111"
ACCOUNT_ARN = f"arn:aws:iam::{ACCOUNT_ID}:root"

SCP_ARN = f"arn:aws:organizations::{ACCOUNT_ID}:policy/o-example/service_control_policy/p-fullaccess"
SCP_ID = "p-fullaccess"

DENY_SCP_ARN = f"arn:aws:organizations::{ACCOUNT_ID}:policy/o-example/service_control_policy/p-denyregion"
DENY_SCP_ID = "p-denyregion"

SCP_CONTENT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


def _build_graph() -> nx.MultiDiGraph:
    """A minimal graph containing just the Account node (via `build_iam_graph`,
    which always creates it) for the SCP tests to attach onto.
    """
    return build_iam_graph(IamScanResult(), account_id=ACCOUNT_ID)


def test_in_organization_false_adds_nothing() -> None:
    graph = _build_graph()
    nodes_before = set(graph.nodes)
    edges_before = graph.number_of_edges()

    scan_result = OrganizationsScanResult(in_organization=False)
    add_scp_policies_to_graph(graph, scan_result, account_id=ACCOUNT_ID)

    assert set(graph.nodes) == nodes_before
    assert graph.number_of_edges() == edges_before


def test_scp_node_created_with_properties_and_content() -> None:
    graph = _build_graph()
    scan_result = OrganizationsScanResult(
        in_organization=True,
        policies=[{"Id": SCP_ID, "Arn": SCP_ARN, "Name": "FullAWSAccess", "Type": "SERVICE_CONTROL_POLICY"}],
        policy_documents={SCP_ID: SCP_CONTENT},
    )

    add_scp_policies_to_graph(graph, scan_result, account_id=ACCOUNT_ID)

    assert SCP_ARN in graph.nodes
    node = graph.nodes[SCP_ARN]
    assert node["type"] == NodeType.SERVICE_CONTROL_POLICY.value
    assert node["name"] == "FullAWSAccess"
    assert node["arn"] == SCP_ARN
    assert node["properties"]["Type"] == "SERVICE_CONTROL_POLICY"
    assert node["properties"]["content"] == SCP_CONTENT
    # Arn/Name are promoted to id/arn/name, so not duplicated in properties.
    assert "Arn" not in node["properties"]
    assert "Name" not in node["properties"]


def test_content_defaults_to_none_when_describe_policy_failed() -> None:
    graph = _build_graph()
    scan_result = OrganizationsScanResult(
        in_organization=True,
        policies=[{"Id": DENY_SCP_ID, "Arn": DENY_SCP_ARN, "Name": "DenyRegion"}],
        policy_documents={},  # DescribePolicy failed for this one -- no entry.
    )

    add_scp_policies_to_graph(graph, scan_result, account_id=ACCOUNT_ID)

    assert graph.nodes[DENY_SCP_ARN]["properties"]["content"] is None


def test_applies_scp_edge_created_from_account_node() -> None:
    graph = _build_graph()
    scan_result = OrganizationsScanResult(
        in_organization=True,
        policies=[
            {"Id": SCP_ID, "Arn": SCP_ARN, "Name": "FullAWSAccess"},
            {"Id": DENY_SCP_ID, "Arn": DENY_SCP_ARN, "Name": "DenyRegion"},
        ],
        policy_documents={SCP_ID: SCP_CONTENT},
    )

    add_scp_policies_to_graph(graph, scan_result, account_id=ACCOUNT_ID)

    for scp_arn in (SCP_ARN, DENY_SCP_ARN):
        edge_id = make_edge_id(EdgeType.APPLIES_SCP, ACCOUNT_ARN, scp_arn)
        assert graph.has_edge(ACCOUNT_ARN, scp_arn, key=edge_id)
        assert graph[ACCOUNT_ARN][scp_arn][edge_id]["type"] == EdgeType.APPLIES_SCP.value
    assert graph.out_degree(ACCOUNT_ARN) == 2
