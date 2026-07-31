from __future__ import annotations

from typing import Any

import networkx as nx

from aws_graph_builder.eval.trust import evaluate_trust_policies
from aws_graph_builder.graph.export import add_node, new_graph
from aws_graph_builder.graph.schema import EdgeType, Node, NodeType

ACCOUNT_ID = "111111111111"
ACCOUNT_ARN = f"arn:aws:iam::{ACCOUNT_ID}:root"
ALICE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/target-role"
IDP_ARN = f"arn:aws:iam::{ACCOUNT_ID}:saml-provider/okta"
CROSS_ACCOUNT_ROLE_ARN = "arn:aws:iam::222222222222:role/other-role"


def _base_graph(*, extra_nodes: list[Node] | None = None) -> nx.MultiDiGraph:
    graph = new_graph()
    add_node(graph, Node(id=ACCOUNT_ARN, type=NodeType.ACCOUNT, name=ACCOUNT_ID, arn=ACCOUNT_ARN))
    for node in extra_nodes or []:
        add_node(graph, node)
    return graph


def _add_role(graph: nx.MultiDiGraph, assume_role_policy_document: dict[str, Any]) -> None:
    add_node(
        graph,
        Node(
            id=ROLE_ARN,
            type=NodeType.IAM_ROLE,
            name="target-role",
            arn=ROLE_ARN,
            properties={"AssumeRolePolicyDocument": assume_role_policy_document},
        ),
    )


def _can_assume_edges(graph: nx.MultiDiGraph) -> list[tuple[str, str, dict[str, Any]]]:
    return [
        (source, target, data)
        for source, target, data in graph.edges(data=True)
        if data.get("type") == EdgeType.CAN_ASSUME.value
    ]


def test_aws_arn_principal_matching_existing_node_creates_can_assume_edge() -> None:
    graph = _base_graph(extra_nodes=[Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN)])
    _add_role(
        graph,
        {
            "Statement": [
                {"Sid": "AllowAlice", "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": ALICE_ARN}}
            ]
        },
    )

    evaluate_trust_policies(graph)

    edges = _can_assume_edges(graph)
    assert len(edges) == 1
    source, target, data = edges[0]
    assert source == ALICE_ARN
    assert target == ROLE_ARN
    assert data["properties"]["requires_mfa"] is False
    assert data["properties"]["external_id_required"] is False
    assert data["properties"]["condition_unresolved"] is False
    assert "principal_kind" not in data["properties"]


def test_bare_account_id_and_account_root_arn_create_edge_from_account_node() -> None:
    graph = _base_graph()
    _add_role(
        graph,
        {
            "Statement": [
                {"Sid": "BareAccountId", "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": ACCOUNT_ID}},
                {
                    "Sid": "RootArn",
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": ACCOUNT_ARN},
                },
            ]
        },
    )

    evaluate_trust_policies(graph)

    edges = _can_assume_edges(graph)
    assert len(edges) == 2
    for source, target, data in edges:
        assert source == ACCOUNT_ARN
        assert target == ROLE_ARN
        assert data["properties"]["principal_kind"] == "account"
        assert "note" in data["properties"]
    # Two different Sids -> distinct edge ids via the discriminator.
    assert edges[0][2]["id"] != edges[1][2]["id"]


def test_wildcard_principal_creates_external_principal_node_and_edge() -> None:
    graph = _base_graph()
    _add_role(
        graph,
        {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}]},
    )

    evaluate_trust_policies(graph)

    assert "external:*" in graph.nodes
    node_data = graph.nodes["external:*"]
    assert node_data["type"] == NodeType.EXTERNAL_PRINCIPAL.value

    edges = _can_assume_edges(graph)
    assert len(edges) == 1
    source, target, data = edges[0]
    assert source == "external:*"
    assert target == ROLE_ARN
    assert data["properties"]["principal_kind"] == "wildcard"


def test_unresolvable_cross_account_arn_creates_external_principal_node() -> None:
    graph = _base_graph()
    _add_role(
        graph,
        {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": CROSS_ACCOUNT_ROLE_ARN}}]},
    )

    evaluate_trust_policies(graph)

    assert CROSS_ACCOUNT_ROLE_ARN in graph.nodes
    node_data = graph.nodes[CROSS_ACCOUNT_ROLE_ARN]
    assert node_data["type"] == NodeType.EXTERNAL_PRINCIPAL.value
    assert node_data["arn"] == CROSS_ACCOUNT_ROLE_ARN
    assert node_data["name"] == "other-role"

    edges = _can_assume_edges(graph)
    assert len(edges) == 1
    assert edges[0][0] == CROSS_ACCOUNT_ROLE_ARN
    assert edges[0][1] == ROLE_ARN


def test_federated_principal_matching_identity_provider_creates_can_assume_and_identifies_via() -> None:
    idp_node = Node(id=IDP_ARN, type=NodeType.IDENTITY_PROVIDER, name="okta", arn=IDP_ARN, properties={"provider_type": "saml"})
    graph = _base_graph(extra_nodes=[idp_node])
    _add_role(
        graph,
        {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithSAML", "Principal": {"Federated": IDP_ARN}}]},
    )

    evaluate_trust_policies(graph)

    can_assume_edges = _can_assume_edges(graph)
    assert len(can_assume_edges) == 1
    assert can_assume_edges[0][0] == IDP_ARN
    assert can_assume_edges[0][1] == ROLE_ARN

    identifies_via_edges = [
        (source, target)
        for source, target, data in graph.edges(data=True)
        if data.get("type") == EdgeType.IDENTIFIES_VIA.value
    ]
    assert identifies_via_edges == [(ROLE_ARN, IDP_ARN)]


def test_federated_principal_with_no_matching_provider_is_skipped_gracefully() -> None:
    graph = _base_graph()
    _add_role(
        graph,
        {
            "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRoleWithSAML", "Principal": {"Federated": IDP_ARN}}
            ]
        },
    )

    evaluate_trust_policies(graph)

    assert _can_assume_edges(graph) == []
    identifies_via_edges = [data for _u, _v, data in graph.edges(data=True) if data.get("type") == EdgeType.IDENTIFIES_VIA.value]
    assert identifies_via_edges == []


def test_service_principal_creates_service_principal_node_and_edge() -> None:
    graph = _base_graph()
    _add_role(
        graph,
        {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "ec2.amazonaws.com"}}]},
    )

    evaluate_trust_policies(graph)

    assert "ec2.amazonaws.com" in graph.nodes
    node_data = graph.nodes["ec2.amazonaws.com"]
    assert node_data["type"] == NodeType.SERVICE_PRINCIPAL.value
    assert node_data["arn"] is None

    edges = _can_assume_edges(graph)
    assert len(edges) == 1
    assert edges[0][0] == "ec2.amazonaws.com"
    assert edges[0][1] == ROLE_ARN


def test_mfa_condition_sets_requires_mfa_true() -> None:
    graph = _base_graph(extra_nodes=[Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN)])
    _add_role(
        graph,
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": ALICE_ARN},
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                }
            ]
        },
    )

    evaluate_trust_policies(graph)

    edges = _can_assume_edges(graph)
    assert edges[0][2]["properties"]["requires_mfa"] is True
    assert edges[0][2]["properties"]["condition_unresolved"] is False


def test_external_id_condition_sets_external_id_required_true() -> None:
    graph = _base_graph()
    _add_role(
        graph,
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": CROSS_ACCOUNT_ROLE_ARN},
                    "Condition": {"StringEquals": {"sts:ExternalId": "some-secret"}},
                }
            ]
        },
    )

    evaluate_trust_policies(graph)

    edges = _can_assume_edges(graph)
    assert edges[0][2]["properties"]["external_id_required"] is True
    assert edges[0][2]["properties"]["condition_unresolved"] is False


def test_unrecognized_condition_sets_condition_unresolved_true() -> None:
    graph = _base_graph()
    _add_role(
        graph,
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": CROSS_ACCOUNT_ROLE_ARN},
                    "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
                }
            ]
        },
    )

    evaluate_trust_policies(graph)

    edges = _can_assume_edges(graph)
    assert edges[0][2]["properties"]["condition_unresolved"] is True
    assert edges[0][2]["properties"]["requires_mfa"] is False
    assert edges[0][2]["properties"]["external_id_required"] is False


def test_role_with_no_assume_role_policy_document_is_skipped() -> None:
    graph = _base_graph()
    add_node(graph, Node(id=ROLE_ARN, type=NodeType.IAM_ROLE, name="target-role", arn=ROLE_ARN, properties={}))

    evaluate_trust_policies(graph)

    assert _can_assume_edges(graph) == []
