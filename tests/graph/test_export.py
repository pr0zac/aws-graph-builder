from __future__ import annotations

from typing import Any

import networkx as nx

from aws_graph_builder.graph.export import (
    add_edge,
    add_node,
    document_to_graph,
    graph_to_document,
    new_graph,
)
from aws_graph_builder.graph.schema import (
    Edge,
    EdgeType,
    Node,
    NodeType,
    inline_policy_id,
    make_edge_id,
)

ACCOUNT_ID = "111111111111"
ACCOUNT_ARN = f"arn:aws:iam::{ACCOUNT_ID}:root"
ALICE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
BOB_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/bob"
GROUP_ARN = f"arn:aws:iam::{ACCOUNT_ID}:group/admins"
POLICY_ARN = f"arn:aws:iam::{ACCOUNT_ID}:policy/AdminPolicy"
ALICE_INLINE_ID = inline_policy_id(ALICE_ARN, "InlineAdmin")


def _build_sample_graph() -> nx.MultiDiGraph:
    """Account, two IamUsers, an IamGroup, a ManagedPolicy, an InlinePolicy,
    wired up with MemberOf/AttachedPolicy/HasInlinePolicy/HasPermissionBoundary
    edges -- including a parallel-edge pair (AttachedPolicy + HasPermissionBoundary)
    between the same (bob, policy) node pair.
    """
    graph = new_graph()

    add_node(graph, Node(id=ACCOUNT_ARN, type=NodeType.ACCOUNT, name=ACCOUNT_ID, arn=ACCOUNT_ARN))
    add_node(
        graph,
        Node(
            id=ALICE_ARN,
            type=NodeType.IAM_USER,
            name="alice",
            arn=ALICE_ARN,
            properties={"mfa_enabled": False, "tags": {"team": "security", "cost_center": 42}},
        ),
    )
    add_node(graph, Node(id=BOB_ARN, type=NodeType.IAM_USER, name="bob", arn=BOB_ARN, properties={"mfa_enabled": True}))
    add_node(graph, Node(id=GROUP_ARN, type=NodeType.IAM_GROUP, name="admins", arn=GROUP_ARN))
    add_node(
        graph,
        Node(id=POLICY_ARN, type=NodeType.MANAGED_POLICY, name="AdminPolicy", arn=POLICY_ARN, properties={"aws_managed": False}),
    )
    add_node(
        graph,
        Node(
            id=ALICE_INLINE_ID,
            type=NodeType.INLINE_POLICY,
            name="InlineAdmin",
            arn=None,
            properties={"document": {"Version": "2012-10-17", "Statement": []}},
        ),
    )

    add_edge(graph, Edge(id=make_edge_id(EdgeType.MEMBER_OF, ALICE_ARN, GROUP_ARN), type=EdgeType.MEMBER_OF, source=ALICE_ARN, target=GROUP_ARN))
    add_edge(graph, Edge(id=make_edge_id(EdgeType.MEMBER_OF, BOB_ARN, GROUP_ARN), type=EdgeType.MEMBER_OF, source=BOB_ARN, target=GROUP_ARN))
    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.ATTACHED_POLICY, ALICE_ARN, POLICY_ARN),
            type=EdgeType.ATTACHED_POLICY,
            source=ALICE_ARN,
            target=POLICY_ARN,
        ),
    )
    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.HAS_INLINE_POLICY, ALICE_ARN, ALICE_INLINE_ID),
            type=EdgeType.HAS_INLINE_POLICY,
            source=ALICE_ARN,
            target=ALICE_INLINE_ID,
        ),
    )
    # Parallel edges: two different edge types between the same (bob, policy) pair.
    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.ATTACHED_POLICY, BOB_ARN, POLICY_ARN),
            type=EdgeType.ATTACHED_POLICY,
            source=BOB_ARN,
            target=POLICY_ARN,
        ),
    )
    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.HAS_PERMISSION_BOUNDARY, BOB_ARN, POLICY_ARN),
            type=EdgeType.HAS_PERMISSION_BOUNDARY,
            source=BOB_ARN,
            target=POLICY_ARN,
            properties={"evidence": {"source": "GetAccountAuthorizationDetails"}},
        ),
    )

    return graph


def test_make_edge_id_discriminator_backward_compatible_and_distinct() -> None:
    # Omitting the discriminator produces the exact same id as before it
    # existed -- every Phase 1 call site passes only 3 positional args, and
    # must keep working unchanged.
    without_discriminator = make_edge_id(EdgeType.CAN_ASSUME, ALICE_ARN, GROUP_ARN)
    assert without_discriminator == make_edge_id(EdgeType.CAN_ASSUME, ALICE_ARN, GROUP_ARN, None)

    # Different discriminators with an otherwise-identical (type, source,
    # target) triple produce different ids, so parallel edges of the same
    # type between the same two nodes stay distinct and stable.
    with_sid_a = make_edge_id(EdgeType.CAN_ASSUME, ALICE_ARN, GROUP_ARN, discriminator="StatementA")
    with_sid_b = make_edge_id(EdgeType.CAN_ASSUME, ALICE_ARN, GROUP_ARN, discriminator="StatementB")
    assert with_sid_a != with_sid_b
    assert with_sid_a != without_discriminator
    assert with_sid_b != without_discriminator

    # Deterministic: same discriminator -> same id across calls.
    assert with_sid_a == make_edge_id(EdgeType.CAN_ASSUME, ALICE_ARN, GROUP_ARN, discriminator="StatementA")


def test_add_edge_supports_parallel_edges_of_different_types() -> None:
    graph = _build_sample_graph()

    assert graph.number_of_edges(BOB_ARN, POLICY_ARN) == 2

    edge_data = graph.get_edge_data(BOB_ARN, POLICY_ARN)
    assert edge_data is not None
    types = {data["type"] for data in edge_data.values()}
    assert types == {EdgeType.ATTACHED_POLICY.value, EdgeType.HAS_PERMISSION_BOUNDARY.value}

    boundary_key = make_edge_id(EdgeType.HAS_PERMISSION_BOUNDARY, BOB_ARN, POLICY_ARN)
    assert edge_data[boundary_key]["properties"] == {"evidence": {"source": "GetAccountAuthorizationDetails"}}


def test_graph_to_document_top_level_shape() -> None:
    graph = _build_sample_graph()

    document = graph_to_document(graph, account_id=ACCOUNT_ID, regions_scanned=[])

    assert set(document.keys()) == {
        "schema_version",
        "generated_at",
        "account_id",
        "regions_scanned",
        "nodes",
        "edges",
    }
    assert document["schema_version"] == "1.0"
    assert document["account_id"] == ACCOUNT_ID
    assert document["regions_scanned"] == []
    assert isinstance(document["generated_at"], str) and document["generated_at"].endswith("Z")
    assert "findings" not in document


def test_graph_to_document_node_and_edge_shapes_and_properties_round_trip() -> None:
    graph = _build_sample_graph()

    document = graph_to_document(graph, account_id=ACCOUNT_ID, regions_scanned=["us-east-1"])

    nodes_by_id = {n["id"]: n for n in document["nodes"]}
    assert set(nodes_by_id) == {ACCOUNT_ARN, ALICE_ARN, BOB_ARN, GROUP_ARN, POLICY_ARN, ALICE_INLINE_ID}

    for node in document["nodes"]:
        assert set(node.keys()) == {"id", "type", "name", "arn", "properties"}

    alice = nodes_by_id[ALICE_ARN]
    assert alice["type"] == NodeType.IAM_USER.value
    assert alice["name"] == "alice"
    assert alice["arn"] == ALICE_ARN
    assert alice["properties"] == {"mfa_enabled": False, "tags": {"team": "security", "cost_center": 42}}

    inline = nodes_by_id[ALICE_INLINE_ID]
    assert inline["type"] == NodeType.INLINE_POLICY.value
    assert inline["arn"] is None
    assert inline["properties"]["document"] == {"Version": "2012-10-17", "Statement": []}

    for edge in document["edges"]:
        assert set(edge.keys()) == {"id", "type", "source", "target", "properties"}

    edges_by_id = {e["id"]: e for e in document["edges"]}
    boundary_edge_id = make_edge_id(EdgeType.HAS_PERMISSION_BOUNDARY, BOB_ARN, POLICY_ARN)
    boundary_edge = edges_by_id[boundary_edge_id]
    assert boundary_edge["type"] == EdgeType.HAS_PERMISSION_BOUNDARY.value
    assert boundary_edge["source"] == BOB_ARN
    assert boundary_edge["target"] == POLICY_ARN
    assert boundary_edge["properties"] == {"evidence": {"source": "GetAccountAuthorizationDetails"}}

    member_of_alice_id = make_edge_id(EdgeType.MEMBER_OF, ALICE_ARN, GROUP_ARN)
    assert edges_by_id[member_of_alice_id]["properties"] == {}


def _node_attrs(graph: nx.MultiDiGraph) -> dict[str, dict[str, Any]]:
    return {node_id: dict(data) for node_id, data in graph.nodes(data=True)}


def _edge_attrs(graph: nx.MultiDiGraph) -> dict[tuple[str, str, str], dict[str, Any]]:
    return {(u, v, k): dict(data) for u, v, k, data in graph.edges(keys=True, data=True)}


def test_document_to_graph_round_trips_nodes_and_edges() -> None:
    original = _build_sample_graph()
    document = graph_to_document(original, account_id=ACCOUNT_ID, regions_scanned=[])

    rebuilt = document_to_graph(document)

    assert isinstance(rebuilt, nx.MultiDiGraph)
    assert set(rebuilt.nodes) == set(original.nodes)
    assert _node_attrs(rebuilt) == _node_attrs(original)

    assert rebuilt.number_of_edges() == original.number_of_edges()
    assert _edge_attrs(rebuilt) == _edge_attrs(original)

    # Parallel edges survive the round trip too.
    assert rebuilt.number_of_edges(BOB_ARN, POLICY_ARN) == 2
