from __future__ import annotations

import networkx as nx

from aws_graph_builder.graph.export import add_edge, add_node, new_graph
from aws_graph_builder.graph.schema import Edge, EdgeType, Node, NodeType, make_edge_id
from aws_graph_builder.privesc.engine import run_privesc_detection

ACCOUNT_ID = "111111111111"
ALICE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
BOB_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/bob"


def _build_graph() -> nx.MultiDiGraph:
    """Hand-built, already-evaluated graph: two IamUsers, and a single
    EffectivePermission edge from alice to bob granting BOTH
    iam:CreateAccessKey and iam:PutUserPolicy -- i.e. two different privesc
    techniques (create_access_key, attach_policy) both apply to the exact
    same (source, target) pair, which is precisely the case the PrivescPath
    edge id's technique_id discriminator exists for.
    """
    graph = new_graph()
    add_node(graph, Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN))
    add_node(graph, Node(id=BOB_ARN, type=NodeType.IAM_USER, name="bob", arn=BOB_ARN))

    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.EFFECTIVE_PERMISSION, ALICE_ARN, BOB_ARN),
            type=EdgeType.EFFECTIVE_PERMISSION,
            source=ALICE_ARN,
            target=BOB_ARN,
            properties={
                "actions": ["iam:CreateAccessKey", "iam:PutUserPolicy"],
                "resource_pattern": "*",
                "evaluated_from": [],
                "effect": "Allow",
                "condition_unresolved": False,
            },
        ),
    )
    return graph


def test_run_privesc_detection_finds_both_techniques() -> None:
    graph = _build_graph()

    findings = run_privesc_detection(graph)

    technique_ids = {finding.technique_id for finding in findings}
    assert technique_ids == {"create_access_key", "attach_policy"}
    for finding in findings:
        assert finding.source == ALICE_ARN
        assert finding.target == BOB_ARN

    # Returned in stable (technique_id, source, target) order.
    assert findings == sorted(findings, key=lambda f: (f.technique_id, f.source, f.target))


def test_two_techniques_on_the_same_source_target_pair_produce_distinct_privesc_path_edges() -> None:
    graph = _build_graph()

    run_privesc_detection(graph)

    all_edges = graph.get_edge_data(ALICE_ARN, BOB_ARN)
    privesc_edges = {key: data for key, data in all_edges.items() if data.get("type") == EdgeType.PRIVESC_PATH.value}

    assert len(privesc_edges) == 2
    technique_ids_on_edges = {data["properties"]["technique_id"] for data in privesc_edges.values()}
    assert technique_ids_on_edges == {"create_access_key", "attach_policy"}

    expected_ids = {
        make_edge_id(EdgeType.PRIVESC_PATH, ALICE_ARN, BOB_ARN, discriminator="create_access_key"),
        make_edge_id(EdgeType.PRIVESC_PATH, ALICE_ARN, BOB_ARN, discriminator="attach_policy"),
    }
    assert set(privesc_edges.keys()) == expected_ids
    # The two edge ids are distinct from one another (confirms the
    # discriminator actually changes the id, not just a coincidence).
    assert len(expected_ids) == 2


def test_privesc_path_edge_properties_match_the_returned_finding() -> None:
    graph = _build_graph()
    findings = run_privesc_detection(graph)

    for finding in findings:
        edge_id = make_edge_id(
            EdgeType.PRIVESC_PATH, finding.source, finding.target, discriminator=finding.technique_id
        )
        edge_data = graph.get_edge_data(finding.source, finding.target)[edge_id]
        assert edge_data["properties"]["severity"] == finding.severity
        assert edge_data["properties"]["required_permissions"] == finding.required_permissions
        assert edge_data["properties"]["evidence_edges"] == finding.evidence_edges
        assert edge_data["properties"]["description"] == finding.description
