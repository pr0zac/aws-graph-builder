from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.export import add_edge, add_node, new_graph
from aws_graph_builder.graph.schema import Edge, EdgeType, Node, NodeType, make_edge_id
from aws_graph_builder.privesc.techniques.pass_role_lambda import SPEC, detect

ACCOUNT_ID = "111111111111"
ALICE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/deploy-role"


def _graph_with_user_and_role() -> nx.MultiDiGraph:
    graph = new_graph()
    add_node(graph, Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN))
    add_node(graph, Node(id=ROLE_ARN, type=NodeType.IAM_ROLE, name="deploy-role", arn=ROLE_ARN))
    return graph


def _add_effective_permission(graph: nx.MultiDiGraph, source: str, target: str, actions: list[str]) -> str:
    edge_id = make_edge_id(EdgeType.EFFECTIVE_PERMISSION, source, target)
    add_edge(
        graph,
        Edge(
            id=edge_id,
            type=EdgeType.EFFECTIVE_PERMISSION,
            source=source,
            target=target,
            properties={
                "actions": actions,
                "resource_pattern": "*",
                "evaluated_from": [],
                "effect": "Allow",
                "condition_unresolved": False,
            },
        ),
    )
    return edge_id


def test_finding_emitted_when_both_actions_present_on_same_role() -> None:
    graph = _graph_with_user_and_role()
    edge_id = _add_effective_permission(graph, ALICE_ARN, ROLE_ARN, ["iam:PassRole", "lambda:CreateFunction"])

    findings = detect(graph, ALICE_ARN, PermissionQuery(graph))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.technique_id == SPEC.id
    assert finding.source == ALICE_ARN
    assert finding.target == ROLE_ARN
    assert finding.severity == SPEC.severity
    assert finding.required_permissions == ["iam:PassRole", "lambda:CreateFunction"]
    # Both actions matched via the same single EffectivePermission edge --
    # evidence_edges must be deduped, not contain the id twice.
    assert finding.evidence_edges == [edge_id]


def test_finding_evidence_merges_two_distinct_edges() -> None:
    graph = _graph_with_user_and_role()
    pass_role_edge = _add_effective_permission(graph, ALICE_ARN, ROLE_ARN, ["iam:PassRole"])
    create_function_edge_id = make_edge_id(
        EdgeType.EFFECTIVE_PERMISSION, ALICE_ARN, ROLE_ARN, discriminator="lambda"
    )
    add_edge(
        graph,
        Edge(
            id=create_function_edge_id,
            type=EdgeType.EFFECTIVE_PERMISSION,
            source=ALICE_ARN,
            target=ROLE_ARN,
            properties={
                "actions": ["lambda:CreateFunction"],
                "resource_pattern": "*",
                "evaluated_from": [],
                "effect": "Allow",
                "condition_unresolved": False,
            },
        ),
    )

    findings = detect(graph, ALICE_ARN, PermissionQuery(graph))

    assert len(findings) == 1
    finding = findings[0]
    assert set(finding.evidence_edges) == {pass_role_edge, create_function_edge_id}
    assert len(finding.evidence_edges) == 2


def test_no_finding_when_only_pass_role_present() -> None:
    graph = _graph_with_user_and_role()
    _add_effective_permission(graph, ALICE_ARN, ROLE_ARN, ["iam:PassRole"])

    findings = detect(graph, ALICE_ARN, PermissionQuery(graph))

    assert findings == []


def test_no_finding_when_only_create_function_present() -> None:
    graph = _graph_with_user_and_role()
    _add_effective_permission(graph, ALICE_ARN, ROLE_ARN, ["lambda:CreateFunction"])

    findings = detect(graph, ALICE_ARN, PermissionQuery(graph))

    assert findings == []


def test_no_finding_when_neither_action_present() -> None:
    graph = _graph_with_user_and_role()
    _add_effective_permission(graph, ALICE_ARN, ROLE_ARN, ["iam:ListRoles"])

    findings = detect(graph, ALICE_ARN, PermissionQuery(graph))

    assert findings == []


def test_no_finding_when_only_qualifying_target_is_own_role() -> None:
    graph = new_graph()
    add_node(graph, Node(id=ROLE_ARN, type=NodeType.IAM_ROLE, name="deploy-role", arn=ROLE_ARN))
    _add_effective_permission(graph, ROLE_ARN, ROLE_ARN, ["iam:PassRole", "lambda:CreateFunction"])

    findings = detect(graph, ROLE_ARN, PermissionQuery(graph))

    assert findings == []
