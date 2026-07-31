from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.export import add_edge, add_node, new_graph
from aws_graph_builder.graph.schema import Edge, EdgeType, Node, NodeType, make_edge_id
from aws_graph_builder.privesc.techniques.add_user_to_group import SPEC, detect

ACCOUNT_ID = "111111111111"
ALICE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
GROUP_ARN = f"arn:aws:iam::{ACCOUNT_ID}:group/admins"


def _graph() -> nx.MultiDiGraph:
    graph = new_graph()
    add_node(graph, Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN))
    add_node(graph, Node(id=GROUP_ARN, type=NodeType.IAM_GROUP, name="admins", arn=GROUP_ARN))
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


def test_finding_emitted_when_add_user_to_group_granted() -> None:
    graph = _graph()
    edge_id = _add_effective_permission(graph, ALICE_ARN, GROUP_ARN, ["iam:AddUserToGroup"])

    findings = detect(graph, ALICE_ARN, PermissionQuery(graph))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.technique_id == SPEC.id
    assert finding.source == ALICE_ARN
    assert finding.target == GROUP_ARN
    assert finding.required_permissions == ["iam:AddUserToGroup"]
    assert finding.evidence_edges == [edge_id]
    assert finding.severity == SPEC.severity


def test_no_finding_when_action_absent() -> None:
    graph = _graph()
    _add_effective_permission(graph, ALICE_ARN, GROUP_ARN, ["iam:GetGroup"])

    findings = detect(graph, ALICE_ARN, PermissionQuery(graph))

    assert findings == []
