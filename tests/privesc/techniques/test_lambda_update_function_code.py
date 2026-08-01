from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.export import add_edge, add_node, new_graph
from aws_graph_builder.graph.schema import Edge, EdgeType, Node, NodeType, make_edge_id
from aws_graph_builder.privesc.techniques.lambda_update_function_code import (
    SPEC,
    detect,
)

ACCOUNT_ID = "111111111111"
ALICE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/lambda-exec-role"
FUNCTION_ARN = f"arn:aws:lambda:us-east-1:{ACCOUNT_ID}:function:my-function"


def _graph_with_function_and_role() -> nx.MultiDiGraph:
    graph = new_graph()
    add_node(graph, Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN))
    add_node(graph, Node(id=ROLE_ARN, type=NodeType.IAM_ROLE, name="lambda-exec-role", arn=ROLE_ARN))
    add_node(graph, Node(id=FUNCTION_ARN, type=NodeType.LAMBDA_FUNCTION, name="my-function", arn=FUNCTION_ARN))
    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.EXECUTION_ROLE, FUNCTION_ARN, ROLE_ARN),
            type=EdgeType.EXECUTION_ROLE,
            source=FUNCTION_ARN,
            target=ROLE_ARN,
        ),
    )
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


def test_finding_emitted_when_update_function_code_granted() -> None:
    graph = _graph_with_function_and_role()
    edge_id = _add_effective_permission(graph, ALICE_ARN, FUNCTION_ARN, ["lambda:UpdateFunctionCode"])

    findings = detect(graph, ALICE_ARN, PermissionQuery(graph))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.technique_id == SPEC.id
    assert finding.source == ALICE_ARN
    assert finding.target == ROLE_ARN
    assert finding.required_permissions == ["lambda:UpdateFunctionCode"]
    assert set(finding.evidence_edges) == {
        edge_id,
        make_edge_id(EdgeType.EXECUTION_ROLE, FUNCTION_ARN, ROLE_ARN),
    }
    assert finding.severity == SPEC.severity


def test_no_finding_when_action_absent() -> None:
    graph = _graph_with_function_and_role()
    _add_effective_permission(graph, ALICE_ARN, FUNCTION_ARN, ["lambda:GetFunction"])

    findings = detect(graph, ALICE_ARN, PermissionQuery(graph))

    assert findings == []


def test_no_finding_when_function_has_no_execution_role_edge() -> None:
    graph = new_graph()
    add_node(graph, Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN))
    add_node(graph, Node(id=FUNCTION_ARN, type=NodeType.LAMBDA_FUNCTION, name="my-function", arn=FUNCTION_ARN))
    _add_effective_permission(graph, ALICE_ARN, FUNCTION_ARN, ["lambda:UpdateFunctionCode"])

    findings = detect(graph, ALICE_ARN, PermissionQuery(graph))

    assert findings == []


def test_no_finding_when_execution_role_is_the_principal_itself() -> None:
    graph = new_graph()
    add_node(graph, Node(id=ROLE_ARN, type=NodeType.IAM_ROLE, name="lambda-exec-role", arn=ROLE_ARN))
    add_node(graph, Node(id=FUNCTION_ARN, type=NodeType.LAMBDA_FUNCTION, name="my-function", arn=FUNCTION_ARN))
    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.EXECUTION_ROLE, FUNCTION_ARN, ROLE_ARN),
            type=EdgeType.EXECUTION_ROLE,
            source=FUNCTION_ARN,
            target=ROLE_ARN,
        ),
    )
    _add_effective_permission(graph, ROLE_ARN, FUNCTION_ARN, ["lambda:UpdateFunctionCode"])

    findings = detect(graph, ROLE_ARN, PermissionQuery(graph))

    assert findings == []
