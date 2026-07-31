from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.engine import evaluate_iam_permissions
from aws_graph_builder.graph.export import add_edge, add_node, new_graph
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
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/deploy-role"
ALICE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
BOB_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/bob"


def _build_structural_graph() -> nx.MultiDiGraph:
    """Hand-built structural graph mimicking what `graph.builder.build_iam_graph`
    would produce: an Account, a role with an inline policy granting
    `iam:CreateAccessKey` on `Resource: "*"` and a trust policy naming alice,
    plus two IamUser nodes.
    """
    graph = new_graph()

    add_node(graph, Node(id=ACCOUNT_ARN, type=NodeType.ACCOUNT, name=ACCOUNT_ID, arn=ACCOUNT_ARN))
    add_node(graph, Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN))
    add_node(graph, Node(id=BOB_ARN, type=NodeType.IAM_USER, name="bob", arn=BOB_ARN))

    add_node(
        graph,
        Node(
            id=ROLE_ARN,
            type=NodeType.IAM_ROLE,
            name="deploy-role",
            arn=ROLE_ARN,
            properties={
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Sid": "AllowAlice",
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Principal": {"AWS": ALICE_ARN},
                        }
                    ]
                }
            },
        ),
    )

    inline_id = inline_policy_id(ROLE_ARN, "CreateKeys")
    add_node(
        graph,
        Node(
            id=inline_id,
            type=NodeType.INLINE_POLICY,
            name="CreateKeys",
            arn=None,
            properties={
                "policy_document": {
                    "Statement": [
                        {
                            "Sid": "AllowCreateAccessKey",
                            "Effect": "Allow",
                            "Action": "iam:CreateAccessKey",
                            "Resource": "*",
                        }
                    ]
                }
            },
        ),
    )
    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.HAS_INLINE_POLICY, ROLE_ARN, inline_id),
            type=EdgeType.HAS_INLINE_POLICY,
            source=ROLE_ARN,
            target=inline_id,
        ),
    )

    return graph


def test_effective_permission_edges_materialized_for_iam_shaped_grant() -> None:
    graph = _build_structural_graph()

    evaluate_iam_permissions(graph)

    effective_permission_edges = {
        (source, target): data
        for source, target, data in graph.edges(data=True)
        if data.get("type") == EdgeType.EFFECTIVE_PERMISSION.value
    }

    # The role's inline policy grants iam:CreateAccessKey on "*", which
    # matches every other node's ARN in this small graph: the Account node
    # and both IamUsers.
    assert (ROLE_ARN, ACCOUNT_ARN) in effective_permission_edges
    assert (ROLE_ARN, ALICE_ARN) in effective_permission_edges
    assert (ROLE_ARN, BOB_ARN) in effective_permission_edges

    edge_to_alice = effective_permission_edges[(ROLE_ARN, ALICE_ARN)]
    props = edge_to_alice["properties"]
    assert props["actions"] == ["iam:CreateAccessKey"]
    assert props["resource_pattern"] == "*"
    assert props["effect"] == "Allow"
    assert props["condition_unresolved"] is False
    assert props["evaluated_from"] == [{"policy": f"inline:{ROLE_ARN}#CreateKeys", "sid": "AllowCreateAccessKey"}]

    # Self-targeting grants ARE materialized: the role's inline policy grants
    # iam:CreateAccessKey on "*", which also matches the role's own ARN.
    # This is intentional -- "principal can modify its own identity" is
    # exactly the shape of the most common real-world privesc techniques
    # (e.g. attaching a policy to yourself), so Phase 3 needs this edge to
    # detect that class of technique.
    assert (ROLE_ARN, ROLE_ARN) in effective_permission_edges

    # Exactly one EffectivePermission edge per (source, target) pair.
    role_to_alice_count = sum(
        1
        for _u, _v, data in graph.edges(data=True)
        if data.get("type") == EdgeType.EFFECTIVE_PERMISSION.value
    )
    assert role_to_alice_count == len(effective_permission_edges)


def test_can_assume_edges_also_created_by_the_same_call() -> None:
    graph = _build_structural_graph()

    evaluate_iam_permissions(graph)

    can_assume_edges = [
        (source, target) for source, target, data in graph.edges(data=True) if data.get("type") == EdgeType.CAN_ASSUME.value
    ]
    assert can_assume_edges == [(ALICE_ARN, ROLE_ARN)]


def test_iam_group_is_not_a_grant_source() -> None:
    """IamGroup nodes are skipped as EffectivePermission *sources* (groups
    can't call AWS APIs) even though they're still just as valid grant
    *targets* as any other node with an ARN.
    """
    graph = _build_structural_graph()
    group_arn = f"arn:aws:iam::{ACCOUNT_ID}:group/admins"
    add_node(graph, Node(id=group_arn, type=NodeType.IAM_GROUP, name="admins", arn=group_arn))

    evaluate_iam_permissions(graph)

    # The group is a valid target (the role's "*" resource grant matches it)...
    assert (ROLE_ARN, group_arn) in {
        (source, target)
        for source, target, data in graph.edges(data=True)
        if data.get("type") == EdgeType.EFFECTIVE_PERMISSION.value
    }
    # ...but never a source, since no EffectivePermission edge originates
    # from the group itself (it has no identity policies of its own here).
    sources = {
        source
        for source, _target, data in graph.edges(data=True)
        if data.get("type") == EdgeType.EFFECTIVE_PERMISSION.value
    }
    assert group_arn not in sources


def test_aws_managed_policy_with_no_document_is_skipped_gracefully() -> None:
    graph = _build_structural_graph()
    aws_managed_arn = f"arn:aws:iam::{ACCOUNT_ID}:policy/SomeAwsManagedPolicy"
    add_node(
        graph,
        Node(id=aws_managed_arn, type=NodeType.MANAGED_POLICY, name="SomeAwsManagedPolicy", arn=aws_managed_arn, properties={"managed_by": "aws"}),
    )
    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.ATTACHED_POLICY, BOB_ARN, aws_managed_arn),
            type=EdgeType.ATTACHED_POLICY,
            source=BOB_ARN,
            target=aws_managed_arn,
        ),
    )

    # Should not raise, and bob (who has no other identity statements) should
    # get no EffectivePermission edges at all.
    evaluate_iam_permissions(graph)

    bob_sources = [
        (source, target)
        for source, target, data in graph.edges(data=True)
        if data.get("type") == EdgeType.EFFECTIVE_PERMISSION.value and source == BOB_ARN
    ]
    assert bob_sources == []
