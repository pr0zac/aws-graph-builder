from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.resource_policy import evaluate_resource_policies
from aws_graph_builder.graph.export import add_node, new_graph
from aws_graph_builder.graph.schema import EdgeType, Node, NodeType

ACCOUNT_ID = "111111111111"
ACCOUNT_ARN = f"arn:aws:iam::{ACCOUNT_ID}:root"
ALICE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/some-role"
BUCKET_ARN = "arn:aws:s3:::my-bucket"
FUNCTION_ARN = f"arn:aws:lambda:us-east-1:{ACCOUNT_ID}:function:my-function"
CROSS_ACCOUNT_ARN = "arn:aws:iam::222222222222:root"


def _base_graph(*, extra_nodes: list[Node] | None = None) -> nx.MultiDiGraph:
    graph = new_graph()
    add_node(graph, Node(id=ACCOUNT_ARN, type=NodeType.ACCOUNT, name=ACCOUNT_ID, arn=ACCOUNT_ARN))
    for node in extra_nodes or []:
        add_node(graph, node)
    return graph


def _add_bucket(graph: nx.MultiDiGraph, bucket_policy: dict | None, *, arn: str = BUCKET_ARN, name: str = "my-bucket") -> None:
    add_node(
        graph,
        Node(id=arn, type=NodeType.S3_BUCKET, name=name, arn=arn, properties={"bucket_policy": bucket_policy}),
    )


def _add_function(graph: nx.MultiDiGraph, resource_policy: dict | None) -> None:
    add_node(
        graph,
        Node(
            id=FUNCTION_ARN,
            type=NodeType.LAMBDA_FUNCTION,
            name="my-function",
            arn=FUNCTION_ARN,
            properties={"resource_policy": resource_policy},
        ),
    )


def _effective_permission_edges(graph: nx.MultiDiGraph) -> list[tuple[str, str, dict]]:
    return [
        (source, target, data)
        for source, target, data in graph.edges(data=True)
        if data.get("type") == EdgeType.EFFECTIVE_PERMISSION.value
    ]


def test_bucket_policy_grants_existing_iam_user_creates_effective_permission_edge() -> None:
    graph = _base_graph(extra_nodes=[Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN)])
    _add_bucket(
        graph,
        {
            "Statement": [
                {
                    "Sid": "AllowAlice",
                    "Effect": "Allow",
                    "Principal": {"AWS": ALICE_ARN},
                    "Action": "s3:GetObject",
                    "Resource": f"{BUCKET_ARN}/*",
                }
            ]
        },
    )

    evaluate_resource_policies(graph)

    edges = _effective_permission_edges(graph)
    assert len(edges) == 1
    source, target, data = edges[0]
    assert source == ALICE_ARN
    assert target == BUCKET_ARN
    props = data["properties"]
    assert props["actions"] == ["s3:GetObject"]
    assert props["resource_pattern"] == f"{BUCKET_ARN}/*"
    assert props["effect"] == "Allow"
    assert props["condition_unresolved"] is False
    assert props["evaluated_from"] == [{"policy": f"resource:{BUCKET_ARN}", "sid": "AllowAlice"}]


def test_bucket_policy_grants_existing_iam_role_creates_effective_permission_edge() -> None:
    graph = _base_graph(extra_nodes=[Node(id=ROLE_ARN, type=NodeType.IAM_ROLE, name="some-role", arn=ROLE_ARN)])
    _add_bucket(
        graph,
        {"Statement": [{"Effect": "Allow", "Principal": {"AWS": ROLE_ARN}, "Action": "s3:PutObject", "Resource": "*"}]},
    )

    evaluate_resource_policies(graph)

    edges = _effective_permission_edges(graph)
    assert len(edges) == 1
    assert edges[0][0] == ROLE_ARN
    assert edges[0][1] == BUCKET_ARN


def test_cross_account_arn_principal_creates_external_principal_node_and_edge() -> None:
    graph = _base_graph()
    _add_bucket(
        graph,
        {"Statement": [{"Effect": "Allow", "Principal": {"AWS": CROSS_ACCOUNT_ARN}, "Action": "s3:GetObject", "Resource": "*"}]},
    )

    evaluate_resource_policies(graph)

    assert CROSS_ACCOUNT_ARN in graph.nodes
    node_data = graph.nodes[CROSS_ACCOUNT_ARN]
    assert node_data["type"] == NodeType.EXTERNAL_PRINCIPAL.value
    assert node_data["arn"] == CROSS_ACCOUNT_ARN

    edges = _effective_permission_edges(graph)
    assert len(edges) == 1
    assert edges[0][0] == CROSS_ACCOUNT_ARN
    assert edges[0][1] == BUCKET_ARN


def test_wildcard_principal_creates_wildcard_external_principal_node_and_edge() -> None:
    graph = _base_graph()
    _add_bucket(
        graph,
        {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"{BUCKET_ARN}/*"}]},
    )

    evaluate_resource_policies(graph)

    assert "external:*" in graph.nodes
    assert graph.nodes["external:*"]["type"] == NodeType.EXTERNAL_PRINCIPAL.value

    edges = _effective_permission_edges(graph)
    assert len(edges) == 1
    assert edges[0][0] == "external:*"
    assert edges[0][1] == BUCKET_ARN


def test_service_principal_creates_service_principal_node_and_edge() -> None:
    graph = _base_graph()
    _add_function(
        graph,
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": FUNCTION_ARN,
                }
            ]
        },
    )

    evaluate_resource_policies(graph)

    assert "s3.amazonaws.com" in graph.nodes
    assert graph.nodes["s3.amazonaws.com"]["type"] == NodeType.SERVICE_PRINCIPAL.value

    edges = _effective_permission_edges(graph)
    assert len(edges) == 1
    assert edges[0][0] == "s3.amazonaws.com"
    assert edges[0][1] == FUNCTION_ARN


def test_lambda_function_with_resource_policy_produces_edge() -> None:
    graph = _base_graph(extra_nodes=[Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN)])
    _add_function(
        graph,
        {"Statement": [{"Effect": "Allow", "Principal": {"AWS": ALICE_ARN}, "Action": "lambda:InvokeFunction", "Resource": FUNCTION_ARN}]},
    )

    evaluate_resource_policies(graph)

    edges = _effective_permission_edges(graph)
    assert len(edges) == 1
    assert edges[0][0] == ALICE_ARN
    assert edges[0][1] == FUNCTION_ARN


def test_bucket_with_no_policy_produces_no_edges() -> None:
    graph = _base_graph()
    _add_bucket(graph, None)

    evaluate_resource_policies(graph)

    assert _effective_permission_edges(graph) == []


def test_function_with_no_resource_policy_produces_no_edges() -> None:
    graph = _base_graph()
    _add_function(graph, None)

    evaluate_resource_policies(graph)

    assert _effective_permission_edges(graph) == []


def test_multiple_statements_for_same_principal_merge_into_one_edge() -> None:
    graph = _base_graph(extra_nodes=[Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN)])
    _add_bucket(
        graph,
        {
            "Statement": [
                {
                    "Sid": "AllowGet",
                    "Effect": "Allow",
                    "Principal": {"AWS": ALICE_ARN},
                    "Action": "s3:GetObject",
                    "Resource": f"{BUCKET_ARN}/*",
                },
                {
                    "Sid": "AllowList",
                    "Effect": "Allow",
                    "Principal": {"AWS": ALICE_ARN},
                    "Action": "s3:ListBucket",
                    "Resource": BUCKET_ARN,
                },
            ]
        },
    )

    evaluate_resource_policies(graph)

    edges = _effective_permission_edges(graph)
    assert len(edges) == 1
    source, target, data = edges[0]
    assert source == ALICE_ARN
    assert target == BUCKET_ARN
    props = data["properties"]
    assert props["actions"] == ["s3:GetObject", "s3:ListBucket"]
    assert sorted(props["resource_pattern"]) == sorted([f"{BUCKET_ARN}/*", BUCKET_ARN])
    assert props["evaluated_from"] == [
        {"policy": f"resource:{BUCKET_ARN}", "sid": "AllowGet"},
        {"policy": f"resource:{BUCKET_ARN}", "sid": "AllowList"},
    ]


def test_multiple_principals_against_same_resource_each_get_their_own_edge() -> None:
    bob_arn = f"arn:aws:iam::{ACCOUNT_ID}:user/bob"
    graph = _base_graph(
        extra_nodes=[
            Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN),
            Node(id=bob_arn, type=NodeType.IAM_USER, name="bob", arn=bob_arn),
        ]
    )
    _add_bucket(
        graph,
        {
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": ALICE_ARN}, "Action": "s3:GetObject", "Resource": f"{BUCKET_ARN}/*"},
                {"Effect": "Allow", "Principal": {"AWS": bob_arn}, "Action": "s3:PutObject", "Resource": f"{BUCKET_ARN}/*"},
            ]
        },
    )

    evaluate_resource_policies(graph)

    edges = {(source, target) for source, target, _data in _effective_permission_edges(graph)}
    assert edges == {(ALICE_ARN, BUCKET_ARN), (bob_arn, BUCKET_ARN)}


def test_unresolvable_condition_still_granted_but_flagged() -> None:
    graph = _base_graph(extra_nodes=[Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN)])
    _add_bucket(
        graph,
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ALICE_ARN},
                    "Action": "s3:GetObject",
                    "Resource": f"{BUCKET_ARN}/*",
                    "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
                }
            ]
        },
    )

    evaluate_resource_policies(graph)

    edges = _effective_permission_edges(graph)
    assert len(edges) == 1
    assert edges[0][2]["properties"]["condition_unresolved"] is True


def test_deny_statement_produces_no_edge() -> None:
    graph = _base_graph(extra_nodes=[Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN)])
    _add_bucket(
        graph,
        {"Statement": [{"Effect": "Deny", "Principal": {"AWS": ALICE_ARN}, "Action": "s3:GetObject", "Resource": "*"}]},
    )

    evaluate_resource_policies(graph)

    assert _effective_permission_edges(graph) == []


def test_statement_with_no_principal_is_skipped() -> None:
    # Not a valid real-world bucket policy statement (Principal is required),
    # but parse_policy_document doesn't reject a missing Principal -- this
    # module must skip it defensively rather than crash.
    graph = _base_graph()
    _add_bucket(graph, {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})

    evaluate_resource_policies(graph)

    assert _effective_permission_edges(graph) == []


def test_malformed_policy_document_is_skipped_gracefully() -> None:
    graph = _base_graph()
    _add_bucket(graph, {"NotAStatementKey": []})

    # Should not raise.
    evaluate_resource_policies(graph)

    assert _effective_permission_edges(graph) == []
