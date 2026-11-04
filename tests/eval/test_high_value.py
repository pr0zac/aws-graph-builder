from __future__ import annotations

from aws_graph_builder.eval.high_value import find_high_value_principals
from aws_graph_builder.graph.export import add_edge, add_node, new_graph
from aws_graph_builder.graph.schema import Edge, EdgeType, Node, NodeType, make_edge_id

ACCOUNT_ID = "111111111111"
ADMIN_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/admin-role"
IAM_ADMIN_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/iam-admin"
S3_ONLY_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/s3-only"
SCOPED_WILDCARD_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/scoped-wildcard-role"
BUCKET_ARN = "arn:aws:s3:::some-bucket"


def _make_effective_permission_edge(
    graph, source: str, target: str, *, actions: list[str], resource_pattern: str
) -> None:
    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.EFFECTIVE_PERMISSION, source, target),
            type=EdgeType.EFFECTIVE_PERMISSION,
            source=source,
            target=target,
            properties={"actions": actions, "resource_pattern": resource_pattern},
        ),
    )


def test_principal_with_star_action_and_star_resource_is_flagged() -> None:
    graph = new_graph()
    add_node(graph, Node(id=ADMIN_ARN, type=NodeType.IAM_ROLE, name="admin-role", arn=ADMIN_ARN))
    add_node(graph, Node(id=BUCKET_ARN, type=NodeType.S3_BUCKET, name="some-bucket", arn=BUCKET_ARN))
    _make_effective_permission_edge(graph, ADMIN_ARN, BUCKET_ARN, actions=["*"], resource_pattern="*")

    assert find_high_value_principals(graph) == {ADMIN_ARN}


def test_principal_with_iam_star_action_and_star_resource_is_flagged() -> None:
    graph = new_graph()
    add_node(graph, Node(id=IAM_ADMIN_ARN, type=NodeType.IAM_USER, name="iam-admin", arn=IAM_ADMIN_ARN))
    add_node(graph, Node(id=BUCKET_ARN, type=NodeType.S3_BUCKET, name="some-bucket", arn=BUCKET_ARN))
    _make_effective_permission_edge(graph, IAM_ADMIN_ARN, BUCKET_ARN, actions=["iam:*"], resource_pattern="*")

    assert find_high_value_principals(graph) == {IAM_ADMIN_ARN}


def test_principal_with_only_s3_star_action_is_not_flagged() -> None:
    graph = new_graph()
    add_node(graph, Node(id=S3_ONLY_ARN, type=NodeType.IAM_USER, name="s3-only", arn=S3_ONLY_ARN))
    add_node(graph, Node(id=BUCKET_ARN, type=NodeType.S3_BUCKET, name="some-bucket", arn=BUCKET_ARN))
    _make_effective_permission_edge(graph, S3_ONLY_ARN, BUCKET_ARN, actions=["s3:*"], resource_pattern="*")

    assert find_high_value_principals(graph) == set()


def test_principal_with_star_action_but_scoped_resource_is_not_flagged() -> None:
    graph = new_graph()
    add_node(graph, Node(id=SCOPED_WILDCARD_ARN, type=NodeType.IAM_ROLE, name="scoped-wildcard-role", arn=SCOPED_WILDCARD_ARN))
    add_node(graph, Node(id=BUCKET_ARN, type=NodeType.S3_BUCKET, name="some-bucket", arn=BUCKET_ARN))
    _make_effective_permission_edge(
        graph, SCOPED_WILDCARD_ARN, BUCKET_ARN, actions=["*"], resource_pattern=f"{BUCKET_ARN}/*"
    )

    assert find_high_value_principals(graph) == set()


def test_non_principal_node_types_are_never_returned() -> None:
    """Even if a non-IamUser/IamRole node somehow had a matching outgoing
    EffectivePermission edge (shouldn't happen via the real pipeline, but
    this function must not assume that), it must never be returned.
    """
    graph = new_graph()
    group_arn = f"arn:aws:iam::{ACCOUNT_ID}:group/some-group"
    add_node(graph, Node(id=group_arn, type=NodeType.IAM_GROUP, name="some-group", arn=group_arn))
    add_node(graph, Node(id=BUCKET_ARN, type=NodeType.S3_BUCKET, name="some-bucket", arn=BUCKET_ARN))
    _make_effective_permission_edge(graph, group_arn, BUCKET_ARN, actions=["*"], resource_pattern="*")

    assert find_high_value_principals(graph) == set()


def test_multiple_high_value_principals_all_returned() -> None:
    graph = new_graph()
    add_node(graph, Node(id=ADMIN_ARN, type=NodeType.IAM_ROLE, name="admin-role", arn=ADMIN_ARN))
    add_node(graph, Node(id=IAM_ADMIN_ARN, type=NodeType.IAM_USER, name="iam-admin", arn=IAM_ADMIN_ARN))
    add_node(graph, Node(id=BUCKET_ARN, type=NodeType.S3_BUCKET, name="some-bucket", arn=BUCKET_ARN))
    _make_effective_permission_edge(graph, ADMIN_ARN, BUCKET_ARN, actions=["*"], resource_pattern="*")
    _make_effective_permission_edge(graph, IAM_ADMIN_ARN, BUCKET_ARN, actions=["iam:*"], resource_pattern="*")

    assert find_high_value_principals(graph) == {ADMIN_ARN, IAM_ADMIN_ARN}


def test_repeated_grants_do_not_repeat_pattern_matching_and_cache_is_per_graph(monkeypatch) -> None:
    """Materialized grants repeat the same action set for every target.

    Instrument the real matcher to enforce a work bound without a flaky timing
    threshold. A graph mutation must still be seen by the next invocation.
    """
    from aws_graph_builder.eval import high_value

    real_match = high_value.action_matches
    calls = []

    def measured(pattern, action):
        calls.append((pattern, action))
        return real_match(pattern, action)

    monkeypatch.setattr(high_value, "action_matches", measured)
    graph = new_graph()
    add_node(graph, Node(id=S3_ONLY_ARN, type=NodeType.IAM_USER, name="s3-only", arn=S3_ONLY_ARN))
    for index in range(20):
        _make_effective_permission_edge(graph, S3_ONLY_ARN, f"bucket-{index}", actions=["s3:*"], resource_pattern="*")
    assert find_high_value_principals(graph) == set()
    assert len(calls) <= 4
    _make_effective_permission_edge(graph, S3_ONLY_ARN, "bucket-0", actions=["*"], resource_pattern="*")
    assert find_high_value_principals(graph) == {S3_ONLY_ARN}
