from __future__ import annotations

from aws_graph_builder.eval.policy_document import Statement
from aws_graph_builder.eval.simulator import PermissionQuery, resolve_grants
from aws_graph_builder.graph.export import add_edge, add_node, new_graph
from aws_graph_builder.graph.schema import Edge, EdgeType, Node, NodeType, make_edge_id

ALICE_ARN = "arn:aws:iam::111111111111:user/alice"
POLICY_ARN = "arn:aws:iam::111111111111:policy/MyPolicy"
BOUNDARY_ARN = "arn:aws:iam::111111111111:policy/Boundary"


def _statement(
    *,
    effect: str,
    actions: list[str],
    resources: list[str],
    sid: str | None = None,
    conditions: dict[str, dict[str, object]] | None = None,
    source: str = POLICY_ARN,
) -> Statement:
    return Statement(
        sid=sid,
        effect=effect,
        actions=actions,
        not_actions=[],
        resources=resources,
        not_resources=[],
        conditions=conditions or {},
        principal=None,
        source=source,
    )


def test_a_allow_with_no_boundary_or_deny_is_granted() -> None:
    allow = _statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"], sid="AllowCreateKey")

    grants = resolve_grants(identity_statements=[allow], boundary_statements=None)

    assert len(grants) == 1
    grant = grants[0]
    assert grant.action_pattern == "iam:CreateAccessKey"
    assert grant.resource_pattern == "*"
    assert grant.evidence == {"policy": POLICY_ARN, "sid": "AllowCreateKey"}
    assert grant.condition_unresolved is False


def test_b_allow_plus_explicit_deny_on_same_action_and_resource_drops_grant() -> None:
    # Unambiguous, concrete (non-wildcard) case: deny wins even though there's
    # an allow -- the single highest-value behavior to get right.
    allow = _statement(
        effect="Allow",
        actions=["iam:CreateAccessKey"],
        resources=["arn:aws:iam::111111111111:user/alice"],
    )
    deny = _statement(
        effect="Deny",
        actions=["iam:CreateAccessKey"],
        resources=["arn:aws:iam::111111111111:user/alice"],
    )

    grants = resolve_grants(identity_statements=[allow, deny], boundary_statements=None)

    assert grants == []


def test_c_allow_plus_deny_on_disjoint_action_still_granted() -> None:
    allow = _statement(
        effect="Allow",
        actions=["iam:CreateAccessKey"],
        resources=["arn:aws:iam::111111111111:user/alice"],
    )
    deny = _statement(
        effect="Deny",
        actions=["iam:DeleteUser"],
        resources=["arn:aws:iam::111111111111:user/alice"],
    )

    grants = resolve_grants(identity_statements=[allow, deny], boundary_statements=None)

    assert len(grants) == 1
    assert grants[0].action_pattern == "iam:CreateAccessKey"


def test_d_allow_plus_boundary_that_also_allows_is_granted() -> None:
    allow = _statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"])
    boundary_allow = _statement(
        effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"], source=f"boundary:{BOUNDARY_ARN}"
    )

    grants = resolve_grants(identity_statements=[allow], boundary_statements=[boundary_allow])

    assert len(grants) == 1
    assert grants[0].action_pattern == "iam:CreateAccessKey"


def test_e_allow_plus_boundary_without_the_action_is_not_granted() -> None:
    # Exercises the documented boundary-intersection approximation
    # (simulator.py module docstring): an identity-ALLOW grant only survives
    # if some boundary-ALLOW statement's patterns "possibly overlap" it via
    # the symmetric wildcard check. Here the boundary only allows a
    # completely different, non-overlapping action, so the grant is dropped.
    allow = _statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"])
    boundary_allow = _statement(
        effect="Allow", actions=["s3:GetObject"], resources=["*"], source=f"boundary:{BOUNDARY_ARN}"
    )

    grants = resolve_grants(identity_statements=[allow], boundary_statements=[boundary_allow])

    assert grants == []


def test_f_unresolvable_condition_still_granted_but_flagged() -> None:
    allow = _statement(
        effect="Allow",
        actions=["iam:CreateAccessKey"],
        resources=["*"],
        conditions={"StringEquals": {"aws:username": "alice"}},
    )

    grants = resolve_grants(identity_statements=[allow], boundary_statements=None)

    assert len(grants) == 1
    assert grants[0].condition_unresolved is True


def test_h_allow_plus_scp_that_also_allows_is_granted() -> None:
    allow = _statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"])
    scp_allow = _statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"], source="scp:policy-1")

    grants = resolve_grants(identity_statements=[allow], boundary_statements=None, scp_statements=[scp_allow])

    assert len(grants) == 1
    assert grants[0].action_pattern == "iam:CreateAccessKey"


def test_i_allow_plus_scp_without_the_action_is_not_granted() -> None:
    # Mirrors test_e_...'s boundary-not-included case: an SCP, like a
    # boundary, can only restrict -- a non-overlapping SCP allow set drops
    # the grant entirely.
    allow = _statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"])
    scp_allow = _statement(effect="Allow", actions=["s3:GetObject"], resources=["*"], source="scp:policy-1")

    grants = resolve_grants(identity_statements=[allow], boundary_statements=None, scp_statements=[scp_allow])

    assert grants == []


def test_j_scp_explicit_deny_drops_grant_even_though_identity_and_boundary_allow() -> None:
    allow = _statement(
        effect="Allow",
        actions=["iam:CreateAccessKey"],
        resources=["arn:aws:iam::111111111111:user/alice"],
    )
    boundary_allow = _statement(
        effect="Allow",
        actions=["iam:CreateAccessKey"],
        resources=["arn:aws:iam::111111111111:user/alice"],
        source=f"boundary:{BOUNDARY_ARN}",
    )
    scp_deny = _statement(
        effect="Deny",
        actions=["iam:CreateAccessKey"],
        resources=["arn:aws:iam::111111111111:user/alice"],
        source="scp:policy-1",
    )

    grants = resolve_grants(
        identity_statements=[allow],
        boundary_statements=[boundary_allow],
        scp_statements=[scp_deny],
    )

    assert grants == []


def test_k_multiple_attached_scps_allow_statements_union_correctly() -> None:
    # A grant covered by SCP #2 but not SCP #1 still survives -- every
    # attached SCP's Allow statements are unioned together before the
    # overlap check, not intersected pairwise.
    allow = _statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"])
    scp_1_allow = _statement(effect="Allow", actions=["s3:GetObject"], resources=["*"], source="scp:policy-1")
    scp_2_allow = _statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"], source="scp:policy-2")

    grants = resolve_grants(
        identity_statements=[allow],
        boundary_statements=None,
        scp_statements=[scp_1_allow, scp_2_allow],
    )

    assert len(grants) == 1
    assert grants[0].action_pattern == "iam:CreateAccessKey"


def test_l_scp_statements_none_skips_scp_filtering_entirely() -> None:
    # Default behavior (no scp_statements passed) must be identical to
    # before this parameter existed.
    allow = _statement(effect="Allow", actions=["iam:CreateAccessKey"], resources=["*"])

    grants = resolve_grants(identity_statements=[allow], boundary_statements=None)

    assert len(grants) == 1


def test_g_permission_query_can_and_evidence_against_hand_built_graph() -> None:
    graph = new_graph()
    add_node(graph, Node(id=ALICE_ARN, type=NodeType.IAM_USER, name="alice", arn=ALICE_ARN))
    add_node(graph, Node(id=POLICY_ARN, type=NodeType.MANAGED_POLICY, name="MyPolicy", arn=POLICY_ARN))

    matching_edge_id = make_edge_id(EdgeType.EFFECTIVE_PERMISSION, ALICE_ARN, POLICY_ARN)
    add_edge(
        graph,
        Edge(
            id=matching_edge_id,
            type=EdgeType.EFFECTIVE_PERMISSION,
            source=ALICE_ARN,
            target=POLICY_ARN,
            properties={
                "actions": ["iam:*"],
                "resource_pattern": "*",
                "evaluated_from": [{"policy": POLICY_ARN, "sid": None}],
                "effect": "Allow",
                "condition_unresolved": False,
            },
        ),
    )

    query = PermissionQuery(graph)

    assert query.can(ALICE_ARN, "iam:CreateAccessKey", POLICY_ARN) is True
    assert query.evidence(ALICE_ARN, "iam:CreateAccessKey", POLICY_ARN) == [matching_edge_id]

    assert query.can(ALICE_ARN, "s3:GetObject", POLICY_ARN) is False
    assert query.evidence(ALICE_ARN, "s3:GetObject", POLICY_ARN) == []

    # No edge at all between this pair.
    assert query.can(POLICY_ARN, "iam:CreateAccessKey", ALICE_ARN) is False
