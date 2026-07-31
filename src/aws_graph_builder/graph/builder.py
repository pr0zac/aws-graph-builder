"""Structural graph builder: `IamScanResult` (raw boto3 shapes) ->
`networkx.MultiDiGraph`, using `graph.schema`'s Node/Edge types.

Phase 1 is structural only: it wires up "X is attached to Y" relationships
that are directly present in the raw IAM data (memberships, attachments,
inline policies, permission boundaries, instance-profile-to-role links). It
deliberately does NOT create `CanAssume` or `IdentifiesVia` edges -- those
require evaluating `AssumeRolePolicyDocument` Principal blocks, which is a
Phase 2/3 concern (`eval/trust.py`). The raw trust policy is still stored on
each `IamRole` node's `properties` so that later phase can consume it.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from aws_graph_builder.graph.export import add_edge, add_node, new_graph
from aws_graph_builder.graph.schema import (
    Edge,
    EdgeType,
    Node,
    NodeType,
    inline_policy_id,
    make_edge_id,
)
from aws_graph_builder.scan.iam import IamScanResult


def _name_from_arn(arn: str) -> str:
    """Fallback display name for a resource we only ever see referenced by
    ARN (e.g. an AWS-managed policy attached to a principal, or a permission
    boundary that references a policy not otherwise present in the scan).
    """
    return arn.rsplit("/", 1)[-1]


def _properties_excluding(item: dict[str, Any], excluded: set[str]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if key not in excluded}


def _ensure_managed_policy_node(
    graph: nx.MultiDiGraph,
    seen_policy_arns: set[str],
    arn: str,
    name: str,
) -> None:
    """Create an AWS-managed `ManagedPolicy` node for `arn` if one doesn't
    already exist (customer-managed policies are seeded into
    `seen_policy_arns` up front, so this only ever creates AWS-managed
    placeholder nodes -- no policy document, since
    `GetAccountAuthorizationDetails` doesn't return AWS-managed policy
    documents). Dedupes by ARN so a policy attached to multiple principals
    produces exactly one node.
    """
    if arn in seen_policy_arns:
        return
    seen_policy_arns.add(arn)
    add_node(
        graph,
        Node(id=arn, type=NodeType.MANAGED_POLICY, name=name, arn=arn, properties={"managed_by": "aws"}),
    )


def _add_attached_policy_edges(
    graph: nx.MultiDiGraph,
    seen_policy_arns: set[str],
    principal_arn: str,
    attached_policies: list[dict[str, Any]],
) -> None:
    for attached in attached_policies:
        policy_arn = attached.get("PolicyArn")
        if not policy_arn:
            continue
        name = attached.get("PolicyName") or _name_from_arn(policy_arn)
        _ensure_managed_policy_node(graph, seen_policy_arns, policy_arn, name)
        add_edge(
            graph,
            Edge(
                id=make_edge_id(EdgeType.ATTACHED_POLICY, principal_arn, policy_arn),
                type=EdgeType.ATTACHED_POLICY,
                source=principal_arn,
                target=policy_arn,
            ),
        )


def _add_inline_policy_edges(
    graph: nx.MultiDiGraph,
    principal_arn: str,
    inline_policies: list[dict[str, Any]],
) -> None:
    for inline in inline_policies:
        policy_name = inline.get("PolicyName", "")
        inline_id = inline_policy_id(principal_arn, policy_name)
        add_node(
            graph,
            Node(
                id=inline_id,
                type=NodeType.INLINE_POLICY,
                name=policy_name,
                arn=None,
                properties={"policy_document": inline.get("PolicyDocument")},
            ),
        )
        add_edge(
            graph,
            Edge(
                id=make_edge_id(EdgeType.HAS_INLINE_POLICY, principal_arn, inline_id),
                type=EdgeType.HAS_INLINE_POLICY,
                source=principal_arn,
                target=inline_id,
            ),
        )


def _add_permission_boundary_edge(
    graph: nx.MultiDiGraph,
    seen_policy_arns: set[str],
    principal_arn: str,
    boundary: dict[str, Any] | None,
) -> None:
    if not boundary:
        return
    boundary_arn = boundary.get("PermissionsBoundaryArn")
    if not boundary_arn:
        return
    # The boundary may reference a policy not otherwise seen (e.g. an
    # AWS-managed policy used only as a boundary, never attached directly).
    _ensure_managed_policy_node(graph, seen_policy_arns, boundary_arn, _name_from_arn(boundary_arn))
    add_edge(
        graph,
        Edge(
            id=make_edge_id(EdgeType.HAS_PERMISSION_BOUNDARY, principal_arn, boundary_arn),
            type=EdgeType.HAS_PERMISSION_BOUNDARY,
            source=principal_arn,
            target=boundary_arn,
        ),
    )


_CUSTOMER_POLICY_EXCLUDED_KEYS = {"Arn", "PolicyName", "PolicyVersionList"}
_GROUP_EXCLUDED_KEYS = {"Arn", "GroupName", "GroupPolicyList", "AttachedManagedPolicies"}
_USER_EXCLUDED_KEYS = {"Arn", "UserName", "UserPolicyList", "GroupList", "AttachedManagedPolicies", "PermissionsBoundary"}
_ROLE_EXCLUDED_KEYS = {"Arn", "RoleName", "RolePolicyList", "AttachedManagedPolicies", "PermissionsBoundary", "InstanceProfileList"}
_INSTANCE_PROFILE_EXCLUDED_KEYS = {"Arn", "InstanceProfileName", "Roles"}


def build_iam_graph(scan_result: IamScanResult, *, account_id: str) -> nx.MultiDiGraph:
    """Convert a raw `IamScanResult` into a structural `MultiDiGraph`."""
    graph = new_graph()

    account_arn = f"arn:aws:iam::{account_id}:root"
    add_node(graph, Node(id=account_arn, type=NodeType.ACCOUNT, name=account_id, arn=account_arn))

    # ManagedPolicy nodes for customer-managed policies go in first, so the
    # AWS-managed dedup set starts seeded with every ARN that already has a
    # "real" node (with its policy document) -- attachments/boundaries that
    # reference these ARNs later must not overwrite them with a bare
    # managed_by="aws" placeholder.
    seen_policy_arns: set[str] = set()
    for policy in scan_result.customer_managed_policies:
        arn = policy["Arn"]
        seen_policy_arns.add(arn)
        default_version_id = policy.get("DefaultVersionId")
        document = None
        for version in policy.get("PolicyVersionList", []):
            if version.get("VersionId") == default_version_id:
                document = version.get("Document")
                break
        properties = _properties_excluding(policy, _CUSTOMER_POLICY_EXCLUDED_KEYS)
        properties["managed_by"] = "customer"
        if document is not None:
            properties["policy_document"] = document
        add_node(
            graph,
            Node(
                id=arn,
                type=NodeType.MANAGED_POLICY,
                name=policy.get("PolicyName", arn),
                arn=arn,
                properties=properties,
            ),
        )

    # Groups next, so the name->ARN map is ready before users' MemberOf edges.
    group_arn_by_name: dict[str, str] = {}
    for group in scan_result.groups:
        arn = group["Arn"]
        name = group.get("GroupName", arn)
        group_arn_by_name[name] = arn
        add_node(
            graph,
            Node(
                id=arn,
                type=NodeType.IAM_GROUP,
                name=name,
                arn=arn,
                properties=_properties_excluding(group, _GROUP_EXCLUDED_KEYS),
            ),
        )
        _add_attached_policy_edges(graph, seen_policy_arns, arn, group.get("AttachedManagedPolicies", []))
        _add_inline_policy_edges(graph, arn, group.get("GroupPolicyList", []))

    for user in scan_result.users:
        arn = user["Arn"]
        name = user.get("UserName", arn)
        add_node(
            graph,
            Node(
                id=arn,
                type=NodeType.IAM_USER,
                name=name,
                arn=arn,
                properties=_properties_excluding(user, _USER_EXCLUDED_KEYS),
            ),
        )

        for group_name in user.get("GroupList", []):
            group_arn = group_arn_by_name.get(group_name)
            if group_arn is None:
                continue
            add_edge(
                graph,
                Edge(
                    id=make_edge_id(EdgeType.MEMBER_OF, arn, group_arn),
                    type=EdgeType.MEMBER_OF,
                    source=arn,
                    target=group_arn,
                ),
            )

        _add_attached_policy_edges(graph, seen_policy_arns, arn, user.get("AttachedManagedPolicies", []))
        _add_inline_policy_edges(graph, arn, user.get("UserPolicyList", []))
        _add_permission_boundary_edge(graph, seen_policy_arns, arn, user.get("PermissionsBoundary"))

    for role in scan_result.roles:
        arn = role["Arn"]
        name = role.get("RoleName", arn)
        add_node(
            graph,
            Node(
                id=arn,
                type=NodeType.IAM_ROLE,
                name=name,
                arn=arn,
                # AssumeRolePolicyDocument is intentionally kept in
                # properties (not excluded) for eval/trust.py in a later
                # phase -- no CanAssume edges are derived from it here.
                properties=_properties_excluding(role, _ROLE_EXCLUDED_KEYS),
            ),
        )
        _add_attached_policy_edges(graph, seen_policy_arns, arn, role.get("AttachedManagedPolicies", []))
        _add_inline_policy_edges(graph, arn, role.get("RolePolicyList", []))
        _add_permission_boundary_edge(graph, seen_policy_arns, arn, role.get("PermissionsBoundary"))

    for profile in scan_result.instance_profiles:
        arn = profile["Arn"]
        name = profile.get("InstanceProfileName", arn)
        add_node(
            graph,
            Node(
                id=arn,
                type=NodeType.INSTANCE_PROFILE,
                name=name,
                arn=arn,
                properties=_properties_excluding(profile, _INSTANCE_PROFILE_EXCLUDED_KEYS),
            ),
        )
        for role in profile.get("Roles", []):
            role_arn = role.get("Arn")
            if role_arn is None or role_arn not in graph.nodes:
                continue
            add_edge(
                graph,
                Edge(
                    id=make_edge_id(EdgeType.ATTACHED_TO, arn, role_arn),
                    type=EdgeType.ATTACHED_TO,
                    source=arn,
                    target=role_arn,
                ),
            )

    for saml in scan_result.saml_providers:
        arn = saml.get("Arn")
        if arn is None:
            continue
        properties = _properties_excluding(saml, {"Arn"})
        properties["provider_type"] = "saml"
        add_node(
            graph,
            Node(id=arn, type=NodeType.IDENTITY_PROVIDER, name=_name_from_arn(arn), arn=arn, properties=properties),
        )

    for oidc in scan_result.oidc_providers:
        arn = oidc.get("Arn")
        if arn is None:
            continue
        properties = _properties_excluding(oidc, {"Arn"})
        properties["provider_type"] = "oidc"
        name = oidc.get("Url") or _name_from_arn(arn)
        add_node(
            graph,
            Node(id=arn, type=NodeType.IDENTITY_PROVIDER, name=name, arn=arn, properties=properties),
        )

    return graph
