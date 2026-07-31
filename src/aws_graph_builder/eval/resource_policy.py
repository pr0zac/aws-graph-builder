"""S3 bucket policies / Lambda resource policies -> `EffectivePermission`
edges.

Structurally, a resource policy (S3 `bucket_policy`, Lambda
`resource_policy`) is shaped just like a trust policy: `Principal` blocks,
`Effect`, `Action`, and (usually) an explicit `Resource`. But it grants OTHER
principals access TO this resource, not permission to assume a role -- so the
edge it produces is an `EffectivePermission` edge FROM the resolved principal
TO the resource node, not a `CanAssume` edge.

This module reuses `eval/trust.py`'s shared, non-private principal-value
resolvers (`resolve_aws_principal`/`resolve_federated_principal`/
`resolve_service_principal`/`normalize_principal_values`) rather than
duplicating that ~80-line Principal-handling dance: those functions only
answer "which node does this Principal VALUE refer to" (creating an
`ExternalPrincipal`/`ServicePrincipal` node if needed) and know nothing about
trust policies specifically. What's different here is entirely in how the
resolved node id gets used: no MFA/ExternalId condition extraction (a
trust-specific concept that doesn't apply to a resource grant), and the
resulting edge is `EffectivePermission` with `eval/simulator.py`'s `Grant`
shape and `eval/engine.py`'s `_materialize_effective_permissions` merge
approach, not `trust.py`'s edge shape.

Like `eval/simulator.py`, statements using `NotAction`/`NotResource` are
skipped entirely (same documented, out-of-scope gap: full negation semantics
require enumerating a pattern's complement).

Conditions follow the same conservative treatment as `eval/simulator.py`'s
`Grant`s: a statement whose `Condition` block isn't statically resolvable
(`matcher.condition_matches` returning `None`) is still granted, flagged
`condition_unresolved=True` rather than guessed either way.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from aws_graph_builder.eval.matcher import condition_matches
from aws_graph_builder.eval.policy_document import parse_policy_document
from aws_graph_builder.eval.simulator import Grant
from aws_graph_builder.eval.trust import (
    normalize_principal_values,
    resolve_aws_principal,
    resolve_federated_principal,
    resolve_service_principal,
)
from aws_graph_builder.graph.export import add_edge
from aws_graph_builder.graph.schema import Edge, EdgeType, NodeType, make_edge_id

# Node type -> the properties key its raw resource policy is stored under
# (see graph.builder.add_s3_buckets_to_graph / add_lambda_functions_to_graph).
_RESOURCE_POLICY_PROPERTY_KEYS = {
    NodeType.S3_BUCKET.value: "bucket_policy",
    NodeType.LAMBDA_FUNCTION.value: "resource_policy",
}


def _account_id_from_graph(graph: nx.MultiDiGraph) -> str:
    """Extract this scan's account id from the (single, always-present)
    `Account` node's arn (`arn:aws:iam::ACCOUNT:root`). Resource ARNs aren't
    used for this: S3 bucket ARNs (`arn:aws:s3:::bucket-name`) famously have
    no account segment at all, so deriving "this resource's own account" from
    its own ARN isn't reliable the way it is for IAM role ARNs in trust.py.
    Returns `""` (never matches any bare account id / root ARN) if no
    `Account` node is present -- defensive, shouldn't normally happen.
    """
    for _node_id, data in graph.nodes(data=True):
        if data.get("type") == NodeType.ACCOUNT.value:
            arn = data.get("arn") or ""
            parts = arn.split(":")
            return parts[4] if len(parts) > 4 else ""
    return ""


def _resolve_statement_principals(
    graph: nx.MultiDiGraph,
    arn_to_node: dict[str, str],
    principal: dict[str, Any],
    own_account_id: str,
) -> list[str]:
    """Resolve every value in a statement's `Principal` block to node ids,
    via the same shared resolvers `eval/trust.py` uses for trust policies.
    """
    node_ids: list[str] = []

    aws_values = normalize_principal_values(principal.get("AWS"))
    raw_value = principal.get("__raw__")
    if isinstance(raw_value, str):
        aws_values.append(raw_value)
    for value in aws_values:
        node_id, _is_account = resolve_aws_principal(graph, arn_to_node, value, own_account_id)
        if node_id is not None:
            node_ids.append(node_id)

    for value in normalize_principal_values(principal.get("Federated")):
        idp_node_id = resolve_federated_principal(graph, arn_to_node, value)
        if idp_node_id is not None:
            node_ids.append(idp_node_id)

    for value in normalize_principal_values(principal.get("Service")):
        node_ids.append(resolve_service_principal(graph, value))

    return node_ids


def _materialize_resource_grant_edge(
    graph: nx.MultiDiGraph,
    principal_node_id: str,
    resource_id: str,
    grants: list[Grant],
) -> None:
    """Merge `grants` (every surviving (action, resource) pattern pulled from
    this resource's policy for `principal_node_id`) into exactly one
    `EffectivePermission` edge, the same merge shape
    `eval/engine.py`'s `_materialize_effective_permissions` uses: actions
    deduped, resource pattern(s) deduped (a single value if only one distinct
    pattern contributed, else a sorted list), evidence deduplicated by
    (policy, sid), and `condition_unresolved` true if any contributing grant
    had it.
    """
    actions = sorted({grant.action_pattern for grant in grants})
    resource_patterns = sorted({grant.resource_pattern for grant in grants})
    resource_pattern_value: str | list[str] = (
        resource_patterns[0] if len(resource_patterns) == 1 else resource_patterns
    )

    evaluated_from: list[dict[str, Any]] = []
    seen_evidence: set[tuple[Any, Any]] = set()
    for grant in grants:
        key = (grant.evidence.get("policy"), grant.evidence.get("sid"))
        if key in seen_evidence:
            continue
        seen_evidence.add(key)
        evaluated_from.append(dict(grant.evidence))

    condition_unresolved = any(grant.condition_unresolved for grant in grants)

    edge_id = make_edge_id(EdgeType.EFFECTIVE_PERMISSION, principal_node_id, resource_id)
    add_edge(
        graph,
        Edge(
            id=edge_id,
            type=EdgeType.EFFECTIVE_PERMISSION,
            source=principal_node_id,
            target=resource_id,
            properties={
                "actions": actions,
                "resource_pattern": resource_pattern_value,
                "evaluated_from": evaluated_from,
                "effect": "Allow",
                "condition_unresolved": condition_unresolved,
            },
        ),
    )


def evaluate_resource_policies(graph: nx.MultiDiGraph) -> None:
    """Mutate `graph` in place: for every `S3Bucket`/`LambdaFunction` node
    carrying a raw resource policy (`properties["bucket_policy"]` /
    `properties["resource_policy"]`, `None`/absent skipped), resolve every
    `Allow` statement's `Principal` block into `EffectivePermission` edges
    FROM the resolved principal node(s) TO the resource node. See module
    docstring for the exact approximations involved.

    Malformed policy documents (`parse_policy_document` raising `ValueError`)
    are handled by skipping that specific resource's policy, mirroring
    `eval/engine.py`/`eval/trust.py`'s defensive handling.
    """
    own_account_id = _account_id_from_graph(graph)
    arn_to_node: dict[str, str] = {data["arn"]: node_id for node_id, data in graph.nodes(data=True) if data.get("arn")}

    resource_entries = [
        (node_id, data) for node_id, data in graph.nodes(data=True) if data.get("type") in _RESOURCE_POLICY_PROPERTY_KEYS
    ]

    for resource_id, data in resource_entries:
        property_key = _RESOURCE_POLICY_PROPERTY_KEYS[data["type"]]
        policy = data.get("properties", {}).get(property_key)
        if policy is None:
            continue
        try:
            parsed = parse_policy_document(policy, source=f"resource:{resource_id}")
        except ValueError:
            continue

        grants_by_principal: dict[str, list[Grant]] = {}
        for statement in parsed.statements:
            if statement.effect != "Allow":
                continue
            if not statement.principal:
                continue
            if statement.not_actions or statement.not_resources:
                continue  # Unsupported negation semantics -- see module docstring.

            resolved = condition_matches(statement.conditions)
            if resolved is False:
                continue  # matcher.py never returns False today, but handled defensively.
            condition_unresolved = resolved is None

            principal_node_ids = _resolve_statement_principals(graph, arn_to_node, statement.principal, own_account_id)

            for principal_node_id in principal_node_ids:
                for action_pattern in statement.actions:
                    for resource_pattern in statement.resources:
                        grants_by_principal.setdefault(principal_node_id, []).append(
                            Grant(
                                action_pattern=action_pattern,
                                resource_pattern=resource_pattern,
                                evidence={"policy": statement.source, "sid": statement.sid},
                                condition_unresolved=condition_unresolved,
                            )
                        )

        for principal_node_id, grants in grants_by_principal.items():
            _materialize_resource_grant_edge(graph, principal_node_id, resource_id, grants)
