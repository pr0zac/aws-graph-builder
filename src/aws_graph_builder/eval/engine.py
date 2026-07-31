"""Orchestrates the policy evaluation engine over a structural IAM graph
(as produced by `graph.builder.build_iam_graph`): resolves each principal's
effective permissions and materializes them as `EffectivePermission` edges,
then evaluates every role's trust policy into `CanAssume`/`IdentifiesVia`
edges, then evaluates every S3/Lambda resource policy into further
`EffectivePermission` edges.

## Scoping (Phase 2, IAM-only -- see aws-graph-builder.md's phase split)

The structural graph at this point only contains IAM-domain nodes (no EC2/S3/
Lambda -- those land in Phase 4). `EffectivePermission` edges may only ever
point to a node that already exists in the graph, so in practice only grants
whose action pattern is IAM-shaped (`iam:...`) or fully generic (`"*"`, e.g.
`AdministratorAccess`) end up producing any materialized edges here --
`s3:*`/`ec2:*`/etc. grants simply never match any node's ARN since no such
nodes exist yet. This isn't special-cased anywhere in this module; it falls
directly out of what nodes exist to match `resource_matches` against, and
will change automatically once Phase 4 adds more node types.

For each `IamUser`/`IamRole` node (candidate principals -- `IamGroup` is
skipped as a source since groups can't call AWS APIs, though group nodes are
still valid grant *targets* like any other node with an ARN):

1. Gather identity statements from every attached `ManagedPolicy` (via
   `AttachedPolicy` edges) and every `InlinePolicy` (via `HasInlinePolicy`
   edges). AWS-managed policies never carry a stored `policy_document` (Phase
   1's `GetAccountAuthorizationDetails` doesn't return one) -- these are
   skipped gracefully; this is a known, expected gap, not an error.
2. Resolve its permission boundary (via `HasPermissionBoundary`), if any --
   again, a boundary policy with no available document (AWS-managed boundary)
   is treated as "no usable boundary data", i.e. the same as having no
   boundary at all, rather than blocking every grant defensively.
3. Call `simulator.resolve_grants` (passing every SCP statement currently in
   the graph -- see below) to get the surviving `Grant`s.
4. For every OTHER node in the graph with a non-`None` `arn`, check
   `resource_matches` against each grant's resource pattern; nodes with at
   least one match get exactly one `EffectivePermission` edge, whose
   `actions` is every distinct contributing action pattern, whose
   `resource_pattern` is the single contributing pattern (or a list of the
   distinct patterns if more than one contributed), whose `evaluated_from` is
   the deduplicated list of contributing evidence pointers, and whose
   `condition_unresolved` is `True` if any contributing grant had one.

## SCP statements

Every `ServiceControlPolicy` node currently in the graph has its
`properties["content"]` parsed once (not per-principal -- there's normally at
most a handful of SCPs in a real account, and Phase 4's Organizations scanner
only fetches SCPs already attached to *this* account, so they all apply
account-wide) and the resulting statements are passed as `resolve_grants`'s
`scp_statements` for every principal. If the graph has no
`ServiceControlPolicy` nodes at all (not in an org, or Organizations wasn't
reachable), `None` is passed instead of an empty list -- SCP filtering is
skipped entirely, the same as if the parameter didn't exist, rather than
treating "no SCP data available" as "an SCP that allows nothing". See
`eval/simulator.py`'s module docstring for the SCP intersection approximation
itself.

Finally, `trust.evaluate_trust_policies` and
`resource_policy.evaluate_resource_policies` each run once (not per-principal
-- they already iterate every `IamRole`/`S3Bucket`/`LambdaFunction` node
themselves).

Malformed policy documents (`parse_policy_document` raising `ValueError`) are
handled by skipping that specific policy for that principal -- there's no
logging infra in this module, so this fails silently rather than crashing the
whole evaluation, consistent with this being a best-effort static analysis
over potentially-messy real-world policy JSON.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from aws_graph_builder.eval.matcher import resource_matches
from aws_graph_builder.eval.policy_document import Statement, parse_policy_document
from aws_graph_builder.eval.resource_policy import evaluate_resource_policies
from aws_graph_builder.eval.simulator import Grant, resolve_grants
from aws_graph_builder.eval.trust import evaluate_trust_policies
from aws_graph_builder.graph.export import add_edge
from aws_graph_builder.graph.schema import Edge, EdgeType, NodeType, make_edge_id

_PRINCIPAL_NODE_TYPES = {NodeType.IAM_USER.value, NodeType.IAM_ROLE.value}


def _collect_identity_statements(graph: nx.MultiDiGraph, principal_arn: str) -> list[Statement]:
    statements: list[Statement] = []
    for _source, target, data in graph.out_edges(principal_arn, data=True):
        edge_type = data.get("type")
        target_data = graph.nodes[target]

        if edge_type == EdgeType.ATTACHED_POLICY.value:
            document = target_data.get("properties", {}).get("policy_document")
            if document is None:
                continue  # AWS-managed policy -- no document available, known gap.
            source = target  # ManagedPolicy node id is the policy's ARN.
        elif edge_type == EdgeType.HAS_INLINE_POLICY.value:
            document = target_data.get("properties", {}).get("policy_document")
            if document is None:
                continue
            policy_name = target_data.get("name", "")
            source = f"inline:{principal_arn}#{policy_name}"
        else:
            continue

        try:
            parsed = parse_policy_document(document, source=source)
        except ValueError:
            continue
        statements.extend(parsed.statements)

    return statements


def _collect_boundary_statements(graph: nx.MultiDiGraph, principal_arn: str) -> list[Statement] | None:
    for _source, target, data in graph.out_edges(principal_arn, data=True):
        if data.get("type") != EdgeType.HAS_PERMISSION_BOUNDARY.value:
            continue
        target_data = graph.nodes[target]
        document = target_data.get("properties", {}).get("policy_document")
        if document is None:
            # AWS-managed boundary policy, no document available -- treat as
            # "no usable boundary data" (same as no boundary at all).
            return None
        try:
            parsed = parse_policy_document(document, source=f"boundary:{target}")
        except ValueError:
            return None
        return parsed.statements
    return None  # No permission boundary at all.


def _collect_scp_statements(graph: nx.MultiDiGraph) -> list[Statement] | None:
    """Every statement from every `ServiceControlPolicy` node currently in
    the graph, or `None` if there are no such nodes at all (see module
    docstring: `None` means "skip SCP filtering", distinct from an empty list
    which would mean "every attached SCP allows nothing").
    """
    scp_nodes = [
        (node_id, data) for node_id, data in graph.nodes(data=True) if data.get("type") == NodeType.SERVICE_CONTROL_POLICY.value
    ]
    if not scp_nodes:
        return None

    statements: list[Statement] = []
    for node_id, data in scp_nodes:
        content = data.get("properties", {}).get("content")
        if content is None:
            continue
        try:
            parsed = parse_policy_document(content, source=f"scp:{node_id}")
        except ValueError:
            continue
        statements.extend(parsed.statements)
    return statements


def _materialize_effective_permissions(
    graph: nx.MultiDiGraph,
    principal_arn: str,
    grants: list[Grant],
    all_target_nodes: list[tuple[str, str]],
) -> None:
    for target_id, target_arn in all_target_nodes:
        # Self-targeting grants ARE materialized (not excluded): "principal P
        # can attach a policy to P's own identity" is a real, security-
        # relevant edge -- one of the most common real-world privesc
        # techniques is exactly this ("if you can modify your own identity's
        # permissions, you can escalate"). Suppressing it would make that
        # class of technique undetectable by Phase 3.
        matched = [grant for grant in grants if resource_matches(grant.resource_pattern, target_arn)]
        if not matched:
            continue

        actions = sorted({grant.action_pattern for grant in matched})
        resource_patterns = sorted({grant.resource_pattern for grant in matched})
        resource_pattern_value: str | list[str] = (
            resource_patterns[0] if len(resource_patterns) == 1 else resource_patterns
        )

        evaluated_from: list[dict[str, Any]] = []
        seen_evidence: set[tuple[Any, Any]] = set()
        for grant in matched:
            key = (grant.evidence.get("policy"), grant.evidence.get("sid"))
            if key in seen_evidence:
                continue
            seen_evidence.add(key)
            evaluated_from.append(dict(grant.evidence))

        condition_unresolved = any(grant.condition_unresolved for grant in matched)

        edge_id = make_edge_id(EdgeType.EFFECTIVE_PERMISSION, principal_arn, target_id)
        add_edge(
            graph,
            Edge(
                id=edge_id,
                type=EdgeType.EFFECTIVE_PERMISSION,
                source=principal_arn,
                target=target_id,
                properties={
                    "actions": actions,
                    "resource_pattern": resource_pattern_value,
                    "evaluated_from": evaluated_from,
                    "effect": "Allow",
                    "condition_unresolved": condition_unresolved,
                },
            ),
        )


def evaluate_iam_permissions(graph: nx.MultiDiGraph) -> None:
    """Mutate `graph` in place: materialize `EffectivePermission` edges for
    every `IamUser`/`IamRole` principal, then evaluate every role's trust
    policy into `CanAssume`/`IdentifiesVia` edges. See module docstring for
    the exact scoping and boundary/deny approximations involved.
    """
    principal_entries = [
        (node_id, data) for node_id, data in graph.nodes(data=True) if data.get("type") in _PRINCIPAL_NODE_TYPES
    ]
    # Snapshot of every node with an ARN, taken before any EffectivePermission
    # edges are added -- materialization only adds edges, never nodes, so this
    # stays valid across the whole principal loop below.
    all_target_nodes = [(node_id, data["arn"]) for node_id, data in graph.nodes(data=True) if data.get("arn") is not None]
    scp_statements = _collect_scp_statements(graph)

    for principal_arn, _data in principal_entries:
        identity_statements = _collect_identity_statements(graph, principal_arn)
        if not identity_statements:
            continue
        boundary_statements = _collect_boundary_statements(graph, principal_arn)
        grants = resolve_grants(
            identity_statements=identity_statements,
            boundary_statements=boundary_statements,
            scp_statements=scp_statements,
        )
        if not grants:
            continue
        _materialize_effective_permissions(graph, principal_arn, grants, all_target_nodes)

    evaluate_trust_policies(graph)
    evaluate_resource_policies(graph)
