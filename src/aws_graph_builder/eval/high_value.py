"""Detection of "high-value" principals: the AWS-equivalent of BloodHound's
Domain Admins -- a principal (`IamUser`/`IamRole`) with essentially
unrestricted control over the account.

Works directly off already-materialized `EffectivePermission` edges (see
`eval/simulator.py`'s module docstring for exactly what those edges mean and
the pattern-based approximations behind them) rather than re-running
`PermissionQuery.can()` against some arbitrary target node -- querying a
single target would conflate "has this specific target" with "has
everything". Instead this inspects each principal's outgoing
`EffectivePermission` edges directly: a principal is high-value if any one
edge grants a full-wildcard resource (`resource_pattern == "*"`) together
with an action pattern that is itself a full wildcard (`"*"`) or grants full
IAM control (`"iam:*"`) -- full IAM control is included because it lets a
principal grant itself anything else via the `attach_policy` privesc
technique (see `privesc/techniques/attach_policy.py`), making it just as much
"keys to the kingdom" as a bare `"*"` grant.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.matcher import action_matches
from aws_graph_builder.graph.schema import EdgeType, NodeType

# Same candidate-source convention as `eval/engine.py` and `privesc/engine.py`:
# only IamUser/IamRole nodes can hold or exercise permissions, so only they're
# eligible to be flagged high-value (an IamGroup or ManagedPolicy node could
# in principle end up as the source of an EffectivePermission edge only
# through a graph-construction bug, and even then shouldn't count).
_CANDIDATE_PRINCIPAL_TYPES = {NodeType.IAM_USER.value, NodeType.IAM_ROLE.value}

# Action patterns that, granted on Resource: "*", constitute "keys to the
# kingdom": a bare wildcard obviously grants everything, and full IAM control
# is equivalent in practice since it lets the principal grant itself anything
# else (see attach_policy).
_HIGH_VALUE_ACTION_PATTERNS = ("*", "iam:*")


def _grants_high_value_access(action_patterns: list[str]) -> bool:
    """True if `action_patterns` (an `EffectivePermission` edge's stored
    `properties.actions`) contains a pattern that itself matches -- i.e. is
    equal to or broader than -- one of the high-value action patterns above.
    Using `action_matches` (rather than raw string equality) keeps this
    consistent with how the rest of the codebase compares action patterns:
    an edge with an even-broader stored pattern (there isn't one broader
    than "*", but this stays robust to any future normalization) is still
    caught.
    """
    return any(
        action_matches(stored_pattern, high_value_pattern)
        for stored_pattern in action_patterns
        for high_value_pattern in _HIGH_VALUE_ACTION_PATTERNS
    )


def find_high_value_principals(graph: nx.MultiDiGraph) -> set[str]:
    """Return the set of node ids (`IamUser`/`IamRole` only) that are
    "high-value" per the rule above: at least one outgoing
    `EffectivePermission` edge whose `resource_pattern` is the full wildcard
    `"*"` and whose `actions` list contains a pattern matching `"*"` or
    `"iam:*"`.

    Must be called after `eval.engine.evaluate_iam_permissions` (and
    `eval.trust`/`eval.resource_policy`, if this graph came through the full
    pipeline) has materialized `EffectivePermission` edges -- this function
    does no evaluation of its own, purely a read over already-materialized
    edges, mirroring `PermissionQuery`'s read-only role in `simulator.py`.
    """
    high_value_ids: set[str] = set()
    for node_id, node_data in graph.nodes(data=True):
        if node_data.get("type") not in _CANDIDATE_PRINCIPAL_TYPES:
            continue
        for _source, _target, edge_data in graph.out_edges(node_id, data=True):
            if edge_data.get("type") != EdgeType.EFFECTIVE_PERMISSION.value:
                continue
            properties = edge_data.get("properties", {})
            if properties.get("resource_pattern") != "*":
                continue
            if _grants_high_value_access(properties.get("actions", [])):
                high_value_ids.add(node_id)
                break
    return high_value_ids
