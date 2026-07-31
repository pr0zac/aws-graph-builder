"""Statement-level allow/deny/boundary resolution ("simulation") and
`PermissionQuery`, the read side used against already-materialized
`EffectivePermission` edges.

## Scope and approximations (read this before changing this module)

This module works with *patterns* (e.g. `"iam:Create*"`, `"arn:aws:iam::*:user/*"`),
never with a concrete, fully-enumerated action/resource pair. Precise policy
simulation (as `iam:SimulatePrincipalPolicy` does) requires either enumerating
every concrete IAM action against every statement, or a real pattern-
intersection algorithm (does the *set* of strings matched by pattern A overlap
with the set matched by pattern B?) -- both are more machinery than Phase 2's
scope warrants. Instead:

- **Deny-vs-allow** and **boundary-vs-identity** overlap are both decided by
  a symmetric wildcard check: two patterns `p` and `q` are treated as
  "possibly overlapping" if `action_matches(p, q) or action_matches(q, p)`
  (and the same for resources). This is exact for concrete (non-wildcard)
  strings compared against each other or against a wildcard pattern, and is a
  conservative *approximation* for wildcard-vs-wildcard comparisons (e.g.
  `"iam:Get*"` vs `"iam:List*"` are treated as non-overlapping even though
  neither contains the other, which is actually correct here since their
  matched sets are genuinely disjoint; but two patterns whose matched sets
  partially overlap without either containing the other -- e.g. `"iam:*Key*"`
  vs `"iam:Create*"` -- are also treated as non-overlapping by this check,
  which is a real gap, not a fabricated one. Getting this fully right needs
  a proper pattern-intersection algorithm; that's out of scope for Phase 2 and
  is a documented, acceptable limitation. Deny statements written with
  concrete actions/resources (by far the common case, and the case this
  module's tests deliberately target) are handled correctly.

- **Permission boundaries** can only ever *restrict*, never grant. A precise
  implementation would compute `identity ∩ boundary` at the level of concrete
  actions. Here, an identity-ALLOW `(action_pattern, resource_pattern)` grant
  survives boundary intersection only if there exists at least one
  boundary-ALLOW statement whose own `(action_pattern, resource_pattern)`
  "possibly overlaps" the identity grant's patterns, using the same symmetric
  wildcard check described above. A boundary with no matching ALLOW statement
  for a given identity grant causes that grant to be dropped entirely (no
  partial grants). This is a deliberately conservative approximation of true
  boundary intersection -- see the module-level note above for exactly where
  it's imprecise.

- **`NotAction`/`NotResource`** are not evaluated by this module (a statement
  using either contributes no Grant/deny-check at all, from either identity,
  boundary, or deny statements). Full negation semantics require enumerating
  the complement of a pattern set, which is out of scope for Phase 2. This is
  a known, documented gap -- most real-world Allow statements use `Action`/
  `Resource`, not their negated forms, so this doesn't affect the common case.

- **Conditions**: an identity-ALLOW statement whose `Condition` block cannot
  be staticly resolved (see `matcher.condition_matches`) is still granted
  (conservative inclusion, not exclusion -- a security tool should surface
  possible risk, not hide it) but flagged `condition_unresolved=True` on the
  resulting `Grant`.

- **Service Control Policies (SCPs)**, like permission boundaries, can only
  ever *restrict*, never grant, an identity-level Allow -- and are applied
  via the exact same symmetric wildcard-overlap check described above for
  boundary intersection, with the same imprecision for wildcard-vs-wildcard
  comparisons. Real AWS SCP evaluation is more involved than this module
  models: SCPs live at every level of an org hierarchy (account, OU, root)
  and the *effective* SCP for an account is the intersection of every level
  above it, with per-policy-type enablement toggles this tool has no visibility
  into. This module doesn't attempt any of that -- `resolve_grants`'s optional
  `scp_statements` parameter is simply every statement from every SCP
  currently attached to *this* account (Phase 4's Organizations scanner only
  fetches policies already attached to the account being scanned, so treating
  them as uniformly account-wide is accurate for what's actually fetched, even
  though it elides the multi-level-hierarchy nuance). When more than one SCP
  is attached, every SCP's Allow statements are unioned together into a single
  "SCP allow set" before the overlap check -- an identity-ALLOW grant survives
  only if it overlaps at least one Allow statement from *any* attached SCP,
  not necessarily the same one. Every SCP's explicit Deny statements are
  likewise unioned and applied via the same explicit-deny-wins overlap check
  used for identity-level denies -- an SCP deny can veto a grant exactly as an
  identity deny can. Passing `scp_statements=None` (the default) skips SCP
  filtering entirely, identical to today's behavior before this parameter
  existed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx

from aws_graph_builder.eval.matcher import (
    action_matches,
    condition_matches,
    resource_matches,
)
from aws_graph_builder.eval.policy_document import Statement
from aws_graph_builder.graph.schema import EdgeType


@dataclass
class Grant:
    """One resolved, surviving (action_pattern, resource_pattern) grant for
    a principal, after boundary intersection and explicit-deny filtering.
    Still pattern-form, not enumerated to concrete actions -- see this
    module's docstring.
    """

    action_pattern: str
    resource_pattern: str
    evidence: dict[str, Any]
    condition_unresolved: bool


def _expand_pairs(statements: list[Statement], *, effect: str) -> list[tuple[str, str, Statement]]:
    """Expand every (action, resource) combination out of each statement
    with the given `effect`, skipping any statement that uses `NotAction`/
    `NotResource` (unsupported -- see module docstring).
    """
    pairs: list[tuple[str, str, Statement]] = []
    for statement in statements:
        if statement.effect != effect:
            continue
        if statement.not_actions or statement.not_resources:
            continue
        for action_pattern in statement.actions:
            for resource_pattern in statement.resources:
                pairs.append((action_pattern, resource_pattern, statement))
    return pairs


def _patterns_overlap(pattern_a: str, pattern_b: str, *, matcher: Any) -> bool:
    """Symmetric wildcard overlap check -- see module docstring for exactly
    what this approximates and where it's imprecise.
    """
    return bool(matcher(pattern_a, pattern_b) or matcher(pattern_b, pattern_a))


def resolve_grants(
    *,
    identity_statements: list[Statement],
    boundary_statements: list[Statement] | None,
    scp_statements: list[Statement] | None = None,
) -> list[Grant]:
    """Resolve a principal's identity statements (already the union of every
    attached managed policy + every inline policy's statements) intersected
    with its permission boundary (if any) and its account's attached SCPs (if
    any), with explicit-deny-always-wins (identity-level AND SCP-level), into
    a list of surviving `Grant`s. `scp_statements=None` (the default) skips
    SCP filtering entirely -- every existing call site keeps working
    unchanged. See module docstring for the boundary/SCP/deny pattern-overlap
    approximation this implements.
    """
    identity_allow_pairs = _expand_pairs(identity_statements, effect="Allow")
    identity_deny_pairs = _expand_pairs(identity_statements, effect="Deny")

    boundary_allow_pairs: list[tuple[str, str, Statement]] | None = None
    if boundary_statements is not None:
        boundary_allow_pairs = _expand_pairs(boundary_statements, effect="Allow")

    scp_allow_pairs: list[tuple[str, str, Statement]] | None = None
    scp_deny_pairs: list[tuple[str, str, Statement]] = []
    if scp_statements is not None:
        scp_allow_pairs = _expand_pairs(scp_statements, effect="Allow")
        scp_deny_pairs = _expand_pairs(scp_statements, effect="Deny")

    grants: list[Grant] = []
    for action_pattern, resource_pattern, statement in identity_allow_pairs:
        # Permission boundary intersection: an identity-ALLOW grant only
        # survives if the boundary has a compatible ALLOW somewhere.
        if boundary_allow_pairs is not None:
            covered = any(
                _patterns_overlap(action_pattern, b_action, matcher=action_matches)
                and _patterns_overlap(resource_pattern, b_resource, matcher=resource_matches)
                for b_action, b_resource, _b_statement in boundary_allow_pairs
            )
            if not covered:
                continue

        # SCP intersection: same approximation as boundary intersection above
        # -- an identity-ALLOW grant only survives if some attached SCP has a
        # compatible ALLOW somewhere (statements from every attached SCP are
        # already unioned together into scp_allow_pairs by the caller).
        if scp_allow_pairs is not None:
            scp_covered = any(
                _patterns_overlap(action_pattern, s_action, matcher=action_matches)
                and _patterns_overlap(resource_pattern, s_resource, matcher=resource_matches)
                for s_action, s_resource, _s_statement in scp_allow_pairs
            )
            if not scp_covered:
                continue

        # Explicit deny always wins: drop the grant entirely if any identity
        # deny statement could plausibly apply.
        denied = any(
            _patterns_overlap(action_pattern, d_action, matcher=action_matches)
            and _patterns_overlap(resource_pattern, d_resource, matcher=resource_matches)
            for d_action, d_resource, _d_statement in identity_deny_pairs
        )
        if denied:
            continue

        # An SCP explicit deny can also veto a grant, via the same overlap
        # check (scp_deny_pairs is [] when scp_statements is None, so this is
        # always False in that case -- no behavior change for existing callers).
        scp_denied = any(
            _patterns_overlap(action_pattern, d_action, matcher=action_matches)
            and _patterns_overlap(resource_pattern, d_resource, matcher=resource_matches)
            for d_action, d_resource, _d_statement in scp_deny_pairs
        )
        if scp_denied:
            continue

        resolved = condition_matches(statement.conditions)
        if resolved is False:
            # This matcher never returns False today (see matcher.py), but
            # if it ever statically proves a condition can never hold, drop
            # the grant rather than surfacing a dead statement.
            continue

        grants.append(
            Grant(
                action_pattern=action_pattern,
                resource_pattern=resource_pattern,
                evidence={"policy": statement.source, "sid": statement.sid},
                condition_unresolved=resolved is None,
            )
        )

    return grants


class PermissionQuery:
    """Read-side query interface over already-materialized `EffectivePermission`
    edges. Constructed AFTER `eval/engine.py` has run (i.e. after edges exist
    in the graph) -- this class does no simulation of its own, it only
    matches concrete actions against the action patterns already stored on
    edges by `engine.py`.
    """

    def __init__(self, graph: nx.MultiDiGraph) -> None:
        self._graph = graph

    def _matching_edges(self, source: str, action: str, target: str) -> list[tuple[str, dict[str, Any]]]:
        edge_data = self._graph.get_edge_data(source, target)
        if not edge_data:
            return []
        matches: list[tuple[str, dict[str, Any]]] = []
        # Use the `id` stored in each edge's own data (set by `graph.export.add_edge`)
        # rather than the raw dict key, so this doesn't depend on networkx's
        # loosely-typed (`Hashable`) edge-key type.
        for data in edge_data.values():
            if data.get("type") != EdgeType.EFFECTIVE_PERMISSION.value:
                continue
            actions = data.get("properties", {}).get("actions", [])
            if any(action_matches(pattern, action) for pattern in actions):
                matches.append((data["id"], data))
        return matches

    def can(self, source: str, action: str, target: str) -> bool:
        """True if any `EffectivePermission` edge from `source` to `target`
        has an action pattern that matches `action`.
        """
        return bool(self._matching_edges(source, action, target))

    def evidence(self, source: str, action: str, target: str) -> list[str]:
        """Edge ids of every `EffectivePermission` edge from `source` to
        `target` whose action patterns match `action` (empty if `can()`
        would be `False`).
        """
        return [edge_id for edge_id, _data in self._matching_edges(source, action, target)]
