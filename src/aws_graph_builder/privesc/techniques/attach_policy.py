"""Attach/PutPolicy privesc technique family: a principal that can attach a
managed policy or put an inline policy on a user, group, or role can grant
that identity arbitrary permissions -- up to and including full
administrator access. This is checked against 6 actions
(`iam:AttachUserPolicy`, `iam:AttachGroupPolicy`, `iam:AttachRolePolicy`,
`iam:PutUserPolicy`, `iam:PutGroupPolicy`, `iam:PutRolePolicy`), grouped by
the node type they target.

Unlike most other detectors in this catalog, self-targeting is NOT excluded
here: a principal that can attach a policy to its own user/role is a
textbook, extremely common real-world self-escalation case -- exactly the
scenario `eval/engine.py`'s self-targeting `EffectivePermission` edges exist
to support.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.schema import NodeType
from aws_graph_builder.privesc.registry import PrivescFinding, TechniqueSpec, register

SPEC = TechniqueSpec(
    id="attach_policy",
    name="Attach/Put Policy",
    description=(
        "A principal that can attach a managed policy or put an inline policy on a user, "
        "group, or role can grant that identity arbitrary permissions, including full "
        "administrator access."
    ),
    reference_url="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    # Critical: the most direct technique in the catalog -- it can grant
    # arbitrary, unbounded permissions rather than merely inheriting the
    # target's existing ones.
    severity="critical",
)

_TARGET_ACTIONS: dict[NodeType, list[str]] = {
    NodeType.IAM_USER: ["iam:AttachUserPolicy", "iam:PutUserPolicy"],
    NodeType.IAM_GROUP: ["iam:AttachGroupPolicy", "iam:PutGroupPolicy"],
    NodeType.IAM_ROLE: ["iam:AttachRolePolicy", "iam:PutRolePolicy"],
}


@register(SPEC)
def detect(graph: nx.MultiDiGraph, principal_id: str, query: PermissionQuery) -> list[PrivescFinding]:
    findings: list[PrivescFinding] = []
    for node_type, actions in _TARGET_ACTIONS.items():
        for target_id, data in graph.nodes(data=True):
            if data.get("type") != node_type.value:
                continue
            matched_actions = [action for action in actions if query.can(principal_id, action, target_id)]
            if not matched_actions:
                continue
            evidence_edges: list[str] = []
            for action in matched_actions:
                evidence_edges.extend(query.evidence(principal_id, action, target_id))
            # Dedupe while preserving order: two matched actions (e.g.
            # AttachRolePolicy and PutRolePolicy) commonly both come from the
            # same wildcard EffectivePermission edge, which would otherwise
            # appear twice in evidence_edges.
            evidence_edges = list(dict.fromkeys(evidence_edges))
            findings.append(
                PrivescFinding(
                    technique_id=SPEC.id,
                    source=principal_id,
                    target=target_id,
                    severity=SPEC.severity,
                    required_permissions=matched_actions,
                    evidence_edges=evidence_edges,
                    description=(
                        f"{principal_id} can attach or put a policy on {target_id} "
                        f"({', '.join(matched_actions)}), granting it arbitrary permissions."
                    ),
                )
            )
    return findings
