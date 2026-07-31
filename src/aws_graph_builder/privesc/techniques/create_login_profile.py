"""CreateLoginProfile/UpdateLoginProfile privesc technique: a principal that
can create or update another user's console login profile can set or reset
that user's console password, gaining interactive console access as them.
Either action alone is sufficient; if both match the same target, still only
one finding is emitted for that (source, target) pair. Self-targeting is
excluded -- resetting your own console password isn't escalation.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.schema import NodeType
from aws_graph_builder.privesc.registry import PrivescFinding, TechniqueSpec, register

_ACTIONS = ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"]

SPEC = TechniqueSpec(
    id="create_login_profile",
    name="Create/Update Login Profile",
    description=(
        "A principal that can call iam:CreateLoginProfile or iam:UpdateLoginProfile on another "
        "user can set or reset that user's console password, gaining interactive console access "
        "as them."
    ),
    reference_url="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    severity="high",
)


@register(SPEC)
def detect(graph: nx.MultiDiGraph, principal_id: str, query: PermissionQuery) -> list[PrivescFinding]:
    findings: list[PrivescFinding] = []
    for target_id, data in graph.nodes(data=True):
        if data.get("type") != NodeType.IAM_USER.value:
            continue
        if target_id == principal_id:
            continue
        matched_actions = [action for action in _ACTIONS if query.can(principal_id, action, target_id)]
        if not matched_actions:
            continue
        evidence_edges: list[str] = []
        for action in matched_actions:
            evidence_edges.extend(query.evidence(principal_id, action, target_id))
        # Dedupe while preserving order: CreateLoginProfile and
        # UpdateLoginProfile commonly both come from the same wildcard
        # EffectivePermission edge, which would otherwise appear twice.
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
                    f"{principal_id} can set or reset the console password for {target_id} "
                    f"({', '.join(matched_actions)}), gaining console access as them."
                ),
            )
        )
    return findings
