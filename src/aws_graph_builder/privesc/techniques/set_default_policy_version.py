"""SetDefaultPolicyVersion privesc technique: a principal that can activate
an existing (non-default) version of a managed policy can reinstate an old,
more permissive version -- without needing iam:CreatePolicyVersion at all.
Managed policies retain up to 5 historical versions, so this is exploitable
even against policies the attacker never modified. No self-exclusion needed
here -- the source principal and the target `ManagedPolicy` node are
different node types and can never collide.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.schema import NodeType
from aws_graph_builder.privesc.registry import PrivescFinding, TechniqueSpec, register

_ACTION = "iam:SetDefaultPolicyVersion"

SPEC = TechniqueSpec(
    id="set_default_policy_version",
    name="Set Default Policy Version",
    description=(
        "A principal that can call iam:SetDefaultPolicyVersion on a managed policy can activate "
        "any of its retained historical versions, reinstating an old, more permissive grant "
        "everywhere the policy is attached -- without needing iam:CreatePolicyVersion."
    ),
    reference_url="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    severity="high",
)


@register(SPEC)
def detect(graph: nx.MultiDiGraph, principal_id: str, query: PermissionQuery) -> list[PrivescFinding]:
    findings: list[PrivescFinding] = []
    for target_id, data in graph.nodes(data=True):
        if data.get("type") != NodeType.MANAGED_POLICY.value:
            continue
        if not query.can(principal_id, _ACTION, target_id):
            continue
        findings.append(
            PrivescFinding(
                technique_id=SPEC.id,
                source=principal_id,
                target=target_id,
                severity=SPEC.severity,
                required_permissions=[_ACTION],
                evidence_edges=query.evidence(principal_id, _ACTION, target_id),
                description=(
                    f"{principal_id} can set the default version of policy {target_id}, "
                    "reinstating any of its retained historical versions -- potentially a more "
                    "permissive grant -- everywhere it's attached."
                ),
            )
        )
    return findings
