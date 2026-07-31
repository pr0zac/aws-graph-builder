"""CreatePolicyVersion privesc technique: a principal that can create a new
version of a managed policy (and set it as default) can rewrite what that
policy grants everywhere it's attached. No self-exclusion needed here -- the
source principal and the target `ManagedPolicy` node are different node
types and can never collide.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.schema import NodeType
from aws_graph_builder.privesc.registry import PrivescFinding, TechniqueSpec, register

_ACTION = "iam:CreatePolicyVersion"

SPEC = TechniqueSpec(
    id="create_policy_version",
    name="Create Policy Version",
    description=(
        "A principal that can call iam:CreatePolicyVersion on a managed policy can create a "
        "new default version of that policy, changing what it grants everywhere it's attached."
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
                    f"{principal_id} can create a new version of policy {target_id}, and calling "
                    "CreatePolicyVersion with SetAsDefault=true immediately changes what that policy "
                    "grants everyone it's attached to."
                ),
            )
        )
    return findings
