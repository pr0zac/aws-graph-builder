"""UpdateAssumeRolePolicy privesc technique: a principal that can rewrite a
role's trust policy can add itself (or any other principal it controls) as a
trusted principal, then assume that role. Self-targeting is excluded -- a
role rewriting its own trust policy to trust itself gains nothing new.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.schema import NodeType
from aws_graph_builder.privesc.registry import PrivescFinding, TechniqueSpec, register

_ACTION = "iam:UpdateAssumeRolePolicy"

SPEC = TechniqueSpec(
    id="update_assume_role_policy",
    name="Update Assume Role Policy",
    description=(
        "A principal that can call iam:UpdateAssumeRolePolicy on a role can rewrite its trust "
        "policy to add itself as a trusted principal, then assume that role."
    ),
    reference_url="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    severity="high",
)


@register(SPEC)
def detect(graph: nx.MultiDiGraph, principal_id: str, query: PermissionQuery) -> list[PrivescFinding]:
    findings: list[PrivescFinding] = []
    for target_id, data in graph.nodes(data=True):
        if data.get("type") != NodeType.IAM_ROLE.value:
            continue
        if target_id == principal_id:
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
                    f"{principal_id} can rewrite the trust policy of role {target_id} to add itself "
                    "as a trusted principal, then assume that role."
                ),
            )
        )
    return findings
