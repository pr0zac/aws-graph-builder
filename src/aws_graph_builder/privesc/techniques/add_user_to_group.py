"""AddUserToGroup privesc technique: a principal that can add a user it
controls to a group inherits every permission granted to that group's
members via its attached/inline policies. No self-exclusion needed here --
the source principal and the target `IamGroup` node are different node types
and can never collide.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.schema import NodeType
from aws_graph_builder.privesc.registry import PrivescFinding, TechniqueSpec, register

_ACTION = "iam:AddUserToGroup"

SPEC = TechniqueSpec(
    id="add_user_to_group",
    name="Add User To Group",
    description=(
        "A principal that can call iam:AddUserToGroup can add a user it controls to a group, "
        "inheriting every permission granted to that group's members."
    ),
    reference_url="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    # Medium: powerful but bounded by whatever the target group already
    # grants (unlike attach_policy, which can grant arbitrary permissions).
    severity="medium",
)


@register(SPEC)
def detect(graph: nx.MultiDiGraph, principal_id: str, query: PermissionQuery) -> list[PrivescFinding]:
    findings: list[PrivescFinding] = []
    for target_id, data in graph.nodes(data=True):
        if data.get("type") != NodeType.IAM_GROUP.value:
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
                    f"{principal_id} can add a user it controls to group {target_id}, "
                    "inheriting the group's permissions."
                ),
            )
        )
    return findings
