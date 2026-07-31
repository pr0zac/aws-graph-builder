"""PassRole+RunInstances privesc technique: a principal that can call
iam:PassRole for a role and ec2:RunInstances can launch a new EC2 instance
with that role attached as its instance profile, inheriting all of the
role's permissions via the instance's credentials. Self-targeting is
excluded -- a role passing itself to a resource it creates gains nothing
new, same reasoning as `create_access_key`/`update_assume_role_policy`.

There's no existing EC2 instance to point a finding at (the technique is
about creating one), so this is checked directly against `IamRole` nodes as
targets. This works because `Resource: "*"` grants for `ec2:RunInstances`
(overwhelmingly the common real-world case, since you can't scope a
resource ARN to a not-yet-created instance) are already matched by Phase 2's
resource-pattern evaluation against every node's ARN in the graph --
including `IamRole` nodes -- so the necessary `EffectivePermission` edges
already exist without any new evaluation-engine machinery.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.schema import NodeType
from aws_graph_builder.privesc.registry import PrivescFinding, TechniqueSpec, register

_PASS_ROLE_ACTION = "iam:PassRole"
_RUN_INSTANCES_ACTION = "ec2:RunInstances"

SPEC = TechniqueSpec(
    id="pass_role_ec2",
    name="PassRole + RunInstances",
    description=(
        "A principal that can call iam:PassRole for a role and ec2:RunInstances can launch a "
        "new EC2 instance with that role attached, inheriting all of the role's permissions via "
        "the instance's credentials."
    ),
    reference_url="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    # High, not critical: grants persistent-while-running access bounded by
    # the target role's existing permissions, not arbitrary/unbounded like
    # attach_policy -- same tier as create_access_key.
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
        if not query.can(principal_id, _PASS_ROLE_ACTION, target_id):
            continue
        if not query.can(principal_id, _RUN_INSTANCES_ACTION, target_id):
            continue
        evidence_edges = list(
            dict.fromkeys(
                query.evidence(principal_id, _PASS_ROLE_ACTION, target_id)
                + query.evidence(principal_id, _RUN_INSTANCES_ACTION, target_id)
            )
        )
        findings.append(
            PrivescFinding(
                technique_id=SPEC.id,
                source=principal_id,
                target=target_id,
                severity=SPEC.severity,
                required_permissions=[_PASS_ROLE_ACTION, _RUN_INSTANCES_ACTION],
                evidence_edges=evidence_edges,
                description=(
                    f"{principal_id} can launch a new EC2 instance with role {target_id} attached "
                    "(iam:PassRole + ec2:RunInstances), inheriting the role's permissions."
                ),
            )
        )
    return findings
