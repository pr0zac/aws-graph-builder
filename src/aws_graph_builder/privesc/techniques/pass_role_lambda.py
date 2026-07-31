"""PassRole+CreateFunction privesc technique: a principal that can call
iam:PassRole for a role and lambda:CreateFunction can create a new Lambda
function with that role as its execution role, inheriting all of the role's
permissions when the function runs. Self-targeting is excluded -- a role
passing itself to a resource it creates gains nothing new, same reasoning as
`create_access_key`/`update_assume_role_policy`.

There's no existing Lambda function to point a finding at (the technique is
about creating one), so this is checked directly against `IamRole` nodes as
targets -- see `pass_role_ec2.py` for the full explanation of why
`Resource: "*"` grants for `lambda:CreateFunction` already produce the
necessary `EffectivePermission` edges against `IamRole` nodes without any
new evaluation-engine machinery.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.schema import NodeType
from aws_graph_builder.privesc.registry import PrivescFinding, TechniqueSpec, register

_PASS_ROLE_ACTION = "iam:PassRole"
_CREATE_FUNCTION_ACTION = "lambda:CreateFunction"

SPEC = TechniqueSpec(
    id="pass_role_lambda",
    name="PassRole + CreateFunction",
    description=(
        "A principal that can call iam:PassRole for a role and lambda:CreateFunction can create "
        "a new Lambda function with that role as its execution role, inheriting all of the "
        "role's permissions when the function runs."
    ),
    reference_url="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    # High, not critical: grants persistent access bounded by the target
    # role's existing permissions, not arbitrary/unbounded like
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
        if not query.can(principal_id, _CREATE_FUNCTION_ACTION, target_id):
            continue
        evidence_edges = list(
            dict.fromkeys(
                query.evidence(principal_id, _PASS_ROLE_ACTION, target_id)
                + query.evidence(principal_id, _CREATE_FUNCTION_ACTION, target_id)
            )
        )
        findings.append(
            PrivescFinding(
                technique_id=SPEC.id,
                source=principal_id,
                target=target_id,
                severity=SPEC.severity,
                required_permissions=[_PASS_ROLE_ACTION, _CREATE_FUNCTION_ACTION],
                evidence_edges=evidence_edges,
                description=(
                    f"{principal_id} can create a new Lambda function with role {target_id} as its "
                    "execution role (iam:PassRole + lambda:CreateFunction), inheriting the role's "
                    "permissions."
                ),
            )
        )
    return findings
