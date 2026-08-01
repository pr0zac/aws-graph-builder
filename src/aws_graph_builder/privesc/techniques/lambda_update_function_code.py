"""UpdateFunctionCode privesc technique: a principal that can call
lambda:UpdateFunctionCode on an existing function can replace its code with
arbitrary code that runs under the function's execution role, inheriting all
of that role's permissions on next invocation. Unlike the PassRole-based
detectors, no iam:PassRole is involved -- the role is already attached to an
existing function, discovered via the graph's `ExecutionRole` edge
(`LambdaFunction` -> `IamRole`) rather than checked as an action target.
Self-targeting is excluded -- a role that can already act as itself gains
nothing new by updating a function it already executes as.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.schema import EdgeType, NodeType
from aws_graph_builder.privesc.registry import PrivescFinding, TechniqueSpec, register

_ACTION = "lambda:UpdateFunctionCode"

SPEC = TechniqueSpec(
    id="lambda_update_function_code",
    name="Lambda Update Function Code",
    description=(
        "A principal that can call lambda:UpdateFunctionCode on an existing function can replace "
        "its code with arbitrary code that runs under the function's execution role, inheriting "
        "all of that role's permissions on next invocation."
    ),
    reference_url="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    # High, not critical: grants persistent access bounded by the target
    # role's existing permissions, not arbitrary/unbounded like
    # attach_policy -- same tier as create_access_key/pass_role_*.
    severity="high",
)


@register(SPEC)
def detect(graph: nx.MultiDiGraph, principal_id: str, query: PermissionQuery) -> list[PrivescFinding]:
    findings: list[PrivescFinding] = []
    for function_id, data in graph.nodes(data=True):
        if data.get("type") != NodeType.LAMBDA_FUNCTION.value:
            continue
        if not query.can(principal_id, _ACTION, function_id):
            continue
        action_evidence = query.evidence(principal_id, _ACTION, function_id)
        for _source, role_id, edge_data in graph.out_edges(function_id, data=True):
            if edge_data.get("type") != EdgeType.EXECUTION_ROLE.value:
                continue
            if role_id == principal_id:
                continue
            evidence_edges = list(dict.fromkeys([*action_evidence, edge_data["id"]]))
            findings.append(
                PrivescFinding(
                    technique_id=SPEC.id,
                    source=principal_id,
                    target=role_id,
                    severity=SPEC.severity,
                    required_permissions=[_ACTION],
                    evidence_edges=evidence_edges,
                    description=(
                        f"{principal_id} can update the code of function {function_id}, whose "
                        f"execution role is {role_id} (lambda:UpdateFunctionCode), inheriting the "
                        "role's permissions on next invocation."
                    ),
                )
            )
    return findings
