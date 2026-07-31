"""CreateAccessKey privesc technique: a principal that can create an access
key for another IAM user can mint long-lived static credentials for that
user, inheriting its entire effective permission set. Self-targeting is
excluded -- creating your own access key isn't escalation, you already have
your own permissions.
"""

from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.schema import NodeType
from aws_graph_builder.privesc.registry import PrivescFinding, TechniqueSpec, register

_ACTION = "iam:CreateAccessKey"

SPEC = TechniqueSpec(
    id="create_access_key",
    name="Create Access Key",
    description=(
        "A principal that can call iam:CreateAccessKey for another IAM user can mint "
        "long-lived static credentials for that user, inheriting all of its permissions."
    ),
    reference_url="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    # High, not critical: grants persistent access bounded by whatever the
    # target user already has (unlike e.g. attach_policy, which can grant
    # arbitrary, unbounded permissions).
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
                description=f"{principal_id} can create an access key for {target_id}, inheriting its permissions.",
            )
        )
    return findings
