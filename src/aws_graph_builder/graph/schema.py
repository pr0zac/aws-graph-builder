"""Node/edge type taxonomy and dataclasses for the attack-path graph.

Scoped to what Phase 1 (IAM-only, structural graph) needs: no EC2/Lambda/S3/SCP/
network node or edge types, and no `EffectivePermission`/`PrivescPath` edges yet
(those depend on the policy-evaluation and privesc-detection engines added in
later phases). See ``aws-graph-builder.md`` -> "Node/edge taxonomy" for the full
v1+ taxonomy this is a subset of.

Both enums are plain ``str`` enums so members serialize directly to their string
value (``NodeType.IAM_USER.value == "IamUser"``) with no custom JSON encoder,
and so new members can be appended in later phases without changing how
existing ones round-trip through the JSON schema.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    """Node type discriminator, written to the JSON `type` field verbatim.

    Values are PascalCase to match the node/edge type names used throughout
    ``aws-graph-builder.md`` (e.g. "IamUser", "ManagedPolicy") and the sample
    JSON output schema, so the strings a downstream visualizer sees are the
    same names the design doc uses.
    """

    ACCOUNT = "Account"
    IAM_USER = "IamUser"
    IAM_GROUP = "IamGroup"
    IAM_ROLE = "IamRole"
    MANAGED_POLICY = "ManagedPolicy"
    INLINE_POLICY = "InlinePolicy"
    IDENTITY_PROVIDER = "IdentityProvider"
    INSTANCE_PROFILE = "InstanceProfile"
    EXTERNAL_PRINCIPAL = "ExternalPrincipal"
    SERVICE_PRINCIPAL = "ServicePrincipal"


class EdgeType(str, Enum):
    """Edge type discriminator, written to the JSON `type` field verbatim.

    Values are PascalCase for the same reason as `NodeType` above.
    """

    MEMBER_OF = "MemberOf"  # IamUser -> IamGroup
    ATTACHED_POLICY = "AttachedPolicy"  # principal -> ManagedPolicy
    HAS_INLINE_POLICY = "HasInlinePolicy"  # principal -> InlinePolicy
    HAS_PERMISSION_BOUNDARY = "HasPermissionBoundary"  # IamUser/IamRole -> ManagedPolicy
    ATTACHED_TO = "AttachedTo"  # InstanceProfile -> IamRole
    IDENTIFIES_VIA = "IdentifiesVia"  # IamRole -> IdentityProvider
    # Assuming-principal -> IamRole. Belongs in the schema now, but trust-policy
    # *evaluation* (i.e. actually populating these edges) is a Phase 2/3 concern
    # per aws-graph-builder.md's eval/trust.py -- no detection logic lives here.
    CAN_ASSUME = "CanAssume"


@dataclass
class Node:
    """A single graph node.

    ``id`` is the node's ARN when the underlying AWS resource has one. The one
    exception in Phase 1 is `InlinePolicy`, which has no ARN of its own (inline
    policies are identified by name within their owning principal): its id is
    the synthetic scheme ``f"{owner_arn}#inline/{policy_name}"``, per
    aws-graph-builder.md.
    """

    id: str
    type: NodeType
    name: str
    arn: str | None
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    """A single graph edge between two node ids."""

    id: str
    type: EdgeType
    source: str
    target: str
    properties: dict[str, Any] = field(default_factory=dict)


def inline_policy_id(owner_arn: str, policy_name: str) -> str:
    """Synthetic node id for an `InlinePolicy` node, per the id scheme above."""
    return f"{owner_arn}#inline/{policy_name}"


def make_edge_id(edge_type: EdgeType, source: str, target: str) -> str:
    """Deterministic, stable edge id derived from (type, source, target).

    Deterministic ids make exported JSON reproducible across runs (nicer for
    diffing test fixtures and real scan output) as long as at most one edge of
    a given type exists between a given (source, target) pair -- true for
    every Phase 1 edge type, since a principal has at most one MemberOf edge to
    a given group, one AttachedPolicy edge to a given policy, etc.
    """
    digest = hashlib.sha1(f"{edge_type.value}|{source}|{target}".encode()).hexdigest()
    return f"e-{digest[:12]}"
