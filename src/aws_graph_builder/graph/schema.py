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
    EC2_INSTANCE = "Ec2Instance"
    LAMBDA_FUNCTION = "LambdaFunction"
    S3_BUCKET = "S3Bucket"
    SERVICE_CONTROL_POLICY = "ServiceControlPolicy"


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
    # Assuming-principal -> IamRole. Populated by eval/trust.py (Phase 2).
    CAN_ASSUME = "CanAssume"
    # principal -> any other node with an arn (IAM-shaped only until Phase 4
    # adds EC2/S3/Lambda nodes). Populated by eval/engine.py (Phase 2).
    EFFECTIVE_PERMISSION = "EffectivePermission"
    # source -> target of a detected privilege-escalation technique. Reserved
    # here so Phase 3's privesc/engine.py doesn't need to touch this enum;
    # nothing in Phase 2 populates this.
    PRIVESC_PATH = "PrivescPath"
    EXECUTION_ROLE = "ExecutionRole"  # LambdaFunction -> IamRole
    APPLIES_SCP = "AppliesSCP"  # Account -> ServiceControlPolicy


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


def make_edge_id(edge_type: EdgeType, source: str, target: str, discriminator: str | None = None) -> str:
    """Deterministic, stable edge id derived from (type, source, target[, discriminator]).

    Deterministic ids make exported JSON reproducible across runs (nicer for
    diffing test fixtures and real scan output) as long as at most one edge of
    a given type exists between a given (source, target) pair -- true for
    every Phase 1 edge type, since a principal has at most one MemberOf edge to
    a given group, one AttachedPolicy edge to a given policy, etc.

    `discriminator` is an optional extra string folded into the hash, for edge
    types where more than one meaningfully-different edge can exist between
    the same (source, target) pair -- e.g. a role's trust policy naming the
    same principal ARN in two different statements (`eval/trust.py`), or
    multiple distinct `PrivescPath`s between the same two nodes (Phase 3).
    When omitted, the id is byte-for-byte identical to calling this function
    without the parameter at all, so every existing Phase 1 call site (which
    passes only 3 positional args) is unaffected.
    """
    key = f"{edge_type.value}|{source}|{target}"
    if discriminator is not None:
        key = f"{key}|{discriminator}"
    digest = hashlib.sha1(key.encode()).hexdigest()
    return f"e-{digest[:12]}"
