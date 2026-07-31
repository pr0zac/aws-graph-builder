"""`AssumeRolePolicyDocument` (trust policy) evaluation -> `CanAssume` /
`IdentifiesVia` edges.

This module is split into two layers:

- **Shared principal resolvers** (`resolve_aws_principal`,
  `resolve_federated_principal`, `resolve_service_principal`, plus the
  helpers `ensure_external_wildcard_node`/`extract_root_account_id`/
  `normalize_principal_values`) answer only "which node does this Principal
  VALUE refer to", creating an `ExternalPrincipal`/`ServicePrincipal` node if
  one doesn't already exist. They do no edge creation and know nothing about
  trust policies specifically -- `eval/resource_policy.py` reuses them as-is
  to resolve S3/Lambda resource-policy principals into `EffectivePermission`
  edges instead of `CanAssume` edges.
- **Trust-specific edge creation** (the private `_handle_*_principal`
  functions plus `evaluate_trust_policies` below) builds `CanAssume` edges
  (and `IdentifiesVia` edges for `Federated` principals) on top of those
  resolvers, attaching the MFA/ExternalId/condition-unresolved properties
  that are specific to trust-policy evaluation.

For every `IamRole` node, parses its `properties["AssumeRolePolicyDocument"]`
(stored verbatim by `graph.builder.build_iam_graph`) and, for each `Allow`
statement's `Principal` block, creates a `CanAssume` edge from the resolved
principal node to the role:

- An `AWS` entry that's an ARN matching an existing graph node (compared
  against that node's `arn`) -> edge from that node. If the matched node is
  the `Account` node (i.e. the principal ARN is exactly this account's
  `arn:aws:iam::ACCOUNT:root`), the edge is additionally flagged
  `principal_kind: "account"` with an explanatory note, since "account root"
  really means "any principal in this account with `sts:AssumeRole`
  permission", not literally the root user.
- A bare 12-digit account id, or `arn:aws:iam::ACCOUNT:root` where `ACCOUNT`
  is this role's own account but didn't already match a node above (should be
  rare -- the `Account` node is always created by `graph.builder` -- but
  handled defensively), is treated the same way.
- A literal `"*"` principal -> a synthetic `ExternalPrincipal` node
  (`id="external:*"`), flagged `principal_kind: "wildcard"`.
- Any other unresolvable ARN (cross-account, or an account principal never
  scanned) -> a synthetic `ExternalPrincipal` node keyed by that ARN.
- `Federated` -> matched against existing `IdentityProvider` nodes by arn;
  when found, creates both the `CanAssume` edge AND an `IdentifiesVia` edge
  from the role to that provider. No matching provider -> skipped
  defensively (shouldn't normally happen since Phase 1 scans every SAML/OIDC
  provider in the account).
- `Service` -> a synthetic `ServicePrincipal` node keyed by the service
  principal string itself (e.g. `"ec2.amazonaws.com"`).

Every `CanAssume` edge additionally carries `requires_mfa` (True if the
statement's conditions reference `aws:MultiFactorAuthPresent` under any
operator), `external_id_required` (True if they reference `sts:ExternalId`
under any operator), and `condition_unresolved` (True if the statement has
any OTHER condition beyond those two recognized keys -- conservative/simple
presence checks, not operator- or value-aware, by design).
"""

from __future__ import annotations

import re
from typing import Any

import networkx as nx

from aws_graph_builder.eval.matcher import condition_matches
from aws_graph_builder.eval.policy_document import parse_policy_document
from aws_graph_builder.graph.export import add_edge, add_node
from aws_graph_builder.graph.schema import Edge, EdgeType, Node, NodeType, make_edge_id

_EXTERNAL_WILDCARD_ID = "external:*"
_MFA_CONDITION_KEY = "aws:multifactorauthpresent"
_EXTERNAL_ID_CONDITION_KEY = "sts:externalid"
_ROOT_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):root$")


def _name_from_arn(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def _role_account_id(role_arn: str) -> str:
    parts = role_arn.split(":")
    return parts[4] if len(parts) > 4 else ""


def extract_root_account_id(value: str) -> str | None:
    """A bare 12-digit account id or `arn:aws:iam::ACCOUNT:root` -> `ACCOUNT`,
    else `None`.
    """
    if value.isdigit() and len(value) == 12:
        return value
    match = _ROOT_ARN_RE.match(value)
    if match:
        return match.group(1)
    return None


def normalize_principal_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _has_condition_key(conditions: dict[str, dict[str, Any]], key: str) -> bool:
    key_lower = key.lower()
    for operator_block in conditions.values():
        if not isinstance(operator_block, dict):
            continue
        for condition_key in operator_block:
            if isinstance(condition_key, str) and condition_key.lower() == key_lower:
                return True
    return False


def _condition_unresolved_beyond_recognized(conditions: dict[str, dict[str, Any]], recognized: set[str]) -> bool:
    """True if, after stripping the recognized MFA/ExternalId condition keys
    (matched case-insensitively) out of `conditions`, anything non-empty
    remains -- reusing `condition_matches`'s empty/non-empty semantics.
    """
    remainder: dict[str, dict[str, Any]] = {}
    for operator, operator_block in conditions.items():
        if not isinstance(operator_block, dict):
            # Malformed condition shape -- can't recognize it as MFA/ExternalId,
            # so conservatively count it toward "unresolved".
            remainder[operator] = operator_block  # type: ignore[assignment]
            continue
        filtered = {k: v for k, v in operator_block.items() if not (isinstance(k, str) and k.lower() in recognized)}
        if filtered:
            remainder[operator] = filtered
    return condition_matches(remainder) is None


def ensure_external_wildcard_node(graph: nx.MultiDiGraph) -> str:
    """Ensure the synthetic `ExternalPrincipal` node representing a literal
    `"*"` principal exists in `graph`, returning its id.
    """
    if _EXTERNAL_WILDCARD_ID not in graph.nodes:
        add_node(
            graph,
            Node(id=_EXTERNAL_WILDCARD_ID, type=NodeType.EXTERNAL_PRINCIPAL, name="Any Principal (*)", arn=None),
        )
    return _EXTERNAL_WILDCARD_ID


def resolve_aws_principal(
    graph: nx.MultiDiGraph,
    arn_to_node: dict[str, str],
    value: str,
    own_account_id: str,
) -> tuple[str | None, bool]:
    """Resolve one `Principal.AWS` (or bare-string `"__raw__"`) value -- a
    literal `"*"`, an ARN matching an existing node, a bare 12-digit account
    id / account-root ARN, or an unresolvable cross-account ARN -- to a node
    id, creating an `ExternalPrincipal`/wildcard node in `graph` if needed.
    Pure node resolution only: no edge is created here.

    `own_account_id` is the account id of whatever this principal value is
    being resolved in the context of (a role's own account for trust-policy
    evaluation, a resource's owning account for resource-policy evaluation)
    -- used only to recognize a bare account id / root ARN naming that same
    account.

    Returns `(node_id, is_account_node)`. `node_id` is `None` only in the
    defensive case where `value` names this same account's root ARN but the
    `Account` node it should resolve to isn't present in the graph (shouldn't
    normally happen -- `graph.builder` always creates it -- but callers must
    handle the no-op case rather than assuming a node id always comes back).
    `is_account_node` is `True` when `node_id` is specifically the `Account`
    node (a bare account id / root ARN matching `own_account_id`, or an `AWS`
    entry that's an ARN already resolving to the `Account` node) -- callers
    that care about that distinction (e.g. trust.py's "assume-role available
    to the whole account" note) can act on it; others can ignore it.
    """
    if value == "*":
        return ensure_external_wildcard_node(graph), False

    existing = arn_to_node.get(value)
    if existing is not None:
        is_account = graph.nodes[existing].get("type") == NodeType.ACCOUNT.value
        return existing, is_account

    account_id = extract_root_account_id(value)
    if account_id is not None and account_id == own_account_id:
        account_node_id = f"arn:aws:iam::{account_id}:root"
        if account_node_id in graph.nodes:
            return account_node_id, True
        return None, False  # Defensive: the Account node should always exist.

    # Cross-account, or an account principal never scanned -> ExternalPrincipal.
    if value not in graph.nodes:
        add_node(graph, Node(id=value, type=NodeType.EXTERNAL_PRINCIPAL, name=_name_from_arn(value), arn=value))
    return value, False


def resolve_federated_principal(graph: nx.MultiDiGraph, arn_to_node: dict[str, str], value: str) -> str | None:
    """Resolve one `Principal.Federated` value to an existing `IdentityProvider`
    node's id, or `None` if no such node exists (callers skip gracefully).
    """
    idp_node_id = arn_to_node.get(value)
    if idp_node_id is None or graph.nodes[idp_node_id].get("type") != NodeType.IDENTITY_PROVIDER.value:
        return None
    return idp_node_id


def resolve_service_principal(graph: nx.MultiDiGraph, value: str) -> str:
    """Resolve one `Principal.Service` value to a `ServicePrincipal` node id,
    creating the node (keyed by the service principal string itself, e.g.
    `"ec2.amazonaws.com"`) in `graph` if it doesn't already exist.
    """
    if value not in graph.nodes:
        add_node(graph, Node(id=value, type=NodeType.SERVICE_PRINCIPAL, name=value, arn=None))
    return value


def _add_can_assume_edge(
    graph: nx.MultiDiGraph,
    source_id: str,
    role_arn: str,
    properties: dict[str, Any],
    discriminator: str,
) -> None:
    edge_id = make_edge_id(EdgeType.CAN_ASSUME, source_id, role_arn, discriminator=discriminator)
    add_edge(graph, Edge(id=edge_id, type=EdgeType.CAN_ASSUME, source=source_id, target=role_arn, properties=dict(properties)))


def _handle_aws_style_principal(
    graph: nx.MultiDiGraph,
    arn_to_node: dict[str, str],
    value: str,
    role_arn: str,
    role_account_id: str,
    edge_props: dict[str, Any],
    discriminator: str,
) -> None:
    node_id, is_account = resolve_aws_principal(graph, arn_to_node, value, role_account_id)
    if node_id is None:
        return  # Defensive: see resolve_aws_principal's docstring.

    props = dict(edge_props)
    if value == "*":
        props["principal_kind"] = "wildcard"
    elif is_account:
        props["principal_kind"] = "account"
        props["note"] = "grants assume-role to any principal in this account with sts:AssumeRole permission"
    _add_can_assume_edge(graph, node_id, role_arn, props, discriminator)


def _handle_federated_principal(
    graph: nx.MultiDiGraph,
    arn_to_node: dict[str, str],
    value: str,
    role_arn: str,
    edge_props: dict[str, Any],
    discriminator: str,
) -> None:
    idp_node_id = resolve_federated_principal(graph, arn_to_node, value)
    if idp_node_id is None:
        return  # Defensive: no matching IdentityProvider node -- skip gracefully.
    _add_can_assume_edge(graph, idp_node_id, role_arn, edge_props, discriminator)
    identifies_via_id = make_edge_id(EdgeType.IDENTIFIES_VIA, role_arn, idp_node_id)
    add_edge(
        graph,
        Edge(id=identifies_via_id, type=EdgeType.IDENTIFIES_VIA, source=role_arn, target=idp_node_id),
    )


def _handle_service_principal(
    graph: nx.MultiDiGraph,
    value: str,
    role_arn: str,
    edge_props: dict[str, Any],
    discriminator: str,
) -> None:
    node_id = resolve_service_principal(graph, value)
    _add_can_assume_edge(graph, node_id, role_arn, edge_props, discriminator)


def evaluate_trust_policies(graph: nx.MultiDiGraph) -> None:
    """Mutate `graph` in place, adding `CanAssume`/`IdentifiesVia` edges (and
    any `ExternalPrincipal`/`ServicePrincipal` nodes they require) derived
    from every `IamRole` node's trust policy.
    """
    # Snapshot of arn -> node id for the structural graph as it exists at the
    # start of this call. New nodes created below (ExternalPrincipal/
    # ServicePrincipal) use their arn/id directly as the node id, so re-runs
    # or repeated principal ARNs within this same call correctly dedupe via
    # plain `graph.nodes` membership checks rather than needing this map kept
    # up to date.
    arn_to_node: dict[str, str] = {data["arn"]: node_id for node_id, data in graph.nodes(data=True) if data.get("arn")}

    role_entries = [
        (node_id, data) for node_id, data in graph.nodes(data=True) if data.get("type") == NodeType.IAM_ROLE.value
    ]

    for role_arn, data in role_entries:
        assume_doc = data.get("properties", {}).get("AssumeRolePolicyDocument")
        if not assume_doc:
            continue
        try:
            parsed = parse_policy_document(assume_doc, source=f"trust:{role_arn}")
        except ValueError:
            continue

        role_account_id = _role_account_id(role_arn)

        for index, statement in enumerate(parsed.statements):
            if statement.effect != "Allow":
                continue
            principal = statement.principal
            if not principal:
                continue

            discriminator = statement.sid or str(index)
            requires_mfa = _has_condition_key(statement.conditions, _MFA_CONDITION_KEY)
            external_id_required = _has_condition_key(statement.conditions, _EXTERNAL_ID_CONDITION_KEY)
            condition_unresolved = _condition_unresolved_beyond_recognized(
                statement.conditions, {_MFA_CONDITION_KEY, _EXTERNAL_ID_CONDITION_KEY}
            )
            edge_props: dict[str, Any] = {
                "requires_mfa": requires_mfa,
                "external_id_required": external_id_required,
                "condition_unresolved": condition_unresolved,
            }

            aws_values = normalize_principal_values(principal.get("AWS"))
            raw_value = principal.get("__raw__")
            if isinstance(raw_value, str):
                aws_values.append(raw_value)
            for value in aws_values:
                _handle_aws_style_principal(graph, arn_to_node, value, role_arn, role_account_id, edge_props, discriminator)

            for value in normalize_principal_values(principal.get("Federated")):
                _handle_federated_principal(graph, arn_to_node, value, role_arn, edge_props, discriminator)

            for value in normalize_principal_values(principal.get("Service")):
                _handle_service_principal(graph, value, role_arn, edge_props, discriminator)
