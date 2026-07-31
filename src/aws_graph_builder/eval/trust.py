"""`AssumeRolePolicyDocument` (trust policy) evaluation -> `CanAssume` /
`IdentifiesVia` edges.

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


def _extract_root_account_id(value: str) -> str | None:
    """A bare 12-digit account id or `arn:aws:iam::ACCOUNT:root` -> `ACCOUNT`,
    else `None`.
    """
    if value.isdigit() and len(value) == 12:
        return value
    match = _ROOT_ARN_RE.match(value)
    if match:
        return match.group(1)
    return None


def _normalize_principal_values(value: Any) -> list[str]:
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


def _ensure_external_wildcard_node(graph: nx.MultiDiGraph) -> str:
    if _EXTERNAL_WILDCARD_ID not in graph.nodes:
        add_node(
            graph,
            Node(id=_EXTERNAL_WILDCARD_ID, type=NodeType.EXTERNAL_PRINCIPAL, name="Any Principal (*)", arn=None),
        )
    return _EXTERNAL_WILDCARD_ID


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
    if value == "*":
        node_id = _ensure_external_wildcard_node(graph)
        _add_can_assume_edge(graph, node_id, role_arn, {**edge_props, "principal_kind": "wildcard"}, discriminator)
        return

    existing = arn_to_node.get(value)
    if existing is not None:
        props = dict(edge_props)
        if graph.nodes[existing].get("type") == NodeType.ACCOUNT.value:
            props["principal_kind"] = "account"
            props["note"] = "grants assume-role to any principal in this account with sts:AssumeRole permission"
        _add_can_assume_edge(graph, existing, role_arn, props, discriminator)
        return

    account_id = _extract_root_account_id(value)
    if account_id is not None and account_id == role_account_id:
        account_node_id = f"arn:aws:iam::{account_id}:root"
        if account_node_id in graph.nodes:
            props = {
                **edge_props,
                "principal_kind": "account",
                "note": "grants assume-role to any principal in this account with sts:AssumeRole permission",
            }
            _add_can_assume_edge(graph, account_node_id, role_arn, props, discriminator)
        # else: defensive skip -- the Account node should always exist.
        return

    # Cross-account, or an account principal never scanned -> ExternalPrincipal.
    if value not in graph.nodes:
        add_node(graph, Node(id=value, type=NodeType.EXTERNAL_PRINCIPAL, name=_name_from_arn(value), arn=value))
    _add_can_assume_edge(graph, value, role_arn, edge_props, discriminator)


def _handle_federated_principal(
    graph: nx.MultiDiGraph,
    arn_to_node: dict[str, str],
    value: str,
    role_arn: str,
    edge_props: dict[str, Any],
    discriminator: str,
) -> None:
    idp_node_id = arn_to_node.get(value)
    if idp_node_id is None or graph.nodes[idp_node_id].get("type") != NodeType.IDENTITY_PROVIDER.value:
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
    if value not in graph.nodes:
        add_node(graph, Node(id=value, type=NodeType.SERVICE_PRINCIPAL, name=value, arn=None))
    _add_can_assume_edge(graph, value, role_arn, edge_props, discriminator)


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

            aws_values = _normalize_principal_values(principal.get("AWS"))
            raw_value = principal.get("__raw__")
            if isinstance(raw_value, str):
                aws_values.append(raw_value)
            for value in aws_values:
                _handle_aws_style_principal(graph, arn_to_node, value, role_arn, role_account_id, edge_props, discriminator)

            for value in _normalize_principal_values(principal.get("Federated")):
                _handle_federated_principal(graph, arn_to_node, value, role_arn, edge_props, discriminator)

            for value in _normalize_principal_values(principal.get("Service")):
                _handle_service_principal(graph, value, role_arn, edge_props, discriminator)
