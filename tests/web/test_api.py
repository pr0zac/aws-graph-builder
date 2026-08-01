from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from aws_graph_builder.graph.schema import EdgeType, NodeType, make_edge_id
from aws_graph_builder.web.server import create_app

ACCOUNT_ID = "111111111111"


def _node(node_id: str, node_type: NodeType, name: str, *, arn: str | None = None, properties: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": node_id,
        "type": node_type.value,
        "name": name,
        "arn": node_id if arn is None else arn,
        "properties": properties or {},
    }


def _edge(
    edge_type: EdgeType,
    source: str,
    target: str,
    *,
    properties: dict[str, Any] | None = None,
    discriminator: str | None = None,
) -> dict[str, Any]:
    return {
        "id": make_edge_id(edge_type, source, target, discriminator=discriminator),
        "type": edge_type.value,
        "source": source,
        "target": target,
        "properties": properties or {},
    }


def _document(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": "2026-01-01T00:00:00Z",
        "account_id": ACCOUNT_ID,
        "regions_scanned": [],
        "nodes": nodes,
        "edges": edges,
    }
    if findings is not None:
        document["findings"] = findings
    return document


def _client(document: dict[str, Any]) -> TestClient:
    return TestClient(create_app(document))


# --------------------------------------------------------------------------
# /api/graph
# --------------------------------------------------------------------------


def test_get_graph_returns_trimmed_nodes_and_edges() -> None:
    alice = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
    group = f"arn:aws:iam::{ACCOUNT_ID}:group/admins"
    nodes = [
        _node(alice, NodeType.IAM_USER, "alice", properties={"mfa_enabled": False}),
        _node(group, NodeType.IAM_GROUP, "admins"),
    ]
    edges = [_edge(EdgeType.MEMBER_OF, alice, group, properties={"evidence": "GetGroupsForUser"})]
    client = _client(_document(nodes, edges))

    response = client.get("/api/graph")

    assert response.status_code == 200
    body = response.json()
    assert len(body["nodes"]) == 2
    assert len(body["edges"]) == 1

    nodes_by_id = {n["id"]: n for n in body["nodes"]}
    alice_node = nodes_by_id[alice]
    assert set(alice_node.keys()) == {"id", "type", "name", "arn", "high_value"}
    assert alice_node["type"] == "IamUser"
    assert alice_node["name"] == "alice"
    assert alice_node["arn"] == alice
    assert alice_node["high_value"] is False

    edge = body["edges"][0]
    assert set(edge.keys()) == {"id", "type", "source", "target"}
    assert edge["type"] == "MemberOf"
    assert edge["source"] == alice
    assert edge["target"] == group


# --------------------------------------------------------------------------
# /api/node
# --------------------------------------------------------------------------


def test_get_node_found_returns_full_properties() -> None:
    alice = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
    nodes = [_node(alice, NodeType.IAM_USER, "alice", properties={"mfa_enabled": False, "tags": {"team": "security"}})]
    client = _client(_document(nodes, []))

    response = client.get("/api/node", params={"id": alice})

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == alice
    assert body["properties"] == {"mfa_enabled": False, "tags": {"team": "security"}}


def test_get_node_missing_returns_404() -> None:
    client = _client(_document([], []))

    response = client.get("/api/node", params={"id": f"arn:aws:iam::{ACCOUNT_ID}:user/ghost"})

    assert response.status_code == 404
    assert response.json()["detail"]


# --------------------------------------------------------------------------
# /api/edge
# --------------------------------------------------------------------------


def test_get_edge_found_returns_full_properties() -> None:
    alice = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
    group = f"arn:aws:iam::{ACCOUNT_ID}:group/admins"
    nodes = [_node(alice, NodeType.IAM_USER, "alice"), _node(group, NodeType.IAM_GROUP, "admins")]
    edge = _edge(EdgeType.MEMBER_OF, alice, group, properties={"evidence": "GetGroupsForUser"})
    client = _client(_document(nodes, [edge]))

    response = client.get("/api/edge", params={"id": edge["id"]})

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == edge["id"]
    assert body["properties"] == {"evidence": "GetGroupsForUser"}


def test_get_edge_missing_returns_404() -> None:
    client = _client(_document([], []))

    response = client.get("/api/edge", params={"id": "nonexistent-edge-id"})

    assert response.status_code == 404
    assert response.json()["detail"]


# --------------------------------------------------------------------------
# /api/findings
# --------------------------------------------------------------------------


def test_get_findings_returns_all_expected_fields() -> None:
    alice = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
    role = f"arn:aws:iam::{ACCOUNT_ID}:role/admin-role"
    finding = {
        "technique_id": "attach_policy",
        "source": alice,
        "target": role,
        "severity": "critical",
        "required_permissions": ["iam:AttachUserPolicy"],
        "evidence_edges": [make_edge_id(EdgeType.EFFECTIVE_PERMISSION, alice, role)],
        "edge_id": make_edge_id(EdgeType.PRIVESC_PATH, alice, role, discriminator="attach_policy"),
        "description": "alice can attach an administrator policy to herself",
    }
    client = _client(_document([], [], findings=[finding]))

    response = client.get("/api/findings")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0] == finding


# --------------------------------------------------------------------------
# /api/paths
# --------------------------------------------------------------------------


def _chain_document() -> dict[str, Any]:
    """alice --MemberOf--> admins --AttachedPolicy--> AdminPolicy, plus an
    unconnected `isolated` user for the "exists but unreachable" case.
    """
    alice = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
    group = f"arn:aws:iam::{ACCOUNT_ID}:group/admins"
    policy = f"arn:aws:iam::{ACCOUNT_ID}:policy/AdminPolicy"
    isolated = f"arn:aws:iam::{ACCOUNT_ID}:user/isolated"
    nodes = [
        _node(alice, NodeType.IAM_USER, "alice"),
        _node(group, NodeType.IAM_GROUP, "admins"),
        _node(policy, NodeType.MANAGED_POLICY, "AdminPolicy"),
        _node(isolated, NodeType.IAM_USER, "isolated"),
    ]
    edges = [
        _edge(EdgeType.MEMBER_OF, alice, group),
        _edge(EdgeType.ATTACHED_POLICY, group, policy),
    ]
    return _document(nodes, edges)


def test_get_paths_finds_multi_hop_chain() -> None:
    alice = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
    group = f"arn:aws:iam::{ACCOUNT_ID}:group/admins"
    policy = f"arn:aws:iam::{ACCOUNT_ID}:policy/AdminPolicy"
    client = _client(_chain_document())

    response = client.get("/api/paths", params={"source": alice, "target": policy})

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert len(paths) == 1
    path = paths[0]
    assert path["nodes"] == [alice, group, policy]
    assert len(path["hops"]) == 2
    assert path["hops"][0]["source"] == alice
    assert path["hops"][0]["target"] == group
    assert len(path["hops"][0]["edge_ids"]) == 1
    assert path["hops"][1]["source"] == group
    assert path["hops"][1]["target"] == policy
    assert len(path["hops"][1]["edge_ids"]) == 1


def test_get_paths_404_when_node_missing() -> None:
    alice = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
    ghost = f"arn:aws:iam::{ACCOUNT_ID}:user/ghost"
    client = _client(_chain_document())

    response = client.get("/api/paths", params={"source": alice, "target": ghost})

    assert response.status_code == 404
    assert response.json()["detail"]


def test_get_paths_empty_when_nodes_exist_but_unconnected() -> None:
    alice = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
    isolated = f"arn:aws:iam::{ACCOUNT_ID}:user/isolated"
    client = _client(_chain_document())

    response = client.get("/api/paths", params={"source": alice, "target": isolated})

    assert response.status_code == 200
    assert response.json()["paths"] == []


# --------------------------------------------------------------------------
# /api/attack-paths
# --------------------------------------------------------------------------


def _attack_document() -> dict[str, Any]:
    """Two independent scenarios in one document:

    - x-role -> y-role: connected by BOTH a CanAssume edge (control-transfer)
      AND a parallel EffectivePermission edge (not control-transfer) -- proves
      attack-paths finds the pair via the CanAssume edge specifically.
    - p-user -> q-role: connected ONLY by an EffectivePermission edge -- proves
      attack-paths does NOT fall back to using it.
    - a-user -> b-role -> c-role: a two-hop chain through CanAssume then
      PrivescPath -- proves chaining across different control-transfer edge
      types works, not just a single hop.
    """
    x = f"arn:aws:iam::{ACCOUNT_ID}:role/x-role"
    y = f"arn:aws:iam::{ACCOUNT_ID}:role/y-role"
    p = f"arn:aws:iam::{ACCOUNT_ID}:user/p-user"
    q = f"arn:aws:iam::{ACCOUNT_ID}:role/q-role"
    a = f"arn:aws:iam::{ACCOUNT_ID}:user/a-user"
    b = f"arn:aws:iam::{ACCOUNT_ID}:role/b-role"
    c = f"arn:aws:iam::{ACCOUNT_ID}:role/c-role"

    nodes = [
        _node(x, NodeType.IAM_ROLE, "x-role"),
        _node(y, NodeType.IAM_ROLE, "y-role"),
        _node(p, NodeType.IAM_USER, "p-user"),
        _node(q, NodeType.IAM_ROLE, "q-role"),
        _node(a, NodeType.IAM_USER, "a-user"),
        _node(b, NodeType.IAM_ROLE, "b-role"),
        _node(c, NodeType.IAM_ROLE, "c-role"),
    ]
    edges = [
        _edge(EdgeType.CAN_ASSUME, x, y),
        _edge(EdgeType.EFFECTIVE_PERMISSION, x, y),
        _edge(EdgeType.EFFECTIVE_PERMISSION, p, q),
        _edge(EdgeType.CAN_ASSUME, a, b),
        _edge(EdgeType.PRIVESC_PATH, b, c, discriminator="attach_policy"),
    ]
    return _document(nodes, edges)


def test_attack_paths_finds_path_via_parallel_control_transfer_edge() -> None:
    x = f"arn:aws:iam::{ACCOUNT_ID}:role/x-role"
    y = f"arn:aws:iam::{ACCOUNT_ID}:role/y-role"
    client = _client(_attack_document())

    response = client.get("/api/attack-paths", params={"source": x, "target": y})

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert len(paths) == 1
    assert paths[0]["nodes"] == [x, y]


def test_attack_paths_empty_when_only_effective_permission_edge() -> None:
    p = f"arn:aws:iam::{ACCOUNT_ID}:user/p-user"
    q = f"arn:aws:iam::{ACCOUNT_ID}:role/q-role"
    client = _client(_attack_document())

    response = client.get("/api/attack-paths", params={"source": p, "target": q})

    assert response.status_code == 200
    assert response.json()["paths"] == []

    # Sanity check: the same pair IS reachable via the unrestricted
    # /api/paths, proving attack-paths really does restrict the edge subset
    # rather than both endpoints coincidentally returning empty.
    general_response = client.get("/api/paths", params={"source": p, "target": q})
    assert len(general_response.json()["paths"]) == 1


def test_attack_paths_chains_across_multiple_control_transfer_edge_types() -> None:
    a = f"arn:aws:iam::{ACCOUNT_ID}:user/a-user"
    b = f"arn:aws:iam::{ACCOUNT_ID}:role/b-role"
    c = f"arn:aws:iam::{ACCOUNT_ID}:role/c-role"
    client = _client(_attack_document())

    response = client.get("/api/attack-paths", params={"source": a, "target": c})

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert len(paths) == 1
    assert paths[0]["nodes"] == [a, b, c]
    assert len(paths[0]["hops"]) == 2


def test_attack_paths_max_hops_bounds_results() -> None:
    a = f"arn:aws:iam::{ACCOUNT_ID}:user/a-user"
    c = f"arn:aws:iam::{ACCOUNT_ID}:role/c-role"
    client = _client(_attack_document())

    # a -> c is a two-hop chain (via b); capping max_hops at 1 must exclude
    # it even though the default (6) finds it, proving max_hops is enforced
    # rather than silently ignored.
    response = client.get("/api/attack-paths", params={"source": a, "target": c, "max_hops": 1})

    assert response.status_code == 200
    assert response.json()["paths"] == []
