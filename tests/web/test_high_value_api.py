"""API-level tests for the high-value-principal feature (see
`eval/high_value.py`): the `high_value` field on `/api/graph`/`/api/node`,
the `/api/attack-paths?target=high_value` sentinel, and the convenience
`/api/high-value-principals` endpoint.

Sibling to `test_api.py` (which already covers the base `/api/graph`,
`/api/node`, `/api/paths`, `/api/attack-paths` behavior) rather than folded
into it, to avoid clobbering that file.
"""

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


def _effective_permission_edge(source: str, target: str, *, actions: list[str], resource_pattern: str) -> dict[str, Any]:
    return {
        "id": make_edge_id(EdgeType.EFFECTIVE_PERMISSION, source, target),
        "type": EdgeType.EFFECTIVE_PERMISSION.value,
        "source": source,
        "target": target,
        "properties": {"actions": actions, "resource_pattern": resource_pattern},
    }


def _can_assume_edge(source: str, target: str) -> dict[str, Any]:
    return {
        "id": make_edge_id(EdgeType.CAN_ASSUME, source, target),
        "type": EdgeType.CAN_ASSUME.value,
        "source": source,
        "target": target,
        "properties": {},
    }


def _document(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-01-01T00:00:00Z",
        "account_id": ACCOUNT_ID,
        "regions_scanned": [],
        "nodes": nodes,
        "edges": edges,
    }


def _client(document: dict[str, Any]) -> TestClient:
    return TestClient(create_app(document))


# --------------------------------------------------------------------------
# Fixture: a small graph with one high-value role (admin) reachable from a
# regular user (mallory) via a CanAssume edge, one non-high-value role
# (limited) also reachable from mallory, and a bucket node the admin role
# has a wildcard EffectivePermission grant against.
# --------------------------------------------------------------------------

MALLORY = f"arn:aws:iam::{ACCOUNT_ID}:user/mallory"
ADMIN_ROLE = f"arn:aws:iam::{ACCOUNT_ID}:role/admin-role"
LIMITED_ROLE = f"arn:aws:iam::{ACCOUNT_ID}:role/limited-role"
BUCKET = "arn:aws:s3:::some-bucket"


def _fixture_document() -> dict[str, Any]:
    nodes = [
        _node(MALLORY, NodeType.IAM_USER, "mallory"),
        _node(ADMIN_ROLE, NodeType.IAM_ROLE, "admin-role"),
        _node(LIMITED_ROLE, NodeType.IAM_ROLE, "limited-role"),
        _node(BUCKET, NodeType.S3_BUCKET, "some-bucket"),
    ]
    edges = [
        _can_assume_edge(MALLORY, ADMIN_ROLE),
        _can_assume_edge(MALLORY, LIMITED_ROLE),
        _effective_permission_edge(ADMIN_ROLE, BUCKET, actions=["*"], resource_pattern="*"),
        _effective_permission_edge(LIMITED_ROLE, BUCKET, actions=["s3:GetObject"], resource_pattern="*"),
    ]
    return _document(nodes, edges)


# --------------------------------------------------------------------------
# /api/graph + /api/node: high_value field
# --------------------------------------------------------------------------


def test_get_graph_marks_high_value_node() -> None:
    client = _client(_fixture_document())

    response = client.get("/api/graph")

    assert response.status_code == 200
    nodes_by_id = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes_by_id[ADMIN_ROLE]["high_value"] is True
    assert nodes_by_id[LIMITED_ROLE]["high_value"] is False
    assert nodes_by_id[MALLORY]["high_value"] is False


def test_get_node_includes_high_value_field() -> None:
    client = _client(_fixture_document())

    admin_response = client.get("/api/node", params={"id": ADMIN_ROLE})
    limited_response = client.get("/api/node", params={"id": LIMITED_ROLE})

    assert admin_response.status_code == 200
    assert admin_response.json()["high_value"] is True
    assert limited_response.status_code == 200
    assert limited_response.json()["high_value"] is False


# --------------------------------------------------------------------------
# /api/high-value-principals
# --------------------------------------------------------------------------


def test_high_value_principals_endpoint_lists_ids() -> None:
    client = _client(_fixture_document())

    response = client.get("/api/high-value-principals")

    assert response.status_code == 200
    assert response.json() == [ADMIN_ROLE]


def test_high_value_principals_endpoint_empty_when_none_qualify() -> None:
    nodes = [_node(MALLORY, NodeType.IAM_USER, "mallory")]
    client = _client(_document(nodes, []))

    response = client.get("/api/high-value-principals")

    assert response.status_code == 200
    assert response.json() == []


# --------------------------------------------------------------------------
# /api/attack-paths?target=high_value
# --------------------------------------------------------------------------


def test_attack_paths_high_value_sentinel_finds_path_to_admin() -> None:
    client = _client(_fixture_document())

    response = client.get("/api/attack-paths", params={"source": MALLORY, "target": "high_value"})

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert len(paths) == 1
    assert paths[0]["nodes"] == [MALLORY, ADMIN_ROLE]


def test_attack_paths_high_value_sentinel_empty_when_no_high_value_principals() -> None:
    nodes = [
        _node(MALLORY, NodeType.IAM_USER, "mallory"),
        _node(LIMITED_ROLE, NodeType.IAM_ROLE, "limited-role"),
    ]
    edges = [_can_assume_edge(MALLORY, LIMITED_ROLE)]
    client = _client(_document(nodes, edges))

    response = client.get("/api/attack-paths", params={"source": MALLORY, "target": "high_value"})

    assert response.status_code == 200
    assert response.json()["paths"] == []


def test_attack_paths_high_value_sentinel_empty_when_source_itself_high_value() -> None:
    client = _client(_fixture_document())

    response = client.get("/api/attack-paths", params={"source": ADMIN_ROLE, "target": "high_value"})

    assert response.status_code == 200
    assert response.json()["paths"] == []


def test_attack_paths_high_value_sentinel_empty_when_source_cannot_reach_admin() -> None:
    """limited-role has no outgoing CanAssume/PrivescPath edges at all, so
    even though a high-value principal exists elsewhere in the graph, this
    must resolve to the normal empty shape rather than an error.
    """
    client = _client(_fixture_document())

    response = client.get("/api/attack-paths", params={"source": LIMITED_ROLE, "target": "high_value"})

    assert response.status_code == 200
    assert response.json()["paths"] == []


def test_attack_paths_high_value_sentinel_404_when_source_not_a_real_node() -> None:
    client = _client(_fixture_document())
    ghost = f"arn:aws:iam::{ACCOUNT_ID}:user/ghost"

    response = client.get("/api/attack-paths", params={"source": ghost, "target": "high_value"})

    assert response.status_code == 404
    assert response.json()["detail"]


def test_attack_paths_high_value_sentinel_merges_across_multiple_high_value_targets() -> None:
    """Two independent high-value roles, both reachable from the same
    source via a one-hop CanAssume edge -- both must show up in the merged
    result, proving the sentinel doesn't just find the first match.
    """
    second_admin = f"arn:aws:iam::{ACCOUNT_ID}:role/second-admin-role"
    nodes = [
        _node(MALLORY, NodeType.IAM_USER, "mallory"),
        _node(ADMIN_ROLE, NodeType.IAM_ROLE, "admin-role"),
        _node(second_admin, NodeType.IAM_ROLE, "second-admin-role"),
        _node(BUCKET, NodeType.S3_BUCKET, "some-bucket"),
    ]
    edges = [
        _can_assume_edge(MALLORY, ADMIN_ROLE),
        _can_assume_edge(MALLORY, second_admin),
        _effective_permission_edge(ADMIN_ROLE, BUCKET, actions=["*"], resource_pattern="*"),
        _effective_permission_edge(second_admin, BUCKET, actions=["iam:*"], resource_pattern="*"),
    ]
    client = _client(_document(nodes, edges))

    response = client.get("/api/attack-paths", params={"source": MALLORY, "target": "high_value"})

    assert response.status_code == 200
    paths = response.json()["paths"]
    result_targets = {path["nodes"][-1] for path in paths}
    assert result_targets == {ADMIN_ROLE, second_admin}
