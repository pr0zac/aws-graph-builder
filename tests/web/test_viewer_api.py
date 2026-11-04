from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from aws_graph_builder.web.server import create_app


def document() -> dict[str, Any]:
    return {
        "account_id": "111111111111", "generated_at": "2026-01-01T00:00:00Z",
        "regions_scanned": ["us-east-1"], "schema_version": "1.0",
        "nodes": [
            {"id": n, "name": n, "type": "IamRole", "arn": n, "properties": {"policy": "heavy"}}
            for n in ["a", "b", "c", "z"]
        ],
        "edges": [
            {"id": "ab1", "source": "a", "target": "b", "type": "CanAssume", "properties": {}},
            {"id": "ab2", "source": "a", "target": "b", "type": "PrivescPath",
             "properties": {"technique_id": "attach_policy", "condition_unresolved": True}},
            {"id": "bz", "source": "b", "target": "z", "type": "CanAssume", "properties": {}},
            {"id": "az", "source": "a", "target": "z", "type": "CanAssume", "properties": {}},
            {"id": "ac", "source": "a", "target": "c", "type": "AttachedPolicy", "properties": {}},
        ], "findings": [],
    }


def test_viewer_summary_reports_unknown_coverage_without_policy_blobs() -> None:
    client = TestClient(create_app(document()))
    response = client.get("/api/viewer")
    assert response.status_code == 200
    body = response.json()
    assert body["metadata"]["account_id"] == "111111111111"
    assert body["coverage"] == {"status": "unknown", "gaps": []}
    assert "properties" not in body["nodes"][0]
    edge = next(e for e in body["edges"] if e["id"] == "ab2")
    assert edge["condition_unresolved"] is True
    assert edge["technique_id"] == "attach_policy"


def test_viewer_propagates_evidence_uncertainty_and_actual_trust_field() -> None:
    doc = document()
    doc["edges"][0]["properties"] = {"external_id_required": True}
    doc["edges"][1]["properties"] = {"evidence_edges": ["permission"]}
    doc["edges"].append({"id": "permission", "source": "a", "target": "b", "type": "EffectivePermission",
                         "properties": {"condition_unresolved": True}})
    body = TestClient(create_app(doc)).get("/api/viewer").json()
    edges = {e["id"]: e for e in body["edges"]}
    assert edges["ab1"]["requires_external_id"] is True
    assert edges["ab2"]["condition_unresolved"] is True


def test_viewer_preserves_report_gaps() -> None:
    report = {"gaps": [{"service": "s3", "error_code": "AccessDenied"}]}
    client = TestClient(create_app(document(), report=report))
    body = client.get("/api/viewer").json()
    assert body["coverage"] == {"status": "partial", "gaps": report["gaps"]}


def test_unique_routes_are_shortest_first_and_preserve_parallel_evidence() -> None:
    client = TestClient(create_app(document()))
    response = client.get("/api/routes", params={"source": "a", "target": "z"})
    assert response.status_code == 200
    body = response.json()
    assert [p["nodes"] for p in body["paths"]] == [["a", "z"], ["a", "b", "z"]]
    assert body["paths"][1]["hops"][0]["edge_ids"] == ["ab1", "ab2"]
    assert body["complete"] is True
    assert body["truncated"] is False
    assert body["stop_reason"] == "exhausted"


def test_route_modes_do_not_confuse_structure_with_control() -> None:
    client = TestClient(create_app(document()))
    params = {"source": "a", "target": "c"}
    assert client.get("/api/routes", params=params).json()["paths"] == []
    assert client.get("/api/routes", params={**params, "mode": "reachability"}).json()["paths"][0]["nodes"] == ["a", "c"]


def test_routes_validate_queries_and_explain_already_target() -> None:
    client = TestClient(create_app(document()))
    for extra in [{"max_hops": 0}, {"max_hops": 11}, {"mode": "bad"}]:
        assert client.get("/api/routes", params={"source": "a", "target": "z", **extra}).status_code == 422
    assert client.get("/api/routes", params={"source": "missing", "target": "z"}).status_code == 404
    body = client.get("/api/routes", params={"source": "a", "target": "a"}).json()
    assert body["already_at_target"] is True
    assert body["paths"] == []


def test_routes_handle_high_value_and_disconnected_nodes() -> None:
    doc = document()
    doc["edges"].append({"id": "admin", "source": "z", "target": "z", "type": "EffectivePermission",
                         "properties": {"actions": ["*"], "resource_pattern": "*"}})
    client = TestClient(create_app(doc))
    assert client.get("/api/routes", params={"source": "a", "target": "high_value"}).json()["paths"][0]["nodes"] == ["a", "z"]
    assert client.get("/api/routes", params={"source": "z", "target": "high_value"}).json()["already_at_target"] is True
    assert client.get("/api/routes", params={"source": "c", "target": "z"}).json()["paths"] == []


def test_route_search_caps_unique_results_and_work(monkeypatch: Any) -> None:
    from aws_graph_builder.web import routes

    doc = document()
    monkeypatch.setattr(routes, "MAX_ROUTES", 1)
    client = TestClient(create_app(doc))
    body = client.get("/api/routes", params={"source": "a", "target": "z"}).json()
    assert len(body["paths"]) == 1
    assert body["truncated"] is True
    assert body["stop_reason"] == "route_limit"
    monkeypatch.setattr(routes, "MAX_STEPS", 1)
    body = client.get("/api/routes", params={"source": "a", "target": "z"}).json()
    assert body["complete"] is False
    assert body["stop_reason"] == "work_limit"


def test_route_deadline_is_reported(monkeypatch: Any) -> None:
    from aws_graph_builder.web import routes

    ticks = iter([0.0, 1.0])
    monkeypatch.setattr(routes, "monotonic", lambda: next(ticks, 1.0))
    client = TestClient(create_app(document()))
    body = client.get("/api/routes", params={"source": "a", "target": "z"}).json()
    assert body["complete"] is False
    assert body["stop_reason"] == "time_limit"


def test_missing_high_value_targets_returns_complete_empty_without_traversal(monkeypatch: Any) -> None:
    from aws_graph_builder.web import routes

    monkeypatch.setattr(routes, "MAX_STEPS", 0)
    body = TestClient(create_app(document())).get("/api/routes", params={"source": "a", "target": "high_value"}).json()
    assert body["paths"] == []
    assert body["complete"] is True
    assert body["truncated"] is False
