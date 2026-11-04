"""Additive viewer contracts. Legacy graph/path endpoints stay compatible."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request

from aws_graph_builder.web.routes import find_routes

router = APIRouter(prefix="/api")


@router.get("/viewer")
def viewer(request: Request) -> dict[str, Any]:
    state = request.app.state
    doc = state.document
    report = state.report
    gaps = report.get("gaps", []) if report is not None else []
    def uncertain(edge: dict[str, Any]) -> bool:
        props = edge.get("properties", {})
        return bool(props.get("condition_unresolved")) or any(
            state.edges_by_id.get(edge_id, {}).get("properties", {}).get("condition_unresolved", False)
            for edge_id in props.get("evidence_edges", [])
        )
    return {
        "metadata": {k: doc.get(k) for k in ("account_id", "generated_at", "regions_scanned", "schema_version")},
        "coverage": {"status": "unknown" if report is None else ("partial" if gaps else "complete"), "gaps": gaps},
        "nodes": [{"id": n["id"], "name": n["name"], "type": n["type"], "arn": n.get("arn"),
                   "high_value": n["id"] in state.high_value_principal_ids} for n in doc["nodes"]],
        "edges": [
            {"id": e["id"], "type": e["type"], "source": e["source"], "target": e["target"],
             "condition_unresolved": uncertain(e),
             "technique_id": e.get("properties", {}).get("technique_id"),
             "requires_mfa": bool(e.get("properties", {}).get("requires_mfa")),
             "requires_external_id": bool(e.get("properties", {}).get("external_id_required"))}
            for e in doc["edges"]
        ],
    }


@router.get("/routes")
def routes(
    request: Request, source: str, target: str,
    mode: Literal["attack", "reachability"] = "attack",
    max_hops: Annotated[int, Query(ge=1, le=10)] = 6,
) -> dict[str, Any]:
    state = request.app.state
    if source not in state.graph:
        raise HTTPException(404, "Source node not found")
    if target == "high_value":
        if mode != "attack":
            raise HTTPException(422, "High-value targets require attack mode")
        targets = set(state.high_value_principal_ids)
    else:
        if target not in state.graph:
            raise HTTPException(404, "Target node not found")
        targets = {target}
    if source in targets:
        return {"paths": [], "complete": True, "truncated": False,
                "stop_reason": "already_at_target", "already_at_target": True}
    graph = state.attack_graph if mode == "attack" else state.graph
    return find_routes(graph, source, targets, max_hops)
