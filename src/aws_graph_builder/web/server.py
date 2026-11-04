"""FastAPI app factory for the local visualizer: serves a previously-written
graph.json document for interactive, offline exploration in a browser.

The document is kept in memory verbatim (`app.state.document`) for full
node/edge/finding property lookups, alongside an `nx.MultiDiGraph`
reconstructed via `graph.export.document_to_graph` (`app.state.graph`) for
path-finding queries -- no AWS calls, no re-evaluation, purely a read-only
view over what `scan`/`rebuild` already computed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import networkx as nx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from aws_graph_builder.eval.high_value import find_high_value_principals
from aws_graph_builder.graph.export import document_to_graph
from aws_graph_builder.graph.schema import EdgeType
from aws_graph_builder.web.api import router
from aws_graph_builder.web.viewer_api import router as viewer_router

_STATIC_DIR = Path(__file__).parent / "static"

# The "control-transfer" edge subset: traversing one of these means you now
# control the target principal (you can assume the role, or a detector has
# already proven a privesc technique gets you there). Raw EffectivePermission/
# MemberOf/AttachedPolicy edges are evidence for *why* a PrivescPath edge
# exists, not pivots themselves, so attack-path queries deliberately exclude
# them -- chaining through "can read an S3 bucket" would produce nonsense
# paths. This is the BloodHound-style "abusable edge" analogue.
_ATTACK_EDGE_TYPES = {EdgeType.CAN_ASSUME.value, EdgeType.PRIVESC_PATH.value}


def _build_attack_subgraph(graph: nx.MultiDiGraph) -> nx.MultiDiGraph:
    subgraph: nx.MultiDiGraph = nx.MultiDiGraph()
    for u, v, k, data in graph.edges(keys=True, data=True):
        if data.get("type") in _ATTACK_EDGE_TYPES:
            subgraph.add_edge(u, v, key=k, **data)
    return subgraph


def create_app(document: dict[str, Any], *, report: dict[str, Any] | None = None) -> FastAPI:
    """Build the FastAPI app serving `document` (a graph.json-shaped dict)."""
    app = FastAPI(title="aws-graph-builder visualizer")
    app.state.document = document
    app.state.report = report
    app.state.graph = document_to_graph(document)
    app.state.attack_graph = _build_attack_subgraph(app.state.graph)
    # Computed once at startup, same as attack_graph above -- the "keys to
    # the kingdom" principal set (see eval/high_value.py), read by both the
    # /api/attack-paths target=high_value sentinel and the high_value field
    # exposed on /api/graph and /api/node responses.
    app.state.high_value_principal_ids = find_high_value_principals(app.state.graph)
    # Built once at startup rather than scanning document["nodes"/"edges"]
    # per request -- id lookups back the /api/node and /api/edge endpoints.
    app.state.nodes_by_id = {node["id"]: node for node in document["nodes"]}
    app.state.edges_by_id = {edge["id"]: edge for edge in document["edges"]}

    app.include_router(router)
    app.include_router(viewer_router)
    # Mounted last and at "/" so it only catches requests the API router
    # above didn't already handle; `html=True` serves static/index.html for "/".
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")

    return app
