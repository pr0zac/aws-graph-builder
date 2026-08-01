"""API route handlers for the visualizer, mounted under `/api` by
`server.py`: read endpoints over a loaded graph.json document (`/api/graph`,
`/api/node`, `/api/edge`, `/api/findings`) plus path-query endpoints
(`/api/paths`, `/api/attack-paths`) added by a later task.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from itertools import islice, pairwise
from typing import Any

import networkx as nx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter(prefix="/api")

# Bounds on path-query cost: AWS graphs can have combinatorially many simple
# paths between two nodes, so both the hop count and the total number of
# paths returned are capped regardless of what a caller requests.
_DEFAULT_MAX_HOPS = 6
_MAX_HOPS_CEILING = 10
_MAX_PATHS = 200

# `/api/attack-paths?target=high_value` sentinel value: "any node in
# app.state.high_value_principal_ids" -- see get_attack_paths below.
_HIGH_VALUE_TARGET_SENTINEL = "high_value"


class GraphNode(BaseModel):
    id: str
    type: str
    name: str
    arn: str | None
    high_value: bool


class GraphEdge(BaseModel):
    id: str
    type: str
    source: str
    target: str


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class Finding(BaseModel):
    technique_id: str
    source: str
    target: str
    severity: str
    required_permissions: list[str]
    evidence_edges: list[str]
    edge_id: str
    description: str


@router.get("/graph")
def get_graph(request: Request) -> GraphResponse:
    """Trimmed nodes/edges for the initial graph render -- omits per-node/edge
    `properties` (raw policy documents, evidence chains, etc.), which is
    where nearly all of a scan output's file size lives. Full detail for a
    given node or edge is fetched on demand via `/api/node` / `/api/edge`.
    """
    document = request.app.state.document
    high_value_ids = request.app.state.high_value_principal_ids
    return GraphResponse(
        nodes=[
            GraphNode(id=n["id"], type=n["type"], name=n["name"], arn=n.get("arn"), high_value=n["id"] in high_value_ids)
            for n in document["nodes"]
        ],
        edges=[GraphEdge(id=e["id"], type=e["type"], source=e["source"], target=e["target"]) for e in document["edges"]],
    )


@router.get("/node")
def get_node(id: str, request: Request) -> dict[str, Any]:
    """Full node detail (including `properties`) for the inspector panel.

    `id` is a query param rather than a path segment -- node ids are ARNs
    full of `:` and `/`, which are awkward to URL-encode as path segments.
    """
    node = request.app.state.nodes_by_id.get(id)
    if node is None:
        raise HTTPException(status_code=404, detail=f"no node with id {id!r}")
    # Shallow-copy rather than mutating the cached dict in place: node is the
    # very same object stored in app.state.nodes_by_id, shared across every
    # request.
    return {**node, "high_value": id in request.app.state.high_value_principal_ids}


@router.get("/edge")
def get_edge(id: str, request: Request) -> dict[str, Any]:
    """Full edge detail (including `properties`) for the inspector panel."""
    edge = request.app.state.edges_by_id.get(id)
    if edge is None:
        raise HTTPException(status_code=404, detail=f"no edge with id {id!r}")
    return edge


@router.get("/findings")
def get_findings(request: Request) -> list[Finding]:
    """Every detected privesc finding, as written by the privesc engine."""
    return [Finding(**finding) for finding in request.app.state.document.get("findings", [])]


class PathHop(BaseModel):
    source: str
    target: str
    edge_ids: list[str]


class Path(BaseModel):
    nodes: list[str]
    hops: list[PathHop]


class PathsResponse(BaseModel):
    paths: list[Path]


def _simple_node_paths(traversal_graph: nx.MultiDiGraph, source: str, target: str, cutoff: int) -> Iterator[list[str]]:
    """`nx.all_simple_paths`, but tolerant of `source`/`target` not being part
    of `traversal_graph` at all (yields nothing instead of raising
    `NodeNotFound`) -- shared by both the single-target and merged
    multi-target (`target=high_value`) queries below.
    """
    if source not in traversal_graph or target not in traversal_graph:
        return iter(())
    return nx.all_simple_paths(traversal_graph, source, target, cutoff=cutoff)


def _paths_response(node_paths: Iterable[list[str]], *, traversal_graph: nx.MultiDiGraph) -> PathsResponse:
    paths = []
    for node_path in node_paths:
        hops = [
            PathHop(source=u, target=v, edge_ids=[str(key) for key in traversal_graph.get_edge_data(u, v)])
            for u, v in pairwise(node_path)
        ]
        paths.append(Path(nodes=node_path, hops=hops))
    return PathsResponse(paths=paths)


def _find_paths(
    *,
    traversal_graph: nx.MultiDiGraph,
    full_graph: nx.MultiDiGraph,
    source: str,
    target: str,
    max_hops: int,
) -> PathsResponse:
    """Shared implementation for `/api/paths` and `/api/attack-paths`:
    `traversal_graph` is the (possibly edge-filtered) graph paths are found
    over, `full_graph` is used only to distinguish "no such node in this
    account" (404) from "this node exists but isn't part of this edge
    subset" (empty result) -- for `/api/paths` the two graphs are the same.
    """
    if source not in full_graph or target not in full_graph:
        raise HTTPException(status_code=404, detail="source or target node not found in graph")

    cutoff = min(max_hops, _MAX_HOPS_CEILING)
    node_paths = islice(_simple_node_paths(traversal_graph, source, target, cutoff), _MAX_PATHS)
    return _paths_response(node_paths, traversal_graph=traversal_graph)


def _find_paths_to_any(
    *,
    traversal_graph: nx.MultiDiGraph,
    source: str,
    targets: Iterable[str],
    max_hops: int,
) -> PathsResponse:
    """Merge simple-path results from `source` to every node in `targets`,
    capping the *combined* result at `_MAX_PATHS` (not per-target) -- used
    for the `target=high_value` sentinel so the response size can't blow up
    just because an account has several high-value principals. Callers are
    expected to have already validated `source` itself (404 if unknown).
    """
    cutoff = min(max_hops, _MAX_HOPS_CEILING)
    combined: list[list[str]] = []
    for target in targets:
        if len(combined) >= _MAX_PATHS:
            break
        remaining = _MAX_PATHS - len(combined)
        combined.extend(islice(_simple_node_paths(traversal_graph, source, target, cutoff), remaining))
    return _paths_response(combined, traversal_graph=traversal_graph)


@router.get("/paths")
def get_paths(source: str, target: str, request: Request, max_hops: int = _DEFAULT_MAX_HOPS) -> PathsResponse:
    """General reachability between two nodes via any edge type, for
    exploring graph structure (not attack-path semantics -- see
    `/api/attack-paths` for that).
    """
    return _find_paths(
        traversal_graph=request.app.state.graph,
        full_graph=request.app.state.graph,
        source=source,
        target=target,
        max_hops=max_hops,
    )


@router.get("/attack-paths")
def get_attack_paths(source: str, target: str, request: Request, max_hops: int = _DEFAULT_MAX_HOPS) -> PathsResponse:
    """BloodHound-style attack-path query: reachability restricted to the
    "control-transfer" edge subset (CanAssume + PrivescPath) built at
    startup as `app.state.attack_graph` -- see `server.py` for why those two
    edge types (and not raw EffectivePermission/MemberOf/AttachedPolicy
    edges) are the ones that mean "traversing this gets you control of the
    target principal".

    `target=high_value` is a sentinel meaning "any node in
    `app.state.high_value_principal_ids`" (see `eval/high_value.py`):
    results from every high-value principal are merged into one response,
    respecting `_MAX_PATHS` across the combined result rather than per-target
    (see `_find_paths_to_any`). Per the BloodHound "shortest path to DA"
    analogy, if there are zero high-value principals, or `source` is itself
    high-value, this returns the normal empty-paths shape rather than
    searching for something that's already true or doesn't exist -- but an
    unknown `source` (not a real node at all) still 404s exactly like the
    plain single-target case below.
    """
    full_graph = request.app.state.graph
    traversal_graph = request.app.state.attack_graph

    if target == _HIGH_VALUE_TARGET_SENTINEL:
        if source not in full_graph:
            raise HTTPException(status_code=404, detail=f"source node not found in graph: {source!r}")
        high_value_ids = request.app.state.high_value_principal_ids
        if not high_value_ids or source in high_value_ids:
            return PathsResponse(paths=[])
        return _find_paths_to_any(
            traversal_graph=traversal_graph,
            source=source,
            targets=sorted(high_value_ids),
            max_hops=max_hops,
        )

    return _find_paths(
        traversal_graph=traversal_graph,
        full_graph=full_graph,
        source=source,
        target=target,
        max_hops=max_hops,
    )


@router.get("/high-value-principals")
def get_high_value_principals(request: Request) -> list[str]:
    """Every node id currently flagged high-value (see `eval/high_value.py`)
    -- a convenience listing endpoint. The same information is also exposed
    per-node via the `high_value` field on `/api/graph` and `/api/node`, so
    this is purely for a caller that just wants the flat id list.
    """
    return sorted(request.app.state.high_value_principal_ids)
