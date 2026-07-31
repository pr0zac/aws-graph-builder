"""Conversion between the in-memory `networkx.MultiDiGraph` and the JSON
node-link output document described in aws-graph-builder.md's "JSON output
schema" section.

The graph is a `MultiDiGraph` (directed, parallel edges) because two nodes can
be connected by more than one edge of different types -- e.g. a role can have
both an `AttachedPolicy` edge and a `HasPermissionBoundary` edge to the same
`ManagedPolicy` node.

Node/edge attributes are stored as plain JSON-compatible values (enum `.value`
strings, not enum instances) so the graph is trivially serializable at every
point, not just at export time.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import networkx as nx

from aws_graph_builder.graph.schema import Edge, Node

SCHEMA_VERSION = "1.0"


def new_graph() -> nx.MultiDiGraph:
    """Construct an empty, directed, parallel-edge-capable graph."""
    return nx.MultiDiGraph()


def add_node(graph: nx.MultiDiGraph, node: Node) -> None:
    """Add or update `node` in `graph`, storing its fields as node attributes."""
    graph.add_node(
        node.id,
        type=node.type.value,
        name=node.name,
        arn=node.arn,
        properties=node.properties,
    )


def add_edge(graph: nx.MultiDiGraph, edge: Edge) -> None:
    """Add or update `edge` in `graph`, keyed by `edge.id` so parallel edges
    between the same (source, target) pair are individually addressable and
    the id round-trips through export/import.
    """
    graph.add_edge(
        edge.source,
        edge.target,
        key=edge.id,
        id=edge.id,
        type=edge.type.value,
        properties=edge.properties,
    )


def graph_to_document(
    graph: nx.MultiDiGraph,
    *,
    account_id: str,
    regions_scanned: list[str],
) -> dict[str, Any]:
    """Render `graph` into the full JSON output document.

    Nodes and edges are shaped explicitly from the graph's stored attributes
    (rather than dumping `networkx.node_link_data` verbatim) so the emitted
    dicts match the schema exactly. Output is sorted by id for reproducible,
    diff-friendly output across runs. No `findings` key is included -- that's
    populated by the privesc engine in a later phase.
    """
    nodes = [
        {
            "id": node_id,
            "type": data["type"],
            "name": data["name"],
            "arn": data["arn"],
            "properties": data.get("properties", {}),
        }
        for node_id, data in graph.nodes(data=True)
    ]
    nodes.sort(key=lambda n: n["id"])

    edges = [
        {
            "id": data["id"],
            "type": data["type"],
            "source": source,
            "target": target,
            "properties": data.get("properties", {}),
        }
        for source, target, data in graph.edges(data=True)
    ]
    edges.sort(key=lambda e: e["id"])

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "account_id": account_id,
        "regions_scanned": list(regions_scanned),
        "nodes": nodes,
        "edges": edges,
    }


def document_to_graph(document: dict[str, Any]) -> nx.MultiDiGraph:
    """Reconstruct a `MultiDiGraph` from a document produced by
    `graph_to_document`, with the same node/edge attributes.
    """
    graph = new_graph()
    for node_doc in document["nodes"]:
        graph.add_node(
            node_doc["id"],
            type=node_doc["type"],
            name=node_doc["name"],
            arn=node_doc["arn"],
            properties=node_doc.get("properties", {}),
        )
    for edge_doc in document["edges"]:
        graph.add_edge(
            edge_doc["source"],
            edge_doc["target"],
            key=edge_doc["id"],
            id=edge_doc["id"],
            type=edge_doc["type"],
            properties=edge_doc.get("properties", {}),
        )
    return graph
