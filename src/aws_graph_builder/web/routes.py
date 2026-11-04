"""Bounded shortest-first traversal of unique node routes, not edge permutations."""

from __future__ import annotations

from collections import deque
from itertools import pairwise
from time import monotonic
from typing import Any

import networkx as nx

MAX_ROUTES = 200
MAX_STEPS = 25_000
MAX_SECONDS = 0.5


def find_routes(graph: nx.MultiDiGraph, source: str, targets: set[str], max_hops: int) -> dict[str, Any]:
    """Breadth-first traversal with deterministic neighbors and bounded queue growth.

    Every examined successor consumes work, including cyclic/dead-end candidates.
    One extra result distinguishes an exact result-cap match from actual truncation.
    """
    if not targets:
        return {"paths": [], "complete": True, "truncated": False,
                "stop_reason": "exhausted", "already_at_target": False}
    deadline = monotonic() + MAX_SECONDS
    pending: deque[list[str]] = deque([[source]])
    found: list[list[str]] = []
    steps = 0
    reason = "exhausted"
    neighbors: dict[str, list[str]] = {}
    while pending:
        if monotonic() >= deadline:
            reason = "time_limit"
            break
        path = pending.popleft()
        last = path[-1]
        if len(path) > 1 and last in targets:
            found.append(path)
            if len(found) > MAX_ROUTES:
                reason = "route_limit"
                break
        if len(path) - 1 >= max_hops or last not in graph:
            continue
        if last not in neighbors:
            neighbors[last] = sorted(str(n) for n in graph.successors(last))
        for neighbor in neighbors[last]:
            if steps >= MAX_STEPS:
                reason = "work_limit"
                break
            steps += 1
            if neighbor not in path:
                pending.append([*path, neighbor])
        if reason != "exhausted":
            break
    paths = [
        {"nodes": path, "hops": [
            {"source": u, "target": v, "edge_ids": sorted(str(k) for k in graph[u][v])}
            for u, v in pairwise(path)
        ]}
        for path in found[:MAX_ROUTES]
    ]
    return {"paths": paths, "complete": reason == "exhausted", "truncated": reason != "exhausted",
            "stop_reason": reason, "already_at_target": False}
