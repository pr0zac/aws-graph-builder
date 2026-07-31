"""Technique metadata, finding shape, and the detector registration
mechanism every module in `privesc/techniques/` uses to add itself to the
catalog `privesc/engine.py` iterates over.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery


@dataclass(frozen=True)
class TechniqueSpec:
    """Static metadata describing one privesc technique -- independent of
    any particular finding.
    """

    id: str
    name: str
    description: str
    reference_url: str
    severity: str


@dataclass
class PrivescFinding:
    """One concrete instance of a technique applying to a specific
    (source, target) pair, produced by a detector function.
    """

    technique_id: str
    source: str
    target: str
    severity: str
    required_permissions: list[str]
    evidence_edges: list[str]
    description: str


# A detector inspects one candidate source principal at a time (the engine
# loops over every IamUser/IamRole node and calls each registered detector
# once per principal), querying already-materialized EffectivePermission
# edges via `query` -- it never re-parses raw policy JSON.
DetectorFn = Callable[[nx.MultiDiGraph, str, PermissionQuery], list[PrivescFinding]]

_REGISTRY: list[tuple[TechniqueSpec, DetectorFn]] = []


def register(spec: TechniqueSpec) -> Callable[[DetectorFn], DetectorFn]:
    """Decorator: register `fn` as the detector for `spec`, appending
    `(spec, fn)` to the module-level registry. Returns `fn` unchanged so the
    decorated function stays directly importable/callable for its own unit
    tests.
    """

    def decorator(fn: DetectorFn) -> DetectorFn:
        _REGISTRY.append((spec, fn))
        return fn

    return decorator


def all_techniques() -> list[tuple[TechniqueSpec, DetectorFn]]:
    """A copy of the registry -- mutating the returned list never affects
    what's actually registered.
    """
    return list(_REGISTRY)
