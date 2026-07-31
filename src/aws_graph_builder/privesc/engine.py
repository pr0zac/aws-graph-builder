"""Orchestrates the privesc technique catalog over an already-evaluated
graph (i.e. after `eval.engine.evaluate_iam_permissions` has materialized
`EffectivePermission`/`CanAssume` edges): runs every registered detector
against every candidate principal, materializes one `PrivescPath` edge per
finding, and returns the flat findings list for the CLI layer to attach to
the JSON output document's `"findings"` key.
"""

from __future__ import annotations

import networkx as nx

# Imported for its `@register` side effects -- this triggers every technique
# module in `privesc/techniques/` to register itself before `all_techniques()`
# is called below.
import aws_graph_builder.privesc.techniques  # noqa: F401
from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.graph.export import add_edge
from aws_graph_builder.graph.schema import Edge, EdgeType, NodeType, make_edge_id
from aws_graph_builder.privesc.registry import PrivescFinding, all_techniques

# Same candidate-source convention as `eval/engine.py`: IamGroup nodes can't
# call AWS APIs, so they're never a privesc *source*, only ever a valid
# target.
_CANDIDATE_SOURCE_TYPES = {NodeType.IAM_USER.value, NodeType.IAM_ROLE.value}


def run_privesc_detection(graph: nx.MultiDiGraph) -> list[PrivescFinding]:
    """Mutate `graph` in place, adding one `PrivescPath` edge per finding,
    and return the flat list of `PrivescFinding`s (sorted by
    (technique_id, source, target) for reproducible output).
    """
    query = PermissionQuery(graph)
    candidate_principals = [
        node_id for node_id, data in graph.nodes(data=True) if data.get("type") in _CANDIDATE_SOURCE_TYPES
    ]

    findings: list[PrivescFinding] = []
    for principal_id in candidate_principals:
        for _spec, detector in all_techniques():
            findings.extend(detector(graph, principal_id, query))

    findings.sort(key=lambda finding: (finding.technique_id, finding.source, finding.target))

    for finding in findings:
        # `discriminator=technique_id`: the same (source, target) pair can
        # have PrivescPath edges for multiple distinct techniques (e.g. a
        # principal that can both create_access_key AND attach_policy
        # against the same target), and each must be its own edge rather
        # than overwriting the others.
        edge_id = make_edge_id(
            EdgeType.PRIVESC_PATH, finding.source, finding.target, discriminator=finding.technique_id
        )
        add_edge(
            graph,
            Edge(
                id=edge_id,
                type=EdgeType.PRIVESC_PATH,
                source=finding.source,
                target=finding.target,
                properties={
                    "technique_id": finding.technique_id,
                    "severity": finding.severity,
                    "required_permissions": finding.required_permissions,
                    "evidence_edges": finding.evidence_edges,
                    "description": finding.description,
                },
            ),
        )

    return findings
