"""The shared back half of both `scan` and `rebuild`: once every scanner
result is in hand (fetched live, or replayed from cache), both commands do
the exact same thing with them -- build the structural graph, evaluate
policies, run privesc detection, write the JSON graph document, write the
companion `*.report.json`, print gap warnings, and print a final summary
line. Factored out here so a fix/change to any of that only needs to happen
once.
"""

from __future__ import annotations

import json
from pathlib import Path

import networkx as nx

from aws_graph_builder.cli._common import json_default, stderr_console, stdout_console
from aws_graph_builder.eval.engine import evaluate_iam_permissions
from aws_graph_builder.graph.builder import (
    add_ec2_instances_to_graph,
    add_lambda_functions_to_graph,
    add_s3_buckets_to_graph,
    add_scp_policies_to_graph,
    build_iam_graph,
)
from aws_graph_builder.graph.export import graph_to_document
from aws_graph_builder.graph.schema import EdgeType, make_edge_id
from aws_graph_builder.privesc.engine import run_privesc_detection
from aws_graph_builder.report import (
    build_scan_report,
    report_path_for,
    write_scan_report,
)
from aws_graph_builder.scan.base import ScanGap
from aws_graph_builder.scan.ec2 import Ec2ScanResult
from aws_graph_builder.scan.iam import IamScanResult
from aws_graph_builder.scan.lambda_ import LambdaScanResult
from aws_graph_builder.scan.organizations import OrganizationsScanResult
from aws_graph_builder.scan.s3 import S3ScanResult


def collect_gaps(
    *,
    iam_result: IamScanResult,
    ec2_results: list[Ec2ScanResult],
    lambda_results: list[LambdaScanResult],
    s3_result: S3ScanResult,
    organizations_result: OrganizationsScanResult,
) -> list[ScanGap]:
    """Every `ScanGap` across every scanner, in a stable, deterministic
    order (IAM, then EC2/Lambda per region in scan order, then S3, then
    Organizations) -- shared by `scan` (live gaps) and `rebuild` (replayed
    gaps, including `NoCachedData` for anything never scanned).
    """
    gaps: list[ScanGap] = list(iam_result.gaps)
    for ec2_result in ec2_results:
        gaps.extend(ec2_result.gaps)
    for lambda_result in lambda_results:
        gaps.extend(lambda_result.gaps)
    gaps.extend(s3_result.gaps)
    gaps.extend(organizations_result.gaps)
    return gaps


def build_graph(
    *,
    iam_result: IamScanResult,
    ec2_results: list[Ec2ScanResult],
    lambda_results: list[LambdaScanResult],
    s3_result: S3ScanResult,
    organizations_result: OrganizationsScanResult,
    account_id: str,
) -> nx.MultiDiGraph:
    """Structural graph from every scanner's raw result -- the same
    resource-type-by-resource-type assembly `scan_cmd.py` used to do
    inline, now shared with `rebuild_cmd.py`.
    """
    graph = build_iam_graph(iam_result, account_id=account_id)
    for ec2_result in ec2_results:
        add_ec2_instances_to_graph(graph, ec2_result, account_id=account_id)
    for lambda_result in lambda_results:
        add_lambda_functions_to_graph(graph, lambda_result)
    add_s3_buckets_to_graph(graph, s3_result)
    add_scp_policies_to_graph(graph, organizations_result, account_id=account_id)
    return graph


def evaluate_and_detect(graph: nx.MultiDiGraph, *, verbose: bool = False) -> list[dict[str, object]]:
    """Run policy evaluation then privesc detection over `graph` in place,
    printing `--verbose` progress in the same style both commands already
    use, and return the findings list already shaped for the output
    document's `"findings"` key.
    """
    if verbose:
        stdout_console.print("[dim cyan]Evaluating IAM/resource policies...[/dim cyan]", soft_wrap=True)
    evaluate_iam_permissions(graph)
    if verbose:
        effective_permission_count = sum(
            1 for _u, _v, data in graph.edges(data=True) if data.get("type") == EdgeType.EFFECTIVE_PERMISSION.value
        )
        can_assume_count = sum(1 for _u, _v, data in graph.edges(data=True) if data.get("type") == EdgeType.CAN_ASSUME.value)
        stdout_console.print(
            f"[dim cyan]  materialized {effective_permission_count} EffectivePermission edge(s), "
            f"{can_assume_count} CanAssume edge(s)[/dim cyan]",
            soft_wrap=True,
        )

    if verbose:
        stdout_console.print("[dim cyan]Running privesc detection...[/dim cyan]", soft_wrap=True)
    findings = run_privesc_detection(graph)
    if verbose:
        stdout_console.print(f"[dim cyan]  found {len(findings)} finding(s)[/dim cyan]", soft_wrap=True)

    return [
        {
            "technique_id": finding.technique_id,
            "source": finding.source,
            "target": finding.target,
            "severity": finding.severity,
            "required_permissions": finding.required_permissions,
            "evidence_edges": finding.evidence_edges,
            "edge_id": make_edge_id(EdgeType.PRIVESC_PATH, finding.source, finding.target, discriminator=finding.technique_id),
            "description": finding.description,
        }
        for finding in findings
    ]


def write_output_and_report(
    graph: nx.MultiDiGraph,
    findings: list[dict[str, object]],
    *,
    account_id: str,
    target_regions: list[str],
    gaps: list[ScanGap],
    output: Path,
) -> None:
    """Write the JSON graph document to `output` and the companion
    `*.report.json` (gaps + coverage metadata) next to it, then print a gap
    warning summary to stderr if there were any -- identical for `scan` and
    `rebuild`.
    """
    document = graph_to_document(graph, account_id=account_id, regions_scanned=target_regions)
    document["findings"] = findings

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, default=json_default, indent=2))

    report = build_scan_report(account_id=account_id, regions_scanned=target_regions, gaps=gaps)
    write_scan_report(report, report_path_for(output))

    if gaps:
        stderr_console.print(
            f"[bold yellow]Warning:[/bold yellow] {len(gaps)} scan gap(s) encountered "
            "(partial results -- some resources may be missing). See "
            f"{report_path_for(output)} for details:"
        )
        for gap in gaps:
            stderr_console.print(f"  - {gap.service}:{gap.operation} (scope={gap.scope}) -> {gap.error_code}: {gap.message}")
