"""`aws-graph-builder scan`: AWS -> disk cache -> structural IAM graph -> JSON file.

Phase 1 scope only: IAM is the only scanner wired in (no EC2/Lambda/S3/regions),
and IAM is a global service so `regions_scanned` in the output document is
always empty. Partial failures (denied/throttled calls) degrade gracefully per
aws-graph-builder.md: the scan still completes and writes output, with a
console warning summary of any `ScanGap`s -- a persisted `*.report.json` file
is explicitly a later phase.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

from aws_graph_builder.cache.store import CacheStore
from aws_graph_builder.eval.engine import evaluate_iam_permissions
from aws_graph_builder.graph.builder import build_iam_graph
from aws_graph_builder.graph.export import graph_to_document
from aws_graph_builder.graph.schema import EdgeType, make_edge_id
from aws_graph_builder.privesc.engine import run_privesc_detection
from aws_graph_builder.scan.base import CachedClient
from aws_graph_builder.scan.iam import IamScanner
from aws_graph_builder.session import (
    CredentialError,
    build_session,
    validate_credentials,
)

CACHE_DIR_ENV_VAR = "AWS_GRAPH_BUILDER_CACHE_DIR"

# `highlight=False`: rich's automatic highlighting wraps numbers and
# parenthesized text in their own ANSI spans (e.g. "1 user(s)" becomes
# several separately-styled fragments), which is unwanted for these
# plain progress/status/error messages.
_stderr_console = Console(stderr=True, highlight=False)
_stdout_console = Console(highlight=False)


def _json_default(obj: Any) -> Any:
    """`json.dumps(default=...)` hook: node/edge properties are raw boto3
    response fragments, which may still contain `datetime` values (e.g.
    `CreateDate`) -- serialize those as ISO 8601 strings, same convention as
    `cache.store`'s cache-entry serialization.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _default_cache_dir() -> Path:
    """Root cache directory before the account-id subdirectory is appended.

    Per aws-graph-builder.md's "Disk cache" section: `$AWS_GRAPH_BUILDER_CACHE_DIR`
    if set, else `~/.cache/aws-graph-builder`.
    """
    override = os.environ.get(CACHE_DIR_ENV_VAR)
    if override:
        return Path(override)
    return Path.home() / ".cache" / "aws-graph-builder"


def scan(
    output: Annotated[
        Path,
        typer.Option("--output", help="Path to write the JSON attack-path graph document to."),
    ] = Path("graph.json"),
    cache_dir: Annotated[
        Path | None,
        typer.Option(
            "--cache-dir",
            help=(
                "Root directory for the on-disk API-response cache "
                f"(default: ${CACHE_DIR_ENV_VAR} if set, else ~/.cache/aws-graph-builder). "
                "The account id is appended automatically as a subdirectory."
            ),
        ),
    ] = None,
    region: Annotated[
        str | None,
        typer.Option("--region", help="AWS region to use for the STS/IAM calls themselves (IAM is a global service)."),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option(
            "--profile",
            help="Named AWS CLI profile to use. Falls back to boto3's standard credential chain (AWS_PROFILE env var, then the `default` profile) if omitted.",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Print each AWS call the scanner makes and what it finds, to stdout."),
    ] = False,
) -> None:
    """Scan the AWS account's IAM resources and write a JSON attack-path graph."""
    # `soft_wrap=True` throughout this function's verbose output: these are
    # log-style progress lines, not prose meant to fill/wrap to the terminal
    # width -- and rich's default word-wrapping is unpredictable (and breaks
    # substring assertions in tests) when no real tty width can be detected.
    reporter = (
        (lambda message: _stdout_console.print(f"[dim cyan]{message}[/dim cyan]", soft_wrap=True)) if verbose else None
    )

    try:
        session = build_session(region=region, profile=profile)
        identity = validate_credentials(session)
    except CredentialError as exc:
        _stderr_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if verbose:
        _stdout_console.print(
            f"[bold]Authenticated as[/bold] {identity.arn} (account {identity.account_id})", soft_wrap=True
        )

    cache_root = (cache_dir if cache_dir is not None else _default_cache_dir()) / identity.account_id
    cache_store = CacheStore(cache_root)

    iam_client = session.client("iam")
    cached_client = CachedClient(iam_client, cache_store, scope="global", service="iam", reporter=reporter)

    try:
        result = IamScanner(cached_client).scan()
    except CredentialError as exc:
        _stderr_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if verbose:
        _stdout_console.print("[dim cyan]Building graph from scan results...[/dim cyan]", soft_wrap=True)
    graph = build_iam_graph(result, account_id=identity.account_id)

    if verbose:
        _stdout_console.print("[dim cyan]Evaluating IAM policies...[/dim cyan]", soft_wrap=True)
    evaluate_iam_permissions(graph)
    if verbose:
        effective_permission_count = sum(
            1 for _u, _v, data in graph.edges(data=True) if data.get("type") == EdgeType.EFFECTIVE_PERMISSION.value
        )
        can_assume_count = sum(1 for _u, _v, data in graph.edges(data=True) if data.get("type") == EdgeType.CAN_ASSUME.value)
        _stdout_console.print(
            f"[dim cyan]  materialized {effective_permission_count} EffectivePermission edge(s), "
            f"{can_assume_count} CanAssume edge(s)[/dim cyan]",
            soft_wrap=True,
        )

    if verbose:
        _stdout_console.print("[dim cyan]Running privesc detection...[/dim cyan]", soft_wrap=True)
    findings = run_privesc_detection(graph)
    if verbose:
        _stdout_console.print(f"[dim cyan]  found {len(findings)} finding(s)[/dim cyan]", soft_wrap=True)

    document = graph_to_document(graph, account_id=identity.account_id, regions_scanned=[])
    document["findings"] = [
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

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, default=_json_default, indent=2))

    if result.gaps:
        _stderr_console.print(
            f"[bold yellow]Warning:[/bold yellow] {len(result.gaps)} scan gap(s) encountered "
            "(partial results -- some resources may be missing):"
        )
        for gap in result.gaps:
            _stderr_console.print(
                f"  - {gap.service}:{gap.operation} (scope={gap.scope}) -> {gap.error_code}: {gap.message}"
            )

    typer.echo(
        f"Scan complete for account {identity.account_id}: "
        f"{graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges written to {output}"
    )
