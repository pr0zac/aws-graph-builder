"""`aws-graph-builder scan`: AWS -> disk cache -> attack-path graph -> JSON file.

Scans IAM (global) plus, per enabled region, EC2 instances and Lambda
functions, plus S3 buckets and (best-effort) Organizations SCPs (both
global). Builds the structural graph, evaluates identity/resource/trust
policies into `EffectivePermission`/`CanAssume`/`IdentifiesVia` edges, runs
privesc technique detection, and writes the result as JSON.

Partial failures (denied/throttled calls) degrade gracefully per
aws-graph-builder.md: the scan still completes and writes output, with a
console warning summary of every `ScanGap` collected across every scanner --
a persisted `*.report.json` file is explicitly a later phase.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from botocore.exceptions import ClientError
from rich.console import Console

from aws_graph_builder.cache.store import CacheStore
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
from aws_graph_builder.regions import discover_enabled_regions
from aws_graph_builder.scan.base import CachedClient, ScanGap
from aws_graph_builder.scan.ec2 import Ec2Scanner
from aws_graph_builder.scan.iam import IamScanner
from aws_graph_builder.scan.lambda_ import LambdaScanner
from aws_graph_builder.scan.organizations import OrganizationsScanner
from aws_graph_builder.scan.s3 import S3Scanner
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


def _resolve_target_regions(
    enabled_regions: list[str], regions_override: str | None
) -> list[str]:
    """Intersect `--regions` (if given) with the enabled-regions set,
    warning about (and dropping) any requested region that isn't enabled.
    With no override, every enabled region is scanned.
    """
    if regions_override is None:
        return enabled_regions

    requested = [r.strip() for r in regions_override.split(",") if r.strip()]
    unknown = sorted(set(requested) - set(enabled_regions))
    if unknown:
        _stderr_console.print(
            f"[bold yellow]Warning:[/bold yellow] requested region(s) not enabled for this "
            f"account, skipping: {', '.join(unknown)}"
        )
    return [r for r in requested if r in enabled_regions]


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
        typer.Option("--region", help="AWS region to use for the STS/IAM/global-service calls themselves."),
    ] = None,
    regions: Annotated[
        str | None,
        typer.Option(
            "--regions",
            help=(
                "Comma-separated list of regions to scan for EC2/Lambda (e.g. us-east-1,us-west-2). "
                "Defaults to every region enabled for the account."
            ),
        ),
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
    """Scan the AWS account and write a JSON attack-path graph."""
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

    if verbose:
        _stdout_console.print("[dim cyan]Discovering enabled regions...[/dim cyan]", soft_wrap=True)
    try:
        enabled_regions = discover_enabled_regions(session)
    except ClientError as exc:
        _stderr_console.print(
            f"[bold yellow]Warning:[/bold yellow] failed to discover enabled regions ({exc}); "
            "skipping EC2/Lambda scanning."
        )
        enabled_regions = []
    target_regions = _resolve_target_regions(enabled_regions, regions)
    if verbose:
        _stdout_console.print(
            f"[dim cyan]  scanning {len(target_regions)} region(s): {', '.join(target_regions) or '(none)'}[/dim cyan]",
            soft_wrap=True,
        )

    try:
        iam_client = CachedClient(session.client("iam"), cache_store, scope="global", service="iam", reporter=reporter)
        iam_result = IamScanner(iam_client).scan()

        ec2_results = []
        lambda_results = []
        for target_region in target_regions:
            if verbose:
                _stdout_console.print(f"[bold]Region: {target_region}[/bold]", soft_wrap=True)
            ec2_client = CachedClient(
                session.client("ec2", region_name=target_region),
                cache_store,
                scope=target_region,
                service="ec2",
                reporter=reporter,
            )
            ec2_results.append(Ec2Scanner(ec2_client, region=target_region).scan())

            lambda_client = CachedClient(
                session.client("lambda", region_name=target_region),
                cache_store,
                scope=target_region,
                service="lambda",
                reporter=reporter,
            )
            lambda_results.append(LambdaScanner(lambda_client, region=target_region).scan())

        s3_client = CachedClient(session.client("s3"), cache_store, scope="global", service="s3", reporter=reporter)
        s3_result = S3Scanner(s3_client).scan()

        organizations_client = CachedClient(
            session.client("organizations"), cache_store, scope="global", service="organizations", reporter=reporter
        )
        organizations_result = OrganizationsScanner(organizations_client, account_id=identity.account_id).scan()
    except CredentialError as exc:
        _stderr_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if verbose:
        _stdout_console.print("[dim cyan]Building graph from scan results...[/dim cyan]", soft_wrap=True)
    graph = build_iam_graph(iam_result, account_id=identity.account_id)
    for ec2_result in ec2_results:
        add_ec2_instances_to_graph(graph, ec2_result, account_id=identity.account_id)
    for lambda_result in lambda_results:
        add_lambda_functions_to_graph(graph, lambda_result)
    add_s3_buckets_to_graph(graph, s3_result)
    add_scp_policies_to_graph(graph, organizations_result, account_id=identity.account_id)

    if verbose:
        _stdout_console.print("[dim cyan]Evaluating IAM/resource policies...[/dim cyan]", soft_wrap=True)
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

    document = graph_to_document(graph, account_id=identity.account_id, regions_scanned=target_regions)
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

    all_gaps: list[ScanGap] = list(iam_result.gaps)
    for ec2_result in ec2_results:
        all_gaps.extend(ec2_result.gaps)
    for lambda_result in lambda_results:
        all_gaps.extend(lambda_result.gaps)
    all_gaps.extend(s3_result.gaps)
    all_gaps.extend(organizations_result.gaps)

    if all_gaps:
        _stderr_console.print(
            f"[bold yellow]Warning:[/bold yellow] {len(all_gaps)} scan gap(s) encountered "
            "(partial results -- some resources may be missing):"
        )
        for gap in all_gaps:
            _stderr_console.print(
                f"  - {gap.service}:{gap.operation} (scope={gap.scope}) -> {gap.error_code}: {gap.message}"
            )

    typer.echo(
        f"Scan complete for account {identity.account_id}: {graph.number_of_nodes()} nodes, "
        f"{graph.number_of_edges()} edges, {len(findings)} finding(s) written to {output}"
    )
