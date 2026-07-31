"""`aws-graph-builder scan`: AWS -> disk cache -> attack-path graph -> JSON file.

Scans IAM (global) plus, per enabled region, EC2 instances and Lambda
functions, plus S3 buckets and (best-effort) Organizations SCPs (both
global). Builds the structural graph, evaluates identity/resource/trust
policies into `EffectivePermission`/`CanAssume`/`IdentifiesVia` edges, runs
privesc technique detection, and writes the result as JSON, plus a companion
`*.report.json` (see `report.py`).

Partial failures (denied/throttled calls) degrade gracefully per
aws-graph-builder.md: the scan still completes and writes output, with a
console warning summary of every `ScanGap` collected across every scanner.

`--use-cache` resumes a previous run: any call already cached is reused
without touching AWS, and only what's missing gets fetched live (see
`scan/base.py`'s `CachedClient` docstring). For a *pure* cache replay with no
AWS calls or credentials at all, see `rebuild` instead.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from botocore.exceptions import ClientError

from aws_graph_builder.cache.store import CacheStore
from aws_graph_builder.cli._common import (
    default_cache_dir,
    stderr_console,
    stdout_console,
)
from aws_graph_builder.cli._pipeline import (
    build_graph,
    collect_gaps,
    evaluate_and_detect,
    write_output_and_report,
)
from aws_graph_builder.regions import discover_enabled_regions
from aws_graph_builder.scan.base import CachedClient
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


def _resolve_target_regions(enabled_regions: list[str], regions_override: str | None) -> list[str]:
    """Intersect `--regions` (if given) with the enabled-regions set,
    warning about (and dropping) any requested region that isn't enabled.
    With no override, every enabled region is scanned.
    """
    if regions_override is None:
        return enabled_regions

    requested = [r.strip() for r in regions_override.split(",") if r.strip()]
    unknown = sorted(set(requested) - set(enabled_regions))
    if unknown:
        stderr_console.print(
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
                "(default: $AWS_GRAPH_BUILDER_CACHE_DIR if set, else ~/.cache/aws-graph-builder). "
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
    use_cache: Annotated[
        bool,
        typer.Option(
            "--use-cache",
            help="Reuse any already-cached API response instead of re-fetching it; only what's missing is called live.",
        ),
    ] = False,
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
        (lambda message: stdout_console.print(f"[dim cyan]{message}[/dim cyan]", soft_wrap=True)) if verbose else None
    )

    try:
        session = build_session(region=region, profile=profile)
        identity = validate_credentials(session)
    except CredentialError as exc:
        stderr_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if verbose:
        stdout_console.print(
            f"[bold]Authenticated as[/bold] {identity.arn} (account {identity.account_id})", soft_wrap=True
        )

    cache_root = (cache_dir if cache_dir is not None else default_cache_dir()) / identity.account_id
    cache_store = CacheStore(cache_root)

    if verbose:
        stdout_console.print("[dim cyan]Discovering enabled regions...[/dim cyan]", soft_wrap=True)
    try:
        enabled_regions = discover_enabled_regions(session)
    except ClientError as exc:
        stderr_console.print(
            f"[bold yellow]Warning:[/bold yellow] failed to discover enabled regions ({exc}); "
            "skipping EC2/Lambda scanning."
        )
        enabled_regions = []
    target_regions = _resolve_target_regions(enabled_regions, regions)
    if verbose:
        stdout_console.print(
            f"[dim cyan]  scanning {len(target_regions)} region(s): {', '.join(target_regions) or '(none)'}[/dim cyan]",
            soft_wrap=True,
        )

    try:
        iam_client = CachedClient(
            session.client("iam"), cache_store, scope="global", service="iam", reporter=reporter, use_cache=use_cache
        )
        iam_result = IamScanner(iam_client).scan()

        ec2_results = []
        lambda_results = []
        for target_region in target_regions:
            if verbose:
                stdout_console.print(f"[bold]Region: {target_region}[/bold]", soft_wrap=True)
            ec2_client = CachedClient(
                session.client("ec2", region_name=target_region),
                cache_store,
                scope=target_region,
                service="ec2",
                reporter=reporter,
                use_cache=use_cache,
            )
            ec2_results.append(Ec2Scanner(ec2_client, region=target_region).scan())

            lambda_client = CachedClient(
                session.client("lambda", region_name=target_region),
                cache_store,
                scope=target_region,
                service="lambda",
                reporter=reporter,
                use_cache=use_cache,
            )
            lambda_results.append(LambdaScanner(lambda_client, region=target_region).scan())

        s3_client = CachedClient(
            session.client("s3"), cache_store, scope="global", service="s3", reporter=reporter, use_cache=use_cache
        )
        s3_result = S3Scanner(s3_client).scan()

        organizations_client = CachedClient(
            session.client("organizations"),
            cache_store,
            scope="global",
            service="organizations",
            reporter=reporter,
            use_cache=use_cache,
        )
        organizations_result = OrganizationsScanner(organizations_client, account_id=identity.account_id).scan()
    except CredentialError as exc:
        stderr_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if verbose:
        stdout_console.print("[dim cyan]Building graph from scan results...[/dim cyan]", soft_wrap=True)
    graph = build_graph(
        iam_result=iam_result,
        ec2_results=ec2_results,
        lambda_results=lambda_results,
        s3_result=s3_result,
        organizations_result=organizations_result,
        account_id=identity.account_id,
    )

    findings = evaluate_and_detect(graph, verbose=verbose)

    gaps = collect_gaps(
        iam_result=iam_result,
        ec2_results=ec2_results,
        lambda_results=lambda_results,
        s3_result=s3_result,
        organizations_result=organizations_result,
    )
    write_output_and_report(
        graph, findings, account_id=identity.account_id, target_regions=target_regions, gaps=gaps, output=output
    )

    typer.echo(
        f"Scan complete for account {identity.account_id}: {graph.number_of_nodes()} nodes, "
        f"{graph.number_of_edges()} edges, {len(findings)} finding(s) written to {output}"
    )
