"""`aws-graph-builder rebuild`: rebuild the attack-path graph purely from a
previous `scan`'s on-disk cache -- zero AWS API calls, no credentials
needed at all.

Every scanner is driven by a `read_only=True` `CachedClient` (see
`scan/base.py`), which answers every `call()`/`paginate()` purely from
whatever `scan` already cached; a cache miss becomes a `NoCachedData`
`ScanGap` rather than reaching out to AWS. From there, graph building,
evaluation, privesc detection, and output/report writing are byte-for-byte
the same pipeline `scan` uses (`cli/_pipeline.py`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

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
from aws_graph_builder.scan.base import CachedClient
from aws_graph_builder.scan.ec2 import Ec2Scanner
from aws_graph_builder.scan.iam import IamScanner
from aws_graph_builder.scan.lambda_ import LambdaScanner
from aws_graph_builder.scan.organizations import OrganizationsScanner
from aws_graph_builder.scan.s3 import S3Scanner


def _discover_cached_regions(cache_root: Path) -> list[str]:
    """Which regions have cached EC2/Lambda data, derived from the cache
    directory layout itself (`<cache_root>/regions/<region>/...`) rather
    than requiring a manifest file -- works against any cache `scan` has
    ever produced, regardless of when it was written.
    """
    regions_dir = cache_root / "regions"
    if not regions_dir.is_dir():
        return []
    return sorted(p.name for p in regions_dir.iterdir() if p.is_dir())


def rebuild(
    account_id: Annotated[
        str,
        typer.Option("--account-id", help="AWS account id whose cached scan to rebuild from."),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", help="Path to write the JSON attack-path graph document to."),
    ] = Path("graph.json"),
    cache_dir: Annotated[
        Path | None,
        typer.Option(
            "--cache-dir",
            help=(
                "Root directory the cache lives under -- same meaning as `scan --cache-dir` "
                "(default: $AWS_GRAPH_BUILDER_CACHE_DIR if set, else ~/.cache/aws-graph-builder). "
                "The account id is appended automatically, same as `scan`."
            ),
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Print each cached entry replayed and what it finds, to stdout."),
    ] = False,
) -> None:
    """Rebuild the graph from a previous scan's cache -- no AWS calls, no credentials needed."""
    reporter = (
        (lambda message: stdout_console.print(f"[dim cyan]{message}[/dim cyan]", soft_wrap=True)) if verbose else None
    )

    cache_root = (cache_dir if cache_dir is not None else default_cache_dir()) / account_id
    if not cache_root.is_dir():
        stderr_console.print(
            f"[bold red]Error:[/bold red] no cache found for account {account_id} under {cache_root}"
        )
        raise typer.Exit(code=1)
    cache_store = CacheStore(cache_root)

    target_regions = _discover_cached_regions(cache_root)
    if verbose:
        stdout_console.print(
            f"[dim cyan]Rebuilding from cache: {len(target_regions)} region(s): "
            f"{', '.join(target_regions) or '(none)'}[/dim cyan]",
            soft_wrap=True,
        )

    iam_client = CachedClient(None, cache_store, scope="global", service="iam", reporter=reporter, read_only=True)
    iam_result = IamScanner(iam_client).scan()

    ec2_results = []
    lambda_results = []
    for target_region in target_regions:
        if verbose:
            stdout_console.print(f"[bold]Region: {target_region}[/bold]", soft_wrap=True)
        ec2_client = CachedClient(
            None, cache_store, scope=target_region, service="ec2", reporter=reporter, read_only=True
        )
        ec2_results.append(Ec2Scanner(ec2_client, region=target_region).scan())

        lambda_client = CachedClient(
            None, cache_store, scope=target_region, service="lambda", reporter=reporter, read_only=True
        )
        lambda_results.append(LambdaScanner(lambda_client, region=target_region).scan())

    s3_client = CachedClient(None, cache_store, scope="global", service="s3", reporter=reporter, read_only=True)
    s3_result = S3Scanner(s3_client).scan()

    organizations_client = CachedClient(
        None, cache_store, scope="global", service="organizations", reporter=reporter, read_only=True
    )
    organizations_result = OrganizationsScanner(organizations_client, account_id=account_id).scan()

    if verbose:
        stdout_console.print("[dim cyan]Building graph from cached scan results...[/dim cyan]", soft_wrap=True)
    graph = build_graph(
        iam_result=iam_result,
        ec2_results=ec2_results,
        lambda_results=lambda_results,
        s3_result=s3_result,
        organizations_result=organizations_result,
        account_id=account_id,
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
        graph, findings, account_id=account_id, target_regions=target_regions, gaps=gaps, output=output
    )

    typer.echo(
        f"Rebuild complete for account {account_id}: {graph.number_of_nodes()} nodes, "
        f"{graph.number_of_edges()} edges, {len(findings)} finding(s) written to {output}"
    )
