import typer

from aws_graph_builder.__version__ import __version__

app = typer.Typer(
    name="aws-graph-builder",
    help="Build an AWS attack-path / privilege-escalation graph from live account data.",
)


@app.command()
def version() -> None:
    """Print the installed aws-graph-builder version."""
    typer.echo(__version__)
