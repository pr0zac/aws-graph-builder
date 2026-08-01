import typer

from aws_graph_builder.__version__ import __version__
from aws_graph_builder.cli.permissions_cmd import permissions
from aws_graph_builder.cli.rebuild_cmd import rebuild
from aws_graph_builder.cli.scan_cmd import scan
from aws_graph_builder.cli.serve_cmd import serve

app = typer.Typer(
    name="aws-graph-builder",
    help="Build an AWS attack-path / privilege-escalation graph from live account data.",
)


@app.command()
def version() -> None:
    """Print the installed aws-graph-builder version."""
    typer.echo(__version__)


app.command("scan")(scan)
app.command("rebuild")(rebuild)
app.command("permissions")(permissions)
app.command("serve")(serve)
