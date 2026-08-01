"""`aws-graph-builder serve`: launch a local web visualizer over a
previously-written graph.json document -- no AWS calls, no credentials
needed at all, same offline contract as `rebuild`.
"""

from __future__ import annotations

import json
import webbrowser
from pathlib import Path
from typing import Annotated

import typer
import uvicorn

from aws_graph_builder.cli._common import stderr_console, stdout_console
from aws_graph_builder.web.server import create_app


def serve(
    input: Annotated[
        Path,
        typer.Option("--input", help="Path to a graph.json document written by `scan` or `rebuild`."),
    ] = Path("graph.json"),
    host: Annotated[
        str,
        typer.Option("--host", help="Host to bind the local web server to."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", help="Port to bind the local web server to."),
    ] = 8765,
    open_browser: Annotated[
        bool,
        typer.Option("--open/--no-open", help="Open the visualizer in the default browser once the server is up."),
    ] = True,
) -> None:
    """Serve a local, offline visualizer over a previously-written graph.json -- no AWS calls, no credentials needed."""
    if not input.is_file():
        stderr_console.print(f"[bold red]Error:[/bold red] no such file: {input}")
        raise typer.Exit(code=1)

    document = json.loads(input.read_text())
    app = create_app(document)

    url = f"http://{host}:{port}/"
    stdout_console.print(
        f"[bold]aws-graph-builder visualizer[/bold] serving {input} "
        f"({len(document.get('nodes', []))} nodes, {len(document.get('edges', []))} edges, "
        f"{len(document.get('findings', []))} findings) at [cyan]{url}[/cyan]"
    )

    if open_browser:
        webbrowser.open(url)

    uvicorn.run(app, host=host, port=port, log_level="warning")
