"""`aws-graph-builder permissions`: emit the minimal least-privilege read-only
IAM policy document a scan needs.

Aggregates every scanner's `Scanner.required_actions()` (single source of
truth -- can't drift from what scanners actually call) plus the fixed extra
action `sts:GetCallerIdentity`, which `session.validate_credentials` calls but
which isn't owned by any resource scanner.

Phase 1 only has `IamScanner` registered in `_ALL_SCANNERS`; later phases
(EC2/Lambda/S3/Organizations) extend that list -- no restructuring needed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from aws_graph_builder.scan.base import Scanner
from aws_graph_builder.scan.iam import IamScanner

_ALL_SCANNERS: list[type[Scanner]] = [IamScanner]

# Actions called directly by the CLI/session layer, not owned by any
# resource scanner's `required_actions()`.
_EXTRA_ACTIONS = ["sts:GetCallerIdentity"]


def _build_policy_document() -> dict[str, object]:
    actions: set[str] = set(_EXTRA_ACTIONS)
    for scanner_cls in _ALL_SCANNERS:
        actions.update(scanner_cls.required_actions())

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": sorted(actions),
                "Resource": "*",
            }
        ],
    }


def permissions(
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Path to write the IAM policy JSON to. If omitted, prints to stdout."),
    ] = None,
) -> None:
    """Emit the minimal least-privilege read-only IAM policy a `scan` needs."""
    document = _build_policy_document()
    rendered = json.dumps(document, indent=2)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
        typer.echo(f"Wrote required-permissions policy to {output}")
    else:
        typer.echo(rendered)
