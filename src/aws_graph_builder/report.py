"""`ScanReport`: persisted metadata about one `scan`/`rebuild` run -- which
regions were covered and every `ScanGap` encountered across every scanner --
written as a companion `*.report.json` file alongside the main graph output
(per aws-graph-builder.md's JSON-schema section: "Scan gaps ... go in a
separate companion `*.report.json`, not the graph file").

This formalizes what was previously only ever printed to stderr and lost the
moment a run ended: `report_path_for(Path("graph.json"))` gives
`Path("graph.report.json")`, and `write_scan_report` serializes a
`ScanReport` there so gaps/coverage can be reviewed later, scripted against
in CI, or diffed between runs -- without re-parsing terminal output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aws_graph_builder.scan.base import ScanGap


@dataclass
class ScanReport:
    """Metadata about one `scan`/`rebuild` run, independent of the graph
    itself: which account/regions were covered, when, and every gap any
    scanner hit along the way.
    """

    account_id: str
    generated_at: str
    regions_scanned: list[str] = field(default_factory=list)
    gaps: list[ScanGap] = field(default_factory=list)


def build_scan_report(*, account_id: str, regions_scanned: list[str], gaps: list[ScanGap]) -> ScanReport:
    """Construct a `ScanReport` stamped with the current UTC time -- the
    single place `generated_at` gets computed, so `scan_cmd.py`/
    `rebuild_cmd.py` don't each need their own `datetime.now(UTC)` call.
    """
    return ScanReport(
        account_id=account_id,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        regions_scanned=list(regions_scanned),
        gaps=list(gaps),
    )


def report_path_for(output_path: Path) -> Path:
    """`graph.json` -> `graph.report.json`. Inserts `.report` before the
    output file's own suffix rather than appending after it, so the
    companion file still sorts/reads next to the graph it describes.
    """
    return output_path.with_name(f"{output_path.stem}.report{output_path.suffix}")


def _gap_to_dict(gap: ScanGap) -> dict[str, str]:
    return {
        "service": gap.service,
        "operation": gap.operation,
        "scope": gap.scope,
        "error_code": gap.error_code,
        "message": gap.message,
    }


def scan_report_to_dict(report: ScanReport) -> dict[str, Any]:
    return {
        "account_id": report.account_id,
        "generated_at": report.generated_at,
        "regions_scanned": list(report.regions_scanned),
        "gaps": [_gap_to_dict(gap) for gap in report.gaps],
    }


def write_scan_report(report: ScanReport, path: Path) -> None:
    """Serialize `report` as JSON to `path`, creating parent directories as
    needed (matching how the main graph output is written).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scan_report_to_dict(report), indent=2))
