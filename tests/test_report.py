from __future__ import annotations

import json
from pathlib import Path

from aws_graph_builder.report import (
    ScanReport,
    build_scan_report,
    report_path_for,
    scan_report_to_dict,
    write_scan_report,
)
from aws_graph_builder.scan.base import ScanGap

GAP = ScanGap(service="lambda", operation="list_functions", scope="us-east-1", error_code="AccessDenied", message="nope")


def test_report_path_for_inserts_report_before_suffix() -> None:
    assert report_path_for(Path("graph.json")) == Path("graph.report.json")
    assert report_path_for(Path("/tmp/out/graph.json")) == Path("/tmp/out/graph.report.json")


def test_build_scan_report_stamps_a_generated_at_timestamp() -> None:
    report = build_scan_report(account_id="123456789012", regions_scanned=["us-east-1"], gaps=[GAP])

    assert report.account_id == "123456789012"
    assert report.regions_scanned == ["us-east-1"]
    assert report.gaps == [GAP]
    assert report.generated_at  # non-empty, ISO-8601-shaped
    assert report.generated_at.endswith("Z")


def test_scan_report_to_dict_shape() -> None:
    report = ScanReport(account_id="123456789012", generated_at="2026-01-01T00:00:00Z", regions_scanned=["us-east-1"], gaps=[GAP])

    document = scan_report_to_dict(report)

    assert document == {
        "account_id": "123456789012",
        "generated_at": "2026-01-01T00:00:00Z",
        "regions_scanned": ["us-east-1"],
        "gaps": [
            {
                "service": "lambda",
                "operation": "list_functions",
                "scope": "us-east-1",
                "error_code": "AccessDenied",
                "message": "nope",
            }
        ],
    }


def test_write_scan_report_creates_parent_dirs_and_writes_json(tmp_path: Path) -> None:
    report = ScanReport(account_id="123456789012", generated_at="2026-01-01T00:00:00Z", regions_scanned=[], gaps=[])
    path = tmp_path / "nested" / "graph.report.json"

    write_scan_report(report, path)

    assert path.exists()
    assert json.loads(path.read_text()) == scan_report_to_dict(report)


def test_write_scan_report_with_no_gaps_writes_empty_list(tmp_path: Path) -> None:
    report = build_scan_report(account_id="123456789012", regions_scanned=["us-east-1"], gaps=[])
    path = tmp_path / "graph.report.json"

    write_scan_report(report, path)

    document = json.loads(path.read_text())
    assert document["gaps"] == []
