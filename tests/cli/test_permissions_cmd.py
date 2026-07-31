from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aws_graph_builder.cli.app import app
from aws_graph_builder.scan.iam import IamScanner

runner = CliRunner()

EXPECTED_ACTIONS = sorted(set(IamScanner.required_actions()) | {"sts:GetCallerIdentity"})


def _assert_is_expected_policy(document: dict[str, object]) -> None:
    assert document["Version"] == "2012-10-17"
    statements = document["Statement"]
    assert isinstance(statements, list)
    assert len(statements) == 1
    statement = statements[0]
    assert statement["Effect"] == "Allow"
    assert statement["Resource"] == "*"
    actions = statement["Action"]
    assert actions == EXPECTED_ACTIONS
    # sorted and deduped
    assert actions == sorted(set(actions))


def test_permissions_prints_policy_to_stdout() -> None:
    result = runner.invoke(app, ["permissions"])

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    _assert_is_expected_policy(document)


def test_permissions_writes_policy_to_output_file(tmp_path: Path) -> None:
    output_path = tmp_path / "policy.json"

    result = runner.invoke(app, ["permissions", "--output", str(output_path)])

    assert result.exit_code == 0, result.output
    assert output_path.exists()
    document = json.loads(output_path.read_text())
    _assert_is_expected_policy(document)
    assert str(output_path) in result.output
