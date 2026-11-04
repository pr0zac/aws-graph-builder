import json
from pathlib import Path

from aws_graph_builder.cli import serve_cmd


def test_serve_loads_companion_report_and_tolerates_missing_or_invalid(tmp_path: Path, monkeypatch) -> None:
    graph = tmp_path / "scan.json"
    graph.write_text(json.dumps({"nodes": [], "edges": []}))
    loaded = []
    monkeypatch.setattr(serve_cmd, "create_app", lambda document, **kwargs: loaded.append(kwargs) or object())
    monkeypatch.setattr(serve_cmd.uvicorn, "run", lambda *args, **kwargs: None)
    report = tmp_path / "scan.report.json"
    for contents, expected in [(None, None), ('{"gaps": []}', {"gaps": []}), ('{broken', None), ('[]', None)]:
        if contents is not None:
            report.write_text(contents)
        serve_cmd.serve(input=graph, host="127.0.0.1", port=8765, open_browser=False)
        assert loaded[-1].get("report") == expected
