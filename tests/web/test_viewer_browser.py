"""Opt-in real Chromium checks: RUN_BROWSER_TESTS=1 uv run pytest tests/web/test_viewer_browser.py."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from aws_graph_builder.web.server import create_app
from tests.web.viewer_fixture import viewer_document


@pytest.fixture
def browser_page(request):
    if not request.config.getoption("--run-browser") and os.environ.get("RUN_BROWSER_TESTS") != "1":
        pytest.skip("Opt-in Chromium integration tests")
    import uvicorn
    from playwright.sync_api import sync_playwright

    if request.node.name == "test_live_graph_smoke":
        if not (graph_path := request.config.getoption("--live-graph")):
            pytest.skip("Supply --live-graph to inspect an existing account artifact")
        document = json.loads(Path(graph_path).read_text())
        report_path = Path(graph_path).with_suffix(".report.json")
        report = json.loads(report_path.read_text()) if report_path.exists() else None
        app = create_app(document, report=report)
    else:
        document = viewer_document()
        if request.node.name == "test_large_expansion_requires_a_bounded_selection":
            for index in range(60):
                node_id = f"neighbor-{index:02d}"
                document["nodes"].append({"id": node_id, "name": node_id, "type": "IamRole", "arn": node_id, "properties": {}})
                document["edges"].append({"id": f"edge-{index}", "source": "analyst", "target": node_id, "type": "CanAssume", "properties": {}})
        app = create_app(document, report={"gaps": []})
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(.01)
    assert server.started
    errors = []
    try:
        with sync_playwright() as p:
            executable = request.config.getoption("--browser-executable") or os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
            browser = p.chromium.launch(executable_path=executable or None)
            page = browser.new_page(viewport={"width": 1440, "height": 980}, reduced_motion="reduce")
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(f"http://127.0.0.1:{port}")
            page.locator("#loading").wait_for(state="hidden")
            page.screenshot_directory = request.config.getoption("--viewer-screenshots")
            yield page
            assert not errors, errors
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()


def screenshot(page, name):
    if directory := page.screenshot_directory or os.environ.get("VIEWER_SCREENSHOT_DIR"):
        Path(directory).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(directory) / f"{name}.png"))


def test_principal_route_evidence_and_back_preserve_context(browser_page):
    from playwright.sync_api import expect

    page = browser_page
    expect(page.locator("#landing")).to_be_visible()
    screenshot(page, "landing")
    page.locator("#explore-search").fill("Analyst")
    page.locator("#principal-list .entity-row").click()
    expect(page.locator("#view-title")).to_have_text("Analyst")
    expect(page.locator("#visible-count")).to_contain_text("3 nodes")
    screenshot(page, "explore")
    page.get_by_role("button", name="Paths to high-value", exact=True).click()
    expect(page.locator("#route-status")).to_contain_text("1 unique route")
    expect(page.locator("#view-kind")).to_have_text("PATH INVESTIGATION")
    expect(page.locator("#route-list .route-card")).to_have_count(1)
    screenshot(page, "route")
    page.locator("#inspector-content .hop-button").first.click()
    expect(page.locator("#inspector-content")).to_contain_text("2 relationship alternatives")
    expect(page.locator("#inspector-content")).to_contain_text("MFA required")
    expect(page.locator("#inspector-content")).to_contain_text("External ID required")
    expect(page.locator("#view-kind")).to_have_text("PATH INVESTIGATION")
    page.locator("#back").click()
    expect(page.locator("#view-title")).to_have_text("Analyst")
    expect(page.locator("#visible-count")).to_contain_text("3 nodes")
    expect(page.locator("#inspector")).to_be_hidden()


def test_findings_reveal_conditions_and_policy_evidence(browser_page):
    from playwright.sync_api import expect

    page = browser_page
    page.locator('[data-tab="findings"]').click()
    page.locator(".finding-card").click()
    expect(page.locator("#view-kind")).to_have_text("FINDING EVIDENCE")
    expect(page.locator("#inspector-content")).to_contain_text("Unresolved condition")
    page.locator(".evidence-button").filter(has_text="Effective Permission").click()
    expect(page.locator("#inspector-content")).to_contain_text("iam:AttachRolePolicy")
    expect(page.locator("#inspector-content")).to_contain_text("DeployPolicy")
    page.get_by_text("Statement: Deploy", exact=True).click()
    expect(page.locator("#inspector-content")).to_contain_text("Matched by statement ID.")
    expect(page.locator("#inspector-content")).to_contain_text('"Effect": "Allow"')
    screenshot(page, "evidence")


def test_keyboard_search_hide_restore_theme_and_mobile(browser_page):
    from playwright.sync_api import expect

    page = browser_page
    page.keyboard.press("/")
    page.locator("#global-search").fill("role/DeployRole")
    page.locator("#global-search").press("ArrowDown")
    page.locator("#global-options").press("Enter")
    expect(page.locator("#view-title")).to_have_text("DeployRole")
    page.get_by_role("button", name="Hide node", exact=True).click()
    expect(page.locator("#hidden-controls")).to_contain_text("1 hidden")
    page.locator("#hidden-controls button").click()
    page.get_by_role("button", name="Restore all", exact=True).click()
    expect(page.locator("#hidden-controls")).to_be_empty()
    page.locator("#theme").click()
    page.locator("#theme").click()
    expect(page.locator("html")).to_have_attribute("data-theme", "dark")
    screenshot(page, "dark")
    page.set_viewport_size({"width": 390, "height": 844})
    page.locator("#nav-toggle").click()
    expect(page.locator("body")).to_have_class("nav-open")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    screenshot(page, "mobile")


def test_saved_route_positions_are_restored_without_automatic_relayout(browser_page):
    page = browser_page
    result = page.evaluate("""async () => {
      const {GraphView} = await import('/graph.mjs');
      const {GraphModel} = await import('/model.mjs');
      const container = document.createElement('div');
      Object.assign(container.style, {position:'fixed',width:'600px',height:'400px'});
      document.body.append(container);
      const model = new GraphModel({nodes:[{id:'a',name:'a',type:'IamRole'},{id:'b',name:'b',type:'IamRole'}],edges:[]},[]);
      const renderer = new GraphView(container, model, () => {}, () => {});
      renderer.render({kind:'route',nodeIds:['a','b'],edgeIds:[],routeOrder:['a','b'],positions:{a:{x:31,y:47},b:{x:205,y:171}},viewport:{zoom:1,pan:{x:10,y:20}}});
      const snapshot = renderer.snapshot();
      renderer.cy.destroy(); container.remove();
      return snapshot;
    }""")
    assert result["positions"] == {"a": {"x": 31, "y": 47}, "b": {"x": 205, "y": 171}}


def test_editing_source_search_cancels_a_pending_query(browser_page):
    from playwright.sync_api import expect

    page = browser_page
    page.locator('[data-tab="paths"]').click()
    page.locator("#route-source").select_option("analyst")
    pending = []
    page.route("**/api/routes?*", lambda route: pending.append(route))
    page.locator("#route-run").click()
    expect(page.locator("#route-status")).to_contain_text("Searching")
    page.locator("#route-source-search").fill("DeployRole")
    expect(page.locator("#route-run")).to_have_text("Find paths →")
    pending[0].fulfill(json={"paths": [{"nodes": ["analyst", "deploy"], "hops": [{"source":"analyst","target":"deploy","edge_ids":["assume"]}]}], "complete":True,"truncated":False,"already_at_target":False,"stop_reason":"exhausted"})
    expect(page.locator("#view-kind")).to_have_text("EXPLORE")
    expect(page.locator("#route-list")).to_be_empty()


def test_back_restores_route_results_and_query_endpoints(browser_page):
    from playwright.sync_api import expect

    page = browser_page
    page.locator('[data-tab="paths"]').click()
    page.locator("#route-source").select_option("analyst")
    page.locator("#route-run").click()
    expect(page.locator("#view-title")).to_have_text("Analyst → AdminRole")
    page.locator("#route-source").select_option("deploy")
    page.locator("#route-run").click()
    expect(page.locator("#view-title")).to_have_text("DeployRole → AdminRole")
    page.locator("#back").click()
    expect(page.locator("#view-title")).to_have_text("Analyst → AdminRole")
    expect(page.locator("#route-source")).to_have_value("analyst")
    expect(page.locator("#route-list")).to_contain_text("Analyst → DeployRole → AdminRole")


def test_relayout_does_not_overwrite_edited_query_endpoints(browser_page):
    from playwright.sync_api import expect

    page = browser_page
    page.locator('[data-tab="paths"]').click()
    page.locator("#route-source").select_option("analyst")
    page.locator("#route-run").click()
    expect(page.locator("#view-title")).to_have_text("Analyst → AdminRole")
    page.locator("#route-source").select_option("deploy")
    page.locator("#relayout").click()
    expect(page.locator("#route-source")).to_have_value("deploy")


def test_related_findings_includes_target_and_resets_conflicting_filters(browser_page):
    from playwright.sync_api import expect

    page = browser_page
    page.locator('[data-tab="findings"]').click()
    page.locator("#finding-severity").select_option("low")
    page.locator('[data-tab="explore"]').click()
    page.locator("#explore-search").fill("DeployRole")
    page.locator("#principal-list .entity-row").click()
    page.get_by_role("button", name="Review 1 related findings →", exact=True).click()
    expect(page.locator(".finding-card")).to_have_count(1)
    expect(page.locator("#finding-count")).to_contain_text("1 of 1")


def test_live_graph_smoke(browser_page):
    from playwright.sync_api import expect

    page = browser_page
    expect(page.locator("#app-error")).to_be_hidden()
    expect(page.locator("#principal-list .entity-row").first).to_be_visible()
    screenshot(page, "live-landing")
    page.locator("#principal-list .entity-row:not(.high-value-row)").first.click()
    if page.locator("#expansion-dialog").is_visible():
        for checkbox in page.locator("#expansion-list input").all()[:3]:
            checkbox.check()
        page.locator("#expansion-apply").click()
    expect(page.locator("#view-kind")).to_have_text("PRINCIPAL EXPLORATION")
    screenshot(page, "live-explore")
    page.get_by_role("button", name="Paths to high-value", exact=True).click()
    expect(page.locator("#route-status")).not_to_contain_text("Searching")
    expect(page.locator("#route-status")).not_to_contain_text("Query failed")
    screenshot(page, "live-paths")


def test_large_expansion_requires_a_bounded_selection(browser_page):
    from playwright.sync_api import expect

    page = browser_page
    page.locator("#explore-search").fill("Analyst")
    page.locator("#principal-list .entity-row").click()
    expect(page.locator("#expansion-dialog")).to_be_visible()
    expect(page.locator("#visible-count")).to_contain_text("1 nodes")
    boxes = page.locator("#expansion-list input").all()
    for checkbox in boxes[:51]:
        checkbox.check()
    expect(page.locator("#expansion-apply")).to_be_disabled()
    boxes[50].uncheck()
    expect(page.locator("#expansion-apply")).to_be_enabled()
    page.locator("#expansion-apply").click()
    expect(page.locator("#visible-count")).to_contain_text("51 nodes")
