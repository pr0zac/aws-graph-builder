# Output Viewer Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task in the current session. Steps use checkbox syntax for tracking.

**Goal:** Ship the approved principal-first investigation workspace.

**Architecture:** Keep the FastAPI server and bundled Cytoscape renderer. Add bounded unique-route queries and viewer summaries without changing legacy endpoints. Replace the frontend with ES modules separating state/model, renderer, API transport, inspector, and workspace orchestration.

**Tech Stack:** Python 3.14, FastAPI, NetworkX, JavaScript ES modules, CSS, vendored Cytoscape; Node's built-in test runner for pure frontend logic. No frontend runtime build step.

**Spec:** `docs/superpowers/specs/2026-11-04-output-viewer-design.md`

## Global constraints

- Ship all frontend assets with the Python package; browsing a graph requires neither an internet connection nor Node.js.
- Preserve the scan graph schema and scanner/evaluator/detector behavior.
- Preserve existing public API behavior; introduce additive/versioned responses for revised route semantics.
- Continue fetching large policy/evidence properties only when required.
- Live account data is never committed as a test fixture.
- Work on `codex/viewer-redesign`. Preserve unrelated untracked files. Leave changes available for user review without automatically committing.

## 1. Viewer API and unique routes

**Files:** create `web/viewer_api.py`, `web/routes.py`, `tests/web/test_viewer_api.py`; modify `web/server.py`, `cli/serve_cmd.py`. Paths are under `src/aws_graph_builder/` unless prefixed with `tests/`.

**Interfaces:** `create_app(document, *, report=None)` remains compatible. New `/api/viewer` returns metadata, coverage, compact nodes and relationships with uncertainty and technique summaries. `/api/routes?source=&target=&mode=attack&max_hops=6` returns `{paths, truncated, complete, stop_reason, already_at_target}`. Each path has `{nodes,hops:[{source,target,edge_ids}]}`. Legacy endpoints stay unchanged.

- [x] Write endpoint tests before implementation. Assert missing coverage is unknown, provided gaps are preserved, summaries omit policy blobs, missing IDs return 404, invalid mode/hops return 422.
- [x] Run `.venv/bin/python -m pytest tests/web/test_viewer_api.py -q` and confirm missing endpoints fail.
- [x] Implement bounded breadth-first traversal over unique successor IDs; retain sorted parallel edge IDs per hop. Stop after 200 unique routes plus a lookahead route, 25,000 examined transitions, or 0.5 seconds. Use a monotonic deadline and report why search stopped. Sort successor IDs and use breadth-first order for stable shortest-first results.
- [x] Test hand-authored graphs: parallel edges `a→b` twice yields one route with both IDs; direct `a→z` precedes `a→b→z`; structural-only paths are absent in attack mode; cyclic/dense no-result graphs stop at the work budget; zero-hop and high-value targets are explicit.
- [x] Read companion report in `serve`, report missing/invalid report as unknown without failing graph serving. Test the report loading boundary.
- [x] Run new and legacy web tests, Ruff, and mypy.

## 2. Frontend model, view history, and request identity

**Files:** create `web/static/model.mjs`, `web/static/api.mjs`, `tests/web/frontend/model.test.mjs`.

**Interfaces:** model exports graph indexing/search, neighborhood derivation, parallel relationship summaries, finding filtering/grouping, view state/history operations. API transport exposes `get(path,params,signal)` and a latest-request gate. Renderer consumes `{nodeIds,edgeIds,positions,viewport,kind}`; inspection is independent of this view.

- [x] Write Node tests for name/ARN/type search; attack/evidence filters; AWS-default filtering; self-target evidence; manual hide then focused reveal then Back; positions and viewport surviving inspection/history; parallel relationship grouping.
- [x] Run `node --test tests/web/frontend/*.test.mjs` and observe missing-module failures.
- [x] Implement model functions with independent immutable snapshots; derive visible elements from active view and filters. No policy interpretation in the frontend.
- [x] Test stale request identity with two deferred resolutions: only the latest may update the inspector/query result.
- [x] Run Node tests and syntax checks on modules.

## 3. Application shell, renderer, and inspection

**Files:** replace `web/static/index.html`, `style.css`, `app.js`; create `graph.mjs`, `inspector.mjs`.

**Interfaces:** `GraphView` emits node/edge selection, selection changes, positions/viewport; supports `render`, `snapshot`, `fit`, `layout`, `resize`, theme updates. Inspector accepts nodes, edge alternatives, findings, and evidence, fetches details lazily, and invalidates prior requests on every selection transition.

- [x] Implement the approved three-column wireframe: header metadata/global search; left Explore/Findings/Paths; center toolbar/canvas/landing state; right resizable inspector. At narrow widths panels become drawers. Use neutral surfaces, cyan interaction accents, restrained severity colors, static focus, light/dark/system themes.
- [x] Preserve name/type labels, gold high-value badge, selection gestures, hide/restore, copy ARN, Fit/Reset/Re-layout, legend, explicit Back, and visibility controls.
- [x] Render only the derived subset. Keep node positions stable during expansion. Use explicit left-to-right preset positions for individual routes; summarize parallel relationships in other views with alternative detail inspection.
- [x] Show readable properties and policy/evidence detail with raw JSON secondary. Explicitly show unresolved conditions, missing evidence, and report unknown/partial states.
- [x] Search and route pickers use keyboard-operable native list controls; selection actions use buttons with accessible labels and visible focus.

## 4. Exploration, findings, and paths

**Files:** `app.js`, `model.mjs`, `inspector.mjs`, tests under `tests/web/frontend/`.

- [x] Explore starts with principal results and high-value shortcuts. Global search can select any node. Node actions expose source/target/expand/path-to-high-value/hide.
- [x] Expansion previews show prospective node/edge counts and selectable neighbors. More than 50 new nodes requires a selected subset; apply only explicit additions and retain old positions. Default neighborhood preview obeys incoming/outgoing, attack/all, permission, AWS-default, and type filters.
- [x] Findings support search/severity/technique/source/target/high-value-source filters and source/technique grouping. Selecting a finding creates a focused evidence view; inspection does not dismiss it.
- [x] Paths default to attack mode and high-value target, allow specific target/general reachability, show unique route rows, display selected route/hops and alternatives, optionally union results, and visibly report truncated/interrupted/already-target/no-route states.
- [x] Every focus transition records a view snapshot; Back restores positions/pan/zoom and visibility preferences. Background selection clearing only affects inspection.
- [x] Add behavior tests for transitions, filter combinations, self-targeting findings, stale responses, and visibility restoration.

## 5. Integration, packaging, and documentation

**Files:** create sanitized reusable fixture and browser smoke test under `tests/web/`; update `README.md`, `CLAUDE.md`, `tasks.md`, this plan.

- [x] Browser test uses a synthetic account graph, real renderer/server, and the primary search→route→evidence→Back workflow. Cover theme, hide/restore, narrow layout, keyboard actions, and request/console failures. If browser automation is unavailable, record that limitation rather than claiming visual verification.
- [x] Serve the live review artifact without copying it into tracked files; inspect payload and route responses for coherent IDs and counts.
- [x] Run `node --test tests/web/frontend/*.test.mjs`, `.venv/bin/python -m pytest -q`, `.venv/bin/ruff check .`, `.venv/bin/mypy src`, and `uv build`. Confirm wheel includes the module assets and can serve them offline.
- [x] Update user docs with viewer workflows, report discovery, route limits, test commands, and known limitations. Update stale status descriptions.
- [x] Review the final diff for XSS-safe rendering, missing evidence, stale-request races, old-endpoint regressions, accidental live data, and scope compliance. Report evidence and any remaining visual verification limits.

## Design review notes

No frontend dependency installation is required for runtime. Backend traversal budgets protect requests even when no paths exist. Route identity is a unique node sequence; technique alternatives remain real edge IDs. The live graph is an optional manual QA artifact, while committed fixtures use fictional IDs only. Existing scan/evaluation behavior and the original API remain unchanged.

## Final verification (2026-11-04)

- Full Python suite: **269 passed**, 10 opt-in browser cases skipped by the ordinary run; one pre-existing Starlette/httpx deprecation warning.
- Explicit Chromium suite: **10 passed**, including the optional live-artifact smoke test, dense expansion limit, history restoration, query invalidation, and lazy policy statements.
- Frontend model suite: **7 passed**.
- Ruff, mypy (55 source files), JavaScript syntax checks, and `git diff --check` passed.
- `uv build` produced the source distribution and wheel. An extracted wheel served all nine viewer assets with correct JavaScript MIME types through its own FastAPI app.
- Screenshots inspected for synthetic light/dark/mobile/route/evidence screens and the local live graph; account artifacts/screenshots remain outside tracked files.
- Independent code review's findings were reproduced, fixed, and regression tested; focused re-review found no remaining issues.
- Live startup profiling isolated repeated high-value action-pattern matching: before, JSON/graph ready at 0.222s and classification ready at 39.305s; after a per-invocation memoization, graph ready at 0.243s and classification ready at 0.628s. The same two principals were flagged. New regression checks bounded repeated work and next-call graph mutations.
- The high-value optimization is the only change outside the viewer/serve layer. It preserves existing classification rules and does not cache across invocations. Scanner, permission evaluation, detector, graph schema, and legacy API behavior are otherwise unchanged.
- The user completed visual/product review and authorized committing the changes on `codex/viewer-redesign`. No merge or push was performed.
