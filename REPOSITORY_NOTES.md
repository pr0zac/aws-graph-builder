# Repository orientation and graph UI notes

Historical orientation reviewed 2026-11-04 before the UI redesign. The implemented replacement is described in `docs/superpowers/specs/2026-11-04-output-viewer-design.md` and README; UI descriptions below record the original viewer. These are code-based observations, not an approved redesign plan. No application behavior was changed during this review.

## What the application does

This is a Python 3.14 / uv CLI for defensive AWS identity and privilege-escalation analysis. It scans a single account using read-only AWS calls, constructs a NetworkX `MultiDiGraph`, evaluates policy/trust/resource-policy relationships, runs 11 privilege-escalation detectors, and writes a graph JSON document plus a separate scan coverage/gap report.

The main flow is:

`scan → cached AWS responses → structural graph → policy evaluation → privesc detection → graph.json + graph.report.json`

`rebuild` uses the same graph/evaluation/output pipeline with cached responses and no AWS calls. `serve` loads an existing graph document without scanning or re-evaluating its permissions. It computes high-value principal annotations at startup and exposes a local read-only web UI/API. Network reachability is deferred.

Start with `CLAUDE.md`, `README.md`, `aws-graph-builder.md`, and `tasks.md`, then check the code: some status descriptions are stale.

Important backend files:

- `cli/_pipeline.py`: shared build/evaluate/detect/write pipeline.
- `scan/base.py`: scanner contract, scan gaps, cache replay/resume behavior.
- `graph/schema.py`: 14 node types, 11 edge types, stable identifiers.
- `graph/builder.py` and `graph/export.py`: structural graph construction and JSON conversion.
- `eval/simulator.py`: documented policy simulation approximations.
- `eval/trust.py` / `eval/resource_policy.py`: trust and resource-policy edges.
- `privesc/engine.py` / `privesc/techniques/`: findings and their `PrivescPath` edges.
- `eval/high_value.py`: admin-equivalent principal heuristic.

## Graph semantics to preserve in a redesign

- Parallel edges and self-targeting grants/findings are meaningful. A single pair of principals can have several distinct escalation techniques.
- Structural relationships, effective permissions, and control-transfer relationships have different meanings.
- Attack-path queries traverse only `CanAssume` and `PrivescPath`. General reachability traverses all edge types; it must not be presented as equivalent to gaining control.
- Findings carry technique, severity, description, required permissions, evidence edge IDs, and a corresponding `PrivescPath` edge ID.
- Edge styling uses critical/serious/structural tiers. Finding severity uses critical/high/medium/low. These are separate scales.
- High-value principals are users/roles with a materialized full-resource wildcard grant whose action pattern matches `*` or `iam:*`. This is a heuristic derived from evaluated permissions.
- Evaluation is approximate: wildcard intersection, unresolved conditions, unsupported `NotAction`/`NotResource`, and incomplete Organizations hierarchy coverage are documented in `eval/simulator.py`. UI language should retain those uncertainties rather than imply live exploit verification.

## UI implementation map

The frontend is bundled with the Python package. There is no JS package manifest, frontend build step, or CDN dependency.

| File | Responsibility |
| --- | --- |
| `web/static/index.html` | Header controls, graph canvas, loading/error overlays, sidebar sections |
| `web/static/style.css` | CSS theme tokens, fixed sidebar layout, controls, lists, inspector, tooltips |
| `web/static/app.js` | Cytoscape setup, API calls, layout, findings, query controls, selection, visibility, focus, theme |
| `web/static/cytoscape.min.js` | Vendored graph renderer |
| `web/server.py` | FastAPI factory, loaded document, graph/subgraph, lookup indexes, static serving |
| `web/api.py` | Trimmed graph, full details, findings, path queries, high-value listing |
| `cli/serve_cmd.py` | Local server launcher and CLI options |

Paths above are relative to `src/aws_graph_builder/`.

`app.js` is approximately 1,600 lines, with most interaction state enclosed in `main()`. Useful entry points:

- Taxonomy maps and `buildCyStyle()`: node colors/shapes, edges, selection, halos, hide classes.
- `coseLayoutOptions()`, `layoutElements()`, `runLayout()`: force layout; parallel edges deduplicated only for layout physics.
- `hideNodes()`, `showHiddenNode()`, `showAllHiddenNodes()`: manual node visibility.
- `snapshotViewIfNeeded()`, `applyIsolate()`, `restoreIsolate()`: temporary focused subgraph and exact prior viewport/position restoration.
- `focusFinding()` and `clearFocus()`: finding evidence reveal/isolation/highlight.
- `createNodePicker()`: local substring search with selected IDs separate from free text.
- `applyPathQueryHighlight()` and `clearPathQueryHighlight()`: union of query result paths.
- `loadFullDetail()` and tap handlers: inspector and deferred full-property fetches.

## Current user experience

- Full-height canvas, header controls, and a fixed 320px right sidebar.
- Sidebar order: legend, severity-filtered findings, path query, hidden nodes, inspector. Lists and inspector introduce nested scrolling.
- Node categories use four colors; node types use different shapes. Labels truncate after 24 characters, use a 6px base font, and disappear below the minimum rendered font size. Hover reveals names/types.
- Effective-permission edges are hidden initially. AWS service principals, AWS-managed policies, and service-linked roles are also hidden initially; SSO roles are deliberately retained.
- Controls include re-layout, hide selected nodes, restore hidden nodes, and persisted System/Light/Dark themes.
- Clicking a finding temporarily reveals its evidence and all required endpoints, hides unrelated elements, re-lays out the subset, and applies cyan highlighting.
- Queries support source/target name search, general reachability or attack mode, max hops, and any high-value target. The latter forces attack mode.
- Path results are rendered together as one violet highlighted union, with a count summary. There is no per-path result list or step-by-step path navigation.
- High-value nodes have persistent gold halos.
- Selecting a node/edge clears focus and restores the full prior view, then fetches full properties. Raw policy/properties data is shown as JSON.
- Background clicks clear focus/inspection. The path-query Clear action clears query highlighting, retaining picker values.

## State and API constraints

Four visibility classes are layered independently: `.ge-hidden` (permission edges), `.node-hidden` (AWS defaults), `.user-hidden` (manual node hiding), and `.isolate-hidden` (temporary focus). Findings and query focus temporarily override relevant hiding and reconcile it when cleared. Preserving those interactions matters more than preserving the present DOM structure.

Focus snapshots retain every node position plus pan/zoom. A focused layout caps zoom at 2. Findings and query highlights are mutually exclusive. Styling uses Cytoscape bypasses; theme changes rebuild the Cytoscape stylesheet from computed CSS variables.

The initial `/api/graph` response provides only node IDs/types/names/ARNs/high-value flags and edge IDs/types/endpoints. Heavy properties arrive from `/api/node?id=...` and `/api/edge?id=...`. Findings are fetched separately at startup. Account ID, scan timestamp, regions, and scan gaps are not exposed in that initial API response/UI.

Both path APIs default to six hops, cap hops at ten, and return at most 200 paths. There is no truncation indicator, shortest-path guarantee, or pagination. NetworkX multigraph traversal can emit the same node sequence for different parallel-edge combinations; each returned hop includes all eligible parallel edge IDs. The UI unions those IDs, so path counts should not be assumed to mean distinct visible node sequences.

The inspector guards superseded detail fetches with a sequence number, but finding/background transitions do not increment it. Path queries do not have a cancellation or stale-response guard. These are areas to verify when restructuring async interaction state.

## Useful redesign opportunities to discuss later

- Make the primary investigation workflow prominent: choose a principal, inspect findings, follow a path, understand its evidence.
- Reduce competition among the legend, findings, path builder, hidden-node management, and inspector in one narrow scrolling column.
- Give overview and focused evidence views explicit navigation and clear return/reset controls.
- Improve readable node labels and relationship explanations at useful zoom levels; dense graph topology will need interaction design as well as visual styling.
- Consider individual path selection and ordered hop/evidence details instead of only a combined graph highlight.
- Make principal names/ARNs and policy evidence readable, with raw JSON available as a secondary detail view.
- Consider graph-level search, type filters, contextual source/target actions, responsive layout, and keyboard-accessible controls. Current name pickers do not provide full arrow-key combobox navigation.
- Keep the offline, bundled-assets workflow unless changing it is an explicit project decision. The existing API separates the viewer from scan/evaluation internals well enough to support a frontend rewrite.

## Documentation drift and verification

`CLAUDE.md` and the unchecked frontend item in `tasks.md` say path-query controls and high-value badges are pending. Both exist in the current implementation. Some comments also describe earlier behavior, such as pulsing focus, while the current focus styling is static.

The local ignored graph inspected during this review contained 115 nodes, 2,859 edges, and 313 findings; 2,456 edges were `EffectivePermission`. These are sample artifact counts, not universal application limits.

Ran `.venv/bin/python -m pytest tests/web tests/eval/test_high_value.py -q`: **29 passed**. Tests cover backend graph/detail/finding/path/high-value behavior; no frontend automated test harness was found. A rendered browser review was unavailable because this session had no connected browser. Visual observations above come from HTML/CSS/JS inspection.

## Live AWS output review (2026-11-04)

With the user's authorization and existing AWS CLI SSO session, ran a fresh read-only scan across all 17 enabled regions. Output/cache were isolated under `/private/tmp/aws-graph-builder-review-20261104/`; the repository's existing `graph.json` was preserved.

- Output: **153 nodes, 5,196 edges, 757 findings, zero reported scan gaps**.
- Inventory includes 3 users, 46 roles, 54 managed policies, 6 Lambda functions, and 12 buckets. No EC2 instance nodes were found.
- Edges: 4,325 effective permissions, 757 privesc paths, 46 assume-role relationships, and 68 other structural relationships.
- Findings: 101 critical, 654 high, 2 medium, across all 11 detector techniques. Two findings target their own source principal.
- Two principals are flagged high-value. Broadly privileged principals themselves generate many findings, so raw finding count is not a count of unique vulnerable low-privilege identities.
- There are 772 edges marked with unresolved conditions. Those qualifications currently live in full edge properties rather than the initial graph render payload.
- Applying the UI's default hiding rules leaves **89 nodes and 539 edges**. Even the default graph therefore has substantial visual density.
- The graph file is about **79.6 MB**; the trimmed `/api/graph` payload is about **1.12 MB**. Keeping heavy policy/evidence properties out of initial rendering is valuable.
- Every finding's privesc/evidence edge reference resolved to an actual edge.
- Exercised `/`, `/api/graph`, `/api/findings`, `/api/node`, `/api/edge`, and a three-hop `/api/attack-paths` query through FastAPI's in-process test client with the real document. All returned HTTP 200 with expected counts/detail.
- The sample attack query returned **8 paths but only 2 distinct node sequences**, confirming the multigraph counting behavior described above with live data.
- Full repository verification: **257 tests passed**, Ruff passed, mypy passed for 53 source files. The suite emits one Starlette/httpx deprecation warning.
- A cache-only `rebuild` completed with the same 153 nodes / 5,196 edges / 757 findings. Parsed graph documents were identical after removing only `generated_at`.

These checks validate scan/output/API behavior; they do not constitute rendered browser or layout verification.
