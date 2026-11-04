# Output viewer redesign

Status: approved by the user on 2026-11-04. Implementation is on `codex/viewer-redesign`; the corresponding implementation plan records delivery and verification.

## Objective

Help an account owner select an identity, understand what it can control, follow a route to valuable access, and inspect the evidence without losing investigation context.

Primary acceptance workflow:

`Find a principal → explore its neighborhood → find a route to high-value access → inspect each hop's evidence → return to the prior view`

The live review artifact contains 153 nodes, 5,196 edges, and 757 findings. Current default filtering still leaves 89 nodes and 539 edges. This motivates progressive exploration and individual route inspection.

## Scope and constraints

- Retain the local, offline `aws-graph-builder serve` workflow, FastAPI server, and Cytoscape renderer.
- Ship all frontend assets with the Python package; browsing a graph requires neither an internet connection nor Node.js.
- Use modular JavaScript and CSS for this rewrite. A framework migration is outside this scope.
- Preserve the scan graph schema and scanner/evaluator/detector behavior.
- Continue fetching large policy/evidence properties only when required.
- Support parallel relationships, self-targeting findings, high-value annotations, and uncertain conditions.
- Preserve existing public API behavior; introduce additive/versioned responses for revised route semantics.
- Network exposure analysis, scan comparison, collaboration, authentication, and persistent investigation storage are outside this release.

## Application structure

The header contains account identity, scan timestamp, coverage status, and global search. Global search matches names, ARNs, and types and identifies ambiguous names using type and ARN.

A collapsible left panel provides three workspaces: Explore, Findings, and Paths. The center is the graph. A resizable right inspector opens for selected nodes, relationships, findings, or route hops. Legends and visibility options are compact graph controls rather than permanent navigation content.

At smaller widths, navigation and inspection become dismissible drawers so the canvas remains usable. Search and list controls support keyboard navigation, visible focus, and accessible labels. Type, severity, and condition information must not rely on color alone.

## Explore workspace

The initial screen shows searchable principals, high-value identities, and compact inventory/coverage counts. It does not immediately fit the full account graph into the canvas. Users can explicitly open an account overview.

Selecting a principal creates a neighborhood view. Controls distinguish incoming/outgoing relationships and attack relationships/supporting structure. Effective-permission edges and AWS-default plumbing remain opt-in during general exploration.

Expansion is explicit. An expansion preview shows how many nodes/relationships will be added; large results require narrowing a filter or choosing a subset before rendering. Existing node positions remain stable as new neighbors are added.

Node actions include Expand connections, Find routes to high-value access, Use as source, Use as target, and Hide. Hidden items can be restored individually or together.

## Findings workspace

Provide search and filters for severity, technique, source, and target. Support grouping by source principal or technique. Include an explicit filter for findings originating from already high-value principals, without silently excluding them.

Selecting a finding opens a focused evidence graph and a readable explanation. The inspector shows source, target, technique, required permissions, evidence relationships, and relevant statements. Self-targeting findings must remain inspectable.

Finding counts describe detector results, not unique vulnerable principals or verified live exploits. Severity labels retain the detector's existing values.

## Paths workspace

Allow source/target selection from search or node actions. Target can be a specific node or any detected high-value principal. Attack routes are the default query mode. General reachability is a separately labeled advanced mode with an explanation that structural reachability does not imply control.

Attack traversal uses only `CanAssume` and `PrivescPath`. Results contain unique node sequences, ordered by hop count, with stable tie ordering. Different techniques between the same pair of nodes are alternatives within a hop rather than duplicate route rows. Source-equals-target has an explicit already-at-target state; self-targeting findings remain available through Findings.

Show a selectable route list and render one route at a time from left to right. Hop detail exposes alternative relationships/techniques and their evidence. The user may explicitly show all returned routes together, but this is not the default.

Queries retain the ten-hop ceiling and a 200-route result cap. Return whether results were truncated, and distinguish an exhausted search from an interrupted search. Search must also have a work/time budget so a graph with few matching routes cannot cause unbounded traversal. Exact budget configuration and response fields will be specified in the implementation plan and verified with adversarial graph fixtures.

## Inspection and navigation

Selecting an element changes inspection without dismissing the current neighborhood, finding, or route. Background clicks clear selection only. Leaving focused evidence is explicit through Back or Return to exploration.

Investigation history restores visible elements, filters, positions, and pan/zoom. Reset view, Fit, and Re-layout are distinct actions with distinct labels. Re-layout affects only the current view and is user initiated.

Focused evidence temporarily reveals required hidden elements and states that it is doing so. Returning to exploration restores visibility preferences. Unrelated reveal/hide rules must not corrupt each other.

Details lead with readable fields and explanations. Raw JSON remains available in a secondary view. Relevant policy statements and evidence references are fetched lazily and linked to their originating policy where the document provides that information. Missing evidence produces an explicit unavailable state rather than a fabricated explanation.

Conditions that could not be resolved are visible beside affected relationships and in detail views. Trust requirements such as MFA/external ID are presented from stored evidence. The viewer does not independently reinterpret AWS policy semantics.

## Visual direction

Use a restrained security-analysis workspace: neutral surfaces, clear typography, compact controls, readable names, and limited accent colors. Support light, dark, and system themes. Retain static highlighting without pulse effects.

Use node category color plus a recognizable type marker. High-value principals receive a persistent labeled badge. Critical attack relationships are visually prominent; supporting evidence is quieter and differentiated by line treatment as well as color.

Overview views may summarize parallel relationships as a counted connection. Summary relationships must expose their underlying edge IDs and expand on demand. Focused route views explain hop meaning and alternative techniques explicitly.

Labels adapt to context: detailed in a small neighborhood/route, selective in an account overview. Full names and ARNs remain available through inspection and copying.

## Frontend boundaries

Separate application state/navigation, API access, graph rendering/layout, exploration, findings, paths, and inspection into focused modules. The renderer consumes a derived view model and emits selection/navigation events; it does not own investigation state.

Track loaded graph data, active workspace, investigation history, visible subset, filters, user-hidden IDs, selected element, active result, and viewport explicitly. Derive element visibility and styling from this state instead of independently mutating multiple temporary classes and bypasses.

Cancel superseded requests or ignore their responses using request identity. All transitions that supersede inspection invalidate prior detail requests. Loading, empty, partial, and error states belong to each panel/query; a failed detail request must not remove the working graph.

## Backend changes

Add metadata/coverage information for the viewer, compact relationship summaries with uncertainty flags, and route results with unique node sequences and search-limit metadata. Preserve existing endpoints for programmatic consumers.

Coverage comes from an available companion report; absence of that report is displayed as coverage unknown, never as zero gaps. A missing report must not prevent serving an otherwise valid graph document.

Use the in-memory indexes/graph for neighborhoods and details. Keep policy blobs out of list/render responses. Route enumeration must deduplicate parallel relationships before applying the route cap while retaining alternative edge IDs per hop.

## Delivery sequence

1. Review this product/behavior specification, then prepare wireframes for the initial exploration screen and a selected-route screen. Agree on visual direction before styling implementation.
2. Write an implementation plan with module boundaries, exact API contracts/search budgets, test fixtures, and independently reviewable milestones.
3. Build the new shell/state/search/inspection foundation, retaining existing behavior until its replacement is verified.
4. Deliver neighborhood exploration, unique-route navigation, and findings/evidence workflows.
5. Validate browser interactions, responsiveness, accessibility, offline packaging, and the full backend suite; update README, CLAUDE.md, and tasks.md to reflect the shipped viewer.

## Acceptance checks

- A principal can be found by name or ARN and opened without rendering the full account.
- Expansion preserves existing positions and prevents accidental large graph additions.
- Attack queries cannot traverse effective-permission or structural edges.
- Parallel techniques produce one route row per unique node sequence, with all alternatives accessible.
- Search limits and unresolved conditions are visible and correctly explained.
- Selecting a route node/hop leaves the route visible; Back restores the exact previous graph view.
- Hiding/restoring nodes and focused evidence reveal do not change persistent visibility preferences.
- Rapid selection/query changes cannot display a stale response as the current result.
- Missing reports and missing evidence have explicit states.
- Automated tests use sanitized fixtures, including parallel edges, self-targeting findings, unresolved conditions, disconnected nodes, dense graphs, and high-value targets. Live account data is never committed as a test fixture.
- Run existing tests, lint, and type checks; add browser tests for the primary investigation workflow and packaged offline serving.
- Check the live review artifact manually for layout/readability/performance. Record browser and timing observations rather than making an unsupported scale guarantee.

## Review boundary

The user approved this specification before implementation. The implementation plan is `docs/superpowers/plans/2026-11-04-output-viewer.md`.
