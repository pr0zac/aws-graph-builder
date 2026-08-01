"use strict";

/* -----------------------------------------------------------------------
   Manual theme override (System / Light / Dark), layered on top of the
   OS-driven prefers-color-scheme default below. style.css's
   :root[data-theme="dark"] / :root[data-theme="light"] blocks were added
   specifically for this control and already define every custom property
   consistently with the base :root / prefers-color-scheme blocks -- so
   applying data-theme here is a pure-CSS repaint, no new color values.

   "System" is represented as the ABSENCE of a stored preference/attribute
   (not a third stored value) so a user who never touches the control gets
   exactly today's behavior: no data-theme attribute is ever set, and the
   prefers-color-scheme media query in style.css keeps working unmodified.

   Applied at module load time -- before main() runs, and therefore before
   its first buildCyStyle() call -- so cssVar()'s getComputedStyle() reads
   already reflect the stored preference on first paint, rather than
   flashing the OS default and then correcting a moment later.
   ----------------------------------------------------------------------- */
const THEME_STORAGE_KEY = "aws-graph-builder-theme";

function getStoredTheme() {
  const v = localStorage.getItem(THEME_STORAGE_KEY);
  return v === "light" || v === "dark" ? v : null;
}

function applyStoredTheme() {
  const stored = getStoredTheme();
  if (stored) {
    document.documentElement.setAttribute("data-theme", stored);
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
}

applyStoredTheme();

/* =======================================================================
   aws-graph-builder visualizer -- graph render view.

   Fetches the trimmed /api/graph document once on load, renders it with
   Cytoscape.js (vendored locally, no CDN/build step), and provides:
     - color-by-category / shape-by-type node styling
     - severity-tiered edge styling (critical / serious / structural)
     - an EffectivePermission visibility toggle (off by default -- this
       edge type can run into the thousands on a real scan and would
       otherwise drown out everything else)
     - pan/zoom (Cytoscape defaults) + a `cose` force-directed layout
     - a legend
     - a click-to-select inspector panel: renders immediately from the
       already-loaded trimmed node/edge data (id/type/name, or
       source/target for edges), then tops up with full /api/node //api/edge
       detail (including `properties`) as it arrives
     - a findings panel (severity-filterable, sorted critical-first) that
       fetches /api/findings once on load; clicking a finding pans/zooms to
       its source+target and highlights its evidence edges via a transient
       style-bypass "focus" state, reusing the inspector panel for its detail
   ========================================================================= */

/* -----------------------------------------------------------------------
   Node type taxonomy: 14 NodeType enum values, grouped into 4 categories
   by color, varied by shape within each category so every one of the 14
   stays visually distinguishable even with label text aside.
   ----------------------------------------------------------------------- */
const NODE_CATEGORY = {
  // Principal
  IamUser: "principal",
  IamRole: "principal",
  IamGroup: "principal",
  ExternalPrincipal: "principal",
  ServicePrincipal: "principal",
  // Policy
  ManagedPolicy: "policy",
  InlinePolicy: "policy",
  // Infra/Resource
  Ec2Instance: "infra",
  LambdaFunction: "infra",
  S3Bucket: "infra",
  InstanceProfile: "infra",
  IdentityProvider: "infra",
  // Org/Governance
  Account: "org",
  ServiceControlPolicy: "org",
};

const NODE_SHAPE = {
  // Principal
  IamUser: "ellipse",
  IamRole: "round-rectangle",
  IamGroup: "hexagon",
  ExternalPrincipal: "diamond",
  ServicePrincipal: "triangle",
  // Policy
  ManagedPolicy: "round-rectangle",
  InlinePolicy: "rectangle",
  // Infra/Resource
  Ec2Instance: "ellipse",
  LambdaFunction: "diamond",
  S3Bucket: "round-rectangle",
  InstanceProfile: "hexagon",
  IdentityProvider: "star",
  // Org/Governance
  Account: "star",
  ServiceControlPolicy: "triangle",
};

// CSS custom-property names backing each category's color -- read at
// runtime via getComputedStyle so light/dark theme swaps (including a
// manual data-theme override, see style.css) are picked up without
// duplicating the hex values here.
const CATEGORY_COLOR_VAR = {
  principal: "--cat-principal",
  policy: "--cat-policy",
  infra: "--cat-infra",
  org: "--cat-org",
};

/* -----------------------------------------------------------------------
   Edge type taxonomy: 11 EdgeType enum values, styled by attack-path
   severity using a separate, fixed status palette (never theme-swapped).
   ----------------------------------------------------------------------- */
const EDGE_SEVERITY = {
  PrivescPath: "critical",
  CanAssume: "serious",
  MemberOf: "structural",
  AttachedPolicy: "structural",
  HasInlinePolicy: "structural",
  HasPermissionBoundary: "structural",
  AttachedTo: "structural",
  IdentifiesVia: "structural",
  EffectivePermission: "structural",
  ExecutionRole: "structural",
  AppliesSCP: "structural",
};

const EDGE_SEVERITY_STYLE = {
  critical: { colorVar: "--edge-critical", width: 2, opacity: 1 },
  serious: { colorVar: "--edge-serious", width: 1.2, opacity: 0.9 },
  structural: { colorVar: "--edge-structural", width: 0.5, opacity: 0.55 },
};

// EffectivePermission is its own thing within "structural": can be
// thousands of edges on a real scan, so it's hidden behind a toggle
// (default off) rather than merely thinned further.
const HIDDEN_BY_DEFAULT_EDGE_TYPES = new Set(["EffectivePermission"]);

/* -----------------------------------------------------------------------
   AWS-default node classification: nodes that are always AWS-owned
   plumbing, never a customer-created resource, and clutter real scans
   (service-linked roles, AWS managed policies, and the ServicePrincipal
   leaves trust policies create for AWS services like ec2.amazonaws.com).
   Hidden by default (see the toggle-aws-default-input wiring in main()).

   Deliberately does NOT match anything under "/aws-reserved/" in the ARN
   path (e.g. AWSReservedSSO_* roles from IAM Identity Center) -- those are
   real, currently-assumable access and exactly what this tool exists to
   surface, not background AWS plumbing.

   A pure function of node data (as stored in a Cytoscape node's data(),
   same id/type/arn shape used throughout this file) so it's trivially
   reusable for both the initial element-build pass and the live toggle.
   ----------------------------------------------------------------------- */
function isAwsDefaultNode(nodeData) {
  if (nodeData.type === "ServicePrincipal") return true;
  const arn = nodeData.arn || "";
  if (arn.startsWith("arn:aws:iam::aws:policy/")) return true;
  if (arn.includes(":role/aws-service-role/")) return true;
  return false;
}

/* -----------------------------------------------------------------------
   Finding severity tiers, from /api/findings -- a distinct scale from
   EDGE_SEVERITY above (findings are critical/high/medium/low; PrivescPath/
   CanAssume/etc. edges are critical/serious/structural). Order is
   high-to-low; anything not in this list (there's no "low" emitted today,
   but the schema allows for it, and defensively for anything unexpected)
   sorts after "low".
   ----------------------------------------------------------------------- */
const FINDING_SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const FINDING_SEVERITY_RANK = Object.fromEntries(FINDING_SEVERITY_ORDER.map((sev, i) => [sev, i]));

function findingSeverityRank(sev) {
  return Object.prototype.hasOwnProperty.call(FINDING_SEVERITY_RANK, sev) ? FINDING_SEVERITY_RANK[sev] : FINDING_SEVERITY_ORDER.length;
}

const MAX_LABEL_LEN = 24;

function truncateLabel(name) {
  if (!name) return "";
  return name.length > MAX_LABEL_LEN ? name.slice(0, MAX_LABEL_LEN - 1) + "…" : name;
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/* -----------------------------------------------------------------------
   Cytoscape stylesheet, built from the maps above plus live-resolved CSS
   variables. Rebuilt (via cy.style()) whenever the OS color scheme
   changes, since node-category colors differ between light and dark.
   ----------------------------------------------------------------------- */
function buildCyStyle() {
  const style = [
    {
      selector: "node",
      style: {
        label: "data(label)",
        // Smaller than an initial pass at this -- less visual weight per
        // node means more of them fit legibly in the same layout-space
        // separation, which matters a lot given some hub nodes here have
        // 100+ connections (see coseLayoutOptions below).
        "font-size": 6,
        // Below this rendered size, Cytoscape skips drawing the label
        // entirely rather than shrinking it further -- the fix for label
        // crowding in the densely-interconnected core: at a zoomed-out
        // fit-everything view the text (not the node shapes themselves,
        // which stay legibly separated) was what overlapped into
        // unreadable clutter. Labels reappear once a user zooms into a
        // given area far enough for them to have room.
        "min-zoomed-font-size": 6,
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 3,
        color: cssVar("--ink-secondary"),
        "background-color": cssVar("--cat-principal"),
        width: 14,
        height: 14,
        "border-width": 0.75,
        "border-color": cssVar("--border-ring"),
      },
    },
  ];

  for (const [category, colorVar] of Object.entries(CATEGORY_COLOR_VAR)) {
    style.push({
      selector: `node[category = "${category}"]`,
      style: { "background-color": cssVar(colorVar) },
    });
  }

  for (const [nodeType, shape] of Object.entries(NODE_SHAPE)) {
    style.push({
      selector: `node[type = "${nodeType}"]`,
      style: { shape },
    });
  }

  style.push({
    selector: "node:selected",
    style: {
      "border-width": 3,
      "border-color": cssVar("--ink-primary"),
    },
  });

  // High-value principal badge: a persistent halo via overlay-* (a glow
  // behind the node), not border-color -- so it coexists with the
  // node:selected bold-border above, and with the --focus-highlight/
  // --path-highlight transient border bypasses below, instead of all of
  // them fighting over the same one border-color/border-width channel.
  style.push({
    selector: "node[?high_value]",
    style: {
      "overlay-color": cssVar("--high-value-badge"),
      "overlay-opacity": 0.45,
      "overlay-padding": 4,
      "overlay-shape": "ellipse",
    },
  });

  // Base edge look, then one rule per severity tier.
  style.push({
    selector: "edge",
    style: {
      "curve-style": "bezier",
      "target-arrow-shape": "triangle",
      "arrow-scale": 0.7,
    },
  });

  for (const [severity, cfg] of Object.entries(EDGE_SEVERITY_STYLE)) {
    const color = cssVar(cfg.colorVar);
    style.push({
      selector: `edge[severity = "${severity}"]`,
      style: {
        "line-color": color,
        "target-arrow-color": color,
        width: cfg.width,
        opacity: cfg.opacity,
      },
    });
  }

  style.push({
    selector: "edge:selected",
    style: {
      width: 4,
      opacity: 1,
    },
  });

  style.push({
    selector: ".ge-hidden",
    style: { display: "none" },
  });

  // AWS-default node visibility toggle (see isAwsDefaultNode and the
  // toggle-aws-default-input wiring in main()) -- a separate class from
  // .ge-hidden above since the two toggles are independent, but the same
  // display:none mechanism. Applied only to nodes: Cytoscape already
  // treats an edge as hidden whenever either endpoint node is
  // display:none'd (verified live), so incident edges need no class of
  // their own.
  style.push({
    selector: ".node-hidden",
    style: { display: "none" },
  });

  // Isolate/focus-zoom (see applyIsolate/restoreIsolate in main()): added
  // to every element NOT part of the currently-focused finding/path-query
  // result while a focus is active. Independent of, and layered on top of,
  // .ge-hidden/.node-hidden above -- an element can carry any/all three
  // classes at once, display:none is idempotent across them, and each
  // toggle's own on/off state is preserved underneath (see clearFocus/
  // clearPathQueryHighlight, which reconcile .ge-hidden/.node-hidden
  // independently of isolate cleanup).
  style.push({
    selector: ".isolate-hidden",
    style: { display: "none" },
  });

  return style;
}

/* -----------------------------------------------------------------------
   Loading / error chrome
   ----------------------------------------------------------------------- */
function showLoading() {
  document.getElementById("loading-overlay").hidden = false;
  document.getElementById("error-overlay").hidden = true;
}

function hideLoading() {
  document.getElementById("loading-overlay").hidden = true;
}

function showError(message) {
  document.getElementById("loading-overlay").hidden = true;
  const errorOverlay = document.getElementById("error-overlay");
  errorOverlay.hidden = false;
  document.getElementById("error-text").textContent = message;
}

/* -----------------------------------------------------------------------
   Inspector panel -- populated generically (kind + label/value field pairs
   + an optional extra HTML block) rather than hardcoding a node/edge/
   finding-only shape, since all three (see main()'s tap handlers and
   focusFinding()) reuse it.
   ----------------------------------------------------------------------- */
function renderInspector(kind, fields, extraHtml) {
  const empty = document.getElementById("inspector-empty");
  const content = document.getElementById("inspector-content");
  empty.hidden = true;
  content.hidden = false;

  const badge = `<span id="inspector-kind-badge">${escapeHtml(kind)}</span>`;
  const rows = fields.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${renderInspectorFieldValue(value)}</dd>`).join("");
  content.innerHTML = `${badge}<dl>${rows}</dl>${extraHtml || ""}`;
}

// A handful of inspector fields (findings' required_permissions/
// evidence_edges) are arrays rather than scalars -- render those as a
// bullet list instead of falling through to Array.prototype.toString's
// comma-joined-with-no-spaces output.
function renderInspectorFieldValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) {
    if (value.length === 0) return "—";
    return `<ul class="inspector-value-list">${value.map((v) => `<li>${escapeHtml(String(v))}</li>`).join("")}</ul>`;
  }
  return escapeHtml(String(value));
}

// Full node/edge detail (the `properties` blob from /api/node//api/edge) is
// arbitrary-shaped -- a pretty-printed JSON block reads better than trying
// to recursively table-ize it, and avoids the classic "[object Object]"
// trap of naive string coercion.
function renderPropertiesLoading() {
  return `<h3>Properties</h3><div class="inspector-properties-status">Loading full detail…</div>`;
}

function renderPropertiesError(message) {
  return `<h3>Properties</h3><div class="inspector-properties-status inspector-properties-error">Failed to load full detail: ${escapeHtml(message)}</div>`;
}

function renderPropertiesBlock(properties) {
  const json = JSON.stringify(properties ?? {}, null, 2);
  return `<h3>Properties</h3><pre class="inspector-properties">${escapeHtml(json)}</pre>`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function clearInspector() {
  document.getElementById("inspector-empty").hidden = false;
  document.getElementById("inspector-content").hidden = true;
  document.getElementById("inspector-content").innerHTML = "";
}

/* -----------------------------------------------------------------------
   Legend
   ----------------------------------------------------------------------- */
function buildLegend() {
  const categoryExamples = {
    principal: { label: "Principal", exampleType: "IamRole", shapeClass: "shape-round-rectangle" },
    policy: { label: "Policy", exampleType: "ManagedPolicy", shapeClass: "shape-round-rectangle" },
    infra: { label: "Infra/Resource", exampleType: "S3Bucket", shapeClass: "shape-round-rectangle" },
    org: { label: "Org/Governance", exampleType: "Account", shapeClass: "shape-star" },
  };

  const nodesList = document.getElementById("legend-nodes");
  nodesList.innerHTML = "";
  for (const [category, info] of Object.entries(categoryExamples)) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="legend-swatch ${info.shapeClass} cat-${category}"></span><span>${info.label} <span style="color:var(--ink-muted)">(e.g. ${info.exampleType})</span></span>`;
    nodesList.appendChild(li);
  }

  // High-value badge -- a halo, not a category color, so its legend swatch
  // is a ring (see .legend-highvalue) rather than a filled shape.
  const highValueLi = document.createElement("li");
  highValueLi.innerHTML = `<span class="legend-swatch shape-ellipse legend-highvalue"></span><span>High-value principal <span style="color:var(--ink-muted)">(e.g. admin-equivalent access)</span></span>`;
  nodesList.appendChild(highValueLi);

  const edgeTiers = [
    { severity: "critical", label: "Critical — proven PrivescPath" },
    { severity: "serious", label: "Serious — CanAssume" },
    { severity: "structural", label: "Structural — everything else" },
  ];

  const edgesList = document.getElementById("legend-edges");
  edgesList.innerHTML = "";
  for (const tier of edgeTiers) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="legend-line edge-${tier.severity}"></span><span>${tier.label}</span>`;
    edgesList.appendChild(li);
  }
}

/* -----------------------------------------------------------------------
   Hover tooltip -- shows edge/node type on hover rather than permanently
   rendering edge-type labels on canvas (unreadable at ~2200 edges).
   ----------------------------------------------------------------------- */
function setupHoverTooltip(cy, container) {
  const tooltip = document.createElement("div");
  tooltip.id = "hover-tooltip";
  container.appendChild(tooltip);

  function showTooltip(text, renderedPosition) {
    tooltip.textContent = text;
    tooltip.style.left = `${renderedPosition.x + 12}px`;
    tooltip.style.top = `${renderedPosition.y + 12}px`;
    tooltip.style.display = "block";
  }

  function hideTooltip() {
    tooltip.style.display = "none";
  }

  cy.on("mouseover", "node", (evt) => {
    const d = evt.target.data();
    showTooltip(`${d.type}: ${d.name}`, evt.renderedPosition || evt.position);
  });
  cy.on("mouseover", "edge", (evt) => {
    const d = evt.target.data();
    showTooltip(d.type, evt.renderedPosition || evt.position);
  });
  cy.on("mousemove", "node, edge", (evt) => {
    const pos = evt.renderedPosition || evt.position;
    tooltip.style.left = `${pos.x + 12}px`;
    tooltip.style.top = `${pos.y + 12}px`;
  });
  cy.on("mouseout", "node, edge", hideTooltip);
  cy.on("pan zoom", hideTooltip);

  // A tap can arrive via a synthetic/programmatic click without a preceding
  // real mousemove, so cytoscape's per-element mouseover/mouseout pair isn't
  // guaranteed to have fired -- return `hide` so callers can force the
  // tooltip closed on tap rather than risk a stale tooltip (showing a
  // previously-hovered element's type) lingering next to the inspector.
  return { hide: hideTooltip };
}

/* -----------------------------------------------------------------------
   Main
   ----------------------------------------------------------------------- */
async function main() {
  showLoading();
  buildLegend();

  let data;
  let findingsData;
  try {
    const [graphResp, findingsResp] = await Promise.all([fetch("/api/graph"), fetch("/api/findings")]);
    if (!graphResp.ok) {
      throw new Error(`/api/graph returned ${graphResp.status} ${graphResp.statusText}`);
    }
    data = await graphResp.json();
    if (!findingsResp.ok) {
      throw new Error(`/api/findings returned ${findingsResp.status} ${findingsResp.statusText}`);
    }
    findingsData = await findingsResp.json();
  } catch (err) {
    showError(`Failed to load graph data: ${err.message}`);
    return;
  }

  // AWS-default nodes (see isAwsDefaultNode) are hidden by default, same
  // convention as HIDDEN_BY_DEFAULT_EDGE_TYPES above -- computed once as an
  // id set for cheap lookups elsewhere (toggle handler, focus reveal).
  //
  // Only NODES get the "node-hidden" class, never edges: verified live in
  // a real browser (via a standalone cytoscape instance in devtools) that
  // Cytoscape already treats an edge as hidden whenever either endpoint
  // node is display:none'd -- ele.hidden()/.visible() come back
  // true/false accordingly even though the edge's own computed style is
  // untouched. Classing edges too would just be redundant state to keep
  // in sync (and to get wrong).
  const awsDefaultNodeIds = new Set(data.nodes.filter(isAwsDefaultNode).map((n) => n.id));

  const elements = {
    nodes: data.nodes.map((n) => ({
      data: {
        id: n.id,
        type: n.type,
        category: NODE_CATEGORY[n.type] || "principal",
        name: n.name,
        arn: n.arn,
        label: truncateLabel(n.name),
        high_value: !!n.high_value,
      },
      classes: awsDefaultNodeIds.has(n.id) ? "node-hidden" : "",
    })),
    edges: data.edges.map((e) => ({
      data: {
        id: e.id,
        type: e.type,
        severity: EDGE_SEVERITY[e.type] || "structural",
        source: e.source,
        target: e.target,
      },
      classes: HIDDEN_BY_DEFAULT_EDGE_TYPES.has(e.type) ? "ge-hidden" : "",
    })),
  };

  // Built from the already-loaded trimmed /api/graph node list, per the
  // findings-panel spec -- avoids an /api/node round-trip per row just to
  // show a human-readable name instead of a raw ARN.
  const nodeNameById = new Map(data.nodes.map((n) => [n.id, n.name]));
  function nodeLabel(id) {
    return nodeNameById.get(id) || id;
  }

  function coseLayoutOptions() {
    return {
      name: "cose",
      animate: false,
      // Pushed further once nodes/edges were also shrunk (see buildCyStyle
      // and EDGE_SEVERITY_STYLE above) -- smaller marks plus more repulsion
      // compound: less visual weight per element AND more space between
      // them. Some hub nodes in a real scan have 100+ connections (shared
      // managed policies attached to dozens of principals), so no amount of
      // tuning here fully declutters their immediate neighborhood -- that's
      // a hard graph-drawing limit, not a parameter problem.
      nodeRepulsion: 120000,
      idealEdgeLength: 100,
      edgeElasticity: 15,
      nodeOverlap: 10,
      // Lower than cose's own default (~80) -- that default pulls every
      // node toward the graph's centroid hard enough to counteract most of
      // the extra repulsion/idealEdgeLength above, which is why naive
      // parameter bumps alone didn't spread the core out.
      gravity: 15,
      numIter: 2500,
      fit: true,
      padding: 30,
    };
  }

  // Run the layout's physics on a de-duplicated edge set (one edge per
  // node pair, ignoring direction/type) rather than every parallel
  // MultiDiGraph edge: this graph has ~370 node pairs connected by 2-6
  // edges at once (e.g. both AttachedPolicy and CanAssume between the same
  // principal/policy), and cose's spring model sums attraction per edge,
  // so those pairs were getting pulled together several times as hard as
  // everywhere else. All original edges (within `eles`) are still
  // rendered -- this only changes what the layout algorithm sees.
  //
  // Takes an explicit element collection rather than always `cy.elements()`
  // so isolate mode (see applyIsolate below) can scope a relayout to just
  // the currently-visible (non-isolate-hidden) subset instead of the whole
  // graph.
  function layoutElements(eles) {
    const seenPairs = new Set();
    const dedupedEdges = eles.edges().filter((e) => {
      const key = [e.data("source"), e.data("target")].sort().join("|");
      if (seenPairs.has(key)) return false;
      seenPairs.add(key);
      return true;
    });
    return eles.nodes().union(dedupedEdges);
  }

  const cy = cytoscape({
    container: document.getElementById("cy"),
    elements,
    style: buildCyStyle(),
  });

  // Scoped to the currently-visible (non-isolate-hidden) elements rather
  // than unconditionally `cy.elements()`: when a finding/path-query focus
  // has isolated the canvas down to a subset (see applyIsolate below), the
  // "Re-run layout" button (wired to this same function) should only
  // reshuffle that visible subset, not silently reveal everything else.
  // When no isolate is active, no element carries .isolate-hidden, so this
  // is simply every element -- behavior is unchanged from before isolate
  // mode existed.
  function runLayout() {
    layoutElements(cy.elements().not(".isolate-hidden")).layout(coseLayoutOptions()).run();
  }

  runLayout();

  hideLoading();

  const hoverTooltip = setupHoverTooltip(cy, document.getElementById("cy"));

  // -----------------------------------------------------------------------
  // Findings panel + transient "focus" highlight.
  //
  // The highlight is applied via Cytoscape style *bypasses* (ele.style()/
  // .removeStyle()) rather than stylesheet classes/selectors -- bypasses
  // sit on top of (and survive) whatever stylesheet is currently applied,
  // so this doesn't need to touch buildCyStyle() or the dark/light
  // stylesheet-swap handler below at all.
  // -----------------------------------------------------------------------
  const findingsByEdgeId = new Map(findingsData.map((f) => [f.edge_id, f]));
  let severityFilterSet = new Set(FINDING_SEVERITY_ORDER);
  let focusedEdgeEles = cy.collection();
  let focusedNodeEles = cy.collection();
  // Nodes force-revealed by focusFinding because they're an AWS-default
  // node caught up in a finding's evidence chain (e.g. an evidence edge's
  // endpoint) but NOT one of the finding's own source/target -- tracked
  // separately from focusedNodeEles since those get the --focus-highlight
  // border treatment below and these don't (they're just made visible).
  let focusedAwsDefaultNodeEles = cy.collection();

  // -----------------------------------------------------------------------
  // Isolate/focus-zoom: when a finding or path-query result is focused
  // (see focusFinding/applyPathQueryHighlight below), hide everything
  // outside the focused subset and relayout just that subset so it gets
  // the whole canvas, then restore the EXACT prior view (positions +
  // pan/zoom, not a fresh cose reshuffle -- cose isn't deterministic) once
  // focus clears. Shared by both focus mechanisms (findings-panel clicks
  // and attack-path query results), which are otherwise independent and
  // mutually exclusive (see clearAllFocus).
  // -----------------------------------------------------------------------
  let isolateSnapshot = null; // { positions: Map<id,{x,y}>, pan: {x,y}, zoom: number } | null

  // Only captures a snapshot if one isn't already pending. If a second
  // finding/path-query is focused while the first is still isolated,
  // focusFinding/applyPathQueryHighlight's own clearAllFocus() call (at
  // their very start, below) already runs restoreIsolate() first --
  // putting the graph fully back to its true pre-isolation positions/
  // pan/zoom and clearing isolateSnapshot to null -- before this is ever
  // reached again. So by the time a new isolate needs a snapshot, it's
  // always capturing the real original state, never an intermediate
  // isolated one.
  function snapshotViewIfNeeded() {
    if (isolateSnapshot !== null) return;
    const positions = new Map();
    cy.nodes().forEach((n) => positions.set(n.id(), { ...n.position() }));
    isolateSnapshot = { positions, pan: { ...cy.pan() }, zoom: cy.zoom() };
  }

  // Ceiling on the zoom level an isolate's fit-to-selection can settle at.
  // runLayout()'s cose layout uses fit:true with a fixed 30px padding
  // (coseLayoutOptions above) -- for a small selection (a typical finding
  // is just 2 nodes + 1-2 edges) that fits the tiny bounding box to the
  // WHOLE canvas, which for this graph's real data measured 17x+ zoom live
  // (a 2-node/2-edge finding, 1620x1025 viewport). At that zoom, node/label
  // rendering is absurdly oversized. 2x reads as "nicely framed" in
  // practice: small enough that a 2-node finding doesn't fill the screen,
  // high enough that it doesn't look zoomed OUT relative to the rest of
  // the UI.
  const ISOLATE_ZOOM_CEILING = 2;

  // Hides everything except keepVisibleEles and relayouts just that
  // visible subset (reusing runLayout(), which is already scoped to
  // non-.isolate-hidden elements) so it fills the canvas. Callers must
  // force-reveal (removeClass "ge-hidden"/"node-hidden") anything in
  // keepVisibleEles that those toggles would otherwise hide BEFORE calling
  // this, and should apply their own highlight styling AFTER, so it isn't
  // wiped/reordered by the relayout.
  //
  // Clamps the resulting zoom down to ISOLATE_ZOOM_CEILING when the fit
  // overshoots it (small selections), but never clamps UP -- a larger
  // isolated result (e.g. a multi-hop attack-path query touching 5-10
  // nodes) that naturally fits at or below the ceiling is left exactly as
  // runLayout()'s fit produced it, so it still gets a full, well-framed
  // view instead of being forced out to a smaller one. Re-centers on the
  // current viewport middle (matching where the fit already centered the
  // selection) rather than using the bare zoom setter, which would zoom
  // around the viewport's top-left origin instead.
  function applyIsolate(keepVisibleEles) {
    snapshotViewIfNeeded();
    cy.elements().difference(keepVisibleEles).addClass("isolate-hidden");
    runLayout();
    if (cy.zoom() > ISOLATE_ZOOM_CEILING) {
      cy.zoom({
        level: ISOLATE_ZOOM_CEILING,
        renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
      });
    }
  }

  // Removes isolate-hidden from every element (not just keepVisibleEles --
  // there is no such reference here, and none is needed) and restores
  // every node's exact cached position plus pan/zoom. A no-op if no
  // isolate is currently active, so it's safe to call unconditionally from
  // both clearFocus() and clearPathQueryHighlight() below -- whichever one
  // corresponds to the actually-active isolate (if any) does the real
  // work; the other is a harmless no-op.
  function restoreIsolate() {
    if (isolateSnapshot === null) return;
    cy.elements().removeClass("isolate-hidden");
    cy.nodes().forEach((n) => {
      const pos = isolateSnapshot.positions.get(n.id());
      if (pos) n.position(pos);
    });
    cy.viewport({ pan: isolateSnapshot.pan, zoom: isolateSnapshot.zoom });
    isolateSnapshot = null;
  }

  function clearFocus() {
    focusedEdgeEles.removeStyle();
    // Evidence edges can include EffectivePermission edges that are hidden
    // by default (see HIDDEN_BY_DEFAULT_EDGE_TYPES) -- focusFinding force-
    // reveals them so the highlight is actually visible; re-hide them here
    // if the toggle is currently off, so clearing focus doesn't leave them
    // permanently visible against the user's toggle choice.
    const toggle = document.getElementById("toggle-effective-permission-input");
    if (toggle && !toggle.checked) {
      focusedEdgeEles.filter((e) => HIDDEN_BY_DEFAULT_EDGE_TYPES.has(e.data("type"))).addClass("ge-hidden");
    }
    // Same idea for AWS-default nodes force-revealed by focusFinding (see
    // isAwsDefaultNode) -- re-hide them if that toggle is off, so clearing
    // focus doesn't leave AWS-default plumbing permanently visible against
    // the user's toggle choice. Their incident edges need no separate
    // handling here: Cytoscape auto-hides an edge once its endpoint node
    // is display:none'd again (see the .node-hidden stylesheet comment).
    const awsDefaultToggle = document.getElementById("toggle-aws-default-input");
    if (awsDefaultToggle && !awsDefaultToggle.checked) {
      focusedAwsDefaultNodeEles.addClass("node-hidden");
    }
    focusedNodeEles.removeStyle();
    focusedEdgeEles = cy.collection();
    focusedNodeEles = cy.collection();
    focusedAwsDefaultNodeEles = cy.collection();
    // Isolate-mode cleanup: restore whatever isolate is currently active
    // (if any) to its exact pre-isolation view. Must run after the
    // ge-hidden/node-hidden reconciliation above, not instead of it --
    // those two classes are independent of .isolate-hidden and still need
    // to end up correctly applied per the user's toggle choices once the
    // isolate-hidden veil itself is lifted.
    restoreIsolate();
  }

  function focusFinding(finding) {
    clearAllFocus();

    const srcEle = cy.getElementById(finding.source);
    const tgtEle = cy.getElementById(finding.target);
    const frameEles = srcEle.union(tgtEle);

    const edgeIdSet = new Set([finding.edge_id, ...(finding.evidence_edges || [])]);
    let edgeEles = cy.collection();
    for (const edgeId of edgeIdSet) {
      const ele = cy.getElementById(edgeId);
      if (!ele.empty()) edgeEles = edgeEles.union(ele);
    }
    edgeEles.removeClass("ge-hidden");

    // Every node touched by the finding itself or its evidence edges --
    // not just source/target, since evidence edges can route through
    // intermediate nodes that also need to stay visible (Cytoscape hides
    // an edge whenever either endpoint node is display:none'd). This is
    // the full "keep visible" set isolate mode below hides everything
    // else relative to.
    let touchedNodes = frameEles;
    edgeEles.forEach((e) => {
      touchedNodes = touchedNodes.union(cy.getElementById(e.data("source"))).union(cy.getElementById(e.data("target")));
    });

    // AWS-default toggle interaction: force-reveal any AWS-default node
    // touched by the finding or its evidence chain, so the highlight below
    // is actually visible even when the "Show AWS-default nodes" toggle is
    // off -- the edges themselves need no separate reveal, since Cytoscape
    // already renders an edge once both its endpoint nodes are visible
    // (see isAwsDefaultNode's comment). Re-hidden by clearFocus() above
    // once focus clears.
    const awsDefaultRevealNodes = touchedNodes.filter((n) => awsDefaultNodeIds.has(n.id()));
    awsDefaultRevealNodes.removeClass("node-hidden");
    focusedAwsDefaultNodeEles = awsDefaultRevealNodes;

    // Isolate mode: hide everything outside the finding's frame/evidence
    // chain and relayout just that subset to fill the canvas. Must run
    // after the ge-hidden/node-hidden force-reveals above (an element
    // still classed ge-hidden/node-hidden stays display:none even once
    // isolate-hidden is withheld from it) and before the highlight styling
    // below, which is applied after the relayout so it isn't wiped/
    // reordered by it.
    const keepVisible = touchedNodes.union(edgeEles);
    if (!keepVisible.empty()) applyIsolate(keepVisible);

    const focusColor = cssVar("--focus-highlight");
    edgeEles.style({
      "line-color": focusColor,
      "target-arrow-color": focusColor,
      width: 4,
      opacity: 1,
    });
    frameEles.style({
      "border-color": focusColor,
      "border-width": 4,
    });

    focusedEdgeEles = edgeEles;
    focusedNodeEles = frameEles;

    renderInspector("Finding", [
      ["technique_id", finding.technique_id],
      ["severity", finding.severity],
      ["source", nodeLabel(finding.source)],
      ["target", nodeLabel(finding.target)],
      ["description", finding.description],
      ["required_permissions", finding.required_permissions],
      ["evidence_edges", finding.evidence_edges],
      ["edge_id", finding.edge_id],
    ]);
  }

  function renderFindingsList() {
    const listEl = document.getElementById("findings-list");
    const visible = findingsData
      .filter((f) => severityFilterSet.has(f.severity))
      .slice()
      .sort((a, b) => findingSeverityRank(a.severity) - findingSeverityRank(b.severity));

    listEl.innerHTML = visible
      .map((f) => {
        const sevClass = Object.prototype.hasOwnProperty.call(FINDING_SEVERITY_RANK, f.severity) ? f.severity : "low";
        return `<li class="finding-row" data-edge-id="${escapeHtml(f.edge_id)}">
          <span class="sev-badge sev-${sevClass}">${escapeHtml(f.severity)}</span>
          <span class="finding-technique">${escapeHtml(f.technique_id)}</span>
          <span class="finding-path">${escapeHtml(nodeLabel(f.source))} &rarr; ${escapeHtml(nodeLabel(f.target))}</span>
        </li>`;
      })
      .join("");

    const total = findingsData.length;
    const shown = visible.length;
    document.getElementById("findings-count").textContent =
      shown === total ? `${total} finding${total === 1 ? "" : "s"}` : `${shown} of ${total} findings shown`;
  }

  document.querySelectorAll(".severity-filter-cb").forEach((cb) => {
    cb.addEventListener("change", () => {
      severityFilterSet = new Set(
        Array.from(document.querySelectorAll(".severity-filter-cb"))
          .filter((c) => c.checked)
          .map((c) => c.value)
      );
      renderFindingsList();
    });
  });

  document.getElementById("findings-list").addEventListener("click", (evt) => {
    const row = evt.target.closest(".finding-row");
    if (!row) return;
    const finding = findingsByEdgeId.get(row.dataset.edgeId);
    if (finding) focusFinding(finding);
  });

  renderFindingsList();

  // -----------------------------------------------------------------------
  // Attack-path query tool: source/target node pickers (searchable by name,
  // built from the already-loaded trimmed /api/graph node list -- no new
  // fetch needed) feeding /api/paths (general reachability, any edge type)
  // or /api/attack-paths (CanAssume/PrivescPath only), with an "any
  // high-value principal" target sentinel as an alternative to a specific
  // node. Results are highlighted as the UNION of all returned paths' edges
  // via a --path-highlight style-bypass -- a second, visually distinct
  // "focus" state alongside the findings panel's --focus-highlight above;
  // clearAllFocus() (defined below) keeps the two mutually exclusive,
  // matching the existing pattern where selecting a new node/edge/finding
  // already clears prior focus.
  // -----------------------------------------------------------------------
  const nodePickerIndex = data.nodes.map((n) => ({ id: n.id, name: n.name, type: n.type }));
  const MAX_SUGGESTIONS = 25;

  // Generic searchable-by-name picker: filters nodePickerIndex by substring
  // match on name as the user types, shows a click-to-select dropdown (name
  // + type, since this real dataset has duplicate names -- e.g. multiple
  // "producer" principals -- so name alone can be ambiguous), and tracks
  // the resolved node id separately from the input's free-text value so a
  // stale/edited search string can never be silently submitted as an id.
  function createNodePicker(inputEl, listEl, onChange) {
    let selectedId = null;

    function renderSuggestions(query) {
      const q = query.trim().toLowerCase();
      if (!q) {
        listEl.hidden = true;
        listEl.innerHTML = "";
        return;
      }
      const matches = nodePickerIndex.filter((n) => n.name.toLowerCase().includes(q)).slice(0, MAX_SUGGESTIONS);
      if (matches.length === 0) {
        listEl.innerHTML = `<li class="node-picker-empty">No matching nodes</li>`;
      } else {
        listEl.innerHTML = matches
          .map(
            (n) =>
              `<li class="node-picker-suggestion" data-id="${escapeHtml(n.id)}">${escapeHtml(n.name)}<span class="node-picker-suggestion-type">${escapeHtml(n.type)}</span></li>`
          )
          .join("");
      }
      listEl.hidden = false;
    }

    function selectNode(id) {
      const node = nodePickerIndex.find((n) => n.id === id);
      if (!node) return;
      selectedId = id;
      inputEl.value = node.name;
      listEl.hidden = true;
      listEl.innerHTML = "";
      onChange();
    }

    inputEl.addEventListener("input", () => {
      // Any manual edit invalidates a prior selection -- a node must be
      // re-picked from the dropdown, never inferred from raw text, so the
      // query can't silently run against a stale/mistyped id.
      selectedId = null;
      renderSuggestions(inputEl.value);
      onChange();
    });
    inputEl.addEventListener("focus", () => {
      if (inputEl.value.trim()) renderSuggestions(inputEl.value);
    });
    inputEl.addEventListener("keydown", (evt) => {
      if (evt.key === "Escape") {
        listEl.hidden = true;
      } else if (evt.key === "Enter") {
        const first = listEl.querySelector(".node-picker-suggestion");
        if (first) {
          evt.preventDefault();
          selectNode(first.dataset.id);
        }
      }
    });
    // mousedown (not click) so this fires before the input's blur handler
    // (there isn't one today, but hiding on outside-click below would
    // otherwise race a click) hides the dropdown.
    listEl.addEventListener("mousedown", (evt) => {
      const li = evt.target.closest(".node-picker-suggestion");
      if (li) selectNode(li.dataset.id);
    });
    document.addEventListener("click", (evt) => {
      if (evt.target !== inputEl && !listEl.contains(evt.target)) listEl.hidden = true;
    });

    return {
      getSelectedId: () => selectedId,
      clear: () => {
        selectedId = null;
        inputEl.value = "";
        listEl.hidden = true;
        listEl.innerHTML = "";
      },
    };
  }

  const pathQueryRunBtn = document.getElementById("pathquery-run-btn");
  const pathQueryStatusEl = document.getElementById("pathquery-status");
  const pathQueryTargetField = document.getElementById("pathquery-target-field");
  const pathQueryTargetInput = document.getElementById("pathquery-target-input");

  function currentTargetMode() {
    return document.querySelector('input[name="pathquery-target-mode"]:checked').value;
  }

  function updatePathQueryRunEnabled() {
    const hasSource = !!sourcePicker.getSelectedId();
    const hasTarget = currentTargetMode() === "high_value" || !!targetPicker.getSelectedId();
    pathQueryRunBtn.disabled = !(hasSource && hasTarget);
  }

  const sourcePicker = createNodePicker(
    document.getElementById("pathquery-source-input"),
    document.getElementById("pathquery-source-suggestions"),
    updatePathQueryRunEnabled
  );
  const targetPicker = createNodePicker(pathQueryTargetInput, document.getElementById("pathquery-target-suggestions"), updatePathQueryRunEnabled);

  const pathQueryReachabilityRadio = document.getElementById("pathquery-mode-reachability-input");
  const pathQueryAttackRadio = document.getElementById("pathquery-mode-attack-input");
  const pathQueryReachabilityLabel = document.getElementById("pathquery-mode-reachability-label");

  document.querySelectorAll('input[name="pathquery-target-mode"]').forEach((radio) => {
    radio.addEventListener("change", () => {
      const isHighValue = currentTargetMode() === "high_value";
      pathQueryTargetInput.disabled = isHighValue;
      pathQueryTargetField.classList.toggle("pathquery-field-disabled", isHighValue);
      if (isHighValue) targetPicker.clear();

      // The target=high_value sentinel ("any high-value principal") is
      // only understood server-side by /api/attack-paths -- /api/paths
      // has no equivalent merge-across-targets behavior and would just
      // 404 on a literal "high_value" node id. Force + lock Attack path
      // mode while this target mode is active instead of letting a user
      // submit a query that's guaranteed to fail.
      pathQueryReachabilityRadio.disabled = isHighValue;
      pathQueryReachabilityLabel.classList.toggle("pathquery-radio-disabled", isHighValue);
      if (isHighValue) pathQueryAttackRadio.checked = true;

      updatePathQueryRunEnabled();
    });
  });

  // Transient path-query highlight state -- parallel to focusedEdgeEles/
  // focusedNodeEles above, kept as separate variables (and a separate
  // clear function) so a finding-focus and a path-query highlight can each
  // be cleared independently of the other, then composed via
  // clearAllFocus() for the mutual-exclusion behavior the spec calls for.
  let pathQueryEdgeEles = cy.collection();
  let pathQueryNodeEles = cy.collection();

  function clearPathQueryHighlight() {
    const hadHighlight = !pathQueryEdgeEles.empty() || !pathQueryNodeEles.empty();
    pathQueryEdgeEles.removeStyle();
    const effPermToggle = document.getElementById("toggle-effective-permission-input");
    if (effPermToggle && !effPermToggle.checked) {
      pathQueryEdgeEles.filter((e) => HIDDEN_BY_DEFAULT_EDGE_TYPES.has(e.data("type"))).addClass("ge-hidden");
    }
    // Same idea for AWS-default nodes force-revealed by
    // applyPathQueryHighlight (see isAwsDefaultNode) -- re-hide them if
    // that toggle is off, mirroring the EffectivePermission handling above.
    // pathQueryNodeEles already contains every node in the result (not
    // just source/target), so this alone covers all revealed endpoints;
    // their incident edges auto-hide again once the node does (see the
    // .node-hidden stylesheet comment), no separate edge handling needed.
    const awsDefaultToggle = document.getElementById("toggle-aws-default-input");
    if (awsDefaultToggle && !awsDefaultToggle.checked) {
      pathQueryNodeEles.filter((n) => awsDefaultNodeIds.has(n.id())).addClass("node-hidden");
    }
    pathQueryNodeEles.removeStyle();
    pathQueryEdgeEles = cy.collection();
    pathQueryNodeEles = cy.collection();
    // Isolate-mode cleanup: restore whatever isolate is currently active
    // (if any) to its exact pre-isolation view. This must happen here too
    // (not only inside clearFocus()) since this function can be reached
    // directly -- the pathquery-clear-btn handler below calls it without
    // going through clearAllFocus()/clearFocus() at all. restoreIsolate()
    // is a no-op if nothing is isolated, so calling it unconditionally
    // from both clear paths is safe.
    restoreIsolate();
    // A stale "N paths found" summary with nothing actually highlighted
    // anymore (e.g. after a finding click took over the highlight) reads
    // as broken -- clear it along with the highlight itself. Skipped when
    // there was nothing highlighted so this doesn't wipe an in-flight
    // "Searching…"/error message that hasn't produced a highlight yet.
    if (hadHighlight) setPathQueryStatus("");
  }

  // The two mutually-exclusive "what's currently focused" states: clearing
  // one on activation of the other (see focusFinding above and the tap
  // handlers / run-query handler below).
  function clearAllFocus() {
    clearFocus();
    clearPathQueryHighlight();
  }

  function unionPathElements(paths) {
    const nodeIds = new Set();
    const edgeIds = new Set();
    for (const path of paths) {
      for (const id of path.nodes) nodeIds.add(id);
      for (const hop of path.hops) {
        for (const edgeId of hop.edge_ids) edgeIds.add(edgeId);
      }
    }
    return { nodeIds, edgeIds };
  }

  // Renders the UNION of all returned paths' nodes/edges as one highlighted
  // set (rather than picking/rendering just the first path) -- still
  // meaningful as "the full reachability surface between source and
  // target(s)" per the spec, and scales fine up to the server's 200-path
  // cap since it's just a dedup over node/edge ids.
  function applyPathQueryHighlight(paths) {
    const { nodeIds, edgeIds } = unionPathElements(paths);

    let nodeEles = cy.collection();
    for (const id of nodeIds) {
      const ele = cy.getElementById(id);
      if (!ele.empty()) nodeEles = nodeEles.union(ele);
    }
    let edgeEles = cy.collection();
    for (const id of edgeIds) {
      const ele = cy.getElementById(id);
      if (!ele.empty()) edgeEles = edgeEles.union(ele);
    }
    // Paths from general reachability (/api/paths) can include
    // EffectivePermission edges, which are hidden by default -- force them
    // visible so the highlight itself isn't invisible, mirroring
    // focusFinding's handling of the same toggle.
    edgeEles.removeClass("ge-hidden");
    // Same idea for AWS-default nodes (see isAwsDefaultNode) -- a path can
    // legitimately route through e.g. a service-linked role. nodeEles here
    // is already every node touched by any returned path (not just
    // source/target), so this covers all revealed endpoints; their
    // incident edges become visible automatically once both endpoints are
    // (see the .node-hidden stylesheet comment).
    nodeEles.removeClass("node-hidden");

    // Isolate mode: hide everything outside the result subset and
    // relayout just that subset to fill the canvas (same pattern as
    // focusFinding above). nodeEles already covers every node touched by
    // any returned path, so union with edgeEles is the full keep-visible
    // set. Must run after the force-reveals above and before the
    // highlight styling below, applied after the relayout so it isn't
    // wiped/reordered by it -- this also replaces the plain cy.fit() this
    // function used to do, since applyIsolate's relayout already fits the
    // viewport to the visible subset.
    const keepVisible = nodeEles.union(edgeEles);
    if (!keepVisible.empty()) applyIsolate(keepVisible);

    const color = cssVar("--path-highlight");
    edgeEles.style({
      "line-color": color,
      "target-arrow-color": color,
      width: 3.5,
      opacity: 1,
    });
    nodeEles.style({
      "border-color": color,
      "border-width": 4,
    });

    pathQueryEdgeEles = edgeEles;
    pathQueryNodeEles = nodeEles;

    return { nodeCount: nodeIds.size, edgeCount: edgeIds.size };
  }

  function setPathQueryStatus(text, kind) {
    pathQueryStatusEl.textContent = text;
    pathQueryStatusEl.className = kind ? `pathquery-status-${kind}` : "";
  }

  pathQueryRunBtn.addEventListener("click", async () => {
    const sourceId = sourcePicker.getSelectedId();
    const targetMode = currentTargetMode();
    const targetId = targetMode === "high_value" ? "high_value" : targetPicker.getSelectedId();
    if (!sourceId || !targetId) return; // run button is disabled otherwise

    const queryMode = document.querySelector('input[name="pathquery-mode"]:checked').value;
    const endpoint = queryMode === "attack" ? "/api/attack-paths" : "/api/paths";

    let maxHops = parseInt(document.getElementById("pathquery-maxhops-input").value, 10);
    if (!Number.isFinite(maxHops) || maxHops < 1) maxHops = 6;

    // Running a query is itself a new "focus" action -- clear any active
    // finding highlight (and any highlight from a prior query run) up
    // front, before the fetch resolves, per the mutual-exclusion spec.
    clearAllFocus();
    setPathQueryStatus("Searching…", "loading");

    const params = new URLSearchParams({ source: sourceId, target: targetId, max_hops: String(maxHops) });
    let resp;
    try {
      resp = await fetch(`${endpoint}?${params.toString()}`);
    } catch (err) {
      setPathQueryStatus(`Error: ${err.message}`, "error");
      return;
    }

    if (!resp.ok) {
      let detail = resp.statusText;
      try {
        const body = await resp.json();
        if (body && body.detail) detail = body.detail;
      } catch (_parseErr) {
        // Response body wasn't JSON -- fall back to statusText above.
      }
      setPathQueryStatus(`Error: ${resp.status} ${detail}`, "error");
      return;
    }

    let result;
    try {
      result = await resp.json();
    } catch (err) {
      setPathQueryStatus(`Error: ${err.message}`, "error");
      return;
    }

    const paths = result.paths || [];
    if (paths.length === 0) {
      setPathQueryStatus("No path found.", "empty");
      return;
    }

    const { nodeCount, edgeCount } = applyPathQueryHighlight(paths);
    setPathQueryStatus(
      `${paths.length} path${paths.length === 1 ? "" : "s"} found, ${edgeCount} edge${edgeCount === 1 ? "" : "s"} involved (${nodeCount} node${nodeCount === 1 ? "" : "s"}).`,
      "success"
    );
  });

  document.getElementById("pathquery-clear-btn").addEventListener("click", () => {
    clearPathQueryHighlight();
    setPathQueryStatus("");
  });

  updatePathQueryRunEnabled();

  // -----------------------------------------------------------------------
  // Inspector: click-to-select fed from already-loaded trimmed data, then
  // topped up with full /api/node//api/edge detail (including `properties`)
  // once it arrives. A request sequence number guards against a slower,
  // superseded fetch (from an earlier click) overwriting a newer selection.
  // -----------------------------------------------------------------------
  let inspectorRequestSeq = 0;

  async function loadFullDetail(kind, endpoint, id, basicFields) {
    const seq = ++inspectorRequestSeq;
    try {
      const resp = await fetch(`${endpoint}?id=${encodeURIComponent(id)}`);
      if (seq !== inspectorRequestSeq) return;
      if (!resp.ok) {
        let detail = resp.statusText;
        try {
          const body = await resp.json();
          if (body && body.detail) detail = body.detail;
        } catch (_parseErr) {
          // Response body wasn't JSON -- fall back to statusText above.
        }
        renderInspector(kind, basicFields, renderPropertiesError(`${resp.status} ${detail}`));
        return;
      }
      const full = await resp.json();
      if (seq !== inspectorRequestSeq) return;
      renderInspector(kind, basicFields, renderPropertiesBlock(full.properties));
    } catch (err) {
      if (seq !== inspectorRequestSeq) return;
      renderInspector(kind, basicFields, renderPropertiesError(err.message));
    }
  }

  cy.on("tap", "node", (evt) => {
    hoverTooltip.hide();
    clearAllFocus();
    const d = evt.target.data();
    const basicFields = [
      ["id", d.id],
      ["type", d.type],
      ["name", d.name],
      ["arn", d.arn],
    ];
    renderInspector("Node", basicFields, renderPropertiesLoading());
    loadFullDetail("Node", "/api/node", d.id, basicFields);
  });
  cy.on("tap", "edge", (evt) => {
    hoverTooltip.hide();
    clearAllFocus();
    const d = evt.target.data();
    const basicFields = [
      ["id", d.id],
      ["type", d.type],
      ["source", d.source],
      ["target", d.target],
    ];
    renderInspector("Edge", basicFields, renderPropertiesLoading());
    loadFullDetail("Edge", "/api/edge", d.id, basicFields);
  });
  cy.on("tap", (evt) => {
    if (evt.target === cy) {
      hoverTooltip.hide();
      clearAllFocus();
      clearInspector();
    }
  });

  // EffectivePermission visibility toggle (default off, per HIDDEN_BY_DEFAULT_EDGE_TYPES).
  const toggle = document.getElementById("toggle-effective-permission-input");
  toggle.checked = false;
  toggle.addEventListener("change", () => {
    const edges = cy.edges().filter((e) => HIDDEN_BY_DEFAULT_EDGE_TYPES.has(e.data("type")));
    if (toggle.checked) {
      edges.removeClass("ge-hidden");
    } else {
      edges.addClass("ge-hidden");
    }
  });

  // AWS-default node visibility toggle (default off, per isAwsDefaultNode /
  // awsDefaultNodeIds above) -- only the nodes need the class toggled;
  // Cytoscape already treats their incident edges as hidden once a
  // connected node is (verified live via a standalone cytoscape instance:
  // ele.hidden() came back true for an edge whose endpoint had
  // display:none, even though the edge's own style was untouched), so
  // there's no separate edge set to manage here.
  const awsDefaultToggle = document.getElementById("toggle-aws-default-input");
  awsDefaultToggle.checked = false;
  awsDefaultToggle.addEventListener("change", () => {
    const nodes = cy.nodes().filter((n) => awsDefaultNodeIds.has(n.id()));
    if (awsDefaultToggle.checked) {
      nodes.removeClass("node-hidden");
    } else {
      nodes.addClass("node-hidden");
    }
  });

  document.getElementById("layout-rerun-btn").addEventListener("click", runLayout);

  // Node-category colors differ between light/dark; edge severity colors
  // are fixed and don't need to change, but re-applying the whole
  // stylesheet on scheme flips is simplest and cheap at this graph size.
  //
  // This fires on every OS scheme change regardless of whether a manual
  // override is currently active. That's intentional, not an oversight: if
  // data-theme is set, style.css's :root[data-theme=...] blocks outrank the
  // prefers-color-scheme media query on specificity, so cssVar() resolves
  // to the SAME override colors either way -- the rebuild below is just a
  // harmless no-op while an override is active, and is exactly what's
  // needed to repaint the canvas for a "System"-mode user whose OS setting
  // changes while the page is open.
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    cy.style(buildCyStyle()).update();
  });

  // -----------------------------------------------------------------------
  // Manual theme toggle: a 3-state System -> Light -> Dark -> System cycle
  // button (see THEME_STORAGE_KEY/applyStoredTheme above, run once at
  // module load before this function's first buildCyStyle() call). Picking
  // Light/Dark sets data-theme + persists to localStorage; picking System
  // clears both, falling back to the OS's prefers-color-scheme setting via
  // the listener above. Every transition rebuilds the Cytoscape stylesheet
  // itself (not just relying on the CSS repaint) since node/edge colors are
  // baked into cy's style at buildCyStyle()-call time -- same reason the
  // OS-change listener above needs to do it.
  // -----------------------------------------------------------------------
  const THEME_CYCLE = ["system", "light", "dark"];
  const THEME_LABEL = { system: "System", light: "Light", dark: "Dark" };
  const themeToggleBtn = document.getElementById("theme-toggle-btn");
  const themeToggleLabel = document.getElementById("theme-toggle-label");

  function currentThemeMode() {
    return getStoredTheme() || "system";
  }

  function renderThemeToggle() {
    const mode = currentThemeMode();
    themeToggleLabel.textContent = THEME_LABEL[mode];
    themeToggleBtn.setAttribute("aria-label", `Color theme: ${THEME_LABEL[mode]} (click to change)`);
  }

  themeToggleBtn.addEventListener("click", () => {
    const next = THEME_CYCLE[(THEME_CYCLE.indexOf(currentThemeMode()) + 1) % THEME_CYCLE.length];
    if (next === "system") {
      localStorage.removeItem(THEME_STORAGE_KEY);
      document.documentElement.removeAttribute("data-theme");
    } else {
      localStorage.setItem(THEME_STORAGE_KEY, next);
      document.documentElement.setAttribute("data-theme", next);
    }
    renderThemeToggle();
    cy.style(buildCyStyle()).update();
  });

  renderThemeToggle();
}

main();
