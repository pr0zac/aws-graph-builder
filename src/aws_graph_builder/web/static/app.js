import {get, LatestRequest} from './api.mjs';
import {GraphModel, Investigation, DEFAULT_FILTERS, titleCase} from './model.mjs';
import {GraphView} from './graph.mjs';
import {Inspector} from './inspector.mjs';
import {$, el, button, badge, option, message} from './ui.mjs';

const themeKey = 'aws-graph-builder-theme';
function storedTheme() { try { return localStorage.getItem(themeKey); } catch { return null; } }
function applyTheme(theme) {
  if (['light', 'dark'].includes(theme)) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
  $('theme-name').textContent = theme ? titleCase(theme) : 'System';
}
applyTheme(storedTheme());

async function main() {
  let data, findings;
  try { [data, findings] = await Promise.all([get('/api/viewer'), get('/api/findings')]); }
  catch (error) {
    $('loading').hidden = true; $('app-error').hidden = false;
    $('app-error').replaceChildren(el('p', '', `Could not load this graph: ${error.message}`), button('Retry', () => location.reload()));
    return;
  }
  const model = new GraphModel(data, findings);
  const state = new Investigation();
  const queryGate = new LatestRequest();
  let currentTab = 'explore';
  let routeResult = null;
  let routeMode = 'attack';
  let activeRoute = -1;
  let expansion = null;
  const filters = {...DEFAULT_FILTERS};
  const graph = new GraphView($('cy'), model, inspect, ids => { $('hide-selected').disabled = !ids.length; });
  const inspector = new Inspector(model, {
    inspect, clearSelection: () => state.select(null), expand,
    paths: id => { setSource(id); $('route-target').value = 'high_value'; syncMode(); runRoutes(); },
    source: setSource, target: setTarget, hide: id => hideNodes([id]),
    findings: id => {
      for (const control of ['finding-source','finding-target','finding-technique','finding-severity','finding-search','finding-access']) $(control).value = '';
      $('finding-related').value = id; setTab('findings'); renderFindings();
      document.body.classList.add('nav-open');
    },
  });

  function setTab(tab) {
    if (currentTab === 'paths' && tab !== 'paths') cancelQuery();
    currentTab = tab;
    for (const name of ['explore', 'findings', 'paths']) $(name + '-panel').hidden = name !== tab;
    for (const control of document.querySelectorAll('[data-tab]')) {
      control.classList.toggle('active', control.dataset.tab === tab);
      if (control.dataset.tab === tab) control.setAttribute('aria-current', 'page');
      else control.removeAttribute('aria-current');
    }
  }
  function capture() {
    if (state.view.kind !== 'landing') Object.assign(state.view, graph.snapshot());
  }
  function navigate(view) {
    queryGate.cancel();
    capture(); state.navigate(view); inspector.close();
    if (state.view.routeContext) restoreRouteContext(state.view.routeContext);
    paint();
    document.body.classList.remove('nav-open');
  }
  function inspect(selection) {
    state.select(selection);
    inspector.show(selection);
  }
  function paint() {
    const view = state.view;
    graph.render(view, state.hidden);
    $('landing').hidden = view.kind !== 'landing';
    $('graph-empty').hidden = view.kind === 'landing' || state.visibleNodeIds().length > 0;
    $('view-kind').textContent = ({route: 'PATH INVESTIGATION', finding: 'FINDING EVIDENCE', overview: 'ACCOUNT OVERVIEW', explore: 'PRINCIPAL EXPLORATION', landing: 'EXPLORE'})[view.kind];
    $('view-title').textContent = view.title;
    $('back').disabled = !state.history.length;
    $('focus-note').hidden = !['finding', 'route'].includes(view.kind);
    $('visible-count').textContent = view.kind === 'landing' ? 'Ready to explore' : `${graph.cy.nodes().length} nodes · ${graph.cy.edges().length} connections`;
    $('filter-toggle').disabled = ['route', 'finding', 'landing'].includes(view.kind);
    if ($('filter-toggle').disabled) { $('graph-filters').hidden = true; $('filter-toggle').setAttribute('aria-expanded', 'false'); }
    const hiddenControls = $('hidden-controls');
    hiddenControls.replaceChildren();
    if (state.hidden.size) hiddenControls.append(button(`${state.hidden.size} hidden · Restore`, showHidden, 'icon-button'));
    for (const control of ['fit', 'relayout', 'reset']) $(control).disabled = view.kind === 'landing';
    $('hide-selected').disabled = true;
  }
  function hideNodes(ids) {
    if (!ids.length) return;
    capture();
    ids.forEach(id => state.hidden.add(id));
    // Focused evidence deliberately keeps required nodes visible until Back.
    inspector.close(); paint();
  }
  function showHidden() {
    const {root} = inspector.shell('Hidden nodes', 'VISIBILITY', '◌');
    root.append(el('p', 'small muted', 'Focused evidence temporarily reveals required nodes. Restore items here to change your exploration preference.'));
    const restore = id => { state.hidden.delete(id); paint(); showHidden(); };
    root.append(button('Restore all', () => { state.hidden.clear(); paint(); inspector.close(); }, 'button wide'));
    for (const id of state.hidden) root.append(button(`Restore ${model.name(id)}`, () => restore(id), 'evidence-button'));
  }
  function entityRow(node) {
    const row = button('', () => openNode(node.id), `entity-row${node.high_value ? ' high-value-row' : ''}`);
    const text = el('span', 'entity-text');
    text.append(el('span', 'entity-name', node.name), el('span', 'entity-type', titleCase(node.type)));
    row.append(el('span', 'entity-icon', node.high_value ? '★' : node.type === 'IamUser' ? '○' : '◇'), text, el('span', 'entity-arrow', '↗'));
    row.title = node.arn || node.id;
    return row;
  }
  function renderPrincipals() {
    const matches = model.search($('explore-search').value, true).filter(n => !$('explore-type').value || n.type === $('explore-type').value);
    const highValue = matches.filter(n => n.high_value);
    $('high-value-list').replaceChildren(...highValue.map(entityRow));
    if (!highValue.length) message($('high-value-list'), 'No matching high-value principals.');
    $('principal-list').replaceChildren(...matches.map(entityRow));
    $('principal-count').textContent = matches.length;
    if (!matches.length) message($('principal-list'), 'No matching principals. Try another name or ARN.');
  }
  function openNode(id) {
    setTab('explore');
    const wanted = model.neighborhood(id, filters);
    if (wanted.nodeIds.length > 51) {
      navigate({...wanted, nodeIds: [id], edgeIds: []});
      expand(id);
    } else navigate(wanted);
    inspect({kind: 'node', id});
  }
  function overview() {
    navigate(model.overview(filters));
  }
  function expand(id) {
    if (!['explore', 'overview'].includes(state.view.kind)) {
      navigate({kind: 'explore', title: model.name(id), root: id, nodeIds: [id], edgeIds: [], filters: {...filters}});
    }
    const candidate = model.neighborhood(id, filters);
    const existing = new Set(state.view.nodeIds);
    const additions = candidate.nodeIds.filter(n => !existing.has(n));
    expansion = {candidate, additions, picked: new Set(additions.length <= 50 ? additions : [])};
    $('expansion-title').textContent = model.name(id);
    $('expansion-summary').textContent = `${additions.length} new nodes · ${candidate.edgeIds.filter(e => !state.view.edgeIds.includes(e)).length} new relationships. Choose up to 50 new nodes at a time.`;
    $('expansion-search').value = '';
    renderExpansion();
    $('expansion-dialog').showModal();
  }
  function renderExpansion() {
    if (!expansion) return;
    const query = $('expansion-search').value.toLowerCase();
    const matches = expansion.additions.filter(id => `${model.name(id)} ${model.nodes.get(id)?.type} ${id}`.toLowerCase().includes(query));
    $('expansion-list').replaceChildren();
    for (const id of matches) {
      const label = el('label', 'expansion-row');
      const check = el('input'); check.type = 'checkbox'; check.checked = expansion.picked.has(id);
      const text = el('span', '', model.name(id)); text.append(el('small', '', titleCase(model.nodes.get(id)?.type)));
      check.addEventListener('change', () => { if (check.checked) expansion.picked.add(id); else expansion.picked.delete(id); updateExpansionCount(); });
      label.append(check, text); $('expansion-list').append(label);
    }
    if (!matches.length) message($('expansion-list'), expansion.additions.length ? 'No matching neighbors.' : 'All neighboring nodes are already included. You can still add missing relationships.');
    updateExpansionCount();
  }
  function updateExpansionCount() {
    $('expansion-count').textContent = `${expansion.picked.size} / 50 new nodes selected`;
    $('expansion-apply').disabled = expansion.picked.size > 50;
  }
  $('expansion-apply').addEventListener('click', () => {
    if (!expansion || expansion.picked.size > 50) return;
    capture();
    const nodeIds = [...new Set([...state.view.nodeIds, ...expansion.picked])];
    const ids = new Set(nodeIds);
    const edgeIds = [...new Set([...state.view.edgeIds, ...expansion.candidate.edgeIds.filter(id => {
      const e = model.edges.get(id); return ids.has(e.source) && ids.has(e.target);
    })])];
    navigate({...state.view, nodeIds, edgeIds, positions: {...state.view.positions}, viewport: state.view.viewport});
    $('expansion-dialog').close();
  });
  $('expansion-close').addEventListener('click', () => $('expansion-dialog').close());
  $('expansion-search').addEventListener('input', renderExpansion);

  function renderFindings() {
    const shown = model.filterFindings({query: $('finding-search').value, severity: $('finding-severity').value,
      technique: $('finding-technique').value, source: $('finding-source').value, target: $('finding-target').value,
      sourceAccess: $('finding-access').value, related: $('finding-related').value});
    $('finding-count').textContent = `${shown.length} of ${findings.length} detected techniques`;
    const groups = new Map();
    for (const f of shown) {
      const key = $('finding-group').value === 'source' ? model.name(f.source) : titleCase(f.technique_id);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(f);
    }
    $('finding-list').replaceChildren();
    for (const [name, group] of groups) {
      $('finding-list').append(el('h3', '', `${name} · ${group.length}`));
      for (const f of group) {
        const row = button('', () => {
          navigate(model.findingView(f)); inspect({kind: 'finding', finding: f});
        }, 'finding-card');
        row.append(badge(f.severity, f.severity), el('strong', '', titleCase(f.technique_id)),
          el('p', 'path-name', model.name(f.source)), el('p', '', `→ ${model.name(f.target)}`));
        if (model.nodes.get(f.source)?.high_value) row.append(badge('Already high-value source', 'subtle'));
        if ((f.evidence_edges || []).some(id => model.edges.get(id)?.condition_unresolved)) row.append(badge('Unresolved condition', 'warning'));
        $('finding-list').append(row);
      }
    }
    if (!shown.length) message($('finding-list'), 'No findings match these filters.');
  }
  function fillNodeSelect(select, query = '', sentinel = false, selected = select.value) {
    const nodes = model.search(query);
    const choices = [option(sentinel ? 'high_value' : '', sentinel ? '★ Any high-value principal' : 'Choose a node…')];
    for (const n of nodes) choices.push(option(n.id, `${n.name} · ${titleCase(n.type)} · ${n.arn || n.id}`));
    select.replaceChildren(...choices);
    if ([...select.options].some(o => o.value === selected)) select.value = selected;
  }
  function setSource(id) {
    cancelQuery(true);
    setTab('paths'); $('route-source-search').value = ''; fillNodeSelect($('route-source'), '', false, id);
  }
  function setTarget(id) {
    cancelQuery(true);
    setTab('paths'); $('route-target-search').value = ''; fillNodeSelect($('route-target'), '', true, id); syncMode();
  }
  function cancelQuery(clearResults = false) {
    queryGate.cancel();
    $('route-run').textContent = 'Find paths →';
    if (clearResults) {
      routeResult = null; activeRoute = -1;
      $('route-list').replaceChildren(); $('route-union').hidden = true; $('route-status').textContent = '';
    }
  }
  function routeContext(index) {
    return {result: routeResult, activeRoute: index, mode: routeMode, source: $('route-source').value,
      target: $('route-target').value, hops: $('route-hops').value, status: $('route-status').textContent};
  }
  function restoreRouteContext(context) {
    routeResult = context.result; activeRoute = context.activeRoute; routeMode = context.mode;
    $('route-source-search').value = ''; $('route-target-search').value = '';
    fillNodeSelect($('route-source'), '', false, context.source); fillNodeSelect($('route-target'), '', true, context.target);
    $('route-mode').value = context.mode; $('route-hops').value = context.hops; syncMode();
    $('route-status').textContent = context.status; $('route-run').textContent = 'Find paths →';
    renderRoutes();
  }
  function syncMode() {
    const isHighValue = $('route-target').value === 'high_value';
    if (isHighValue) $('route-mode').value = 'attack';
    $('route-mode').disabled = isHighValue;
    $('route-explanation').textContent = $('route-mode').value === 'attack' ? 'Uses assume-role and privilege-escalation relationships.' : 'Structural reachability explores all relationships. It does not imply gaining control.';
  }
  async function runRoutes() {
    const source = $('route-source').value;
    const target = $('route-target').value;
    if (!source || !target) { $('route-status').textContent = 'Choose a source and target first.'; return; }
    const hops = Number($('route-hops').value);
    if (!Number.isInteger(hops) || hops < 1 || hops > 10) { $('route-status').textContent = 'Choose between 1 and 10 hops.'; return; }
    const ticket = queryGate.begin();
    $('route-status').textContent = 'Searching for unique routes…';
    $('route-run').textContent = 'Searching…';
    $('route-list').replaceChildren(); $('route-union').hidden = true;
    routeResult = null;
    const mode = $('route-mode').value;
    try {
      const result = await get('/api/routes', {source, target, max_hops: hops, mode}, ticket.signal);
      if (!queryGate.valid(ticket)) return;
      routeResult = result; routeMode = mode;
      const limit = result.complete ? '' : ` Search stopped at the ${({route_limit: '200-route limit', work_limit: 'work limit', time_limit: 'time limit'})[result.stop_reason] || 'search limit'}; results are partial.`;
      $('route-status').textContent = result.already_at_target ? 'The source already has the selected target access.' :
        result.paths.length ? `${result.paths.length} unique route${result.paths.length === 1 ? '' : 's'}, shortest first.${limit}` :
          `No route ${result.complete ? 'found within this hop limit.' : 'found before search stopped.'}${limit}`;
      $('route-status').className = `small${result.complete ? '' : ' notice warning'}`;
      renderRoutes();
      if (result.paths.length) selectRoute(0);
    } catch (err) { if (queryGate.valid(ticket)) $('route-status').textContent = `Query failed: ${err.message}`; }
    finally { if (queryGate.valid(ticket)) $('route-run').textContent = 'Find paths →'; }
  }
  function renderRoutes() {
    $('route-list').replaceChildren();
    for (const [i, path] of (routeResult?.paths || []).entries()) {
      const row = button('', () => selectRoute(i), `route-card${i === activeRoute ? ' active' : ''}`);
      row.append(badge(`${path.hops.length} hops`, 'subtle'), el('strong', '', `Route ${i + 1}`),
        el('p', '', path.nodes.map(id => model.name(id)).join(' → ')));
      $('route-list').append(row);
    }
    $('route-union').hidden = (routeResult?.paths.length || 0) < 2;
  }
  function selectRoute(index) {
    const path = routeResult?.paths[index];
    if (!path) return;
    activeRoute = index;
    navigate({kind: 'route', title: `${model.name(path.nodes[0])} → ${model.name(path.nodes.at(-1))}`,
      nodeIds: path.nodes, edgeIds: path.hops.flatMap(h => h.edge_ids), routeOrder: path.nodes, mode: routeMode,
      routeContext: routeContext(index)});
    renderRoutes(); inspect({kind: 'route', path, mode: routeMode});
    $('route-run').textContent = 'Find paths →';
  }
  $('route-union').addEventListener('click', () => {
    if (!routeResult?.paths.length) return;
    activeRoute = -1;
    navigate({kind: 'route', title: `${routeResult.paths.length} routes · combined view`,
      nodeIds: [...new Set(routeResult.paths.flatMap(p => p.nodes))], edgeIds: [...new Set(routeResult.paths.flatMap(p => p.hops.flatMap(h => h.edge_ids)))],
      routeContext: routeContext(-1)});
    renderRoutes();
  });

  $('account-id').textContent = data.metadata.account_id || 'Unknown account';
  const coverage = $('coverage-pill');
  coverage.replaceWith(button(data.coverage.status === 'complete' ? '● Coverage complete' : data.coverage.status === 'partial' ? `● ${data.coverage.gaps.length} scan gaps` : 'Coverage unknown', () => inspect({kind: 'coverage', coverage: data.coverage, metadata: data.metadata}), `badge${data.coverage.status === 'complete' ? '' : ' warning'}`));
  const stamp = new Date(data.metadata.generated_at);
  $('scan-date').textContent = Number.isNaN(stamp.valueOf()) ? 'Scan date unavailable' : `Scanned ${stamp.toLocaleDateString(undefined, {month: 'short', day: 'numeric', year: 'numeric'})}`;
  $('findings-total').textContent = findings.length;
  const highValueCount = [...model.nodes.values()].filter(n => n.high_value).length;
  $('landing-stats').replaceChildren(...[[model.nodes.size, 'RESOURCES'], [findings.length, 'FINDINGS'], [highValueCount, 'HIGH-VALUE IDENTITIES']].map(([count, label]) => {
    const stat = el('div', 'landing-stat'); stat.append(el('strong', '', count), el('span', '', label)); return stat;
  }));
  $('finding-technique').append(option('', 'All techniques'), ...[...new Set(findings.map(f => f.technique_id))].sort().map(id => option(id, titleCase(id))));
  for (const role of ['source', 'target', 'related']) {
    const ids = [...new Set(findings.flatMap(f => role === 'related' ? [f.source, f.target] : [f[role]]))].sort((a,b) => model.name(a).localeCompare(model.name(b)));
    $(`finding-${role}`).append(option('', `All ${role} identities`), ...ids.map(id => option(id, `${model.name(id)} · ${titleCase(model.nodes.get(id)?.type)} · ${id}`)));
  }
  $('filter-type').append(option('', 'All node types'), ...[...new Set(data.nodes.map(n => n.type))].sort().map(type => option(type, titleCase(type))));
  fillNodeSelect($('route-source')); fillNodeSelect($('route-target'), '', true);
  syncMode(); renderPrincipals(); renderFindings(); paint(); $('loading').hidden = true;

  document.querySelectorAll('[data-tab]').forEach(control => control.addEventListener('click', () => setTab(control.dataset.tab)));
  $('explore-search').addEventListener('input', renderPrincipals); $('explore-type').addEventListener('change', renderPrincipals);
  for (const id of ['finding-search','finding-severity','finding-technique','finding-source','finding-target','finding-related','finding-access','finding-group']) $(id).addEventListener(id === 'finding-search' ? 'input' : 'change', renderFindings);
  $('overview').addEventListener('click', overview); $('landing-overview').addEventListener('click', overview);
  $('landing-findings').addEventListener('click', () => { setTab('findings'); document.body.classList.add('nav-open'); });
  $('back').addEventListener('click', () => {
    cancelQuery(); capture(); state.back(); inspector.close();
    setTab(state.view.kind === 'route' ? 'paths' : state.view.kind === 'finding' ? 'findings' : 'explore');
    if (state.view.routeContext) restoreRouteContext(state.view.routeContext);
    Object.assign(filters, state.view.filters || filters); syncFilterControls(); paint();
  });
  $('fit').addEventListener('click', () => graph.fit());
  $('relayout').addEventListener('click', () => {
    if (state.view.kind === 'route' && state.view.routeOrder) { delete state.view.positions; delete state.view.viewport; paint(); }
    else graph.layout();
  });
  $('reset').addEventListener('click', () => {
    queryGate.cancel(); state.history = []; state.hidden.clear(); state.view = {kind:'landing',title:'Start an investigation',nodeIds:[],edgeIds:[],filters:{...DEFAULT_FILTERS}};
    Object.assign(filters, DEFAULT_FILTERS); syncFilterControls(); inspector.close(); paint();
  });
  $('hide-selected').addEventListener('click', () => hideNodes(graph.selected()));
  $('filter-toggle').addEventListener('click', () => { $('graph-filters').hidden = !$('graph-filters').hidden; $('filter-toggle').setAttribute('aria-expanded', String(!$('graph-filters').hidden)); });
  function syncFilterControls() {
    $('filter-direction').value = filters.direction; $('filter-relationship').value = filters.relationship;
    $('filter-type').value = filters.nodeType; $('filter-permissions').checked = filters.showPermissions; $('filter-aws').checked = filters.showAws;
  }
  function changeFilters() {
    filters.direction = $('filter-direction').value; filters.relationship = $('filter-relationship').value;
    filters.nodeType = $('filter-type').value; filters.showPermissions = $('filter-permissions').checked; filters.showAws = $('filter-aws').checked;
    if (!['overview', 'explore'].includes(state.view.kind)) return;
    capture();
    if (state.view.kind === 'overview') navigate({...model.overview(filters), positions: state.view.positions, viewport: state.view.viewport});
    else {
      const wanted = model.neighborhood(state.view.root, filters);
      if (wanted.nodeIds.length > 51) { navigate({...wanted, nodeIds: [wanted.root], edgeIds: []}); expand(wanted.root); }
      else navigate({...wanted, positions: state.view.positions, viewport: state.view.viewport});
    }
  }
  ['filter-direction','filter-relationship','filter-type','filter-permissions','filter-aws'].forEach(id => $(id).addEventListener('change', changeFilters));
  $('route-form').addEventListener('submit', event => { event.preventDefault(); runRoutes(); });
  $('route-source-search').addEventListener('input', () => { cancelQuery(true); fillNodeSelect($('route-source'), $('route-source-search').value); });
  $('route-target-search').addEventListener('input', () => { cancelQuery(true); fillNodeSelect($('route-target'), $('route-target-search').value, true); syncMode(); });
  for (const id of ['route-source','route-target','route-mode','route-hops']) $(id).addEventListener('change', () => { cancelQuery(true); syncMode(); });
  $('theme').addEventListener('click', () => {
    const modes = [null,'light','dark']; const mode = modes[(modes.indexOf(storedTheme()) + 1) % modes.length];
    try { if (mode) localStorage.setItem(themeKey, mode); else localStorage.removeItem(themeKey); } catch { /* Storage can be unavailable. */ }
    applyTheme(mode); graph.theme();
  });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => graph.theme());
  $('nav-toggle').addEventListener('click', () => document.body.classList.toggle('nav-open'));
  $('global-search').addEventListener('input', () => {
    const query = $('global-search').value;
    $('global-results').hidden = !query.trim();
    const matches = model.search(query).slice(0, 50);
    $('global-options').replaceChildren(...matches.map(n => option(n.id, `${n.name} · ${titleCase(n.type)} · ${n.arn || n.id}`)));
    if (matches.length) $('global-options').selectedIndex = 0;
    $('global-open').disabled = !matches.length;
  });
  function openGlobal() { const id = $('global-options').value; if (id) { openNode(id); $('global-results').hidden = true; $('global-search').value = ''; } }
  $('global-open').addEventListener('click', openGlobal); $('global-options').addEventListener('dblclick', openGlobal);
  $('global-options').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); openGlobal(); } });
  $('global-search').addEventListener('keydown', e => { if (e.key === 'ArrowDown') { e.preventDefault(); $('global-options').focus(); } if (e.key === 'Enter') { e.preventDefault(); openGlobal(); } });
  document.addEventListener('keydown', e => {
    if (e.key === '/' && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)) { e.preventDefault(); $('global-search').focus(); }
    if (e.key === 'Escape') { $('global-results').hidden = true; document.body.classList.remove('nav-open'); }
  });
  document.addEventListener('click', e => { if (!e.target.closest('.global-search')) $('global-results').hidden = true; });
}

main().catch(error => { $('loading').hidden = true; $('app-error').hidden = false; $('app-error').textContent = `Viewer error: ${error.message}`; });
