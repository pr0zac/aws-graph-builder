import {summarizeEdges, titleCase} from './model.mjs';

const category = type => ['ManagedPolicy', 'InlinePolicy', 'ServiceControlPolicy'].includes(type) ? 'policy' :
  ['IamUser', 'IamRole', 'IamGroup', 'ExternalPrincipal', 'ServicePrincipal'].includes(type) ? 'identity' : 'resource';
export class GraphView {
  constructor(container, model, onSelect, onSelection) {
    this.model = model;
    this.cy = cytoscape({container, elements: [], layout: {name: 'preset'}, minZoom: 0.12, maxZoom: 2.5,
      wheelSensitivity: 0.2, style: this.styles()});
    this.cy.on('tap', 'node', e => onSelect({kind: 'node', id: e.target.id()}));
    this.cy.on('tap', 'edge', e => onSelect({kind: 'connection', edgeIds: e.target.data('edgeIds')}));
    this.cy.on('tap', e => { if (e.target === this.cy) onSelect(null); });
    this.cy.on('select unselect', () => onSelection(this.cy.nodes(':selected').map(n => n.id())));
    let size = {width: container.clientWidth, height: container.clientHeight};
    new ResizeObserver(() => {
      if (this.cy.destroyed()) return;
      const next = {width: container.clientWidth, height: container.clientHeight};
      const pan = this.cy.pan();
      this.cy.resize();
      this.cy.pan({x: pan.x + (next.width - size.width) / 2, y: pan.y + (next.height - size.height) / 2});
      size = next;
    }).observe(container);
  }
  token(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  styles() {
    const color = name => this.token(name);
    return [
      {selector: 'node', style: {width: 42, height: 42, 'background-color': color('--node-bg'),
        'border-color': color('--accent'), 'border-width': 1.7, label: 'data(label)', 'font-size': 11,
        'font-family': 'system-ui', color: color('--ink'), 'text-valign': 'bottom', 'text-margin-y': 9,
        'text-wrap': 'ellipsis', 'text-max-width': 155, 'min-zoomed-font-size': 7}},
      {selector: 'node[category = "policy"]', style: {'border-color': color('--purple'), shape: 'round-rectangle'}},
      {selector: 'node[category = "resource"]', style: {'border-color': color('--blue'), shape: 'round-rectangle'}},
      {selector: 'node[type = "IamRole"]', style: {shape: 'round-rectangle'}},
      {selector: 'node[?high_value]', style: {'border-color': color('--gold'), 'border-width': 3,
        'underlay-color': color('--gold'), 'underlay-opacity': 0.13, 'underlay-padding': 7}},
      {selector: 'node:selected', style: {'background-color': color('--accent-soft'), 'border-width': 3}},
      {selector: 'edge', style: {'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'arrow-scale': 0.8,
        width: 1.4, 'line-color': color('--line'), 'target-arrow-color': color('--line'), label: 'data(label)',
        'font-size': 9, color: color('--muted'), 'text-background-color': color('--canvas'),
        'text-background-opacity': 1, 'text-background-padding': 4, 'text-rotation': 'autorotate',
        'min-zoomed-font-size': 7}},
      {selector: 'edge[type = "PrivescPath"]', style: {'line-color': color('--danger'), 'target-arrow-color': color('--danger'), width: 2}},
      {selector: 'edge[type = "CanAssume"]', style: {'line-color': color('--accent'), 'target-arrow-color': color('--accent'), width: 1.8}},
      {selector: 'edge[?uncertain]', style: {'line-style': 'dashed'}},
      {selector: 'edge:selected', style: {width: 4, 'line-color': color('--accent'), 'target-arrow-color': color('--accent')}},
    ];
  }
  snapshot() {
    return {positions: Object.fromEntries(this.cy.nodes().map(n => [n.id(), {...n.position()}])),
      viewport: {pan: {...this.cy.pan()}, zoom: this.cy.zoom()}};
  }
  render(view, hidden = new Set()) {
    const focused = ['finding', 'route'].includes(view.kind);
    const ids = new Set(view.nodeIds.filter(id => this.model.nodes.has(id) && (focused || !hidden.has(id))));
    const edges = summarizeEdges(view.edgeIds.map(id => this.model.edges.get(id)).filter(e => e && ids.has(e.source) && ids.has(e.target)));
    const old = this.snapshot().positions;
    const positions = view.positions || old;
    const rootPos = positions[view.root] || {x: 0, y: 0};
    const nodeIds = [...ids];
    const elements = nodeIds.map((id, index) => {
      const node = this.model.nodes.get(id);
      let position = positions[id];
      if (view.kind === 'route' && view.routeOrder && !view.positions) {
        position = {x: view.routeOrder.indexOf(id) * 260, y: 100};
      }
      if (!position) {
        const angle = index * Math.PI * 2 / Math.max(nodeIds.length, 1);
        const radius = 170 + Math.floor(index / 12) * 110;
        position = id === view.root ? rootPos : {x: rootPos.x + Math.cos(angle) * radius, y: rootPos.y + Math.sin(angle) * radius};
      }
      return {group: 'nodes', data: {...node, category: category(node.type), label: `${node.high_value ? '★ ' : ''}${node.name}`}, position};
    });
    elements.push(...edges.map(edge => ({group: 'edges', data: {...edge,
      uncertain: edge.condition_unresolved, label: ids.size > 30 ? '' :
        edge.edgeIds.length > 1 ? `${edge.edgeIds.length} relationships` : titleCase(edge.type)}})));
    this.cy.elements().remove();
    this.cy.add(elements);
    if (view.viewport) this.cy.viewport(view.viewport);
    else this.fit();
  }
  fit() {
    if (!this.cy.nodes().length) return;
    this.cy.fit(undefined, 85);
    if (this.cy.zoom() > 1.35) this.cy.zoom({level: 1.35, renderedPosition: {x: this.cy.width() / 2, y: this.cy.height() / 2}});
  }
  layout() {
    this.cy.layout({name: 'cose', animate: false, fit: false, nodeRepulsion: 100000, idealEdgeLength: 140, gravity: 10, numIter: 600}).run();
    this.fit();
  }
  theme() { this.cy.style(this.styles()); }
  selected() { return this.cy.nodes(':selected').map(n => n.id()); }
}
