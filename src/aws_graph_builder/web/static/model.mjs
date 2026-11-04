export const ATTACK_TYPES = new Set(['CanAssume', 'PrivescPath']);
export const DEFAULT_FILTERS = {direction: 'both', relationship: 'all', showAws: false, showPermissions: false, nodeType: ''};
export const titleCase = value => String(value || '').replace(/([a-z])([A-Z])/g, '$1 $2').replaceAll('_', ' ');
export const isAwsDefault = node => node.type === 'ServicePrincipal' || (node.arn || '').startsWith('arn:aws:iam::aws:policy/') || (node.arn || '').includes(':role/aws-service-role/');
export const isPrincipal = node => ['IamUser', 'IamRole'].includes(node.type);

export class GraphModel {
  constructor(data, findings) {
    this.nodes = new Map(data.nodes.map(node => [node.id, node]));
    this.edges = new Map(data.edges.map(edge => [edge.id, edge]));
    this.findings = findings;
    this.incident = new Map(data.nodes.map(n => [n.id, []]));
    for (const edge of data.edges) {
      this.incident.get(edge.source)?.push(edge);
      if (edge.target !== edge.source) this.incident.get(edge.target)?.push(edge);
    }
  }
  name(id) { return this.nodes.get(id)?.name || id; }
  search(query = '', principalsOnly = false) {
    const q = query.trim().toLowerCase();
    return [...this.nodes.values()].filter(n => (!principalsOnly || isPrincipal(n)) &&
      `${n.name} ${n.arn || ''} ${n.type}`.toLowerCase().includes(q))
      .sort((a, b) => Number(!!b.high_value) - Number(!!a.high_value) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  }
  allowed(edge, filters = {}) {
    const f = {...DEFAULT_FILTERS, ...filters};
    if (f.relationship === 'attack' && !ATTACK_TYPES.has(edge.type)) return false;
    if (!f.showPermissions && edge.type === 'EffectivePermission') return false;
    return [edge.source, edge.target].every(id => {
      const node = this.nodes.get(id);
      return node && (f.showAws || !isAwsDefault(node));
    });
  }
  neighborhood(id, filters = {}) {
    const f = {...DEFAULT_FILTERS, ...filters};
    const edges = (this.incident.get(id) || []).filter(e => this.allowed(e, f) &&
      (f.direction !== 'out' || e.source === id) && (f.direction !== 'in' || e.target === id) &&
      (!f.nodeType || this.nodes.get(e.source === id ? e.target : e.source)?.type === f.nodeType));
    return {kind: 'explore', title: this.name(id), root: id, filters: f,
      nodeIds: [...new Set([id, ...edges.flatMap(e => [e.source, e.target])])], edgeIds: edges.map(e => e.id)};
  }
  overview(filters = {}) {
    const f = {...DEFAULT_FILTERS, ...filters};
    const nodes = [...this.nodes.values()].filter(n => (f.showAws || !isAwsDefault(n)) && (!f.nodeType || n.type === f.nodeType));
    const ids = new Set(nodes.map(n => n.id));
    return {kind: 'overview', title: 'Account overview', filters: f, nodeIds: [...ids],
      edgeIds: [...this.edges.values()].filter(e => ids.has(e.source) && ids.has(e.target) && this.allowed(e, f)).map(e => e.id)};
  }
  findingView(finding) {
    const wanted = [...new Set([finding.edge_id, ...(finding.evidence_edges || [])])];
    const edges = wanted.map(id => this.edges.get(id)).filter(Boolean);
    return {kind: 'finding', title: titleCase(finding.technique_id), finding,
      nodeIds: [...new Set([finding.source, finding.target, ...edges.flatMap(e => [e.source, e.target])])],
      edgeIds: edges.map(e => e.id), missingEvidence: wanted.filter(id => !this.edges.has(id))};
  }
  filterFindings(filters = {}) {
    const q = (filters.query || '').toLowerCase();
    const rank = {critical: 0, high: 1, medium: 2, low: 3};
    return this.findings.filter(f => (!filters.severity || f.severity === filters.severity) &&
      (!filters.technique || f.technique_id === filters.technique) && (!filters.source || f.source === filters.source) &&
      (!filters.target || f.target === filters.target) &&
      (!filters.related || f.source === filters.related || f.target === filters.related) &&
      (filters.sourceAccess !== 'ordinary' || !this.nodes.get(f.source)?.high_value) &&
      (filters.sourceAccess !== 'high_value' || this.nodes.get(f.source)?.high_value) &&
      `${f.technique_id} ${f.description} ${this.name(f.source)} ${this.name(f.target)}`.toLowerCase().includes(q))
      .sort((a, b) => (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4) || a.technique_id.localeCompare(b.technique_id));
  }
}

export function summarizeEdges(edges) {
  const grouped = new Map();
  for (const e of edges) {
    const key = JSON.stringify([e.source, e.target]);
    if (!grouped.has(key)) grouped.set(key, {id: `connection:${key}`, source: e.source, target: e.target, type: e.type, edgeIds: [], condition_unresolved: false});
    const group = grouped.get(key);
    group.edgeIds.push(e.id);
    group.condition_unresolved ||= !!e.condition_unresolved;
    if (e.type === 'PrivescPath' || (e.type === 'CanAssume' && group.type !== 'PrivescPath')) group.type = e.type;
  }
  return [...grouped.values()];
}

export class Investigation {
  constructor() {
    this.view = {kind: 'landing', title: 'Start an investigation', nodeIds: [], edgeIds: [], filters: {...DEFAULT_FILTERS}};
    this.history = [];
    this.hidden = new Set();
    this.selection = null;
  }
  navigate(view) {
    this.history.push(structuredClone(this.view));
    this.view = structuredClone(view);
    this.selection = null;
  }
  back() {
    if (this.history.length) this.view = this.history.pop();
    this.selection = null;
  }
  select(selection) { this.selection = selection; }
  visibleNodeIds() {
    const focused = ['route', 'finding'].includes(this.view.kind);
    return this.view.nodeIds.filter(id => focused || !this.hidden.has(id));
  }
}
