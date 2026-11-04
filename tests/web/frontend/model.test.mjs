import test from 'node:test';
import assert from 'node:assert/strict';
import { GraphModel, Investigation, summarizeEdges } from '../../../src/aws_graph_builder/web/static/model.mjs';
import { LatestRequest } from '../../../src/aws_graph_builder/web/static/api.mjs';

const data = {
  nodes: [
    {id: 'a', name: 'Alice', type: 'IamUser', arn: 'arn:user/alice'},
    {id: 'b', name: 'Deploy', type: 'IamRole', arn: 'arn:role/deploy', high_value: true},
    {id: 'p', name: 'AWS policy', type: 'ManagedPolicy', arn: 'arn:aws:iam::aws:policy/Admin'},
  ],
  edges: [
    {id: 'ab', source: 'a', target: 'b', type: 'CanAssume'},
    {id: 'ab2', source: 'a', target: 'b', type: 'PrivescPath'},
    {id: 'ap', source: 'a', target: 'p', type: 'AttachedPolicy'},
    {id: 'aa', source: 'a', target: 'a', type: 'EffectivePermission'},
  ],
};
test('search resolves names, ARNs and types, with principal-only filtering', () => {
  const graph = new GraphModel(data, []);
  assert.deepEqual(graph.search('role/deploy').map(n => n.id), ['b']);
  assert.deepEqual(graph.search('iamuser').map(n => n.id), ['a']);
  assert.deepEqual(graph.search('policy', true), []);
});
test('neighborhood applies direction, attack and AWS default filters', () => {
  const graph = new GraphModel(data, []);
  assert.deepEqual(graph.neighborhood('a', {relationship: 'attack'}).edgeIds, ['ab', 'ab2']);
  assert.deepEqual(graph.neighborhood('b', {direction: 'out'}).edgeIds, []);
  assert.deepEqual(graph.neighborhood('a', {showAws: true, showPermissions: true}).edgeIds, ['ab', 'ab2', 'ap', 'aa']);
});
test('finding focus includes self-targeting edges and all evidence endpoints', () => {
  const graph = new GraphModel(data, []);
  const view = graph.findingView({source: 'a', target: 'a', edge_id: 'aa', evidence_edges: ['ap', 'missing'], technique_id: 'self'});
  assert.deepEqual(new Set(view.nodeIds), new Set(['a', 'p']));
  assert.deepEqual(view.edgeIds, ['aa', 'ap']);
  assert.deepEqual(view.missingEvidence, ['missing']);
});
test('inspection preserves view and Back restores positions, filters and viewport', () => {
  const store = new Investigation();
  store.navigate({kind: 'explore', nodeIds: ['a', 'b'], edgeIds: ['ab'], filters: {showAws: true}, positions: {a: {x: 12, y: 8}}, viewport: {zoom: 1.2, pan: {x: 2, y: 3}}});
  store.hidden.add('b');
  store.navigate({kind: 'route', nodeIds: ['a', 'b'], edgeIds: ['ab']});
  store.select({kind: 'node', id: 'a'});
  assert.equal(store.view.kind, 'route');
  assert.deepEqual(store.visibleNodeIds(), ['a', 'b']);
  store.back();
  assert.deepEqual(store.visibleNodeIds(), ['a']);
  assert.deepEqual(store.view.positions.a, {x: 12, y: 8});
  assert.equal(store.view.viewport.zoom, 1.2);
  assert.equal(store.view.filters.showAws, true);
});
test('parallel relationships collapse by directed pair without losing evidence', () => {
  const result = summarizeEdges(data.edges.slice(0, 2));
  assert.equal(result.length, 1);
  assert.deepEqual(result[0].edgeIds, ['ab', 'ab2']);
  assert.equal(result[0].type, 'PrivescPath');
});
test('finding filters combine severity, source, target and privileged source', () => {
  const findings = [
    {source: 'a', target: 'b', severity: 'high', technique_id: 'key', description: 'Create a key'},
    {source: 'b', target: 'a', severity: 'critical', technique_id: 'attach', description: 'Attach'},
  ];
  const graph = new GraphModel(data, findings);
  assert.equal(graph.filterFindings({severity: 'high', source: 'a', target: 'b'}).length, 1);
  assert.equal(graph.filterFindings({sourceAccess: 'ordinary'})[0].source, 'a');
  assert.equal(graph.filterFindings({query: 'attach', sourceAccess: 'high_value'})[0].source, 'b');
  assert.equal(graph.filterFindings({related: 'b'}).length, 2);
  assert.equal(graph.filterFindings({related: 'p'}).length, 0);
});
test('new request invalidates pending detail even when selection is cleared', () => {
  const gate = new LatestRequest();
  const old = gate.begin();
  const current = gate.begin();
  assert.equal(old.signal.aborted, true);
  assert.equal(gate.valid(old), false);
  assert.equal(gate.valid(current), true);
  gate.cancel();
  assert.equal(gate.valid(current), false);
});
