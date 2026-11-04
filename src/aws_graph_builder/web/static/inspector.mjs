import {get, LatestRequest} from './api.mjs';
import {titleCase} from './model.mjs';
import {$, el, button, badge, field, message} from './ui.mjs';

export class Inspector {
  constructor(model, actions) {
    this.model = model;
    this.actions = actions;
    this.gate = new LatestRequest();
    $('inspector-close').addEventListener('click', () => this.close());
    const handle = $('inspector-resize');
    handle.addEventListener('pointerdown', event => {
      handle.setPointerCapture(event.pointerId);
      const move = e => { $('inspector').style.width = `${Math.max(280, Math.min(innerWidth * 0.48, innerWidth - e.clientX))}px`; };
      const end = () => { handle.removeEventListener('pointermove', move); handle.removeEventListener('pointerup', end); };
      handle.addEventListener('pointermove', move);
      handle.addEventListener('pointerup', end);
    });
    handle.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
      event.preventDefault();
      $('inspector').style.width = `${Math.max(280, Math.min(innerWidth * 0.48, $('inspector').offsetWidth + (event.key === 'ArrowLeft' ? 20 : -20)))}px`;
    });
  }
  close() { this.gate.cancel(); $('inspector').hidden = true; this.actions.clearSelection?.(); }
  shell(name, kind, icon = '◇') {
    this.gate.cancel();
    $('inspector').hidden = false;
    const root = $('inspector-content');
    const hero = el('div', 'inspector-hero');
    hero.append(el('div', 'entity-icon', icon), el('span', 'eyebrow', kind), el('h2', '', name));
    root.replaceChildren(hero);
    return {root, hero};
  }
  tabs(root) {
    const nav = el('div', 'inspector-tabs');
    const detail = el('div');
    const raw = el('pre', 'json-block');
    raw.hidden = true;
    const detailBtn = button('Details', () => activate(false), 'active');
    const rawBtn = button('Raw JSON', () => activate(true), '');
    const activate = isRaw => {
      detail.hidden = isRaw; raw.hidden = !isRaw;
      detailBtn.classList.toggle('active', !isRaw); rawBtn.classList.toggle('active', isRaw);
    };
    nav.append(detailBtn, rawBtn);
    root.append(nav, detail, raw);
    return {detail, raw};
  }
  async show(selection) {
    if (!selection) { this.close(); return; }
    if (selection.kind === 'finding') { this.finding(selection.finding); return; }
    if (selection.kind === 'route') { this.route(selection.path, selection.mode); return; }
    if (selection.kind === 'coverage') { this.coverage(selection.coverage, selection.metadata); return; }
    if (selection.kind === 'node') { await this.node(selection.id); return; }
    if (selection.kind === 'connection') await this.connection(selection.edgeIds);
  }
  async node(id) {
    const node = this.model.nodes.get(id);
    if (!node) return;
    const {root, hero} = this.shell(node.name, titleCase(node.type), node.type === 'IamUser' ? '○' : '◇');
    if (node.high_value) hero.append(badge('★ High-value access', 'high-value'));
    const actions = el('div', 'inspector-actions');
    actions.append(
      button('Expand connections', () => this.actions.expand(id)),
      button('Paths to high-value', () => this.actions.paths(id)),
      button('Use as source', () => this.actions.source(id)),
      button('Use as target', () => this.actions.target(id)),
      button('Hide node', () => this.actions.hide(id)),
      button('Copy ARN', async event => {
        const control = event.currentTarget;
        try { await navigator.clipboard.writeText(node.arn || id); control.textContent = 'Copied'; }
        catch { control.textContent = 'Copy unavailable'; }
      }),
    );
    root.append(actions);
    const {detail, raw} = this.tabs(root);
    const fields = el('dl');
    fields.append(field('Type', titleCase(node.type)), field('ARN / identifier', node.arn || id));
    detail.append(fields);
    const related = this.model.findings.filter(f => f.source === id || f.target === id);
    if (related.length) detail.append(button(`Review ${related.length} related findings →`, () => this.actions.findings(id), 'button wide'));
    const list = el('section', 'detail-section');
    list.append(el('h3', '', 'CONNECTIONS'));
    const connections = new Map();
    for (const edge of this.model.incident.get(id) || []) {
      const other = edge.source === id ? edge.target : edge.source;
      if (!connections.has(other)) connections.set(other, []);
      connections.get(other).push(edge);
    }
    for (const [other, edges] of [...connections].slice(0, 40)) {
      const b = button(this.model.name(other), () => this.actions.inspect({kind: 'node', id: other}), 'evidence-button');
      b.append(el('small', '', `${edges.length} relationship${edges.length === 1 ? '' : 's'} · ${titleCase(this.model.nodes.get(other)?.type)}`));
      list.append(b);
    }
    if (connections.size > 40) list.append(el('p', 'small muted', `Showing 40 of ${connections.size} connections. Expand to choose more.`));
    detail.append(list);
    const properties = el('section', 'detail-section');
    detail.append(properties);
    message(properties, 'Loading full properties…');
    await this.load('/api/node', id, raw, full => this.properties(properties, full.properties));
  }
  async connection(ids) {
    const edges = ids.map(id => this.model.edges.get(id)).filter(Boolean);
    if (!edges.length) { this.shell('Evidence unavailable', 'RELATIONSHIP'); return; }
    const {root, hero} = this.shell(edges.length > 1 ? `${edges.length} relationship alternatives` : titleCase(edges[0].type), 'RELATIONSHIP', '→');
    hero.append(el('p', '', `${this.model.name(edges[0].source)} → ${this.model.name(edges[0].target)}`));
    if (edges.some(e => e.condition_unresolved)) root.append(el('p', 'notice warning', 'Unresolved conditions: this relationship may depend on request context that was unavailable during analysis.'));
    const {detail, raw} = this.tabs(root);
    const ticket = this.gate.begin();
    raw.textContent = 'Loading…';
    const fullEdges = [];
    for (const edge of edges) {
      const section = el('section', 'detail-section');
      section.append(el('h3', '', titleCase(edge.technique_id || edge.type)));
      if (edge.condition_unresolved) section.append(badge('Conditional / unresolved', 'warning'));
      detail.append(section);
      try {
        const full = await get('/api/edge', {id: edge.id}, ticket.signal);
        if (!this.gate.valid(ticket)) return;
        fullEdges.push(full);
        this.edgeProperties(section, full);
      } catch (err) {
        if (!this.gate.valid(ticket)) return;
        section.append(el('p', 'message error', `Evidence unavailable: ${err.message}`));
      }
    }
    if (this.gate.valid(ticket)) raw.textContent = JSON.stringify(fullEdges.length === 1 ? fullEdges[0] : fullEdges, null, 2);
  }
  edgeProperties(section, full) {
    const p = full.properties || {};
    const fields = el('dl');
    if (p.description) fields.append(field('Explanation', p.description));
    if (p.actions) fields.append(field('Actions', p.actions.join(', ')));
    if (p.resource_pattern) fields.append(field('Resource scope', p.resource_pattern));
    if (p.required_permissions) fields.append(field('Required permissions', p.required_permissions.join(', ')));
    if (p.requires_mfa) fields.append(field('Trust requirement', 'MFA required'));
    if (p.external_id_required) fields.append(field('Trust requirement', 'External ID required'));
    section.append(fields);
    if (p.evidence_edges?.length) this.evidence(section, p.evidence_edges);
    const evidenceEntries = p.evaluated_from || p.evidence;
    if (evidenceEntries) {
      const evidence = el('section', 'detail-section');
      evidence.append(el('h3', '', 'POLICY EVIDENCE'));
      const entries = Array.isArray(evidenceEntries) ? evidenceEntries : [evidenceEntries];
      for (const entry of entries) {
        const reference = entry.policy || entry.policy_node_id || entry.policy_arn || entry.policy_id;
        let policyId = reference;
        if (reference?.startsWith('inline:')) {
          const [owner, ...name] = reference.slice(7).split('#');
          policyId = `${owner}#inline/${name.join('#')}`;
        } else policyId = reference?.replace(/^(boundary|trust|resource):/, '');
        const block = el('div');
        if (policyId && this.model.nodes.has(policyId)) {
          block.append(button(`Open ${this.model.name(policyId)}`, () => this.actions.inspect({kind: 'node', id: policyId}), 'evidence-button'));
          const detail = el('details', 'detail-section');
          detail.append(el('summary', '', entry.sid ? `Statement: ${entry.sid}` : 'View originating policy statements'));
          const content = el('div'); detail.append(content);
          const ticket = this.gate.ticket;
          detail.addEventListener('toggle', async () => {
            if (!detail.open || content.childNodes.length) return;
            content.append(el('p', 'small muted', 'Loading policy evidence…'));
            try {
              const policy = await get('/api/node', {id: policyId}, ticket?.signal);
              if (!this.gate.valid(ticket)) return;
              const props = policy.properties || {};
              const doc = props.policy_document || props.AssumeRolePolicyDocument || props.resource_policy || props.bucket_policy;
              if (!doc) { message(content, 'Policy statement unavailable in this scan.'); return; }
              const statements = Array.isArray(doc.Statement) ? doc.Statement : doc.Statement ? [doc.Statement] : [];
              const matched = entry.sid ? statements.filter(s => s.Sid === entry.sid) : statements;
              if (!matched.length) { message(content, 'Referenced statement unavailable in this scan.'); return; }
              content.replaceChildren(el('p', 'small muted', entry.sid ? 'Matched by statement ID.' : 'No statement ID recorded; showing policy statements for review.'), el('pre', 'json-block', JSON.stringify(matched, null, 2)));
            } catch (err) { if (this.gate.valid(ticket)) message(content, `Evidence unavailable: ${err.message}`, 'error'); }
          });
          block.append(detail);
        } else block.append(el('p', 'message', `Originating policy unavailable: ${reference || 'no policy reference'}`));
        block.append(el('pre', 'json-block', JSON.stringify(entry, null, 2)));
        evidence.append(block);
      }
      section.append(evidence);
    }
    const other = Object.fromEntries(Object.entries(p).filter(([k]) => !['description','actions','resource_pattern','required_permissions','evidence','evaluated_from','evidence_edges'].includes(k)));
    if (Object.keys(other).length) {
      const properties = el('section', 'detail-section');
      this.properties(properties, other);
      section.append(properties);
    }
  }
  finding(finding) {
    const {root, hero} = this.shell(titleCase(finding.technique_id), 'DETECTED TECHNIQUE', '↗');
    hero.append(badge(finding.severity, finding.severity));
    const {detail, raw} = this.tabs(root);
    raw.textContent = JSON.stringify(finding, null, 2);
    detail.append(el('p', 'notice', finding.description));
    const fields = el('dl');
    fields.append(field('From', this.model.name(finding.source)), field('To', this.model.name(finding.target)),
      field('Required permissions', (finding.required_permissions || []).join(', ')));
    detail.append(fields);
    this.evidence(detail, [finding.edge_id, ...(finding.evidence_edges || [])]);
    detail.append(el('p', 'small muted', 'A detected technique is based on static policy analysis. Review policy conditions and evidence before drawing conclusions.'));
  }
  route(path, mode) {
    const {root, hero} = this.shell(`${path.hops.length} hop${path.hops.length === 1 ? '' : 's'} to target`, mode === 'reachability' ? 'STRUCTURAL REACHABILITY' : 'ATTACK PATH', '⇢');
    hero.append(el('p', '', `${this.model.name(path.nodes[0])} → ${this.model.name(path.nodes.at(-1))}`));
    const {detail, raw} = this.tabs(root);
    raw.textContent = JSON.stringify(path, null, 2);
    for (const [index, hop] of path.hops.entries()) {
      const b = button(`${index + 1}. ${this.model.name(hop.source)} → ${this.model.name(hop.target)}`, () => this.actions.inspect({kind: 'connection', edgeIds: hop.edge_ids}), 'hop-button');
      const edges = hop.edge_ids.map(id => this.model.edges.get(id)).filter(Boolean);
      b.append(el('small', '', edges.map(e => titleCase(e.technique_id || e.type)).join(' · ')));
      if (edges.some(e => e.condition_unresolved)) b.append(badge('Unresolved condition', 'warning'));
      detail.append(b);
    }
    detail.append(el('h3', 'detail-section', 'NODES ON THIS PATH'));
    for (const id of path.nodes) detail.append(button(this.model.name(id), () => this.actions.inspect({kind: 'node', id}), 'evidence-button'));
  }
  evidence(container, ids) {
    const section = el('section', 'detail-section');
    section.append(el('h3', '', 'SUPPORTING RELATIONSHIPS'));
    for (const id of [...new Set(ids)]) {
      const edge = this.model.edges.get(id);
      if (!edge) { section.append(el('p', 'notice warning', `Evidence unavailable: ${id}`)); continue; }
      const b = button(titleCase(edge.technique_id || edge.type), () => this.actions.inspect({kind: 'connection', edgeIds: [id]}), 'evidence-button');
      b.append(el('small', '', `${this.model.name(edge.source)} → ${this.model.name(edge.target)}`));
      if (edge.condition_unresolved) b.append(badge('Unresolved condition', 'warning'));
      section.append(b);
    }
    container.append(section);
  }
  properties(container, properties = {}) {
    container.replaceChildren(el('h3', '', 'PROPERTIES'));
    for (const [key, value] of Object.entries(properties)) {
      if (typeof value === 'object' && value !== null) {
        const block = el('details', 'detail-section');
        block.append(el('summary', '', titleCase(key)), el('pre', 'json-block', JSON.stringify(value, null, 2)));
        container.append(block);
      } else {
        const row = el('div', 'property-row');
        row.append(el('span', '', titleCase(key)), el('span', '', String(value ?? '—')));
        container.append(row);
      }
    }
    if (!Object.keys(properties).length) container.append(el('p', 'message', 'No additional properties.'));
  }
  async load(endpoint, id, raw, display) {
    const ticket = this.gate.begin();
    try {
      const full = await get(endpoint, {id}, ticket.signal);
      if (!this.gate.valid(ticket)) return;
      raw.textContent = JSON.stringify(full, null, 2);
      display(full);
    } catch (err) {
      if (this.gate.valid(ticket)) { raw.textContent = `Detail unavailable: ${err.message}`; raw.hidden = false; }
    }
  }
  coverage(coverage, metadata) {
    const {root} = this.shell('Scan coverage', 'ACCOUNT CONTEXT', '◎');
    const {detail, raw} = this.tabs(root);
    raw.textContent = JSON.stringify({metadata, coverage}, null, 2);
    const fields = el('dl');
    fields.append(field('Account', metadata.account_id), field('Generated', metadata.generated_at),
      field('Regions scanned', (metadata.regions_scanned || []).join(', ')), field('Coverage', coverage.status));
    detail.append(fields);
    if (coverage.status === 'unknown') detail.append(el('p', 'notice warning', 'No readable companion report was available. Coverage is unknown.'));
    else if (!coverage.gaps.length) detail.append(el('p', 'notice', 'No scan gaps were reported. Policy evaluation still has documented static-analysis limitations.'));
    for (const gap of coverage.gaps) {
      detail.append(el('h3', 'detail-section', `${gap.service} · ${gap.operation || gap.error_code}`), el('pre', 'json-block', JSON.stringify(gap, null, 2)));
    }
  }
}
