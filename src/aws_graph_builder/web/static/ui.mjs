export const $ = id => document.getElementById(id);
export function el(tag, className = '', text = '') {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== '' && text != null) node.textContent = String(text);
  return node;
}
export function button(text, action, className = 'button') {
  const node = el('button', className, text);
  node.type = 'button';
  node.addEventListener('click', action);
  return node;
}
export function badge(text, kind = '') { return el('span', `badge ${kind}`, text); }
export function field(label, value) {
  const node = el('div', 'detail-field');
  node.append(el('dt', '', label), el('dd', '', value ?? '—'));
  return node;
}
export function message(container, text, kind = '') { container.replaceChildren(el('p', `message ${kind}`, text)); }
export function option(value, text) {
  const node = el('option', '', text);
  node.value = value;
  return node;
}
