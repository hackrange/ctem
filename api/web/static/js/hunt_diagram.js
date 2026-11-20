// Incident flow: one lane per source, steps left to right, arrows follow the story
const FLOW_COLORS = ['#e05252', '#e8913a', '#3a8ee8', '#3aa76d', '#9b59b6', '#7f8c8d'];
const _e = s => (typeof esc === 'function' ? esc(s) : String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));

function _wrap(text, width, lines) {
  const words = String(text || '').split(/\s+/);
  const out = [''];
  for (const w of words) {
    const cur = out[out.length - 1];
    if ((cur + ' ' + w).trim().length <= width) out[out.length - 1] = (cur + ' ' + w).trim();
    else if (out.length < lines) out.push(w);
    else { out[out.length - 1] = cur.replace(/.{0,3}$/, '...'); break; }
  }
  return out;
}

function flowDiagram(timeline) {
  const steps = (timeline || []).filter(t => t && t.what);
  if (!steps.length) return '';
  const lanes = [];
  steps.forEach(s => { const k = s.source || 'Other'; if (!lanes.includes(k)) lanes.push(k); });
  const W = 190, H = 64, GAP = 40, LANE = 92, LEFT = 130, TOP = 16;
  const width = LEFT + steps.length * (W + GAP);
  const height = TOP + lanes.length * LANE;
  const pos = steps.map((s, i) => ({ x: LEFT + i * (W + GAP), y: TOP + lanes.indexOf(s.source || 'Other') * LANE + (LANE - H) / 2 - 6 }));
  const bands = lanes.map((l, j) => `<rect x="0" y="${TOP + j * LANE - 6}" width="${width}" height="${LANE}" fill="${FLOW_COLORS[j % 6]}" opacity="0.06"/>
    <text x="8" y="${TOP + j * LANE + LANE / 2 - 2}" font-size="12" font-weight="700" fill="${FLOW_COLORS[j % 6]}">${_e(_wrap(l, 16, 1)[0])}</text>`).join('');
  const arrows = pos.slice(1).map((p, i) => {
    const a = pos[i], x1 = a.x + W, y1 = a.y + H / 2, x2 = p.x - 4, y2 = p.y + H / 2, mid = (x1 + x2) / 2;
    return `<path d="M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}" fill="none" stroke="currentColor" stroke-opacity="0.45" stroke-width="1.6" marker-end="url(#flow-arrow)"/>`;
  }).join('');
  const nodes = steps.map((s, i) => {
    const { x, y } = pos[i], color = FLOW_COLORS[lanes.indexOf(s.source || 'Other') % 6];
    const lines = _wrap(s.what, 30, 2);
    return `<g><title>${_e(s.time)} - ${_e(s.source)}: ${_e(s.what)}</title>
      <rect x="${x}" y="${y}" width="${W}" height="${H}" rx="8" fill="${color}" fill-opacity="0.14" stroke="${color}" stroke-width="1.5"/>
      <text x="${x + 10}" y="${y + 16}" font-size="10.5" font-weight="700" fill="${color}">${i + 1}. ${_e(String(s.time || '').slice(5, 16))}</text>
      ${lines.map((l, k) => `<text x="${x + 10}" y="${y + 33 + k * 14}" font-size="11" fill="currentColor">${_e(l)}</text>`).join('')}</g>`;
  }).join('');
  return `<div class="flow-wrap"><svg class="flow-svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="How the incident unfolded">
    <defs><marker id="flow-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
    ${bands}${arrows}${nodes}</svg></div>`;
}
