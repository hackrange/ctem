// An interactive attack map (laid out on the server by api/core/attack_map.py): click a box to follow its path (what
// led to it, and what it led to next) and read its details; drag to pan; wheel or +/- to zoom. Used by the alert page and
// Threat Hunt findings. AttackMap.mount(el) fills `el` and returns { draw(graph), follow(id), clear() }.
// Everything shown goes through esc().
window.AttackMap = (() => {
  const NS = 'http://www.w3.org/2000/svg';
  const COLOR = { host: '#3a8ee8', user: '#e8913a', process: '#4a5568', detection: '#e05252', action: '#3aa76d', quarantine: '#e05252',
                  indicator: '#9b59b6', file: '#e8913a', network: '#e8913a', dns: '#e8913a', event: '#4a5568', alert: '#e05252',
                  log: '#3a8ee8', ip: '#e8913a' };
  const GLYPH = { host: '\u{1F5A5}', user: '\u{1F464}', process: '</>', detection: '!', action: '\u{1F6E1}', quarantine: '\u{1F512}',
                  indicator: '⚠', file: '\u{1F4C4}', network: '\u{1F310}', dns: '\u{1F50D}', event: '▶', alert: '!',
                  log: '≡', ip: '\u{1F310}' };
  const KIND = { host: 'Host', user: 'User', process: 'Process', detection: 'Detection', action: 'What the EDR did',
                 quarantine: 'Quarantined file', indicator: 'Indicator', file: 'File', network: 'Connection', dns: 'DNS lookup',
                 event: 'Step', alert: 'Alert', log: 'Log event', ip: 'Address' };
  const R = 20;
  const cut = (s, n) => { s = String(s || ''); return s.length > n ? `${s.slice(0, n - 1)}…` : s; };

  function el(name, attrs, parent) {
    const e = document.createElementNS(NS, name);
    Object.entries(attrs || {}).forEach(([k, v]) => e.setAttribute(k, v));
    if (parent) parent.appendChild(e);
    return e;
  }
  function text(parent, x, y, s, cls, style) {
    const t = el('text', { x, y, 'text-anchor': 'middle', class: cls || '' }, parent);
    if (style) t.setAttribute('style', style);
    t.textContent = s;
    return t;
  }

  function mount(root, onPick) {
    root.classList.add('agp__map');
    root.innerHTML = `<svg role="img" aria-label="Attack map"></svg><div class="agp__info" style="display:none"></div>
      <div class="agp__zoom"><button type="button" data-z="in" aria-label="Zoom in">+</button>
        <button type="button" data-z="out" aria-label="Zoom out">&minus;</button><button type="button" data-z="fit" aria-label="Fit to view">&#x26F6;</button></div>`;
    const svg = root.querySelector('svg'), info = root.querySelector('.agp__info');
    let graph = null, view = null, full = null, drag = null;
    const setView = v => { view = v; svg.setAttribute('viewBox', `${v.x} ${v.y} ${v.w} ${v.h}`); };
    function zoom(f, cx, cy) {
      const v = view, nx = cx == null ? v.x + v.w / 2 : cx, ny = cy == null ? v.y + v.h / 2 : cy;
      const w = Math.min(Math.max(v.w * f, 200), full.w * 4), h = v.h * (w / v.w);
      setView({ x: nx - (nx - v.x) * (w / v.w), y: ny - (ny - v.y) * (h / v.h), w, h });
    }

    function draw(g) {
      graph = g;
      svg.innerHTML = '';
      full = { x: -20, y: 0, w: g.w + 40, h: g.h };
      setView({ ...full });
      const defs = el('defs', {}, svg);
      [['hot', '#e05252'], ['cool', '#e8913a']].forEach(([id, c]) => {
        const m = el('marker', { id: `agp-arrow-${id}`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto' }, defs);
        el('path', { d: 'M0,0 L10,5 L0,10 z', fill: c }, m);
      });
      const edges = el('g', {}, svg), nodes = el('g', {}, svg);
      const pos = Object.fromEntries(g.nodes.map(n => [n.id, n]));
      g.edges.forEach((e, i) => {
        const a = pos[e.from], b = pos[e.to];
        if (!a || !b) return;
        const c = e.hot ? '#e05252' : '#e8913a', down = Math.abs(b.x - a.x) < 1;
        // left to right between columns; straight down within one, below the first box's label
        const [x1, y1, x2, y2] = down ? [a.x, a.y + R + 36, b.x, b.y - R - 6] : [a.x + R, a.y, b.x - R - 6, b.y];
        const d = down ? `M${x1},${y1} L${x2},${y2}` : `M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}`;
        const grp = el('g', { class: 'agp-edge', 'data-i': i }, edges);
        el('path', { d, stroke: c, 'stroke-width': e.hot ? 2.6 : 1.5, 'marker-end': `url(#agp-arrow-${e.hot ? 'hot' : 'cool'})` }, grp);
        const label = cut(e.label, 20), lw = label.length * 6 + 16, pill = el('g', { class: 'agp-pill' }, grp);
        const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
        el('rect', { x: mx - lw / 2, y: my - 9, width: lw, height: 18, rx: 9, stroke: c }, pill);
        text(pill, mx, my + 4, label);
      });
      g.nodes.forEach(n => {
        const grp = el('g', { class: 'agp-node', 'data-id': n.id, tabindex: 0, role: 'button', 'aria-label': `${KIND[n.kind] || n.kind}: ${n.label}` }, nodes);
        el('circle', { cx: n.x, cy: n.y, r: R, fill: COLOR[n.kind] || '#7f8c8d', stroke: n.hit ? '#e05252' : 'var(--surface)', 'stroke-width': n.hit ? 3 : 2 }, grp);
        text(grp, n.x, n.y + 5, GLYPH[n.kind] || '•', '', 'fill:#fff;font-size:13px;font-weight:700');
        if (n.hit) {
          el('circle', { cx: n.x + 15, cy: n.y - 15, r: 7, fill: '#e05252' }, grp);
          text(grp, n.x + 15, n.y - 11.5, '×', '', 'fill:#fff;font-size:11px;font-weight:700');
        }
        text(grp, n.x, n.y + R + 16, cut(n.label, 30));
        if (n.sub) text(grp, n.x, n.y + R + 30, cut(n.sub, 34), 'agp-sub');
        el('title', {}, grp).textContent = `${KIND[n.kind] || n.kind}: ${n.label}`;
      });
      info.style.display = 'none';
    }

    // The path to a box: everything that led to it, and what it led to next
    function follow(id) {
      const up = new Set([id]), down = new Set([id]);
      for (let grew = true; grew;) {
        grew = false;
        graph.edges.forEach(e => { if (up.has(e.to) && !up.has(e.from)) { up.add(e.from); grew = true; } });
      }
      graph.edges.forEach(e => { if (e.from === id) down.add(e.to); });
      const on = new Set([...up, ...down]);
      svg.querySelectorAll('.agp-node').forEach(n => n.classList.toggle('agp-dim', !on.has(n.dataset.id)));
      svg.querySelectorAll('.agp-edge').forEach(x => {
        const e = graph.edges[x.dataset.i];
        x.classList.toggle('agp-dim', !((up.has(e.to) && up.has(e.from)) || (down.has(e.from) && down.has(e.to))));
      });
      const n = graph.nodes.find(x => x.id === id);
      if (!n) return;
      info.innerHTML = `<div class="text-sm text-muted">${esc(KIND[n.kind] || n.kind)}</div>
        <div style="font-weight:600;overflow-wrap:anywhere">${esc(n.label)}</div>${n.sub ? `<div class="text-sm text-muted">${esc(n.sub)}</div>` : ''}
        ${(n.facts || []).length ? `<dl>${n.facts.map(([k, v]) => `<dt class="text-muted">${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>` : ''}
        <button type="button" class="btn btn--ghost btn--sm" data-clear="1" style="margin-top:8px">Show everything</button>`;
      info.style.display = '';
      if (onPick) onPick(id);
    }
    function clear() {
      svg.querySelectorAll('.agp-dim').forEach(x => x.classList.remove('agp-dim'));
      info.style.display = 'none';
      if (onPick) onPick(null);
    }

    svg.addEventListener('pointerdown', e => {
      drag = { x: e.clientX, y: e.clientY, v: { ...view }, moved: false, node: e.target.closest('.agp-node') };
      svg.setPointerCapture(e.pointerId);
    });
    svg.addEventListener('pointermove', e => {
      if (!drag) return;
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (!drag.moved && Math.hypot(dx, dy) < 4) return;
      drag.moved = true;
      svg.classList.add('agp--drag');
      const r = svg.getBoundingClientRect();
      setView({ ...drag.v, x: drag.v.x - dx * (drag.v.w / r.width), y: drag.v.y - dy * (drag.v.h / r.height) });
    });
    svg.addEventListener('pointerup', () => {
      if (drag && !drag.moved) { if (drag.node) follow(drag.node.dataset.id); else clear(); }
      drag = null;
      svg.classList.remove('agp--drag');
    });
    svg.addEventListener('keydown', e => {
      const n = e.target.closest('.agp-node');
      if (n && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); follow(n.dataset.id); }
    });
    svg.addEventListener('wheel', e => {
      e.preventDefault();
      const r = svg.getBoundingClientRect();
      zoom(e.deltaY > 0 ? 1.15 : 1 / 1.15, view.x + ((e.clientX - r.left) / r.width) * view.w, view.y + ((e.clientY - r.top) / r.height) * view.h);
    }, { passive: false });
    root.querySelector('.agp__zoom').addEventListener('click', e => {
      const z = e.target.closest('button') && e.target.closest('button').dataset.z;
      if (z === 'in') zoom(1 / 1.25); else if (z === 'out') zoom(1.25); else if (z === 'fit') setView({ ...full });
    });
    info.addEventListener('click', e => { if (e.target.dataset.clear) clear(); });
    return { draw, follow, clear };
  }

  return { mount, KIND };
})();
