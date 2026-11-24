// An interactive attack map (laid out on the server by api/core/attack_map.py): click a box to follow its path (what
// led to it, and what it led to next) and read its details; drag to pan; wheel or +/- to zoom. Used by the alert page and
// Threat Hunt findings. AttackMap.mount(el) fills `el` and returns { draw(graph), follow(id), clear() }.
// Everything shown goes through esc().
window.AttackMap = (() => {
  const NS = 'http://www.w3.org/2000/svg';
  const COLOR = { host: '#3a8ee8', user: '#e8913a', process: '#4a5568', detection: '#e05252', action: '#3aa76d', quarantine: '#e05252',
                  indicator: '#9b59b6', file: '#e8913a', network: '#e8913a', dns: '#e8913a', event: '#4a5568', alert: '#e05252',
                  log: '#3a8ee8', ip: '#e8913a', launch: '#4a5568', service: '#e8913a', weakness: '#e05252', credential: '#9b59b6',
                  impact: '#c62828' };
  const GLYPH = { host: '\u{1F5A5}', user: '\u{1F464}', process: '</>', detection: '!', action: '\u{1F6E1}', quarantine: '\u{1F512}',
                  indicator: '⚠', file: '\u{1F4C4}', network: '\u{1F310}', dns: '\u{1F50D}', event: '▶', alert: '!',
                  log: '≡', ip: '\u{1F310}', launch: '▶', service: '⚙', weakness: '⚡', credential: '\u{1F511}', impact: '\u{1F3AF}' };
  const KIND = { host: 'Host', user: 'User', process: 'Process', detection: 'Detection', action: 'What the EDR did',
                 quarantine: 'Quarantined file', indicator: 'Indicator', file: 'File', network: 'Connection', dns: 'DNS lookup',
                 event: 'Step', alert: 'Alert', log: 'Log event', ip: 'Address', launch: 'Pentest start', service: 'Service',
                 weakness: 'Weakness exploited', credential: 'Credential', impact: 'Impact' };
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
      <div class="agp__zoom"><button type="button" data-z="in" aria-label="Zoom in" title="Zoom in">+</button>
        <button type="button" data-z="out" aria-label="Zoom out" title="Zoom out">&minus;</button>
        <button type="button" data-z="fit" aria-label="Fit to view" title="Fit to view">&#x2316;</button>
        <button type="button" data-z="turn" aria-label="Switch between left to right and top to bottom" title="Left to right / top to bottom">&#x21C5;</button>
        <button type="button" data-z="max" aria-label="Full screen" title="Full screen (Esc to leave)">&#x26F6;</button></div>`;
    const svg = root.querySelector('svg'), info = root.querySelector('.agp__info');
    let graph = null, view = null, full = null, drag = null;
    const setView = v => { view = v; svg.setAttribute('viewBox', `${v.x} ${v.y} ${v.w} ${v.h}`); };
    function zoom(f, cx, cy) {
      const v = view, nx = cx == null ? v.x + v.w / 2 : cx, ny = cy == null ? v.y + v.h / 2 : cy;
      const w = Math.min(Math.max(v.w * f, 200), full.w * 4), h = v.h * (w / v.w);
      setView({ x: nx - (nx - v.x) * (w / v.w), y: ny - (ny - v.y) * (h / v.h), w, h });
    }

    let source = null;
    let vertical = localStorage.getItem('ctem.map.orient') === 'v';
    // Top to bottom: each column of the server's layout becomes a row, spaced so labels don't collide
    function turned(g) {
      const nodes = g.nodes.map(n => ({ ...n, x: 90 + (n.y - 60) * 2.3, y: 60 + (n.x - 90) * 0.62 }));
      const w = Math.max(...nodes.map(n => n.x), 0) + 200, h = Math.max(...nodes.map(n => n.y), 0) + 90;
      return { ...g, nodes, w, h };
    }

    // Room to spare (full screen, a big window): spread the boxes apart to fill it, keeping them and their text the
    // same size, so the map uses the screen instead of growing into a blur
    function spread(g, reserve = 0) {
      const r = svg.getBoundingClientRect();
      if (!r.width || !r.height || !g.nodes.length) return g;
      const xs = g.nodes.map(n => n.x), ys = g.nodes.map(n => n.y);
      const x0 = Math.min(...xs), y0 = Math.min(...ys), w = Math.max(...xs) - x0, h = Math.max(...ys) - y0;
      const pad = { x: 120, top: 60, bottom: 80 };
      const roomW = r.width - 2 * pad.x - reserve, roomH = r.height - pad.top - pad.bottom;
      if (w > roomW && h > roomH) return g;                       // bigger than the screen: the usual fit-to-view
      const sx = w ? Math.min(3, Math.max(1, roomW / w)) : 1, sy = h ? Math.min(3, Math.max(1, roomH / h)) : 1;
      // centered in the room left over (beside the details panel when one is open)
      const ox = pad.x + Math.max(0, (roomW - w * sx) / 2), oy = pad.top + Math.max(0, (roomH - h * sy) / 2);
      const nodes = g.nodes.map(n => ({ ...n, x: ox + (n.x - x0) * sx, y: oy + (n.y - y0) * sy }));
      return { ...g, nodes, w: Math.max(r.width - 40, ox + w * sx + pad.x + reserve), h: Math.max(r.height, oy + h * sy + pad.bottom) };
    }

    // Boxes, their labels and the labels already placed: a link's label goes where it covers none of them
    const overlaps = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
    function taken(g) {
      const boxes = [];
      g.nodes.forEach(n => {
        boxes.push({ x: n.x - R - 2, y: n.y - R - 2, w: 2 * R + 4, h: 2 * R + 4 });
        const lw = Math.max(cut(n.label, 30).length * 6.6, n.sub ? cut(n.sub, 34).length * 5.8 : 0);
        boxes.push({ x: n.x - lw / 2, y: n.y + R + 4, w: lw, h: n.sub ? 30 : 16 });
      });
      return boxes;
    }

    // Clicking a box shows only its path: what led to it and what it led to next, packed together to use the room
    let focus = null;
    const gap = vals => {
      const v = [...new Set(vals.map(x => Math.round(x)))].sort((a, b) => a - b), d = v.slice(1).map((x, i) => x - v[i]).filter(x => x > 1);
      return d.length ? Math.min(...d) : 0;
    };
    function pathOf(g, id) {
      const up = new Set([id]), down = new Set([id]);
      for (let grew = true; grew;) {
        grew = false;
        g.edges.forEach(e => { if (up.has(e.to) && !up.has(e.from)) { up.add(e.from); grew = true; } });
      }
      g.edges.forEach(e => { if (e.from === id) down.add(e.to); });
      const edges = g.edges.filter(e => (up.has(e.to) && up.has(e.from)) || (down.has(e.from) && down.has(e.to)));
      const keep = new Set([id, ...edges.flatMap(e => [e.from, e.to])]);
      const nodes = g.nodes.filter(n => keep.has(n.id));
      const colStep = gap(g.nodes.map(n => n.x)) || 240, rowStep = Math.max(gap(g.nodes.map(n => n.y)) || 90, 90);
      const cols = [...new Set(nodes.map(n => Math.round(n.x)))].sort((a, b) => a - b);
      const tall = Math.max(...cols.map(c => nodes.filter(n => Math.round(n.x) === c).length));
      const placed = [];
      cols.forEach((c, i) => {
        const here = nodes.filter(n => Math.round(n.x) === c).sort((a, b) => a.y - b.y);
        const top = 60 + ((tall - here.length) * rowStep) / 2;
        here.forEach((n, j) => placed.push({ ...n, x: 90 + i * colStep, y: top + j * rowStep }));
      });
      return { ...g, nodes: placed, edges, w: 90 + (cols.length - 1) * colStep + 200, h: 60 + tall * rowStep + 40 };
    }

    function draw(input) {
      source = input;
      focus = null;
      info.style.display = 'none';
      render();
    }

    function render() {
      const base = focus ? pathOf(source, focus) : source;
      const g = spread(vertical ? turned(base) : base, focus ? Math.min(460, info.offsetWidth || 440) + 20 : 0);
      graph = g;
      svg.innerHTML = '';
      full = { x: -20, y: 0, w: g.w + 40, h: g.h };
      setView({ ...full });
      const defs = el('defs', {}, svg);
      [['hot', '#e05252'], ['cool', '#e8913a']].forEach(([id, c]) => {
        const m = el('marker', { id: `agp-arrow-${id}`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto' }, defs);
        el('path', { d: 'M0,0 L10,5 L0,10 z', fill: c }, m);
      });
      const edges = el('g', {}, svg), nodes = el('g', {}, svg), pills = el('g', {}, svg);   // link labels sit on top
      const pos = Object.fromEntries(g.nodes.map(n => [n.id, n]));
      const busy = taken(g);
      g.edges.forEach((e, i) => {
        const a = pos[e.from], b = pos[e.to];
        if (!a || !b) return;
        const c = e.hot ? '#e05252' : '#e8913a';
        // Between levels: left to right (or top to bottom when turned); within one level: straight across or down
        const sameCol = Math.abs(b.x - a.x) < 1, sameRow = Math.abs(b.y - a.y) < 1;
        let x1, y1, x2, y2, d;
        if (vertical && !sameRow) {
          [x1, y1, x2, y2] = [a.x, a.y + R + 36, b.x, b.y - R - 6];
          d = `M${x1},${y1} C${x1},${(y1 + y2) / 2} ${x2},${(y1 + y2) / 2} ${x2},${y2}`;
        } else if (sameCol) {
          [x1, y1, x2, y2] = [a.x, a.y + R + 36, b.x, b.y - R - 6];
          d = `M${x1},${y1} L${x2},${y2}`;
        } else {
          [x1, y1, x2, y2] = b.x > a.x ? [a.x + R, a.y, b.x - R - 6, b.y] : [a.x - R, a.y, b.x + R + 6, b.y];
          d = `M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}`;
        }
        const grp = el('g', { class: 'agp-edge', 'data-i': i }, edges);
        const line = el('path', { d, stroke: c, 'stroke-width': e.hot ? 2.6 : 1.5, 'marker-end': `url(#agp-arrow-${e.hot ? 'hot' : 'cool'})` }, grp);
        if (!e.label) return;
        const label = cut(e.label, 20), lw = label.length * 6 + 16;
        // Slide the label along its line to the first spot that covers no box, box label or other link label
        let len = 0;
        try { len = line.getTotalLength(); } catch (_) { len = 0; }
        let at = { x: (x1 + x2) / 2, y: (y1 + y2) / 2 }, best = Infinity;
        for (const t of [0.5, 0.4, 0.6, 0.3, 0.7, 0.22, 0.78, 0.15, 0.85]) {
          const p = len ? line.getPointAtLength(len * t) : { x: x1 + (x2 - x1) * t, y: y1 + (y2 - y1) * t };
          const box = { x: p.x - lw / 2, y: p.y - 9, w: lw, h: 18 };
          const hits = busy.filter(b => overlaps(box, b)).length;
          if (hits < best) { best = hits; at = p; }
          if (!hits) break;
        }
        busy.push({ x: at.x - lw / 2, y: at.y - 9, w: lw, h: 18 });
        const pill = el('g', { class: 'agp-pill agp-edge', 'data-i': i }, pills);
        el('rect', { x: at.x - lw / 2, y: at.y - 9, width: lw, height: 18, rx: 9, stroke: c }, pill);
        text(pill, at.x, at.y + 4, label);
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
    }

    // The path to a box: everything that led to it, and what it led to next
    function follow(id) {
      if (!source || !source.nodes.some(x => x.id === id)) return;
      focus = id;
      render();
      svg.querySelectorAll('.agp-node').forEach(x => x.classList.toggle('agp-focus', x.dataset.id === id));
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
      if (focus) { focus = null; render(); }
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
      if (z === 'in') zoom(1 / 1.25);
      else if (z === 'out') zoom(1.25);
      else if (z === 'fit') setView({ ...full });
      else if (z === 'turn') {
        vertical = !vertical;
        localStorage.setItem('ctem.map.orient', vertical ? 'v' : 'h');
        if (source) render();
      } else if (z === 'max') {
        const box = root.closest('.agp') || root;   // the story cards come along
        if (document.fullscreenElement) document.exitFullscreen();
        else if (box.requestFullscreen) box.requestFullscreen().catch(() => {});
      }
    });
    // Entering or leaving full screen, or resizing the window, lays the map out again for the room it has
    let again = null;
    const relayout = () => { clearTimeout(again); again = setTimeout(() => { if (source) render(); }, 120); };
    document.addEventListener('fullscreenchange', relayout);
    window.addEventListener('resize', relayout);
    info.addEventListener('click', e => { if (e.target.dataset.clear) clear(); });
    return { draw, follow, clear };
  }

  return { mount, KIND };
})();
