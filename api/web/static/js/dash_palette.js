// The widget library shown while editing a dashboard: themes to pick from, stock widgets grouped by topic, and
// every catalog metric. Drag one onto the grid (or click it to add it at the bottom), then move, resize and
// switch its chart type right on the grid.
(function () {
  const ICON = {
    kpi: '<text x="2" y="15" font-size="11" font-weight="700" fill="currentColor">123</text>',
    gauge: '<path d="M3 16a9 9 0 0 1 18 0" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" opacity=".35"/><path d="M3 16a9 9 0 0 1 13-8" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>',
    line: '<polyline points="2,16 8,9 13,12 22,4" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>',
    area: '<path d="M2 18V14L8 8l5 4 9-8v14z" fill="currentColor" opacity=".55"/><polyline points="2,14 8,8 13,12 22,4" fill="none" stroke="currentColor" stroke-width="2"/>',
    bar: '<rect x="3" y="9" width="4" height="9" rx="1" fill="currentColor"/><rect x="10" y="4" width="4" height="14" rx="1" fill="currentColor"/><rect x="17" y="11" width="4" height="7" rx="1" fill="currentColor"/>',
    stacked: '<rect x="3" y="9" width="5" height="9" rx="1" fill="currentColor" opacity=".5"/><rect x="3" y="13" width="5" height="5" fill="currentColor"/><rect x="10" y="4" width="5" height="14" rx="1" fill="currentColor" opacity=".5"/><rect x="10" y="10" width="5" height="8" fill="currentColor"/><rect x="17" y="7" width="5" height="11" rx="1" fill="currentColor" opacity=".5"/><rect x="17" y="13" width="5" height="5" fill="currentColor"/>',
    column: '<rect x="3" y="9" width="4" height="9" rx="1" fill="currentColor"/><rect x="10" y="4" width="4" height="14" rx="1" fill="currentColor"/><rect x="17" y="11" width="4" height="7" rx="1" fill="currentColor"/>',
    donut: '<circle cx="12" cy="11" r="7" fill="none" stroke="currentColor" stroke-width="4" opacity=".35"/><path d="M12 4a7 7 0 0 1 7 7" fill="none" stroke="currentColor" stroke-width="4"/>',
    pie: '<circle cx="12" cy="11" r="8" fill="currentColor" opacity=".35"/><path d="M12 11V3a8 8 0 0 1 8 8z" fill="currentColor"/>',
    table: '<rect x="3" y="4" width="18" height="14" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M3 9h18M3 13.5h18M10 4v14" stroke="currentColor" stroke-width="1.4"/>',
    bubble: '<circle cx="7" cy="14" r="3" fill="currentColor" opacity=".6"/><circle cx="15" cy="8" r="5" fill="currentColor" opacity=".6"/><circle cx="19" cy="16" r="2" fill="currentColor"/>',
    scatter: '<circle cx="5" cy="15" r="1.8" fill="currentColor"/><circle cx="9" cy="10" r="1.8" fill="currentColor"/><circle cx="14" cy="12" r="1.8" fill="currentColor"/><circle cx="17" cy="6" r="1.8" fill="currentColor"/><circle cx="20" cy="9" r="1.8" fill="currentColor"/>',
  };
  ICON.bar = '<rect x="3" y="4" width="12" height="4" rx="1" fill="currentColor"/><rect x="3" y="10" width="18" height="4" rx="1" fill="currentColor"/><rect x="3" y="16" width="8" height="4" rx="1" fill="currentColor"/>';
  const VIZ = { kpi: 'Number', gauge: 'Gauge', line: 'Line', area: 'Area', bar: 'Bars', stacked: 'Stacked bars', column: 'Columns',
                donut: 'Donut', pie: 'Pie', table: 'Table', bubble: 'Bubbles', scatter: 'Scatter' };
  // Series bars run up; parts bars run across. The icon follows the chart.
  const icon = (viz, shape) => `<svg class="pal-ico" viewBox="0 0 24 22" aria-hidden="true">${viz === 'bar' && shape === 'series' ? ICON.column : ICON[viz] || ICON.table}</svg>`;
  const uid = () => Math.random().toString(36).slice(2, 14);

  function fromPreset(p) {
    return { id: uid(), metric: p.metric, viz: p.viz, title: p.title, params: { ...p.params }, style: { ...p.style }, x: 0, y: 1000, w: p.w, h: p.h };
  }
  function fromMetric(m) {
    const small = m.shape === 'value';
    return { id: uid(), metric: m.id, viz: m.viz[0], title: m.label, params: {}, style: {}, x: 0, y: 1000, w: small ? 3 : 6, h: small ? 2 : 4 };
  }

  // opts: { el, presets, catalog, theme, onAdd(widget), onTheme(name), onCustom() }
  function mount(opts) {
    const el = opts.el;
    const byKey = {};
    const groups = {};
    opts.presets.forEach(p => { byKey[`p:${p.key}`] = fromPreset(p); (groups[p.group] = groups[p.group] || []).push(p); });
    opts.catalog.forEach(m => { byKey[`m:${m.id}`] = fromMetric(m); });
    const item = (key, title, viz, shape, sub) => {
      const w = byKey[key];
      return `<div class="pal-item grid-stack-item" gs-w="${w.w}" gs-h="${w.h}" data-key="${esc(key)}" tabindex="0" role="button"
        title="Drag onto the dashboard, or click to add" data-text="${esc(`${title} ${sub || ''}`.toLowerCase())}">
        <div class="grid-stack-item-content pal-item__inner">${icon(viz, shape)}<span class="pal-item__text"><b>${esc(title)}</b>${sub ? `<small>${esc(sub)}</small>` : ''}</span></div></div>`;
    };
    const themes = Object.entries(DashCharts.THEMES).map(([k, t]) => `<button type="button" class="pal-theme${k === opts.theme ? ' is-on' : ''}" data-theme-key="${esc(k)}"
      title="${esc(t.label)}" aria-pressed="${k === opts.theme}"><span class="pal-theme__sw">${(t.palette || ['var(--severity-info)', 'var(--accent)', 'var(--severity-low)', 'var(--severity-high)'])
        .slice(0, 4).map(c => `<i style="background:${c}"></i>`).join('')}</span>${esc(t.label)}</button>`).join('');
    const cats = [...new Set(opts.catalog.map(m => m.category))];
    el.innerHTML = `<div class="pal-head"><b>Widgets</b><span class="text-sm text-muted">Drag onto the grid</span></div>
      <input type="search" class="form-input pal-search" placeholder="Search widgets" aria-label="Search widgets">
      <details class="pal-group" open><summary>Theme</summary><div class="pal-themes">${themes}</div></details>
      <button type="button" class="btn btn--ghost btn--sm pal-custom">+ Build your own chart</button>
      ${Object.entries(groups).map(([g, list], i) => `<details class="pal-group"${i < 2 ? ' open' : ''}><summary>${esc(g)} <span class="text-muted">${list.length}</span></summary>
        <div class="pal-list">${list.map(p => item(`p:${p.key}`, p.title, p.viz, p.shape, VIZ[p.viz])).join('')}</div></details>`).join('')}
      ${cats.map(c => `<details class="pal-group"><summary>All: ${esc(c)}</summary><div class="pal-list">${opts.catalog.filter(m => m.category === c)
        .map(m => item(`m:${m.id}`, m.label, m.viz[0], m.shape, m.viz.map(v => VIZ[v] || v).join(' · '))).join('')}</div></details>`).join('')}`;
    GridStack.setupDragIn(el.querySelectorAll('.pal-item'), { appendTo: 'body', helper: 'clone' });
    const take = key => (byKey[key] ? { ...JSON.parse(JSON.stringify(byKey[key])), id: uid() } : null);
    el.onclick = e => {
      const th = e.target.closest('[data-theme-key]');
      if (th) {
        el.querySelectorAll('.pal-theme').forEach(b => { b.classList.toggle('is-on', b === th); b.setAttribute('aria-pressed', String(b === th)); });
        opts.onTheme(th.dataset.themeKey);
        return;
      }
      if (e.target.closest('.pal-custom')) { opts.onCustom(); return; }
      const it = e.target.closest('.pal-item');
      if (it) { const w = take(it.dataset.key); if (w) opts.onAdd(w); }
    };
    el.onkeydown = e => { if (e.key === 'Enter' && e.target.classList.contains('pal-item')) e.target.click(); };
    el.querySelector('.pal-search').addEventListener('input', e => {
      const q = e.target.value.trim().toLowerCase();
      el.querySelectorAll('.pal-item').forEach(i => { i.hidden = !!q && !i.dataset.text.includes(q); });
      el.querySelectorAll('.pal-group').forEach(g => { if (q && g.querySelector('.pal-item:not([hidden])')) g.open = true; });
    });
    return { take };
  }

  window.DashPalette = { mount, VIZ, icon };
})();
