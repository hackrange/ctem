// Admin > Utilization: CPU, memory and disk gauges (refreshed every 5 seconds while the tab is open), where the
// storage goes, and history from an hour to a year. Charts are ECharts (vendored); everything goes through esc().
(() => {
  const BASE = '/api/v1/admin/utilization';
  const pane = () => document.getElementById('pane-util');
  let range = '24h', timer = null, charts = {};

  const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim() || '#888';
  const bytes = n => {
    if (n == null) return '--';
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0, v = Number(n);
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
    return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
  };
  const pct = (a, b) => (a != null && b ? Math.round(1000 * a / b) / 10 : null);
  const level = p => (p == null ? 'info' : p >= 90 ? 'critical' : p >= 80 ? 'high' : 'low');
  async function get(path) {
    const r = await fetch(BASE + path, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error(r.status === 403 ? 'Admins only.' : 'Could not load utilization.');
    return r.json();
  }

  function chart(id) {
    const el = document.getElementById(id);
    if (!el || !window.echarts) return null;
    if (!charts[id]) charts[id] = echarts.init(el, null, { renderer: 'svg' });
    return charts[id];
  }

  function gauge(id, title, value, detail) {
    const c = chart(id);
    if (!c) return;
    const v = value == null ? 0 : value;
    c.setOption({ series: [{ type: 'gauge', startAngle: 225, endAngle: -45, min: 0, max: 100, radius: '80%', center: ['50%', '45%'],
      progress: { show: true, width: 12, itemStyle: { color: css(`--severity-${level(value)}`) } },
      axisLine: { lineStyle: { width: 12, color: [[1, css('--border')]] } }, pointer: { show: false },
      axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false },
      title: { offsetCenter: [0, '108%'], color: css('--fg-muted'), fontSize: 12 },   // the caption sits under the dial
      detail: { valueAnimation: true, offsetCenter: [0, '0%'], fontSize: 24, fontWeight: 600, color: css('--fg'),
                formatter: () => (value == null ? '--' : `${Math.round(v)}%`) },
      data: [{ value: v, name: detail || title }] }] });
  }

  async function live() {
    if (!pane() || pane().style.display === 'none') return;
    try {
      const s = await get('/live');
      gauge('ut-cpu', 'CPU', s.cpu, `CPU · ${s.cpus} cores`);
      gauge('ut-mem', 'Memory', pct(s.mem_used, s.mem_total), `Memory · ${bytes(s.mem_used)} of ${bytes(s.mem_total)}`);
      gauge('ut-disk', 'Disk', pct(s.disk_used, s.disk_total), `Disk · ${bytes(s.disk_total - s.disk_used)} free`);
    } catch (e) { /* the next tick tries again */ }
  }

  function bar(list, total) {
    return list.map(x => `<div style="display:grid;grid-template-columns:minmax(90px,220px) minmax(40px,1fr) 70px;gap:8px;align-items:center;margin:3px 0">
      <span class="text-sm" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(x.name)}">${esc(x.name)}</span>
      <span style="background:var(--border);border-radius:4px;height:10px;overflow:hidden"><span style="display:block;height:100%;width:${Math.max(1, Math.min(100, 100 * x.bytes / (total || 1)))}%;background:var(--accent)"></span></span>
      <span class="text-sm text-mono" style="text-align:right">${esc(bytes(x.bytes))}</span></div>`).join('');
  }

  async function storageView() {
    const s = await get('/storage');
    const d = s.disk, p = d.pct, db = s.database;
    const t = (db.tables || []);
    document.getElementById('ut-storage').innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(min(200px,100%),1fr));gap:12px;margin-bottom:12px">
        <div class="panel"><div class="text-sm text-muted">Disk (${esc(d.path)})</div><div style="font-size:1.3rem;font-weight:600">${esc(bytes(d.used))} of ${esc(bytes(d.total))}</div>
          <div class="text-sm"><span class="chip chip--${level(p)}">${p == null ? '--' : esc(p)}% used</span> ${esc(bytes(d.free))} free</div></div>
        <div class="panel"><div class="text-sm text-muted">CTEM database</div><div style="font-size:1.3rem;font-weight:600">${esc(bytes(db.bytes))}</div>
          <div class="text-sm text-muted">plus ${esc(bytes(db.wal_bytes))} write-ahead log</div></div>
        <div class="panel"><div class="text-sm text-muted">Redis (cache and queue)</div><div style="font-size:1.3rem;font-weight:600">${esc(bytes(s.redis.bytes))}</div>
          <div class="text-sm text-muted">${s.redis.max ? `limit ${esc(bytes(s.redis.max))}` : 'no memory limit set'}</div></div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr));gap:16px">
        <div><div class="text-sm" style="font-weight:600;margin-bottom:4px">Biggest CTEM tables</div>${bar(t, t.length ? t[0].bytes : 1)}</div>
        <div><div class="text-sm" style="font-weight:600;margin-bottom:4px">Databases on this server</div>${bar(db.all || [], (db.all || [])[0]?.bytes)}</div>
      </div>`;
    return s;
  }

  async function historyView() {
    const h = await get(`/history?range=${encodeURIComponent(range)}`);
    const pts = h.points || [];
    const x = pts.map(p => p.t);
    const line = (name, data, color) => ({ name, type: 'line', data: data.map((v, i) => [x[i], v]), showSymbol: false,
                                           smooth: true, lineStyle: { width: 2, color }, itemStyle: { color } });
    const base = { animation: false, grid: { left: 56, right: 16, top: 28, bottom: 28 }, tooltip: { trigger: 'axis' },
                   legend: { top: 0, textStyle: { color: css('--fg-muted') } }, xAxis: { type: 'time', axisLabel: { color: css('--fg-muted') } } };
    const pctAxis = { type: 'value', min: 0, max: 100, axisLabel: { formatter: '{value}%', color: css('--fg-muted') }, splitLine: { lineStyle: { color: css('--border') } } };
    const byteAxis = { type: 'value', axisLabel: { formatter: v => bytes(v), color: css('--fg-muted') }, splitLine: { lineStyle: { color: css('--border') } } };
    chart('ut-h-cpu')?.setOption({ ...base, yAxis: pctAxis, series: [line('CPU', pts.map(p => p.cpu), css('--accent')),
      line('Peak', pts.map(p => p.cpu_max), css('--severity-medium'))] }, true);
    chart('ut-h-mem')?.setOption({ ...base, yAxis: pctAxis, series: [line('Memory', pts.map(p => pct(p.mem_used, p.mem_total)), css('--severity-info'))] }, true);
    chart('ut-h-disk')?.setOption({ ...base, yAxis: pctAxis, series: [line('Disk', pts.map(p => pct(p.disk_used, p.disk_total)), css('--severity-high'))],
      markLine: undefined }, true);
    chart('ut-h-db')?.setOption({ ...base, yAxis: byteAxis, series: [line('CTEM database', pts.map(p => p.db_bytes), css('--accent')),
      line('Redis', pts.map(p => p.redis_bytes), css('--severity-low'))] }, true);
    document.getElementById('ut-empty').hidden = pts.length > 1;
    return h;
  }

  function banner(s, h) {
    const p = s.disk.pct, eta = h.days_until_full;
    const el = document.getElementById('ut-banner');
    if (p == null || (p < s.warn_pct && !(eta != null && eta < 30))) { el.hidden = true; return; }
    el.hidden = false;
    el.style.borderLeft = `4px solid var(--severity-${p >= s.bad_pct ? 'critical' : 'high'})`;
    el.innerHTML = `<b>The disk is ${esc(p)}% full</b> (${esc(bytes(s.disk.free))} free).
      ${eta != null ? ` At the current rate it fills in about <b>${esc(eta)} days</b>.` : ''}
      If it fills, PostgreSQL stops accepting writes and CTEM stops working. Free space on the server (old Docker images
      and build cache are the usual cause) or add disk.`;
  }

  async function load() {
    pane().innerHTML = `<div id="ut-banner" class="panel" hidden style="margin-bottom:12px"></div>
      <div class="panel" style="margin-bottom:12px">
        <div class="panel__header"><span class="panel__title">Now</span><span class="text-sm text-muted">This server, refreshed every 5 seconds</span></div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(min(180px,100%),1fr));gap:8px">
          <div id="ut-cpu" style="height:200px"></div><div id="ut-mem" style="height:200px"></div><div id="ut-disk" style="height:200px"></div></div></div>
      <div class="panel" style="margin-bottom:12px"><div class="panel__header"><span class="panel__title">Storage</span></div><div id="ut-storage">Loading...</div></div>
      <div class="panel"><div class="panel__header" style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px">
          <span class="panel__title">History</span><span id="ut-ranges" style="display:flex;gap:4px">${['1h', '24h', '7d', '30d', '365d'].map(r =>
            `<button type="button" class="btn btn--sm ${r === range ? 'btn--primary' : 'btn--ghost'}" data-range="${r}">${r === '365d' ? '1 year' : r}</button>`).join('')}</span></div>
        <p id="ut-empty" class="text-sm text-muted" hidden>History builds up a minute at a time; check back shortly.</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(min(380px,100%),1fr));gap:12px">
          <div><div class="text-sm" style="font-weight:600">CPU</div><div id="ut-h-cpu" style="height:220px"></div></div>
          <div><div class="text-sm" style="font-weight:600">Memory</div><div id="ut-h-mem" style="height:220px"></div></div>
          <div><div class="text-sm" style="font-weight:600">Disk</div><div id="ut-h-disk" style="height:220px"></div></div>
          <div><div class="text-sm" style="font-weight:600">CTEM database and Redis</div><div id="ut-h-db" style="height:220px"></div></div>
        </div></div>`;
    Object.values(charts).forEach(c => c.dispose());
    charts = {};
    try {
      const [s, h] = await Promise.all([storageView(), historyView()]);
      banner(s, h);
    } catch (e) { document.getElementById('ut-storage').textContent = e.message; }
    live();
    clearInterval(timer);
    timer = setInterval(live, 5000);
  }

  document.addEventListener('click', async e => {
    const b = e.target.closest('#ut-ranges [data-range]');
    if (!b) return;
    range = b.dataset.range;
    document.querySelectorAll('#ut-ranges [data-range]').forEach(x => x.className = `btn btn--sm ${x.dataset.range === range ? 'btn--primary' : 'btn--ghost'}`);
    try { await historyView(); } catch (err) { toast(err.message, 'error'); }
  });
  window.addEventListener('resize', () => Object.values(charts).forEach(c => c.resize()));
  window.AdminUtilization = { load };
})();
