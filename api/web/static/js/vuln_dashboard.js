// Vulnerability dashboard: KPI tiles and Apache ECharts charts, themed from CTEM's CSS variables (light and dark).
// Every label from the server goes through esc() in HTML or is set as chart data (ECharts renders text, not HTML).
(() => {
  const $ = id => document.getElementById(id);
  const SEV = ['critical', 'high', 'medium', 'low'];
  const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  const MIN_CVSS = { critical: 9, high: 7, medium: 4 };
  const charts = {};
  const init = new URLSearchParams(location.search);   // read before the first load rewrites the address
  let data = null;

  const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const theme = () => ({
    fg: css('--fg') || '#1a1a2e', muted: css('--fg-muted') || '#6b7280', border: css('--border') || '#e5e7eb',
    surface: css('--surface') || '#fff', accent: css('--accent') || '#f5a623', info: css('--severity-info') || '#3b82f6',
    sev: Object.fromEntries(SEV.map(s => [s, css(`--severity-${s}`)])),
  });
  const n = v => (v == null ? '--' : Number(v).toLocaleString());

  function base(t) {
    return {
      textStyle: { color: t.fg, fontFamily: 'inherit' },
      grid: { left: 8, right: 16, top: 36, bottom: 8, containLabel: true },
      legend: { top: 0, textStyle: { color: t.muted }, icon: 'roundRect', itemWidth: 12, itemHeight: 8 },
      tooltip: { trigger: 'axis', backgroundColor: t.surface, borderColor: t.border, textStyle: { color: t.fg },
                 valueFormatter: v => n(v) },
      xAxis: { axisLine: { lineStyle: { color: t.border } }, axisLabel: { color: t.muted }, splitLine: { show: false } },
      yAxis: { axisLabel: { color: t.muted, formatter: v => (v >= 1e6 ? `${v / 1e6}M` : v >= 1e3 ? `${v / 1e3}k` : v) },
               splitLine: { lineStyle: { color: t.border, type: 'dashed' } } },
    };
  }

  function chart(id) {
    if (!charts[id]) {
      charts[id] = echarts.init($(id), null, { renderer: 'canvas' });
      new ResizeObserver(() => charts[id].resize()).observe($(id));
    }
    return charts[id];
  }

  function kpis(k, ex) {
    const tile = (label, value, href, cls = '', hint = '') => `<a class="vd-kpi ${cls}" href="${esc(href)}"${hint ? ` title="${esc(hint)}"` : ''}>
        <span class="vd-kpi__label">${esc(label)}</span><span class="vd-kpi__value">${esc(n(value))}</span></a>`;
    $('vd-kpis').innerHTML = [
      tile('Open findings', k.open, '/vulns'),
      tile('Critical', k.critical, '/vulns?min_cvss=9', 'vd-kpi--critical'),
      tile('High', k.high, '/vulns?min_cvss=7', 'vd-kpi--high'),
      tile('KEV', k.kev, '/vulns?is_kev=true', 'vd-kpi--critical', 'Known exploited (CISA KEV)'),
      tile('Exploit available', k.exploitable, '/vulns', 'vd-kpi--high'),
      tile('Past SLA', k.past_sla, '/grc/checks/ctem_vuln_sla', 'vd-kpi--high', 'Critical and high open longer than their SLA'),
      tile('Devices affected', k.devices, '/devices'),
      tile('New (7 days)', k.new_7d, '/vulns'),
      tile('Fixed (7 days)', k.fixed_7d, '/vulns', 'vd-kpi--low'),
      tile('Exceptions', ex.active, '/exceptions', '', `${ex.pending} waiting for approval, ${ex.ending_14d} ending within 14 days`),
    ].join('');
  }

  function trend(tr, since) {
    const t = theme(), o = base(t);
    const series = SEV.slice().reverse().map(s => ({
      name: SEV_LABEL[s], type: 'line', stack: 'open', areaStyle: { opacity: 0.35 }, symbol: 'none', smooth: 0.2,
      lineStyle: { width: 1.5 }, color: t.sev[s], data: tr[s], emphasis: { focus: 'series' },
    }));
    series.push({ name: 'KEV', type: 'line', yAxisIndex: 1, symbol: 'none', lineStyle: { width: 2, type: 'dashed' },
                  color: t.fg, data: tr.kev });
    if (since && tr.days.includes(since)) {
      series[0].markLine = { symbol: 'none', silent: true, lineStyle: { color: t.muted, type: 'dotted' },
                             label: { color: t.muted, formatter: 'fixes tracked from here' }, data: [{ xAxis: since }] };
    }
    chart('c-trend').setOption({
      ...o, legend: { ...o.legend, data: [...SEV.map(s => SEV_LABEL[s]), 'KEV'] },
      grid: { ...o.grid, bottom: 40 },
      xAxis: { ...o.xAxis, type: 'category', boundaryGap: false, data: tr.days },
      yAxis: [{ ...o.yAxis, type: 'value', name: 'open', nameTextStyle: { color: t.muted } },
              { ...o.yAxis, type: 'value', name: 'KEV', nameTextStyle: { color: t.muted }, splitLine: { show: false } }],
      dataZoom: [{ type: 'inside' }, { type: 'slider', height: 18, bottom: 6, borderColor: t.border, textStyle: { color: t.muted } }],
      series,
    }, true);
  }

  function flow(tr) {
    const t = theme(), o = base(t);
    chart('c-flow').setOption({
      ...o, xAxis: { ...o.xAxis, type: 'category', data: tr.days }, yAxis: { ...o.yAxis, type: 'value' },
      dataZoom: [{ type: 'inside' }],
      series: [{ name: 'New', type: 'bar', color: t.sev.high, data: tr.new, barMaxWidth: 14 },
               { name: 'Fixed', type: 'bar', color: t.sev.low, data: tr.fixed, barMaxWidth: 14 }],
    }, true);
  }

  function aging(a, sla) {
    const t = theme(), o = base(t);
    $('vd-sla-note').textContent = `SLA: critical ${sla.critical}d, high ${sla.high}d`;
    chart('c-aging').setOption({
      ...o, tooltip: { ...o.tooltip, axisPointer: { type: 'shadow' } },
      xAxis: { ...o.xAxis, type: 'category', data: a.buckets }, yAxis: { ...o.yAxis, type: 'value' },
      series: SEV.map(s => ({ name: SEV_LABEL[s], type: 'bar', stack: 'age', color: t.sev[s], data: a[s], barMaxWidth: 48 })),
    }, true);
  }

  function mttr(m) {
    const t = theme(), o = base(t);
    chart('c-mttr').setOption({
      ...o, tooltip: { ...o.tooltip, valueFormatter: v => (v == null ? '--' : `${v} days`) },
      xAxis: { ...o.xAxis, type: 'category', data: m.months }, yAxis: { ...o.yAxis, type: 'value', name: 'days', nameTextStyle: { color: t.muted } },
      series: ['critical', 'high', 'medium'].map(s => ({ name: SEV_LABEL[s], type: 'line', color: t.sev[s], data: m[s],
                                                        symbolSize: 7, connectNulls: true })),
    }, true);
  }

  function types(rows) {
    const t = theme();
    const palette = [t.info, t.accent, t.sev.low, t.sev.high, t.sev.medium, t.muted, t.sev.critical, t.fg];
    const c = chart('c-types');
    c.setOption({
      textStyle: { color: t.fg }, color: palette,
      tooltip: { trigger: 'item', backgroundColor: t.surface, borderColor: t.border, textStyle: { color: t.fg },
                 valueFormatter: v => n(v) },
      legend: { orient: 'vertical', right: 8, top: 'middle', textStyle: { color: t.muted } },
      series: [{ type: 'pie', radius: ['48%', '76%'], center: ['38%', '52%'], avoidLabelOverlap: true,
                 itemStyle: { borderColor: t.surface, borderWidth: 2, borderRadius: 4 }, label: { show: false },
                 data: rows.map(r => ({ name: r.type.replace(/_/g, ' '), value: r.open, raw: r.type })) }],
    }, true);
    c.off('click');
    c.on('click', p => { if (p.data && p.data.raw) location.href = `/devices?device_type=${encodeURIComponent(p.data.raw)}`; });
  }

  function tables(d) {
    $('vd-topv').innerHTML = d.top_vulns.map(v => `<tr data-href="/vulns/${encodeURIComponent(v.id)}" style="cursor:pointer">
        <td class="text-sm"><a class="dt-link" href="/vulns/${encodeURIComponent(v.id)}">${v.cve_id ? `<b>${esc(v.cve_id)}</b> ` : ''}${esc(v.title.slice(0, 70))}</a>
          ${v.kev ? ' <span class="chip chip--critical" style="font-size:.65rem">KEV</span>' : ''}</td>
        <td class="text-sm">${esc(v.cvss ?? '--')}</td><td class="text-sm">${esc(n(v.devices))}</td></tr>`).join('')
      || '<tr><td colspan="3" class="text-muted text-sm" style="text-align:center;padding:16px">None</td></tr>';
    $('vd-topd').innerHTML = d.top_devices.map(x => `<tr data-href="/devices/${encodeURIComponent(x.id)}" style="cursor:pointer">
        <td class="text-sm"><a class="dt-link" href="/devices/${encodeURIComponent(x.id)}">${esc(x.hostname || x.id)}</a></td>
        <td>${DataTableGrade(x.grade)}</td><td class="text-sm">${esc(x.score == null ? '--' : Math.round(x.score))}</td>
        <td class="text-sm">${esc(n(x.open))}</td><td class="text-sm">${x.kev ? `<span class="chip chip--critical" style="font-size:.65rem">${esc(n(x.kev))}</span>` : '0'}</td></tr>`).join('')
      || '<tr><td colspan="5" class="text-muted text-sm" style="text-align:center;padding:16px">None</td></tr>';
  }
  const GRADE = { F: 'critical', D: 'high', C: 'medium', B: 'low', A: 'info' };
  const DataTableGrade = g => (g ? `<span class="chip chip--${GRADE[g] || 'info'}">${esc(g)}</span>` : '<span class="text-muted">--</span>');

  function render() {
    if (!data) return;
    kpis(data.kpis, data.exceptions);
    trend(data.trend, data.tracking_since);
    flow(data.trend);
    aging(data.aging, data.sla_days);
    mttr(data.mttr);
    types(data.by_type);
    tables(data);
    const at = new Date(data.generated_at);
    $('vd-sub').textContent = `${data.scoped ? 'Posture and trends for the devices you can see' : 'Posture and trends across every device'}. Updated ${at.toLocaleTimeString()}.`;
    $('vd-trend-note').textContent = data.tracking_since
      ? `CTEM has tracked fixes since ${new Date(data.tracking_since).toLocaleDateString()}; earlier points read low` : '';
  }

  async function load() {
    const q = new URLSearchParams({ range: $('vd-range').value });
    if ($('vd-source').value) q.set('source', $('vd-source').value);
    if ($('vd-type').value) q.set('device_type', $('vd-type').value);
    history.replaceState(null, '', `?${q}`);
    $('vd-kpis').classList.add('is-loading');
    try {
      const res = await fetch(`/api/v1/vuln-dashboard?${q}`, { headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error(res.status);
      data = await res.json();
      fillFilters(data.filters);
      render();
    } catch (_) {
      $('vd-kpis').innerHTML = '<div class="text-muted text-sm" style="padding:16px">The dashboard could not load. Try again in a minute.</div>';
    } finally {
      $('vd-kpis').classList.remove('is-loading');
    }
  }

  let filled = false;
  function fillFilters(f) {
    if (filled || !f) return;
    filled = true;
    const add = (sel, vals, label) => vals.forEach(v => { const o = document.createElement('option'); o.value = v; o.textContent = label(v); sel.appendChild(o); });
    add($('vd-source'), f.sources, v => v.replace(/_/g, ' '));
    add($('vd-type'), f.device_types, v => v.replace(/_/g, ' '));
    if (init.get('source')) $('vd-source').value = init.get('source');
    if (init.get('device_type')) $('vd-type').value = init.get('device_type');
  }

  document.addEventListener('click', e => {
    const tr = e.target.closest('#vd-topv tr[data-href], #vd-topd tr[data-href]');
    if (tr && !e.target.closest('a')) location.href = tr.dataset.href;
  });
  ['vd-range', 'vd-source', 'vd-type'].forEach(id => $(id).addEventListener('change', load));
  // Charts read colors once per draw, so redraw when the theme flips
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', render);
  new MutationObserver(render).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  if (init.get('range')) $('vd-range').value = init.get('range');
  // the filter options arrive with the first answer; a shared link with filters loads again to apply them
  load().then(() => { if (init.get('source') || init.get('device_type')) load(); });
})();
