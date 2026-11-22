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
  // Infrastructure (default), Code, Web apps, or All side by side. The last choice is remembered per browser.
  const KINDS = ['infra', 'code', 'web', 'all'];
  const KIND_NAME = { infra: 'Infrastructure', code: 'Code', web: 'Web apps' };
  const remembered = (() => { try { return localStorage.getItem('ctem.vulnType'); } catch (e) { return null; } })();
  let kind = KINDS.includes(init.get('kind')) ? init.get('kind') : KINDS.includes(remembered) ? remembered : 'infra';
  let allSources = [], byType = {};

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
    // The first five count in the chosen unit: findings, unique vulnerabilities, or fixes
    const u = unit !== 'findings' && data.units ? data.units[unit] : k;
    const fx = s => `/vulns/fixes?kind=${kind}${s ? `&severity=${s}` : ''}`;
    const head = unit === 'fixes' ? [
      tile('Fixes to apply', u.open, fx(''), '', `Each patch, upgrade or rollup once. ${n(u.unassigned_findings)} findings have no fix named by their source.`),
      tile('Fix critical', u.critical, fx('critical'), 'vd-kpi--critical', 'Fixes that resolve at least one critical finding'),
      tile('Fix high', u.high, fx(''), 'vd-kpi--high', 'Fixes whose worst finding is high'),
      tile('Fix KEV', u.kev, fx('kev'), 'vd-kpi--critical', 'Fixes that resolve a known exploited vulnerability'),
      tile('Fix exploitable', u.exploitable, fx('exploitable'), 'vd-kpi--high', 'Fixes that resolve a vulnerability with a public exploit'),
    ] : [
      tile(unit === 'vulns' ? 'Unique vulnerabilities' : 'Open findings', u.open, '/vulns'),
      tile('Critical', u.critical, '/vulns?min_cvss=9', 'vd-kpi--critical'),
      tile('High', u.high, '/vulns?min_cvss=7', 'vd-kpi--high'),
      tile('KEV', u.kev, '/vulns?is_kev=true', 'vd-kpi--critical', 'Known exploited (CISA KEV)'),
      tile('Exploit available', u.exploitable, '/vulns', 'vd-kpi--high'),
    ];
    $('vd-kpis').innerHTML = [
      ...head,
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

  // Sortable by any column; % of findings is each fix's share of the open findings in this view
  let fixSort = { key: 'critical', dir: -1 };
  function fixTable(d) {
    $('vd-allfixes').href = `/vulns/fixes?kind=${kind}`;
    // % of the open findings that have a known fix (not of every finding: many have no fix named by their source yet)
    const total = Math.max(0, ((d.kpis || {}).open || 0) - (((d.units || {}).fixes || {}).unassigned_findings || 0));
    const rows = ((d.units || {}).top_fixes || []).map(f => ({ ...f, pct: total ? f.findings / total * 100 : 0 }));
    const { key, dir } = fixSort;
    rows.sort((a, b) => (key === 'title' ? a.title.localeCompare(b.title) : (a[key] || 0) - (b[key] || 0)) * dir
                        || (b.findings - a.findings));
    document.querySelectorAll('#vd-topf-head [data-fsort]').forEach(b =>
      b.setAttribute('aria-sort', b.dataset.fsort === key ? (dir < 0 ? 'descending' : 'ascending') : 'none'));
    const top = Math.max(0.0001, ...rows.map(f => f.pct));
    const pct = v => (v >= 10 ? v.toFixed(0) : v >= 1 ? v.toFixed(1) : v > 0 ? v.toFixed(2) : '0');
    $('vd-topf').innerHTML = rows.map(f => {
      const href = `/vulns/fixes?kind=${kind}&key=${encodeURIComponent(f.key)}`;
      return `<tr data-href="${esc(href)}" style="cursor:pointer">
        <td class="text-sm"><a class="dt-link" href="${esc(href)}">${esc(f.title.slice(0, 90))}</a>${f.kind === 'rollup' ? ' <span class="chip" style="font-size:.65rem" title="Supersedes older patches">rollup</span>' : ''}</td>
        <td class="text-sm">${esc(n(f.vulns))}</td>
        <td class="text-sm">${f.critical ? `<span class="chip chip--critical" style="font-size:.65rem">${esc(n(f.critical))}</span>` : '0'}</td>
        <td class="text-sm">${f.kev ? `<span class="chip chip--critical" style="font-size:.65rem">${esc(n(f.kev))}</span>` : '0'}</td>
        <td class="text-sm">${esc(n(f.devices))}</td><td class="text-sm">${esc(n(f.findings))}</td>
        <td class="text-sm"><span class="vd-pct"><span style="width:${(f.pct / top * 60).toFixed(1)}px" aria-hidden="true"></span>${esc(pct(f.pct))}%</span></td></tr>`;
    }).join('') || `<tr><td colspan="7" class="text-muted text-sm" style="text-align:center;padding:16px">${
      kind === 'web' ? 'Web scanners name no shared fixes; each finding is its own.' : 'No fixes recorded yet. They arrive with each source\'s next full sync.'}</td></tr>`;
  }

  $('vd-topf-head').addEventListener('click', e => {
    const b = e.target.closest('[data-fsort]');
    if (!b || !data) return;
    const k = b.dataset.fsort;
    fixSort = { key: k, dir: fixSort.key === k ? -fixSort.dir : (k === 'title' ? 1 : -1) };
    fixTable(data);
  });

  function tables(d) {
    fixTable(d);
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
    const what = { infra: 'Infrastructure: hosts, network and cloud', code: 'Code: repositories (SAST, packages, secrets, IaC)',
                   web: 'Web apps: DAST and web application scanning' }[kind];
    $('vd-sub').textContent = `${what}, ${data.scoped ? 'for the devices you can see' : 'across every device'}. Updated ${at.toLocaleTimeString()}.`;
    $('vd-trend-note').textContent = data.tracking_since
      ? `CTEM has tracked fixes since ${new Date(data.tracking_since).toLocaleDateString()}; earlier points read low` : '';
  }

  // All: the three types side by side, never added together
  async function loadAll() {
    $('vd-kpis').hidden = true;
    document.querySelector('.vd-grid').hidden = true;
    $('vd-all').hidden = false;
    const q = new URLSearchParams({ range: $('vd-range').value, kind: 'all' });
    history.replaceState(null, '', `?${q}`);
    $('vd-all').innerHTML = '<div class="text-muted text-sm">Loading...</div>';
    const one = async k => {
      try {
        const r = await fetch(`/api/v1/vuln-dashboard?range=${encodeURIComponent($('vd-range').value)}&kind=${k}`, { headers: { Accept: 'application/json' } });
        return r.ok ? r.json() : null;
      } catch (e) { return null; }
    };
    if (pending) { pending.abort(); pending = null; }   // a single-tab answer still on its way no longer applies
    const [a, b, c] = await Promise.all(['infra', 'code', 'web'].map(one));
    if (kind !== 'all') return;   // they moved on while it loaded
    if (a) fillFilters(a.filters);
    const spark = tr => {
      const tot = (tr.days || []).map((_, i) => SEV.reduce((s, k) => s + ((tr[k] || [])[i] || 0), 0));
      if (tot.length < 2) return '';
      const hi = Math.max(...tot) || 1, lo = Math.min(...tot);
      const pts = tot.map((v, i) => `${(i / (tot.length - 1) * 400).toFixed(1)},${(110 - (v - lo) / ((hi - lo) || 1) * 100).toFixed(1)}`).join(' ');
      return `<svg viewBox="0 0 400 120" preserveAspectRatio="none" role="img" aria-label="Open findings over the range"><polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="2.5"></polyline></svg>`;
    };
    const col = (k, d) => {
      if (!d) return `<section class="vd-col"><h2>${KIND_NAME[k]}</h2><p class="vd-col__note">Couldn't load.</p></section>`;
      const x = d.kpis || {};
      const row = (l, v) => `<div class="vd-col__row"><span>${esc(l)}</span><b>${esc(n(v))}</b></div>`;
      return `<section class="vd-col"><div style="display:flex;justify-content:space-between;align-items:baseline"><h2>${KIND_NAME[k]}</h2>
        <button type="button" class="btn btn--ghost btn--sm" data-open="${k}">Open tab</button></div>
        ${row('Open findings', x.open)}${row('Critical', x.critical)}${row('Known exploited (KEV)', x.kev)}${row('Past SLA', x.past_sla)}
        ${row(k === 'infra' ? 'Hosts affected' : k === 'code' ? 'Repositories affected' : 'Sites affected', x.devices)}${spark(d.trend || {})}</section>`;
    };
    $('vd-all').innerHTML = col('infra', a) + col('code', b) + col('web', c)
      + '<p class="vd-col__note" style="grid-column:1/-1">The three are shown side by side and never added together: different work for different teams.</p>';
    $('vd-sub').textContent = 'Infrastructure, Code and Web apps side by side.';
  }

  // Count by findings, unique vulnerabilities, or fixes (remembered, and kept in the link)
  const UNITS = ['findings', 'vulns', 'fixes'];
  let unit = UNITS.includes(init.get('count')) ? init.get('count') : (() => {
    try { const u = localStorage.getItem('ctem.vulnUnit'); return UNITS.includes(u) ? u : 'findings'; } catch (e) { return 'findings'; }
  })();
  const pressUnit = () => document.querySelectorAll('#vd-unit [data-unit]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.unit === unit)));
  pressUnit();
  $('vd-unit').addEventListener('click', e => {
    const b = e.target.closest('[data-unit]');
    if (!b || b.dataset.unit === unit) return;
    unit = b.dataset.unit;
    try { localStorage.setItem('ctem.vulnUnit', unit); } catch (err) { /* not remembered, still works */ }
    pressUnit();
    const q = new URLSearchParams(location.search);
    q.set('count', unit);
    history.replaceState(null, '', `?${q}`);
    render();   // the counts are already here: no reload
  });

  let pending = null;
  async function load() {
    try { localStorage.setItem('ctem.vulnType', kind); } catch (e) { /* not remembered, still works */ }
    $('vd-source').disabled = kind === 'all';
    if (kind === 'all') { status(''); return loadAll(); }
    $('vd-all').hidden = true;
    $('vd-kpis').hidden = false;
    document.querySelector('.vd-grid').hidden = false;
    const q = new URLSearchParams({ range: $('vd-range').value, kind });
    if ($('vd-source').value) q.set('source', $('vd-source').value);
    if (kind === 'infra' && $('vd-type').value) q.set('device_type', $('vd-type').value);
    if (unit !== 'findings') q.set('count', unit);
    history.replaceState(null, '', `?${q}`);
    // Only the latest click counts: an earlier, slower answer is dropped instead of replacing the newer one
    if (pending) pending.abort();
    const mine = pending = new AbortController();
    $('vd-kpis').classList.add('is-loading');
    if (!data) document.querySelector('.vd-grid').hidden = true;   // no empty charts while the first answer comes
    status('Loading the dashboard...', true);
    const slow = setTimeout(() => mine === pending && status('Still working: your view is being built from the latest data, which can take about 15 seconds the first time.', true), 4000);
    const limit = setTimeout(() => { mine.timedOut = true; mine.abort(); }, 120000);
    try {
      const res = await fetch(`/api/v1/vuln-dashboard?${q}`, { headers: { Accept: 'application/json' }, signal: mine.signal });
      if (!res.ok) throw new Error(res.status);
      const got = await res.json();
      if (mine !== pending) return;
      data = got;
      fillFilters(data.filters);
      document.querySelector('.vd-grid').hidden = false;
      status('');
      render();
    } catch (e) {
      if (mine !== pending || (e.name === 'AbortError' && !mine.timedOut)) return;
      status(mine.timedOut ? 'The dashboard is taking too long to load.' : 'The dashboard could not load.', false, true);
    } finally {
      clearTimeout(slow);
      clearTimeout(limit);
      if (mine === pending) { pending = null; $('vd-kpis').classList.remove('is-loading'); }
    }
  }
  // What the page is doing while an answer is on its way, or why it has none (with a way to try again)
  function status(text, busy, failed) {
    let el = $('vd-status');
    if (!el) {
      el = document.createElement('div');
      el.id = 'vd-status';
      el.className = 'vd-status';
      el.setAttribute('role', 'status');
      el.setAttribute('aria-live', 'polite');
      $('vd-kpis').before(el);
    }
    el.hidden = !text;
    el.classList.toggle('is-error', !!failed);
    el.innerHTML = text ? `${busy ? '<span class="vd-spin" aria-hidden="true"></span>' : ''}<span>${esc(text)}</span>${failed
      ? ' <button type="button" class="btn btn--ghost btn--sm" id="vd-retry">Try again</button>' : ''}` : '';
    if (failed) $('vd-retry').onclick = () => load();
  }

  let filled = false;
  const add = (sel, vals, label) => vals.forEach(v => { const o = document.createElement('option'); o.value = v; o.textContent = label(v); sel.appendChild(o); });
  // The source list follows the buttons: only application scanners under Application, the rest under Non application
  function sourceOptions() {
    const sel = $('vd-source'), cur = sel.value;
    const list = kind === 'all' ? allSources : (byType[kind] || []);
    sel.innerHTML = '<option value="">All sources</option>';
    add(sel, list, v => v.replace(/_/g, ' '));
    sel.value = list.includes(cur) ? cur : '';
    return sel.value === cur;
  }
  function fillFilters(f) {
    if (filled || !f) return;
    filled = true;
    allSources = f.sources || [];
    byType = f.by_type || {};
    sourceOptions();
    hostTypes = (f.device_types || []).filter(v => !APP_TYPES.includes(v));
    typeOptions();
    if (init.get('source')) { $('vd-source').value = init.get('source'); }
    if (init.get('device_type') && hostTypes.includes(init.get('device_type')) && kind === 'infra') $('vd-type').value = init.get('device_type');
  }
  // The device type follows the tab: Code is all repositories and Web apps all sites, so there it shows that type and
  // is locked (a "server" left over from Infrastructure would otherwise match nothing). Infrastructure lists the
  // host types and keeps the one picked there.
  const APP_TYPES = ['code_repository', 'website'];
  const TAB_TYPE = { code: 'code_repository', web: 'website' };
  let hostTypes = [], hostPick = '';
  function typeOptions() {
    const sel = $('vd-type');
    if (!sel.disabled && hostTypes.length > 1) hostPick = sel.value;
    const fixed = TAB_TYPE[kind];
    sel.innerHTML = '';
    if (fixed) {
      add(sel, [fixed], v => v.replace(/_/g, ' '));
      sel.value = fixed;
    } else if (hostTypes.length === 1) {
      // one type is the same as all of them, so just name it (and filter nothing)
      sel.innerHTML = `<option value="">${esc(hostTypes[0].replace(/_/g, ' '))}</option>`;
    } else {
      sel.innerHTML = '<option value="">All device types</option>';
      add(sel, hostTypes, v => v.replace(/_/g, ' '));
      sel.value = hostTypes.includes(hostPick) ? hostPick : '';
    }
    sel.disabled = !!fixed || hostTypes.length === 1;
    sel.hidden = kind === 'all';
    sel.title = fixed ? `The ${kind === 'code' ? 'Code' : 'Web apps'} tab is all ${fixed === 'website' ? 'websites' : 'code repositories'}` : '';
  }
  function pressKind() {
    document.querySelectorAll('#vd-kind [data-kind]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.kind === kind)));
  }
  $('vd-all').addEventListener('click', e => {
    const b = e.target.closest('[data-open]');
    if (b) { kind = b.dataset.open; pressKind(); sourceOptions(); typeOptions(); load(); }
  });
  $('vd-kind').addEventListener('click', e => {
    const b = e.target.closest('[data-kind]');
    if (!b || b.dataset.kind === kind) return;
    kind = b.dataset.kind;
    pressKind();
    sourceOptions();   // a source from the other side no longer applies
    typeOptions();
    load();
  });
  pressKind();

  document.addEventListener('click', e => {
    const tr = e.target.closest('#vd-topv tr[data-href], #vd-topd tr[data-href], #vd-topf tr[data-href]');
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
