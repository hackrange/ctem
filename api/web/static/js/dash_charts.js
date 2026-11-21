// Dashboard charts drawn with ECharts: lines, areas, bars (stacked or with a risk line on a second axis), donuts,
// pies, columns, scatter and bubble maps, and gauges. Colors come from the site's CSS variables when drawn, so
// charts follow the dark and light themes; a dashboard theme swaps the non-severity colors and the card style.
// Text from the server reaches ECharts as data, and the only HTML (tooltips) goes through esc().
(function () {
  const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const n = v => (v == null ? '--' : typeof v === 'number' ? v.toLocaleString() : String(v));
  const THEMES = {
    default: { label: 'Default', card: 'solid', palette: null },
    ocean: { label: 'Ocean glass', card: 'glass', opacity: 75, palette: ['#0ea5e9', '#6366f1', '#14b8a6', '#38bdf8', '#818cf8', '#2dd4bf'] },
    sunset: { label: 'Sunset', card: 'solid', palette: ['#f97316', '#ec4899', '#f59e0b', '#fb7185', '#a855f7', '#facc15'] },
    forest: { label: 'Forest', card: 'solid', palette: ['#16a34a', '#0d9488', '#65a30d', '#4ade80', '#2dd4bf', '#a3e635'] },
    violet: { label: 'Violet glass', card: 'glass', opacity: 75, palette: ['#8b5cf6', '#d946ef', '#6366f1', '#a78bfa', '#e879f9', '#818cf8'] },
    slate: { label: 'Slate outline', card: 'outline', palette: ['#64748b', '#0ea5e9', '#94a3b8', '#475569', '#38bdf8', '#cbd5e1'] },
    neon: { label: 'Neon glass', card: 'glass', opacity: 70, palette: ['#22d3ee', '#a3e635', '#f472b6', '#facc15', '#818cf8', '#34d399'] },
  };
  const NAMED = { blue: '#3b82f6', green: '#22c55e', red: '#ef4444', orange: '#f97316', yellow: '#eab308',
                  purple: '#a855f7', teal: '#14b8a6', gray: '#64748b' };
  let current = 'default';
  const charts = new WeakMap();

  const setTheme = name => { current = THEMES[name] ? name : 'default'; return THEMES[current]; };
  const own = w => (w && w.style && NAMED[w.style.color]) || null;
  const opacity = w => ((w && w.style && w.style.opacity) || THEMES[current].opacity || 100) / 100;

  function color(c) {
    if (!c) return undefined;
    const p = THEMES[current].palette;
    if (p && c === '--accent') return p[0];
    if (p && c === '--severity-info') return p[1];
    return c.startsWith('--') ? css(c) : c;
  }
  function rgba(c, a) {
    if (!c) return c;
    let m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(c.trim());
    if (m) {
      let h = m[1];
      if (h.length === 3) h = h.split('').map(x => x + x).join('');
      return `rgba(${parseInt(h.slice(0, 2), 16)},${parseInt(h.slice(2, 4), 16)},${parseInt(h.slice(4, 6), 16)},${a})`;
    }
    m = /^rgba?\(([^)]+)\)$/i.exec(c.trim());
    if (m) { const p = m[1].split(',').map(s => s.trim()); return `rgba(${p[0]},${p[1]},${p[2]},${a})`; }
    return c;
  }
  const fade = (c, a) => new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: rgba(c, a) }, { offset: 1, color: rgba(c, a * 0.08) }]);

  function theme() {
    const base = ['--severity-info', '--accent', '--severity-low', '--severity-high', '--severity-medium', '--fg-muted', '--severity-critical'].map(css);
    const p = THEMES[current].palette;
    return { fg: css('--fg'), muted: css('--fg-muted'), border: css('--border'), surface: css('--surface'), palette: p ? [...p, ...base] : base };
  }
  const short = v => (Math.abs(v) >= 1e6 ? `${+(v / 1e6).toFixed(1)}M` : Math.abs(v) >= 1e3 ? `${+(v / 1e3).toFixed(1)}k` : v);

  function axisBase(t, narrow) {
    return {
      animationDuration: 500, textStyle: { color: t.fg, fontFamily: 'inherit' }, color: t.palette,
      grid: { left: 6, right: 12, top: narrow ? 14 : 30, bottom: narrow ? 26 : 6, containLabel: true },
      legend: { type: 'scroll', textStyle: { color: t.muted }, icon: 'roundRect', itemWidth: 10, itemHeight: 7,
                ...(narrow ? { bottom: 0 } : { top: 0 }) },
      tooltip: { trigger: 'axis', backgroundColor: t.surface, borderColor: t.border, textStyle: { color: t.fg }, valueFormatter: n,
                 confine: true },
      xAxis: { axisLine: { lineStyle: { color: t.border } }, axisTick: { show: false }, axisLabel: { color: t.muted, hideOverlap: true } },
      yAxis: { axisLabel: { color: t.muted, formatter: short }, splitLine: { lineStyle: { color: t.border, type: 'dashed', opacity: 0.6 } } },
    };
  }

  // The chart lives in .dw-chart under an optional headline; resizing follows the widget.
  function mount(el, d, foot) {
    dispose(el);
    el.innerHTML = `${d.headline ? `<div class="dw-headline">${esc(d.headline)}</div>` : ''}<div class="dw-chart"></div>${foot || ''}`;
    const box = el.querySelector('.dw-chart');
    const chart = echarts.init(box, null, { renderer: 'canvas' });
    const ro = new ResizeObserver(() => chart.resize());
    ro.observe(box);
    charts.set(el, { chart, ro });
    return { chart, narrow: box.clientWidth < 380 };
  }
  function dispose(el) {
    const c = charts.get(el);
    if (c) { c.ro.disconnect(); c.chart.dispose(); charts.delete(el); }
  }
  function clicks(chart, nav) {
    chart.off('click');
    if (nav) chart.on('click', p => { if (p.data && p.data.href) location.href = p.data.href; });
  }

  function series(el, w, d) {
    const { chart, narrow } = mount(el, d);
    const t = theme(), o = axisBase(t, narrow), viz = w.viz, op = opacity(w);
    const list = d.series || [];
    const two = list.some(s => s.axis === 1);
    const yAxis = [{ ...o.yAxis, type: 'value', name: d.y_unit || '', nameTextStyle: { color: t.muted } }];
    if (two) yAxis.push({ ...o.yAxis, type: 'value', name: d.y2_unit || '', nameTextStyle: { color: t.muted }, splitLine: { show: false } });
    chart.setOption({
      ...o, yAxis, xAxis: { ...o.xAxis, type: 'category', data: d.x || [], boundaryGap: viz === 'bar' || viz === 'stacked' },
      dataZoom: (d.x || []).length > 60 ? [{ type: 'inside' }] : [],
      series: list.map((s, i) => {
        const c = (i === 0 && own(w)) || color(s.color) || t.palette[i % t.palette.length];
        const overlay = s.axis === 1 || s.type === 'line';
        const bar = !overlay && (viz === 'bar' || viz === 'stacked');
        const stack = overlay ? undefined : viz === 'stacked' ? 'all' : viz === 'line' ? undefined : s.stack;
        return {
          name: s.name, data: s.data, yAxisIndex: s.axis === 1 ? 1 : 0, type: bar ? 'bar' : 'line', stack, color: c,
          symbol: overlay ? 'circle' : 'none', symbolSize: 6, smooth: 0.3, connectNulls: true, barMaxWidth: 30, barGap: '15%',
          lineStyle: { width: overlay ? 2.5 : 2 }, emphasis: { focus: 'series' },
          itemStyle: bar ? { color: rgba(c, op), borderRadius: stack ? 2 : [5, 5, 0, 0] } : { color: c },
          areaStyle: viz === 'area' && !overlay ? { color: fade(c, Math.min(op, 0.85)) } : undefined,
        };
      }),
    }, true);
  }

  function parts(el, w, d, nav) {
    const items = d.items || [];
    const { chart, narrow } = mount(el, d);
    const t = theme(), op = opacity(w);
    const col = (i, x) => own(w) || color(x.color) || t.palette[i % t.palette.length];
    if (w.viz === 'bar' || w.viz === 'column') {
      const o = axisBase(t, narrow), across = w.viz === 'bar';
      const cat = { type: 'category', inverse: across, data: items.map(i => i.name), axisTick: { show: false },
                    axisLabel: { color: t.muted, width: across ? 120 : 80, overflow: 'truncate', hideOverlap: true }, axisLine: { lineStyle: { color: t.border } } };
      const val = { type: 'value', axisLabel: o.yAxis.axisLabel, splitLine: o.yAxis.splitLine };
      chart.setOption({ ...o, legend: { show: false }, tooltip: { ...o.tooltip, axisPointer: { type: 'shadow' } },
        grid: { ...o.grid, top: 10, bottom: 6 }, xAxis: across ? val : cat, yAxis: across ? cat : val,
        series: [{ type: 'bar', barMaxWidth: 26, data: items.map((x, i) => ({ value: x.value, href: x.href,
                     itemStyle: { color: rgba(col(i, x), op), borderRadius: across ? [0, 5, 5, 0] : [5, 5, 0, 0] } })),
                   label: { show: true, position: across ? 'right' : 'top', color: t.muted, formatter: p => short(p.value) + (d.unit || '') } }],
      }, true);
    } else {
      const wide = !narrow;
      const cx = wide ? '36%' : '50%', cy = wide ? '52%' : '44%';
      const total = items.reduce((a, x) => a + (Number(x.value) || 0), 0);
      const center = d.center || (w.viz === 'donut' ? { value: total, label: d.unit === '%' ? '' : 'total' } : null);
      chart.setOption({
        animationDuration: 500, textStyle: { color: t.fg }, color: t.palette,
        title: center && w.viz === 'donut' ? { text: n(center.value), subtext: center.label || '', left: cx, top: cy, textAlign: 'center',
          textVerticalAlign: 'middle', itemGap: 2, textStyle: { color: t.fg, fontSize: 20, fontWeight: 700 }, subtextStyle: { color: t.muted, fontSize: 11 } } : undefined,
        tooltip: { trigger: 'item', backgroundColor: t.surface, borderColor: t.border, textStyle: { color: t.fg }, confine: true,
                   valueFormatter: v => n(v) + (d.unit || '') },
        legend: wide ? { type: 'scroll', orient: 'vertical', right: 4, top: 'middle', textStyle: { color: t.muted }, icon: 'circle', itemWidth: 8 }
                     : { type: 'scroll', bottom: 0, textStyle: { color: t.muted }, icon: 'circle', itemWidth: 8 },
        series: [{ type: 'pie', radius: w.viz === 'donut' ? ['54%', '78%'] : [0, '76%'], center: [cx, cy], label: { show: false },
                   itemStyle: { borderColor: t.surface, borderWidth: 2, borderRadius: w.viz === 'donut' ? 6 : 3 },
                   data: items.map((x, i) => ({ name: x.name, value: x.value, href: x.href, itemStyle: { color: rgba(col(i, x), op) } })) }],
      }, true);
    }
    clicks(chart, nav);
  }

  function points(el, w, d, nav) {
    const { chart, narrow } = mount(el, d);
    const t = theme(), o = axisBase(t, narrow), op = opacity(w);
    const groups = d.groups || [];
    const big = Math.max(1, ...groups.flatMap(g => g.points.map(p => p[2] || 0)));
    const tip = p => `<b>${esc(p.name)}</b><br>${esc(d.x_label)}: ${esc(n(p.value[0]))}<br>${esc(d.y_label)}: ${esc(n(p.value[1]))}`
      + (d.size_label ? `<br>${esc(d.size_label)}: ${esc(n(p.value[2]))}` : '');
    chart.setOption({
      ...o, tooltip: { trigger: 'item', backgroundColor: t.surface, borderColor: t.border, textStyle: { color: t.fg }, confine: true, formatter: tip },
      grid: { ...o.grid, bottom: narrow ? 30 : 22, left: 14 },
      xAxis: { ...o.xAxis, type: 'value', name: d.x_label, nameLocation: 'middle', nameGap: 22, nameTextStyle: { color: t.muted },
               splitLine: o.yAxis.splitLine, axisLabel: { color: t.muted, formatter: short } },
      yAxis: { ...o.yAxis, type: 'value', name: d.y_label, nameTextStyle: { color: t.muted } },
      series: groups.map((g, i) => {
        const c = (groups.length === 1 && own(w)) || color(g.color) || t.palette[i % t.palette.length];
        return { name: g.name, type: 'scatter', emphasis: { focus: 'series', scale: 1.3 },
                 symbolSize: w.viz === 'bubble' ? v => 6 + 30 * Math.sqrt((v[2] || 0) / big) : 9,
                 itemStyle: { color: rgba(c, op), borderColor: c, borderWidth: 1 },
                 data: g.points.map(p => ({ value: [p[0], p[1], p[2]], name: p[3], href: p[4] })) };
      }),
    }, true);
    clicks(chart, nav);
  }

  function gauge(el, w, d, tint, foot) {
    const { chart } = mount(el, d, foot);
    const t = theme(), max = d.max || 100;
    const c = tint || own(w) || color('--accent');
    chart.setOption({ series: [{
      type: 'gauge', startAngle: 200, endAngle: -20, min: 0, max, radius: '100%', center: ['50%', '62%'],
      progress: { show: true, roundCap: true, width: 14, itemStyle: { color: new echarts.graphic.LinearGradient(0, 0, 1, 0,
        [{ offset: 0, color: rgba(c, 0.55) }, { offset: 1, color: c }]) } },
      axisLine: { roundCap: true, lineStyle: { width: 14, color: [[1, rgba(t.border, 0.7)]] } },
      axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false }, pointer: { show: false }, anchor: { show: false },
      title: { show: false },
      detail: { valueAnimation: true, offsetCenter: [0, '-4%'], fontSize: 26, fontWeight: 700, color: c,
                formatter: v => n(v) + (d.unit || '') },
      data: [{ value: d.value == null ? 0 : d.value }],
    }] }, true);
  }

  // A tiny trend line under a number card (inline SVG: no chart instance needed)
  function spark(vals, c) {
    const v = (vals || []).filter(x => typeof x === 'number');
    if (v.length < 2) return '';
    const lo = Math.min(...v), hi = Math.max(...v), span = hi - lo || 1;
    const pts = v.map((x, i) => `${(i / (v.length - 1) * 100).toFixed(1)},${(28 - (x - lo) / span * 24).toFixed(1)}`);
    const id = `sg${Math.random().toString(36).slice(2, 8)}`;
    return `<svg class="dw-spark" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true">
      <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${c}" stop-opacity=".35"/><stop offset="1" stop-color="${c}" stop-opacity="0"/></linearGradient></defs>
      <polygon points="0,30 ${pts.join(' ')} 100,30" fill="url(#${id})"/><polyline points="${pts.join(' ')}" fill="none" stroke="${c}" stroke-width="1.6" vector-effect="non-scaling-stroke"/></svg>`;
  }

  window.DashCharts = { THEMES, NAMED, setTheme, theme: () => current, own, color, rgba, opacity, series, parts, points, gauge, spark, dispose };
})();
