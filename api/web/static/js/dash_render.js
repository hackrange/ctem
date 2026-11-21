// Draws one dashboard widget from its data: a number tile, an ECharts chart, or a table. Also a small dialog helper.
// Text from the server goes through esc() in HTML, or into ECharts as data (ECharts draws text, it doesn't parse HTML).
(function () {
  const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const color = c => (c && c.startsWith('--') ? css(c) : c) || undefined;
  const n = v => (v == null ? '--' : typeof v === 'number' ? v.toLocaleString() : String(v));
  const charts = new WeakMap();

  function theme() {
    return { fg: css('--fg'), muted: css('--fg-muted'), border: css('--border'), surface: css('--surface'),
             palette: ['--severity-info', '--accent', '--severity-low', '--severity-high', '--severity-medium', '--fg-muted', '--severity-critical'].map(css) };
  }

  function axisBase(t) {
    return {
      textStyle: { color: t.fg, fontFamily: 'inherit' }, color: t.palette,
      grid: { left: 6, right: 12, top: 30, bottom: 6, containLabel: true },
      legend: { top: 0, type: 'scroll', textStyle: { color: t.muted }, icon: 'roundRect', itemWidth: 10, itemHeight: 7 },
      tooltip: { trigger: 'axis', backgroundColor: t.surface, borderColor: t.border, textStyle: { color: t.fg }, valueFormatter: n },
      xAxis: { axisLine: { lineStyle: { color: t.border } }, axisLabel: { color: t.muted } },
      yAxis: { axisLabel: { color: t.muted, formatter: v => (v >= 1e6 ? `${v / 1e6}M` : v >= 1e3 ? `${v / 1e3}k` : v) },
               splitLine: { lineStyle: { color: t.border, type: 'dashed' } } },
    };
  }

  function chartIn(el) {
    let c = charts.get(el);
    if (!c) {
      c = echarts.init(el, null, { renderer: 'canvas' });
      charts.set(el, c);
      new ResizeObserver(() => c.resize()).observe(el);
    }
    return c;
  }

  function dispose(el) {
    const c = charts.get(el);
    if (c) { c.dispose(); charts.delete(el); }
  }

  function series(el, w, d) {
    const t = theme(), o = axisBase(t), viz = w.viz;
    const many = (d.x || []).length > 40;
    chartIn(el).setOption({
      ...o, xAxis: { ...o.xAxis, type: 'category', data: d.x || [], boundaryGap: viz === 'bar' },
      yAxis: { ...o.yAxis, type: 'value', name: d.y_unit || '', nameTextStyle: { color: t.muted } },
      dataZoom: many ? [{ type: 'inside' }] : [],
      series: (d.series || []).map(s => ({
        name: s.name, data: s.data, color: color(s.color), stack: viz === 'line' ? undefined : s.stack,
        type: viz === 'bar' ? 'bar' : 'line', symbol: 'none', smooth: 0.2, connectNulls: true, barMaxWidth: 28,
        areaStyle: viz === 'area' ? { opacity: 0.35 } : undefined,
      })),
    }, true);
  }

  function parts(el, w, d, nav) {
    const t = theme(), items = d.items || [];
    const c = chartIn(el);
    if (w.viz === 'bar') {
      const o = axisBase(t);
      c.setOption({ ...o, legend: { show: false }, tooltip: { ...o.tooltip, axisPointer: { type: 'shadow' } },
        grid: { ...o.grid, top: 8 }, xAxis: { ...o.xAxis, type: 'value', axisLabel: o.yAxis.axisLabel, splitLine: o.yAxis.splitLine },
        yAxis: { type: 'category', inverse: true, data: items.map(i => i.name), axisLabel: { color: t.muted, width: 120, overflow: 'truncate' },
                 axisLine: { lineStyle: { color: t.border } } },
        series: [{ type: 'bar', barMaxWidth: 22, data: items.map(i => ({ value: i.value, href: i.href, itemStyle: { color: color(i.color) } })),
                   label: { show: true, position: 'right', color: t.muted, formatter: p => n(p.value) + (d.unit || '') } }],
      }, true);
    } else {
      c.setOption({ textStyle: { color: t.fg }, color: t.palette,
        tooltip: { trigger: 'item', backgroundColor: t.surface, borderColor: t.border, textStyle: { color: t.fg },
                   valueFormatter: v => n(v) + (d.unit || '') },
        legend: { type: 'scroll', orient: 'vertical', right: 4, top: 'middle', textStyle: { color: t.muted } },
        series: [{ type: 'pie', radius: ['45%', '74%'], center: ['36%', '52%'], label: { show: false },
                   itemStyle: { borderColor: t.surface, borderWidth: 2, borderRadius: 4 },
                   data: items.map(i => ({ name: i.name, value: i.value, href: i.href, itemStyle: { color: color(i.color) } })) }],
      }, true);
    }
    c.off('click');
    if (nav) c.on('click', p => { if (p.data && p.data.href) location.href = p.data.href; });
  }

  function table(el, cols, rows, hrefs) {
    el.innerHTML = `<div style="overflow:auto;height:100%"><table class="data-table data-table--striped" style="font-size:.85rem">
      <thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead>
      <tbody>${rows.map((r, i) => `<tr${hrefs && hrefs[i] ? ` data-href="${esc(hrefs[i])}" style="cursor:pointer"` : ''}>${r.map((v, j) =>
        `<td>${j === 0 && hrefs && hrefs[i] ? `<a class="dt-link" href="${esc(hrefs[i])}">${esc(n(v))}</a>` : esc(n(v))}</td>`).join('')}</tr>`).join('')
        || `<tr><td colspan="${cols.length}" class="text-muted" style="text-align:center;padding:14px">Nothing here</td></tr>`}</tbody></table></div>`;
  }

  // el: the widget body. w: widget config. d: its data. nav: clicks navigate (off while editing).
  function render(el, w, d, nav = true) {
    if (!d) { dispose(el); el.innerHTML = '<div class="dw-msg text-muted">Loading...</div>'; return; }
    if (d.error) { dispose(el); el.innerHTML = `<div class="dw-msg text-muted">${esc(d.error)}</div>`; return; }
    if (d.shape === 'value') {
      dispose(el);
      const v = d.value == null ? '--' : n(d.value) + (d.unit || '');
      el.innerHTML = `${nav && d.href ? `<a class="dw-kpi" href="${esc(d.href)}">` : '<div class="dw-kpi">'}
        <span class="dw-kpi__value">${esc(v)}</span>${d.note ? `<span class="dw-kpi__note">${esc(d.note)}</span>` : ''}
        ${nav && d.href ? '</a>' : '</div>'}`;
      return;
    }
    if (d.shape === 'table' || (d.shape === 'parts' && w.viz === 'table')) {
      dispose(el);
      if (d.shape === 'parts') table(el, ['', 'Count'], (d.items || []).map(i => [i.name, i.value]), (d.items || []).map(i => (nav ? i.href : null)));
      else table(el, d.columns || [], d.rows || [], nav ? d.hrefs : null);
      return;
    }
    el.innerHTML = '';
    if (d.shape === 'series') series(el, w, d);
    else parts(el, w, d, nav);
    if (d.note) el.title = d.note;
  }

  // A dialog that only closes from its own buttons, so a stray click outside never loses what was typed.
  function dialog(id, title, width = 640) {
    let wrap = document.getElementById(id);
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = id;
      wrap.className = 'tk-backdrop';
      wrap.setAttribute('role', 'dialog');
      wrap.setAttribute('aria-modal', 'true');
      document.body.appendChild(wrap);
    }
    wrap.innerHTML = `<div class="tk-dialog" style="max-width:${width}px;max-height:90vh;overflow:auto">
      <h2 class="tk-title"></h2><div class="dlg-body"></div>
      <div class="dlg-msg text-sm" style="min-height:1.2em;margin-top:8px"></div>
      <div class="dlg-actions" style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px"></div></div>`;
    wrap.querySelector('.tk-title').textContent = title;
    wrap.classList.add('is-open');
    const actions = wrap.querySelector('.dlg-actions');
    return {
      body: wrap.querySelector('.dlg-body'),
      msg: (t, bad) => { const m = wrap.querySelector('.dlg-msg'); m.style.color = bad ? 'var(--severity-critical)' : 'var(--fg-muted)'; m.textContent = t || ''; },
      button(label, cls, fn) { const b = document.createElement('button'); b.type = 'button'; b.className = `btn ${cls} btn--sm`; b.textContent = label; b.onclick = fn; actions.appendChild(b); return b; },
      close: () => wrap.classList.remove('is-open'),
    };
  }

  async function api(method, url, body) {
    const res = await fetch(url, { method, headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
                                   body: body ? JSON.stringify(body) : undefined });
    if (res.status === 422) return { ok: false, error: 'Check the form: a name without < or >, and fewer than 40 widgets.' };
    if (!res.ok) return { ok: false, error: res.status === 404 ? "That isn't available to you." : 'Something went wrong. Try again.' };
    return res.json();
  }

  window.DashRender = { render, dispose, dialog, api };
})();
