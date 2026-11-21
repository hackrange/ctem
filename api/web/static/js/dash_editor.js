// The widget editor (pick a metric, chart type and options, with a live preview) and the AI "describe a widget" box.
(function () {
  const VIZ = { kpi: 'Number', line: 'Line', area: 'Area', bar: 'Bars', donut: 'Donut', table: 'Table' };
  const uid = () => Math.random().toString(36).slice(2, 14);

  async function preview(el, w) {
    DashRender.render(el, w, null, false);
    const r = await DashRender.api('POST', '/api/v1/dashboards/data', { widgets: [{ ...w, id: 'preview' }] });
    DashRender.render(el, w, (r.data || {}).preview || { error: r.error || 'No preview' }, false);
  }

  // opts: { catalog: [metric specs], widget?: existing, onSave(widget) }
  function open(opts) {
    const cat = opts.catalog;
    const byId = Object.fromEntries(cat.map(m => [m.id, m]));
    const cats = [...new Set(cat.map(m => m.category))];
    const w = opts.widget ? JSON.parse(JSON.stringify(opts.widget)) : null;
    const d = DashRender.dialog('dw-editor', w && !opts.isNew ? 'Edit widget' : 'Add a widget', 820);
    d.body.innerHTML = `<div class="dw-edit">
      ${opts.note ? `<div class="tk-note" style="grid-column:1/-1">The AI noted: ${esc(opts.note)}</div>` : ''}
      <div class="dw-edit__form">
        <label class="form-label" for="dwe-cat">Data</label>
        <select id="dwe-cat" class="form-input">${cats.map(c => `<option>${esc(c)}</option>`).join('')}</select>
        <label class="form-label" for="dwe-metric" style="margin-top:8px">Metric</label>
        <select id="dwe-metric" class="form-input"></select>
        <div id="dwe-about" class="text-sm text-muted" style="margin-top:4px"></div>
        <label class="form-label" for="dwe-viz" style="margin-top:8px">Show as</label>
        <select id="dwe-viz" class="form-input"></select>
        <div id="dwe-params"></div>
        <label class="form-label" for="dwe-title" style="margin-top:8px">Title</label>
        <input id="dwe-title" class="form-input" maxlength="120">
      </div>
      <div class="dw-edit__preview"><div class="text-sm text-muted" style="margin-bottom:4px">Preview (your data)</div>
        <div id="dwe-preview" class="dw-body" style="height:260px;border:1px solid var(--border);border-radius:8px"></div></div>
    </div>`;
    const $ = id => document.getElementById(id);
    let titleTouched = !!w;

    function fillMetrics(sel) {
      const list = cat.filter(m => m.category === $('dwe-cat').value);
      $('dwe-metric').innerHTML = list.map(m => `<option value="${esc(m.id)}">${esc(m.label)}</option>`).join('');
      if (sel) $('dwe-metric').value = sel;
      fillMetric();
    }
    function fillMetric(params) {
      const m = byId[$('dwe-metric').value];
      $('dwe-about').textContent = m.description || '';
      $('dwe-viz').innerHTML = m.viz.map(v => `<option value="${v}">${VIZ[v] || v}</option>`).join('');
      if (w && w.metric === m.id) $('dwe-viz').value = w.viz;
      $('dwe-params').innerHTML = m.params.map(p => {
        const id = `dwp-${p.key}`, cur = params && params[p.key] != null ? params[p.key] : p.default;
        if (p.choices) return `<label class="form-label" for="${id}" style="margin-top:8px">${esc(p.label)}</label>
          <select id="${id}" class="form-input" data-p="${esc(p.key)}">${p.choices.map(c =>
            `<option value="${esc(c.value)}"${String(c.value) === String(cur) ? ' selected' : ''}>${esc(c.label)}</option>`).join('')}</select>`;
        if (p.type === 'int') return `<label class="form-label" for="${id}" style="margin-top:8px">${esc(p.label)}</label>
          <input id="${id}" type="number" class="form-input" data-p="${esc(p.key)}" min="${p.min}" max="${p.max}" value="${esc(cur)}">`;
        return `<label class="tk-radio" style="margin-top:10px"><input id="${id}" type="checkbox" data-p="${esc(p.key)}"${cur ? ' checked' : ''}> ${esc(p.label)}</label>`;
      }).join('');
      if (!titleTouched) $('dwe-title').value = m.label;
      refresh();
    }
    function current() {
      const m = byId[$('dwe-metric').value];
      const params = {};
      d.body.querySelectorAll('[data-p]').forEach(el => {
        const p = m.params.find(x => x.key === el.dataset.p);
        params[p.key] = el.type === 'checkbox' ? el.checked : p.type === 'int' ? Number(el.value) : el.value;
      });
      const small = m.shape === 'value';
      return { id: w ? w.id : uid(), metric: m.id, viz: $('dwe-viz').value, title: $('dwe-title').value.trim() || m.label, params,
               x: w ? w.x : 0, y: w ? w.y : 0, w: w ? w.w : (small ? 3 : 6), h: w ? w.h : (small ? 2 : 4) };
    }
    let t;
    function refresh() { clearTimeout(t); t = setTimeout(() => preview($('dwe-preview'), current()), 250); }

    $('dwe-cat').onchange = () => fillMetrics();
    $('dwe-metric').onchange = () => fillMetric();
    $('dwe-viz').onchange = refresh;
    $('dwe-params').addEventListener('change', refresh);
    $('dwe-title').addEventListener('input', () => { titleTouched = true; });
    if (w && byId[w.metric]) {
      $('dwe-cat').value = byId[w.metric].category;
      fillMetrics(w.metric);
      fillMetric(w.params);
      $('dwe-title').value = w.title;
    } else fillMetrics();
    d.button('Cancel', 'btn--ghost', () => { DashRender.dispose($('dwe-preview')); d.close(); });
    d.button(w && !opts.isNew ? 'Update widget' : 'Add to dashboard', 'btn--primary', () => {
      const out = current();
      if (/[<>]/.test(out.title)) return d.msg("Please don't use < or > in the title.", true);
      DashRender.dispose($('dwe-preview'));
      d.close();
      opts.onSave(out);
    });
  }

  // AI: describe a widget in plain words; the result opens in the editor to check before it's added
  function describe(opts) {
    const d = DashRender.dialog('dw-ai', 'Describe a widget', 560);
    d.body.innerHTML = `<p class="text-sm text-muted" style="margin-top:0">For example: "critical KEV findings on servers over the last 90 days" or
      "how many devices are hidden in Falcon".</p>
      <textarea id="dwa-text" class="form-input" rows="3" maxlength="1000"></textarea>`;
    d.button('Cancel', 'btn--ghost', d.close);
    const go = d.button('Draft it', 'btn--primary', async () => {
      const text = document.getElementById('dwa-text').value.trim();
      if (text.length < 5) return d.msg('Describe the widget first.', true);
      go.disabled = true;
      d.msg('Asking the AI...');
      const r = await DashRender.api('POST', '/api/v1/dashboards/ai/widget', { text });
      go.disabled = false;
      if (r.available === false) return d.msg('No AI integration is set up. Use Add widget instead, or add one under Integrations.', true);
      if (!r.widget) return d.msg(r.error || 'The AI had no suggestion. Try rewording it.', true);
      d.close();
      open({ catalog: opts.catalog, widget: r.widget, onSave: opts.onSave, note: r.note, isNew: true });
    });
  }

  window.DashEditor = { open, describe };
})();
