// Draws one dashboard widget from its data: a number card (with its change and a sparkline), a gauge, a chart
// (dash_charts.js), or a table. Also a small dialog helper and the API call wrapper.
// Text from the server goes through esc() in HTML, or into ECharts as data (ECharts draws text, it doesn't parse HTML).
(function () {
  const n = v => (v == null ? '--' : typeof v === 'number' ? v.toLocaleString() : String(v));
  const C = () => window.DashCharts;
  function level(w, v) {
    const s = (w && w.style) || {};
    if (typeof v !== 'number' || (s.warn_at == null && s.bad_at == null)) return null;
    const worse = (a, b) => (s.higher_is_worse === false ? a <= b : a >= b);
    if (s.bad_at != null && worse(v, s.bad_at)) return 'critical';
    if (s.warn_at != null && worse(v, s.warn_at)) return 'medium';
    return 'low';
  }

  function table(el, cols, rows, hrefs) {
    el.innerHTML = `<div class="dw-table"><table class="data-table data-table--striped">
      <thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead>
      <tbody>${rows.map((r, i) => `<tr${hrefs && hrefs[i] ? ` data-href="${esc(hrefs[i])}" style="cursor:pointer"` : ''}>${r.map((v, j) =>
        `<td>${j === 0 && hrefs && hrefs[i] ? `<a class="dt-link" href="${esc(hrefs[i])}">${esc(n(v))}</a>` : esc(n(v))}</td>`).join('')}</tr>`).join('')
        || `<tr><td colspan="${cols.length}" class="text-muted" style="text-align:center;padding:14px">Nothing here</td></tr>`}</tbody></table></div>`;
  }

  // "↑ 3.9%" in green when the change is good news, red when it isn't
  function deltaChip(dl) {
    if (!dl || typeof dl.pct !== 'number') return '';
    const good = dl.pct === 0 ? null : (dl.pct < 0) === (dl.better !== 'up');
    const arrow = dl.pct > 0 ? '&#9650;' : dl.pct < 0 ? '&#9660;' : '=';
    return `<span class="dw-delta ${good == null ? '' : good ? 'is-good' : 'is-bad'}" title="Was ${esc(n(dl.was))}">${arrow} ${esc(Math.abs(dl.pct).toLocaleString())}%</span>`;
  }

  function kpi(el, w, d, nav) {
    const v = d.value == null ? '--' : n(d.value) + (d.unit || '');
    const lv = level(w, d.value), tint = lv ? `var(--severity-${lv})` : C().own(w);
    const sc = C().own(w) || C().color('--accent');
    const tag = nav && d.href ? 'a' : 'div';
    el.innerHTML = `<${tag} class="dw-kpi${lv === 'critical' ? ' dw-kpi--alert' : ''}"${tag === 'a' ? ` href="${esc(d.href)}" title="Show these"` : ''}>
      <span class="dw-kpi__row"><span class="dw-kpi__value"${tint ? ` style="color:${tint}"` : ''}>${esc(v)}</span>${deltaChip(d.delta)}</span>
      ${d.note ? `<span class="dw-kpi__note">${esc(d.note)}</span>` : ''}${C().spark(d.spark, sc)}</${tag}>`;
  }

  // el: the widget body. w: widget config. d: its data. nav: clicks navigate (off while editing).
  function render(el, w, d, nav = true) {
    C().dispose(el);
    el.title = '';
    if (!d) { el.innerHTML = '<div class="dw-msg"><span class="dw-skeleton"></span></div>'; return; }
    if (d.error) { el.innerHTML = `<div class="dw-msg text-muted">${esc(d.error)}</div>`; return; }
    if (d.shape === 'value') {
      if (w.viz === 'gauge' && d.value != null) {
        const lv = level(w, d.value);
        const foot = `<div class="dw-gauge-foot">${deltaChip(d.delta)}${d.note ? `<span>${esc(d.note)}</span>` : ''}</div>`;
        C().gauge(el, w, d, lv ? getComputedStyle(document.documentElement).getPropertyValue(`--severity-${lv}`).trim() : null, foot);
        if (nav && d.href) { el.style.cursor = 'pointer'; el.onclick = e => { if (!e.target.closest('a')) location.href = d.href; }; }
        return;
      }
      el.onclick = null;
      el.style.cursor = '';
      kpi(el, w, d, nav);
      return;
    }
    el.onclick = null;
    el.style.cursor = '';
    if (d.shape === 'table' || (d.shape === 'parts' && w.viz === 'table')) {
      if (d.shape === 'parts') table(el, ['', 'Count'], (d.items || []).map(i => [i.name, i.value]), (d.items || []).map(i => (nav ? i.href : null)));
      else table(el, d.columns || [], d.rows || [], nav ? d.hrefs : null);
      if (d.headline) el.insertAdjacentHTML('afterbegin', `<div class="dw-headline">${esc(d.headline)}</div>`);
      return;
    }
    if (d.shape === 'series') C().series(el, w, d);
    else if (d.shape === 'points') C().points(el, w, d, nav);
    else C().parts(el, w, d, nav);
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

  // The AI asked back instead of guessing: show its question with its suggested answers and a box for your own.
  // onAnswer gets "question -> answer", which goes back with the original request.
  function clarify(box, q, onAnswer) {
    box.hidden = false;
    box.innerHTML = `<div class="ai-q"><div class="ai-q__text"><b>The AI asks:</b> ${esc(q.question)}</div>
      <div class="ai-q__opts">${(q.options || []).map((o, i) => `<button type="button" class="btn btn--ghost btn--sm" data-opt="${i}">${esc(o)}</button>`).join('')}</div>
      <div class="ai-q__own"><input class="form-input" maxlength="400" placeholder="Or type your own answer" aria-label="Your answer">
        <button type="button" class="btn btn--primary btn--sm">Answer</button></div></div>`;
    const send = a => { if (!a) return; box.innerHTML = ''; box.hidden = true; onAnswer(`${q.question} -> ${a}`.slice(0, 600)); };
    box.querySelectorAll('[data-opt]').forEach(b => { b.onclick = () => send(q.options[Number(b.dataset.opt)]); });
    const inp = box.querySelector('input');
    box.querySelector('.ai-q__own .btn').onclick = () => send(inp.value.trim());
    inp.onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); send(inp.value.trim()); } };
  }

  async function api(method, url, body) {
    const res = await fetch(url, { method, headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
                                   body: body ? JSON.stringify(body) : undefined });
    if (res.status === 422) return { ok: false, error: 'Check the form: a name without < or >, and fewer than 40 widgets.' };
    if (!res.ok) return { ok: false, error: res.status === 404 ? "That isn't available to you." : 'Something went wrong. Try again.' };
    return res.json();
  }

  window.DashRender = { render, dispose: el => C().dispose(el), dialog, api, clarify };
})();
