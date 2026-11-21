// Admin > Tag mapping: say what your tags mean (executive owner, application, environment...).
// Each role has prefixes ("starts with") or exact tags; a live preview shows what they match. Everything goes through esc().
(() => {
  const BASE = '/api/v1/tag-roles';
  const pane = () => document.getElementById('pane-tags');
  let roles = [], suggestions = [], dirty = {};

  async function call(method, path, body) {
    const res = await fetch(BASE + path, { method, credentials: 'same-origin',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body) });
    const d = await res.json().catch(() => ({}));
    if (res.status === 422) throw new Error('Check the values: a prefix is 1 to 128 characters, a name up to 60.');
    if (!res.ok) throw new Error('The server refused that change.');
    if (d.ok === false) throw new Error(d.error || 'The server refused that change.');
    return d;
  }

  const ruleText = r => `${r.match === 'exact' ? 'is exactly' : 'starts with'} ${r.value}`;
  const roleOf = key => roles.find(r => r.key === key);

  function card(r) {
    const rules = (r.rules || []).map((x, i) => `<span class="chip chip--info" style="font-size:.75rem">${esc(ruleText(x))}
        <button type="button" class="btn btn--ghost btn--sm" data-del-rule="${i}" aria-label="Remove this rule" title="Remove">&#10005;</button></span>`).join(' ')
      || '<span class="text-sm text-muted">No tags mapped yet.</span>';
    return `<div class="panel tm-card" data-role="${esc(r.key)}" style="margin-bottom:12px">
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <input class="form-input" data-f="name" value="${esc(r.name)}" maxlength="60" aria-label="Role name" style="max-width:240px;font-weight:600">
        ${r.builtin ? '<span class="chip chip--low" style="font-size:.7rem" title="CTEM features read this role">Built-in</span>' : ''}
        <label class="tk-radio"><input type="checkbox" data-f="show_filter"${r.show_filter ? ' checked' : ''}> Dashboard filter</label>
        <label class="tk-radio" title="Show jeff davis as Jeff Davis"><input type="checkbox" data-f="title_case"${r.title_case ? ' checked' : ''}> Title case values</label>
        <span style="flex:1"></span>
        ${r.builtin ? '' : '<button type="button" class="btn btn--ghost btn--sm" data-act="delete">Delete role</button>'}
        <button type="button" class="btn btn--primary btn--sm" data-act="save"${dirty[r.key] ? '' : ' disabled'}>Save</button>
      </div>
      <div style="margin:10px 0 6px;display:flex;gap:6px;flex-wrap:wrap;align-items:center">${rules}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
        <select class="form-input" data-f="match" aria-label="How to match" style="max-width:140px">
          <option value="prefix">Starts with</option><option value="exact">Is exactly</option></select>
        <input class="form-input" data-f="value" maxlength="128" placeholder="e.g. owner:E-O:" aria-label="Tag text" style="max-width:320px">
        <button type="button" class="btn btn--ghost btn--sm" data-act="add">Add</button>
      </div>
      <div class="text-sm text-muted" data-preview style="margin-top:8px"></div>
    </div>`;
  }

  function suggestionsHtml() {
    if (!suggestions.length) return '';
    const rows = suggestions.map((s, i) => `<tr><td>${esc((roleOf(s.role) || {}).name || s.role)}</td>
      <td><code>${esc(s.value)}</code></td><td>${Number(s.devices).toLocaleString()}</td>
      <td><button type="button" class="btn btn--ghost btn--sm" data-suggest="${i}">Add</button></td></tr>`).join('');
    return `<div class="panel" style="margin-bottom:14px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
        <strong>Suggested from your tags</strong>
        <button type="button" class="btn btn--primary btn--sm" data-suggest="all">Add all</button></div>
      <p class="text-sm text-muted" style="margin:4px 0 8px">Prefixes in your tags that look like a role and aren't mapped yet. Check each one before adding.</p>
      <table class="data-table"><thead><tr><th>Role</th><th>Tags starting with</th><th>Devices</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function render() {
    pane().innerHTML = `<div class="panel" style="margin-bottom:14px">
        <strong>What your tags mean</strong>
        <p class="text-sm text-muted" style="margin:4px 0 0">Map your tags to roles CTEM understands. For example, if your scanner tags owners as
        <code>owner:E-O: Jane Doe</code>, add the prefix <code>owner:E-O:</code> to Executive owner and CTEM shows <em>Jane Doe</em>.
        Matching ignores case; when several prefixes match a tag, the longest wins. Your tags are never changed.</p></div>
      ${suggestionsHtml()}
      <div id="tm-cards">${roles.map(card).join('')}</div>
      <div class="panel" style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
        <strong style="margin-right:6px">Add a role</strong>
        <input class="form-input" id="tm-new-name" maxlength="60" placeholder="e.g. Data owner" style="max-width:240px">
        <button type="button" class="btn btn--ghost btn--sm" id="tm-new">Add role</button></div>`;
    roles.forEach(r => preview(r.key));
  }

  async function preview(key) {
    const r = roleOf(key), el = pane().querySelector(`.tm-card[data-role="${CSS.escape(key)}"] [data-preview]`);
    if (!r || !el) return;
    if (!(r.rules || []).length) { el.textContent = ''; return; }
    try {
      const p = await call('POST', '/preview', { rules: r.rules, title_case: r.title_case, key: r.key });
      el.textContent = p.devices ? `Matches ${p.devices.toLocaleString()} devices, ${p.values.toLocaleString()} values: ${p.sample.join(', ')}${p.values > p.sample.length ? ', ...' : ''}`
        : 'Matches no devices yet.';
    } catch (e) { el.textContent = e.message; }
  }

  function touched(key) {
    dirty[key] = true;
    const btn = pane().querySelector(`.tm-card[data-role="${CSS.escape(key)}"] [data-act="save"]`);
    if (btn) btn.disabled = false;
  }

  function redrawCard(key) {
    const el = pane().querySelector(`.tm-card[data-role="${CSS.escape(key)}"]`);
    if (el) { el.outerHTML = card(roleOf(key)); preview(key); }
  }

  async function save(key) {
    const r = roleOf(key);
    try {
      const d = await call('PUT', `/${encodeURIComponent(key)}`, { name: r.name, show_filter: r.show_filter, title_case: r.title_case, rules: r.rules });
      Object.assign(r, d.role);
      delete dirty[key];
      try { sessionStorage.removeItem('ctem.tagLabels'); } catch (e) { /* private mode */ }
      redrawCard(key);
      toast(`${r.name} saved`, 'ok');
    } catch (e) { toast(e.message, 'error'); }
  }

  function addRule(key, match, value) {
    const r = roleOf(key);
    value = (value || '').trim() ? value : '';
    if (!value) return toast('Type the start of the tag first.', 'error');
    if (/[<>]/.test(value)) return toast("Please don't use < or >.", 'error');
    if ((r.rules || []).some(x => x.match === match && x.value.toLowerCase() === value.toLowerCase())) return;
    r.rules = [...(r.rules || []), { match, value }];
    touched(key);
    redrawCard(key);
  }

  async function addSuggestion(i) {
    const s = suggestions[i];
    if (!s) return;
    addRule(s.role, s.match, s.value);
    suggestions.splice(i, 1);
  }

  async function load() {
    try {
      roles = (await call('GET', '')).roles || [];
      suggestions = (await call('GET', '/suggestions')).suggestions || [];
    } catch (e) { pane().innerHTML = `<div class="panel text-muted">${esc(e.message)}</div>`; return; }
    dirty = {};
    render();
  }

  document.addEventListener('click', async e => {
    if (!pane() || !pane().contains(e.target)) return;
    const c = e.target.closest('.tm-card'), key = c && c.dataset.role;
    const act = e.target.closest('[data-act]'), del = e.target.closest('[data-del-rule]'), sug = e.target.closest('[data-suggest]');
    if (del && key) { const r = roleOf(key); r.rules.splice(Number(del.dataset.delRule), 1); touched(key); redrawCard(key); return; }
    if (sug) {
      if (sug.dataset.suggest === 'all') { [...suggestions].forEach(s => addRule(s.role, s.match, s.value)); suggestions = []; }
      else addSuggestion(Number(sug.dataset.suggest));
      const keep = roles.map(r => r.key).filter(k => dirty[k]);
      render();
      keep.forEach(k => touched(k));
      toast('Added. Review each role, then Save it.', 'ok');
      return;
    }
    if (e.target.id === 'tm-new') {
      const name = document.getElementById('tm-new-name').value.trim();
      if (!name) return toast('Name the role first.', 'error');
      const k = ('custom_' + name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')).slice(0, 40);
      try { await call('POST', '', { key: k, name, show_filter: true, title_case: false, rules: [] }); await load(); }
      catch (err) { toast(err.message, 'error'); }
      return;
    }
    if (!act || !key) return;
    if (act.dataset.act === 'add') addRule(key, c.querySelector('[data-f="match"]').value, c.querySelector('[data-f="value"]').value);
    if (act.dataset.act === 'save') save(key);
    if (act.dataset.act === 'delete') {
      if (!confirm(`Delete the ${roleOf(key).name} role? Its tags stay as they are.`)) return;
      try { await call('DELETE', `/${encodeURIComponent(key)}`); await load(); } catch (err) { toast(err.message, 'error'); }
    }
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' || !e.target.matches('#pane-tags [data-f="value"]')) return;
    e.preventDefault();
    const c = e.target.closest('.tm-card');
    addRule(c.dataset.role, c.querySelector('[data-f="match"]').value, e.target.value);
  });
  document.addEventListener('change', e => {
    if (!pane() || !pane().contains(e.target)) return;
    const c = e.target.closest('.tm-card'), f = e.target.dataset.f;
    if (!c || !['name', 'show_filter', 'title_case'].includes(f)) return;
    const r = roleOf(c.dataset.role);
    r[f] = e.target.type === 'checkbox' ? e.target.checked : e.target.value.trim();
    touched(r.key);
    if (f === 'title_case') preview(r.key);
  });

  window.TagRoles = { load };
})();
