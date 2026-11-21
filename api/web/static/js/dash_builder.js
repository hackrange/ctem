// One dashboard: view it, or (owner and admins) edit it on a drag-and-resize grid. Data is the viewer's own.
(() => {
  const $ = id => document.getElementById(id);
  const API = '/api/v1/dashboards';
  const id = location.pathname.split('/').filter(Boolean).pop();
  const ROLE_LABEL = { admin: 'Admins', cyber: 'Cyber', grc: 'GRC', it_user: 'IT users', read_only: 'Read-only',
                       inventory: 'Inventory', business_stakeholder: 'Business stakeholders' };
  let dash, catalog = [], roles = [], grid, editing = false, widgets = [], data = {}, timer;

  const body = wid => document.querySelector(`.grid-stack-item[gs-id="${CSS.escape(wid)}"] .dw-body`);

  function item(w) {
    return `<div class="dw"><div class="dw-head"><span class="dw-title">${esc(w.title)}</span>
      <span class="dw-tools" ${editing ? '' : 'hidden'}><button type="button" class="dw-tool" data-edit="${esc(w.id)}" title="Edit widget" aria-label="Edit widget">&#9998;</button>
      <button type="button" class="dw-tool" data-remove="${esc(w.id)}" title="Remove widget" aria-label="Remove widget">&#10005;</button></span></div>
      <div class="dw-body"></div></div>`;
  }

  function build() {
    if (grid) { grid.removeAll(true); } else {
      grid = GridStack.init({ column: 12, cellHeight: 70, margin: 8, float: false, staticGrid: true,
                              resizable: { handles: 'se' }, draggable: { handle: '.dw-head' } }, $('db-grid'));
    }
    widgets.forEach(w => {
      const el = grid.addWidget({ id: w.id, x: w.x, y: w.y, w: w.w, h: w.h, minW: 2, minH: 2 });
      el.querySelector('.grid-stack-item-content').innerHTML = item(w);
      DashRender.render(body(w.id), w, data[w.id], !editing);
    });
    $('db-empty').hidden = widgets.length > 0;
  }

  async function load(only) {
    const list = only || widgets;
    if (!list.length) return;
    list.forEach(w => DashRender.render(body(w.id), w, null, !editing));
    const r = await DashRender.api('POST', `${API}/data`, { widgets: list });
    Object.assign(data, r.data || {});
    list.forEach(w => DashRender.render(body(w.id), w, data[w.id] || { error: r.error || 'No data' }, !editing));
  }

  function layout() {
    const pos = Object.fromEntries(grid.save(false).map(n => [n.id, n]));
    widgets = widgets.map(w => ({ ...w, ...(pos[w.id] ? { x: pos[w.id].x, y: pos[w.id].y, w: pos[w.id].w, h: pos[w.id].h } : {}) }));
  }

  function header() {
    $('db-name').textContent = dash.name;
    document.title = `${dash.name} -- open-ctem`;
    const share = dash.visibility === 'everyone' ? 'Shared with everyone'
      : dash.visibility === 'roles' ? `Shared with ${dash.share_roles.map(r => ROLE_LABEL[r] || r).join(', ')}` : 'Private';
    $('db-sub').textContent = [dash.description, `${share} · by ${dash.owner}`].filter(Boolean).join(' · ');
    $('db-star').hidden = false;
    $('db-star').innerHTML = dash.starred ? '&#9733;' : '&#9734;';
    $('db-star').setAttribute('aria-pressed', String(dash.starred));
    $('db-star').title = dash.starred ? 'Remove from Favorites' : 'Add to Favorites';
    const a = $('db-actions');
    a.innerHTML = '';
    const btn = (label, cls, fn, title) => { const b = document.createElement('button'); b.type = 'button'; b.className = `btn ${cls} btn--sm`;
                                             b.textContent = label; if (title) b.title = title; b.onclick = fn; a.appendChild(b); return b; };
    if (editing) {
      btn('Add widget', 'btn--primary', () => DashEditor.open({ catalog, onSave: add }));
      btn('Edit with AI', 'btn--ghost', aiEdit, 'Describe a change, e.g. "make the trend blue" or "add a 14-day card"');
      btn('Describe a widget (AI)', 'btn--ghost', () => DashEditor.describe({ catalog, onSave: add }));
      btn('Cancel', 'btn--ghost', () => { editing = false; $('db-explain').hidden = true; open(); });
      btn('Save', 'btn--primary', save);
      return;
    }
    btn('Refresh', 'btn--ghost', () => load());
    btn('Explain (AI)', 'btn--ghost', explain, 'A plain-English summary of what this dashboard shows right now');
    btn('Copy', 'btn--ghost', copy, 'Make your own copy to change');
    if (dash.can_edit) {
      btn('Edit with AI', 'btn--ghost', aiEdit, 'Describe a change, e.g. "make the trend blue" or "add a 14-day card"');
      btn('Share', 'btn--ghost', settings);
      btn('Delete', 'btn--ghost', remove);
      btn('Edit', 'btn--primary', () => { editing = true; header(); grid.setStatic(false); build(); });
    }
  }

  function add(w) {
    if (editing) layout();
    const i = widgets.findIndex(x => x.id === w.id);
    if (i >= 0) widgets[i] = w; else { w.y = 1000; widgets.push(w); }   // new ones go to the bottom
    delete data[w.id];
    build();
    load([w]);
  }

  async function save() {
    layout();
    const r = await DashRender.api('PUT', `${API}/${id}`, { name: dash.name, description: dash.description,
      visibility: dash.visibility, share_roles: dash.share_roles, widgets });
    if (!r.ok) { alert(r.error || 'Could not save'); return; }
    editing = false;
    $('db-explain').hidden = true;
    open();
  }

  function settings() {
    const d = DashRender.dialog('db-share', 'Name and sharing', 560);
    d.body.innerHTML = `<label class="form-label" for="dbs-name">Name</label>
      <input id="dbs-name" class="form-input" maxlength="120" value="${esc(dash.name)}">
      <label class="form-label" for="dbs-desc" style="margin-top:8px">Description <span class="text-muted">(optional)</span></label>
      <textarea id="dbs-desc" class="form-input" rows="2" maxlength="1000">${esc(dash.description || '')}</textarea>
      <span class="form-label" style="margin-top:10px;display:block">Who can see it</span>
      ${[['private', 'Only me (and admins)'], ['roles', 'People in these roles'], ['everyone', 'Everyone']].map(([v, l]) =>
        `<label class="tk-radio" style="margin:4px 0"><input type="radio" name="dbs-vis" value="${v}"${dash.visibility === v ? ' checked' : ''}> ${l}</label>`).join('')}
      <div id="dbs-roles" style="display:flex;flex-wrap:wrap;gap:10px;margin:6px 0 0 22px">${roles.map(r =>
        `<label class="tk-radio"><input type="checkbox" value="${esc(r)}"${dash.share_roles.includes(r) ? ' checked' : ''}> ${esc(ROLE_LABEL[r] || r)}</label>`).join('')}</div>
      <p class="text-sm text-muted">People you share with can view, star and copy it; only you and admins can change it.
        Everyone sees only the data they're allowed to see.</p>`;
    d.button('Cancel', 'btn--ghost', d.close);
    d.button('Save', 'btn--primary', async () => {
      const vis = document.querySelector('input[name="dbs-vis"]:checked').value;
      const share = [...document.querySelectorAll('#dbs-roles input:checked')].map(x => x.value);
      const name = $('dbs-name').value.trim(), desc = $('dbs-desc').value.trim();
      if (!name || /[<>]/.test(name + desc)) return d.msg('Give it a name, without < or >.', true);
      if (vis === 'roles' && !share.length) return d.msg('Pick at least one role.', true);
      const r = await DashRender.api('PUT', `${API}/${id}`, { name, description: desc || null, visibility: vis, share_roles: share, widgets });
      if (!r.ok) return d.msg(r.error || 'Could not save', true);
      d.close();
      open();
    });
  }

  // Describe a change; the AI's version is shown in edit mode to review. Nothing is saved until Save.
  function aiEdit() {
    const d = DashRender.dialog('db-ai-edit', 'Edit with AI', 600);
    d.body.innerHTML = `<p class="text-sm text-muted" style="margin-top:0">For example: "make the stale trend blue", "add a card for
      14 days", "turn the donut into bars", "make the 90-day card red above 100".</p>
      <textarea id="dbe-text" class="form-input" rows="3" maxlength="1000"></textarea>`;
    d.button('Cancel', 'btn--ghost', d.close);
    const go = d.button('Apply', 'btn--primary', async () => {
      const text = $('dbe-text').value.trim();
      if (text.length < 5) return d.msg('Describe the change first.', true);
      go.disabled = true;
      d.msg('Asking the AI...');
      const r = await DashRender.api('POST', `${API}/ai/edit/${id}`, { text });
      go.disabled = false;
      if (r.available === false) return d.msg('No AI integration is set up. Use Edit instead.', true);
      if (!r.widgets) return d.msg(r.error || 'The AI had no change. Try rewording it.', true);
      d.close();
      editing = true;
      widgets = r.widgets;
      data = {};
      header();
      grid.setStatic(false);
      build();
      load();
      $('db-explain').hidden = false;
      $('db-explain-text').textContent = `AI change, not saved yet: ${r.note || 'see the widgets below'}. Review it, then Save, or Cancel to discard.`;
    });
    $('dbe-text').focus();
  }

  async function copy() {
    const r = await DashRender.api('POST', `${API}/${id}/copy`);
    if (r.ok) location.href = `/dashboards/${encodeURIComponent(r.id)}?edit=1`;
  }

  function remove() {
    const d = DashRender.dialog('db-del', 'Delete this dashboard?', 460);
    d.body.innerHTML = `<p>${esc(dash.name)} will be deleted for everyone it's shared with. This can't be undone.</p>`;
    d.button('Cancel', 'btn--ghost', d.close);
    d.button('Delete', 'btn--primary', async () => {
      const r = await DashRender.api('DELETE', `${API}/${id}`);
      if (r.ok) location.href = '/dashboards'; else d.msg(r.error, true);
    });
  }

  async function explain() {
    $('db-explain').hidden = false;
    $('db-explain-text').textContent = 'Asking the AI to read this dashboard...';
    const r = await DashRender.api('POST', `${API}/ai/explain/${id}`);
    $('db-explain-text').textContent = r.available === false ? 'No AI integration is set up, so there is nothing to explain with.'
      : r.summary || r.error || 'No summary this time.';
  }

  $('db-star').addEventListener('click', async () => {
    const r = await DashRender.api(dash.starred ? 'DELETE' : 'PUT', `/api/v1/favorites/dashboard/${id}`);
    if (r.ok) { dash.starred = r.starred; header(); window.dispatchEvent(new Event('favorites-changed')); }
  });
  $('db-grid').addEventListener('click', e => {
    const ed = e.target.closest('[data-edit]'), rm = e.target.closest('[data-remove]');
    if (ed) { layout(); DashEditor.open({ catalog, widget: widgets.find(w => w.id === ed.dataset.edit), onSave: add }); }
    if (rm) { layout(); widgets = widgets.filter(w => w.id !== rm.dataset.remove); build(); }
    const tr = !editing && e.target.closest('tr[data-href]');
    if (tr && !e.target.closest('a')) location.href = tr.dataset.href;
  });
  // charts take their colors from the theme when drawn
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => build());

  async function open() {
    const [d, c] = await Promise.all([DashRender.api('GET', `${API}/${id}`), catalog.length ? null : DashRender.api('GET', `${API}/catalog`)]);
    if (!d.id) { $('db-name').textContent = 'Dashboard not found'; $('db-sub').textContent = "It may have been deleted, or it isn't shared with you."; return; }
    if (c) { catalog = c.metrics || []; roles = c.roles || []; }
    dash = d;
    widgets = d.widgets;
    if (editing && !dash.can_edit) editing = false;
    header();
    build();
    grid.setStatic(!editing);
    load();
    clearInterval(timer);
    timer = setInterval(() => { if (!editing && !document.hidden) { data = {}; load(); } }, 5 * 60 * 1000);
  }

  if (/^[0-9a-f-]{36}$/i.test(id)) {
    editing = new URLSearchParams(location.search).get('edit') === '1';
    open();
    if (editing) history.replaceState(null, '', location.pathname);
  } else $('db-name').textContent = 'Dashboard not found';
})();
