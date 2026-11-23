// One dashboard: view it, or (owner and admins) edit it on a drag-and-resize grid with a widget library to drag
// from, chart types and colors switched right on each widget, and a theme. Edits save as a draft that only the
// owner and admins see; Publish makes it what everyone it's shared with sees. Data is always the viewer's own.
(() => {
  const $ = id => document.getElementById(id);
  const API = '/api/v1/dashboards';
  const id = location.pathname.split('/').filter(Boolean).pop();
  const ROLE_LABEL = { admin: 'Admins', cyber: 'Cyber', grc: 'GRC', it_user: 'IT users', read_only: 'Read-only',
                       inventory: 'Inventory', business_stakeholder: 'Business stakeholders' };
  const COLORS = ['blue', 'green', 'red', 'orange', 'yellow', 'purple', 'teal', 'gray'];
  const OPACITY = [100, 85, 70, 55, 40, 25];
  let dash, catalog = [], presets = [], roles = [], filterOptions = null, dfilters = { filters: [], match: 'all' }, grid, editing = false, widgets = [], data = {}, timer, theme = 'default';
  let showing = 'published';   // or 'draft': what the owner is looking at
  const byMetric = () => Object.fromEntries(catalog.map(m => [m.id, m]));

  const body = wid => document.querySelector(`.grid-stack-item[gs-id="${CSS.escape(wid)}"] .dw-body`);

  function bar(w) {   // quick controls while editing: chart type, color, transparency
    const m = byMetric()[w.metric];
    if (!m) return '';
    const st = w.style || {};
    return `<div class="dw-bar">
      <span class="dw-bar__viz">${m.viz.map(v => `<button type="button" class="dw-vbtn${v === w.viz ? ' is-on' : ''}" data-viz="${esc(v)}" data-w="${esc(w.id)}"
        title="${esc(DashPalette.VIZ[v] || v)}" aria-label="${esc(DashPalette.VIZ[v] || v)}">${DashPalette.icon(v, m.shape)}</button>`).join('')}</span>
      <span class="dw-bar__colors"><button type="button" class="dw-dot dw-dot--auto${st.color ? '' : ' is-on'}" data-color="" data-w="${esc(w.id)}" title="Automatic" aria-label="Automatic color"></button>${COLORS.map(c =>
        `<button type="button" class="dw-dot${st.color === c ? ' is-on' : ''}" style="background:${DashCharts.NAMED[c]}" data-color="${c}" data-w="${esc(w.id)}" title="${c}" aria-label="${c}"></button>`).join('')}</span>
      ${m.shape === 'table' ? '' : `<select class="dw-op" data-w="${esc(w.id)}" title="Transparency" aria-label="Transparency">${OPACITY.map(o =>
        `<option value="${o}"${(st.opacity || 100) === o ? ' selected' : ''}>${o === 100 ? 'Solid' : `${o}%`}</option>`).join('')}</select>`}</div>`;
  }

  // The widget's conditions as chips while editing: remove one (x) or refine them (click)
  function chips(w) {
    const m = byMetric()[w.metric];
    const parts = DashFilters.parts(w, filterOptions);
    const can = dash && dash.can_edit && m && m.filterable !== false;
    if (!editing) return '';   // filters are shown and changed in edit mode only
    const join = w.filter_match === 'any' ? '<span class="dw-chips__or">or</span>' : '';
    return `<div class="dw-chips" aria-label="Filters">${parts.map((p, i) => `${i && join ? join : ''}<span class="dw-chip${can ? ' is-live' : ''}"
        ${can ? `data-refine="${esc(w.id)}" role="button" tabindex="0" title="Change the filters"` : `title="${esc(p)}"`}>${esc(p)}${can
        ? `<button type="button" class="dw-chip__x" data-unfilter="${esc(w.id)}" data-i="${i}" title="Remove this filter" aria-label="Remove filter: ${esc(p)}">&#10005;</button>` : ''}</span>`).join('')}
      ${can ? `<button type="button" class="dw-chip dw-chip--add" data-refine="${esc(w.id)}" title="Add or change filters">+ Filter</button>` : ''}</div>`;
  }

  function item(w) {
    return `<div class="dw"><div class="dw-head"><span class="dw-title" title="${esc(w.title)}">${esc(w.title)}</span>
      ${!editing && (byMetric()[w.metric] || {}).shape !== 'value' && w.viz !== 'kpi' ? `<button type="button" class="dw-tool dw-csv" data-csv="${esc(w.id)}"
        title="Download the data as CSV" aria-label="Download ${esc(w.title)} as CSV">CSV</button>` : ''}
      <span class="dw-tools" ${editing ? '' : 'hidden'}><button type="button" class="dw-tool" data-edit="${esc(w.id)}" title="All settings" aria-label="Edit widget">&#9998;</button>
      <button type="button" class="dw-tool" data-dup="${esc(w.id)}" title="Duplicate" aria-label="Duplicate widget">&#10697;</button>
      <button type="button" class="dw-tool" data-remove="${esc(w.id)}" title="Remove" aria-label="Remove widget">&#10005;</button></span></div>
      ${editing ? bar(w) : ''}${chips(w)}<div class="dw-body"></div></div>`;
  }

  // Dashboard-wide filters, set in edit mode and saved with the dashboard
  const copyF = f => ({ filters: JSON.parse(JSON.stringify((f && f.filters) || [])), match: (f && f.match) === 'any' ? 'any' : 'all' });
  const active = () => dfilters;
  function filterBar() {
    const box = $('db-filters');
    const f = active();
    const parts = DashFilters.parts({ filters: f.filters, filter_match: f.match }, filterOptions);
    const join = f.match === 'any' ? '<span class="dw-chips__or">or</span>' : '';
    box.hidden = !editing;   // edit mode only; viewers see the data as filtered
    box.innerHTML = `<span class="db-filters__label">Dashboard filters</span>
      ${parts.map((p, i) => `${i && join ? join : ''}<span class="dw-chip is-live" data-dfilter role="button" tabindex="0" title="Change">${esc(p)}<button type="button"
        class="dw-chip__x" data-dunfilter="${i}" title="Remove this filter" aria-label="Remove filter: ${esc(p)}">&#10005;</button></span>`).join('')
        || '<span class="text-sm text-muted">None: every widget counts all the devices you can see</span>'}
      <button type="button" class="dw-chip dw-chip--add" data-dfilter>+ Filter</button>
      ${editing ? '<span class="db-filters__note">Saved with the dashboard; applies to every widget that counts devices</span>' : ''}`;
  }
  function setFilters(next) {
    dfilters = next;
    data = {};
    filterBar();
    load();
  }
  function refineDashboard() {
    const cur = active();
    const d = DashRender.dialog('db-refine', 'Dashboard filters', 760);
    d.body.innerHTML = `<div id="dbr-box"></div><p class="text-sm text-muted">These apply to every widget that counts devices, on top of
      each widget's own filters. Saved with the dashboard. Alerts, GRC and snapshot trends aren't affected.</p>`;
    const f = DashFilters.mount($('dbr-box'), filterOptions, { filters: cur.filters, match: cur.match });
    d.button('Cancel', 'btn--ghost', d.close);
    d.button('Apply', 'btn--primary', () => { const g = f.get(); d.close(); setFilters({ filters: g.filters, match: g.filter_match }); });
  }
  $('db-filters').addEventListener('click', e => {
    const x = e.target.closest('[data-dunfilter]');
    if (x) { const c = copyF(active()); c.filters.splice(Number(x.dataset.dunfilter), 1); setFilters(c); return; }
    if (e.target.closest('[data-dfilter]')) refineDashboard();
  });
  $('db-filters').addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('.dw-chip[data-dfilter]')) { e.preventDefault(); refineDashboard(); }
  });

  function applyTheme() {
    const t = DashCharts.setTheme(theme);
    $('db-wrap').className = `db-wrap db-theme--${t.card}${t.palette ? ` db-theme-${theme}` : ''}${editing ? ' is-editing' : ''}`;
  }

  function build() {
    applyTheme();
    if (grid) grid.removeAll(true);
    else {
      grid = GridStack.init({ column: 12, cellHeight: 72, margin: 8, float: false, staticGrid: true, acceptWidgets: true,
                              columnOpts: { breakpoints: [{ w: 640, c: 1 }, { w: 1000, c: 6 }] },
                              resizable: { handles: 'se,e,s' }, draggable: { handle: '.dw-head' } }, $('db-grid'));
      grid.on('dropped', (_e, _prev, node) => {   // a widget dragged in from the library
        const w = palette && palette.take(node.el && node.el.dataset.key);
        grid.removeWidget(node.el, true, false);
        if (w) { layout(); add({ ...w, x: node.x, y: node.y }, true); }
      });
      grid.on('change', () => layout());
    }
    widgets.forEach(w => {
      const el = grid.addWidget({ id: w.id, x: w.x, y: w.y, w: w.w, h: w.h, minW: 2, minH: 2 });
      el.querySelector('.grid-stack-item-content').innerHTML = item(w);
      DashRender.render(body(w.id), w, data[w.id], !editing);
    });
    grid.setStatic(!editing);
    filterBar();
    $('db-empty').hidden = widgets.length > 0 || editing;
    $('db-drop-hint').hidden = !(editing && !widgets.length);
  }

  // A dashboard an admin set to show all the data: the published widgets are asked for by dashboard, so the server
  // can use its stored copy (see DashAccess)
  const wideRef = () => (!editing && showing === 'published' && dash && dash.data_scope === 'everything' ? { dashboard: id } : {});

  async function load(only) {
    const list = only || widgets;
    if (!list.length) return;
    list.forEach(w => DashRender.render(body(w.id), w, null, !editing));
    const f = active();
    const r = await DashRender.api('POST', `${API}/data`, { widgets: list, filters: f.filters, filter_match: f.match, ...wideRef() });
    Object.assign(data, r.data || {});
    list.forEach(w => { const b = body(w.id); if (b) DashRender.render(b, w, data[w.id] || { error: r.error || 'No data' }, !editing); });
  }

  function layout() {   // positions only count from the full 12-column grid (not the phone layout)
    if (!grid || grid.getColumn() !== 12) return;
    const pos = Object.fromEntries(grid.save(false).map(n => [n.id, n]));
    widgets = widgets.map(w => ({ ...w, ...(pos[w.id] ? { x: pos[w.id].x, y: pos[w.id].y, w: pos[w.id].w, h: pos[w.id].h } : {}) }));
  }

  function status() {
    const s = $('db-status');
    if (!dash.can_edit) { s.hidden = true; return; }
    s.hidden = false;
    s.className = `db-status ${!dash.published ? 'is-draft' : dash.has_draft ? 'is-changed' : 'is-live'}`;
    s.textContent = !dash.published ? 'Draft' : dash.has_draft ? 'Unpublished changes' : 'Published';
    const b = $('db-banner');
    b.hidden = editing || !(dash.has_draft || !dash.published);
    if (!b.hidden) {
      b.innerHTML = !dash.published
        ? '<span>This dashboard is a <b>draft</b>: only you and admins can see it. Publish it to share it.</span>'
        : `<span>${showing === 'draft' ? "You're looking at your <b>draft</b>. Others still see the published version."
                                       : "You're looking at the <b>published</b> version. You have unpublished changes."}</span>
           <button type="button" class="btn btn--ghost btn--sm" id="db-toggle">${showing === 'draft' ? 'View published' : 'View draft'}</button>`;
    }
  }

  function header() {
    $('db-name').textContent = dash.name;
    document.title = `${dash.name} -- open-ctem`;
    const share = dash.visibility === 'everyone' ? 'Shared with everyone'
      : dash.visibility === 'roles' ? `Shared with ${dash.share_roles.map(r => ROLE_LABEL[r] || r).join(', ')}` : 'Private';
    $('db-sub').textContent = [dash.description, `${share} · by ${dash.owner}`, DashAccess.note(dash)].filter(Boolean).join(' · ');
    DashAccess.bar(dash, id, () => open(showing));
    $('db-star').hidden = false;
    $('db-star').innerHTML = dash.starred ? '&#9733;' : '&#9734;';
    $('db-star').setAttribute('aria-pressed', String(dash.starred));
    $('db-star').title = dash.starred ? 'Remove from Favorites' : 'Add to Favorites';
    status();
    const a = $('db-actions');
    a.innerHTML = '';
    const btn = (label, cls, fn, title) => { const b = document.createElement('button'); b.type = 'button'; b.className = `btn ${cls} btn--sm`;
                                             b.textContent = label; if (title) b.title = title; b.onclick = fn; a.appendChild(b); return b; };
    if (editing) {
      btn('Describe a widget (AI)', 'btn--ghost', () => DashEditor.describe({ catalog, filterOptions, onSave: w => add(w) }));
      btn('Cancel', 'btn--ghost', () => { editing = false; $('db-explain').hidden = true; open(); }, 'Throw away changes since the last save');
      btn('Save draft', 'btn--ghost', () => save(false), 'Only you and admins see it until you publish');
      btn('Save and publish', 'btn--primary', () => save(true));
      return;
    }
    btn('Refresh', 'btn--ghost', () => { data = {}; load(); });
    btn('Explain (AI)', 'btn--ghost', explain, 'A plain-English summary of what this dashboard shows right now');
    btn('Copy', 'btn--ghost', copy, 'Make your own copy to change');
    if (dash.can_edit) {
      btn('Edit with AI', 'btn--ghost', aiEdit, 'Describe changes and keep refining them');
      btn('Rename', 'btn--ghost', () => DashRename.open(dash, `${API}/${id}`, () => open(showing)), 'Change the name and description');
      btn('Share', 'btn--ghost', settings);
      if (dash.has_draft) btn('Discard draft', 'btn--ghost', discard);
      if (dash.published) btn('Unpublish', 'btn--ghost', unpublish, 'Back to a draft only you and admins see');
      btn('Delete', 'btn--ghost', remove);
      if (!dash.published || dash.has_draft) btn('Publish', 'btn--primary', publish);
      btn('Edit', 'btn--primary', startEdit);
    }
  }

  let palette = null;
  function startEdit() {
    if (dash.draft) { widgets = dash.draft.widgets; theme = dash.draft.theme; dfilters = copyF(dash.draft.filters); showing = 'draft'; }
    editing = true;
    header();
    $('db-palette').hidden = false;
    palette = DashPalette.mount({ el: $('db-palette'), presets, catalog, theme,
      onAdd: w => add(w, true), onCustom: () => DashEditor.open({ catalog, filterOptions, onSave: w => add(w, true) }),
      onTheme: k => { layout(); theme = k; build(); } });
    data = {};
    build();
    load();
    aiBar();
  }

  function add(w, isNew) {
    layout();
    const i = widgets.findIndex(x => x.id === w.id);
    if (i >= 0) widgets[i] = w;
    else { if (!isNew || w.y == null) w.y = 1000; widgets.push(w); }
    delete data[w.id];
    build();
    load([w]);
    const el = document.querySelector(`.grid-stack-item[gs-id="${CSS.escape(w.id)}"]`);
    if (el) el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  async function save(andPublish) {
    layout();
    const r = await DashRender.api('PUT', `${API}/${id}`, { name: dash.name, description: dash.description,
      visibility: dash.visibility, share_roles: dash.share_roles, widgets, theme, filters: dfilters.filters, filter_match: dfilters.match });
    if (!r.ok) { alert(r.error || 'Could not save'); return; }
    if (andPublish) await DashRender.api('POST', `${API}/${id}/publish`);
    editing = false;
    $('db-explain').hidden = true;
    open(andPublish ? 'published' : 'draft');
  }

  async function publish() {
    const r = await DashRender.api('POST', `${API}/${id}/publish`);
    if (r.ok) open('published'); else alert(r.error || 'Could not publish');
  }
  function discard() {
    const d = DashRender.dialog('db-discard', 'Discard your draft?', 460);
    d.body.innerHTML = '<p>Your unpublished changes will be thrown away. The published version stays as it is.</p>';
    d.button('Cancel', 'btn--ghost', d.close);
    d.button('Discard', 'btn--primary', async () => { const r = await DashRender.api('POST', `${API}/${id}/discard`); d.close(); if (r.ok) open('published'); });
  }
  function unpublish() {
    const d = DashRender.dialog('db-unpub', 'Unpublish this dashboard?', 460);
    d.body.innerHTML = '<p>It goes back to a draft. Only you and admins will see it until you publish it again.</p>';
    d.button('Cancel', 'btn--ghost', d.close);
    d.button('Unpublish', 'btn--primary', async () => { const r = await DashRender.api('POST', `${API}/${id}/unpublish`); d.close(); if (r.ok) open('draft'); });
  }

  function settings() {
    const d = DashRender.dialog('db-share', 'Share', 580);
    const link = `${location.origin}/dashboards/${id}`;
    d.body.innerHTML = `${dash.published ? '' : '<div class="tk-note" style="margin-bottom:10px">This is still a draft. People you share with will see it once you publish.</div>'}
      <label class="form-label" for="dbs-name">Name</label>
      <input id="dbs-name" class="form-input" maxlength="120" value="${esc(dash.name)}">
      <label class="form-label" for="dbs-desc" style="margin-top:8px">Description <span class="text-muted">(optional)</span></label>
      <textarea id="dbs-desc" class="form-input" rows="2" maxlength="1000">${esc(dash.description || '')}</textarea>
      <span class="form-label" style="margin-top:10px;display:block">Who can see it</span>
      ${[['private', 'Only me (and admins)'], ['roles', 'People in these roles'], ['everyone', 'Everyone']].map(([v, l]) =>
        `<label class="tk-radio" style="margin:4px 0"><input type="radio" name="dbs-vis" value="${v}"${dash.visibility === v ? ' checked' : ''}> ${l}</label>`).join('')}
      <div id="dbs-roles" style="display:flex;flex-wrap:wrap;gap:10px;margin:6px 0 0 22px">${roles.map(r =>
        `<label class="tk-radio"><input type="checkbox" value="${esc(r)}"${dash.share_roles.includes(r) ? ' checked' : ''}> ${esc(ROLE_LABEL[r] || r)}</label>`).join('')}</div>
      <label class="form-label" for="dbs-link" style="margin-top:12px">Link</label>
      <div style="display:flex;gap:8px"><input id="dbs-link" class="form-input" readonly value="${esc(link)}"><button type="button" class="btn btn--ghost btn--sm" id="dbs-copy">Copy link</button></div>
      ${DashAccess.field(dash)}`;
    $('dbs-copy').onclick = async () => {
      try { await navigator.clipboard.writeText(link); d.msg('Link copied.'); } catch (e) { $('dbs-link').select(); d.msg('Press Ctrl+C to copy.'); }
    };
    d.button('Cancel', 'btn--ghost', d.close);
    d.button('Save', 'btn--primary', async () => {
      const vis = document.querySelector('input[name="dbs-vis"]:checked').value;
      const share = [...document.querySelectorAll('#dbs-roles input:checked')].map(x => x.value);
      const name = $('dbs-name').value.trim(), desc = $('dbs-desc').value.trim();
      if (!name || /[<>]/.test(name + desc)) return d.msg('Give it a name, without < or >.', true);
      if (vis === 'roles' && !share.length) return d.msg('Pick at least one role.', true);
      const cur = dash.draft || { widgets: dash.widgets, theme: dash.theme, filters: dash.filters };
      const r = await DashRender.api('PUT', `${API}/${id}`, { name, description: desc || null, visibility: vis, share_roles: share,
                                                             widgets: cur.widgets, theme: cur.theme,
                                                             filters: (cur.filters || {}).filters || [], filter_match: (cur.filters || {}).match || 'all',
                                                             ...DashAccess.value(dash) });
      if (!r.ok) return d.msg(r.error || 'Could not save', true);
      d.close();
      open(showing);
    });
  }

  // Talk to the AI while editing: each request builds on what's on screen (unsaved work included) and on what was
  // asked before, so people can keep clarifying. Nothing is saved until Save draft or Save and publish.
  let aiAsked = [];
  function aiBar() {
    const box = $('db-ai');
    box.hidden = !editing;
    if (!editing) return;
    box.innerHTML = `<div class="db-ai__row"><span class="db-ai__label">Ask the AI</span>
      <input id="db-ai-text" class="form-input" maxlength="2000" placeholder='e.g. "make the 44-day card red above 50", "add a trend line", "turn the donut into a pie"'>
      <button type="button" class="btn btn--primary btn--sm" id="db-ai-go">Apply</button></div>
      <div class="db-ai__log" id="db-ai-log">${aiAsked.map(a => `<span class="db-ai__ask" title="Already applied">${esc(a)}</span>`).join('')}</div>
      <div id="db-ai-q" hidden></div><div class="text-sm" id="db-ai-msg"></div>`;
    let answers = [];
    const go = async () => {
      const text = $('db-ai-text').value.trim();
      if (text.length < 5) { $('db-ai-msg').textContent = 'Describe the change in a few more words.'; return; }
      $('db-ai-go').disabled = true;
      $('db-ai-msg').textContent = 'Asking the AI...';
      layout();
      const r = await DashRender.api('POST', `${API}/ai/edit/${id}`, { text, widgets, filters: dfilters, history: aiAsked.slice(-8), answers });
      $('db-ai-go').disabled = false;
      if (r.available === false) { $('db-ai-msg').textContent = 'No AI integration is set up. Use the widget library instead.'; return; }
      if (r.question) {   // it wasn't sure: answer, and the same request goes again with the answer
        $('db-ai-msg').textContent = '';
        DashRender.clarify($('db-ai-q'), r, a => { answers.push(a); go(); });
        return;
      }
      if (!r.widgets) { $('db-ai-msg').textContent = r.error || 'The AI had no change. Try rewording it.'; return; }
      aiAsked.push((answers.length ? `${text} (${answers.map(x => x.split(' -> ').pop()).join('; ')})` : text).slice(0, 1000));
      answers = [];
      widgets = r.widgets;
      if (r.filters) dfilters = copyF(r.filters);
      data = {};
      build();
      load();
      aiBar();
      $('db-ai-msg').textContent = `${r.note || 'Changed.'} Not saved yet: keep refining, or Save.`;
      $('db-ai-text').focus();
    };
    $('db-ai-go').onclick = go;
    $('db-ai-text').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); go(); } };
    $('db-ai-text').addEventListener('input', () => { answers = []; $('db-ai-q').hidden = true; });
  }
  function aiEdit() {
    if (!editing) startEdit();
    aiBar();
    $('db-ai-text').focus();
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

  function patch(wid, change) {   // a quick control changed one widget: redraw it from the data it already has
    layout();
    const w = widgets.find(x => x.id === wid);
    if (!w) return;
    change(w);
    const el = document.querySelector(`.grid-stack-item[gs-id="${CSS.escape(wid)}"] .grid-stack-item-content`);
    el.innerHTML = item(w);
    if (data[wid]) DashRender.render(body(wid), w, data[wid], false); else load([w]);
  }

  // Change one widget's filters. From view mode this opens edit mode first, so it stays a draft until saved.
  function changeFilters(wid, fn) {
    if (!dash || !dash.can_edit) return;
    if (!editing) startEdit();
    layout();
    const w = widgets.find(x => x.id === wid);
    if (!w) return;
    w.filters = [...(w.filters || [])];
    fn(w);
    if (!w.filters.length) w.filter_match = 'all';
    delete data[wid];
    const el = document.querySelector(`.grid-stack-item[gs-id="${CSS.escape(wid)}"] .grid-stack-item-content`);
    if (el) el.innerHTML = item(w);
    load([w]);
  }
  function refine(wid) {
    const w = widgets.find(x => x.id === wid);
    if (!w || !dash.can_edit) return;
    const d = DashRender.dialog('dw-refine', `Filters: ${w.title}`, 760);
    d.body.innerHTML = '<div id="dwr-box"></div><p class="text-sm text-muted">Saved with the dashboard. Others see the change once you publish.</p>';
    const f = DashFilters.mount(document.getElementById('dwr-box'), filterOptions, { filters: w.filters || [], match: w.filter_match });
    d.button('Cancel', 'btn--ghost', d.close);
    d.button('Apply', 'btn--primary', () => {
      const got = f.get();
      d.close();
      changeFilters(wid, x => { x.filters = got.filters; x.filter_match = got.filter_match; });
    });
  }
  document.getElementById('db-grid').addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('.dw-chip[data-refine]')) { e.preventDefault(); refine(e.target.dataset.refine); }
  });

  async function csv(w, button) {   // the server builds the file for this viewer, formula-safe
    if (!w) return;
    button.disabled = true;
    try {
      const r = await fetch(`${API}/export`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ widget: w, filters: active().filters, filter_match: active().match, ...wideRef() }) });
      if (!r.ok) { alert('That widget has no data to export right now.'); return; }
      const name = (/filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '') || [, 'widget.csv'])[1];
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement('a');
      a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } finally { button.disabled = false; }
  }

  $('db-star').addEventListener('click', async () => {
    const r = await DashRender.api(dash.starred ? 'DELETE' : 'PUT', `/api/v1/favorites/dashboard/${id}`);
    if (r.ok) { dash.starred = r.starred; header(); window.dispatchEvent(new Event('favorites-changed')); }
  });
  $('db-banner').addEventListener('click', e => { if (e.target.closest('#db-toggle')) open(showing === 'draft' ? 'published' : 'draft'); });
  $('db-grid').addEventListener('click', e => {
    const t = e.target.closest('[data-edit],[data-remove],[data-dup],[data-viz],[data-color]');
    if (t && editing) {
      if (t.dataset.edit) { layout(); DashEditor.open({ catalog, filterOptions, widget: widgets.find(w => w.id === t.dataset.edit), onSave: w => add(w) }); }
      else if (t.dataset.remove) { layout(); widgets = widgets.filter(w => w.id !== t.dataset.remove); build(); }
      else if (t.dataset.dup) {
        const src = widgets.find(w => w.id === t.dataset.dup);
        if (src) { const c = { ...JSON.parse(JSON.stringify(src)), id: Math.random().toString(36).slice(2, 14), y: src.y + src.h }; data[c.id] = data[src.id]; add(c, true); }
      } else if (t.dataset.viz) patch(t.dataset.w, w => { w.viz = t.dataset.viz; });
      else if (t.dataset.color != null) patch(t.dataset.w, w => { w.style = { ...(w.style || {}) }; if (t.dataset.color) w.style.color = t.dataset.color; else delete w.style.color; });
      return;
    }
    const un = e.target.closest('[data-unfilter]');
    if (un) { e.stopPropagation(); changeFilters(un.dataset.unfilter, w => { w.filters = w.filters.filter((_, i) => i !== Number(un.dataset.i)); }); return; }
    const rf = e.target.closest('[data-refine]');
    if (rf) { refine(rf.dataset.refine); return; }
    const dl = !editing && e.target.closest('[data-csv]');
    if (dl) { csv(widgets.find(w => w.id === dl.dataset.csv), dl); return; }
    const tr = !editing && e.target.closest('tr[data-href]');
    if (tr && !e.target.closest('a')) location.href = tr.dataset.href;
  });
  $('db-grid').addEventListener('change', e => {
    const s = e.target.closest('select.dw-op');
    if (s) patch(s.dataset.w, w => { w.style = { ...(w.style || {}) }; const v = Number(s.value); if (v >= 100) delete w.style.opacity; else w.style.opacity = v; });
  });
  // charts take their colors from the light or dark theme when drawn, so redraw when it changes
  const redraw = () => { if (grid) { layout(); build(); } };
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', redraw);
  new MutationObserver(redraw).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  async function open(view) {
    const [d, c] = await Promise.all([DashRender.api('GET', `${API}/${id}`), catalog.length ? null : DashRender.api('GET', `${API}/catalog`)]);
    if (!d.id) { $('db-name').textContent = 'Dashboard not found'; $('db-sub').textContent = "It may have been deleted, or it isn't shared with you."; return; }
    if (c) { catalog = c.metrics || []; roles = c.roles || []; presets = c.presets || []; filterOptions = c.filter_options || null; }
    dash = d;
    if (editing && !dash.can_edit) editing = false;
    showing = view || (dash.draft ? 'draft' : 'published');
    const shown = showing === 'draft' && dash.draft ? dash.draft : { widgets: dash.widgets, theme: dash.theme, filters: dash.filters };
    widgets = shown.widgets;
    theme = shown.theme || 'default';
    dfilters = copyF(shown.filters);
    $('db-palette').hidden = true;
    $('db-ai').hidden = true;
    aiAsked = [];
    palette = null;
    data = {};
    if (editing) { startEdit(); return; }
    header();
    build();
    load();
    clearInterval(timer);
    timer = setInterval(() => { if (!editing && !document.hidden) { data = {}; load(); } }, 5 * 60 * 1000);
  }

  if (/^[0-9a-f-]{36}$/i.test(id)) {
    editing = new URLSearchParams(location.search).get('edit') === '1';
    open().then(() => {   // a dashboard the AI just drafted: its first request counts as already applied
      try {
        const first = sessionStorage.getItem(`ctem.dashAsk.${id}`);
        if (first && editing) { aiAsked = [first]; aiBar(); }
        sessionStorage.removeItem(`ctem.dashAsk.${id}`);
      } catch (e) { /* no storage: nothing to carry over */ }
    });
    if (editing) history.replaceState(null, '', location.pathname);
  } else $('db-name').textContent = 'Dashboard not found';
})();
