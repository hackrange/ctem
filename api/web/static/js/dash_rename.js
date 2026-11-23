// Rename a dashboard: name and description only, so sharing, data scope and widgets stay put (and no draft is made)
window.DashRename = (() => {
  const $ = id => document.getElementById(id);
  function open(dash, url, done) {
    const d = DashRender.dialog('db-rename', 'Rename dashboard', 480);
    d.body.innerHTML = `<label class="form-label" for="dbr-name">Name</label>
      <input id="dbr-name" class="form-input" maxlength="120" value="${esc(dash.name)}">
      <label class="form-label" for="dbr-desc" style="margin-top:8px">Description <span class="text-muted">(optional)</span></label>
      <textarea id="dbr-desc" class="form-input" rows="2" maxlength="1000">${esc(dash.description || '')}</textarea>`;
    d.button('Cancel', 'btn--ghost', d.close);
    const go = async () => {
      const name = $('dbr-name').value.trim(), desc = $('dbr-desc').value.trim();
      if (!name || /[<>]/.test(name + desc)) return d.msg('Give it a name, without < or >.', true);
      const cur = dash.draft || { widgets: dash.widgets, theme: dash.theme, filters: dash.filters };
      const r = await DashRender.api('PUT', url, { name, description: desc || null, visibility: dash.visibility,
                                                   share_roles: dash.share_roles, widgets: cur.widgets, theme: cur.theme,
                                                   filters: (cur.filters || {}).filters || [], filter_match: (cur.filters || {}).match || 'all' });
      if (!r.ok) return d.msg(r.error || 'Could not rename', true);
      d.close();
      done();
    };
    d.button('Save', 'btn--primary', go);
    $('dbr-name').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); go(); } });
    $('dbr-name').focus();
    $('dbr-name').select();
  }
  return { open };
})();
