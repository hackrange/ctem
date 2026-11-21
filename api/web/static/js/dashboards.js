// Dashboards list: mine, shared with me, favorites, and (admins) all. New dashboards start blank or from the AI.
(() => {
  const $ = id => document.getElementById(id);
  const API = '/api/v1/dashboards';
  const SHARE = { private: 'Private', roles: 'Shared with roles', everyone: 'Shared with everyone' };
  let tab = new URLSearchParams(location.search).get('tab') || 'mine', isAdmin = false, timer;

  function tabs() {
    const list = [['mine', 'My dashboards'], ['shared', 'Shared with me'], ['starred', 'Favorites'], ...(isAdmin ? [['all', 'All dashboards']] : [])];
    $('dl-tabs').innerHTML = list.map(([v, l]) => `<button type="button" role="tab" class="btn btn--sm ${v === tab ? 'btn--primary' : 'btn--ghost'}"
      data-tab="${v}" aria-selected="${v === tab}">${esc(l)}</button>`).join('');
  }

  function card(d) {
    return `<div class="panel dl-card">
      <div style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start">
        <a class="dt-link dl-card__name" href="/dashboards/${encodeURIComponent(d.id)}">${esc(d.name)}</a>
        <button type="button" class="db-star" data-star="${esc(d.id)}" data-on="${d.starred ? 1 : 0}" aria-pressed="${d.starred}"
          title="${d.starred ? 'Remove from Favorites' : 'Add to Favorites'}">${d.starred ? '&#9733;' : '&#9734;'}</button>
      </div>
      ${d.description ? `<div class="text-sm" style="margin:4px 0 8px">${esc(d.description)}</div>` : ''}
      <div class="text-sm text-muted">${esc(SHARE[d.visibility] || d.visibility)} · ${esc(d.widgets)} widget${d.widgets === 1 ? '' : 's'}
        · ${d.mine ? 'yours' : `by ${esc(d.owner)}`} · updated ${esc(new Date(d.updated_at).toLocaleDateString())}</div>
    </div>`;
  }

  async function load() {
    const q = $('dl-search').value.trim();
    const r = await DashRender.api('GET', `${API}?scope=${encodeURIComponent(tab)}${q ? `&q=${encodeURIComponent(q)}` : ''}`);
    isAdmin = !!r.is_admin;
    tabs();
    const empty = { mine: "You haven't built a dashboard yet. Click <b>New dashboard</b> to start.",
                    shared: 'Nothing has been shared with you yet.', starred: 'Star a dashboard (&#9734;) to keep it here and in the menu.',
                    all: 'No dashboards yet.' }[tab];
    $('dl-list').innerHTML = (r.dashboards || []).map(card).join('') || `<div class="text-muted text-sm">${empty}</div>`;
  }

  function newDash() {
    const d = DashRender.dialog('dl-new-dlg', 'New dashboard', 600);
    d.body.innerHTML = `<label class="form-label" for="dln-name">Name</label>
      <input id="dln-name" class="form-input" maxlength="120" placeholder="e.g. Server patching review">
      <label class="form-label" for="dln-ai" style="margin-top:12px">Or describe it and let the AI draft it <span class="text-muted">(optional)</span></label>
      <textarea id="dln-ai" class="form-input" rows="3" maxlength="1000"
        placeholder="e.g. A weekly patching review for the server team: critical and KEV findings on servers, what's past SLA, the trend, and the worst servers"></textarea>
      <p class="text-sm text-muted">It starts private. You can add, move and resize widgets, then share it.</p>`;
    d.button('Cancel', 'btn--ghost', d.close);
    const go = d.button('Create', 'btn--primary', async () => {
      const name = $('dln-name').value.trim(), text = $('dln-ai').value.trim();
      if (/[<>]/.test(name)) return d.msg("Please don't use < or > in the name.", true);
      let body = { name: name || 'New dashboard', visibility: 'private', share_roles: [], widgets: [] };
      go.disabled = true;
      if (text) {
        if (text.length < 5) { go.disabled = false; return d.msg('Describe it in a few more words.', true); }
        d.msg('Asking the AI to draft it...');
        const r = await DashRender.api('POST', `${API}/ai/dashboard`, { text });
        if (r.available === false) { go.disabled = false; return d.msg('No AI integration is set up. Clear the description to start blank.', true); }
        if (!r.widgets) { go.disabled = false; return d.msg(r.error || 'The AI had no draft. Try rewording it.', true); }
        body = { ...body, name: name || r.name, description: r.description, widgets: r.widgets };
      }
      const made = await DashRender.api('POST', API, body);
      go.disabled = false;
      if (!made.ok) return d.msg(made.error || 'Could not create it.', true);
      location.href = `/dashboards/${encodeURIComponent(made.id)}?edit=1`;
    });
    $('dln-name').focus();
  }

  $('dl-tabs').addEventListener('click', e => {
    const b = e.target.closest('button[data-tab]');
    if (!b) return;
    tab = b.dataset.tab;
    history.replaceState(null, '', `?tab=${tab}`);
    load();
  });
  $('dl-list').addEventListener('click', async e => {
    const s = e.target.closest('button[data-star]');
    if (!s) return;
    const on = s.dataset.on === '1';
    const r = await DashRender.api(on ? 'DELETE' : 'PUT', `/api/v1/favorites/dashboard/${encodeURIComponent(s.dataset.star)}`);
    if (r.ok) { window.dispatchEvent(new Event('favorites-changed')); load(); }
  });
  $('dl-search').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(load, 300); });
  $('dl-new').addEventListener('click', newDash);
  load();
})();
