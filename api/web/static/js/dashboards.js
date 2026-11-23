// Dashboards list: mine, shared with me, favorites, and (admins) all. New dashboards start blank, from a starter
// dashboard, or from the AI, as private drafts.
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
        <span><a class="dt-link dl-card__name" href="/dashboards/${encodeURIComponent(d.id)}">${esc(d.name)}</a>${!d.published ? '<span class="dl-draft">Draft</span>'
          : d.has_draft ? '<span class="dl-draft">Unpublished changes</span>' : ''}${
            d.scope_request ? ` <span class="dl-draft" title="Asked to show everyone all the data">${d.can_widen ? 'Needs your approval' : 'Waiting for approval'}</span>` : ''}</span>
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

  // New: blank, from a starter dashboard, or drafted by the AI. It starts as a private draft.
  let templates = null;
  async function newDash() {
    const d = DashRender.dialog('dl-new-dlg', 'New dashboard', 720);
    if (!templates) templates = await DashRender.api('GET', `${API}/catalog`);
    const T = (templates && templates.templates) || [];
    const SW = { default: ['var(--severity-info)', 'var(--accent)', 'var(--severity-low)', 'var(--severity-high)'],
                 ocean: ['#0ea5e9', '#6366f1', '#14b8a6', '#38bdf8'], sunset: ['#f97316', '#ec4899', '#f59e0b', '#fb7185'],
                 forest: ['#16a34a', '#0d9488', '#65a30d', '#4ade80'], violet: ['#8b5cf6', '#d946ef', '#6366f1', '#a78bfa'],
                 slate: ['#64748b', '#0ea5e9', '#94a3b8', '#475569'], neon: ['#22d3ee', '#a3e635', '#f472b6', '#facc15'] };
    let pick = '';
    d.body.innerHTML = `<label class="form-label" for="dln-name">Name</label>
      <input id="dln-name" class="form-input" maxlength="120" placeholder="e.g. Server patching review">
      <span class="form-label" style="margin-top:12px;display:block">Start from</span>
      <div class="tpl-grid" id="dln-tpl"><button type="button" class="tpl-card is-on" data-tpl=""><b>Blank</b><small>Drag widgets in from the library.</small></button>
        ${T.map(t => `<button type="button" class="tpl-card" data-tpl="${esc(t.key)}"><span class="pal-theme__sw">${(SW[t.theme] || SW.default).map(c => `<i style="background:${c}"></i>`).join('')}</span>
          <b>${esc(t.name)}</b><small>${esc(t.description)} (${esc(t.widgets)} widgets)</small></button>`).join('')}</div>
      <label class="form-label" for="dln-ai">Or describe it and let the AI draft it <span class="text-muted">(optional)</span></label>
      <textarea id="dln-ai" class="form-input" rows="3" maxlength="2000"
        placeholder="e.g. A weekly patching review for the server team: critical and KEV findings on servers, what's past SLA, the trend, and the worst servers"></textarea>
      <div id="dln-q" hidden></div>
      <p class="text-sm text-muted">It starts as a private draft. Move, resize and restyle widgets, then publish and share it.</p>`;
    $('dln-tpl').onclick = e => {
      const b = e.target.closest('[data-tpl]');
      if (!b) return;
      pick = b.dataset.tpl;
      $('dln-tpl').querySelectorAll('.tpl-card').forEach(x => x.classList.toggle('is-on', x === b));
      const t = T.find(x => x.key === pick);
      if (t && !$('dln-name').value.trim()) $('dln-name').placeholder = t.name;
    };
    let answers = [];
    $('dln-ai').addEventListener('input', () => { answers = []; $('dln-q').hidden = true; });
    d.button('Cancel', 'btn--ghost', d.close);
    const go = d.button('Create', 'btn--primary', async () => {
      const name = $('dln-name').value.trim(), text = $('dln-ai').value.trim();
      if (/[<>]/.test(name)) return d.msg("Please don't use < or > in the name.", true);
      const t = T.find(x => x.key === pick);
      let body = { name: name || (t ? t.name : 'New dashboard'), visibility: 'private', share_roles: [], widgets: [],
                   ...(t ? { template: t.key, description: t.description } : {}) };
      go.disabled = true;
      if (text && !t) {
        if (text.length < 5) { go.disabled = false; return d.msg('Describe it in a few more words.', true); }
        d.msg('Asking the AI to draft it...');
        const r = await DashRender.api('POST', `${API}/ai/dashboard`, { text, answers });
        if (r.question) {   // it wasn't sure: ask, then send the answer with the request
          go.disabled = false;
          d.msg('');
          DashRender.clarify($('dln-q'), r, a => { answers.push(a); go.click(); });
          return;
        }
        if (r.available === false) { go.disabled = false; return d.msg('No AI integration is set up. Clear the description to start blank.', true); }
        if (!r.widgets) { go.disabled = false; return d.msg(r.error || 'The AI had no draft. Try rewording it.', true); }
        body = { ...body, name: name || r.name, description: r.description, widgets: r.widgets };
      }
      const made = await DashRender.api('POST', API, body);
      go.disabled = false;
      if (!made.ok) return d.msg(made.error || 'Could not create it.', true);
      if (text && !t) { try { sessionStorage.setItem(`ctem.dashAsk.${made.id}`, text.slice(0, 2000)); } catch (e) { /* refining still works */ } }
      location.href = `/dashboards/${encodeURIComponent(made.id)}${t ? '' : '?edit=1'}`;
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
