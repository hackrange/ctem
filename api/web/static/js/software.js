// Software inventory: one row per title ("Google Chrome (14 versions)"), its versions and the assets running each,
// and approving a title or marking it unauthorized (admins and cyber). Everything shown goes through esc().
(() => {
  const API = '/api/v1/software';
  const $ = id => document.getElementById(id);
  const n = v => Number(v || 0).toLocaleString();
  const CHIP = { approved: 'chip--low', unauthorized: 'chip--critical', unreviewed: 'chip--info' };
  const LABEL = { approved: 'Approved', unauthorized: 'Unauthorized', unreviewed: 'Unreviewed' };
  const init = new URLSearchParams(location.search);
  let status = ['unreviewed', 'approved', 'unauthorized'].includes(init.get('status')) ? init.get('status') : '';
  let sort = 'assets', order = 'desc', offset = 0, pending = null, picked = init.get('id') || '';
  const LIMIT = 50;
  $('sw-q').value = init.get('q') || '';
  $('sw-system').checked = init.get('system') === '1';

  async function get(url, signal) {
    const r = await fetch(url, { headers: { Accept: 'application/json' }, signal });
    if (r.status === 401) { location.href = `/login?next=${encodeURIComponent(location.pathname + location.search)}`; return null; }
    if (!r.ok) throw new Error(r.status);
    return r.json();
  }

  function remember() {
    const q = new URLSearchParams();
    if (status) q.set('status', status);
    if ($('sw-q').value.trim()) q.set('q', $('sw-q').value.trim());
    if ($('sw-system').checked) q.set('system', '1');
    if (picked) q.set('id', picked);
    history.replaceState(null, '', `?${q}`);
  }

  async function load() {
    remember();
    if (pending) pending.abort();
    const mine = pending = new AbortController();
    const q = new URLSearchParams({ sort, order, limit: LIMIT, offset, include_system: $('sw-system').checked });
    if (status) q.set('status', status);
    if ($('sw-q').value.trim()) q.set('q', $('sw-q').value.trim());
    $('sw-rows').style.opacity = '.5';
    try {
      const d = await get(`${API}?${q}`, mine.signal);
      if (mine !== pending || !d) return;
      Object.entries(d.counts).forEach(([k, v]) => { const el = document.querySelector(`[data-count="${k}"]`); if (el) el.textContent = `(${n(v)})`; });
      $('sw-sub').textContent = d.scoped ? 'Third-party software on the assets you have access to, one title per product.'
        : 'Third-party software on your assets, one title per product. Approve it or mark it unauthorized.';
      $('sw-rows').innerHTML = d.titles.map(t => `<tr data-id="${esc(t.id)}" class="${t.id === picked ? 'is-picked' : ''}" style="cursor:pointer">
          <td class="text-sm"><b>${esc(t.title)}</b> <button type="button" class="sw-vers" data-open="${esc(t.id)}" title="See every version">(${esc(n(t.versions))} version${t.versions === 1 ? '' : 's'})</button>
            ${t.system ? ' <span class="chip chip--info" style="font-size:.65rem">system</span>' : ''}</td>
          <td class="text-sm text-muted">${esc(t.vendor || '--')}</td>
          <td class="text-sm">${esc(n(t.assets))}</td>
          <td><span class="chip ${CHIP[t.status]}">${esc(LABEL[t.status])}</span></td></tr>`).join('')
        || `<tr><td colspan="4" class="text-muted text-sm" style="text-align:center;padding:16px">${
          $('sw-q').value || status ? 'No software matches.' : 'No software yet. It arrives with the InsightVM console shipper’s next software run (once a day).'}</td></tr>`;
      const end = Math.min(offset + LIMIT, d.total);
      $('sw-page').textContent = d.total ? `${n(offset + 1)} to ${n(end)} of ${n(d.total)} titles` : '';
      $('sw-prev').disabled = offset === 0;
      $('sw-next').disabled = end >= d.total;
    } catch (e) {
      if (mine !== pending || e.name === 'AbortError') return;
      $('sw-rows').innerHTML = '<tr><td colspan="4" class="text-muted text-sm" style="text-align:center;padding:16px">Software could not load. Try again in a minute.</td></tr>';
    } finally {
      if (mine === pending) { pending = null; $('sw-rows').style.opacity = ''; }
    }
  }

  async function assets(id, version) {
    const box = $('sw-assets');
    if (!box) return;
    box.innerHTML = '<p class="text-muted text-sm">Loading...</p>';
    const q = new URLSearchParams({ limit: 200 });
    if (version != null) q.set('version', version);
    let d;
    try { d = await get(`${API}/${encodeURIComponent(id)}/assets?${q}`); } catch (e) { d = null; }
    if (!d) { box.innerHTML = '<p class="text-muted text-sm">The assets could not load.</p>'; return; }
    box.innerHTML = `<h3 style="font-size:14px;margin:0 0 6px">${version != null ? `Version ${esc(version)}` : 'Every version'}: ${esc(n(d.total))} asset${d.total === 1 ? '' : 's'}</h3>
      <div style="max-height:360px;overflow:auto"><table class="data-table"><thead><tr><th>Asset</th><th>Version</th><th>OS</th><th>Last reported</th></tr></thead><tbody>
      ${d.assets.map(a => `<tr><td class="text-sm"><a class="dt-link" href="/devices/${encodeURIComponent(a.id)}#software">${esc(a.hostname)}</a>${
        a.exception && a.exception.active ? ` <span class="chip ${a.exception.decision === 'allowed' ? 'chip--low' : 'chip--critical'}" style="font-size:.65rem" title="${esc(a.exception.reason)}">${a.exception.decision === 'allowed' ? 'allowed here' : 'not allowed here'}</span>` : ''}</td>
        <td class="text-sm">${esc(a.version)}</td><td class="text-sm text-muted">${esc(a.os || '--')}</td>
        <td class="text-sm text-muted">${a.last_seen ? esc(new Date(a.last_seen).toLocaleDateString()) : '--'}</td></tr>`).join('')
        || '<tr><td colspan="4" class="text-muted text-sm" style="text-align:center;padding:12px">None</td></tr>'}</tbody></table></div>
      ${d.total > d.assets.length ? `<p class="text-sm text-muted">Showing the first ${esc(n(d.assets.length))}.</p>` : ''}`;
  }

  async function detail(id) {
    picked = id;
    remember();
    document.querySelectorAll('#sw-rows tr[data-id]').forEach(tr => tr.classList.toggle('is-picked', tr.dataset.id === id));
    const box = $('sw-detail');
    box.hidden = false;
    box.innerHTML = '<div class="text-muted text-sm">Loading...</div>';
    let d;
    try { d = await get(`${API}/${encodeURIComponent(id)}`); } catch (e) { d = null; }
    if (picked !== id) return;
    if (!d) { box.innerHTML = '<div class="text-muted text-sm">That software isn\'t available to you.</div>'; return; }
    box.innerHTML = `<div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap">
        <div><h2>${esc(d.title)} <span class="chip ${CHIP[d.status]}" style="font-size:.7rem;vertical-align:middle">${esc(LABEL[d.status])}</span></h2>
          <div class="text-sm text-muted">${esc(d.vendor || 'Unknown vendor')} · ${esc(n(d.versions.length))} version${d.versions.length === 1 ? '' : 's'}${
            d.decided_by ? ` · ${esc(LABEL[d.status].toLowerCase())} by ${esc(d.decided_by)} ${esc(new Date(d.decided_at).toLocaleDateString())}` : ''}${
            d.status_note ? ` · "${esc(d.status_note)}"` : ''}</div>
          ${d.reported_as.length ? `<div class="text-sm text-muted" style="margin-top:2px">Reported as: ${esc(d.reported_as.slice(0, 6).join('; '))}${d.reported_as.length > 6 ? '...' : ''}</div>` : ''}</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          ${d.can_decide ? `<input id="sw-note" class="form-input" maxlength="1000" placeholder="Note (optional)" value="${esc(d.status_note || '')}" style="width:220px">
            <button type="button" class="btn btn--primary btn--sm" data-decide="approved">Approve</button>
            <button type="button" class="btn btn--ghost btn--sm" data-decide="unauthorized" style="color:var(--severity-critical)">Mark unauthorized</button>
            ${d.status !== 'unreviewed' ? '<button type="button" class="btn btn--ghost btn--sm" data-decide="unreviewed">Clear</button>' : ''}` : ''}
          <button type="button" class="btn btn--ghost btn--sm" id="sw-close">Close</button></div></div>
      <p id="sw-msg" class="text-sm" role="status" style="min-height:1em;margin:6px 0 0"></p>
      <div class="sw-cols">
        <div><h3 style="font-size:14px;margin:0 0 6px">Versions</h3>
          <div style="max-height:360px;overflow:auto"><table class="data-table"><thead><tr><th>Version</th><th>Assets</th></tr></thead><tbody>
          <tr data-ver="" style="cursor:pointer"><td class="text-sm"><b>Every version</b></td><td class="text-sm">${esc(n(d.versions.reduce((s, v) => s + v.assets, 0)))}</td></tr>
          ${d.versions.map(v => `<tr data-ver="${esc(v.version)}" style="cursor:pointer"><td class="text-sm">${esc(v.version)}</td><td class="text-sm">${esc(n(v.assets))}</td></tr>`).join('')}
          </tbody></table></div></div>
        <div id="sw-assets"></div></div>`;
    $('sw-close').onclick = () => { box.hidden = true; picked = ''; remember(); document.querySelectorAll('#sw-rows tr.is-picked').forEach(tr => tr.classList.remove('is-picked')); };
    box.querySelectorAll('[data-decide]').forEach(b => b.addEventListener('click', async () => {
      b.disabled = true;
      const r = await fetch(`${API}/${encodeURIComponent(id)}/status`, { method: 'PUT', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                                                                         body: JSON.stringify({ status: b.dataset.decide, note: $('sw-note').value.trim() || null }) });
      b.disabled = false;
      if (!r.ok) { $('sw-msg').textContent = r.status === 422 ? 'The note can\'t contain < or >.' : 'Could not save.'; return; }
      await detail(id);
      load();
    }));
    box.querySelectorAll('tr[data-ver]').forEach(tr => tr.addEventListener('click', () => {
      box.querySelectorAll('tr[data-ver]').forEach(x => x.classList.toggle('is-picked', x === tr));
      assets(id, tr.dataset.ver === '' ? null : tr.dataset.ver);
    }));
    assets(id, null);
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  $('sw-status').addEventListener('click', e => {
    const b = e.target.closest('[data-status]');
    if (!b) return;
    status = b.dataset.status;
    offset = 0;
    document.querySelectorAll('#sw-status [data-status]').forEach(x => x.setAttribute('aria-pressed', String(x.dataset.status === status)));
    load();
  });
  document.querySelectorAll('[data-sort]').forEach(b => b.addEventListener('click', () => {
    const text = ['title', 'vendor', 'status'].includes(b.dataset.sort);
    order = sort === b.dataset.sort ? (order === 'asc' ? 'desc' : 'asc') : (text ? 'asc' : 'desc');   // same column flips
    sort = b.dataset.sort;
    offset = 0;
    load();
  }));
  let typing;
  $('sw-q').addEventListener('input', () => { clearTimeout(typing); typing = setTimeout(() => { offset = 0; load(); }, 300); });
  $('sw-system').addEventListener('change', () => { offset = 0; load(); });
  $('sw-prev').addEventListener('click', () => { offset = Math.max(0, offset - LIMIT); load(); });
  $('sw-next').addEventListener('click', () => { offset += LIMIT; load(); });
  $('sw-rows').addEventListener('click', e => {
    const tr = e.target.closest('tr[data-id]');
    if (tr) detail(tr.dataset.id);
  });

  document.querySelectorAll('#sw-status [data-status]').forEach(x => x.setAttribute('aria-pressed', String(x.dataset.status === status)));
  load();
  if (picked) detail(picked);
})();
