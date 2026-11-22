// The asset page's Software tab: what's installed (third-party by default), each title once with its versions here,
// its review status and when it was last reported. The Findings | Software choice is kept in the link (#software).
window.AssetSoftware = (() => {
  const CHIP = { approved: 'chip--low', unauthorized: 'chip--critical', unreviewed: 'chip--info' };
  const LABEL = { approved: 'Approved', unauthorized: 'Unauthorized', unreviewed: 'Unreviewed' };
  const $ = id => document.getElementById(id);
  let deviceId = null;

  function show(which) {
    const sw = which === 'software';
    $('tab-findings').setAttribute('aria-selected', String(!sw));
    $('tab-software').setAttribute('aria-selected', String(sw));
    $('dev-findings-panel').hidden = sw;
    $('dev-software-panel').hidden = !sw;
    history.replaceState(null, '', sw ? '#software' : location.pathname + location.search);
  }

  // A per-asset exception: allowed here although unauthorized elsewhere, or not allowed here although approved
  function exceptionDialog(s, decision) {
    let wrap = $('swx-dialog');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'swx-dialog';
      wrap.className = 'tk-backdrop';
      wrap.setAttribute('role', 'dialog');
      wrap.setAttribute('aria-modal', 'true');
      wrap.setAttribute('aria-labelledby', 'swx-title');
      document.body.appendChild(wrap);
    }
    const today = new Date().toISOString().slice(0, 10);
    const max = new Date(Date.now() + 730 * 864e5).toISOString().slice(0, 10);
    wrap.innerHTML = `<div class="tk-dialog" style="max-width:520px">
        <h2 class="tk-title" id="swx-title">${decision === 'allowed' ? 'Allow on this asset' : 'Not allowed on this asset'}</h2>
        <p class="tk-sub"><b>${esc(s.title)}</b>: ${decision === 'allowed'
          ? 'allowed on this asset, whatever its status elsewhere. It stops counting as unauthorized here.'
          : 'not allowed on this asset, even if it is approved elsewhere. It counts as unauthorized here.'}</p>
        <label class="form-label" for="swx-reason">Reason</label>
        <textarea id="swx-reason" class="form-input" rows="3" maxlength="1000" placeholder="For example: needed for the payroll export, approved by the finance lead">${esc((s.exception || {}).reason || '')}</textarea>
        <label class="form-label" for="swx-end" style="margin-top:8px">Ends <span class="text-muted">(optional)</span></label>
        <input id="swx-end" type="date" class="form-input" style="width:auto" min="${today}" max="${max}">
        <p id="swx-msg" class="text-sm" role="status" style="min-height:1.2em;margin:8px 0 0;color:var(--severity-critical)"></p>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px">
          <button type="button" class="btn btn--ghost btn--sm" id="swx-cancel">Cancel</button>
          <button type="button" class="btn btn--primary btn--sm" id="swx-save">Save</button></div></div>`;
    wrap.classList.add('is-open');
    $('swx-reason').focus();
    $('swx-cancel').onclick = () => wrap.classList.remove('is-open');   // only its own buttons close it
    $('swx-save').onclick = async () => {
      const reason = $('swx-reason').value.trim();
      if (reason.length < 5 || /[<>]/.test(reason)) { $('swx-msg').textContent = 'Give a reason of at least 5 characters, without < or >.'; return; }
      $('swx-save').disabled = true;
      const r = await fetch(`/api/v1/software/${encodeURIComponent(s.id)}/exceptions/${encodeURIComponent(deviceId)}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ decision, reason, expires_on: $('swx-end').value || null }) });
      $('swx-save').disabled = false;
      if (!r.ok) { $('swx-msg').textContent = r.status === 422 ? 'Check the reason and the end date (within 2 years).' : 'Could not save.'; return; }
      wrap.classList.remove('is-open');
      load();
    };
  }

  const short = h => (h ? `${h.slice(0, 12)}...` : '');
  function files(s) {
    if (!s.files.length) return '';
    return `<tr class="sw-files" data-files="${esc(s.id)}" hidden><td colspan="6" class="text-sm" style="background:var(--bg)">
      ${s.files.map(f => `<div style="display:grid;grid-template-columns:110px minmax(0,1fr);gap:2px 10px;margin:4px 0">
        <span class="text-muted">Version</span><span>${esc(f.version)} <span class="text-muted">(${esc(String(f.source).replace(/_/g, ' '))})</span></span>
        ${f.publisher ? `<span class="text-muted">Publisher</span><span>${esc(f.publisher)}</span>` : ''}
        ${f.path ? `<span class="text-muted">Path</span><span class="text-mono" style="overflow-wrap:anywhere">${esc(f.path)}</span>` : ''}
        ${f.sha256 ? `<span class="text-muted">SHA-256</span><span class="text-mono" style="overflow-wrap:anywhere">${esc(f.sha256)}</span>` : ''}
        ${f.md5 ? `<span class="text-muted">MD5</span><span class="text-mono">${esc(f.md5)}</span>` : ''}</div>`).join('')}</td></tr>`;
  }

  async function load() {
    const body = $('dev-software');
    body.innerHTML = '<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:14px">Loading...</td></tr>';
    let d;
    try {
      const r = await fetch(`/api/v1/software/device/${encodeURIComponent(deviceId)}?include_system=${$('dev-software-system').checked}`,
                            { headers: { Accept: 'application/json' } });
      d = r.ok ? await r.json() : null;
    } catch (e) { d = null; }
    if (!d) { body.innerHTML = '<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:14px">Software could not load.</td></tr>'; return; }
    const rows = d.software.sort((a, b) => (b.status_here === 'unauthorized') - (a.status_here === 'unauthorized') || a.title.localeCompare(b.title));
    const bad = rows.filter(s => s.status_here === 'unauthorized').length;
    $('dev-software-count').textContent = rows.length ? `(${rows.length})` : '';
    $('dev-software-note').innerHTML = bad ? `<span class="chip chip--critical" style="font-size:.7rem">${bad} unauthorized here</span>` : '';
    const byId = Object.fromEntries(rows.map(s => [s.id, s]));
    body.innerHTML = rows.map(s => {
      const x = s.exception && s.exception.active ? s.exception : null;
      const pub = (s.files.find(f => f.publisher) || {}).publisher;
      const sha = (s.files.find(f => f.sha256) || {}).sha256;
      return `<tr><td class="text-sm"><a class="dt-link" href="/software?id=${encodeURIComponent(s.id)}">${esc(s.title)}</a>
          ${s.system ? ' <span class="chip chip--info" style="font-size:.65rem">system</span>' : ''}
          ${sha ? `<div class="text-mono text-muted" style="font-size:.72rem" title="SHA-256 ${esc(sha)}">${esc(short(sha))}</div>` : ''}</td>
        <td class="text-sm text-muted">${esc(pub || s.vendor || '--')}</td>
        <td class="text-sm">${esc(s.versions.join(', '))}</td>
        <td><span class="chip ${CHIP[s.status_here]}" style="font-size:.7rem" title="${esc(x ? x.reason : (s.status_note || ''))}">${esc(LABEL[s.status_here])}</span>
          ${x ? `<div class="text-sm text-muted" title="${esc(x.reason)}">${x.decision === 'allowed' ? 'allowed here' : 'not allowed here'} by ${esc(x.decided_by)}${x.expires_at ? ` until ${esc(new Date(x.expires_at).toLocaleDateString())}` : ''}</div>` : ''}</td>
        <td class="text-sm text-muted">${s.last_seen ? esc(new Date(s.last_seen).toLocaleDateString()) : '--'}</td>
        <td class="text-sm nowrap">${s.files.length ? `<button type="button" class="btn btn--ghost btn--sm" data-filebtn="${esc(s.id)}">Details</button>` : ''}
          ${d.can_decide ? (x ? `<button type="button" class="btn btn--ghost btn--sm" data-clear="${esc(s.id)}">Remove exception</button>`
            : s.status === 'unauthorized' ? `<button type="button" class="btn btn--ghost btn--sm" data-allow="${esc(s.id)}">Allow here</button>`
            : `<button type="button" class="btn btn--ghost btn--sm" data-deny="${esc(s.id)}">Not allowed here</button>`) : ''}</td></tr>${files(s)}`;
    }).join('') || `<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:14px">No ${$('dev-software-system').checked ? '' : 'third-party '}software reported for this asset yet.</td></tr>`;
    body.querySelectorAll('[data-filebtn]').forEach(b => b.addEventListener('click', () => {
      const r = body.querySelector(`tr[data-files="${CSS.escape(b.dataset.filebtn)}"]`);
      if (r) r.hidden = !r.hidden;
    }));
    body.querySelectorAll('[data-allow]').forEach(b => b.addEventListener('click', () => exceptionDialog(byId[b.dataset.allow], 'allowed')));
    body.querySelectorAll('[data-deny]').forEach(b => b.addEventListener('click', () => exceptionDialog(byId[b.dataset.deny], 'denied')));
    body.querySelectorAll('[data-clear]').forEach(b => b.addEventListener('click', async () => {
      b.disabled = true;
      const r = await fetch(`/api/v1/software/${encodeURIComponent(b.dataset.clear)}/exceptions/${encodeURIComponent(deviceId)}`,
                            { method: 'DELETE', headers: { Accept: 'application/json' } });
      if (r.ok) load(); else b.disabled = false;
    }));
  }

  function mount(id) {
    deviceId = id;
    $('tab-findings').onclick = () => show('findings');
    $('tab-software').onclick = () => show('software');
    $('dev-software-system').onchange = load;
    load();
    if (location.hash === '#software') show('software');
  }
  return { mount };
})();
