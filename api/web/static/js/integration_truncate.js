// Settings > Integrations: Truncate (admins) removes the data a source reported, behind a warning that says what
// goes, what's shared with other integrations of the same vendor, and needs the integration's name typed to confirm.
(() => {
  const $ = id => document.getElementById(id);
  const NO_DATA = new Set(['ai', 'anthropic', 'openai', 'custom_ai', 'bedrock', 'fairtprm', 'servicenow', 'email']);
  const n = v => Number(v || 0).toLocaleString();

  window.truncateBtn = i => window._canTruncate && !NO_DATA.has(i.vendor)
    ? `<button class="btn btn--ghost btn--sm" style="color:var(--severity-critical)" onclick="openTruncate('${esc(i.id)}')">Truncate</button>`
    : '';

  // A shipper warning, a failure's reason or a truncate note, under the card's last sync line
  window.syncNote = i => {
    if (!i.last_sync_note) return '';
    const failed = i.last_sync_status === 'failed', warn = /warning:/i.test(i.last_sync_note);
    const color = failed ? 'var(--severity-critical)' : warn ? 'var(--severity-medium)' : 'var(--text-muted)';
    return `<div class="text-sm" role="status" style="margin:-6px 0 12px;color:${color}">${failed || warn ? '&#9888; ' : ''}${esc(i.last_sync_note)}</div>`;
  };

  function dialog() {
    let wrap = $('trunc-dialog');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'trunc-dialog';
      wrap.className = 'tk-backdrop';
      wrap.setAttribute('role', 'alertdialog');
      wrap.setAttribute('aria-modal', 'true');
      wrap.setAttribute('aria-labelledby', 'trunc-title');
      document.body.appendChild(wrap);
    }
    return wrap;
  }

  window.openTruncate = async id => {
    const wrap = dialog();
    wrap.innerHTML = '<div class="tk-dialog" style="max-width:540px"><p class="text-muted">Counting what this would remove...</p></div>';
    wrap.classList.add('is-open');
    const r = await fetch(`/api/v1/integrations/${encodeURIComponent(id)}/truncate`, { headers: { Accept: 'application/json' } });
    const p = r.ok ? await r.json() : null;
    if (!p || !p.truncatable) {
      wrap.innerHTML = `<div class="tk-dialog" style="max-width:540px"><p>${p ? 'This integration doesn\'t report data.' : 'Could not load this integration.'}</p>
        <div style="text-align:right"><button type="button" class="btn btn--ghost btn--sm" id="trunc-cancel">Close</button></div></div>`;
      $('trunc-cancel').onclick = () => wrap.classList.remove('is-open');
      return;
    }
    const shared = p.shared_with.length
      ? `<p style="color:var(--severity-critical)"><b>Shared data:</b> ${p.shared_with.map(esc).join(', ')} report${p.shared_with.length === 1 ? 's' : ''}
         as the same source (${esc(p.source)}), so ${p.shared_with.length === 1 ? 'its' : 'their'} data is removed too.</p>` : '';
    wrap.innerHTML = `<div class="tk-dialog" style="max-width:540px">
      <h2 class="tk-title" id="trunc-title" style="color:var(--severity-critical)">&#9888; Truncate ${esc(p.name)}?</h2>
      <p class="tk-sub">This permanently removes the data this integration reported. It can't be undone; the next sync brings back what the source still reports.</p>
      <ul class="text-sm" style="margin:8px 0 12px 18px;line-height:1.6">
        <li><b>${n(p.findings)}</b> findings (tickets and risk exceptions on them lose their link)</li>
        <li><b>${n(p.assets_deleted)}</b> assets only this source reports, deleted with their assignments and history</li>
        <li><b>${n(p.assets_kept)}</b> assets other sources also report: kept, minus this source's data</li>
        <li><b>${n(p.software_installs)}</b> software installs</li>
        <li>Cached alerts, tag links and the sync history, so the next sync is a full one</li></ul>
      ${shared}
      <p class="text-sm text-muted">Kept: software review decisions, tags and access rules, and vulnerabilities with an exception. Scores are recalculated afterwards.</p>
      ${p.running ? '<p style="color:var(--severity-medium)">A truncate of this source is running now.</p>' : ''}
      <label class="form-label" for="trunc-confirm">Type <b>${esc(p.name)}</b> to confirm</label>
      <input id="trunc-confirm" class="form-input" autocomplete="off" spellcheck="false">
      <p id="trunc-msg" class="text-sm" role="status" style="min-height:1.2em;margin:8px 0 0;color:var(--severity-critical)"></p>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px">
        <button type="button" class="btn btn--ghost btn--sm" id="trunc-cancel">Cancel</button>
        <button type="button" class="btn btn--sm" id="trunc-go" disabled style="background:var(--severity-critical);color:#fff">Truncate data</button></div></div>`;
    const input = $('trunc-confirm'), go = $('trunc-go');
    input.focus();
    input.oninput = () => { go.disabled = p.running || input.value.trim() !== (p.name || '').trim(); };
    $('trunc-cancel').onclick = () => wrap.classList.remove('is-open');   // only its own buttons close it
    go.onclick = async () => {
      go.disabled = true;
      const res = await fetch(`/api/v1/integrations/${encodeURIComponent(id)}/truncate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ confirm: input.value }) });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        $('trunc-msg').textContent = typeof e.detail === 'string' ? e.detail : 'Could not start the truncate.';
        go.disabled = false;
        return;
      }
      wrap.classList.remove('is-open');
      if (typeof toast === 'function') toast('Truncating in the background; the card updates when it finishes', 'success');
      setTimeout(loadIntegrations, 5000);
    };
  };
})();
