// Cyber Threats > alert: accept it (the allow list), so it raises no more hunt, hourly-check or SIEM findings. The
// entry is this detection, narrowed by whatever the person keeps ticked (host, process, parent process, file, hash), with a reason and an
// end date. Rules in api/core/alert_allow.py; everything goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const call = async (url, opts) => {
    const r = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, ...opts });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'The server refused that.');
    return d;
  };
  const inDays = n => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);

  function shown(e) {
    const scope = [['host', e.hostname], ['process', e.process], ['parent process', e.parent], ['file', e.file], ['hash', e.sha256]].filter(x => x[1]);
    $('al-allow').innerHTML = `<p style="margin:0 0 6px"><span class="chip chip--low">Accepted</span>
        by ${esc(e.created_by)} until ${esc(new Date(e.expires_at).toLocaleDateString())}: ${esc(e.reason)}</p>
      <p class="text-sm text-muted" style="margin:0 0 8px">Matches the detection${scope.length ? ` when ${scope.map(([k, v]) => `${esc(k)} is ${esc(v)}`).join(', ')}` : ' anywhere'}.
        It raises no hunt, hourly-check or SIEM findings; the alert itself stays here. Matched ${esc(e.hits)} time${e.hits === 1 ? '' : 's'}.</p>
      <button type="button" class="btn btn--ghost btn--sm" id="al-allow-off">Stop accepting it</button>`;
    $('al-allow-off').addEventListener('click', async () => {
      try { await call(`/api/v1/threat/allow/${encodeURIComponent(e.id)}`, { method: 'PUT', body: JSON.stringify({ enabled: false }) }); location.reload(); }
      catch (err) { $('al-allow').insertAdjacentHTML('beforeend', `<p class="text-sm" style="color:var(--severity-critical)">${esc(err.message)}</p>`); }
    });
  }

  async function form(a) {
    let s;
    try { s = await call(`/api/v1/threat/allow/suggest?id=${encodeURIComponent(a.id)}`); } catch (e) { return; }
    const opt = (k, label, v, on) => (v ? `<label class="text-sm" style="display:flex;gap:6px;align-items:flex-start;overflow-wrap:anywhere">
        <input type="checkbox" data-k="${esc(k)}" data-v="${esc(v)}"${on ? ' checked' : ''}> <span>Only when the ${esc(label)} is <span class="text-mono">${esc(v)}</span></span></label>` : '');
    $('al-allow').innerHTML = `<p class="text-sm text-muted" style="margin:0 0 8px">Accept <b>${esc(s.title)}</b> as expected here, so it raises
        no more hunt, hourly-check or SIEM findings. The alert stays in CTEM and in ${esc(s.source || 'the tool')}. Keep it narrow:</p>
      <div style="display:grid;gap:6px;margin-bottom:10px">${opt('hostname', 'host', s.hostname, true)}${opt('process', 'process', s.process, true)}${opt('parent', 'parent process', s.parent, true)}
        ${opt('file', 'file', s.file, !!s.file)}${opt('sha256', 'process hash', s.sha256, false)}</div>
      <label class="text-sm">Why it's acceptable (at least 10 characters)
        <textarea id="al-allow-reason" class="form-input" rows="2" maxlength="1000" style="margin-top:4px" placeholder="For example: the backup agent reads LSASS by design (change CHG0012345)"></textarea></label>
      <div style="display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin-top:8px">
        <label class="text-sm">Until<input id="al-allow-until" class="form-input" type="date" value="${inDays(90)}" min="${inDays(1)}" max="${inDays(366)}" style="margin-top:4px"></label>
        <button type="button" class="btn btn--primary btn--sm" id="al-allow-save">Accept this alert</button>
        <span id="al-allow-msg" class="text-sm"></span></div>`;
    $('al-allow-save').addEventListener('click', async () => {
      const body = { title: s.title, source: s.source || null, reason: $('al-allow-reason').value.trim(), expires_on: $('al-allow-until').value };
      $('al-allow').querySelectorAll('input[data-k]').forEach(c => { if (c.checked) body[c.dataset.k] = c.dataset.v; });
      try { await call('/api/v1/threat/allow', { method: 'POST', body: JSON.stringify(body) }); location.reload(); }
      catch (err) { $('al-allow-msg').textContent = err.message; $('al-allow-msg').style.color = 'var(--severity-critical)'; }
    });
  }

  function render(a) {
    if (!a.title) return;
    $('al-allow-panel').style.display = '';
    if (a.accepted_by) shown(a.accepted_by);
    else $('al-allow').innerHTML = '<button type="button" class="btn btn--ghost btn--sm" id="al-allow-start">Accept this alert…</button>';
    const start = $('al-allow-start');
    if (start) start.addEventListener('click', () => form(a));
  }

  window.AlertAllow = { render };
})();
