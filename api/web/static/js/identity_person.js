// Identity > one person (GET /api/v1/identity/people/{id}): who they are, their scores, the apps holding their weak,
// reused or leaked passwords, the notice asking them to change them (POST .../notify), their ITDR alerts and findings.
(async () => {
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const when = s => (s ? new Date(s).toLocaleString() : '--');
  const SEV = { critical: 'chip--critical', high: 'chip--high', medium: 'chip--medium', low: 'chip--low' };
  const chip = s => `<span class="chip ${SEV[s] || 'chip--info'}">${esc(s || '--')}</span>`;
  const id = new URLSearchParams(location.search).get('id') || '';
  if (!/^[0-9a-f-]{36}$/i.test(id)) { $('ip-name').textContent = 'Identity not found'; return; }
  const r = await fetch(`/api/v1/identity/people/${encodeURIComponent(id)}`, { headers: { Accept: 'application/json' } });
  if (!r.ok) { $('ip-name').textContent = r.status === 404 ? 'Identity not found' : 'Could not load this identity'; return; }
  const d = await r.json(), p = d.person, c = d.credentials;

  $('ip-name').textContent = p ? p.name : (d.user_display || 'Unknown identity');
  document.title = `${p ? p.name : 'Identity'} -- open-ctem`;
  $('ip-sub').innerHTML = p
    ? [p.email, p.title, p.username, p.disabled ? '<span class="chip chip--critical">Disabled in the directory</span>' : '',
       p.last_logon ? `Last logon ${esc(when(p.last_logon))}` : ''].filter(Boolean).map(x => x.startsWith('<span') ? x : esc(x)).join(' &middot; ')
    : `Grip identity ${esc(d.user_display || '')}, not matched to anyone in the directory`;
  if (p) $('ip-actions').innerHTML = `<a class="btn btn--ghost btn--sm" href="/users?person=${encodeURIComponent(p.id)}">Directory record &rsaquo;</a>`;

  const tile = (n, label) => `<div class="ip-tile"><b>${esc(n ?? '--')}</b>${esc(label)}</div>`;
  const sc = d.scores;
  $('ip-tiles').innerHTML = [tile(Math.round(sc.composite_identity_score || 0), 'Identity risk'), tile(c.leaked, 'Leaked passwords'),
    tile(c.reused, 'Reused passwords'), tile(c.weak, 'Weak passwords'), tile(c.mfa_coverage_pct == null ? '--' : `${c.mfa_coverage_pct}%`, 'MFA coverage'),
    tile(c.risky_extensions, 'Risky extensions'), tile(d.threats.length, 'ITDR alerts'), tile(d.posture.length, 'Posture findings')].join('');

  const yes = (on, cls, word) => (on ? `<span class="chip ${cls}">${word}</span>` : '');
  $('ip-pw').innerHTML = c.apps.length
    ? `<table class="data-table"><thead><tr><th>App</th><th>What is wrong</th><th>How sure</th></tr></thead><tbody>${c.apps.map(a => `<tr>
        <td><b>${esc(a.app)}</b></td>
        <td>${yes(a.leaked, 'chip--critical', 'Leaked in a breach list')} ${yes(a.reused, 'chip--high', 'Reused elsewhere')} ${yes(a.weak, 'chip--medium', 'Weak')}</td>
        <td class="text-sm">${a.certain ? 'This account' : '<span class="text-muted">Possibly this account</span>'}</td></tr>`).join('')}</tbody></table>`
    : `<p class="text-sm text-muted" style="padding:12px 16px;margin:0">${c.leaked || c.reused || c.weak
        ? 'Grip counts passwords at risk for this person but has not tied them to an app yet; they appear after the next Grip sync.'
        : 'No weak, reused or leaked passwords known for this person (Grip only knows where its browser extension runs).'}</p>`;

  if (d.notice) {
    $('ip-notice-panel').style.display = '';
    $('ip-to').textContent = d.notice.to || '';
    $('ip-subject').textContent = d.notice.subject;
    $('ip-body').textContent = d.notice.body;
    $('ip-notified').textContent = d.notified_at ? `Last sent ${when(d.notified_at)} by ${d.notified_by}` : 'Not sent yet';
    const msg = (t, bad) => { $('ip-msg').textContent = t; $('ip-msg').style.color = bad ? 'var(--severity-critical)' : 'var(--severity-low)'; };
    if (!d.email_on) {
      $('ip-send').disabled = true;
      $('ip-send').title = 'Email is turned off: set it up in Settings, or copy the message';
      msg('Email is turned off in Settings, so copy the message and send it yourself.', false);
      $('ip-msg').style.color = 'var(--text-muted)';
    }
    $('ip-copy').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(`To: ${d.notice.to}\nSubject: ${d.notice.subject}\n\n${d.notice.body}`); msg('Copied.'); }
      catch (_) { msg('Copy failed; select the message and copy it.', true); }
    });
    $('ip-send').addEventListener('click', async () => {
      if (!confirm(`Email this notice to ${d.notice.to}?`)) return;
      $('ip-send').disabled = true;
      try {
        const s = await fetch(`/api/v1/identity/people/${encodeURIComponent(id)}/notify`, { method: 'POST', credentials: 'same-origin',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ confirm: true }) });
        const b = await s.json().catch(() => ({}));
        if (!s.ok) throw new Error(typeof b.detail === 'string' ? b.detail : 'The server refused that.');
        msg('Sent.');
        $('ip-notified').textContent = `Last sent ${when(b.notified_at)} by you`;
      } catch (e) { msg(e.message, true); $('ip-send').disabled = false; }
    });
  }

  $('ip-threats').innerHTML = d.threats.length ? d.threats.map(t => `<tr><td>${chip(t.severity)}</td>
      <td class="text-sm">${esc((t.threat_type || '').replace(/_/g, ' '))}</td><td class="text-sm"><b>${esc(t.title)}</b>
      ${t.description ? `<br><span class="text-muted">${esc(t.description)}</span>` : ''}</td><td class="text-sm">${esc(t.app_name || '--')}</td>
      <td class="text-sm">${esc(t.status)}</td><td class="text-sm">${esc(when(t.detected_at))}</td></tr>`).join('')
    : '<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:16px">None</td></tr>';
  $('ip-posture').innerHTML = d.posture.length ? d.posture.map(f => `<tr class="id-row" tabindex="0" data-kind="posture" data-id="${esc(f.id)}">
      <td>${chip(f.severity)}</td><td class="text-sm"><b>${esc(f.title)}</b></td><td class="text-sm">${esc(f.app_name || '--')}</td>
      <td class="text-sm">${esc(when(f.detected_at))}</td></tr>`).join('')
    : '<tr><td colspan="4" class="text-muted text-sm" style="text-align:center;padding:16px">None</td></tr>';
})();
