// IDV page (cyber, admin, IDV approvers): Persona identity verifications in Pending, Approved and Rejected tabs.
// Clicking a row (or Review, right after the name) opens the request in full: why it needs a decision, what the
// person presented, which checks failed and what to validate, their other attempts, the device. IDV approvers decide
// there (a reason from the list and a note), can compare the name on the ID with the directory (read live, never
// kept), and can revoke a verified person. Everything shown goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const API = '/api/v1/idv';
  const STATE = { pending: ['info', 'In progress'], review: ['high', 'Needs review'], approved: ['low', 'Verified'],
                  rejected: ['critical', 'Rejected'], expired: ['info', 'Expired'], superseded: ['info', 'Failed, passed later'] };
  const FLAG = { vpn: 'VPN', proxy: 'Proxy', tor: 'Tor', datacenter: 'Datacenter' };
  const CHECK_STATE = { passed: 'low', failed: 'critical', not_applicable: 'info' };
  const day = s => (s ? new Date(s).toLocaleString() : '--');
  const chip = (c, t) => `<span class="chip chip--${c}" style="font-size:.7rem">${esc(t)}</span>`;
  const words = s => String(s || '').replace(/_/g, ' ');
  let tab = new URLSearchParams(location.search).get('tab') || 'pending', table, cur = null, names = null;
  if (!['pending', 'approved', 'rejected'].includes(tab)) tab = 'pending';

  async function getJson(url, opts) {
    const r = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, ...opts });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'That did not go through.');
    return d;
  }

  async function tabs() {
    let s = {};
    try { s = await getJson(`${API}/summary`); } catch (e) { /* tabs still work */ }
    const list = [['pending', 'Pending', s.review], ['approved', 'Approved'], ['rejected', 'Rejected']];
    $('idv-tabs').innerHTML = list.map(([v, l, n]) =>
      `<button type="button" role="tab" class="btn btn--sm ${v === tab ? 'btn--primary' : 'btn--ghost'}" data-tab="${v}" aria-selected="${v === tab}">${esc(l)}${
        n ? ` <span class="count-bubble" title="${esc(n)} waiting for review">${esc(n > 99 ? '99+' : n)}</span>` : ''}</button>`).join('');
  }

  const person = r => (r.person
    ? `<b>${esc(r.person.name)}</b>${IdvBadge.html(r.person.idv_verified_at, false)}<div class="text-sm text-muted text-mono">${esc(r.person.upn || '')}</div>`
    : '<span class="text-muted text-sm">Not matched to a person yet</span>');
  const device = r => `<span class="text-sm">${esc([r.device_type, r.os, r.browser].filter(Boolean).join(' · ') || '--')}</span>${
    (r.flags || []).map(f => ` ${chip('critical', FLAG[f] || f)}`).join('')}${
    r.threat_level && r.threat_level !== 'low' ? ` ${chip('high', `Threat ${r.threat_level}`)}` : ''}`;

  function start() {
    history.replaceState(null, '', `?tab=${tab}`);
    table = DataTable.create({
      mount: $('idv-table'), endpoint: `${API}/requests`, listKey: 'requests',
      emptyText: { pending: 'Nothing waiting', approved: 'No verified identities yet', rejected: 'Nothing rejected or expired' }[tab],
      params: () => ({ tab, q: $('idv-search').value.trim() }),
      columns: [
        { label: 'Person', render: r => `<span data-open="${esc(r.id)}" style="cursor:pointer">${person(r)}</span>` },
        { label: '', render: r => `<button type="button" class="btn btn--sm ${r.state === 'review' ? 'btn--primary' : 'btn--ghost'}" data-open="${esc(r.id)}">${r.state === 'review' ? 'Review' : 'Details'}</button>` },
        { label: 'Status', render: r => chip(...(STATE[r.state] || ['info', r.state])) + (r.origin === 'service_desk' ? ` ${chip('info', 'Service desk')}` : '') },
        { label: 'Country', render: r => `<span class="text-sm">${esc([r.country, r.region].filter(Boolean).join(' · ') || '--')}</span>` },
        { label: 'ID', render: r => `<span class="text-sm">${esc(r.id_type || '--')}</span>` },
        { label: 'Device', render: device },
        { label: 'Requested', render: r => `<span class="text-sm">${esc(day(r.created_at))}</span>` },
        { label: tab === 'approved' ? 'Verified' : 'Decided', render: r => `<span class="text-sm">${esc(day(r.reviewed_at || r.completed_at || r.decided_at))}</span>` },
        { label: 'Template', render: r => `<span class="text-sm text-muted">${esc(r.template || '--')}</span>` },
      ],
      onLoad: d => { table._rows = d.requests || []; },
    });
  }

  // ── the request in full ───────────────────────────────────────────────────
  const grid = rows => `<table class="data-table" style="width:100%;font-size:13px;margin-bottom:10px"><tbody>${rows}</tbody></table>`;
  const h = t => `<h3 class="text-sm" style="margin:14px 0 4px;text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted)">${esc(t)}</h3>`;
  function body(d) {
    const x = d.explain || {};
    const via = d.origin === 'service_desk' ? 'the service desk' : d.created_via === 'API' ? "Okta's verification flow" : d.created_via ? 'a hosted link (never earns the badge)' : 'unknown';
    let out = `<p class="text-sm" style="margin:0 0 6px">${chip(...(STATE[d.state] || ['info', d.state]))} ${esc(d.template || '')} · requested ${esc(day(d.created_at))} · started by ${esc(via)}</p>`;
    if (d.person) out += `<p class="text-sm" style="margin:0"><a class="dt-link" href="/users?person=${encodeURIComponent(d.person.id)}">${esc(d.person.name)}</a>
      ${IdvBadge.html(d.person.idv_verified_at, true)} <span class="text-muted text-mono">${esc(d.person.upn || '')}</span>
      ${d.person_detail && d.person_detail.title ? `<span class="text-muted"> · ${esc(d.person_detail.title)}</span>` : ''}</p>`;
    if (d.can && d.can.names) out += h('Name and network (read from Persona now, not kept; audited)') + '<div id="idv-live" class="text-sm">Reading from Persona...</div>';
    if (!x.read) out += `<p class="text-sm text-muted">What Persona checked hasn't been read yet; it comes with the next Persona sync.</p>`;
    if ((x.notes || []).length || (x.failed || []).length) {
      out += h(d.state === 'review' ? 'Why this needs a decision' : 'What failed');
      out += (x.notes || []).map(n => `<p class="text-sm" style="margin:2px 0;color:var(--severity-high)"><b>${esc(n)}</b></p>`).join('');
      if ((x.failed || []).length) out += grid(`<tr><th>Failed check</th><th>What it means</th><th>What to validate before approving</th></tr>` +
        x.failed.map(f => `<tr><td><b>${esc(words(f.check).replace(/^id |^selfie /, ''))}</b><div class="text-muted">${esc(f.on)}${f.reasons.length ? ' · ' + esc(f.reasons.map(words).join(', ')) : ''}</div></td>
          <td>${esc(f.means)}</td><td>${esc(f.validate)}</td></tr>`).join(''));
    }
    if ((x.presented || []).length) out += h('What the person presented') + grid(`<tr><th>Verification</th><th>ID</th><th>Country</th><th>Captured</th><th>Result</th><th>When</th></tr>` +
      x.presented.map(p => `<tr><td>${esc(p.kind)}</td><td>${esc(p.id_type || '--')}</td><td>${esc(p.country || '--')}</td><td>${esc(words(p.capture) || '--')}</td>
        <td>${chip(CHECK_STATE[p.status] || 'info', words(p.status))}</td><td class="text-muted">${esc(day(p.at))}</td></tr>`).join(''));
    if ((x.passed_key_checks || []).length) out += h('Key checks') + grid(x.passed_key_checks.map(k =>
      `<tr><td>${esc(words(k.check))}</td><td class="text-muted">${esc(k.on)}</td><td>${chip(CHECK_STATE[k.status] || 'info', words(k.status))}${k.reasons.length ? ` <span class="text-muted">${esc(k.reasons.map(words).join(', '))}</span>` : ''}</td></tr>`).join(''));
    out += h('Device and network') + `<p class="text-sm" style="margin:0">${device(d)}</p>`;
    if ((d.attempts || []).length) out += h(`This person's other attempts (${d.attempts.length})`) + grid(d.attempts.map(a =>
      `<tr><td>${chip(...(STATE[a.state] || ['info', a.state]))}</td><td>${esc(day(a.created_at))}</td><td>${esc([a.id_type, a.country].filter(Boolean).join(' · ') || '--')}</td>
        <td class="text-muted">${esc(a.failed.map(f => words(f)).join(', '))}</td></tr>`).join(''));
    if (d.review_reason || d.review_note) out += h('Decision') + `<p class="text-sm">${esc(words(d.review_reason || ''))}${d.review_note ? ' · ' + esc(d.review_note) : ''} · ${esc(day(d.reviewed_at))}</p>`;
    return out;
  }

  const select = (id, reasons, groups) => `<select id="${id}" class="filter-select" style="width:100%">
    <option value="">Pick a reason...</option>${groups.map(([label, key, set]) => `<optgroup label="${esc(label)}">${
      Object.entries(reasons[set]).map(([k, v]) => `<option value="${esc(key + ':' + k)}">${esc(v)}</option>`).join('')}</optgroup>`).join('')}</select>`;
  function actions(d) {
    if (!d.reasons) return `<p class="text-sm text-muted" style="margin-top:12px">Only members of IDV Approvers can approve, decline or revoke.</p>`;
    let out = '';
    const form = (kind, sel, label, cls) => `${sel}<textarea id="idv-${kind}-note" class="form-input" rows="2" maxlength="500" placeholder="Note: what you checked (kept in the audit log, sent to Persona)" style="width:100%;margin-top:6px"></textarea>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px">${label}</div><p id="idv-${kind}-msg" class="text-sm" role="status" style="min-height:1.2em;margin:4px 0 0"></p>`;
    if (d.can.review) out += h('Decision') + form('review', select('idv-review-reason', d.reasons, [['Approve because', 'approve', 'approve'], ['Decline because', 'decline', 'decline']]),
      `<button type="button" class="btn btn--ghost btn--sm" data-decide="decline">Decline</button><button type="button" class="btn btn--primary btn--sm" data-decide="approve">Approve</button>`);
    if (d.can.revoke) out += h('Revoke verification') + `<p class="text-sm text-muted" style="margin:0 0 6px">Removes the IDV badge and declines their approved checks in Persona. They need to pass a new verification for it to come back.</p>` +
      form('revoke', select('idv-revoke-reason', d.reasons, [['Revoke because', 'revoke', 'revoke']]), `<button type="button" class="btn btn--danger btn--sm" data-revoke>Revoke</button>`);
    return out;
  }

  async function open(id) {
    names = null;
    $('idv-detail-body').innerHTML = 'Loading...';
    $('idv-detail').showModal();
    try {
      cur = await getJson(`${API}/requests/${encodeURIComponent(id)}`);
      $('idv-detail-title').textContent = cur.person ? cur.person.name : 'Identity verification';
      $('idv-detail-body').innerHTML = body(cur) + actions(cur);
      if (cur.can.names) live(cur.id);
    } catch (e) { $('idv-detail-body').textContent = e.message; }
  }

  // The name on each ID next to the directory's, and the network each session came from
  async function live(id) {
    const box = $('idv-live');
    try {
      const n = await getJson(`${API}/requests/${encodeURIComponent(id)}/live`);
      if (!cur || cur.id !== id) return;
      names = n;
      const full = p => [p.first, p.middle, p.last].filter(Boolean).join(' ');
      const dir = n.directory ? [n.directory.first, n.directory.last].filter(Boolean).join(' ') || n.directory.display : null;
      const norm = s => String(s || '').toLowerCase().normalize('NFD').replace(/[^a-z ]/g, '').split(/\s+/).filter(Boolean);
      const same = p => { const a = norm(full(p)), b = norm(dir); return a.length && b.length && b.every(w => a.includes(w)); };
      box.innerHTML = grid(`<tr><th>Name</th><th></th><th>Country</th><th>Result</th></tr>
        <tr><td>In the directory</td><td><b>${esc(dir || 'Not matched to a person')}</b></td><td></td><td></td></tr>` +
        (n.on_id.length ? n.on_id.map(p => `<tr><td>On the ${esc(p.id_type || 'ID')}</td><td><b>${esc(full(p) || 'Not read from the ID')}</b>
          ${dir && full(p) ? (same(p) ? ` ${chip('low', 'matches')}` : ` ${chip('critical', "doesn't match")}`) : ''}</td>
          <td>${esc(p.country || '--')}</td><td>${chip(CHECK_STATE[p.status] || 'info', words(p.status))}</td></tr>`).join('')
          : '<tr><td colspan="4" class="text-muted">No government ID was presented in this check</td></tr>')) +
        (n.sessions.length ? grid(`<tr><th>Session</th><th>Device</th><th>ISP / network</th><th>Country by IP</th><th>By GPS</th></tr>` +
          n.sessions.map(x => `<tr><td class="text-muted">${esc(day(x.at))}</td><td>${esc([x.device_type, x.os, x.browser].filter(Boolean).join(' · ') || '--')}</td>
            <td>${esc(x.isp || '--')}${x.organization && x.organization !== x.isp ? `<div class="text-muted">${esc(x.organization)}</div>` : ''}${x.connection ? `<div class="text-muted">${esc(words(x.connection))}</div>` : ''}</td>
            <td>${esc([x.ip_country, x.ip_region].filter(Boolean).join(' · ') || '--')}</td><td>${esc(x.gps_country || '--')}</td></tr>`).join('')) : '');
      prefill();
    } catch (e) { box.textContent = e.message; }
  }

  // A name mismatch: say so in the note without copying the name off the ID (CTEM never keeps it; Persona has it)
  function prefill() {
    const r = $('idv-review-reason');
    if (!r || r.value !== 'decline:name_mismatch' || $('idv-review-note').value) return;
    $('idv-review-note').value = "Name on the ID doesn't match the directory (compared side by side in CTEM).";
  }

  async function send(kind, url, payload) {
    const msg = $(`idv-${kind}-msg`);
    msg.textContent = 'Sending to Persona...';
    try {
      const d = await getJson(url, { method: 'POST', body: JSON.stringify(payload) });
      if (kind === 'revoke' && d.not_declined_in_persona) msg.textContent = `Revoked in CTEM; ${d.not_declined_in_persona} check(s) couldn't be declined in Persona.`;
      window.dispatchEvent(new Event('idv-changed'));
      tabs();
      table.reload();
      await open(cur.id);
    } catch (e) { msg.textContent = e.message; }
  }

  $('idv-detail').addEventListener('change', e => { if (e.target.id === 'idv-review-reason') prefill(); });
  $('idv-detail').addEventListener('click', async e => {
    if (e.target === $('idv-detail') || e.target.closest('[data-close]')) { $('idv-detail').close(); return; }
    const dec = e.target.closest('[data-decide]');
    if (dec) {
      const [kind, reason] = ($('idv-review-reason').value || ':').split(':');
      const note = $('idv-review-note').value.trim();
      if (kind !== dec.dataset.decide) { $('idv-review-msg').textContent = `Pick a reason under "${dec.dataset.decide === 'approve' ? 'Approve' : 'Decline'} because".`; return; }
      if (note.length < 3) { $('idv-review-msg').textContent = 'Add a note: what you checked.'; return; }
      await send('review', `${API}/requests/${encodeURIComponent(cur.id)}/review`, { decision: kind, reason, note });
      return;
    }
    if (e.target.closest('[data-revoke]')) {
      const reason = ($('idv-revoke-reason').value || ':').split(':')[1];
      const note = $('idv-revoke-note').value.trim();
      if (!reason) { $('idv-revoke-msg').textContent = 'Pick a reason.'; return; }
      if (note.length < 3) { $('idv-revoke-msg').textContent = 'Add a note.'; return; }
      if (!confirm(`Revoke ${cur.person.name}'s identity verification? Their IDV badge goes until they verify again.`)) return;
      await send('revoke', `${API}/people/${encodeURIComponent(cur.person.id)}/revoke`, { reason, note });
    }
  });

  $('idv-tabs').addEventListener('click', e => {
    const b = e.target.closest('[data-tab]');
    if (!b || b.dataset.tab === tab) return;
    tab = b.dataset.tab;
    tabs();
    start();
  });
  let t;
  $('idv-search').addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => table && table.reload(), 300); });
  $('idv-table').addEventListener('click', e => {
    const o = e.target.closest('[data-open]') || (e.target.closest('tr') && e.target.closest('tr').querySelector('[data-open]'));
    if (o && !e.target.closest('a')) open(o.dataset.open);
  });

  tabs();
  start();
})();
