// IDV page (cyber, admin, IDV approvers): Persona identity verifications in Pending, Approved and Rejected tabs.
// Clicking a row (or Review, right after the name) opens the request in full: why it needs a decision, what the
// person presented, which checks failed and what to validate, their other attempts, the device. IDV approvers decide
// there (a reason from the list and a note), can compare the name on the ID with the directory (read live, never
// kept), and can revoke a verified person. Everything shown goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const API = '/api/v1/idv';
  const STATE = { pending: ['info', 'In progress'], review: ['high', 'Needs review'], approved: ['low', 'Verified'],
                  rejected: ['critical', 'Rejected'], expired: ['info', 'Expired'], superseded: ['info', 'Failed, passed later'],
                  unproven: ['high', 'Passed, not ID-verified'] };
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
    const list = [['pending', 'Pending', s.review_recent], ['approved', 'Approved'], ['rejected', 'Rejected']];   // like the sidebar: the last 5 days
    $('idv-tabs').innerHTML = list.map(([v, l, n]) =>
      `<button type="button" role="tab" class="btn btn--sm ${v === tab ? 'btn--primary' : 'btn--ghost'}" data-tab="${v}" aria-selected="${v === tab}">${esc(l)}${
        n ? ` <span class="count-bubble" title="${esc(n)} waiting for review from the last 5 days">${esc(n > 99 ? '99+' : n)}</span>` : ''}</button>`).join('');
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
      emptyText: { pending: 'Nothing waiting for a decision', approved: 'No verified identities yet', rejected: 'Nothing rejected' }[tab],
      // the last few days by default; a search looks at every date
      params: () => { const q = $('idv-search').value.trim(), days = $('idv-days').value; return { tab, q, ...(days && !q ? { days } : {}) }; },
      columns: [
        { label: 'Person', render: r => `<span data-open="${esc(r.id)}" style="cursor:pointer">${person(r)}</span>` },
        { label: '', render: r => `<button type="button" class="btn btn--sm ${['review', 'unproven'].includes(r.state) ? 'btn--primary' : 'btn--ghost'}" data-open="${esc(r.id)}">${['review', 'unproven'].includes(r.state) ? 'Review' : 'Details'}</button>` },
        { label: 'Status', render: r => chip(...(STATE[r.state] || ['info', r.state])) + (r.origin === 'service_desk' ? ` ${chip('info', 'Service desk')}` : '') },
        { label: 'Country', render: r => `<span class="text-sm">${esc([r.country, r.region].filter(Boolean).join(' · ') || '--')}</span>` },
        { label: 'ID', render: r => `<span class="text-sm">${esc(r.id_type || '--')}</span>` },
        { label: 'Device', render: device },
        { label: 'Requested', render: r => `<span class="text-sm">${esc(day(r.created_at))}</span>` },
        { label: tab === 'approved' ? 'Verified' : 'Decided', render: r => `<span class="text-sm">${esc(day(r.reviewed_at || r.completed_at || r.decided_at))}</span>` },
        { label: 'Template', render: r => `<span class="text-sm text-muted">${esc(r.template || '--')}</span>` },
      ],
      onLoad: d => {
        table._rows = d.requests || [];
        const o = $('idv-older');
        o.hidden = !d.older;
        o.innerHTML = d.older ? `${esc(d.older)} older not shown. <button type="button" class="dt-link" style="background:none;border:0;padding:0;cursor:pointer" data-all>Show all</button>` : '';
      },
    });
  }

  // ── the request in full: why it needs a person, the signals for this one check, what to validate ──
  const h = t => `<h3 class="text-sm" style="margin:16px 0 6px;text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted)">${esc(t)}</h3>`;
  const NAME_CHECKS = new Set(['id_inquiry_comparison', 'id_account_comparison']);
  const fullName = p => [p.first, p.middle, p.last].filter(Boolean).join(' ');
  const dirName = n => (n && n.directory ? [n.directory.first, n.directory.last].filter(Boolean).join(' ') || n.directory.display || '' : '');
  const norm = v => String(v || '').toLowerCase().normalize('NFD').replace(/[^a-z ]/g, '').split(/\s+/).filter(Boolean);
  const sameName = (a, b) => { const x = norm(a), y = norm(b); return x.length && y.length && y.every(w => x.includes(w)) ? true : (x.length && y.length ? false : null); };
  const ids = d => ((d.explain || {}).presented || []).filter(p => /Government ID/.test(p.kind));
  const idLabel = p => [p.id_type || 'ID', p.country ? `(${p.country})` : ''].filter(Boolean).join(' ');

  // Plain sentences, with the real values: the name on the ID against the directory, the ID that looked like a copy
  function why(d, n) {
    const x = d.explain || {}, out = [], gov = ids(d);
    const idOnId = n && (n.on_id || []).find(p => fullName(p));
    const dir = dirName(n);
    for (const f of x.failed || []) {
      if (NAME_CHECKS.has(f.check)) {
        out.push(idOnId && dir ? `The name on the ${idOnId.id_type || 'ID'} is <b>${esc(fullName(idOnId))}</b>, but the directory has <b>${esc(dir)}</b>.`
          : `${esc(f.means)} ${n ? '' : '<span class="text-muted">(the names load below)</span>'}`);
      } else if (f.check === 'id_electronic_replica_detection') {
        const which = gov.filter(p => p.status === 'failed').map(idLabel);
        out.push(`${which.length > 1 ? `All ${which.length} IDs presented (${esc(which.join(', '))}) looked` : `The ${esc(which[0] || 'ID')} looked`} like a photo of a screen or a printout, not the physical document.`);
      } else {
        out.push(`<b>${esc(f.on)}:</b> ${esc(f.means)}`);
      }
    }
    if (idOnId && dir && sameName(fullName(idOnId), dir) === false && !(x.failed || []).some(f => NAME_CHECKS.has(f.check)))
      out.push(`The name on the ${esc(idOnId.id_type || 'ID')} (<b>${esc(fullName(idOnId))}</b>) differs from the directory (<b>${esc(dir)}</b>).`);
    if (d.state === 'unproven') out.push(d.created_via && d.created_via !== 'API' && d.origin !== 'service_desk'
      ? 'Persona passed this check, but it was started from a hosted link, so anyone holding the link could have done it. It earns no badge until an approver confirms who it was.'
      : `Persona passed this check, but ${esc(d.person ? d.person.name : 'the person')} has never passed a government ID check: it was a selfie re-check, which compares a face with an earlier selfie, not with an ID.`);
    for (const note of x.notes || []) out.push(`<b>${esc(note)}</b>`);
    if (!out.length) out.push(!x.read ? "What Persona checked hasn't been read yet; it comes with the next Persona sync."
      : d.persona_status === 'needs_review' ? "Persona's template sent this for manual review; no single check failed."
      : d.persona_status === 'failed' ? "Persona marked it failed without a check CTEM can read; open it in Persona." : 'Nothing failed.');
    return out.map(t => `<li style="margin:3px 0">${t}</li>`).join('');
  }

  function pastChecks(d) {
    const y = d.history || {};
    const parts = [y.verified ? `Verified ${y.verified} time${y.verified === 1 ? '' : 's'} before${y.last_verified_at ? ` (last ${esc(day(y.last_verified_at))})` : ''}` : 'Never verified before'];
    if (y.failed) parts.push(`${y.failed} failed attempt${y.failed === 1 ? '' : 's'}`);
    parts.push(y.id_passed_before ? 'has passed a government ID check before' : '<b>has never passed a government ID check</b>');
    return parts.join(' · ');
  }

  // The signals for this check, one per line
  function signals(d, n) {
    const x = d.explain || {}, gov = ids(d), row = (k, v) => (v ? `<dt>${esc(k)}</dt><dd>${v}</dd>` : '');
    const key = Object.fromEntries((x.passed_key_checks || []).map(k => [k.check, k]));
    const selfie = (x.presented || []).find(p => p.kind === 'Selfie');
    const selfieTxt = selfie ? [chip(CHECK_STATE[selfie.status] || 'info', words(selfie.status)),
      key.selfie_id_comparison ? (key.selfie_id_comparison.status === 'passed' ? 'face matches the ID' : `no ID to compare with (${esc(key.selfie_id_comparison.reasons.map(words).join(', ') || 'not applicable')})`) : '',
      key.selfie_account_comparison && key.selfie_account_comparison.status === 'passed' ? 'matches their earlier selfie' : '',
      key.selfie_liveness_detection && key.selfie_liveness_detection.status === 'passed' ? 'live person' : ''].filter(Boolean).join(' · ') : '';
    const s = n && n.sessions && n.sessions[0];
    const idCountry = (gov[gov.length - 1] || {}).country || d.country;
    const away = c => (c && idCountry && c.length === 2 && c !== idCountry ? ` ${chip('high', `not ${idCountry}`)}` : '');
    const idOnId = n && (n.on_id || []).find(p => fullName(p));
    const dir = dirName(n), match = idOnId && dir ? sameName(fullName(idOnId), dir) : null;
    return `<dl class="idv-signals">
      ${row('ID presented', gov.map(p => `${esc(p.id_type || 'ID')} · ${esc(p.country || '?')}${p.capture ? ` · ${esc(words(p.capture))} capture` : ''} ${chip(CHECK_STATE[p.status] || 'info', words(p.status))}`).join('<br>') || '<span class="text-muted">No government ID in this check</span>')}
      ${row('Selfie', selfieTxt)}
      ${d.can && d.can.names ? row('Name on the ID', n ? (idOnId ? `<b>${esc(fullName(idOnId))}</b>${match === true ? ` ${chip('low', 'matches')}` : match === false ? ` ${chip('critical', "doesn't match")}` : ''}` : '<span class="text-muted">Not read from the ID</span>') : '<span class="text-muted">Reading from Persona...</span>') : ''}
      ${row('Name in the directory', d.person_detail ? `<b>${esc([d.person_detail.first_name, d.person_detail.last_name].filter(Boolean).join(' ') || d.person.name)}</b>` : '<span class="text-muted">Not matched to a person</span>')}
      ${row('Device', esc([d.device_type, d.os, d.browser].filter(Boolean).join(' · ')) || '<span class="text-muted">--</span>')}
      ${s ? row('ISP / network', `${esc(s.isp || '--')}${s.organization && s.organization !== s.isp ? ` · ${esc(s.organization)}` : ''}${s.connection ? ` · ${esc(words(s.connection))}` : ''}`) : ''}
      ${s ? row('Country by IP', `${esc([s.ip_country, s.ip_region].filter(Boolean).join(' · ') || '--')}`) : ''}
      ${s && s.gps_country ? row('Country by GPS', `${esc(s.gps_country)}${away(s.gps_country)}`) : ''}
      ${row('Network flags', (d.flags || []).map(f => chip('critical', FLAG[f] || f)).join(' ') || '<span class="text-muted">No VPN, proxy, Tor or datacenter</span>')}
      ${d.threat_level ? row('Threat level', d.threat_level === 'low' ? esc(d.threat_level) : chip('high', d.threat_level)) : ''}
      ${row('Started by', esc(d.origin === 'service_desk' ? 'The service desk' : d.created_via === 'API' ? "Okta's verification flow" : d.created_via ? 'A hosted link (never earns the badge)' : 'Unknown'))}
      ${row('Requested', `${esc(day(d.created_at))} · ${esc(d.template || '')}`)}
    </dl>`;
  }

  function body(d) {
    const x = d.explain || {};
    let out = '';
    if (d.person) out += `<p class="text-sm" style="margin:0 0 4px"><a class="dt-link" href="/users?person=${encodeURIComponent(d.person.id)}">${esc(d.person.name)}</a>
      ${IdvBadge.html(d.person.idv_verified_at, true)} <span class="text-muted text-mono">${esc(d.person.upn || '')}</span>
      ${d.person_detail && (d.person_detail.title || d.person_detail.department) ? `<span class="text-muted"> · ${esc([d.person_detail.title, d.person_detail.department].filter(Boolean).join(' · '))}</span>` : ''}</p>`;
    out += `<p class="text-sm" style="margin:0">${chip(...(STATE[d.state] || ['info', d.state]))} ${pastChecks(d)}</p>`;
    out += h(['review', 'unproven'].includes(d.state) ? 'Why this needs a manual review' : 'What happened') +
      `<ul id="idv-why" class="text-sm" style="margin:0;padding-left:18px;color:var(--fg)">${why(d, null)}</ul>`;
    out += h('Signals for this check') + `<div id="idv-signals">${signals(d, null)}</div>`;
    const todo = [...new Set((x.failed || []).map(f => f.validate))];
    if (d.state === 'unproven') todo.push('Verify the person and a government ID on a live video call, or expire it so they verify again with an ID.');
    if (todo.length && ['review', 'unproven'].includes(d.state)) out += h('Validate before approving') +
      `<ul class="text-sm" style="margin:0;padding-left:18px">${todo.map(t => `<li style="margin:3px 0">${esc(t)}</li>`).join('')}</ul>`;
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
    if (d.can.revoke) out += h('Require a new verification') + `<p class="text-sm" style="margin:0 0 6px;color:var(--severity-high)"><b>Warning:</b> either one removes the
      person's IDV badge. It comes back only when they pass a new check with <b>both a government ID and a selfie that matches it</b>
      (a selfie-only re-check won't do). Send them a re-verification link from Discovered Users to start it.
      <b>Expire</b> when it's simply no longer enough; <b>Revoke</b> when something is wrong with it (their approved checks are declined in Persona too).</p>` +
      form('revoke', select('idv-revoke-reason', d.reasons, [['Expire because', 'expire', 'expire'], ['Revoke because', 'revoke', 'revoke']]),
        `<button type="button" class="btn btn--ghost btn--sm" data-revoke="expire">Expire verification</button><button type="button" class="btn btn--danger btn--sm" data-revoke="revoke">Revoke</button>`);
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

  // The name on each ID and the network each session came from, read live: fills in the why and the signals
  async function live(id) {
    try {
      const n = await getJson(`${API}/requests/${encodeURIComponent(id)}/live`);
      if (!cur || cur.id !== id) return;
      names = n;
      $('idv-why').innerHTML = why(cur, n);
      $('idv-signals').innerHTML = signals(cur, n);
      prefill();
    } catch (e) {
      if (cur && cur.id === id) $('idv-signals').insertAdjacentHTML('beforeend', `<p class="text-sm" style="color:var(--severity-high)">${esc(e.message)}</p>`);
    }
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
    const rv = e.target.closest('[data-revoke]');
    if (rv) {
      const mode = rv.dataset.revoke;
      const [kind, reason] = ($('idv-revoke-reason').value || ':').split(':');
      const note = $('idv-revoke-note').value.trim();
      if (kind !== mode) { $('idv-revoke-msg').textContent = `Pick a reason under "${mode === 'expire' ? 'Expire' : 'Revoke'} because".`; return; }
      if (note.length < 3) { $('idv-revoke-msg').textContent = 'Add a note.'; return; }
      if (!confirm(`${mode === 'expire' ? 'Expire' : 'Revoke'} ${cur.person.name}'s identity verification?\n\nThis forces them to onboard again: `
        + 'their IDV badge is removed until they pass a new check with both a government ID and a selfie that matches it.')) return;
      await send('revoke', `${API}/people/${encodeURIComponent(cur.person.id)}/revoke`, { mode, reason, note });
    }
  });

  $('idv-tabs').addEventListener('click', e => {
    const b = e.target.closest('[data-tab]');
    if (!b || b.dataset.tab === tab) return;
    tab = b.dataset.tab;
    tabs();
    start();
  });
  $('idv-days').addEventListener('change', () => table && table.reload());
  $('idv-older').addEventListener('click', e => { if (e.target.closest('[data-all]')) { $('idv-days').value = ''; table.reload(); } });
  let t;
  $('idv-search').addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => table && table.reload(), 300); });
  $('idv-table').addEventListener('click', e => {
    const o = e.target.closest('[data-open]') || (e.target.closest('tr') && e.target.closest('tr').querySelector('[data-open]'));
    if (o && !e.target.closest('a')) open(o.dataset.open);
  });

  tabs();
  start();
})();
