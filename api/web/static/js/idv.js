// IDV page (cyber and admin): Persona identity verifications in Pending, Approved and Rejected tabs. Pending puts
// the ones waiting for a cyber decision (failed or flagged) first, with Review to approve or decline them; the
// decision goes to Persona too. Everything shown goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const API = '/api/v1/idv';
  const STATE = { pending: ['info', 'In progress'], review: ['high', 'Needs review'], approved: ['low', 'Verified'],
                  rejected: ['critical', 'Rejected'], expired: ['info', 'Expired'],
                  superseded: ['info', 'Failed, passed later'] };
  const FLAG = { vpn: 'VPN', proxy: 'Proxy', tor: 'Tor', datacenter: 'Datacenter' };
  const day = s => (s ? new Date(s).toLocaleString() : '--');
  const chip = (c, t) => `<span class="chip chip--${c}" style="font-size:.7rem">${esc(t)}</span>`;
  let tab = new URLSearchParams(location.search).get('tab') || 'pending', table, current = null;
  if (!['pending', 'approved', 'rejected'].includes(tab)) tab = 'pending';

  async function tabs() {
    let s = {};
    try { s = await (await fetch(`${API}/summary`, { headers: { Accept: 'application/json' } })).json(); } catch (e) { /* tabs still work */ }
    const list = [['pending', 'Pending', s.review], ['approved', 'Approved'], ['rejected', 'Rejected']];
    $('idv-tabs').innerHTML = list.map(([v, l, n]) =>
      `<button type="button" role="tab" class="btn btn--sm ${v === tab ? 'btn--primary' : 'btn--ghost'}" data-tab="${v}" aria-selected="${v === tab}">${esc(l)}${
        n ? ` <span class="count-bubble" title="${esc(n)} waiting for review">${esc(n > 99 ? '99+' : n)}</span>` : ''}</button>`).join('');
  }

  const person = r => (r.person
    ? `<a class="dt-link" href="/users?person=${encodeURIComponent(r.person.id)}">${esc(r.person.name)}</a>${IdvBadge.html(r.person.idv_verified_at, false)}
       <div class="text-sm text-muted text-mono">${esc(r.person.upn || '')}</div>`
    : '<span class="text-muted text-sm">Not matched to a person yet</span>');
  const idCell = r => esc([r.id_type, [r.region, r.country].filter(Boolean).join(', ')].filter(Boolean).join(' · ') || '--');
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
        { label: 'Person', render: person },
        { label: 'Status', render: r => chip(...(STATE[r.state] || ['info', r.state])) + (r.origin === 'service_desk' ? ` ${chip('info', 'Service desk')}` : '') },
        { label: 'ID', render: idCell },
        { label: 'Device', render: device },
        { label: 'Requested', render: r => `<span class="text-sm">${esc(day(r.created_at))}</span>` },
        { label: tab === 'approved' ? 'Verified' : 'Decided', render: r => `<span class="text-sm">${esc(day(r.reviewed_at || r.completed_at || r.decided_at))}</span>${
          r.review_note ? `<div class="text-sm text-muted">${esc(r.review_note)}</div>` : ''}` },
        { label: 'Template', render: r => `<span class="text-sm text-muted">${esc(r.template || '--')}</span>` },
        { label: '', render: r => (r.state === 'review' ? `<button type="button" class="btn btn--primary btn--sm" data-review="${esc(r.id)}">Review</button>` : '') },
      ],
      onLoad: d => { table._rows = d.requests || []; },
    });
  }

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
    const b = e.target.closest('[data-review]');
    if (!b) return;
    current = (table._rows || []).find(r => r.id === b.dataset.review);
    if (!current) return;
    $('idv-review-who').textContent = `${current.person ? current.person.name : 'Unmatched person'} · ${STATE[current.state][1]} · ${current.persona_status || ''}`;
    $('idv-review-note').value = '';
    $('idv-review-msg').textContent = '';
    $('idv-review').showModal();
  });
  $('idv-review-cancel').addEventListener('click', () => $('idv-review').close());
  const decide = decision => async () => {
    const note = $('idv-review-note').value.trim();
    const msg = $('idv-review-msg');
    if (note.length < 3) { msg.textContent = 'Say why, in a few words.'; return; }
    msg.textContent = 'Sending to Persona...';
    try {
      const r = await fetch(`${API}/requests/${encodeURIComponent(current.id)}/review`, { method: 'POST', credentials: 'same-origin',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ decision, note }) });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        msg.textContent = typeof d.detail === 'string' ? d.detail : 'That did not go through.';
        return;
      }
      $('idv-review').close();
      window.dispatchEvent(new Event('idv-changed'));
      tabs();
      table.reload();
    } catch (err) { msg.textContent = 'That did not go through.'; }
  };
  $('idv-review-approve').addEventListener('click', decide('approve'));
  $('idv-review-decline').addEventListener('click', decide('decline'));

  tabs();
  start();
})();
