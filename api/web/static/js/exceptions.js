// Exceptions page: a tab per state, a detail dialog with approve / reject / revoke / cancel.
// IT users see only their own requests (the API enforces it); admin and cyber see and decide everything.
(() => {
  const R = DataTable.R;
  const $ = id => document.getElementById(id);
  const API = '/api/v1/exceptions';
  const CHIP = { pending: 'medium', approved: 'low', rejected: 'critical', revoked: 'high', expired: 'info', cancelled: 'info' };
  const LABEL = { pending: 'Waiting for approval', approved: 'Approved', rejected: 'Rejected', revoked: 'Revoked',
                  expired: 'Expired', cancelled: 'Withdrawn' };
  const chip = s => `<span class="chip chip--${CHIP[s] || 'info'}" style="font-size:.7rem">${esc(LABEL[s] || s)}</span>`;
  const day = s => (s ? new Date(s).toLocaleDateString() : '--');
  let canDecide = false, tab = 'pending', table;
  const picked = new Map();   // exception id -> label, for bulk revoke on the Active tab
  const revocable = e => canDecide && e.status === 'approved';
  const bulk = () => canDecide && tab === 'active';
  function pickedLabel() {
    $('ex-revoke').hidden = !bulk();
    $('ex-revoke').disabled = !picked.size;
    $('ex-revoke').textContent = `Revoke selected${picked.size ? ` (${picked.size})` : ''}`;
  }
  const syncPicks = CtemFindings.picker({ mount: $('ex-table'), rows: () => (table ? table.rows() : []), picked,
                                          entry: e => e.cve_id || e.title, onChange: pickedLabel });

  function tabs(pending) {
    const list = canDecide
      ? [['pending', 'Waiting for approval', pending], ['active', 'Active'], ['rejected', 'Rejected'], ['ended', 'Ended'], ['mine', 'My requests'], ['all', 'All']]
      : [['all', 'My requests'], ['pending', 'Waiting'], ['active', 'Approved'], ['rejected', 'Rejected'], ['ended', 'Ended']];
    $('ex-tabs').innerHTML = list.map(([v, l, count]) =>
      `<button type="button" role="tab" class="btn btn--sm ${v === tab ? 'btn--primary' : 'btn--ghost'}" data-tab="${v}" aria-selected="${v === tab}">${esc(l)}${
        count ? ` <span class="count-bubble" title="${esc(count)} waiting for approval">${esc(count > 99 ? '99+' : count)}</span>` : ''}</button>`).join('');
  }

  function vulnCell(e) {
    if (e.scope === 'rule') return `<span class="chip chip--info" style="font-size:.7rem">Rule</span> <b>${esc(e.name || '')}</b>`;
    const text = `${e.cve_id ? `<b>${esc(e.cve_id)}</b> ` : ''}${esc((e.title || '').slice(0, 90))}`;
    return canDecide ? `<a class="dt-link" href="/vulns/${encodeURIComponent(e.vuln_id)}">${text}</a>` : text;
  }

  function start() {
    picked.clear();
    pickedLabel();
    table = DataTable.create({
      mount: $('ex-table'),
      endpoint: API,
      listKey: 'exceptions',
      emptyText: canDecide ? 'Nothing here' : "You haven't asked for any exceptions with this status",
      params: () => ({ tab, q: $('ex-search').value.trim() }),
      onLoad: syncPicks,
      columns: [
        ...(bulk() ? [{ label: 'Select', head: CtemFindings.PICK_HEAD,
          render: e => (revocable(e) ? `<input type="checkbox" data-pick="${esc(e.id)}" aria-label="Select"${picked.has(e.id) ? ' checked' : ''}>` : '') }] : []),
        { label: 'Vulnerability', render: vulnCell },
        { label: 'Covers', render: e => `<span class="text-sm">${esc(e.covers)}</span>` },
        { label: 'Status', render: e => chip(e.status) + (e.kind === 'false_positive' ? ' <span class="chip chip--info" style="font-size:.7rem">False positive</span>' : '') },
        { label: 'Ends', render: e => esc(day(e.expires_at)) },
        { label: 'Requested by', render: e => `<span class="text-sm">${esc(e.requested_by)}</span><div class="text-sm text-muted">${esc(day(e.requested_at))}</div>` },
        { label: 'Decided by', render: e => (e.decided_by ? `<span class="text-sm">${esc(e.decided_by)}</span><div class="text-sm text-muted">${esc(day(e.decided_at))}</div>` : R.date(null)) },
        { label: '', render: e => `<span style="display:flex;gap:4px"><button type="button" class="btn btn--ghost btn--sm" data-open="${esc(e.id)}">Details</button>${revocable(e)
          ? `<button type="button" class="btn btn--ghost btn--sm" data-revoke="${esc(e.id)}" data-label="${esc(e.cve_id || e.title || '')}">Revoke</button>` : ''}</span>` },
      ],
    });
  }

  function field(label, html) {
    return `<div style="margin-bottom:10px"><div class="text-sm text-muted">${esc(label)}</div><div style="overflow-wrap:anywhere">${html}</div></div>`;
  }

  async function open(id) {
    const res = await fetch(`${API}/${encodeURIComponent(id)}`, { headers: { Accept: 'application/json' } });
    if (!res.ok) return;
    const e = await res.json();
    let wrap = $('exd-modal');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'exd-modal';
      wrap.className = 'tk-backdrop';
      wrap.setAttribute('role', 'dialog');
      wrap.setAttribute('aria-modal', 'true');
      document.body.appendChild(wrap);
    }
    const text = t => `<div style="white-space:pre-wrap">${esc(t || '--')}</div>`;
    const devs = (e.devices || []).map(d => (d.hostname ? `<a class="dt-link" href="/devices/${encodeURIComponent(d.id)}">${esc(d.hostname)}</a>` : 'a device you can no longer see')).join(', ');
    const max = new Date(Date.now() + 365 * 864e5).toISOString().slice(0, 10);
    wrap.innerHTML = `<div class="tk-dialog" style="max-width:700px;max-height:88vh;overflow:auto">
      <h2 class="tk-title">Exception</h2><p class="tk-sub">${chip(e.status)}</p>
      ${field('Vulnerability', vulnCell(e))}
      ${field('Covers', esc(e.covers) + (devs ? `<div class="text-sm" style="margin-top:4px">${devs}</div>` : ''))}
      ${field('Findings covered right now', esc(e.findings_covered))}
      ${field('Reason', text(e.reason))}
      ${e.compensating_controls ? field('Compensating controls', text(e.compensating_controls)) : ''}
      ${field('Ends', esc(day(e.expires_at)))}
      ${field('Requested', `${esc(e.requested_by)} on ${esc(new Date(e.requested_at).toLocaleString())}`)}
      ${e.decided_by ? field('Decided', `${esc(e.decided_by)} on ${esc(new Date(e.decided_at).toLocaleString())}`) : ''}
      ${e.decision_note ? field('Note', text(e.decision_note)) : ''}
      ${e.can_decide && ['pending', 'approved'].includes(e.status) ? `<div class="form-group"><label class="form-label" for="exd-note">Note ${e.status === 'pending' ? '(required to reject)' : '(required to revoke)'}</label>
        <textarea id="exd-note" class="form-input" rows="2" maxlength="1000"></textarea></div>` : ''}
      ${e.can_decide && e.status === 'pending' ? `<div class="form-group"><label class="form-label" for="exd-until">End date (change it before approving if needed)</label>
        <input id="exd-until" type="date" class="form-input" style="max-width:200px" max="${max}" value="${esc(e.expires_at.slice(0, 10))}"></div>` : ''}
      <div id="exd-msg" class="text-sm" style="min-height:1.2em;color:var(--severity-critical)"></div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px" id="exd-actions"></div></div>`;
    const acts = $('exd-actions');
    const btn = (label, cls, fn) => { const b = document.createElement('button'); b.type = 'button'; b.className = `btn ${cls} btn--sm`; b.textContent = label; b.onclick = fn; acts.appendChild(b); };
    const act = async (verb, body) => {
      const r = await CtemFindings.post(`${API}/${encodeURIComponent(e.id)}/${verb}`, body);
      if (!r.ok) { $('exd-msg').textContent = r.error || 'That did not work.'; return; }
      wrap.classList.remove('is-open');
      refresh();
    };
    const note = () => ($('exd-note') ? $('exd-note').value.trim() : '') || null;
    btn('Close', 'btn--ghost', () => wrap.classList.remove('is-open'));
    if (e.can_cancel) btn('Withdraw request', 'btn--ghost', () => act('cancel', {}));
    if (e.can_decide && e.status === 'pending') {
      btn('Reject', 'btn--ghost', () => act('reject', { note: note() }));
      btn('Approve', 'btn--primary', () => act('approve', { note: note(), expires_on: $('exd-until').value || null }));
    }
    if (e.can_decide && e.status === 'approved') btn('Revoke', 'btn--ghost', () => act('revoke', { note: note() }));
    wrap.classList.add('is-open');
  }

  // Revoke one or many: one note for all, required, shown to the requester and kept in the audit log
  function revokeDialog(ids) {
    let wrap = $('exr-modal');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'exr-modal';
      wrap.className = 'tk-backdrop';
      wrap.setAttribute('role', 'dialog');
      wrap.setAttribute('aria-modal', 'true');
      document.body.appendChild(wrap);
    }
    const names = ids.map(([, l]) => l).filter(Boolean);
    wrap.innerHTML = `<div class="tk-dialog" style="max-width:560px">
      <h2 class="tk-title">Revoke ${ids.length === 1 ? 'this exception' : `${ids.length} exceptions`}</h2>
      <p class="tk-sub">${esc(names.slice(0, 6).join(', '))}${names.length > 6 ? ` and ${names.length - 6} more` : ''}</p>
      <div class="tk-note">Revoking ends it now: the findings count against risk and SLA again.</div>
      <div class="form-group"><label class="form-label" for="exr-note">Why? <span style="color:var(--severity-critical)">*</span></label>
        <textarea id="exr-note" class="form-input" rows="2" maxlength="1000" placeholder="e.g. Patch is now available"></textarea></div>
      <div id="exr-msg" class="text-sm" style="min-height:1.2em;color:var(--severity-critical)"></div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px">
        <button type="button" class="btn btn--ghost btn--sm" id="exr-cancel">Cancel</button>
        <button type="button" class="btn btn--primary btn--sm" id="exr-go">Revoke</button></div></div>`;
    wrap.classList.add('is-open');
    $('exr-cancel').onclick = () => wrap.classList.remove('is-open');
    $('exr-go').onclick = async () => {
      const note = $('exr-note').value.trim();
      if (note.length < 3) { $('exr-msg').textContent = 'Add a short note saying why.'; return; }
      if (/[<>]/.test(note)) { $('exr-msg').textContent = "Please don't use < or >."; return; }
      $('exr-go').disabled = true;
      const failed = [];
      for (const [id] of ids) {
        const r = await CtemFindings.post(`${API}/${encodeURIComponent(id)}/revoke`, { note });
        if (!r.ok) failed.push(r.error);
      }
      $('exr-go').disabled = false;
      if (failed.length === ids.length) { $('exr-msg').textContent = failed[0] || 'That did not work.'; return; }
      wrap.classList.remove('is-open');
      picked.clear();
      refresh();
    };
  }

  async function refresh() {
    const s = await fetch(`${API}/summary`, { headers: { Accept: 'application/json' } }).then(r => (r.ok ? r.json() : {})).catch(() => ({}));
    canDecide = !!s.can_decide;
    tabs(s.pending || 0);
    window.dispatchEvent(new Event('exceptions-changed'));   // the menu bubble follows approvals made here
    if (table) table.reload(false); else start();
  }

  $('ex-tabs').addEventListener('click', e => {
    const b = e.target.closest('button[data-tab]');
    if (!b) return;
    tab = b.dataset.tab;
    table = null;
    refresh();
  });
  $('ex-table').addEventListener('click', e => {
    const b = e.target.closest('button[data-open]');
    if (b) open(b.dataset.open);
    const r = e.target.closest('button[data-revoke]');
    if (r) revokeDialog([[r.dataset.revoke, r.dataset.label]]);
  });
  $('ex-revoke').addEventListener('click', () => revokeDialog([...picked.entries()]));
  let timer;
  $('ex-search').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => table && table.reload(), 300); });

  (async () => {
    const s = await fetch(`${API}/summary`, { headers: { Accept: 'application/json' } }).then(r => (r.ok ? r.json() : {})).catch(() => ({}));
    canDecide = !!s.can_decide;
    if (s.is_admin && window.ExceptionRule) {   // admins: an exception for whatever a rule describes
      $('ex-rule').hidden = false;
      $('ex-rule').onclick = () => ExceptionRule.open(() => { tab = 'active'; table = null; refresh(); });
    }
    tab = canDecide ? (s.pending ? 'pending' : 'active') : 'all';
    $('ex-sub').textContent = canDecide ? 'Approve or reject requests, and create or revoke exceptions'
      : 'Your exception requests and how they were decided';
    tabs(s.pending || 0);
    start();
    const id = new URLSearchParams(location.search).get('id');
    if (id && /^[0-9a-f-]{36}$/i.test(id)) open(id);
  })();
})();
