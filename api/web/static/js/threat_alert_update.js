// Cyber Threats > alert: update the alert in CrowdStrike (status, classification, comment) and the updates made so far.
// The page is for cyber and admin only, and the server checks the role again. Everything goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const STATUS = [['', 'Leave as it is'], ['in_progress', 'In progress'], ['closed', 'Closed'], ['reopened', 'Reopened'], ['new', 'New']];
  const CLASS = [['', 'No classification'], ['true_positive', 'True positive'], ['false_positive', 'False positive'], ['benign', 'Benign / expected']];
  const NAMES = Object.fromEntries([...STATUS, ...CLASS].filter(x => x[0]));
  const opts = list => list.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join('');
  const at = s => (s ? new Date(s).toLocaleString() : '');

  function result(u) {
    if (u.state === 'done') return '<span class="chip chip--low">Done in CrowdStrike</span>';
    if (u.state === 'failed') return `<span class="chip chip--critical">Failed</span> <span class="text-sm">${esc(u.error || '')}</span>`;
    if (u.state === 'sent') return '<span class="chip chip--info">Sent by the shipper, waiting for its answer</span>';
    return `<span class="chip chip--medium">${u.via === 'shipper' ? 'Waiting for the shipper (within about 5 minutes)' : 'Sending'}</span>`;
  }

  function history(list) {
    if (!list.length) return '';
    return `<div class="dt-scroll" style="margin-top:14px"><table class="data-table data-table--striped">
      <thead><tr><th>When</th><th>By</th><th>Change</th><th>Comment</th><th>Result</th></tr></thead>
      <tbody>${list.map(u => `<tr><td class="text-sm">${esc(at(u.at))}</td><td class="text-sm">${esc(u.by)}</td>
        <td class="text-sm">${esc([NAMES[u.status], NAMES[u.classification]].filter(Boolean).join(', ') || 'Comment')}</td>
        <td class="text-sm" style="white-space:pre-wrap;overflow-wrap:anywhere;max-width:360px">${esc(u.comment || '')}</td>
        <td>${result(u)}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function render(a) {
    if (a.source !== 'crowdstrike' || !a.can_update) return;
    const c = a.can_update, list = a.updates || [];
    const how = c.via === 'shipper'
      ? 'The on-prem shipper sends it to CrowdStrike with its own API client on its next check-in (within about 5 minutes); the result shows below.'
      : 'Sent to CrowdStrike at once with the CrowdStrike integration\'s API client.';
    $('al-update').innerHTML = (c.ok ? `<form id="al-upd-form" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px 16px;align-items:end">
        <label class="text-sm">Status<select id="al-upd-status" class="form-input" style="margin-top:4px">${opts(STATUS)}</select></label>
        <label class="text-sm">Classification<select id="al-upd-class" class="form-input" style="margin-top:4px">${opts(CLASS)}</select></label>
        <label class="text-sm" style="grid-column:1/-1">Comment (added to the alert in CrowdStrike with your name)
          <textarea id="al-upd-comment" class="form-input" style="margin-top:4px" rows="3" maxlength="1000" placeholder="What you found and why"></textarea></label>
        <div style="grid-column:1/-1;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <button type="submit" class="btn btn--primary btn--sm" id="al-upd-send">Update in CrowdStrike</button>
          <span class="text-sm text-muted">${esc(how)} A classification is a <span class="text-mono">ctem_</span> tag on the alert.</span>
        </div>
        <div id="al-upd-msg" class="text-sm" style="grid-column:1/-1"></div></form>`
      : `<p class="text-sm text-muted" style="margin:0">${esc(c.why || 'Updates aren\'t available.')}</p>`) + history(list);
    $('al-update-panel').style.display = '';
    const form = $('al-upd-form');
    if (form) form.addEventListener('submit', e => { e.preventDefault(); send(a); });
  }

  async function send(a) {
    const body = { ids: [a.id] };
    const status = $('al-upd-status').value, cls = $('al-upd-class').value, comment = $('al-upd-comment').value.trim();
    if (status) body.status = status;
    if (cls) body.classification = cls;
    if (comment) body.comment = comment;
    const msg = $('al-upd-msg');
    if (!status && !cls && !comment) { msg.textContent = 'Pick a status or a classification, or write a comment.'; return; }
    $('al-upd-send').disabled = true;
    msg.textContent = 'Sending...';
    try {
      const r = await fetch('/api/v1/threat/alerts/update', { method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'The server refused that.');
      const u = (d.updates || [])[0] || {};
      if (u.state === 'failed') throw new Error(u.error || 'CrowdStrike refused the update.');
      if (typeof toast === 'function') toast(d.via === 'shipper' ? 'Queued: the shipper sends it on its next check-in' : 'Updated in CrowdStrike', 'success');
      setTimeout(() => location.reload(), 600);
    } catch (err) {
      msg.textContent = err.message;
      msg.style.color = 'var(--severity-critical)';
      $('al-upd-send').disabled = false;
    }
  }

  window.AlertUpdate = { render };
})();
