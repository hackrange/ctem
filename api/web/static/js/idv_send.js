// "Send re-verification link": a small button next to a person (Discovered Users, a device's detected user) that
// opens a dialog with the verified channels their SSO/MFA provider holds (masked; the full number or address never
// reaches the browser), a warning, and Send. The server starts the Persona check and sends the one-time link.
// Everything shown goes through esc().
window.IdvSend = (() => {
  let dlg, who = null, plan = null;
  const API = '/api/v1/idv/people';

  // Only for IDV Approvers and IDV Validation (the page marks <body data-can-send-idv>; a different name from the buttons' data-idv-send, which a click is matched on); the server checks idv:send too
  const button = (userId, name) => (userId && document.body.dataset.canSendIdv === '1'
    ? `<button type="button" class="btn btn--ghost btn--sm" data-idv-send="${esc(userId)}" data-idv-name="${esc(name || '')}"
        style="margin-left:6px;padding:1px 8px;font-size:12px" title="Send a Persona identity verification link to this person">Send re-verification link</button>`
    : '');

  function modal() {
    if (dlg) return dlg;
    dlg = document.createElement('dialog');
    dlg.className = 'modal';
    dlg.setAttribute('aria-labelledby', 'idv-send-title');
    dlg.innerHTML = `<div style="padding:16px 20px;min-width:340px;max-width:520px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <h2 id="idv-send-title" class="panel__title" style="margin:0">Send re-verification link</h2>
        <button type="button" class="btn btn--ghost btn--sm" data-close aria-label="Close">&#10005;</button></div>
      <div id="idv-send-body" class="text-sm" style="margin-top:8px"></div></div>`;
    dlg.addEventListener('click', async e => {
      if (e.target === dlg || e.target.closest('[data-close]')) { dlg.close(); return; }
      const go = e.target.closest('[data-go]');
      if (!go) return;
      const pick = dlg.querySelector('input[name="idv-send-ch"]:checked');
      const msg = dlg.querySelector('#idv-send-msg');
      if (!pick) { msg.textContent = 'Pick where to send it.'; return; }
      const recent = pick.closest('label').querySelector('[data-recent="1"]');
      const confirmed = dlg.querySelector('#idv-send-confirmed').checked;
      if (recent && !confirmed) { msg.textContent = 'Tick the box once you have confirmed the contact with the person.'; return; }
      go.disabled = true;
      msg.textContent = 'Starting the verification in Persona and sending...';
      try {
        const r = await fetch(`${API}/${encodeURIComponent(who)}/send`, { method: 'POST', credentials: 'same-origin',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ channel: pick.value, confirm_recent: !!(recent && confirmed),
          kind: dlg.querySelector('#idv-send-full') && dlg.querySelector('#idv-send-full').checked ? 'id_selfie' : 'auto' }) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { msg.textContent = typeof d.detail === 'string' ? d.detail : 'That did not go through.'; go.disabled = false; return; }
        msg.innerHTML = `<b style="color:var(--severity-low)">Sent</b>${plan && plan.persona_decides ? '' : ` (${esc(d.kind === 'selfie' ? 'selfie' : 'government ID and selfie')})`} by ${esc(d.channel === 'sms' ? 'text' : 'email')} to ${esc(d.to)}.
          The link works for ${esc(d.expires_hours)} hours; the result shows on the IDV page when they finish.`;
        window.dispatchEvent(new Event('idv-changed'));
      } catch (err) { msg.textContent = 'That did not go through.'; go.disabled = false; }
    });
    dlg.addEventListener('change', () => {   // the confirmation shows only for a recently changed contact
      const pick = dlg.querySelector('input[name="idv-send-ch"]:checked');
      dlg.querySelector('#idv-send-confirm').style.display = pick && pick.closest('label').querySelector('[data-recent="1"]') ? 'flex' : 'none';
    });
    document.body.appendChild(dlg);
    return dlg;
  }

  async function open(userId, name) {
    who = userId;
    const m = modal(), box = m.querySelector('#idv-send-body');
    box.textContent = 'Loading...';
    m.showModal();
    try {
      const r = await fetch(`${API}/${encodeURIComponent(userId)}/contacts`, { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
      if (r.status === 403) { box.textContent = "You don't have permission to send verification requests."; return; }
      const d = await r.json();
      const chans = d.channels || [];
      const opts = chans.map((c, i) => `<label style="display:flex;gap:8px;align-items:center;margin:6px 0;${c.available ? '' : 'opacity:.55'}">
          <input type="radio" name="idv-send-ch" value="${esc(c.channel)}" ${c.available ? '' : 'disabled'} ${c.available && !chans.slice(0, i).some(x => x.available) ? 'checked' : ''}>
          <span data-recent="${c.recent ? 1 : 0}"><b>${esc(c.channel === 'sms' ? 'Text message' : 'Email')}</b> to ${esc(c.shown)} <span class="text-muted">(${esc(c.source)}, verified${
            c.since ? `, enrolled or changed ${esc(new Date(c.since).toLocaleDateString())}` : ''})</span>
          ${c.recent ? ` <span class="chip chip--high" style="font-size:.7rem">${c.since ? 'changed in the last 7 days' : 'enrollment date unknown'}</span>` : ''}
          ${c.available ? '' : `<span class="text-muted"> · ${esc(c.why_not)}</span>`}</span></label>`).join('');
      const p = plan = d.plan || { kind: 'id_selfie', why: '' };
      const idTxt = p.active_id ? `${p.active_id.id_type || 'Government ID'}${p.active_id.country ? ` (${p.active_id.country})` : ''}${p.active_id.at ? `, verified ${new Date(p.active_id.at).toLocaleDateString()}` : ''}` : '';
      box.innerHTML = `<p style="margin:0 0 6px">${esc(name || 'This person')} gets a one-time Persona link. It goes only to a contact their identity provider verified.</p>
        <div style="padding:8px 10px;border-radius:6px;background:var(--surface2);margin:0 0 8px">
          <b>${p.persona_decides ? 'Persona decides what they verify with' : `They will verify with: ${p.kind === 'selfie' ? 'a selfie' : 'a government ID and a selfie'}`}</b>
          <div class="text-muted">${esc(p.why)}${idTxt ? ` On file: ${esc(idTxt)}.` : ''}</div>
          ${p.warning ? `<div style="color:var(--severity-high);margin-top:4px">${esc(p.warning)}</div>` : ''}
          ${p.kind === 'selfie' && !p.persona_decides ? `<label style="display:flex;gap:6px;align-items:center;margin-top:6px"><input type="checkbox" id="idv-send-full"> Require a government ID and a selfie instead</label>` : ''}
        </div>
        ${opts || '<p class="text-muted">No verified SMS MFA phone or MFA email address for this person, so nothing can be sent.</p>'}
        ${(d.missing || []).length ? `<p style="color:var(--severity-high);margin:8px 0 0">Can't send yet: ${esc(d.missing.join('; '))}.</p>` : ''}
        <label id="idv-send-confirm" style="display:none;gap:8px;align-items:flex-start;margin:8px 0 0;color:var(--severity-high)">
          <input type="checkbox" id="idv-send-confirmed"> <span>This contact was enrolled or changed recently, which is what an account takeover
          looks like. I confirmed with the person another way (a call to a known number, their manager) that it's theirs.</span></label>
        <p id="idv-send-msg" role="status" style="min-height:1.2em;margin:8px 0 0"></p>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px">
          <button type="button" class="btn btn--ghost btn--sm" data-close>Cancel</button>
          <button type="button" class="btn btn--primary btn--sm" data-go ${chans.some(c => c.available) && !(d.missing || []).length ? '' : 'disabled'}>Send link</button></div>`;
      m.dispatchEvent(new Event('change'));
    } catch (e) { box.textContent = "Couldn't load this person's verified contacts."; }
  }

  document.addEventListener('click', e => {
    const b = e.target.closest('[data-idv-send]');
    if (b) { e.preventDefault(); e.stopPropagation(); open(b.dataset.idvSend, b.dataset.idvName); }
  }, true);
  return { button, open };
})();
