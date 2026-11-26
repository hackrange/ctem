// Email (outgoing mail): SMTP or Microsoft 365 Graph; and the Twilio card's Send test text. Like the AI providers it has nothing to sync: Test signs in,
// and the card adds "Send test email".
Object.assign(VENDOR_FIELDS, {
  email: [
    { key: 'mode', label: 'Send with', type: 'select', options: ['smtp', 'ms365'],
      optionLabels: { smtp: 'SMTP server', ms365: 'Microsoft 365 (Graph API)' }, required: true },
    { key: 'from_address', label: 'From address', type: 'text', placeholder: 'ctem@acme.example.com', required: true },
    // mode: shown only for that way of sending (emailFieldsShown below); hidden fields aren't saved
    { key: 'smtp_host', label: 'SMTP host', type: 'text', placeholder: 'smtp.acme.example.com', required: false, mode: 'smtp' },
    { key: 'smtp_port', label: 'SMTP port', type: 'number', placeholder: '587', required: false, mode: 'smtp' },
    { key: 'smtp_security', label: 'Security', type: 'select', options: ['starttls', 'ssl', 'none'],
      optionLabels: { starttls: 'STARTTLS (port 587)', ssl: 'SSL/TLS (port 465)', none: 'None (internal relay only)' }, required: false, mode: 'smtp' },
    { key: 'smtp_username', label: 'SMTP username (blank = no login)', type: 'text', placeholder: '', required: false, mode: 'smtp' },
    { key: 'smtp_password', label: 'SMTP password', type: 'password', placeholder: '', required: false, mode: 'smtp' },
    { key: 'ms365_tenant_id', label: 'Tenant ID', type: 'text', placeholder: '00000000-0000-0000-0000-000000000000', required: false, mode: 'ms365' },
    { key: 'ms365_client_id', label: 'App (client) ID', type: 'text', placeholder: '', required: false, mode: 'ms365' },
    { key: 'ms365_client_secret', label: 'Client secret (the app needs the Mail.Send application permission)', type: 'password', placeholder: '', required: false, mode: 'ms365' },
  ],
});
AI_VENDORS.add('email');   // a "Test" card (Connected / Test failed) rather than a sync card

// Only the fields for the chosen way of sending: SMTP's server settings or Microsoft 365's app registration
// A phone number as Twilio needs it (E.164): + then country code and number. Spaces, dashes, dots and brackets
// are tidied away; nothing is guessed, so a number without its country code is flagged, not changed.
window.toE164 = raw => { const v = String(raw || '').replace(/[\s\-.()]/g, ''); return /^\+[1-9]\d{7,14}$/.test(v) ? v : null; };
function e164Field(el) {
  const note = document.createElement('div');
  note.className = 'text-sm';
  note.style.cssText = 'margin-top:3px;color:var(--severity-critical)';
  el.insertAdjacentElement('afterend', note);
  const check = () => {
    const v = el.value.trim(), ok = toE164(v);
    if (ok && ok !== v) el.value = ok;
    note.textContent = !v || ok ? '' : 'Use international form: + then the country code and number, like +15550100199';
    el.setAttribute('aria-invalid', String(!!(v && !ok)));
  };
  el.addEventListener('blur', check);
  el.addEventListener('input', () => { if (note.textContent) check(); });
}

window.emailFieldsShown = vendor => {
  if (vendor === 'twilio') {
    const from = document.getElementById('cfg-from_number');
    if (from && !from.dataset.e164) { from.dataset.e164 = '1'; e164Field(from); }
    return;
  }
  const mode = vendor === 'email' && document.getElementById('cfg-mode');
  if (!mode) return;
  const apply = () => {
    for (const f of VENDOR_FIELDS.email) {
      const el = f.mode && document.getElementById(`cfg-${f.key}`);
      if (el) el.parentElement.hidden = f.mode !== mode.value;
    }
    const from = document.getElementById('cfg-from_address');
    if (from) from.placeholder = mode.value === 'ms365' ? 'the Microsoft 365 mailbox, e.g. ctem@acme.example.com' : 'ctem@acme.example.com';
  };
  mode.addEventListener('change', apply);
  apply();
};

window.emailTestBtn = i => (i.shipper_managed ? ''
  : i.vendor === 'email' ? `<button class="btn btn--ghost btn--sm" onclick="sendTestEmail('${esc(i.id)}')">Send test email</button>`
  : i.vendor === 'twilio' ? `<button class="btn btn--ghost btn--sm" onclick="sendTestSms('${esc(i.id)}')">Send test text</button>`
  : i.vendor === 'persona' ? `<button class="btn btn--ghost btn--sm" onclick="personaTemplates('${esc(i.id)}')">Templates in use</button>` : '');

// Persona > Templates in use: each inquiry template, its use, and what CTEM uses it for (admins)
window.personaTemplates = async id => {
  let wrap = document.getElementById('ptpl-dialog');
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.id = 'ptpl-dialog';
    wrap.className = 'tk-backdrop';
    wrap.setAttribute('role', 'dialog');
    wrap.setAttribute('aria-modal', 'true');
    wrap.setAttribute('aria-labelledby', 'ptpl-title');
    document.body.appendChild(wrap);
  }
  wrap.innerHTML = `<div class="tk-dialog" style="max-width:1100px;width:94vw;max-height:88vh;overflow:auto">
    <div style="display:flex;justify-content:space-between;align-items:center"><h2 class="tk-title" id="ptpl-title">Persona inquiry templates</h2>
      <button type="button" class="btn btn--ghost btn--sm" id="ptpl-close" aria-label="Close">&#10005;</button></div>
    <p class="text-sm text-muted" style="margin:4px 0 10px">Inquiry templates (itmpl_...) are whole flows a person goes through. Verification templates (vtmpl_...) are the
      single steps inside them and never go in CTEM. Uses come from the checks CTEM has read; "selfie only" counts runs where the template skipped the ID
      for someone verified before.</p>
    <div id="ptpl-body" class="text-sm">Loading...</div></div>`;
  wrap.classList.add('is-open');
  document.getElementById('ptpl-close').onclick = () => wrap.classList.remove('is-open');
  const body = document.getElementById('ptpl-body');
  try {
    const r = await fetch(`/api/v1/integrations/${encodeURIComponent(id)}/persona-templates`, { headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error();
    const d = await r.json();
    const day = s => (s ? new Date(s).toLocaleDateString() : 'never');
    body.innerHTML = (d.error ? `<p style="color:var(--severity-high)">${esc(d.error)}</p>` : '') + `<table class="data-table" style="width:100%;font-size:13px">
      <thead><tr><th>Template</th><th>Status</th><th>Uses</th><th>Last 30 days</th><th>Passed</th><th>Selfie only</th><th>Last used</th><th>CTEM uses it for</th></tr></thead>
      <tbody>${d.templates.map(t => `<tr${t.uses ? '' : ' style="opacity:.6"'}>
        <td><b>${esc(t.name || '(no name)')}</b><div class="text-mono text-muted" style="font-size:11px">${esc(t.id)}</div></td>
        <td>${t.status === 'active' ? '<span class="chip chip--low">Active</span>' : `<span class="chip chip--info">${esc(t.status)}</span>`}</td>
        <td>${esc(t.uses.toLocaleString())}</td><td>${esc(t.last_30_days.toLocaleString())}</td><td>${esc(t.passed.toLocaleString())}</td>
        <td>${esc(t.selfie_only.toLocaleString())}</td><td>${esc(day(t.last_used))}</td>
        <td>${t.ctem_uses.length ? t.ctem_uses.map(u => `<span class="chip chip--medium" style="font-size:.7rem;margin:0 4px 4px 0">${esc(u)}</span>`).join('') : '<span class="text-muted">--</span>'}</td>
      </tr>`).join('')}</tbody></table>`;
  } catch (e) { body.textContent = "Couldn't load the templates."; }
};

window.sendTestSms = id => {
  let wrap = document.getElementById('sms-dialog');
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.id = 'sms-dialog';
    wrap.className = 'tk-backdrop';
    wrap.setAttribute('role', 'dialog');
    wrap.setAttribute('aria-modal', 'true');
    wrap.setAttribute('aria-labelledby', 'sms-title');
    document.body.appendChild(wrap);
  }
  wrap.innerHTML = `<div class="tk-dialog" style="max-width:440px"><h2 class="tk-title" id="sms-title">Send a test text</h2>
    <label class="form-label" for="sms-to">To (international form)</label>
    <input id="sms-to" class="form-input" type="tel" maxlength="24" placeholder="+15550100199" autocomplete="off">
    <p class="text-sm text-muted" style="margin:6px 0 0">A short fixed message, no link. Up to five an hour.</p>
    <p id="sms-msg" class="text-sm" role="status" style="min-height:1.2em;margin:8px 0 0"></p>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px">
      <button type="button" class="btn btn--ghost btn--sm" id="sms-cancel">Close</button>
      <button type="button" class="btn btn--primary btn--sm" id="sms-send">Send</button></div></div>`;
  wrap.classList.add('is-open');
  const input = document.getElementById('sms-to');
  e164Field(input);
  input.focus();
  document.getElementById('sms-cancel').onclick = () => wrap.classList.remove('is-open');
  document.getElementById('sms-send').onclick = async () => {
    const msg = document.getElementById('sms-msg'), btn = document.getElementById('sms-send');
    const to = toE164(input.value);
    if (!to) { msg.style.color = 'var(--severity-critical)'; msg.textContent = 'Enter the number as + then the country code and number, like +15550100199.'; return; }
    input.value = to;
    btn.disabled = true;
    msg.style.color = 'var(--text-muted)';
    msg.textContent = 'Sending...';
    const r = await fetch(`/api/v1/integrations/${encodeURIComponent(id)}/sms-test`, { method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ to }) });
    btn.disabled = false;
    const e = await r.json().catch(() => ({}));
    msg.style.color = r.ok ? 'var(--severity-low)' : 'var(--severity-critical)';
    msg.textContent = r.ok ? `Sent to ${e.to} (Twilio: ${e.status}). Check the phone.` : (typeof e.detail === 'string' ? e.detail : 'Could not send.');
  };
};

window.sendTestEmail = async id => {
  let wrap = document.getElementById('mail-dialog');
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.id = 'mail-dialog';
    wrap.className = 'tk-backdrop';
    wrap.setAttribute('role', 'dialog');
    wrap.setAttribute('aria-modal', 'true');
    wrap.setAttribute('aria-labelledby', 'mail-title');
    document.body.appendChild(wrap);
  }
  wrap.innerHTML = `<div class="tk-dialog" style="max-width:440px"><h2 class="tk-title" id="mail-title">Send a test email</h2>
    <label class="form-label" for="mail-to">To</label><input id="mail-to" class="form-input" type="email" maxlength="254" placeholder="you@acme.example.com">
    <p id="mail-msg" class="text-sm" role="status" style="min-height:1.2em;margin:8px 0 0"></p>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px">
      <button type="button" class="btn btn--ghost btn--sm" id="mail-cancel">Close</button>
      <button type="button" class="btn btn--primary btn--sm" id="mail-send">Send</button></div></div>`;
  wrap.classList.add('is-open');
  document.getElementById('mail-to').focus();
  document.getElementById('mail-cancel').onclick = () => wrap.classList.remove('is-open');   // only its own buttons close it
  document.getElementById('mail-send').onclick = async () => {
    const msg = document.getElementById('mail-msg'), btn = document.getElementById('mail-send');
    btn.disabled = true;
    msg.style.color = 'var(--text-muted)';
    msg.textContent = 'Sending...';
    const r = await fetch(`/api/v1/integrations/${encodeURIComponent(id)}/email-test`, { method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ to: document.getElementById('mail-to').value.trim() }) });
    btn.disabled = false;
    const e = await r.json().catch(() => ({}));
    msg.style.color = r.ok ? 'var(--severity-low)' : 'var(--severity-critical)';
    msg.textContent = r.ok ? 'Sent. Check the inbox (and spam).' : r.status === 422 ? 'Enter a valid email address.' : (typeof e.detail === 'string' ? e.detail : 'Could not send.');
  };
};
