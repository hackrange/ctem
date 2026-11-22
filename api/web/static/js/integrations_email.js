// Email (outgoing mail): SMTP or Microsoft 365 Graph. Like the AI providers it has nothing to sync: Test signs in,
// and the card adds "Send test email".
Object.assign(VENDOR_FIELDS, {
  email: [
    { key: 'mode', label: 'Send with', type: 'select', options: ['smtp', 'ms365'],
      optionLabels: { smtp: 'SMTP server', ms365: 'Microsoft 365 (Graph API)' }, required: true },
    { key: 'from_address', label: 'From address (the Microsoft 365 mailbox for Graph)', type: 'text', placeholder: 'ctem@acme.example.com', required: true },
    { key: 'smtp_host', label: 'SMTP host (SMTP)', type: 'text', placeholder: 'smtp.acme.example.com', required: false },
    { key: 'smtp_port', label: 'SMTP port (SMTP)', type: 'number', placeholder: '587', required: false },
    { key: 'smtp_security', label: 'Security (SMTP)', type: 'select', options: ['starttls', 'ssl', 'none'],
      optionLabels: { starttls: 'STARTTLS (port 587)', ssl: 'SSL/TLS (port 465)', none: 'None (internal relay only)' }, required: false },
    { key: 'smtp_username', label: 'SMTP username (blank = no login)', type: 'text', placeholder: '', required: false },
    { key: 'smtp_password', label: 'SMTP password', type: 'password', placeholder: '', required: false },
    { key: 'ms365_tenant_id', label: 'Tenant ID (Microsoft 365)', type: 'text', placeholder: '00000000-0000-0000-0000-000000000000', required: false },
    { key: 'ms365_client_id', label: 'App (client) ID (Microsoft 365)', type: 'text', placeholder: '', required: false },
    { key: 'ms365_client_secret', label: 'Client secret (Microsoft 365; the app needs the Mail.Send application permission)', type: 'password', placeholder: '', required: false },
  ],
});
AI_VENDORS.add('email');   // a "Test" card (Connected / Test failed) rather than a sync card

window.emailTestBtn = i => (i.vendor === 'email' && !i.shipper_managed
  ? `<button class="btn btn--ghost btn--sm" onclick="sendTestEmail('${esc(i.id)}')">Send test email</button>` : '');

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
