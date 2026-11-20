// ServiceNow ticket dialog. Only shows delivery methods that are set up; copy-to-clipboard always works.
// openTicketModal(vulnId, label[, findingId])
(function () {
  const API = '/api/v1';
  let state = null;
  let previewTimer = null;

  function el(id) { return document.getElementById(id); }

  function build() {
    if (el('tk-modal')) return;
    const wrap = document.createElement('div');
    wrap.id = 'tk-modal';
    wrap.className = 'tk-backdrop';
    wrap.setAttribute('role', 'dialog');
    wrap.setAttribute('aria-modal', 'true');
    wrap.setAttribute('aria-labelledby', 'tk-title');
    wrap.innerHTML = `
      <div class="tk-dialog">
        <h2 id="tk-title" class="tk-title">Create ServiceNow ticket</h2>
        <p id="tk-label" class="tk-sub text-mono"></p>
        <div id="tk-methods" class="form-group" hidden>
          <span class="form-label">Create via</span>
          <div id="tk-method-list" class="tk-methods"></div>
        </div>
        <div id="tk-nosetup" class="tk-note" hidden>
          ServiceNow is not set up yet, so tickets can't be created automatically.
          Copy the ticket text below and send it by email. To automate this, add a ServiceNow
          integration under <a href="/settings/integrations">Settings &rsaquo; Integrations</a>.
        </div>
        <div class="form-group">
          <label class="form-label" for="tk-group">Assignment group <span class="text-muted">(optional)</span></label>
          <input id="tk-group" class="form-input" type="text" maxlength="128" placeholder="e.g. Security Operations">
        </div>
        <div class="form-group">
          <label class="form-label" for="tk-notes">Additional notes <span class="text-muted">(optional)</span></label>
          <textarea id="tk-notes" class="form-input" rows="2" maxlength="2000" placeholder="Any context for the responder"></textarea>
        </div>
        <div class="form-group">
          <span class="form-label">Ticket text</span>
          <input id="tk-subject" class="form-input tk-subject" type="text" readonly aria-label="Subject">
          <textarea id="tk-body" class="form-input tk-body" rows="8" readonly aria-label="Ticket text"></textarea>
          <div class="tk-copy">
            <button type="button" class="btn btn--ghost btn--sm" data-copy="subject">Copy subject</button>
            <button type="button" class="btn btn--ghost btn--sm" data-copy="all">Copy ticket text</button>
            <span id="tk-copied" class="text-sm" role="status"></span>
          </div>
        </div>
        <div id="tk-result" class="tk-result" hidden></div>
        <div class="tk-actions">
          <button type="button" class="btn btn--ghost" data-close>Close</button>
          <button type="button" class="btn btn--primary" id="tk-submit" hidden>Create ticket</button>
        </div>
      </div>`;
    document.body.appendChild(wrap);
    wrap.addEventListener('click', e => { if (e.target === wrap || e.target.closest('[data-close]')) close(); });
    wrap.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
    wrap.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => copy(b.dataset.copy)));
    el('tk-submit').addEventListener('click', submit);
    ['tk-group', 'tk-notes'].forEach(id => el(id).addEventListener('input', () => {
      clearTimeout(previewTimer);
      previewTimer = setTimeout(loadPreview, 400);
    }));
  }

  async function getJson(url) {
    const r = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error(r.status === 404 ? 'No open finding you can access for this vulnerability' : 'Request failed');
    return r.json();
  }

  async function open(vulnId, label, findingId) {
    build();
    state = { vulnId, findingId: findingId || null };
    el('tk-label').textContent = label || '';
    el('tk-group').value = '';
    el('tk-notes').value = '';
    el('tk-subject').value = '';
    el('tk-body').value = 'Loading...';
    el('tk-copied').textContent = '';
    el('tk-result').hidden = true;
    el('tk-modal').classList.add('is-open');
    el('tk-group').focus();

    const opts = await getJson(`${API}/vulns/findings/ticket-options`).catch(() => ({ api: false, email: false }));
    const methods = [opts.api && ['api', 'ServiceNow API'], opts.email && ['email', 'Inbound email']].filter(Boolean);
    el('tk-methods').hidden = methods.length < 2;
    el('tk-method-list').innerHTML = methods.map(([v, t], i) =>
      `<label class="tk-radio"><input type="radio" name="tk-method" value="${v}" ${i === 0 ? 'checked' : ''}> ${esc(t)}</label>`).join('');
    el('tk-nosetup').hidden = methods.length > 0;
    const submitBtn = el('tk-submit');
    submitBtn.hidden = methods.length === 0;
    submitBtn.disabled = false;
    submitBtn.textContent = methods.length === 1 ? `Create via ${methods[0][1]}` : 'Create ticket';
    state.methods = methods.map(m => m[0]);

    try {
      if (!state.findingId) {
        const f = await getJson(`${API}/vulns/${encodeURIComponent(vulnId)}/findings?limit=1`);
        state.findingId = f.findings && f.findings[0] && f.findings[0].id;
        if (!state.findingId) throw new Error('No open finding you can access for this vulnerability');
      }
      await loadPreview();
    } catch (err) {
      el('tk-body').value = '';
      showResult(false, err.message);
      submitBtn.hidden = true;
    }
  }

  async function loadPreview() {
    if (!state || !state.findingId) return;
    const p = new URLSearchParams();
    const notes = el('tk-notes').value.trim();
    const group = el('tk-group').value.trim();
    if (notes) p.set('notes', notes);
    if (group) p.set('assignment_group', group);
    const data = await getJson(`${API}/vulns/findings/${encodeURIComponent(state.findingId)}/ticket/preview?${p}`);
    el('tk-subject').value = data.subject;
    el('tk-body').value = data.body;
  }

  async function copy(which) {
    const text = which === 'subject' ? el('tk-subject').value : `Subject: ${el('tk-subject').value}\n\n${el('tk-body').value}`;
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; } catch { /* fall back below */ }
    if (!ok) {
      // Older browsers or blocked clipboard API: select the text so Ctrl+C works
      const t = which === 'subject' ? el('tk-subject') : el('tk-body');
      t.focus(); t.select();
      try { ok = document.execCommand('copy'); } catch { ok = false; }
    }
    el('tk-copied').textContent = ok ? 'Copied' : 'Selected: press Ctrl+C to copy';
  }

  function showResult(ok, html) {
    const r = el('tk-result');
    r.hidden = false;
    r.className = `tk-result ${ok ? 'tk-result--ok' : 'tk-result--err'}`;
    if (ok) r.innerHTML = html; else r.textContent = html;
  }

  async function submit() {
    if (!state || !state.findingId) return;
    const method = (document.querySelector('input[name="tk-method"]:checked') || {}).value || state.methods[0];
    const btn = el('tk-submit');
    btn.disabled = true;
    btn.textContent = 'Creating...';
    try {
      const res = await fetch(`${API}/vulns/findings/${encodeURIComponent(state.findingId)}/ticket`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ method, assignment_group: el('tk-group').value.trim() || null, notes: el('tk-notes').value.trim() || null }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Ticket creation failed');
      const num = esc(data.number || 'pending');
      const url = /^https?:\/\//i.test(data.url || '') ? esc(data.url) : '';
      showResult(true, `&#10003; Ticket created: <strong>${url ? `<a href="${url}" target="_blank" rel="noopener">${num}</a>` : num}</strong>`
        + (data.sent_to ? `<br><small>Sent to ${esc(data.sent_to)}</small>` : ''));
      btn.textContent = 'Done';
    } catch (err) {
      showResult(false, err.message);
      btn.disabled = false;
      btn.textContent = 'Retry';
    }
  }

  function close() {
    const m = el('tk-modal');
    if (m) m.classList.remove('is-open');
    state = null;
  }

  window.openTicketModal = open;
  window.closeTicketModal = close;
})();
