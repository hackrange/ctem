// Admin: an exception for the devices and vulnerabilities a rule describes. Describe it in plain words for the
// AI to draft (when it's set up), or edit the rule; Check previews what it covers; Create needs a checked rule,
// a reason, compensating controls and an end date. The dialog closes only from its own buttons.
(() => {
  const API = '/api/v1/exceptions/rule';
  const $ = id => document.getElementById(id);
  const TEMPLATE = { schema: 'open-ctem/exception-rule@1', name: 'Legacy Cisco IOS gear behind the bastion',
                     devices: { include: { hostname_patterns: ['can*'], os_starts_with: ['Cisco IOS'] } } };
  let checked = null, checkedDevices = 0, done = null;

  async function post(path, body) {
    const r = await fetch(API + path, { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
    if (r.status === 422) return { ok: false, error: 'Check the fields: the reason and compensating controls need at least 10 characters, and the end date must be within a year.' };
    if (!r.ok) return { ok: false, error: 'The server refused that.' };
    return r.json();
  }

  const msg = (text, bad) => { const m = $('exr2-msg'); m.textContent = text || ''; m.style.color = bad ? 'var(--severity-critical)' : 'var(--fg-muted)'; };

  function ruleText() {
    try { return JSON.parse($('exr2-rule').value); } catch (e) { return null; }
  }

  function invalidate() {
    checked = null;
    $('exr2-create').disabled = true;
    $('exr2-preview').innerHTML = '<span class="text-muted">Changed. Check it again before creating.</span>';
  }

  async function check() {
    const rule = ruleText();
    if (!rule) return msg('The rule is not valid JSON.', true);
    msg('Checking...');
    const p = await post('/preview', { rule });
    if (!p.ok) { invalidate(); return msg(p.error, true); }
    msg('');
    $('exr2-rule').value = JSON.stringify(p.rule, null, 2);
    checked = $('exr2-rule').value;
    checkedDevices = p.devices;
    $('exr2-preview').innerHTML = `<div><b>${esc(p.summary)}</b></div>
      <div style="margin-top:4px">Covers <b>${p.devices.toLocaleString()}</b> devices and <b>${p.open_findings.toLocaleString()}</b>
        open findings (${p.vulnerabilities.toLocaleString()} vulnerabilities) right now. New matches are covered as they appear.</div>
      ${p.warning ? `<div class="tk-note" style="margin-top:6px;border-color:var(--severity-high)"><b>Warning:</b> ${esc(p.warning)}</div>` : ''}
      ${p.kev_findings ? `<div class="tk-note" style="margin-top:6px">Includes ${p.kev_findings.toLocaleString()} known-exploited (KEV) findings. Consider "kev": false.</div>` : ''}
      ${p.too_broad ? `<div class="tk-note" style="margin-top:6px;color:var(--severity-critical)">Too broad: at most ${p.max_devices.toLocaleString()} devices.</div>` : ''}
      ${p.sample.length ? `<div class="text-sm text-muted" style="margin-top:6px">${esc(p.sample.join(', '))}${p.devices > p.sample.length ? ', ...' : ''}</div>` : ''}`;
    $('exr2-create').disabled = !p.devices || p.too_broad;
  }

  async function draft() {
    const text = $('exr2-text').value.trim();
    if (text.length < 5) return msg('Describe the devices first.', true);
    $('exr2-draft').disabled = true;
    msg('Asking the AI...');
    const r = await post('/draft', { text });
    $('exr2-draft').disabled = false;
    if (r.available === false) return msg('No AI integration is set up. Edit the rule below instead.', true);
    if (!r.document) return msg(r.error || 'The AI had no draft. Try rewording it.', true);
    $('exr2-rule').value = JSON.stringify(r.document, null, 2);
    if (r.error) { invalidate(); return msg(r.error, true); }
    msg(r.note ? `The AI noted: ${r.note}` : '');
    await check();
  }

  async function create() {
    if (!checked || $('exr2-rule').value !== checked) return msg('Check the rule first.', true);
    const reason = $('exr2-reason').value.trim(), controls = $('exr2-controls').value.trim(), until = $('exr2-until').value;
    if (reason.length < 10) return msg('Give a reason (at least 10 characters).', true);
    if (controls.length < 10) return msg('Describe the compensating controls in place (at least 10 characters).', true);
    if (/[<>]/.test(reason + controls)) return msg("Please don't use < or >.", true);
    if (!until) return msg('Pick an end date.', true);
    if (!confirm(`This exception will exclude ${checkedDevices.toLocaleString()} host${checkedDevices === 1 ? '' : 's'} until ${until}. Create it?`)) return;
    $('exr2-create').disabled = true;
    const r = await post('', { rule: JSON.parse(checked), reason, compensating_controls: controls, expires_on: until });
    $('exr2-create').disabled = false;
    if (!r.ok) return msg(r.error, true);
    $('exr2-modal').classList.remove('is-open');
    toast(`Exception created: ${r.findings_covered.toLocaleString()} findings on ${r.devices.toLocaleString()} devices`, 'ok');
    if (done) done();
  }

  function open(onDone) {
    done = onDone;
    let wrap = $('exr2-modal');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'exr2-modal';
      wrap.className = 'tk-backdrop';
      wrap.setAttribute('role', 'dialog');
      wrap.setAttribute('aria-modal', 'true');
      document.body.appendChild(wrap);
    }
    const today = new Date(), max = new Date(Date.now() + 365 * 864e5).toISOString().slice(0, 10);
    const def = new Date(today.getTime() + 90 * 864e5).toISOString().slice(0, 10);
    wrap.innerHTML = `<div class="tk-dialog" style="max-width:780px;max-height:90vh;overflow:auto">
      <h2 class="tk-title">Rule exception</h2>
      <p class="tk-sub">An exception for every device and vulnerability a rule describes, kept up to date as devices and findings change.</p>
      <label class="form-label" for="exr2-text">Describe it <span class="text-muted">(the AI drafts the rule, if it's set up)</span></label>
      <div style="display:flex;gap:6px;align-items:flex-start">
        <textarea id="exr2-text" class="form-input" rows="2" maxlength="1000" placeholder="e.g. Devices named starting with CAN with an OS starting with Cisco IOS"></textarea>
        <button type="button" class="btn btn--ghost btn--sm" id="exr2-draft">Draft with AI</button></div>
      <label class="form-label" for="exr2-rule" style="margin-top:10px">Rule <span class="text-muted">(open-ctem/exception-rule@1: devices uses the curated-rule filters; leave vulnerabilities out to cover all of them)</span></label>
      <textarea id="exr2-rule" class="form-input" rows="9" spellcheck="false" style="font-family:var(--font-mono, monospace);font-size:.8rem">${esc(JSON.stringify(TEMPLATE, null, 2))}</textarea>
      <div style="display:flex;justify-content:flex-end;margin-top:6px"><button type="button" class="btn btn--ghost btn--sm" id="exr2-check">Check</button></div>
      <div id="exr2-preview" class="panel text-sm" style="margin:8px 0"><span class="text-muted">Check the rule to see what it covers.</span></div>
      <label class="form-label" for="exr2-reason">Reason <span style="color:var(--severity-critical)">*</span></label>
      <textarea id="exr2-reason" class="form-input" rows="2" maxlength="2000" placeholder="e.g. End-of-life Cisco switches pending replacement in Q3; no vendor patches"></textarea>
      <label class="form-label" for="exr2-controls" style="margin-top:8px">Compensating controls in place <span style="color:var(--severity-critical)">*</span></label>
      <textarea id="exr2-controls" class="form-input" rows="2" maxlength="2000" placeholder="e.g. Reachable only from the bastion hosts; firewall rules allow SSH from 2 admin IPs; no internet access"></textarea>
      <label class="form-label" for="exr2-until" style="margin-top:8px">Ends <span style="color:var(--severity-critical)">*</span></label>
      <input id="exr2-until" type="date" class="form-input" style="max-width:200px" min="${today.toISOString().slice(0, 10)}" max="${max}" value="${def}">
      <div id="exr2-msg" class="text-sm" style="min-height:1.2em;margin-top:8px"></div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px">
        <button type="button" class="btn btn--ghost btn--sm" id="exr2-cancel">Cancel</button>
        <button type="button" class="btn btn--primary btn--sm" id="exr2-create" disabled>Create exception</button></div></div>`;
    $('exr2-cancel').onclick = () => wrap.classList.remove('is-open');
    $('exr2-draft').onclick = draft;
    $('exr2-check').onclick = check;
    $('exr2-create').onclick = create;
    $('exr2-rule').addEventListener('input', invalidate);
    checked = null;
    wrap.classList.add('is-open');
    $('exr2-text').focus();
  }

  window.ExceptionRule = { open };
})();
