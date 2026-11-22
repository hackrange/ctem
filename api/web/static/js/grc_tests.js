// GRC > Controls: open a control to test it and record the attestation (what was tested, expected, outcome, pass or
// fail and why), see its testing history and when the next test is due; admins set the testing rules (how often
// each control must be tested). Dialogs close only from their own buttons. Everything shown goes through esc().
window.GrcTests = (() => {
  const API = '/api/v1/grc';
  const $ = id => document.getElementById(id);
  const day = iso => (iso ? new Date(iso.length === 10 ? `${iso}T12:00:00` : iso).toLocaleDateString() : '--');
  const SENT = { sent: ['chip--low', 'Sent to FairTPRM'], summary: ['chip--medium', 'FairTPRM: dates only'],
                 failed: ['chip--critical', 'Not sent'], not_connected: ['chip--info', 'CTEM only'] };

  async function call(method, path, body) {
    const r = await fetch(API + path, { method, headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                                        body: body ? JSON.stringify(body) : undefined });
    if (r.status === 401) return { ok: false, error: 'Your sign-in has expired. Sign in again.' };
    if (r.status === 422) {
      const d = await r.json().catch(() => ({}));
      const m = Array.isArray(d.detail) ? d.detail.map(x => String(x.msg || '').replace(/^Value error, /, '')).join('; ') : '';
      return { ok: false, error: m || 'Check the form.' };
    }
    if (!r.ok) return { ok: false, error: r.status === 403 || r.status === 404 ? "That isn't available to you." : 'Something went wrong. Try again.' };
    return r.json();
  }

  // The Testing cell in the controls list
  function cell(t) {
    if (!t) return '';
    const res = t.last_result ? ` <span class="chip ${t.last_result === 'pass' ? 'chip--low' : 'chip--critical'}" style="font-size:.65rem">${esc(t.last_result)}</span>` : '';
    if (!t.last_tested) return `<span class="chip chip--critical" title="Every ${esc(t.interval_days)} days (${esc(t.interval_why)})">Never tested</span>`;
    if (t.overdue) return `<span class="chip chip--critical" title="Due ${esc(day(t.next_due))}; every ${esc(t.interval_days)} days">Overdue</span>${res}`;
    const cls = t.days_left <= 14 ? 'chip--medium' : 'chip--low';
    return `<span class="chip ${cls}" title="Every ${esc(t.interval_days)} days (${esc(t.interval_why)})">Due ${esc(day(t.next_due))}</span>${res}`;
  }

  function dialog(id, width = 820) {
    let wrap = $(id);
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = id;
      wrap.className = 'tk-backdrop';
      wrap.setAttribute('role', 'dialog');
      wrap.setAttribute('aria-modal', 'true');
      wrap.setAttribute('aria-labelledby', `${id}-title`);
      wrap.innerHTML = `<div class="tk-dialog" style="max-width:${width}px;width:96vw;max-height:90vh;overflow:auto">
        <h2 class="tk-title" id="${id}-title"></h2><div id="${id}-body"></div>
        <p id="${id}-msg" class="text-sm" role="status" style="min-height:1.2em;margin:8px 0 0"></p>
        <div id="${id}-actions" style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px"></div></div>`;
      document.body.appendChild(wrap);
    }
    $(`${id}-msg`).textContent = '';
    $(`${id}-actions`).innerHTML = '';
    wrap.classList.add('is-open');
    const button = (label, cls, fn) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = `btn ${cls} btn--sm`;
      b.textContent = label;
      b.onclick = fn;
      $(`${id}-actions`).appendChild(b);
      return b;
    };
    return { wrap, title: $(`${id}-title`), body: $(`${id}-body`), msg: (t, bad) => { const m = $(`${id}-msg`); m.textContent = t; m.style.color = bad ? 'var(--severity-critical)' : ''; },
             button, close: () => wrap.classList.remove('is-open') };
  }

  async function open(controlId) {
    const d = dialog('ct-dialog');
    d.title.textContent = 'Loading...';
    d.body.innerHTML = '';
    const r = await call('GET', `/controls/${encodeURIComponent(controlId)}/tests`);
    if (!r.control) { d.title.textContent = 'Control'; d.msg(r.error || 'That control could not load.', true); d.button('Close', 'btn--primary', d.close); return; }
    const c = r.control, t = r.testing;
    d.title.textContent = `${c.control_ref ? `${c.control_ref}: ` : ''}${c.title}`;
    const status = !t.last_tested ? '<b style="color:var(--severity-critical)">Never tested</b>'
      : t.overdue ? `<b style="color:var(--severity-critical)">Overdue since ${esc(day(t.next_due))}</b>` : `Next test due <b>${esc(day(t.next_due))}</b>`;
    const today = new Date().toISOString().slice(0, 10);
    d.body.innerHTML = `
      <p class="tk-sub" style="margin:0 0 10px">${[c.control_type, c.risk_level ? `${c.risk_level} risk` : '', c.frequency ? `frequency ${c.frequency}` : '',
        (c.frameworks || []).join(', ')].filter(Boolean).map(esc).join(' · ')}</p>
      <div class="text-sm" style="margin-bottom:12px">${status}. Tested every <b>${esc(t.interval_days)}</b> days (${esc(t.interval_why)})${
        t.last_tested ? `; last tested ${esc(day(t.last_tested))}${t.last_tested_by ? ` by ${esc(t.last_tested_by)}` : ''}` : ''}.</div>
      ${r.can_test ? `<details id="ct-form-wrap" ${r.tests.length ? '' : 'open'} style="border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:14px">
        <summary style="cursor:pointer;font-weight:600">Record a test</summary>
        <p class="text-sm text-muted" style="margin:8px 0">You attest to this test as <b>${esc(r.you || 'yourself')}</b>.${c.from_fairtprm ? ' It is also sent to FairTPRM.' : ''}</p>
        <label class="form-label" for="ct-what">What was tested</label>
        <textarea id="ct-what" class="form-input" rows="3" maxlength="5000" placeholder="For example: pulled 25 terminated users from HR and checked each account was disabled within 24 hours"></textarea>
        <label class="form-label" for="ct-expected" style="margin-top:8px">Expected result</label>
        <textarea id="ct-expected" class="form-input" rows="2" maxlength="5000"></textarea>
        <label class="form-label" for="ct-outcome" style="margin-top:8px">Outcome (what you found)</label>
        <textarea id="ct-outcome" class="form-input" rows="2" maxlength="5000"></textarea>
        <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-top:10px">
          <span class="form-label" style="margin:0">Result</span>
          <label class="tk-radio"><input type="radio" name="ct-result" value="pass"> Pass</label>
          <label class="tk-radio"><input type="radio" name="ct-result" value="fail"> Fail</label>
          <label class="form-label" for="ct-date" style="margin:0 0 0 auto">Tested on</label>
          <input id="ct-date" type="date" class="form-input" style="width:auto" max="${today}" value="${today}">
        </div>
        <div id="ct-reason-wrap" hidden><label class="form-label" for="ct-reason" style="margin-top:8px">Failure reason</label>
          <textarea id="ct-reason" class="form-input" rows="2" maxlength="5000" placeholder="Why it failed, and what will be done"></textarea></div>
      </details>` : '<p class="text-sm text-muted">You can see this control\'s tests. Recording one needs GRC write access.</p>'}
      <h3 style="font-size:14px;margin:6px 0">Test history</h3>
      <div style="overflow-x:auto"><table class="data-table"><thead><tr><th>Tested</th><th>By</th><th>What was tested</th><th>Expected</th><th>Outcome</th><th>Result</th><th>FairTPRM</th></tr></thead>
      <tbody>${r.tests.map(x => `<tr>
        <td class="text-sm nowrap">${esc(day(x.tested_at))}</td><td class="text-sm">${esc(x.tested_by)}</td>
        <td class="text-sm" style="white-space:pre-wrap">${esc(x.what_tested)}</td><td class="text-sm" style="white-space:pre-wrap">${esc(x.expected_result)}</td>
        <td class="text-sm" style="white-space:pre-wrap">${esc(x.outcome)}</td>
        <td><span class="chip ${x.result === 'pass' ? 'chip--low' : 'chip--critical'}">${esc(x.result)}</span>${x.failure_reason ? `<div class="text-sm" style="white-space:pre-wrap;margin-top:4px">${esc(x.failure_reason)}</div>` : ''}</td>
        <td class="text-sm">${x.fairtprm_status ? `<span class="chip ${(SENT[x.fairtprm_status] || SENT.failed)[0]}" title="${esc(x.fairtprm_detail || '')}">${esc((SENT[x.fairtprm_status] || SENT.failed)[1])}</span>` : ''}${
          r.can_test && ['failed', 'summary'].includes(x.fairtprm_status) && c.from_fairtprm ? ` <button type="button" class="btn btn--ghost btn--sm" data-resend="${esc(x.id)}">Send again</button>` : ''}</td></tr>`).join('')
        || '<tr><td colspan="7" class="text-muted text-sm" style="text-align:center;padding:14px">No tests yet</td></tr>'}</tbody></table></div>`;
    d.body.querySelectorAll('input[name="ct-result"]').forEach(x => x.addEventListener('change', () => {
      $('ct-reason-wrap').hidden = x.value !== 'fail' || !x.checked;
    }));
    d.body.querySelectorAll('[data-resend]').forEach(b => b.addEventListener('click', async () => {
      b.disabled = true;
      const s = await call('POST', `/control-tests/${encodeURIComponent(b.dataset.resend)}/send`);
      d.msg((s.fairtprm || {}).detail || s.error || '', !s.ok);
      if (s.ok) setTimeout(() => open(controlId), 900);
      else b.disabled = false;
    }));
    d.button('Close', 'btn--ghost', d.close);
    if (r.can_test) {
      const save = d.button('Save attestation', 'btn--primary', async () => {
        if (!$('ct-form-wrap').open) { $('ct-form-wrap').open = true; return; }
        const pick = document.querySelector('input[name="ct-result"]:checked');
        const body = { what_tested: $('ct-what').value.trim(), expected_result: $('ct-expected').value.trim(),
                       outcome: $('ct-outcome').value.trim(), result: pick ? pick.value : null,
                       failure_reason: $('ct-reason').value.trim() || null,
                       tested_at: $('ct-date').value ? new Date(`${$('ct-date').value}T12:00:00`).toISOString() : null };
        if (!body.what_tested || !body.expected_result || !body.outcome) return d.msg('Fill in what was tested, the expected result and the outcome.', true);
        if (!body.result) return d.msg('Choose pass or fail.', true);
        if (body.result === 'fail' && !body.failure_reason) return d.msg('A failed test needs a failure reason.', true);
        save.disabled = true;
        save.textContent = 'Saving...';
        const s = await call('POST', `/controls/${encodeURIComponent(controlId)}/tests`, body);
        save.disabled = false;
        save.textContent = 'Save attestation';
        if (!s.ok) return d.msg(s.error || 'Could not save.', true);
        document.dispatchEvent(new CustomEvent('ctem:controls-changed'));
        await open(controlId);
        dialog('ct-dialog').msg(`Saved. ${(s.fairtprm || {}).detail || ''}`, (s.fairtprm || {}).status === 'failed');
      });
    }
  }

  async function rules() {
    const d = dialog('ct-rules', 760);
    d.title.textContent = 'Testing rules';
    d.body.innerHTML = '<p class="text-muted text-sm">Loading...</p>';
    const r = await call('GET', '/test-cadence');
    if (!r.rules) { d.msg(r.error || 'The rules could not load.', true); d.button('Close', 'btn--primary', d.close); return; }
    const R = r.rules, lim = r.limits;
    const num = (id, v, ph = '') => `<input id="${id}" class="form-input" type="number" min="${lim[0]}" max="${lim[1]}" step="1" value="${esc(v ?? '')}" placeholder="${esc(ph)}" style="width:96px">`;
    d.body.innerHTML = `
      <p class="tk-sub" style="margin:0 0 10px">How often each control must be tested. For each control, the first that applies:
        its own setting below, then its frequency from FairTPRM (when that's on), then its risk level, then the default.</p>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:10px">
        ${['critical', 'high', 'medium', 'low'].map(k => `<label class="text-sm"><b>${k[0].toUpperCase() + k.slice(1)} risk</b><br>${num(`cr-${k}`, R.by_risk[k])} days</label>`).join('')}
        <label class="text-sm"><b>Default</b><br>${num('cr-default', R.default_days)} days</label>
      </div>
      <label class="tk-radio"><input type="checkbox" id="cr-freq"${R.use_control_frequency ? ' checked' : ''}> Use the control's own frequency from FairTPRM (monthly, quarterly...) when it has one</label>
      <h3 style="font-size:14px;margin:14px 0 6px">Per control <span class="text-muted text-sm" style="font-weight:400">(blank follows the rules above)</span></h3>
      <div style="max-height:320px;overflow:auto"><table class="data-table"><thead><tr><th>Control</th><th>Risk</th><th>Frequency</th><th>Every (days)</th></tr></thead><tbody>
      ${r.controls.map(c => `<tr><td class="text-sm"><b>${esc(c.control_ref || '')}</b> ${esc(c.title)}</td><td class="text-sm">${esc(c.risk_level || '--')}</td>
        <td class="text-sm">${esc(c.frequency || '--')}</td><td>${num(`cr-c-${c.id}`, R.controls[c.id])}</td></tr>`).join('')
        || '<tr><td colspan="4" class="text-muted text-sm" style="text-align:center;padding:12px">No controls yet</td></tr>'}</tbody></table></div>`;
    d.button('Cancel', 'btn--ghost', d.close);
    if (!r.can_edit) { d.msg('Only admins can change the testing rules.'); d.body.querySelectorAll('input').forEach(x => { x.disabled = true; }); return; }
    d.button('Use defaults', 'btn--ghost', () => {
      ['critical', 'high', 'medium', 'low'].forEach(k => { $(`cr-${k}`).value = r.defaults.by_risk[k]; });
      $('cr-default').value = r.defaults.default_days;
      $('cr-freq').checked = r.defaults.use_control_frequency;
    });
    const save = d.button('Save', 'btn--primary', async () => {
      const n = v => (v === '' ? null : Number(v));
      const ok = v => v === null || (Number.isInteger(v) && v >= lim[0] && v <= lim[1]);
      const body = { by_risk: {}, default_days: n($('cr-default').value), use_control_frequency: $('cr-freq').checked, controls: {} };
      for (const k of ['critical', 'high', 'medium', 'low']) {
        const v = n($(`cr-${k}`).value);
        if (v === null || !ok(v)) return d.msg(`${k} risk: whole days from ${lim[0]} to ${lim[1]}.`, true);
        body.by_risk[k] = v;
      }
      if (body.default_days === null || !ok(body.default_days)) return d.msg(`Default: whole days from ${lim[0]} to ${lim[1]}.`, true);
      for (const c of r.controls) {
        const v = n($(`cr-c-${c.id}`).value);
        if (!ok(v)) return d.msg(`${c.control_ref || c.title}: whole days from ${lim[0]} to ${lim[1]}, or blank.`, true);
        if (v !== null) body.controls[c.id] = v;
      }
      save.disabled = true;
      const s = await call('PUT', '/test-cadence', body);
      save.disabled = false;
      if (!s.ok) return d.msg(s.error || 'Could not save.', true);
      d.close();
      document.dispatchEvent(new CustomEvent('ctem:controls-changed'));
    });
  }

  // CTEM Control Checks > Run schedule (admins): how often the checks run
  const every = h => (h === 1 ? 'every hour' : h === 24 ? 'daily' : `every ${h} hours`);
  async function schedule() {
    const d = dialog('cs-dialog', 680);
    d.title.textContent = 'Run schedule';
    d.body.innerHTML = '<p class="text-muted text-sm">Loading...</p>';
    const r = await call('GET', '/check-schedule');
    if (!r.rules) { d.msg(r.error || 'The schedule could not load.', true); d.button('Close', 'btn--primary', d.close); return; }
    const opts = (cur, blank) => (blank ? '<option value="">Same as all</option>' : '')
      + r.choices.map(h => `<option value="${h}"${h === cur ? ' selected' : ''}>${esc(every(h))}</option>`).join('');
    d.body.innerHTML = `<p class="tk-sub" style="margin:0 0 10px">How often each CTEM control check runs. A run of every check takes seconds;
        FairTPRM's monitors read the newest result, so shorter intervals keep its evidence fresher.</p>
      <label class="form-label" for="cs-all">Every check</label>
      <select id="cs-all" class="filter-select">${opts(r.rules.default_hours)}</select>
      <h3 style="font-size:14px;margin:14px 0 6px">Per check <span class="text-muted text-sm" style="font-weight:400">(for one that needs to run more or less often)</span></h3>
      <div style="max-height:340px;overflow:auto"><table class="data-table"><thead><tr><th>Check</th><th>Last run</th><th>Runs</th></tr></thead><tbody>
      ${r.checks.map(c => `<tr><td class="text-sm">${esc(c.name)}<br><span class="text-muted" style="font-size:.75rem">${esc(c.check_type)}</span></td>
        <td class="text-sm nowrap">${c.last_run ? esc(new Date(c.last_run).toLocaleString()) : '<span class="text-muted">not run yet</span>'}</td>
        <td><select class="filter-select" data-cs="${esc(c.check_type)}">${opts(r.rules.checks[c.check_type] || null, true)}</select></td></tr>`).join('')}</tbody></table></div>`;
    d.button('Cancel', 'btn--ghost', d.close);
    if (!r.can_edit) { d.msg('Only admins can change the schedule.'); d.body.querySelectorAll('select').forEach(x => { x.disabled = true; }); return; }
    const save = d.button('Save', 'btn--primary', async () => {
      const body = { default_hours: Number($('cs-all').value), checks: {} };
      d.body.querySelectorAll('[data-cs]').forEach(s => { if (s.value) body.checks[s.dataset.cs] = Number(s.value); });
      save.disabled = true;
      const s = await call('PUT', '/check-schedule', body);
      save.disabled = false;
      if (!s.ok) return d.msg(s.error || 'Could not save.', true);
      d.close();
      note(s.rules);
    });
  }
  const note = rules => {
    const n = $('cs-note');
    if (n) n.textContent = `Runs ${every(rules.default_hours)}${Object.keys(rules.checks).length ? ' (some checks their own)' : ''} · evidence for FairTPRM continuous monitors`;
  };

  document.addEventListener('click', e => {
    const a = e.target.closest('#controls-tbody [data-control-open], #controls-tbody tr[data-control]');
    if (!a) return;
    if (e.target.closest('a')) e.preventDefault();
    open(a.dataset.controlOpen || a.dataset.control);
  });
  document.addEventListener('DOMContentLoaded', async () => {
    const sb = $('cs-btn');
    if (sb) {
      const s = await call('GET', '/check-schedule');
      if (s.rules) { note(s.rules); sb.hidden = !s.can_edit; sb.addEventListener('click', schedule); }
    }
    const b = $('ct-rules-btn');
    if (!b) return;
    const r = await call('GET', '/test-cadence');
    b.hidden = !r.can_edit;   // the server enforces it too
    b.addEventListener('click', rules);
  });

  return { cell, open, rules, schedule };
})();
