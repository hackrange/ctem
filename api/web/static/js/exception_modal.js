// Show proof and request/create an exception, shared by the vulnerability and device pages.
// The dialogs only close from their own buttons: a stray click outside never throws away what was typed.
// Everything shown goes through esc() or textContent.
(function () {
  const API = '/api/v1';
  const $ = id => document.getElementById(id);
  const MAX_DAYS = 365;

  function dialog(id, title) {
    let wrap = $(id);
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = id;
      wrap.className = 'tk-backdrop';
      wrap.setAttribute('role', 'dialog');
      wrap.setAttribute('aria-modal', 'true');
      wrap.innerHTML = `<div class="tk-dialog" style="max-width:760px;max-height:88vh;overflow:auto">
        <h2 class="tk-title" id="${id}-title"></h2><p class="tk-sub" id="${id}-sub"></p>
        <div id="${id}-body"></div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px" id="${id}-actions"></div></div>`;
      document.body.appendChild(wrap);
    }
    $(`${id}-title`).textContent = title;
    $(`${id}-sub`).textContent = '';
    $(`${id}-actions`).innerHTML = '';
    wrap.classList.add('is-open');
    return { body: $(`${id}-body`), sub: $(`${id}-sub`), actions: $(`${id}-actions`), close: () => wrap.classList.remove('is-open') };
  }

  function button(label, cls, onClick) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = `btn ${cls} btn--sm`;
    b.textContent = label;
    b.addEventListener('click', onClick);
    return b;
  }

  async function post(url, body) {
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                                   body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    if (res.status === 422) return { ok: false, error: 'Check the form: a reason of at least 10 characters (no < or >) and an end date within a year.' };
    if (!res.ok) return { ok: false, error: res.status === 404 ? "That isn't available to you." : 'Something went wrong. Try again.' };
    return data;
  }

  // ── Show proof ────────────────────────────────────────────────────────────
  async function proof(findingId, label) {
    const d = dialog('fp-modal', 'Proof');
    d.sub.textContent = label || '';
    d.body.innerHTML = '<p class="text-muted">Asking the scanner for the evidence...</p>';
    d.actions.appendChild(button('Close', 'btn--primary', d.close));
    let r;
    try {
      const res = await fetch(`${API}/findings/${encodeURIComponent(findingId)}/proof`, { headers: { Accept: 'application/json' } });
      r = res.ok ? await res.json() : { available: false, reason: "This finding isn't available to you.", instances: [] };
    } catch (_) {
      r = { available: false, reason: "Couldn't reach CTEM. Try again.", instances: [] };
    }
    d.sub.textContent = [r.hostname, r.cve_id, r.title].filter(Boolean).join(' · ') || label || '';
    const exc = r.exception ? `<div class="tk-note">Covered by an <a href="/exceptions?id=${encodeURIComponent(r.exception.id)}">exception</a>
      until ${esc(new Date(r.exception.expires_at).toLocaleDateString())}.</div>` : '';
    if (!r.available) {
      d.body.innerHTML = `${exc}<div class="tk-note">${esc(r.reason || 'No proof available.')}</div>`;
      return;
    }
    const pre = t => `<pre class="text-mono" style="white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;margin:4px 0 0;padding:10px;background:var(--bg);border:1px solid var(--border);border-radius:6px"></pre>`;
    d.body.innerHTML = exc + r.instances.map((x, i) => `<div style="margin-bottom:14px">
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:baseline">
          <b>${r.instances.length > 1 ? `Instance ${i + 1}` : 'What the scanner found'}</b>
          ${x.port != null ? `<span class="chip chip--info" style="font-size:.7rem">${esc(`${x.protocol || ''} ${x.port}`.trim())}</span>` : ''}
          <span class="text-sm text-muted">${x.last_found ? `last found ${esc(new Date(x.last_found).toLocaleString())}` : ''}</span>
        </div>
        <div data-proof="${i}">${pre()}</div>
        ${x.solution || x.fix ? `<details style="margin-top:6px"><summary class="text-sm" style="cursor:pointer">How to fix</summary><div data-fix="${i}">${pre()}</div></details>` : ''}
      </div>`).join('');
    r.instances.forEach((x, i) => {
      d.body.querySelector(`[data-proof="${i}"] pre`).textContent = x.proof || '(the scanner gave no detail)';
      const fix = d.body.querySelector(`[data-fix="${i}"] pre`);
      if (fix) fix.textContent = [x.solution, x.fix].filter(Boolean).join('\n\n');
    });
    d.actions.prepend(button('Copy', 'btn--ghost', () => {
      const text = r.instances.map(x => x.proof || '').join('\n\n');
      navigator.clipboard && navigator.clipboard.writeText(text);
    }));
  }

  // ── Exception form ────────────────────────────────────────────────────────
  // opts: { vulnId, label, devices: [{id, hostname}], canDecide, onDone, vulns?: [{vulnId, label, deviceId}] }
  // `vulns` with devices (device page, several findings ticked): one exception per vulnerability on that device.
  // `vulns` without devices (vulnerability list): one exception per vulnerability, for all devices or a tag.
  function exceptionForm(opts) {
    const fleet = !(opts.devices && opts.devices.length);
    const many = !fleet && opts.vulns && opts.vulns.length;
    const d = dialog('ex-modal', opts.canDecide ? 'Create an exception' : 'Request an exception');
    d.sub.textContent = fleet ? (opts.vulns.length === 1 ? opts.vulns[0].label : `${opts.vulns.length} vulnerabilities`)
      : many ? `${opts.vulns.length} findings on ${opts.devices[0].hostname || 'this device'}` : (opts.label || '');
    const max = new Date(Date.now() + MAX_DAYS * 864e5).toISOString().slice(0, 10);
    const min = new Date(Date.now() + 864e5).toISOString().slice(0, 10);
    const dflt = new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10);
    const n = fleet ? 0 : opts.devices.length;
    const scopes = fleet ? [['all', 'Every device, including ones found later'], ['tag', 'Every device with a tag, including ones tagged later']]
      : many ? [] : [
      n === 1 ? ['finding', `Just ${opts.devices[0].hostname || 'this device'}`] : ['devices', `The ${n} selected devices`],
      ...(opts.canDecide ? [['all', 'Every device, including ones found later'], ['tag', 'Every device with a tag, including ones tagged later']] : []),
    ];
    d.body.innerHTML = `
      ${opts.canDecide ? '' : '<div class="tk-note">Cyber or an admin will review this. You can follow it under <a href="/exceptions">Exceptions</a>.</div>'}
      ${scopes.length > 1 ? `<div class="form-group"><span class="form-label">Covers</span>
        ${scopes.map(([v, l], i) => `<label class="tk-radio" style="margin:4px 0"><input type="radio" name="ex-scope" value="${v}" ${i ? '' : 'checked'}> ${esc(l)}</label>`).join('')}
        <div id="ex-tag-wrap" hidden style="margin-top:6px"><select id="ex-tag" class="form-input"><option value="">Loading tags...</option></select></div></div>` : ''}
      <div class="form-group"><label class="form-label" for="ex-reason">Reason <span style="color:var(--severity-critical)">*</span></label>
        <textarea id="ex-reason" class="form-input" rows="3" maxlength="2000" placeholder="Why can't this be fixed now? e.g. Vendor patch due in March; app is internal only"></textarea></div>
      <div class="form-group"><label class="form-label" for="ex-comp">Compensating controls <span class="text-muted">(optional)</span></label>
        <textarea id="ex-comp" class="form-input" rows="2" maxlength="2000" placeholder="What reduces the risk meanwhile? e.g. Blocked at the firewall, EDR in prevent mode"></textarea></div>
      <div class="form-group"><label class="form-label" for="ex-until">Ends on <span style="color:var(--severity-critical)">*</span></label>
        <input id="ex-until" type="date" class="form-input" min="${min}" max="${max}" value="${dflt}" style="max-width:200px">
        <div class="text-sm text-muted" style="margin-top:4px">At most a year. When it ends, the findings count again.</div></div>
      <div id="ex-msg" class="text-sm" style="min-height:1.2em"></div>`;
    const scopeVal = () => (document.querySelector('input[name="ex-scope"]:checked') || {}).value || (many ? 'finding' : scopes[0][0]);
    if (fleet) d.body.insertAdjacentHTML('afterbegin', `<div class="tk-note">${esc(opts.vulns.map(v => v.label).slice(0, 8).join(', '))}${opts.vulns.length > 8 ? ` and ${opts.vulns.length - 8} more` : ''}</div>`);
    d.body.querySelectorAll('input[name="ex-scope"]').forEach(r => r.addEventListener('change', async () => {
      const wrap = $('ex-tag-wrap');
      wrap.hidden = scopeVal() !== 'tag';
      if (!wrap.hidden && $('ex-tag').options.length < 2) {
        const t = await fetch(`${API}/tags?limit=500`, { headers: { Accept: 'application/json' } }).then(x => x.json()).catch(() => ({}));
        const tags = t.tags || t.items || [];
        $('ex-tag').innerHTML = '<option value="">Pick a tag...</option>' + tags.map(x => `<option value="${esc(x.id)}">${esc(x.name)}</option>`).join('');
      }
    }));
    const msg = (t, bad) => { $('ex-msg').style.color = bad ? 'var(--severity-critical)' : 'var(--fg-muted)'; $('ex-msg').innerHTML = t; };
    const submit = button(opts.canDecide ? 'Create exception' : 'Send request', 'btn--primary', async () => {
      const reason = $('ex-reason').value.trim();
      const until = $('ex-until').value;
      if (reason.length < 10) return msg('Give a reason of at least 10 characters.', true);
      if (/[<>]/.test(reason + $('ex-comp').value)) return msg("Please don't use < or > in the text.", true);
      if (!until || until < min || until > max) return msg('Pick an end date between tomorrow and a year from now.', true);
      const scope = scopeVal();
      if (scope === 'tag' && !$('ex-tag').value) return msg('Pick a tag.', true);
      const base = { reason, compensating_controls: $('ex-comp').value.trim() || null, expires_on: until };
      const items = fleet ? opts.vulns.map(v => ({ ...base, vuln_id: v.vulnId, scope, device_ids: [], tag_id: scope === 'tag' ? $('ex-tag').value : null }))
        : many ? opts.vulns.map(v => ({ ...base, vuln_id: v.vulnId, scope: 'finding', device_ids: [v.deviceId] }))
        : [{ ...base, vuln_id: opts.vulnId, scope, device_ids: ['finding', 'devices'].includes(scope) ? opts.devices.map(x => x.id) : [],
             tag_id: scope === 'tag' ? $('ex-tag').value : null }];
      submit.disabled = true;
      msg('Saving...');
      const problems = [];
      let done = 0;
      for (const body of items) {
        const r = await post(`${API}/exceptions`, body);
        if (r.ok) done += 1; else problems.push(r.error);
      }
      submit.disabled = false;
      if (problems.length && !done) return msg(esc(problems[0]), true);
      const what = opts.canDecide ? 'in effect now' : 'sent for approval';
      d.actions.innerHTML = '';
      d.actions.appendChild(button('Done', 'btn--primary', () => { d.close(); opts.onDone && opts.onDone(); }));
      d.body.innerHTML = `<div class="tk-note">${done} exception${done === 1 ? '' : 's'} ${what}.
        ${problems.length ? `<br>${problems.length} couldn't be saved: ${esc(problems[0])}` : ''}
        <br><a href="/exceptions">Open Exceptions</a></div>`;
    });
    d.actions.append(button('Cancel', 'btn--ghost', d.close), submit);
  }

  // Row selection with a "select all on this page" box in the header. Picks survive paging and searching.
  // opts: { mount, rows: () => current rows, picked: Map, entry: row => value, onChange }
  // Returns sync(), for the table's onLoad, which keeps the header box honest.
  function picker(opts) {
    const boxes = () => [...opts.mount.querySelectorAll('input[data-pick]')];
    const all = () => opts.mount.querySelector('input[data-pick-all]');
    const sync = () => {
      const b = boxes(), a = all();
      if (!a) return;
      const n = b.filter(x => x.checked).length;
      a.checked = !!b.length && n === b.length;
      a.indeterminate = n > 0 && n < b.length;
      a.disabled = !b.length;
    };
    const set = (box, on) => {
      const row = opts.rows().find(r => r.id === box.dataset.pick);
      box.checked = on;
      if (on && row) opts.picked.set(row.id, opts.entry(row));
      else opts.picked.delete(box.dataset.pick);
    };
    opts.mount.addEventListener('change', e => {
      if (e.target.matches('input[data-pick-all]')) boxes().forEach(b => set(b, e.target.checked));
      else if (e.target.matches('input[data-pick]')) set(e.target, e.target.checked);
      else return;
      sync();
      opts.onChange();
    });
    return sync;
  }
  const PICK_HEAD = '<input type="checkbox" data-pick-all aria-label="Select all on this page" title="Select all on this page">';

  window.CtemFindings = { proof, exceptionForm, post, picker, PICK_HEAD };
})();
