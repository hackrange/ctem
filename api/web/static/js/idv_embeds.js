// IDV page > Iframe Code (admins): where the caller verification panel may be shown. Make one (site, server and
// analyst network ranges), copy the ServiceNow code and its token (shown once), or revoke one, which turns its token
// off and ends its open panels. Everything shown goes through esc(); the code is put in a <textarea> as text.
(() => {
  const open = document.getElementById('idv-embeds-open');
  if (!open) return;
  const API = '/api/v1/idv/desk/embeds';
  let dlg;

  async function call(url, opts = {}) {
    const r = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, ...opts });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) {
      const det = Array.isArray(d.detail) ? d.detail.map(x => String(x.msg || '').replace(/^Value error, /, '')).join('; ') : d.detail;
      throw new Error(typeof det === 'string' && det ? det : 'That did not go through.');
    }
    return d;
  }
  const lines = v => v.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
  const day = s => (s ? new Date(s).toLocaleString() : '--');

  // The UI Macro ServiceNow developers paste: its server part asks CTEM for a one-time panel link with the token kept
  // in a ServiceNow property, then shows the panel. Phase 2 (g2/j2, $[...]) so every form render starts its own
  // session; ServiceNow caches phase 1 output, which would hand one analyst's panel to the next.
  const macro = base => `<?xml version="1.0" encoding="utf-8" ?>
<j:jelly trim="false" xmlns:j="jelly:core" xmlns:g="glide" xmlns:j2="null" xmlns:g2="null">
<g2:evaluate var="jvar_ctem_src" jelly="true">
  var src = '';
  try {
    var r = new sn_ws.RESTMessageV2();
    r.setEndpoint('${base}/api/v1/idv/desk/sessions');
    r.setHttpMethod('POST');
    r.setRequestHeader('Authorization', 'Bearer ' + gs.getProperty('x_ctem.idv_desk_token'));
    r.setRequestHeader('Content-Type', 'application/json');
    r.setRequestHeader('Accept', 'application/json');
    r.setHttpTimeout(10000);
    var caller = current.caller_id.nil() ? '' : String(current.caller_id.user_name);
    r.setRequestBody(JSON.stringify({ ticket: String(current.number), analyst: String(gs.getUserName()), caller: caller }));
    var resp = r.execute();
    if (resp.getStatusCode() == 200) {
      src = '${base}' + JSON.parse(resp.getBody()).launch_path;
    } else {
      gs.warn('CTEM caller verification: HTTP ' + resp.getStatusCode());
    }
  } catch (e) {
    gs.warn('CTEM caller verification: ' + e);
  }
  src;
</g2:evaluate>
<j2:if test="$[jvar_ctem_src != '']">
  <iframe src="$[jvar_ctem_src]" title="Caller verification" width="100%" height="560" frameborder="0"
          sandbox="allow-scripts allow-same-origin" referrerpolicy="no-referrer"></iframe>
</j2:if>
<j2:if test="$[jvar_ctem_src == '']">
  <div>Caller verification is unavailable right now. Contact the security team.</div>
</j2:if>
</j:jelly>`;

  const steps = (e, base) => `In ServiceNow (an admin, about 10 minutes):

1. System Properties > New
   Name: x_ctem.idv_desk_token     Type: password2
   Value: the token shown above (CTEM shows it only once)
   Read roles: admin               Write roles: admin

2. System UI > UI Macros > New
   Name: ctem_caller_verification
   XML: paste the code below, as it is

3. System UI > Formatters > New
   Name: Caller verification       Formatter: ctem_caller_verification.xml       Table: Incident [incident]

4. Open an incident > Configure > Form Layout: add "Caller verification" where the panel should show. Save.

5. Check: open an incident as a service desk analyst from the office network. The panel appears and finds the
   ticket's caller. If it says "unavailable", the server addresses or the token are off: System Logs > Warnings,
   search "CTEM caller verification".

This embed works only:
  - inside ${e.frame_origin}
  - when ServiceNow calls from: ${(e.server_ips || []).join(', ')}
  - for analysts browsing from: ${(e.client_ips || []).join(', ')}
CTEM address used in the code: ${base}`;

  function modal() {
    if (dlg) return dlg;
    dlg = document.createElement('dialog');
    dlg.className = 'modal modal--wide';
    dlg.setAttribute('aria-labelledby', 'emb-title');
    dlg.innerHTML = `<div style="padding:16px 24px;max-height:90vh;overflow:auto">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <h2 id="emb-title" class="panel__title" style="margin:0">Caller verification in the service desk</h2>
        <button type="button" class="btn btn--ghost btn--sm" data-close aria-label="Close">&#10005;</button></div>
      <p class="text-sm text-muted" style="margin:6px 0 10px">Each embed lets one service desk site show the caller verification panel in its tickets.
        It works only inside that exact site, only when the site's servers call from their address ranges with the embed's token,
        and only for analysts on the networks you list. Revoke one and its token and open panels stop at once.</p>
      <div id="emb-list"></div>
      <h3 class="text-sm" style="margin:16px 0 6px;text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted)">New embed</h3>
      <form id="emb-form" style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
        <label class="text-sm">Name<input class="form-input" name="name" maxlength="80" placeholder="ServiceNow production" required style="width:100%"></label>
        <label class="text-sm">Service desk site (exact)<input class="form-input" name="frame_origin" maxlength="256" placeholder="https://acme.service-now.com" required style="width:100%"></label>
        <label class="text-sm">Service desk server addresses (its outbound IPs or CIDRs)
          <textarea class="form-input" name="server_ips" rows="3" placeholder="203.0.113.0/24" required style="width:100%"></textarea></label>
        <label class="text-sm">Analysts' network ranges (office and VPN egress)
          <textarea class="form-input" name="client_ips" rows="3" placeholder="198.51.100.0/24" required style="width:100%"></textarea></label>
        <label class="text-sm">Token valid for
          <select class="filter-select" name="expires_in_days" style="width:100%"><option value="90">90 days</option><option value="180">180 days</option>
            <option value="365" selected>1 year</option><option value="730">2 years</option></select></label>
        <div style="display:flex;align-items:flex-end;gap:8px"><button type="submit" class="btn btn--primary btn--sm">Create and show the code</button>
          <span id="emb-msg" class="text-sm" role="status"></span></div>
      </form>
      <div id="emb-code" hidden style="margin-top:14px"></div>
    </div>`;
    dlg.addEventListener('click', async e => {
      if (e.target === dlg || e.target.closest('[data-close]')) { dlg.close(); return; }
      const rv = e.target.closest('[data-revoke]');
      if (rv) {
        if (!confirm(`Revoke "${rv.dataset.name}"? Its token stops working and any open caller verification panels end now. This can't be undone; make a new embed to restore it.`)) return;
        try { await call(`${API}/${encodeURIComponent(rv.dataset.revoke)}/revoke`, { method: 'POST' }); await list(); } catch (err) { alert(err.message); }
      }
      const cp = e.target.closest('[data-copy]');
      if (cp) {
        const ta = dlg.querySelector(`#${cp.dataset.copy}`);
        ta.select();
        try { await navigator.clipboard.writeText(ta.value); cp.textContent = 'Copied'; } catch (err) { document.execCommand('copy'); cp.textContent = 'Copied'; }
      }
    });
    dlg.querySelector('#emb-form').addEventListener('submit', async e => {
      e.preventDefault();
      const f = new FormData(e.target), msg = dlg.querySelector('#emb-msg');
      msg.style.color = 'var(--text-muted)';
      msg.textContent = 'Creating...';
      try {
        const d = await call(API, { method: 'POST', body: JSON.stringify({ name: f.get('name').trim(), frame_origin: f.get('frame_origin').trim(),
          server_ips: lines(f.get('server_ips')), client_ips: lines(f.get('client_ips')), expires_in_days: Number(f.get('expires_in_days')) }) });
        msg.textContent = '';
        e.target.reset();
        showCode(d);
        await list();
      } catch (err) { msg.style.color = 'var(--severity-critical)'; msg.textContent = err.message; }
    });
    document.body.appendChild(dlg);
    return dlg;
  }

  function showCode(d) {
    const box = dlg.querySelector('#emb-code'), base = location.origin;
    box.hidden = false;
    box.innerHTML = `<div style="padding:10px 12px;border:1px solid var(--severity-high);border-radius:6px">
      <p class="text-sm" style="margin:0 0 6px"><b>Token for "${esc(d.name)}"</b>: copy it now, CTEM won't show it again.</p>
      <div style="display:flex;gap:6px"><input id="emb-token" class="form-input text-mono" readonly style="flex:1"><button type="button" class="btn btn--ghost btn--sm" data-copy="emb-token">Copy token</button></div></div>
      <h3 class="text-sm" style="margin:12px 0 4px">Steps for the ServiceNow admin</h3>
      <textarea id="emb-steps" class="form-input text-mono" rows="14" readonly style="width:100%;font-size:12px"></textarea>
      <div style="display:flex;justify-content:space-between;align-items:center;margin:10px 0 4px"><h3 class="text-sm" style="margin:0">UI Macro code (paste as is)</h3>
        <button type="button" class="btn btn--ghost btn--sm" data-copy="emb-macro">Copy code</button></div>
      <textarea id="emb-macro" class="form-input text-mono" rows="16" readonly style="width:100%;font-size:12px"></textarea>`;
    box.querySelector('#emb-token').value = d.token;
    box.querySelector('#emb-steps').value = steps(d, base);
    box.querySelector('#emb-macro').value = macro(base);
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function list() {
    const box = dlg.querySelector('#emb-list');
    try {
      const d = await call(API);
      box.innerHTML = d.embeds.length ? `<table class="data-table" style="width:100%;font-size:13px"><thead><tr><th>Name</th><th>Site</th>
        <th>Server ranges</th><th>Analyst ranges</th><th>Panels opened</th><th>Last used</th><th>Token expires</th><th></th></tr></thead><tbody>${
        d.embeds.map(e => `<tr${e.active ? '' : ' style="opacity:.55"'}><td><b>${esc(e.name)}</b><div class="text-muted">by ${esc(e.created_by || '')}, ${esc(day(e.created_at))}</div></td>
          <td class="text-mono">${esc(e.frame_origin)}</td><td class="text-mono">${esc(e.server_ips.join(', '))}</td><td class="text-mono">${esc(e.client_ips.join(', '))}</td>
          <td>${esc(e.sessions)}</td><td>${esc(day(e.last_used))}</td><td>${esc(day(e.expires_at))}</td>
          <td>${e.active ? `<button type="button" class="btn btn--danger btn--sm" data-revoke="${esc(e.id)}" data-name="${esc(e.name)}">Revoke</button>`
            : `<span class="chip chip--info" style="font-size:.7rem">Revoked ${esc(day(e.revoked_at))}</span>`}</td></tr>`).join('')}</tbody></table>`
        : '<p class="text-sm text-muted">No embeds yet. Make one below.</p>';
    } catch (err) { box.textContent = err.message; }
  }

  open.addEventListener('click', () => { const m = modal(); m.querySelector('#emb-code').hidden = true; list(); m.showModal(); });
})();
