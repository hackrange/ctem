// Hunt > a finding > Suppress similar (api/routes/hunt_suppress.py): pick the signatures (detection, process and the
// process that started it) among the finding's alerts and accept them, narrowed to its hosts or exact files if wanted.
// Uses reg, api(), currentSource and showWatch() from hunt.js. Everything shown goes through esc().
(() => {
  const inDays = n => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);
  const box = document.createElement('div');
  box.className = 'modal-overlay';
  box.style.display = 'none';
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-modal', 'true');
  box.setAttribute('aria-labelledby', 'hs-title');
  box.innerHTML = `<div class="modal-box" style="max-width:760px"><div class="modal-header"><h2 class="modal-title" id="hs-title">Suppress similar</h2>
    <button type="button" class="modal-close" aria-label="Close">&times;</button></div><div class="modal-body" id="hs-body"></div></div>`;
  document.body.appendChild(box);
  const body = box.querySelector('#hs-body');
  const close = () => { box.style.display = 'none'; };
  box.addEventListener('click', e => { if (e.target === box || e.target.closest('.modal-close')) close(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && box.style.display !== 'none') close(); });

  const sigLine = s => `<b>${esc(s.detection)}</b>${s.process ? ` by <span class="text-mono">${esc(s.process)}</span>` : ''}${s.parent ? ` started by <span class="text-mono">${esc(s.parent)}</span>` : ''}
    <span class="text-muted">&middot; ${esc(s.alerts)} alert${s.alerts === 1 ? '' : 's'} on ${esc(s.hosts.length)} host${s.hosts.length === 1 ? '' : 's'}${s.source ? ` &middot; ${esc(s.source)}` : ''}${s.hashes.length ? ` &middot; ${esc(s.hashes.length)} file version${s.hashes.length === 1 ? '' : 's'}` : ''}</span>`;

  async function open(target) {
    const url = `${API}/hunt/suppress/${encodeURIComponent(target.source)}/${encodeURIComponent(target.issue)}`;
    box.style.display = 'flex';
    body.textContent = 'Loading...';
    let d;
    try { d = await api(url); } catch (e) { body.textContent = e.message; return; }
    if (!d.signatures.length) {
      body.innerHTML = '<p class="text-sm">This finding was raised from other evidence (not from alerts), so there is no alert signature to suppress.</p>';
      return;
    }
    body.innerHTML = `<p class="text-sm text-muted" style="margin:0 0 10px">Alerts with a ticked signature stop raising hunt, watch, hourly-check and SIEM
        findings. They stay in CTEM and in the tool, and show as Accepted. Any program can be given the same name, so keep it as narrow as you can.</p>
      <div style="display:grid;gap:8px;margin-bottom:12px">${d.signatures.map(s => `<label class="text-sm" style="display:flex;gap:8px;align-items:flex-start;overflow-wrap:anywhere">
        <input type="checkbox" data-sig="${esc(s.id)}"${d.signatures.length === 1 ? ' checked' : ''}> <span>${sigLine(s)}</span></label>`).join('')}</div>
      <div style="display:grid;gap:6px;margin-bottom:10px">
        <label class="text-sm"><input type="checkbox" id="hs-hosts"> Only on the hosts in this finding</label>
        <label class="text-sm"><input type="checkbox" id="hs-hash"> Only these exact files (by hash). Safest, but an update to the program brings the alerts back</label></div>
      <label class="text-sm">Why it's acceptable (at least 10 characters)
        <textarea id="hs-reason" class="form-input" rows="2" maxlength="1000" style="margin-top:4px" placeholder="For example: VS Code remote tunnels are approved for developers (change CHG0012345)"></textarea></label>
      <div style="display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin-top:8px">
        <label class="text-sm">Until<input id="hs-until" class="form-input" type="date" value="${inDays(90)}" min="${inDays(1)}" max="${inDays(366)}" style="margin-top:4px"></label>
        <button type="button" class="btn btn--primary btn--sm" id="hs-save">Suppress</button>
        <span id="hs-msg" class="text-sm" role="status"></span></div>`;
    body.querySelector('#hs-save').addEventListener('click', async () => {
      const msg = body.querySelector('#hs-msg');
      const picked = [...body.querySelectorAll('input[data-sig]:checked')].map(c => Number(c.dataset.sig));
      if (!picked.length) { msg.textContent = 'Tick at least one signature.'; return; }
      try {
        const r = await api(url, { method: 'POST', body: JSON.stringify({ signatures: picked, hosts_only: body.querySelector('#hs-hosts').checked,
          pin_hash: body.querySelector('#hs-hash').checked, reason: body.querySelector('#hs-reason').value.trim(), expires_on: body.querySelector('#hs-until').value }) });
        body.innerHTML = `<p class="text-sm">Suppressed: ${esc(r.created)} new accepted alert${r.created === 1 ? '' : 's'}${r.already ? ` (${esc(r.already)} already accepted)` : ''}.
          ${r.watch_removed ? `${esc(r.watch_removed)} watch finding${r.watch_removed === 1 ? ' is' : 's are'} gone now that all ${r.watch_removed === 1 ? 'its' : 'their'} alerts are accepted.` : 'New hunts leave these alerts out.'}
          Review or stop it any time from the alert's page in Cyber Threats.</p>`;
        if (target.source === 'watch' && typeof showWatch === 'function') showWatch();
      } catch (e) { msg.textContent = e.message; msg.style.color = 'var(--severity-critical)'; }
    });
  }

  document.addEventListener('click', e => {
    const b = e.target.closest('button[data-suppress]');
    if (b) open(reg[+b.dataset.suppress]);
  });
})();
