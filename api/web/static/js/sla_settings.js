// Vulnerabilities > Change SLAs (admins): days to fix by severity, for the whole install. The dialog closes only
// from its own buttons. Everything shown goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const SEV = [['critical', 'Critical', 'CVSS 9.0+'], ['high', 'High', 'CVSS 7.0-8.9'], ['medium', 'Medium', 'CVSS 4.0-6.9'], ['low', 'Low', 'below 4.0']];
  let info = null;

  async function call(method, body) {
    const r = await fetch('/api/v1/sla', { method, headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                                           body: body ? JSON.stringify(body) : undefined });
    if (r.status === 422) return { ok: false, error: `Each SLA is a whole number of days from ${info.limits[0]} to ${info.limits[1]}.` };
    if (!r.ok) return { ok: false, error: r.status === 401 ? 'Your sign-in has expired. Sign in again.' : 'Could not save the SLAs.' };
    return r.json();
  }

  function open() {
    let wrap = $('sla-dialog');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'sla-dialog';
      wrap.className = 'tk-backdrop';
      wrap.setAttribute('role', 'dialog');
      wrap.setAttribute('aria-modal', 'true');
      wrap.setAttribute('aria-labelledby', 'sla-title');
      document.body.appendChild(wrap);
    }
    const cur = info.sla_days, def = info.defaults;
    wrap.innerHTML = `<div class="tk-dialog" style="max-width:520px">
        <h2 class="tk-title" id="sla-title">Change SLAs</h2>
        <p class="tk-sub">Days to fix an open finding, by severity, from when it was first found. Used everywhere:
          age colors and past-SLA flags, the Vulnerability Dashboard, and the remediation SLA control check.</p>
        <div style="display:grid;grid-template-columns:auto 110px auto;gap:10px 12px;align-items:center;margin:12px 0">
          ${SEV.map(([k, label, hint]) => `<label for="sla-${k}"><b>${label}</b> <span class="text-sm text-muted">${hint}</span></label>
            <input id="sla-${k}" class="form-input" type="number" inputmode="numeric" min="${info.limits[0]}" max="${info.limits[1]}" step="1" value="${esc(cur[k])}" required>
            <span class="text-sm text-muted">days${cur[k] !== def[k] ? ` (default ${esc(def[k])})` : ''}</span>`).join('')}
        </div>
        <p class="text-sm text-muted" style="margin:0">Shorter SLAs flag more findings at once. A curated rule that sets the control check's own days still wins for that check.</p>
        <p id="sla-msg" class="text-sm" role="status" style="min-height:1.2em;margin:8px 0 0"></p>
        <div style="display:flex;gap:8px;justify-content:space-between;margin-top:12px">
          <button type="button" class="btn btn--ghost btn--sm" id="sla-reset">Use defaults</button>
          <span style="display:flex;gap:8px"><button type="button" class="btn btn--ghost btn--sm" id="sla-cancel">Cancel</button>
            <button type="button" class="btn btn--primary btn--sm" id="sla-save">Save</button></span>
        </div></div>`;
    wrap.classList.add('is-open');
    $('sla-critical').focus();
    const close = () => wrap.classList.remove('is-open');
    $('sla-cancel').onclick = close;
    $('sla-reset').onclick = () => SEV.forEach(([k]) => { $(`sla-${k}`).value = def[k]; });
    $('sla-save').onclick = async () => {
      const body = {};
      for (const [k, label] of SEV) {
        const v = Number($(`sla-${k}`).value);
        if (!Number.isInteger(v) || v < info.limits[0] || v > info.limits[1]) {
          $('sla-msg').textContent = `${label}: a whole number of days from ${info.limits[0]} to ${info.limits[1]}.`;
          return;
        }
        body[k] = v;
      }
      if (!(body.critical <= body.high && body.high <= body.medium && body.medium <= body.low)) {
        $('sla-msg').textContent = 'Each SLA must be no longer than the next lower severity’s (critical, then high, medium, low).';
        return;
      }
      const btn = $('sla-save');
      btn.disabled = true;
      btn.textContent = 'Saving...';
      const r = await call('PUT', body);
      btn.disabled = false;
      btn.textContent = 'Save';
      if (!r.ok) { $('sla-msg').textContent = r.error || 'Could not save the SLAs.'; return; }
      info.sla_days = r.sla_days;
      close();
      if (typeof toast === 'function') toast('SLAs saved. Ages and past-SLA counts now use them.', 'success');
      document.dispatchEvent(new CustomEvent('ctem:sla-changed'));
    };
  }

  document.addEventListener('DOMContentLoaded', async () => {
    const btn = $('vl-sla');
    if (!btn) return;
    try {
      info = await call('GET');
    } catch (e) { info = null; }
    if (!info || !info.sla_days) return;
    btn.title = SEV.map(([k, l]) => `${l} ${info.sla_days[k]} days`).join(', ');
    btn.hidden = !info.can_edit;   // the server enforces it too
    btn.addEventListener('click', open);
  });
})();
