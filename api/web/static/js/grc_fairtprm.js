// GRC page: FairTPRM risk register, controls, evidence, and CTEM's control checks.
(() => {
  const BASE = '/api/v1/grc';
  const RESULT_CHIP = { pass: 'chip--low', warning: 'chip--medium', fail: 'chip--critical', error: 'chip--high' };
  const EFFECT_CHIP = { effective: 'chip--low', partially_effective: 'chip--medium', ineffective: 'chip--critical' };
  const label = s => esc(String(s || '--').replace(/_/g, ' '));
  const when = iso => iso ? new Date(iso).toLocaleString() : '--';
  const day = iso => iso ? new Date(iso).toLocaleDateString() : '--';
  const empty = (cols, text) => `<tr><td colspan="${cols}" class="text-muted text-sm" style="text-align:center;padding:16px">${text}</td></tr>`;

  async function get(path) {
    const res = await fetch(BASE + path, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(res.statusText);
    return res.json();
  }

  async function loadRisks() {
    const body = document.getElementById('risks-tbody');
    const driftOnly = document.getElementById('risk-drift-only').checked;
    try {
      const d = await get(`/risks${driftOnly ? '?drift_only=true' : ''}`);
      document.getElementById('risk-count').textContent = `${d.total} risks, ${d.drifting} drifting`;
      body.innerHTML = d.risks.map(r => `
        <tr${r.drift.length ? ' style="background:color-mix(in srgb, var(--severity-high) 8%, transparent)"' : ''}>
          <td class="text-sm"><b>${esc(r.risk_ref || '')}</b> ${esc(r.title)}
            ${r.vendor ? `<br><span class="text-muted" style="font-size:.75rem">Supplier: ${esc(r.vendor)}</span>` : ''}
            ${r.controls.length ? `<br><span class="text-muted" style="font-size:.75rem">Controls: ${r.controls.map(esc).join(', ')}</span>` : ''}</td>
          <td class="text-sm">${label(r.risk_category)}</td>
          <td class="text-sm">${r.inherent_risk_score ?? '--'}</td>
          <td class="text-sm">${r.residual_risk_score ?? '--'}</td>
          <td class="text-sm">${label(r.risk_treatment)}</td>
          <td class="text-sm">${label(r.status)}</td>
          <td class="text-sm">${r.drift.length ? r.drift.map(x => `<div>&bull; ${esc(x)}</div>`).join('') : '<span class="text-muted">--</span>'}</td>
        </tr>`).join('') || empty(7, driftOnly ? 'No drifting risks' : 'No risks yet. Connect FairTPRM under Settings &gt; Integrations.');
    } catch (_) {
      body.innerHTML = empty(7, 'Risk register unavailable');
    }
  }

  async function loadChecks() {
    const body = document.getElementById('checks-tbody');
    try {
      const d = await get('/overview');
      body.innerHTML = d.checks.map(c => `
        <tr>
          <td class="text-sm"><b>${esc(c.name)}</b><br><span class="text-muted" style="font-size:.75rem">${esc(c.check_type)}</span></td>
          <td class="text-sm">${c.result ? `<span class="chip ${RESULT_CHIP[c.result] || 'chip--info'}">${esc(c.result)}</span>
            <div class="text-muted" style="font-size:.75rem;margin-top:3px">${esc(c.summary || '')}</div>` : '<span class="text-muted">not run yet</span>'}</td>
          <td class="text-sm">${when(c.measured_at)}</td>
          <td class="text-sm">${c.used_by_fairtprm ? 'yes' : '<span class="text-muted">no</span>'}</td>
          <td class="text-sm" style="white-space:nowrap">
            <a href="${BASE}/checks/${encodeURIComponent(c.check_type)}/report?format=csv">CSV</a> &middot;
            <a href="${BASE}/checks/${encodeURIComponent(c.check_type)}/report?format=json">JSON</a></td>
        </tr>`).join('');
    } catch (_) {
      body.innerHTML = empty(5, 'Control checks unavailable');
    }
  }

  async function loadControls() {
    const body = document.getElementById('controls-tbody');
    try {
      const d = await get('/controls');
      document.getElementById('control-count').textContent = `${d.controls.length} controls`;
      body.innerHTML = d.controls.map(c => `
        <tr>
          <td class="text-sm"><b>${esc(c.control_ref || '')}</b> ${esc(c.title)}
            <br><span class="text-muted" style="font-size:.75rem">${c.frameworks.map(esc).join(', ')}</span></td>
          <td><span class="chip ${EFFECT_CHIP[c.effectiveness] || 'chip--info'}">${label(c.effectiveness || 'not_tested')}</span></td>
          <td class="text-sm">${c.ctem_checks.map(k => `${esc(k.check_type)}${k.result ? ` <span class="chip ${RESULT_CHIP[k.result] || 'chip--info'}">${esc(k.result)}</span>` : ''}`).join('<br>') || '<span class="text-muted">--</span>'}</td>
        </tr>`).join('') || empty(3, 'No controls yet');
    } catch (_) {
      body.innerHTML = empty(3, 'Controls unavailable');
    }
  }

  async function loadEvidence() {
    const body = document.getElementById('evidence-tbody');
    try {
      const d = await get('/evidence-status');
      document.getElementById('evidence-count').textContent = `${d.current} current, ${d.expiring_30d} expiring, ${d.expired} expired`;
      const rows = [...d.expired_items.map(e => ({ ...e, state: 'expired' })), ...d.expiring_items.map(e => ({ ...e, state: 'expiring' }))];
      body.innerHTML = rows.map(e => `
        <tr>
          <td class="text-sm"><b>${esc(e.evidence_ref || '')}</b> ${esc(e.title)}</td>
          <td class="text-sm">${label(e.evidence_type)}</td>
          <td class="text-sm"><span class="chip ${e.state === 'expired' ? 'chip--critical' : 'chip--medium'}">${day(e.valid_until)}</span></td>
        </tr>`).join('') || empty(3, d.total ? 'All evidence is current' : 'No evidence yet');
    } catch (_) {
      body.innerHTML = empty(3, 'Evidence status unavailable');
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('risk-drift-only').addEventListener('change', loadRisks);
    loadRisks();
    loadChecks();
    loadControls();
    loadEvidence();
  });
})();

// Admin: issue the token FairTPRM's monitors use (shown once)
(() => {
  const btn = document.getElementById('fairtprm-token-btn');
  if (!btn) return;
  const modal = document.getElementById('ftok-modal');
  const err = document.getElementById('ftok-error');
  const out = document.getElementById('ftok-result');
  btn.addEventListener('click', () => {
    err.style.display = out.style.display = 'none';
    out.innerHTML = '';
    modal.style.display = 'flex';
  });
  document.getElementById('ftok-close').addEventListener('click', () => {
    out.innerHTML = '';  // don't leave the token sitting in the page
    modal.style.display = 'none';
  });
  document.getElementById('ftok-create').addEventListener('click', async () => {
    err.style.display = 'none';
    const ips = document.getElementById('ftok-ips').value.split(',').map(s => s.trim()).filter(Boolean);
    try {
      const res = await fetch('/api/v1/grc/fairtprm-token', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ allowed_ips: ips }),
      });
      const d = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'Enter the FairTPRM server address(es)');
      out.innerHTML = `<div style="margin-bottom:6px">In FairTPRM, add an <b>open-ctem</b> integration with:</div>
        <div>CTEM URL: <code>${esc(d.ctem_url || window.location.origin)}</code></div>
        <div style="margin-top:4px">API token: <code style="word-break:break-all">${esc(d.token)}</code></div>
        <div class="text-muted" style="margin-top:6px">Shown once. Expires ${esc(new Date(d.expires_at).toLocaleDateString())}.</div>`;
      out.style.display = 'block';
    } catch (e) {
      err.textContent = e.message;
      err.style.display = 'block';
    }
  });
})();
