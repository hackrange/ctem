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

  let canEdit = false, risksById = {};
  const STATUSES = ['identified', 'assessing', 'treating', 'monitoring', 'closed'];

  // Status, review date and treatment plan go to FairTPRM; everything else is edited there
  function editorRow(r) {
    const opts = STATUSES.map(s => `<option value="${s}"${s === r.status ? ' selected' : ''}>${label(s)}</option>`).join('');
    return `<tr class="risk-editor" data-for="${esc(r.id)}"><td colspan="7" style="background:var(--surface2)">
      <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end">
        <label class="text-sm">Status<br><select class="filter-select" data-f="status">${opts}</select></label>
        <label class="text-sm">Review date<br><input type="date" class="input" data-f="review_date" value="${esc(r.review_date || '')}"></label>
        <label class="text-sm" style="flex:1;min-width:240px">Treatment plan<br>
          <textarea class="input" data-f="treatment_plan" rows="2" maxlength="10000" style="width:100%;resize:vertical">${esc(r.treatment_plan || '')}</textarea></label>
        <button type="button" class="btn btn--primary btn--sm" data-risk-save="${esc(r.id)}">Save to FairTPRM</button>
        <button type="button" class="btn btn--ghost btn--sm" data-risk-cancel>Cancel</button>
      </div>
      <div class="text-sm" data-msg style="margin-top:6px"></div>
      <div class="text-muted" style="font-size:.75rem;margin-top:4px">Likelihood, impact, owner and controls are edited in FairTPRM.</div>
    </td></tr>`;
  }

  async function saveRisk(id, box) {
    const msg = box.querySelector('[data-msg]');
    const v = f => box.querySelector(`[data-f="${f}"]`).value;
    const body = { status: v('status'), treatment_plan: v('treatment_plan') };
    if (v('review_date')) body.review_date = v('review_date'); else body.clear_review_date = true;
    msg.textContent = 'Saving...';
    try {
      const res = await fetch(`${BASE}/risks/${encodeURIComponent(id)}/review`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
      if (res.status === 403) throw new Error('You need GRC write access to edit risks.');
      if (!res.ok) throw new Error('Check the values and try again.');
      const d = await res.json();
      if (!d.saved) throw new Error(d.message || 'FairTPRM did not accept the change.');
      loadRisks();
    } catch (e) {
      msg.style.color = 'var(--severity-critical)';
      msg.textContent = e.message;
    }
  }

  async function loadRisks() {
    const body = document.getElementById('risks-tbody');
    const driftOnly = document.getElementById('risk-drift-only').checked;
    try {
      const d = await get(`/risks${driftOnly ? '?drift_only=true' : ''}`);
      canEdit = !!d.can_edit;
      risksById = Object.fromEntries(d.risks.map(r => [r.id, r]));
      document.getElementById('risk-count').textContent = `${d.total} risks, ${d.drifting} drifting`;
      body.innerHTML = d.risks.map(r => `
        <tr${r.drift.length ? ' class="row-flag" title="Risk drift"' : ''}>
          <td class="text-sm"><b>${esc(r.risk_ref || '')}</b> ${esc(r.title)}
            ${r.vendor ? `<br><span class="text-muted" style="font-size:.75rem">Supplier: ${esc(r.vendor)}</span>` : ''}
            ${r.controls.length ? `<br><span class="text-muted" style="font-size:.75rem">Controls: ${r.controls.map(esc).join(', ')}</span>` : ''}</td>
          <td class="text-sm">${label(r.risk_category)}</td>
          <td class="text-sm">${r.inherent_risk_score ?? '--'}</td>
          <td class="text-sm">${r.residual_risk_score ?? '--'}</td>
          <td class="text-sm">${label(r.risk_treatment)}</td>
          <td class="text-sm">${label(r.status)}${r.review_date ? `<br><span class="text-muted" style="font-size:.75rem">review ${day(r.review_date)}</span>` : ''}
            ${canEdit ? `<br><button type="button" class="btn-link" data-risk-edit="${esc(r.id)}">(edit)</button>` : ''}</td>
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
        <tr data-href="/grc/checks/${encodeURIComponent(c.check_type)}" style="cursor:pointer" title="Show what to remediate">
          <td class="text-sm"><b><a class="dt-link" href="/grc/checks/${encodeURIComponent(c.check_type)}">${esc(c.name)}</a></b>${c.custom ? ' <span class="chip chip--info" title="Created from a curated rule">custom</span>' : ''}<br><span class="text-muted" style="font-size:.75rem">${esc(c.check_type)}</span></td>
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
  // a click anywhere on a check row opens its remediation list (links inside the row keep their own target)
  document.addEventListener('click', e => {
    const tr = e.target.closest('#checks-tbody tr[data-href]');
    if (tr && !e.target.closest('a,button')) location.href = tr.dataset.href;
  });

  async function loadControls() {
    const body = document.getElementById('controls-tbody');
    try {
      const d = await get('/controls');
      document.getElementById('control-count').textContent = `${d.controls.length} controls`;
      body.innerHTML = d.controls.map(c => `
        <tr data-control="${esc(c.id)}" style="cursor:pointer" title="Open to test this control">
          <td class="text-sm"><a class="dt-link" href="#" data-control-open="${esc(c.id)}"><b>${esc(c.control_ref || '')}</b> ${esc(c.title)}</a>
            <br><span class="text-muted" style="font-size:.75rem">${c.frameworks.map(esc).join(', ')}</span></td>
          <td><span class="chip ${EFFECT_CHIP[c.effectiveness] || 'chip--info'}">${label(c.effectiveness || 'not_tested')}</span></td>
          <td class="text-sm">${window.GrcTests ? GrcTests.cell(c.testing) : ''}</td>
          <td class="text-sm">${c.ctem_checks.map(k => `${esc(k.check_type)}${k.result ? ` <span class="chip ${RESULT_CHIP[k.result] || 'chip--info'}">${esc(k.result)}</span>` : ''}`).join('<br>') || '<span class="text-muted">--</span>'}</td>
        </tr>`).join('') || empty(4, 'No controls yet');
    } catch (_) {
      body.innerHTML = empty(4, 'Controls unavailable');
    }
  }

  document.addEventListener('ctem:controls-changed', () => loadControls());   // a test or the testing rules changed

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
    document.getElementById('risks-tbody').addEventListener('click', e => {
      const ed = e.target.closest('[data-risk-edit]'), sv = e.target.closest('[data-risk-save]');
      if (ed) {
        const tr = ed.closest('tr'), open = tr.nextElementSibling;
        if (open && open.classList.contains('risk-editor')) { open.remove(); return; }
        tr.insertAdjacentHTML('afterend', editorRow(risksById[ed.dataset.riskEdit]));
      } else if (sv) {
        saveRisk(sv.dataset.riskSave, sv.closest('tr'));
      } else if (e.target.closest('[data-risk-cancel]')) {
        e.target.closest('tr').remove();
      }
    });
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
