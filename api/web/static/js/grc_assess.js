// GRC page: FairTPRM assessment results and audits. Shared renderers live on window.GrcAssess.
(() => {
  const BASE = '/api/v1/grc';
  const label = s => esc(String(s || '--').replace(/_/g, ' '));
  const day = iso => iso ? esc(new Date(iso + (iso.length === 10 ? 'T00:00:00' : '')).toLocaleDateString()) : '--';
  const empty = (cols, text) => `<tr><td colspan="${cols}" class="text-muted text-sm" style="text-align:center;padding:16px">${text}</td></tr>`;
  const STATUS = { completed: 'chip--low', in_progress: 'chip--medium', under_review: 'chip--medium', draft: 'chip--info',
                   archived: 'chip--info', planning: 'chip--info', fieldwork: 'chip--medium', reporting: 'chip--medium',
                   remediation: 'chip--high', closed: 'chip--low', open: 'chip--high', in_remediation: 'chip--medium',
                   remediated: 'chip--low', verified_closed: 'chip--low', risk_accepted: 'chip--info' };
  const SEV = { critical: 'chip--critical', high: 'chip--high', medium: 'chip--medium', low: 'chip--low', informational: 'chip--info' };
  const chip = (s, map = STATUS) => s ? `<span class="chip ${map[s] || 'chip--info'}">${label(s)}</span>` : '<span class="text-muted">--</span>';

  // FairScore runs 1-4; color it like the rest of the page (green good, red bad)
  const tone = (v, good, ok) => v == null ? 'var(--fg-muted)' : v >= good ? 'var(--severity-low)' : v >= ok ? 'var(--severity-medium)' : 'var(--severity-critical)';
  const score = v => v == null ? '<span class="text-muted">--</span>' : `<b style="color:${tone(v, 3, 2)}">${Number(v).toFixed(2)}</b><span class="text-muted"> / 4</span>`;
  const pct = v => v == null ? '<span class="text-muted">--</span>' : `<b style="color:${tone(v, 80, 60)}">${Number(v).toFixed(0)}%</b>`;
  const bar = (v, max, target) => {
    const w = v == null ? 0 : Math.max(0, Math.min(100, v / max * 100));
    const t = target == null ? '' : `<div title="Target ${esc(Number(target).toFixed(2))}" style="position:absolute;top:-3px;bottom:-3px;left:${Math.min(100, target / max * 100)}%;width:2px;background:var(--fg)"></div>`;
    return `<div style="position:relative;height:6px;background:var(--border);border-radius:3px;min-width:80px">
      <div style="height:100%;width:${w}%;border-radius:3px;background:${tone(v, max === 4 ? 3 : 80, max === 4 ? 2 : 60)}"></div>${t}</div>`;
  };
  const href = a => `/grc/assessments/${encodeURIComponent(a.id)}`;

  function domainsTable(rows) {
    if (!rows.length) return '<p class="text-muted text-sm" style="margin:0">No domain scores yet.</p>';
    return `<div class="dt-scroll"><table class="data-table">
      <thead><tr><th>Domain</th><th style="min-width:140px">FairScore vs target</th><th>Score</th><th>Conforming</th><th>Partial</th><th>Non-conforming</th><th>Answered</th></tr></thead>
      <tbody>${rows.map(d => `<tr>
        <td class="text-sm"><b>${esc(d.code || '')}</b> ${esc(d.name || '')}</td>
        <td>${bar(d.score, 4, d.target)}</td>
        <td class="text-sm" style="white-space:nowrap">${score(d.score)}${d.target != null ? `<span class="text-muted text-sm"> (target ${esc(Number(d.target).toFixed(2))})</span>` : ''}</td>
        <td class="text-sm">${esc(d.conforming_count)}</td>
        <td class="text-sm">${esc(d.partial_count)}</td>
        <td class="text-sm">${d.non_conforming_count ? `<b style="color:var(--severity-critical)">${esc(d.non_conforming_count)}</b>` : '0'}</td>
        <td class="text-sm">${esc(d.questions_answered)}/${esc(d.questions_total)}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function frameworksGrid(rows) {
    rows = rows.filter(f => f.total_mapped);
    if (!rows.length) return '';
    return `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;margin-top:14px">${rows.map(f => `
      <div style="border:1px solid var(--border);border-radius:6px;padding:10px 12px">
        <div class="text-sm" style="font-weight:700;margin-bottom:6px" title="${esc(f.name || '')}">${esc(f.code || f.name || '')}</div>
        ${bar(f.compliance_pct, 100)}
        <div class="text-sm" style="display:flex;justify-content:space-between;margin-top:6px">
          <span class="text-muted">${esc(f.conforming)} ok &middot; ${esc(f.partial)} partial &middot; ${esc(f.non_conforming)} gaps</span>${pct(f.compliance_pct)}</div>
      </div>`).join('')}</div>`;
  }

  function stat(name, html) {
    return `<div><div class="text-muted text-sm">${esc(name)}</div><div style="font-size:1.25rem;margin-top:2px">${html}</div></div>`;
  }

  function latestPanel(a) {
    const p = a.progress || {};
    return `<div style="display:flex;flex-wrap:wrap;gap:28px;margin-bottom:14px">
        ${stat('FairScore', score(a.fairscore))}
        ${stat('Compliance', pct(a.compliance_pct))}
        ${stat('Answered', `${esc(p.answered ?? 0)}<span class="text-muted">/${esc(p.total_questions ?? 0)}</span>`)}
        ${stat('Non-conforming', `<b style="color:${a.non_conforming ? 'var(--severity-critical)' : 'inherit'}">${esc(a.non_conforming)}</b>`)}
        ${stat('Partial', esc(a.partial))}
      </div>${domainsTable(a.domain_scores || [])}`;
  }

  // The assessment's per-framework results lead the page (they replace FairTPRM's all-zero requirement tracker)
  function topFrameworks(a) {
    const row = document.getElementById('compliance-row');
    const html = frameworksGrid(a.framework_compliance || []);
    if (!row || !html) return;
    row.dataset.src = 'assessment';
    row.style.display = 'block';
    row.innerHTML = html.replace('margin-top:14px', 'margin-top:0');
    const head = document.getElementById('compliance-head');
    head.innerHTML = `Compliance by framework, from the latest assessment: <a class="dt-link" href="${href(a)}">${esc(a.ref || '')} ${esc(a.title)}</a>`;
    head.hidden = false;
  }

  async function load() {
    const latest = document.getElementById('assess-latest');
    if (!latest) return;
    try {
      const res = await fetch(`${BASE}/assessments`, { headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error(res.status);
      const d = await res.json();
      const items = d.assessments || [];
      document.getElementById('assess-count').textContent = items.length ? `${items.length} total` : '';
      if (d.latest) {
        document.getElementById('assess-latest-label').innerHTML =
          `Latest: <a class="dt-link" href="${href(d.latest)}">${esc(d.latest.ref || '')} ${esc(d.latest.title)}</a> ${chip(d.latest.status)}`;
        latest.innerHTML = latestPanel(d.latest);
        topFrameworks(d.latest);
      } else {
        latest.innerHTML = `<p class="text-muted text-sm" style="margin:0">${d.available
          ? 'No assessments in FairTPRM yet.'
          : 'Your FairTPRM doesn\'t share assessment results yet. Update FairTPRM to a version with <code>GET /api/v2/grc/assessments</code>; the next sync pulls them in.'}</p>`;
      }
      document.getElementById('assess-tbody').innerHTML = items.map(a => `<tr data-href="${esc(href(a))}" style="cursor:pointer">
          <td class="text-sm"><a class="dt-link" href="${esc(href(a))}"><b>${esc(a.ref || '')}</b> ${esc(a.title)}</a>
            <br><span class="text-muted" style="font-size:.75rem">${label(a.type)}${a.completed ? ` &middot; completed ${day(a.completed)}` : ''}</span></td>
          <td>${chip(a.status)}</td>
          <td class="text-sm" style="white-space:nowrap">${score(a.fairscore)}</td>
          <td class="text-sm">${pct(a.compliance_pct)}</td>
          <td class="text-sm">${a.non_conforming || a.partial ? `<b style="color:var(--severity-critical)">${esc(a.non_conforming)}</b> / ${esc(a.partial)} partial` : '<span class="text-muted">none</span>'}</td>
        </tr>`).join('') || empty(5, d.available ? 'No assessments yet' : 'Needs a FairTPRM update');
    } catch (_) {
      latest.innerHTML = '<p class="text-muted text-sm" style="margin:0">Assessment results unavailable.</p>';
      document.getElementById('assess-tbody').innerHTML = empty(5, 'Unavailable');
    }
    try {
      const res = await fetch(`${BASE}/audits`, { headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error(res.status);
      const audits = (await res.json()).audits || [];
      document.getElementById('audit-count').textContent = audits.length ? `${audits.length} total` : '';
      document.getElementById('audit-tbody').innerHTML = audits.map((a, i) => `<tr>
          <td class="text-sm"><b>${esc(a.ref || '')}</b> ${esc(a.title)}
            <br><span class="text-muted" style="font-size:.75rem">${label(a.type)}${a.framework ? ` &middot; ${esc(a.framework)}` : ''}${a.firm ? ` &middot; ${esc(a.firm)}` : ''}</span>
            ${(a.findings || []).length ? `<details style="margin-top:4px"><summary class="text-sm" style="cursor:pointer">Findings</summary>
              ${a.findings.map(f => `<div class="text-sm" style="margin-top:4px">${chip(f.severity, SEV)} ${chip(f.status)} <b>${esc(f.ref || '')}</b> ${esc(f.title || '')}${f.due_date ? ` <span class="text-muted">due ${day(f.due_date)}</span>` : ''}</div>`).join('')}</details>` : ''}</td>
          <td>${chip(a.status)}</td>
          <td class="text-sm">${esc(a.findings_count)}${a.critical_findings ? ` <span class="chip chip--critical">${esc(a.critical_findings)} critical</span>` : ''}${a.open_findings ? `<br><span class="text-muted" style="font-size:.75rem">${esc(a.open_findings)} open</span>` : ''}</td>
          <td class="text-sm" style="white-space:nowrap">${day(a.planned_start)} &ndash; ${day(a.completed || a.planned_end)}${a.certification_valid_until ? `<br><span class="text-muted" style="font-size:.75rem">cert until ${day(a.certification_valid_until)}</span>` : ''}</td>
        </tr>`).join('') || empty(4, 'No audits in FairTPRM yet');
    } catch (_) {
      document.getElementById('audit-tbody').innerHTML = empty(4, 'Audits unavailable');
    }
  }

  document.addEventListener('click', e => {
    if (e.target.closest('a,button,summary,details')) return;
    const tr = e.target.closest('#assess-tbody tr[data-href]');
    if (tr) location.href = tr.dataset.href;
  });
  document.addEventListener('DOMContentLoaded', load);
  window.GrcAssess = { chip, score, pct, label, day, domainsTable, frameworksGrid, latestPanel, SEV };
})();
