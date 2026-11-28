// Why this grade: a link beside the grade that opens a modal with two tables, what decreases the risk and what
// increases it, from the scoring engine's reasons for the worst finding, so the page header stays small.
// Every reason carries its effect ("(+30%)", "(-50%)") or a value to judge ("Likelihood 72.0%: ..."). Everything
// shown goes through esc().
window.ScoreWhy = (() => {
  let dlg;
  const cap = s => s.charAt(0).toUpperCase() + s.slice(1);

  // One reason as {side, factor, detail, effect}: side "up" raises the risk, "down" lowers it
  function sort(text) {
    const s = String(text || '').trim();
    let m = s.match(/^(Likelihood|Reachability|Impact) ([0-9.]+)%: (.*)$/);
    if (m) {
      const v = parseFloat(m[2]);
      return { side: v >= 50 ? 'up' : 'down', factor: m[1], detail: cap(m[3]), effect: `${Math.round(v)}%` };
    }
    m = s.match(/^(.*?)\s*\(([+-])(\d+)%\)\s*(.*)$/);
    if (m) return { side: m[2] === '+' ? 'up' : 'down', factor: cap(m[1]), detail: m[4] ? cap(m[4]) : '', effect: `${m[2]}${m[3]}%` };
    m = s.match(/^CVSS ([0-9.]+)$/);
    if (m) return { side: +m[1] >= 7 ? 'up' : 'down', factor: 'Severity', detail: `CVSS ${m[1]}`, effect: '' };
    m = s.match(/^EPSS ([0-9.]+)%$/);
    if (m) return { side: +m[1] >= 10 ? 'up' : 'down', factor: 'Chance of exploitation (EPSS)', detail: `${m[1]}%`, effect: '' };
    m = s.match(/^asset criticality ([0-9.]+)$/i);
    if (m) return { side: +m[1] >= 0.5 ? 'up' : 'down', factor: 'Asset criticality', detail: m[1], effect: '' };
    if (/known exploited|KEV/i.test(s)) return { side: 'up', factor: 'Known exploited (KEV)', detail: '', effect: '' };
    return { side: /block|prevent|offline|not exploitable|mitigat|segment|closed/i.test(s) ? 'down' : 'up', factor: cap(s), detail: '', effect: '' };
  }

  function table(title, rows, tone) {
    const body = rows.length
      ? rows.map(r => `<tr><td>${esc(r.factor)}</td><td class="text-muted">${esc(r.detail || '')}</td>
          <td style="text-align:right;white-space:nowrap;color:var(${tone})"><b>${esc(r.effect || '')}</b></td></tr>`).join('')
      : '<tr><td colspan="3" class="text-muted">Nothing</td></tr>';
    return `<h3 class="text-sm" style="margin:12px 0 4px;color:var(${tone})">${esc(title)}</h3>
      <table class="data-table" style="width:100%;font-size:13px"><thead><tr><th>Factor</th><th>Detail</th>
      <th style="text-align:right">Effect</th></tr></thead><tbody>${body}</tbody></table>`;
  }

  function modal() {
    if (dlg) return dlg;
    dlg = document.createElement('dialog');
    dlg.className = 'modal';
    dlg.setAttribute('aria-labelledby', 'score-why-title');
    dlg.innerHTML = `<div style="padding:16px 20px;min-width:340px;max-width:640px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <h2 id="score-why-title" class="panel__title" style="margin:0"></h2>
        <button type="button" class="btn btn--ghost btn--sm" data-close aria-label="Close">&#10005;</button></div>
      <div id="score-why-body"></div></div>`;
    dlg.addEventListener('click', e => {
      if (e.target === dlg || e.target.closest('[data-close]')) dlg.close();
      const t = e.target.closest('[data-tab]');   // a tab on this page: close and open it
      if (t && window.AssetSoftware) { e.preventDefault(); dlg.close(); AssetSoftware.show(t.dataset.tab); }
    });
    document.body.appendChild(dlg);
    return dlg;
  }

  // The finding the reasons are about, linked to its vulnerability: ": CVE-2026-1234 Acme Viewer heap overflow"
  function worst(f) {
    if (!f) return ':';
    const what = [f.cve_id, f.title && f.title !== f.cve_id ? f.title : null].filter(Boolean).join(' ') || 'this finding';
    return `: <a class="dt-link" href="/vulns/${encodeURIComponent(f.vuln_id)}">${esc(what)}</a>`;
  }

  // Which pentest proved it, and when
  function proved(f) {
    const p = f && f.pentest;
    if (!p || !(p.name || p.completed_at)) return '';
    const when = p.completed_at ? new Date(p.completed_at).toLocaleDateString() : '';
    const what = p.name ? `Proved by the NodeZero pentest <b>${esc(p.name)}</b>${when ? ` completed ${esc(when)}` : ''}`
      : `NodeZero last found it on ${esc(when)}`;
    return `<p class="text-sm" style="margin:6px 0 0">${what}; the proof and how it got in are on the <a class="dt-link" href="#pentest" data-tab="pentest">Pentest</a> tab.</p>`;
  }

  function render(el, d) {
    const w = d.score_why;
    el.hidden = !w;
    if (!w) { el.innerHTML = ''; return; }
    const label = `Why ${d.risk_grade || ''}${d.risk_score == null ? '' : `, risk ${Math.round(d.risk_score)}/100`}`.trim();
    el.innerHTML = `<button type="button" class="dt-link" style="background:none;border:0;padding:0;cursor:pointer;font-size:13px">${esc(label)}?</button>`;
    el.querySelector('button').onclick = () => {
      const m = modal(), rows = (w.worst || []).map(sort);
      m.querySelector('#score-why-title').textContent = label;
      m.querySelector('#score-why-body').innerHTML =
        `<p class="text-sm" style="margin:6px 0 0">${esc(cap(String(w.why || '')))}</p>`
        + (rows.length ? `<p class="text-sm text-muted" style="margin:2px 0 0">For the finding that weighs most on this score${worst(w.finding)}</p>` : '')
        + proved(w.finding)
        + table('What decreases the risk', rows.filter(r => r.side === 'down'), '--severity-low')
        + table('What increases the risk', rows.filter(r => r.side === 'up'), '--severity-critical');
      m.showModal();
    };
  }
  return { render, sort };
})();
