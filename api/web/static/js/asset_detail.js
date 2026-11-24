// The asset page for Code (a repository) and Web apps (a site): the facts that matter for that kind of asset,
// findings columns that fit it (file and line or package for code, URL for web), and a details view per finding
// with where it is, how to fix it and a link back to the tool. Cloud resources: asset_cloud.js. Hosts keep the device layout.
// Everything from the server goes through esc(); links are only ever https://.
(function () {
  const KIND = { code_repository: 'code', website: 'web', cloud_resource: 'cloud' };
  const safeUrl = u => (typeof u === 'string' && /^https:\/\//i.test(u) ? u : null);
  const tagVals = (d, prefix) => (d.tags || []).filter(t => t.toLowerCase().startsWith(prefix)).map(t => t.slice(prefix.length));

  function kind(d) { return KIND[d && d.device_type] || null; }

  // h: { info, txt, R, tagChips } from the page
  function info(d, h) {
    const k = kind(d);
    if (k === 'cloud') return window.CloudDetail.info(d, h);
    const list = (vals, mono) => (vals.length ? vals.map(v => `<div${mono ? ' class="text-mono text-sm"' : ''}>${esc(v)}</div>`).join('') : h.txt(null));
    // An owner this asset's source didn't give: from other assets of the same application, else say who didn't
    const owner = (label, key, prefix) => {
      const own = tagVals(d, prefix);
      if (own.length) return h.info(label, list(own));
      const r = (d.related_owners || {})[key];
      if (r && r.values.length) return h.info(label, `${list(r.values)}<div class="text-sm text-muted">from other ${esc(r.via)} assets</div>`);
      const src = (d.sources || []).includes('github_code_review') ? 'GitHub Code Review' : 'its sources';
      return h.info(label, `<span class="text-muted">Not provided by ${esc(src)}</span><div class="text-sm text-muted">Add it with the integration's tag map or Admin &gt; Tag mapping</div>`);
    };
    const people = () => [
      h.info('Application', list(tagVals(d, 'app:'))),
      owner('Technical owner', 'technical_owner', 'tech_owner:'),
      owner('Application owner', 'application_owner', 'app_owner:'),
      owner('Executive owner', 'executive_owner', 'exec_owner:'),
    ];
    const common = [
      h.info('Open findings', h.R.num(d.open_findings)),
      h.info('Known exploited (KEV)', d.kev_findings ? `<span class="chip chip--critical">${h.R.num(d.kev_findings)}</span>` : '0'),
      h.info('Sources', (d.sources || []).map(c => `<span class="chip chip--info" style="font-size:.7rem">${esc(c)}</span>`).join(' ') || h.txt(null)),
      h.info('Tags', h.tagChips(d.tags || [])),
    ];
    if (k === 'code') {
      const sites = tagVals(d, 'site:');
      return [
        h.info('Repository', `<span class="text-mono">${esc(d.hostname)}</span>`),
        ...people(),
        h.info('Visibility and data', list(tagVals(d, 'gcr:'))),
        h.info('Live sites in front of it', list(sites, true)),
        h.info('Reachable from the internet', d.is_internet_exposed ? '<span class="chip chip--high">Yes, behind a live site</span>' : '<span class="chip chip--low">No</span>'),
        ...common,
      ].join('');
    }
    const url = `https://${d.hostname}`;
    return [
      h.info('Site', `<a class="dt-link text-mono" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a>`),
      h.info('IP address', `<span class="text-mono">${h.txt(d.ip)}</span>`),
      h.info('Environment', list(tagVals(d, 'env:'))),
      h.info('Site configuration grade (TLS and headers, from GitHub Code Review)', list(tagVals(d, 'gcr:grade '))),
      ...people(),
      h.info('Code behind it', list(tagVals(d, 'repo:'), true)),
      h.info('Internet facing', d.is_internet_exposed ? '<span class="chip chip--high">Yes</span>' : '<span class="chip chip--low">No</span>'),
      ...common,
    ].join('');
  }

  function where(f) {
    const x = f.details || {};
    if (f.domain === 'web') return x.url ? `<span class="text-mono text-sm" title="${esc(x.url)}">${esc(x.url.replace(/^https?:\/\//, '').slice(0, 60))}</span>` : '';
    if (x.package) return `<span class="text-mono text-sm">${esc(x.package.name || '')}@${esc(x.package.version || '?')}</span>`;
    if (x.file) return `<span class="text-mono text-sm" title="${esc(x.file)}">${esc(x.file.split('/').slice(-2).join('/'))}${x.line ? `:${esc(x.line)}` : ''}</span>`;
    return '';
  }

  // h: { sevChip, dim, txt, R, vulnLink }
  function columns(k, h) {
    const btn = f => `<button type="button" class="btn btn--ghost btn--sm" data-detail="${esc(f.id)}">Details</button>`;
    const status = f => h.dim(f, esc((f.status || '').replace(/_/g, ' ')));
    if (k === 'cloud') return window.CloudDetail.columns(h, btn, status);
    if (k === 'code') {
      return [
        { label: 'Severity', sort: 'cvss_base', firstOrder: 'desc', render: f => h.sevChip(f) },
        { label: 'Finding', sort: 'title', render: f => h.dim(f, h.vulnLink(f, (f.title || '').replace(/ \([^)]*\)$/, ''))) },
        { label: 'Kind', render: f => h.dim(f, `<span class="chip chip--info" style="font-size:.7rem">${esc((f.details || {}).kind || 'Code')}</span>`) },
        { label: 'Where', render: f => h.dim(f, where(f)) },
        { label: 'Fix', render: f => { const p = (f.details || {}).package; return h.dim(f, p && p.fixed_in ? `Upgrade to <b>${esc(p.fixed_in)}</b>` : (f.details || {}).fix ? 'See details' : h.txt(null)); } },
        { label: 'Reach', render: f => h.dim(f, h.R.reach(f)) },
        { label: 'Status', sort: 'status', render: status },
        { label: 'Age', sort: 'age', firstOrder: 'desc', render: f => h.dim(f, h.R.age(f)) },
        { label: 'Last seen', sort: 'last_seen', firstOrder: 'desc', render: f => h.dim(f, h.R.date(f.last_seen)) },
        { label: '', render: btn },
      ];
    }
    return [
      { label: 'Severity', sort: 'cvss_base', firstOrder: 'desc', render: f => h.sevChip(f) },
      { label: 'Finding', sort: 'title', render: f => h.dim(f, h.vulnLink(f, f.title)) },
      { label: 'URL', render: f => h.dim(f, where(f)) },
      { label: 'Weakness', render: f => h.dim(f, esc((f.details || {}).cwe || '')) },
      { label: 'Status', sort: 'status', render: status },
      { label: 'Age', sort: 'age', firstOrder: 'desc', render: f => h.dim(f, h.R.age(f)) },
      { label: 'Last scanned', sort: 'last_seen', firstOrder: 'desc', render: f => h.dim(f, h.R.date(f.last_seen)) },
      { label: '', render: btn },
    ];
  }

  // What happened when CTEM's exception was sent to the tool the finding came from
  // Why GCR gives this grade: what the scanner said, what changed it, who and why
  const gradeHtml = g => {
    if (!g || !g.severity) return '';
    const moved = g.engine_severity && g.engine_severity !== g.severity;
    const who = [g.source_label ? `set by ${g.source_label}` : '', g.by, g.at ? new Date(g.at).toLocaleDateString() : ''].filter(Boolean).join(' · ');
    return `<span class="chip chip--${esc(g.severity)}" style="font-size:.7rem">${esc(g.severity)}</span>${moved ? ` <span class="text-sm text-muted">the scanner said ${esc(g.engine_severity)}</span>` : ''}
      ${who ? `<div class="text-sm text-muted">${esc(who)}</div>` : ''}${g.validation ? `<div class="text-sm">Validation: <b>${esc(g.validation.rating)}</b>${g.validation.confidence ? `, ${esc(g.validation.confidence)} confidence` : ''}</div>` : ''}
      ${g.reason ? `<div class="text-sm" style="white-space:pre-wrap;margin-top:2px">${esc(g.reason)}</div>` : ''}`;
  };
  // A GCR waiver (requested, approved...) or an exclusion rule
  const gcrExc = e => (!e ? '' : `<b>${esc(e.source === 'exclusion' ? 'Excluded by a rule' : `Waiver${e.status ? ` ${e.status}` : ''}`)}</b>${
    e.category === 'not_deployed' ? ' <span class="text-sm text-muted">(not deployed)</span>' : ''}${e.expires ? ` <span class="text-sm text-muted">until ${esc(String(e.expires).slice(0, 10))}</span>` : ''}${
    e.by ? ` <span class="text-sm text-muted">· ${esc(e.by)}</span>` : ''}${e.reason ? `<div class="text-sm">${esc(e.reason)}</div>` : ''}`);
  const tx = t => {
    if (!t) return '';
    const label = { approved: ['low', 'Approved there too'], requested: ['medium', 'Requested there, waiting for an admin'], already: ['info', 'Already had one there'],
                    failed: ['critical', 'Could not be sent; retried after the next sync'], skipped: ['info', 'Not sent yet'] }[t.state] || ['info', t.state];
    return `<span class="chip chip--${label[0]}">${esc(label[1])}</span>${t.why ? ` <span class="text-sm text-muted">${esc(t.why)}</span>` : ''}`;
  };

  // Where it is, how it was found and how to fix it, for a Code or Web app finding (dialog and vulnerability page)
  function sections(f) {
    const x = f.details || {};
    const pre = v => `<pre style="white-space:pre-wrap;margin:0;font-size:.76rem;max-height:320px;overflow:auto;background:var(--bg-page);border:1px solid var(--border);border-radius:6px;padding:8px">${esc(v)}</pre>`;
    const fold = (label, v) => (v ? `<details style="margin-top:4px"><summary style="cursor:pointer">${esc(label)}</summary>${pre(v)}</details>` : '');
    const row = (label, html) => (html ? `<div style="display:grid;grid-template-columns:170px minmax(0,1fr);gap:10px;padding:7px 0;border-bottom:1px solid var(--border)">
      <span class="text-muted text-sm">${esc(label)}</span><div style="min-width:0;overflow-wrap:anywhere">${html}</div></div>` : '');
    const mono = v => (v ? `<span class="text-mono text-sm">${esc(v)}</span>` : '');
    if (f.domain === 'cloud') return window.CloudDetail.sections(f, row);
    const link = safeUrl(x.link);
    const pkg = x.package || {};
    const body = f.domain === 'web' ? [
      row('What it is', x.description ? `<div style="white-space:pre-wrap">${esc(x.description)}</div>` : ''),
      row('Decision in the tool', x.decision ? `<b>${esc(x.decision.kind || '')}</b>${x.decision.reason ? `: ${esc(x.decision.reason)}` : ''}<div class="text-sm text-muted">${esc([x.decision.by, x.decision.at ? new Date(x.decision.at).toLocaleDateString() : '', x.decision.expires ? `until ${x.decision.expires}` : ''].filter(Boolean).join(' · '))}</div>` : ''),
      row('Risk', x.risk ? `<b>${esc(x.risk)}</b>${x.likelihood ? ` · likelihood ${esc(x.likelihood)}` : ''}${x.impact ? ` · impact ${esc(x.impact)}` : ''}${x.risk_basis ? `<div class="text-sm text-muted">${esc(x.risk_basis)}</div>` : ''}` : ''),
      row('Attack', esc(x.attack_type || '')), row('Site', mono(x.site)), row('URL', mono(x.url)), row('Method', mono(x.method)),
      row(`All URLs (${(x.urls || []).length})`, (x.urls || []).length > 1 ? x.urls.map(u => `<div class="text-mono text-sm">${esc(u)}</div>`).join('') : ''),
      row('References', (x.references || []).filter(r => /^https:\/\//.test(r)).map(r => `<div><a class="dt-link" href="${esc(r)}" target="_blank" rel="noopener noreferrer">${esc(r)}</a></div>`).join('')),
      row('Found by', esc(x.tool || '')),
      row('Parameter', mono(x.parameter)), row('Original value', mono(x.original_value)), row('Attack value', mono(x.attack_value)),
      row('What the scanner saw', x.message ? `<div style="white-space:pre-wrap">${esc(x.message)}</div>` : ''),
      row('Proof', x.proof ? pre(x.proof) : ''), row('Evidence', x.evidence ? pre(x.evidence) : ''),
      row('Weakness', esc([x.cwe, ...(x.references || []).filter(r => r !== x.cwe)].filter(Boolean).join(', '))),
      row('Score', x.score != null ? esc(`${x.score}${x.vector ? ` (${x.vector})` : ''}`) : ''),
      row('Request and response', (x.request || x.response) ? `${fold('Request the scanner sent', x.request)}${fold('Response it got', x.response)}
        <div class="text-sm text-muted" style="margin-top:4px">Cookies, authorization headers and token-like values are removed.</div>` : ''),
      row('Scanned', x.scanned_at ? esc(new Date(x.scanned_at).toLocaleString()) : ''), row('Scanner', esc(x.engine || '')),
      row('Exception in the tool', tx(x.tool_exception)),
      row('Why this score', (x.score_why || []).length ? esc(x.score_why.join(' · ')) : ''),
    ] : [
      row('What it is', x.description ? `<div style="white-space:pre-wrap">${esc(x.description)}</div>` : ''),
      row('Risk in GitHub Code Review', x.gcr_risk ? `<b>${esc(x.gcr_risk.score)}</b> of 100${x.gcr_risk.evidence ? ` <span class="chip chip--info" style="font-size:.7rem">${esc(x.gcr_risk.evidence)}</span>` : ''}
        ${x.gcr_risk.likelihood ? `<div>Likelihood <b>${esc(x.gcr_risk.likelihood)}</b>${x.gcr_risk.likelihood_reason ? ` <span class="text-sm text-muted">${esc(x.gcr_risk.likelihood_reason)}</span>` : ''}</div>` : ''}
        ${x.gcr_risk.impact ? `<div>Impact <b>${esc(x.gcr_risk.impact)}</b>${x.gcr_risk.impact_reason ? ` <span class="text-sm text-muted">${esc(x.gcr_risk.impact_reason)}</span>` : ''}</div>` : ''}` : ''),
      row('Grade here', gradeHtml(x.grade)),
      row('Triage', x.triage ? `${x.triage.state ? `<b>${esc(x.triage.state.replace(/_/g, ' '))}</b> ` : ''}${x.triage.reason ? `<span class="text-sm">${esc(x.triage.reason)}</span>` : ''}` : ''),
      row('Found by', (x.engines || []).length ? `${esc(x.engines.join(', '))}${x.corroborated ? ' <span class="chip chip--info" style="font-size:.7rem">corroborated</span>' : ''}${x.confidence ? ` <span class="text-sm text-muted">${esc(x.confidence)} confidence</span>` : ''}` : ''),
      row('In GitHub Code Review', gcrExc(x.gcr_exception) + (x.out_of_scope ? ' <span class="chip chip--info" style="font-size:.7rem">out of scope</span>' : '')),
      row('Validation', x.validation ? `<b>${esc(x.validation.rating || '')}</b>${x.validation.confidence ? ` <span class="text-sm text-muted">${esc(x.validation.confidence)} confidence</span>` : ''}${x.validation.reviewed_at ? ` <span class="text-sm text-muted">· ${esc(new Date(x.validation.reviewed_at).toLocaleDateString())}</span>` : ''}
        ${x.validation.summary ? `<div style="white-space:pre-wrap;margin-top:4px">${esc(x.validation.summary)}</div>` : ''}
        ${fold('Why this rating', x.validation.why)}${fold('What to check', x.validation.what_to_check)}${fold('Compensating controls', x.validation.compensating_controls)}` : ''),
      row('Supply chain', x.supply_chain ? `<span class="chip chip--critical">${esc(x.supply_chain.signal || 'flagged')}</span>${x.supply_chain.reason ? ` <span class="text-sm">${esc(x.supply_chain.reason)}</span>` : ''}` : ''),
      row('Kind', esc(x.kind || '')), row('Repository', mono(x.repository)), row('Branch', mono([x.branch, ...(x.branches || []).filter(b => b !== x.branch)].filter(Boolean).join(', '))),
      row('File', x.file ? mono(`${x.file}${x.line ? `:${x.line}` : ''}`) : ''), row('Rule', mono(x.rule)),
      row('Package', pkg.name ? mono(`${pkg.name} ${pkg.version || ''}${pkg.ecosystem ? ` (${pkg.ecosystem})` : ''}`) : ''),
      row('Fixed in', mono(pkg.fixed_in)), row('Declared in', mono(pkg.declared_in)), row('Advisory', mono(x.advisory)),
      row('Weakness', esc([...(x.cwe || []), ...(x.owasp || [])].join(', '))),
      row('Reachable', x.reachability ? `${esc(x.reachability.verdict)}${x.reachability.why ? ` <span class="text-muted text-sm">${esc(x.reachability.why)}</span>` : ''}${(x.reachability.direct || x.reachability.scope) ? `<div class="text-sm text-muted">${esc([x.reachability.direct && x.reachability.direct !== 'unknown' ? `${x.reachability.direct} dependency` : '', x.reachability.scope && x.reachability.scope !== 'unknown' ? x.reachability.scope : ''].filter(Boolean).join(', '))}</div>` : ''}` : ''),
      row('Secret', x.secret ? (x.secret.verified ? '<span class="chip chip--critical">Confirmed live</span>' : 'Not confirmed') + (x.secret.exposure ? ` <span class="text-sm text-muted">${esc(x.secret.exposure)}</span>` : '') : ''),
      row('Committed by', x.author ? `${esc(x.author)}${x.committed_at ? ` <span class="text-sm text-muted">${esc(new Date(x.committed_at).toLocaleDateString())}</span>` : ''}` : ''),
      row('Commit', x.commit ? (safeUrl(x.commit_url) ? `<a class="dt-link text-mono text-sm" href="${esc(x.commit_url)}" target="_blank" rel="noopener noreferrer">${esc(x.commit.slice(0, 12))}</a>` : mono(x.commit)) : ''),
      row('File on GitHub', safeUrl(x.file_url) ? `<a class="dt-link text-sm" href="${esc(x.file_url)}" target="_blank" rel="noopener noreferrer">Open the file</a>` : ''),
      row('Repository holds', x.asset && (x.asset.holds || []).length ? x.asset.holds.map(h => `<span class="chip chip--medium" style="font-size:.7rem">${esc(h)}</span>`).join(' ') + (x.asset.application ? ` <span class="text-sm text-muted">${esc(x.asset.application)}</span>` : '') : ''),
      row('Tool reference', mono(x.gcr_id)),
      row('Exception in the tool', tx(x.tool_exception)),
      row('Why this score', (x.score_why || []).length ? esc(x.score_why.join(' · ')) : ''),
    ];
    const fix = x.fix ? `<div style="background:var(--accent-dim);border-radius:8px;padding:10px 12px;margin-bottom:10px"><b>How to fix</b><div style="white-space:pre-wrap;margin-top:4px">${esc(x.fix)}</div></div>` : '';
    const tool = f.source === 'github_code_review' ? 'GitHub Code Review' : f.source === 'rapid7_appsec' ? 'Rapid7 AppSec' : 'the tool';
    return { fix, body: body.join(''), link, tool };
  }

  // The vulnerability page's "What the scanner found": the same facts, from one finding of it
  function panel(f) {
    const s = sections(f);
    return `${s.fix}${s.body || '<p class="text-muted">The tool sent no more detail for this finding.</p>'}
      ${s.link ? `<p style="margin:10px 0 0"><a class="btn btn--ghost btn--sm" href="${esc(s.link)}" target="_blank" rel="noopener noreferrer">Open in ${esc(s.tool)}</a></p>` : ''}`;
  }

  // A dialog that closes only from its own button
  function open(f) {
    const s = sections(f);
    let wrap = document.getElementById('asset-finding');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'asset-finding';
      wrap.className = 'tk-backdrop';
      wrap.setAttribute('role', 'dialog');
      wrap.setAttribute('aria-modal', 'true');
      wrap.setAttribute('aria-labelledby', 'asset-finding-title');
      document.body.appendChild(wrap);
    }
    wrap.innerHTML = `<div class="tk-dialog" style="max-width:760px;max-height:88vh;overflow:auto">
      <h2 class="tk-title" id="asset-finding-title">${esc((f.title || '').replace(/ \([^)]*\)$/, ''))}</h2>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
        <span class="chip chip--${esc(f.severity)}">${esc(f.severity)}</span>
        <span class="chip chip--info">${{ web: 'Web app', cloud: 'Cloud' }[f.domain] || 'Code'}</span>
        <span class="chip chip--info">${esc((f.status || '').replace(/_/g, ' '))}</span>
        ${f.is_kev ? '<span class="chip chip--critical">Known exploited</span>' : ''}
      </div>
      ${s.fix}
      ${s.body || '<p class="text-muted">The tool sent no more detail for this finding.</p>'}
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px;flex-wrap:wrap">
        ${s.link ? `<a class="btn btn--ghost btn--sm" href="${esc(s.link)}" target="_blank" rel="noopener noreferrer">Open in ${esc(s.tool)}</a>` : ''}
        <a class="btn btn--ghost btn--sm" href="/vulns/${encodeURIComponent(f.vuln_id)}">All ${{ web: 'sites', cloud: 'resources' }[f.domain] || 'repositories'} with this</a>
        <button type="button" class="btn btn--primary btn--sm" data-close>Close</button>
      </div></div>`;
    wrap.classList.add('is-open');
    wrap.querySelector('[data-close]').onclick = () => wrap.classList.remove('is-open');
    wrap.querySelector('[data-close]').focus();
  }

  // The vulnerability page's list: which repositories or sites have it, and where in each
  function affectedColumns(k, h) {
    const btn = f => `<button type="button" class="btn btn--ghost btn--sm" data-detail="${esc(f.id)}">Details</button>`;
    const name = f => h.dim(f, h.R.link(h.dev(f), f.hostname));
    const status = f => h.dim(f, f.exception_id
      ? `<a class="chip chip--info" style="font-size:.7rem" href="/exceptions?id=${encodeURIComponent(f.exception_id)}">Excepted</a>`
      : `<span class="text-sm">${esc((f.status || '').replace('_', ' '))}</span>`);
    const sev = f => `<span class="chip chip--${esc(f.severity)}" style="font-size:.7rem">${esc(f.severity === 'info' ? 'Info' : f.severity)}</span>`;
    if (k === 'cloud') return window.CloudDetail.affected(h, btn, status, sev);
    if (k === 'code') {
      return [
        { label: 'Repository', sort: 'hostname', render: name },
        { label: 'Severity', render: sev },
        { label: 'Where', render: f => h.dim(f, where(f)) },
        { label: 'Branch', render: f => h.dim(f, `<span class="text-mono text-sm">${esc((f.details || {}).branch || '')}</span>`) },
        { label: 'Fix', render: f => { const p = (f.details || {}).package; return h.dim(f, p && p.fixed_in ? `Upgrade to <b>${esc(p.fixed_in)}</b>` : (f.details || {}).fix ? 'See details' : ''); } },
        { label: 'Reach', render: f => h.dim(f, h.R.reach(f)) },
        { label: 'Status', sort: 'status', render: status },
        { label: 'Age', sort: 'age', firstOrder: 'desc', render: f => h.dim(f, h.R.age(f)) },
        { label: 'Last seen', sort: 'last_seen', firstOrder: 'desc', render: f => h.dim(f, h.R.date(f.last_seen)) },
        { label: '', render: btn },
      ];
    }
    return [
      { label: 'Site', sort: 'hostname', render: name },
      { label: 'Severity', render: sev },
      { label: 'URL', render: f => h.dim(f, where(f)) },
      { label: 'Status', sort: 'status', render: status },
      { label: 'Age', sort: 'age', firstOrder: 'desc', render: f => h.dim(f, h.R.age(f)) },
      { label: 'Last scanned', sort: 'last_seen', firstOrder: 'desc', render: f => h.dim(f, h.R.date(f.last_seen)) },
      { label: '', render: btn },
    ];
  }

  const LABEL = { code: 'Code repository', web: 'Web application', cloud: 'Cloud resource' };
  const AFFECTED = { code: 'Affected repositories', web: 'Affected sites', infra: 'Affected devices', cloud: 'Affected resources' };
  window.AssetDetail = { kind, info, columns, affectedColumns, open, panel, label: k => LABEL[k], affectedLabel: k => AFFECTED[k] || AFFECTED.infra };
})();
