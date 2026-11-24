// Cloud resources (CSPM): the asset facts, finding columns and finding details that fit a cloud configuration check:
// provider, account, region, resource type and ARN instead of IP, OS and EDR, and the tool's own fix steps.
// Loaded before asset_detail.js, which hands cloud assets to it. Everything from the server goes through esc().
(function () {
  const SIGNAL = { public: ['high', 'Public or internet-facing'], identity: ['medium', 'Identity or admin rights'], hygiene: ['info', 'Logging or housekeeping'] };
  const mono = v => (v ? `<span class="text-mono text-sm">${esc(v)}</span>` : '');
  const signals = x => (x.signals || []).filter(s => SIGNAL[s]).map(s => `<span class="chip chip--${SIGNAL[s][0]}" style="font-size:.7rem">${esc(SIGNAL[s][1])}</span>`).join(' ');
  const account = x => (x.account || x.account_id ? `${esc(x.account || x.account_id)}${x.account && x.account_id ? ` <span class="text-sm text-muted text-mono">${esc(x.account_id)}</span>` : ''}` : '');

  // h: { info, txt, R, tagChips }
  function info(d, h) {
    const w = d.cloud_where || {};
    return [
      h.info('Resource', `<span class="text-mono">${esc(d.hostname)}</span>`),
      h.info('Provider', h.txt(w.provider)),
      h.info('Account', account(w) || h.txt(null)),
      h.info('Region', h.txt(w.region)),
      h.info('Resource type', h.txt(w.resource_type)),
      h.info('Resource ID', w.resource ? mono(w.resource) : h.txt(null)),
      h.info('ARN or cloud ID', w.arn ? `<span class="text-mono text-sm" style="overflow-wrap:anywhere">${esc(w.arn)}</span>` : h.txt(null)),
      h.info('Open findings', h.R.num(d.open_findings)),
      h.info('Sources', (d.sources || []).map(c => `<span class="chip chip--info" style="font-size:.7rem">${esc(c)}</span>`).join(' ') || h.txt(null)),
      h.info('Tags', h.tagChips(d.tags || [])),
    ].join('');
  }

  // The resource's own findings. h: { sevChip, dim, txt, R, vulnLink }, plus the page's Details button and status
  function columns(h, btn, status) {
    return [
      { label: 'Severity', sort: 'cvss_base', firstOrder: 'desc', render: f => h.sevChip(f) },
      { label: 'Check', sort: 'title', render: f => h.dim(f, h.vulnLink(f, f.title)) },
      { label: 'About', render: f => h.dim(f, signals(f.details || {})) },
      { label: 'Grade', sort: 'composite_score', firstOrder: 'desc', render: f => h.dim(f, `${h.R.grade(f.risk_grade)} ${h.R.score(f.composite_score)}`) },
      { label: 'Fix', render: f => h.dim(f, (f.details || {}).fix ? 'See details' : h.txt(null)) },
      { label: 'Status', sort: 'status', render: status },
      { label: 'Age', sort: 'age', firstOrder: 'desc', render: f => h.dim(f, h.R.age(f)) },
      { label: 'Last seen', sort: 'last_seen', firstOrder: 'desc', render: f => h.dim(f, h.R.date(f.last_seen)) },
      { label: '', render: btn },
    ];
  }

  // A check's page: every resource that fails it. h: { dim, R, dev }
  function affected(h, btn, status, sev) {
    const x = f => f.details || {};
    return [
      { label: 'Resource', sort: 'hostname', render: f => h.dim(f, h.R.link(h.dev(f), f.hostname)) },
      { label: 'Severity', render: sev },
      { label: 'Account', render: f => h.dim(f, account(x(f))) },
      { label: 'Region', render: f => h.dim(f, esc(x(f).region || '')) },
      { label: 'Type', render: f => h.dim(f, esc(x(f).resource_type || '')) },
      { label: 'Grade', sort: 'risk_score', firstOrder: 'desc', render: f => h.dim(f, `${h.R.grade(f.risk_grade)} ${h.R.score(f.composite_score)}`) },
      { label: 'Status', sort: 'status', render: status },
      { label: 'Age', sort: 'age', firstOrder: 'desc', render: f => h.dim(f, h.R.age(f)) },
      { label: 'Last seen', sort: 'last_seen', firstOrder: 'desc', render: f => h.dim(f, h.R.date(f.last_seen)) },
      { label: '', render: btn },
    ];
  }

  // The details dialog and the check page's panel. row(label, html) is the shared layout.
  function sections(f, row) {
    const x = f.details || {};
    const links = (x.fix_links || []).filter(u => /^https:\/\//i.test(u));
    const fix = x.fix ? `<div style="background:var(--accent-dim);border-radius:8px;padding:10px 12px;margin-bottom:10px"><b>How to fix</b>
      <div style="white-space:pre-wrap;margin-top:4px;max-height:360px;overflow:auto">${esc(x.fix)}</div>
      ${links.length ? `<div style="margin-top:6px">${links.map(u => `<div><a class="dt-link text-sm" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a></div>`).join('')}</div>` : ''}</div>` : '';
    const body = [
      row('About', signals(x)),
      row('Provider', esc(x.provider || '')), row('Account', account(x)), row('Region', esc(x.region || '')),
      row('Resource type', esc(x.resource_type || '')), row('Resource ID', mono(x.resource)), row('ARN or cloud ID', mono(x.arn)),
      row('Tool tags', (x.tags || []).map(t => `<span class="chip chip--info" style="font-size:.7rem">${esc(t)}</span>`).join(' ')),
      row('Compliance controls', (x.compliance || []).map(c => `<div class="text-sm">${esc(c)}</div>`).join('')),
      row('Why this score', (x.score_why || []).length ? esc(x.score_why.join(' · ')) : ''),
    ];
    return { fix, body: body.join(''), link: null, tool: 'Rapid7 InsightCloudSec' };
  }

  window.CloudDetail = { info, columns, affected, sections };
})();
