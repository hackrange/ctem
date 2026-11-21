// Cloud Inventory: cards that filter, and a table of every cloud instance with its reachability, firewall,
// scanner and EDR coverage and findings. Everything goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const R = DataTable.R;
  const API = '/api/v1/cloud';
  const PROVIDER = { aws: 'AWS', azure: 'Azure', oci: 'OCI', gcp: 'GCP' };
  const initial = new URLSearchParams(location.search);
  const FILTERS = { q: 'cl-search', provider: 'cl-provider', account: 'cl-account', region: 'cl-region', show: 'cl-show' };
  let summary = null;

  const yesNo = (v, good, bad) => v ? `<span class="chip chip--low">${esc(good)}</span>` : `<span class="chip chip--critical">${esc(bad)}</span>`;

  function cards(s) {
    const card = (key, cls, title, value, label) => `<div class="summary-card summary-card--${cls} stat-card--link" data-show="${key}" role="button" tabindex="0"
      title="Show these"><p class="summary-card__eyebrow">${esc(title)}</p><p class="summary-card__value">${Number(value || 0).toLocaleString()}</p>
      <p class="summary-card__label">${esc(label)}</p></div>`;
    $('cl-cards').innerHTML = [
      card('', 'info', 'Cloud instances', s.total, (s.providers || []).map(p => `${PROVIDER[p.provider] || p.provider} ${p.count}`).join(' · ') || 'none yet'),
      card('breachable', s.breachable ? 'critical' : 'low', 'Breachable now', s.breachable, 'Internet + KEV or grade F'),
      card('exposed', s.exposed ? 'high' : 'low', 'Internet exposed', s.exposed, 'Public IP and an open port'),
      card('unscanned', s.unscanned ? 'medium' : 'low', 'Not scanned', s.unscanned, 'No vulnerability scanner'),
      card('no_edr', s.no_edr ? 'medium' : 'low', 'No EDR', s.no_edr, 'No healthy EDR agent'),
      card('unmatched', 'info', 'Cloud only', s.unmatched, 'In no other tool'),
    ].join('');
  }

  function options(s) {
    const fill = (id, list, label) => {
      const cur = $(id).value || initial.get(id.replace('cl-', '')) || '';
      $(id).innerHTML = `<option value="">${esc(label)}</option>` + list.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join('');
      $(id).value = cur;
    };
    fill('cl-provider', (s.providers || []).map(p => [p.provider, PROVIDER[p.provider] || p.provider]), 'All providers');
    fill('cl-account', (s.accounts || []).map(a => [a.account, `${PROVIDER[a.provider] || a.provider} ${a.account} (${a.count})`]), 'All accounts');
    fill('cl-region', (s.regions || []).map(r => [r, r]), 'All regions');
  }

  const table = DataTable.create({
    mount: $('cl-table'),
    endpoint: API,
    exportUrl: `${API}/export`,
    listKey: 'items',
    syncUrl: true,
    emptyText: 'No cloud instances match. Add AWS, Azure or OCI under Integrations and run a sync.',
    rowHref: c => (c.device_id ? `/devices/${encodeURIComponent(c.device_id)}` : null),
    params: () => Object.fromEntries(Object.entries(FILTERS).map(([k, id]) => [k, $(id).value.trim()])),
    columns: [
      { label: 'Name', sort: 'name', render: c => `<div><b>${esc(c.name || c.resource_id)}</b></div>`
        + (c.hostname ? `<div class="text-sm">${R.link(`/devices/${encodeURIComponent(c.device_id)}`, c.hostname)}</div>`
                      : '<div class="text-sm text-muted">No CTEM device</div>') },
      { label: 'Where', sort: 'provider', render: c => `<span class="chip chip--info">${esc(PROVIDER[c.provider] || c.provider)}</span>
          <div class="text-sm text-muted nowrap">${esc(c.account || '')}</div><div class="text-sm text-muted">${esc(c.region || '')}</div>` },
      { label: 'Public IP', render: c => (c.public_ips.length ? c.public_ips.map(ip => `<div class="text-mono text-sm">${esc(ip)}</div>`).join('')
          : '<span class="text-muted text-sm">None</span>') },
      { label: 'Reachability', sort: 'exposed', firstOrder: 'desc', render: c => (c.internet_ports.length
          ? `<span class="chip chip--critical">Internet</span><div class="text-sm text-mono" style="margin-top:2px">${esc(c.internet_ports.join(' '))}</div>`
          : '<span class="chip chip--low">Not from the internet</span>')
          + (c.restricted_ports ? `<div class="text-sm text-muted">${c.restricted_ports} limited rule${c.restricted_ports === 1 ? '' : 's'}</div>` : '') },
      { label: 'Firewall', render: c => c.firewalls.map(f => `<div class="text-sm" title="${esc(f.type)}"><span class="text-mono">${esc(f.id)}</span>${f.name ? ` ${esc(f.name)}` : ''}</div>`).join('')
          || '<span class="text-muted text-sm">None recorded</span>' },
      { label: 'Scanner', render: c => yesNo(c.scanned, 'Scanned', 'Not scanned') },
      { label: 'EDR', render: c => yesNo(c.edr, 'EDR', 'No EDR') },
      { label: 'Findings', sort: 'open', firstOrder: 'desc', render: c => (c.device_id
          ? `${R.num(c.open_findings)}${c.kev_findings ? ` <span class="chip chip--critical">${R.num(c.kev_findings)} KEV</span>` : ''}`
          : '<span class="text-muted">--</span>') },
      { label: 'Grade', sort: 'risk', firstOrder: 'desc', render: c => R.grade(c.risk_grade) },
      { label: 'Owner', render: c => `<span class="text-sm">${esc(c.owner || '--')}</span>` },
    ],
  });

  async function loadSummary() {
    try {
      const r = await fetch(`${API}/summary`, { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
      if (!r.ok) return;
      summary = await r.json();
      cards(summary);
      options(summary);
    } catch (e) { /* the table still works */ }
  }

  Object.entries(FILTERS).forEach(([k, id]) => { if (initial.get(k)) $(id).value = initial.get(k); });
  let timer;
  $('cl-search').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => table.reload(), 300); });
  ['cl-provider', 'cl-account', 'cl-region', 'cl-show'].forEach(id => $(id).addEventListener('change', () => table.reload()));
  $('cl-cards').addEventListener('click', e => {
    const c = e.target.closest('[data-show]');
    if (!c) return;
    $('cl-show').value = c.dataset.show;
    table.reload();
  });
  $('cl-cards').addEventListener('keydown', e => { if (e.key === 'Enter') e.target.closest('[data-show]')?.click(); });
  loadSummary();
})();
