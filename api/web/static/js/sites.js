// Sites page (api/routes/locations.py): each inferred place with its coverage by tool, pentest-only assets and open
// risk; picking one lists its subnets. Everything shown goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const pct = (n, t) => (t ? `${Math.round((n / t) * 100)}%` : '');
  const cell = (n, t) => `<td class="text-sm">${esc(n)}<span class="text-muted" style="font-size:.72rem"> ${esc(pct(n, t))}</span></td>`;
  const params = r => {
    const p = new URLSearchParams();
    [['loc_state', r.state], ['loc_city', r.city], ['loc_office', r.office], ['loc_site', r.site]].forEach(([k, v]) => { if (v) p.set(k, v); });
    return p;
  };
  let rows = [];

  async function subnets(i) {
    const r = rows[i];
    const name = r ? [[r.city, r.state].filter(Boolean).join(', '), r.office, r.site && `AD site ${r.site}`].filter(Boolean).join(' · ') : 'Unlocated assets';
    $('subnets-panel').hidden = false;
    $('subnets-title').textContent = `Subnets: ${name}`;
    $('subnets-body').innerHTML = '<p class="text-muted text-sm" style="padding:14px">Loading...</p>';
    const res = await fetch(`/api/v1/locations/subnets?${r ? params(r) : ''}`, { headers: { Accept: 'application/json' } });
    if (!res.ok) { $('subnets-body').innerHTML = '<p class="text-sm" style="padding:14px">Couldn\'t load.</p>'; return; }
    const d = await res.json();
    $('subnets-body').innerHTML = `<table class="data-table"><thead><tr><th>Subnet</th><th>Assets</th><th>Scanner</th><th>EDR</th><th>Directory</th><th>Pentest</th><th>Pentest only</th><th>Open findings</th></tr></thead><tbody>
      ${d.subnets.map(s => {
        const q = r ? params(r) : new URLSearchParams();
        if (s.subnet.includes('/')) q.set('subnet', s.subnet);
        return `<tr><td class="text-sm text-mono"><a href="/devices?${q}">${esc(s.subnet)}</a></td><td class="text-sm">${esc(s.assets)}</td>
          ${cell(s.scanner, s.assets)}${cell(s.edr, s.assets)}${cell(s.directory, s.assets)}${cell(s.pentest, s.assets)}
          <td class="text-sm">${s.pentest_only ? `<b style="color:var(--accent)">${esc(s.pentest_only)}</b>` : '0'}</td><td class="text-sm">${esc(s.open_findings)}</td></tr>`;
      }).join('')}</tbody></table>`;
  }

  async function load() {
    const res = await fetch('/api/v1/locations', { headers: { Accept: 'application/json' } });
    if (!res.ok) { $('sites-body').innerHTML = '<p class="text-sm" style="padding:14px">Couldn\'t load sites.</p>'; return; }
    const d = await res.json();
    rows = d.locations;
    $('sites-body').innerHTML = !rows.length
      ? `<p class="text-sm" style="padding:14px">No locations yet. They come from the EDR's AD sites and people's offices (shipper 1.6.0), and spread to neighbors. ${esc(d.unlocated)} assets have none.</p>`
      : `<table class="data-table"><thead><tr><th>Place</th><th>Office</th><th>AD site</th><th>Assets</th><th>Scanner</th><th>EDR</th><th>Directory</th><th>Pentest</th><th>Pentest only</th><th>Open</th><th>KEV</th></tr></thead><tbody>
        ${rows.map((r, i) => `<tr><td class="text-sm"><a href="#" data-i="${i}">${esc([r.city, r.state].filter(Boolean).join(', ') || '(unknown city)')}</a></td>
          <td class="text-sm">${esc(r.office || '')}</td><td class="text-sm">${esc(r.site || '')}</td>
          <td class="text-sm"><a href="/devices?${params(r)}">${esc(r.assets)}</a></td>
          ${cell(r.scanner, r.assets)}${cell(r.edr, r.assets)}${cell(r.directory, r.assets)}${cell(r.pentest, r.assets)}
          <td class="text-sm">${r.pentest_only ? `<b style="color:var(--accent)">${esc(r.pentest_only)}</b>` : '0'}</td>
          <td class="text-sm"><a href="/vulns?${params(r)}">${esc(r.open_findings)}</a></td><td class="text-sm">${esc(r.kev)}</td></tr>`).join('')}
        <tr><td class="text-sm text-muted" colspan="3"><a href="#" data-i="-1">Unlocated</a></td><td class="text-sm text-muted" colspan="8">${esc(d.unlocated)} assets</td></tr>
        </tbody></table>`;
    $('sites-body').querySelectorAll('[data-i]').forEach(a => a.addEventListener('click', e => { e.preventDefault(); subnets(Number(a.dataset.i)); }));
  }
  load();
})();
