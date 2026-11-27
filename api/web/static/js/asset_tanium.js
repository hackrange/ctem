// The asset page's Tanium tab: the last patch installed and by what (the way to spot machines that stopped
// patching), patch scan age, pending reboot, disk encryption, hardware, and Tanium's vulnerability count. The tab
// appears only for machines Tanium reports. Everything goes through esc().
window.AssetTanium = (() => {
  const row = (k, v) => `<span class="text-muted">${esc(k)}</span><span>${v}</span>`;
  const txt = v => (v == null || v === '' ? '<span class="text-muted">--</span>' : esc(v));
  const yes = v => (v == null ? txt(null) : v ? 'Yes' : 'No');
  const grid = rows => `<div class="text-sm" style="display:grid;grid-template-columns:190px minmax(0,1fr);gap:4px 10px;padding:10px 14px">${rows.join('')}</div>`;
  const head = t => `<div class="panel__header" style="border-top:1px solid var(--border)"><span class="panel__title">${esc(t)}</span></div>`;

  // "2026-11-19 (8 days ago, Windows Update)", red past 30 days
  function lastPatch(p) {
    if (!p) return txt(null);
    const ago = p.days === 0 ? 'today' : p.days === 1 ? '1 day ago' : `${p.days} days ago`;
    const chip = p.stale ? ' <span class="chip chip--high" style="font-size:.65rem" title="No patch installed in 30 days">Not patching</span>' : '';
    return `<span title="${esc(p.title || '')}">${esc(p.date)}</span> <span class="text-sm text-muted">(${esc(ago)}${p.source ? ', ' + esc(p.source) : ''})</span>${chip}`;
  }

  function draw(panel, d) {
    const p = d.patch || {}, h = d.hardware || {}, e = d.encryption, u = d.users;
    const scan = p.scan_age_days != null ? `${p.scan_age_days} days ago` + (p.scan_age_days > 7 ? ' <span class="chip chip--medium" style="font-size:.65rem">Stale</span>' : '') : txt(p.scan_note);
    const recent = (p.recent || []).map(r => `<tr><td class="text-sm">${esc(r.date)}</td><td class="text-sm">${esc(r.title)}</td><td class="text-sm text-muted">${txt(r.source)}</td></tr>`).join('');
    panel.innerHTML = `<div class="panel__header"><span class="panel__title">Patching (Tanium)</span></div>
      ${grid([row('Last patch installed', lastPatch(p.view)), row('Installed in the last 90 days', txt(p.in_90_days)),
              row('Last successful patch scan', scan), row('Reboot pending', yes(p.reboot_required)), row('Last reboot', txt(p.last_reboot))])}
      ${recent ? `<table class="table" style="margin:0 14px 10px;width:calc(100% - 28px)"><thead><tr><th>Installed</th><th>Patch</th><th>By</th></tr></thead><tbody>${recent}</tbody></table>` : ''}
      ${e ? head('Disk encryption') + grid([row('Encrypted', yes(e.encrypted)), ...(e.bitlocker || []).map(b => row(`BitLocker ${b.drive || ''}`,
        esc([b.protection, b.conversion, b.method, b.percent ? b.percent + '%' : null].filter(Boolean).join(', ') || '--')))]) : ''}
      ${head('Vulnerabilities')}${grid([row('Open, found by Tanium', txt(d.vulns.open)), row('Also found by a scanner', txt(d.vulns.also_by_scanner))])}
      ${head('Device')}${grid([row('Model', txt([h.manufacturer, h.model].filter(Boolean).join(' '))), row('Serial', txt(h.serial)),
        row('Type', txt(h.chassis)), row('OS', txt(h.os)), row('Last reported to Tanium', txt(d.seen ? new Date(d.seen).toLocaleString() : null)),
        ...(u ? [row('Primary user', txt(u.primary) + (u.primary_email ? ` <span class="text-muted">${esc(u.primary_email)}</span>` : '')), row('Last signed-in user', txt(u.last))] : [])])}`;
  }

  async function mount(id) {
    let d;
    try {
      const r = await fetch(`/api/v1/devices/${encodeURIComponent(id)}/tanium`, { headers: { Accept: 'application/json' } });
      d = r.ok ? await r.json() : null;
    } catch (err) { d = null; }
    if (!d || !d.available) return;
    const panel = AssetEdr.addTab('tanium', 'Tanium');
    if (!panel) return;
    draw(panel, d);
    if (location.hash === '#tanium') AssetSoftware.show('tanium');
  }
  return { mount, lastPatch };
})();
