// The asset page's Firewall, USB and Posture tabs (admins and cyber): the host firewall's effective ruleset, the
// device control (USB) policy and the EDR's posture checks (disk encryption among them), as the EDR reported them. A tab appears only when the EDR reports that policy for this asset.
// Everything shown goes through esc().
window.AssetEdr = (() => {
  const $ = id => document.getElementById(id);
  const CHIP = { Allow: 'chip--low', Block: 'chip--critical', Watch: 'chip--medium' };

  function addTab(key, label) {
    const bar = document.querySelector('.dev-tabs');
    if (!bar || $(`tab-${key}`)) return null;
    const tab = document.createElement('button');
    Object.assign(tab, { type: 'button', id: `tab-${key}`, textContent: label });
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-controls', `dev-${key}-panel`);
    tab.setAttribute('aria-selected', 'false');
    tab.onclick = () => AssetSoftware.show(key);
    bar.appendChild(tab);
    const panel = document.createElement('div');
    Object.assign(panel, { className: 'panel', id: `dev-${key}-panel`, hidden: true });
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', `tab-${key}`);
    panel.style.cssText = 'padding:0;margin-top:0';
    $('dev-software-panel').after(panel);
    return panel;
  }

  const when = t => (t ? `Reported ${esc(new Date(t).toLocaleString())}` : '');

  function firewall(panel, d) {
    let showOff = false;
    const draw = () => {
      const rules = d.rules.filter(r => showOff || r.enabled);
      const hidden = d.rules.length - rules.length;
      panel.innerHTML = `<div class="panel__header" style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap">
          <span class="panel__title">Host firewall rules <span class="chip ${d.enforced ? 'chip--low' : 'chip--medium'}" style="font-size:.7rem;vertical-align:middle">${esc(d.state)}</span></span>
          <span style="display:flex;gap:10px;align-items:center"><span class="text-sm text-muted">${when(d.reported_at)}</span>
            <label class="tk-radio text-sm"><input type="checkbox" id="fw-off"${showOff ? ' checked' : ''}> Disabled rules${hidden ? ` (${hidden})` : ''}</label></span></div>
        <p class="text-sm text-muted" style="margin:8px 14px">Evaluated top to bottom; the first rule that matches decides. ${d.enforced ? '' : 'The policy isn\'t enforced, so these rules only describe what it would do.'}</p>
        <div style="overflow:auto"><table class="data-table"><thead><tr><th>#</th><th>Action</th><th>Direction</th><th>Protocol</th>
          <th>Remote address</th><th>FQDN</th><th>Remote port</th><th>Local address</th><th>Local port</th><th>Rule</th></tr></thead><tbody>
        ${rules.map(r => `<tr${r.enabled ? '' : ' style="opacity:.55"'}${r.default ? ' class="fw-default"' : ''}>
            <td class="text-sm text-muted">${r.n == null ? '' : esc(r.n)}</td>
            <td><span class="chip ${CHIP[r.action] || 'chip--info'}">${esc(r.action)}</span>${
              r.logged ? '<div class="text-muted" style="font-size:.7rem;margin-top:2px" title="Falcon logs each match">Logged</div>' : ''}</td>
            <td class="text-sm">${esc(r.direction)}</td><td class="text-sm">${esc(r.protocol)}</td>
            <td class="text-sm text-mono">${esc(r.remote)}</td>
            <td class="text-sm text-mono">${r.fqdn ? esc(r.fqdn) : '<span class="text-muted">--</span>'}</td>
            <td class="text-sm text-mono">${esc(r.remote_port)}</td>
            <td class="text-sm text-mono">${esc(r.local)}</td><td class="text-sm text-mono">${esc(r.local_port)}</td>
            <td class="text-sm">${r.default ? `<i>${esc(r.name)}</i>` : esc(r.name || '')}${r.enabled ? '' : ' <span class="text-muted">(disabled)</span>'}${
              r.program ? `<div style="font-size:.75rem">Program: <span class="text-mono">${esc(r.program)}</span></div>` : ''}${
              r.description ? `<div class="text-muted" style="font-size:.75rem">${esc(r.description)}</div>` : ''}</td></tr>`).join('')
          || '<tr><td colspan="10" class="text-muted text-sm" style="text-align:center;padding:14px">No rules reported.</td></tr>'}
        </tbody></table></div>`;
      $('fw-off').onchange = e => { showOff = e.target.checked; draw(); };
    };
    draw();
  }

  function usb(panel, d) {
    const cls = d.classes || [];
    panel.innerHTML = `<div class="panel__header" style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap">
        <span class="panel__title">USB device control <span class="chip ${d.enforced ? 'chip--low' : 'chip--medium'}" style="font-size:.7rem;vertical-align:middle">${esc(d.state)}</span></span>
        <span class="text-sm text-muted">${when(d.reported_at)}</span></div>
      <div style="overflow:auto"><table class="data-table"><thead><tr><th>Device type</th><th>What happens</th><th>Devices allowed anyway</th></tr></thead><tbody>
      ${cls.map(c => `<tr><td class="text-sm"><b>${esc(c.class)}</b></td><td class="text-sm">${esc(c.action)}</td>
          <td class="text-sm">${c.allowed.length ? esc(c.allowed.length) : '<span class="text-muted">None</span>'}</td></tr>`).join('')
        || '<tr><td colspan="3" class="text-muted text-sm" style="text-align:center;padding:14px">The policy sets no device types.</td></tr>'}
      </tbody></table></div>
      ${cls.some(c => c.allowed.length) ? `<div class="panel__header"><span class="panel__title">Authorized devices</span></div>
      <div style="overflow:auto"><table class="data-table"><thead><tr><th>Device type</th><th>Vendor</th><th>Product</th><th>Serial number</th>
        <th>Access</th><th>Ends</th><th>Note</th></tr></thead><tbody>
      ${cls.flatMap(c => c.allowed.map(a => `<tr><td class="text-sm">${esc(c.class)}</td>
          <td class="text-sm">${esc(a.vendor || '')}${a.vendor_id ? ` <span class="text-muted text-mono">${esc(a.vendor_id)}</span>` : ''}</td>
          <td class="text-sm">${esc(a.product || '')}${a.product_id ? ` <span class="text-muted text-mono">${esc(a.product_id)}</span>` : ''}</td>
          <td class="text-sm text-mono">${esc(a.serial || 'Any')}</td><td class="text-sm">${esc(a.action)}</td>
          <td class="text-sm text-muted">${a.expires ? esc(new Date(a.expires).toLocaleDateString()) : 'No end'}</td>
          <td class="text-sm text-muted">${esc(a.description || '')}</td></tr>`)).join('')}</tbody></table></div>` : ''}`;
  }

  function posture(panel, d) {
    const score = v => (v == null ? '--' : `<b>${esc(v)}</b>/100`);
    const res = s => (s.passed === true ? '<span class="chip chip--low">Meets</span>' : s.passed === false
      ? '<span class="chip chip--critical">Doesn\'t meet</span>' : `<span class="chip chip--info">${esc(s.meets || 'Unknown')}</span>`);
    const enc = d.disk_encryption_reported
      ? (d.disk_encryption === true ? 'Disk encryption checks pass' : d.disk_encryption === false ? 'A disk encryption check fails' : 'Disk encryption checked, result unclear')
      : 'The EDR reported no disk encryption check for this host';
    panel.innerHTML = `<div class="panel__header" style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap">
        <span class="panel__title">Posture checks</span><span class="text-sm text-muted">${d.assessed_at ? `Assessed ${esc(new Date(d.assessed_at).toLocaleString())}` : ''}</span></div>
      <div style="display:flex;gap:18px;flex-wrap:wrap;padding:10px 14px" class="text-sm">
        <span>Overall ${score(d.overall)}</span><span>Operating system ${score(d.os)}</span><span>Sensor settings ${score(d.sensor_config)}</span>
        <span class="chip ${d.disk_encryption === true ? 'chip--low' : d.disk_encryption === false ? 'chip--critical' : 'chip--info'}">${esc(enc)}</span></div>
      <div style="overflow:auto"><table class="data-table"><thead><tr><th>Check</th><th>Area</th><th>What it looks for</th><th>Result</th></tr></thead><tbody>
      ${d.signals.map(s => `<tr><td class="text-sm"><b>${esc(s.name)}</b>${s.encryption ? ' <span class="chip chip--medium" style="font-size:.65rem">encryption</span>' : ''}</td>
          <td class="text-sm text-muted">${esc(s.group || (s.kind === 'os' ? 'Operating system' : 'Sensor'))}</td>
          <td class="text-sm text-muted">${esc(s.criteria || '')}</td><td>${res(s)}</td></tr>`).join('')
        || '<tr><td colspan="4" class="text-muted text-sm" style="text-align:center;padding:14px">No checks reported.</td></tr>'}</tbody></table></div>`;
  }

  function pentest(panel, d) {
    const sev = { CRITICAL: 'chip--critical', HIGH: 'chip--high', MEDIUM: 'chip--medium', LOW: 'chip--low' };
    const list = (title, head, rows) => rows.length ? `<div class="panel__header"><span class="panel__title">${esc(title)}</span></div>
      <div style="overflow:auto"><table class="data-table"><thead><tr>${head.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>` : '';
    panel.innerHTML = `<div class="panel__header" style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap">
        <span class="panel__title">Attacker view (autonomous pentest)${d.severity ? ` <span class="chip ${sev[d.severity] || 'chip--info'}" style="font-size:.7rem;vertical-align:middle">${esc(d.severity)}${d.score != null ? ` ${esc(d.score)}` : ''}</span>` : ''}</span>
        <span class="text-sm text-muted">${esc(d.pentest || '')}${d.tested_at ? ` · tested ${esc(new Date(d.tested_at).toLocaleDateString())}` : ''}</span></div>
      ${window.AssetPentest ? AssetPentest.story(d) : ''}
      ${list(`Weaknesses NodeZero has open here (${(d.findings || []).length})`, ['Weakness', 'Score', 'Port', 'Confirmed', 'Last seen'], (d.findings || []).map(f => `<tr>
          <td class="text-sm"><a href="/vulns/${encodeURIComponent(f.vuln_id)}">${esc(f.name || f.cve || '')}</a>${f.cve && f.name !== f.cve ? ` <span class="text-muted text-mono" style="font-size:.75rem">${esc(f.cve)}</span>` : ''}${
            f.kev ? ' <span class="chip chip--critical" style="font-size:.65rem">KEV</span>' : ''}</td>
          <td><span class="chip ${f.score >= 9 ? 'chip--critical' : f.score >= 7 ? 'chip--high' : f.score >= 4 ? 'chip--medium' : 'chip--low'}">${esc(f.score ?? '')}</span></td>
          <td class="text-sm text-mono">${esc(f.ports || '')}</td>
          <td class="text-sm">${f.proved ? '<b>Exploited</b>' : 'Reached'}${f.paths ? ` <span class="text-muted">· ${esc(f.paths)} attack path${f.paths === 1 ? '' : 's'}</span>` : ''}</td>
          <td class="text-sm text-muted">${f.last_seen ? esc(new Date(f.last_seen).toLocaleDateString()) : ''}</td></tr>`))}
      ${(d.open_services || []).length ? `<div class="panel__header"><span class="panel__title">Open services NodeZero found (${d.open_services.length})</span></div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 14px">${d.open_services.map(s => `<span class="chip chip--info text-mono">${esc(s.port)}/${esc(s.protocol || 'tcp')}</span>`).join('')}</div>` : ''}
      <div style="display:flex;gap:18px;flex-wrap:wrap;padding:10px 14px" class="text-sm">
        ${d.domain_controller ? '<span class="chip chip--high">Domain controller</span>' : ''}${d.os ? `<span>OS <b>${esc(d.os)}</b></span>` : ''}
        <span>Open services <b>${esc(d.services ?? '--')}</b></span><span>Weaknesses <b>${esc(d.weaknesses ?? '--')}</b></span>
        <span>Credentials found <b>${esc(d.credentials_found ?? '--')}</b></span>${d.cloud ? `<span>Cloud <b>${esc(d.cloud)}</b></span>` : ''}</div>
      ${list('Attack paths through this asset', ['Impact', 'How', 'Score', 'Found in'], ((d.chains || []).length ? [] : d.attack_paths || []).map(p => `<tr>
          <td class="text-sm"><b>${esc(p.impact || p.impact_type || '')}</b></td><td class="text-sm">${esc(p.name || '')}<div class="text-muted" style="font-size:.75rem">${esc(p.where || '')}</div></td>
          <td><span class="chip ${sev[p.severity] || 'chip--info'}">${esc(p.score ?? '')}</span></td>
          <td class="text-sm text-muted">${p.minutes_to_find != null ? `${esc(p.minutes_to_find)} min` : ''}</td></tr>`))}
      ${list('Credentials it found here', ['Account', 'Type', 'How'], (d.credentials || []).map(c => `<tr>
          <td class="text-sm text-mono">${esc(c.user || '')}${c.domain_admin ? ' <span class="chip chip--critical" style="font-size:.65rem">domain admin</span>' : ''}</td>
          <td class="text-sm">${esc((c.type || '').replace(/_/g, ' ').toLowerCase())}</td>
          <td class="text-sm text-muted">${[c.cracked ? 'cracked' : '', c.proved ? 'proved working' : ''].filter(Boolean).join(', ') || 'found'}</td></tr>`))}
      ${list('Data it could reach', ['Where', 'Type'], (d.data_stores || []).map(s => `<tr><td class="text-sm text-mono">${esc(s.name || '')}${s.port ? `:${esc(s.port)}` : ''}</td>
          <td class="text-sm">${esc(s.type || '')}</td></tr>`))}`;
  }

  async function one(id, kind, label, draw) {
    let d;
    try {
      const r = await fetch(`/api/v1/devices/${encodeURIComponent(id)}/${kind}`, { headers: { Accept: 'application/json' } });
      if (!r.ok) return;   // not for this viewer, or not reported
      d = await r.json();
    } catch (e) { return; }
    if (!d.available) return;
    const panel = addTab(kind, label);
    if (!panel) return;
    draw(panel, d);
    if (location.hash === `#${kind}`) AssetSoftware.show(kind);
  }

  // An existing panel of the page (the cloud firewall) shown as a tab instead
  function adopt(key, label, panel) {
    const bar = document.querySelector('.dev-tabs');
    if (!bar || !panel || $(`tab-${key}`)) return;
    const tab = document.createElement('button');
    Object.assign(tab, { type: 'button', id: `tab-${key}`, textContent: label });
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-controls', panel.id);
    tab.setAttribute('aria-selected', 'false');
    tab.onclick = () => AssetSoftware.show(key);
    bar.insertBefore(tab, $('tab-software') ? $('tab-software').nextSibling : null);
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', tab.id);
    panel.style.marginTop = '0';
    panel.hidden = true;
    $('dev-software-panel').after(panel);
    if (location.hash === `#${key}`) AssetSoftware.show(key);
  }

  function mount(id) {
    one(id, 'firewall', 'Firewall', firewall);
    one(id, 'usb', 'USB', usb);
    one(id, 'posture', 'Posture', posture);
    one(id, 'pentest', 'Pentest', pentest);
  }
  return { mount, adopt, addTab };
})();
