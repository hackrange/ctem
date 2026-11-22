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
          <th>Remote address</th><th>Remote port</th><th>Local address</th><th>Local port</th><th>Rule</th></tr></thead><tbody>
        ${rules.map(r => `<tr${r.enabled ? '' : ' style="opacity:.55"'}${r.default ? ' class="fw-default"' : ''}>
            <td class="text-sm text-muted">${r.n == null ? '' : esc(r.n)}</td>
            <td><span class="chip ${CHIP[r.action] || 'chip--info'}">${esc(r.action)}</span></td>
            <td class="text-sm">${esc(r.direction)}</td><td class="text-sm">${esc(r.protocol)}</td>
            <td class="text-sm text-mono">${esc(r.remote)}</td><td class="text-sm text-mono">${esc(r.remote_port)}</td>
            <td class="text-sm text-mono">${esc(r.local)}</td><td class="text-sm text-mono">${esc(r.local_port)}</td>
            <td class="text-sm">${r.default ? `<i>${esc(r.name)}</i>` : esc(r.name || '')}${r.enabled ? '' : ' <span class="text-muted">(disabled)</span>'}${
              r.description ? `<div class="text-muted" style="font-size:.75rem">${esc(r.description)}</div>` : ''}</td></tr>`).join('')
          || '<tr><td colspan="9" class="text-muted text-sm" style="text-align:center;padding:14px">No rules reported.</td></tr>'}
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

  function mount(id) {
    one(id, 'firewall', 'Firewall', firewall);
    one(id, 'usb', 'USB', usb);
    one(id, 'posture', 'Posture', posture);
  }
  return { mount };
})();
