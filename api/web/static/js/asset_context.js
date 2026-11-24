// The asset page's Context tab (admins and cyber, api/routes/device_context.py): where CTEM thinks the asset is and
// why, which tools see it, who shares its public address, and its neighbors on the same /24. Everything goes through esc().
window.AssetContext = (() => {
  const TOOLS = [['scanner', 'Scanner'], ['edr', 'EDR'], ['directory', 'Directory'], ['pentest', 'Pentest'], ['cloud', 'Cloud']];
  const CONF = { high: 'chip--low', medium: 'chip--medium', low: 'chip--high' };
  const yes = (on, label) => `<span class="chip ${on ? 'chip--info' : ''}" style="font-size:.68rem;${on ? '' : 'opacity:.45;text-decoration:line-through'}" title="${esc(label)}${on ? ' sees it' : ' does not see it'}">${esc(label)}</span>`;
  const tools = c => TOOLS.map(([k, l]) => yes(c && c[k], l)).join(' ');

  function where(loc) {
    const place = [loc.city, loc.state].filter(Boolean).join(', ');
    const bits = [place && `<b>${esc(place)}</b>`, loc.office && `office <b>${esc(loc.office)}</b>`, loc.site && `AD site <b>${esc(loc.site)}</b>`].filter(Boolean);
    if (!bits.length) {
      return `<p class="text-sm" style="margin:0">No location yet. CTEM infers it from the EDR's AD site, the offices of the people who sign in,
        and the neighbors below; shipper 1.6.0 sends the first two.</p>`;
    }
    return `<div class="text-sm">Likely ${bits.join(' · ')} ${loc.confidence ? `<span class="chip ${CONF[loc.confidence] || ''}" style="font-size:.7rem">${esc(loc.confidence)} confidence</span>` : ''}</div>
      ${(loc.evidence || []).length ? `<ul class="text-sm text-muted" style="margin:6px 0 0 18px">${loc.evidence.map(e => `<li>${esc(e)}</li>`).join('')}</ul>` : ''}`;
  }

  function draw(panel, d) {
    const n = d.neighbors || [];
    const cov = d.subnet_coverage || {};
    const total = d.neighbors_total || 0;
    const pub = d.public_ip;
    panel.innerHTML = `<div class="panel__header"><span class="panel__title">Where it is</span></div>
      <div style="padding:8px 14px">${where(d.location || {})}
        ${d.location && d.location.edr_ou ? `<div class="text-sm text-muted" style="margin-top:4px">EDR OUs: ${esc(d.location.edr_ou)}</div>` : ''}</div>
      <div class="panel__header"><span class="panel__title">Which tools see it</span></div>
      <div style="padding:8px 14px">${tools(d.coverage)}
        ${(d.gaps || []).map(g => `<div class="text-sm" style="margin-top:6px;color:var(--accent)"><b>${esc(g)}</b></div>`).join('')}</div>
      ${pub ? `<div class="panel__header"><span class="panel__title">Internet address</span></div>
        <div class="text-sm" style="padding:8px 14px">Reaches the internet from <span class="text-mono">${esc(pub.address || '')}</span>,
          shared with <b>${esc(pub.shared_with)}</b> other asset${pub.shared_with === 1 ? '' : 's'}${(pub.places || []).length
            ? `: ${pub.places.map(([p, c]) => `${esc(p)} (${esc(c)})`).join(', ')}` : ''}.</div>` : ''}
      <div class="panel__header"><span class="panel__title">Neighbors on ${esc(d.subnet || 'its subnet')} (${esc(total)})</span></div>
      ${!d.subnet ? '<p class="text-sm text-muted" style="padding:8px 14px">No internal address on file, so no neighbors to show.</p>'
        : !total ? '<p class="text-sm text-muted" style="padding:8px 14px">No other asset you can see is on this subnet.</p>'
        : `<p class="text-sm text-muted" style="padding:6px 14px 0">Of these, the scanner sees ${esc(cov.scanner || 0)}, the EDR ${esc(cov.edr || 0)},
            the directory ${esc(cov.directory || 0)} and the pentest ${esc(cov.pentest || 0)}${total > n.length ? ` (first ${esc(n.length)} shown, riskiest first)` : ''}.</p>
          <div style="overflow:auto"><table class="data-table"><thead><tr><th>Asset</th><th>IP</th><th>Type</th><th>Where</th><th>Owner</th><th>Seen by</th><th>Grade</th><th>Open</th></tr></thead><tbody>
          ${n.map(x => `<tr><td class="text-sm"><a href="/devices/${encodeURIComponent(x.id)}#context">${esc(x.name || '')}</a>${
              (x.gaps || []).length ? ` <span class="chip chip--high" style="font-size:.62rem" title="${esc(x.gaps.join('; '))}">gap</span>` : ''}<div class="text-muted" style="font-size:.72rem">${esc(x.os || '')}</div></td>
            <td class="text-sm text-mono">${esc(x.ip || '')}</td><td class="text-sm">${esc((x.type || '').replace(/_/g, ' '))}</td>
            <td class="text-sm">${esc(x.place || '')}${x.site ? `<div class="text-muted" style="font-size:.72rem">AD site ${esc(x.site)}</div>` : ''}</td>
            <td class="text-sm">${esc(x.owner || '')}${(x.owner_tags || []).map(t => `<div class="text-muted" style="font-size:.72rem">${esc(t.replace(/^owner:/i, ''))}</div>`).join('')}</td>
            <td style="white-space:nowrap">${tools(x.coverage)}</td><td class="text-sm">${esc(x.grade || '')}</td>
            <td class="text-sm">${esc(x.open_findings ?? '')}${x.kev ? ` <span class="chip chip--critical" style="font-size:.62rem">${esc(x.kev)} KEV</span>` : ''}</td></tr>`).join('')}
          </tbody></table></div>`}`;
  }

  async function mount(id) {
    let d;
    try {
      const r = await fetch(`/api/v1/devices/${encodeURIComponent(id)}/context`, { headers: { Accept: 'application/json' } });
      if (!r.ok) return;   // not for this viewer
      d = await r.json();
    } catch (e) { return; }
    const panel = AssetEdr.addTab('context', 'Context');
    if (!panel) return;
    draw(panel, d);
    if (location.hash === '#context') AssetSoftware.show('context');
  }
  return { mount };
})();
