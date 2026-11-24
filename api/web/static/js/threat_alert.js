// Cyber Threats > alert: the whole story without opening the source console. Everything goes through esc().
(() => {
  const T = ThreatView;
  const $ = id => document.getElementById(id);
  const txt = v => (v == null || v === '' ? '<span class="text-muted">--</span>' : esc(v));
  const mono = v => (v ? `<span class="text-mono text-sm" style="overflow-wrap:anywhere">${esc(v)}</span>` : txt(null));
  const info = (label, html) => `<div style="min-width:0"><dt class="text-sm text-muted">${esc(label)}</dt><dd style="margin:2px 0 0;overflow-wrap:anywhere">${html}</dd></div>`;
  const at = s => (s ? new Date(s).toLocaleString() : '--');
  const show = (id, on) => { $(id).style.display = on ? '' : 'none'; };
  const ICON = { process: '&#9881;', file: '&#128196;', network: '&#127760;', dns: '&#128269;', detection: '&#9888;',
                 action: '&#128737;', alert: '&#128276;', related: '&#128279;', status: '&#9998;' };
  const ACTION_CHIP = a => `<span class="chip chip--low" style="font-size:.75rem">${esc(a)}</span>`;

  function story(a, d) {
    if (!a.story) return;
    const disp = d.disposition || {};
    const meta = [
      d.severity_score != null && `severity ${d.severity_score}/100`,
      d.confidence != null && `confidence ${d.confidence}/100`,
      d.objective && `objective: ${d.objective}`,
      d.scenario && `scenario: ${d.scenario.replace(/_/g, ' ')}`,
    ].filter(Boolean);
    $('al-story').innerHTML = `<p style="margin:0 0 8px">${esc(a.story)}</p>
      ${(a.actions_text || []).length ? `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">${a.actions_text.map(ACTION_CHIP).join('')}</div>` : ''}
      ${disp.summary ? `<div class="text-sm" style="margin-bottom:6px">${esc(disp.summary)}</div>` : ''}
      ${meta.length ? `<div class="text-sm text-muted">${esc(meta.join(' · '))}</div>` : ''}`;
    show('al-story-panel', true);
  }

  function details(a, d) {
    const tactic = a.tactic_id
      ? `<a class="dt-link" href="${esc(T.tacticUrl(a.tactic_id))}" target="_blank" rel="noopener noreferrer">${esc(a.tactic_id)}</a> ${txt(a.tactic)}`
      : txt(a.tactic);
    const technique = a.technique_id ? `${T.mitre(a)} ${txt(a.technique)}` : txt(a.technique);
    const u = d.user || {}, h = d.host || {}, c = a.ctem_device;
    const rows = [
      info('Device', T.device(a)),
      info('Source', esc(T.sourceName(a))),
      info('Detected', T.when(a)),
      info('Status', T.statusChip(a.status) + (d.assigned_to ? ` <span class="text-sm text-muted">assigned to ${esc(d.assigned_to)}</span>` : '')),
      info('MITRE tactic', tactic),
      info('MITRE technique', technique),
    ];
    if (u.name) rows.push(info('User', `${esc(u.domain ? `${u.domain}\\${u.name}` : u.name)}${u.principal ? `<div class="text-sm text-mono">${esc(u.principal)}</div>` : ''}`));
    if (h.os_version || h.platform) rows.push(info('Host OS', txt([h.platform, h.os_version].filter(Boolean).join(' / '))));
    if (h.local_ip || h.external_ip) {
      rows.push(info('Host IPs', [h.local_ip && `<div class="text-sm">Internal: ${mono(h.local_ip)}</div>`,
                                  h.external_ip && `<div class="text-sm">External: ${mono(h.external_ip)}</div>`].filter(Boolean).join('')));
    }
    if (h.domain || h.site) rows.push(info('Domain / site', txt([h.domain, h.site].filter(Boolean).join(' / '))));
    if (h.containment) rows.push(info('Falcon containment', txt(h.containment.replace(/_/g, ' '))));
    if (d.prevalence) rows.push(info('File prevalence', txt(['global ' + (d.prevalence.global || '?'), 'local ' + (d.prevalence.local || '?')].join(', '))));
    if (c) {
      rows.push(info('CTEM risk', `${c.risk_grade ? `<span class="chip chip--info">${esc(c.risk_grade)}</span>` : ''} ${txt(c.risk_score)}`));
      rows.push(info('Open findings on host', `${esc(c.open_findings)}${c.kev_findings ? ` <span class="chip chip--critical">${esc(c.kev_findings)} KEV</span>` : ''}`));
      rows.push(info('Assigned to (CTEM)', txt(c.assigned_to || c.user)));
      if (c.internet_exposed) rows.push(info('Internet exposed', '<span class="chip chip--high">yes</span>'));
    }
    rows.push(info('Alert ID', `<span class="text-mono text-sm">${txt(a.id.replace(/^threat_alert_/, ''))}</span>`));
    $('al-info').innerHTML = rows.join('');
  }

  function timeline(a) {
    const ev = a.timeline || [];
    if (!ev.length) return;
    $('al-timeline').innerHTML = ev.map(e => `<li class="tl__item tl__item--${esc(e.kind)}">
        <span class="tl__icon" aria-hidden="true">${ICON[e.kind] || '&#8226;'}</span>
        <div class="tl__body">
          <div class="text-sm text-muted">${esc(at(e.at))}</div>
          <div>${e.ref ? `<a class="dt-link" href="${esc(T.href({ id: e.ref }))}">${esc(e.title)}</a>` : esc(e.title)}</div>
          ${e.text ? `<div class="text-sm ${e.kind === 'process' ? 'text-mono' : 'text-muted'}" style="overflow-wrap:anywhere">${esc(e.text)}</div>` : ''}
        </div></li>`).join('');
    show('al-timeline-panel', true);
  }

  function proc(label, p, last) {
    if (!p) return '';
    const kv = (k, v, m) => (v != null && v !== '' ? `<div class="text-sm"><span class="text-muted">${esc(k)}:</span> ${m ? mono(v) : esc(v)}</div>` : '');
    return `<div class="ptree__node${last ? ' ptree__node--hit' : ''}">
      <div class="text-sm text-muted">${esc(label)}</div>
      <div style="font-weight:600;overflow-wrap:anywhere">${esc(p.filename || p.filepath || 'unknown')}</div>
      ${kv('Path', p.filepath, true)}${kv('Command line', p.cmdline, true)}${kv('User', p.user)}
      ${kv('PID', p.pid)}${kv('Started', p.start && at(p.start))}${kv('Ended', p.end && at(p.end))}
      ${kv('SHA256', p.sha256, true)}${kv('MD5', p.md5, true)}</div>`;
  }

  function tree(d) {
    const nodes = [['Grandparent', d.grandparent], ['Parent', d.parent], ['Process that triggered the alert', d.process]].filter(n => n[1]);
    if (!nodes.length) return;
    $('al-tree').innerHTML = nodes.map(([l, p], i) => proc(l, p, i === nodes.length - 1)).join('<div class="ptree__arrow" aria-hidden="true">&#8595;</div>');
    show('al-tree-panel', true);
  }

  function indicators(d) {
    const parts = [];
    if (d.ioc) parts.push(`<div style="margin-bottom:10px"><b>Indicator</b> ${txt(d.ioc.type)}: ${mono(d.ioc.value)}
      ${d.ioc.source ? `<span class="text-sm text-muted">from ${esc(d.ioc.source)}</span>` : ''}
      ${d.ioc.description ? `<div class="text-sm">${esc(d.ioc.description)}</div>` : ''}</div>`);
    const list = (title, items, fn) => (items && items.length
      ? `<div style="margin-bottom:10px"><b>${esc(title)}</b><ul style="margin:4px 0 0 18px">${items.map(x => `<li class="text-sm" style="overflow-wrap:anywhere">${fn(x)}</li>`).join('')}</ul></div>` : '');
    parts.push(list('Quarantined', d.quarantined, f => `${esc(f.filename || '')} ${f.sha256 ? mono(f.sha256) : ''} ${f.state ? `<span class="text-muted">(${esc(f.state)})</span>` : ''}`));
    parts.push(list('Files written', d.files_written, f => `${mono(f.filepath || f.filename)} ${f.sha256 ? `<span class="text-muted">${esc(f.sha256.slice(0, 16))}...</span>` : ''}`));
    parts.push(list('Documents opened', d.documents, f => mono(f.filepath || f.filename)));
    parts.push(list('MITRE ATT&CK', d.mitre, m => `${esc(m.tactic_id || '')} ${esc(m.tactic || '')} &rarr; ${m.technique_id ? T.mitre(m) : ''} ${esc(m.technique || '')}`));
    const html = parts.join('');
    if (!html) return;
    $('al-ioc').innerHTML = html;
    show('al-ioc-panel', true);
  }

  function network(d) {
    const net = d.network || [], dns = d.dns || [];
    if (!net.length && !dns.length) return;
    $('al-net').innerHTML = (net.length ? `<div class="dt-scroll"><table class="data-table data-table--striped">
        <thead><tr><th>When</th><th>Direction</th><th>Remote</th><th>Local</th><th>Protocol</th></tr></thead>
        <tbody>${net.map(n => `<tr><td class="text-sm">${esc(at(n.at))}</td><td class="text-sm">${txt(n.direction)}</td>
          <td>${mono(`${n.remote}${n.remote_port != null ? `:${n.remote_port}` : ''}`)}</td>
          <td>${mono(n.local ? `${n.local}${n.local_port != null ? `:${n.local_port}` : ''}` : '')}</td><td class="text-sm">${txt(n.protocol)}</td></tr>`).join('')}</tbody>
      </table></div>` : '')
      + (dns.length ? `<div class="dt-scroll"><table class="data-table data-table--striped">
        <thead><tr><th>When</th><th>DNS lookup</th><th>Type</th></tr></thead>
        <tbody>${dns.map(x => `<tr><td class="text-sm">${esc(at(x.at))}</td><td>${mono(x.domain)}</td><td class="text-sm">${txt(x.type)}</td></tr>`).join('')}</tbody>
      </table></div>` : '');
    show('al-net-panel', true);
  }

  function related(a) {
    const r = a.related || [];
    if (!r.length) return;
    $('al-related').innerHTML = r.map(x => `<tr data-href="${esc(T.href(x))}" style="cursor:pointer">
      <td class="text-sm">${esc(at(x.detected_at))}</td><td>${T.sevChip(x.severity)}</td>
      <td class="text-sm"><a class="dt-link" href="${esc(T.href(x))}">${esc(x.title || x.id)}</a></td>
      <td>${T.mitre(x)}</td><td>${T.statusChip(x.status)}</td></tr>`).join('');
    show('al-related-panel', true);
  }
  document.addEventListener('click', e => {
    const tr = e.target.closest('#al-related tr[data-href]');
    if (tr && !e.target.closest('a')) location.href = tr.dataset.href;
  });

  async function load() {
    const id = new URLSearchParams(location.search).get('id') || '';
    const res = await fetch(`/api/v1/threat/alerts/detail?id=${encodeURIComponent(id)}`, { headers: { Accept: 'application/json' } });
    if (!res.ok) {
      $('al-title').textContent = 'Alert not found';
      $('al-sub').textContent = 'It may have aged out of the source tool.';
      return;
    }
    const a = await res.json();
    const d = a.detail || {};
    document.title = `${a.title || 'Alert'} -- open-ctem`;
    $('al-title').textContent = a.title || a.id;
    $('al-sub').innerHTML = `${T.sevChip(a.severity)} ${T.statusChip(a.status)} ${T.sourceChip(a)}`;
    if (a.link) {
      $('al-actions').innerHTML = `<a class="btn btn--ghost btn--sm" href="${esc(a.link)}" target="_blank" rel="noopener noreferrer">Open in ${esc(T.sourceName(a))} &#8599;</a>`;
    }
    show('al-nodetail', a.source === 'crowdstrike' && !a.has_detail);
    story(a, d);
    details(a, d);
    if (a.description) {
      $('al-desc').textContent = a.description;
      show('al-desc-panel', true);
    }
    timeline(a);
    tree(d);
    indicators(d);
    network(d);
    related(a);
  }
  load();
})();
