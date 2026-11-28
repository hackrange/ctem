// AI Inventory (GET /api/v1/ai/inventory): agents, apps, browser extensions and installed AI software, each with whether
// it's sanctioned; agents also with their owner and what spreads their risk (shared, internet, no owner). Filter by
// state or search. Everything goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const n = v => Number(v || 0).toLocaleString();
  const day = s => (s ? new Date(s).toLocaleDateString() : '--');
  const CHIP = { sanctioned: 'chip--low', unsanctioned: 'chip--critical', unreviewed: 'chip--medium' };
  const WORD = { sanctioned: 'Sanctioned', unsanctioned: 'Unsanctioned', unreviewed: 'Not reviewed' };
  const chip = st => `<span class="chip ${CHIP[st] || 'chip--info'}" style="font-size:.7rem">${esc(WORD[st] || st)}</span>`;
  const ABOUT = {
    agents: 'AI agents people built (from Grip): who owns each, whether it is shared or reaches the internet, and whether it has been reviewed.',
    apps: 'AI apps people use (shadow AI from Grip and FairTPRM), with how many use each.',
    extensions: 'AI browser extensions (from Grip).',
    software: 'AI software installed on assets, from the software inventory. Mark titles approved or unauthorized in Software.',
  };
  let data = null, tab = (location.hash || '').slice(1) || 'agents';

  const cols = {
    agents: [['Agent', a => `<b>${esc(a.name)}</b>${a.platform ? `<div class="text-sm text-muted">${esc(a.platform)}</div>` : ''}`],
      ['Owner', a => a.owner_identity_id ? `<a class="dt-link" href="/identity/person?id=${encodeURIComponent(a.owner_identity_id)}">${esc(a.owner)}</a>`
        : (a.owner ? esc(a.owner) : '<span class="chip chip--high" style="font-size:.7rem">No owner</span>')],
      ['Reach', a => [a.sharing ? esc(a.sharing) : '', a.internet ? 'internet' : ''].filter(Boolean).join(', ') || '--'],
      ['Review', a => chip(a.state)],
      ['Concerns', a => a.concerns.length ? a.concerns.map(c => `<span class="chip chip--high" style="font-size:.7rem;margin:0 4px 2px 0">${esc(c)}</span>`).join('') : '<span class="text-muted">--</span>'],
      ['Last seen', a => day(a.last_seen)]],
    apps: [['App', a => `<b>${esc(a.name)}</b>${a.vendor ? `<div class="text-sm text-muted">${esc(a.vendor)}</div>` : ''}`],
      ['Users', a => n(a.users)], ['Review', a => chip(a.state)], ['Risk', a => esc(a.risk || '--')], ['Source', a => esc(a.source)],
      ['Last seen', a => day(a.last_seen)]],
    extensions: [['Extension', a => `<b>${esc(a.name)}</b>`], ['Users', a => n(a.users)], ['Review', a => chip(a.state)],
      ['Risk', a => esc(a.risk || '--')], ['Last seen', a => day(a.last_seen)]],
    software: [['Software', a => `<a class="dt-link" href="/software?title=${encodeURIComponent(a.id)}"><b>${esc(a.name)}</b></a>${a.vendor ? `<div class="text-sm text-muted">${esc(a.vendor)}</div>` : ''}`],
      ['Assets', a => n(a.assets)], ['Review', a => chip(a.state)], ['Last reported', a => day(a.last_seen)]],
  };

  function tiles() {
    const s = data.summary;
    const t = (label, v, sub, go, warn) => `<button type="button" class="stat-tile" data-go="${go}"${warn ? ' style="border-color:var(--severity-high)"' : ''}>
      <div class="stat-tile__value">${esc(n(v))}</div><div class="stat-tile__label">${esc(label)}</div>${sub ? `<div class="text-sm text-muted">${esc(sub)}</div>` : ''}</button>`;
    $('ai-tiles').innerHTML = [
      t('AI agents', s.agents.total, `${n(data.agents_with_concerns)} with concerns, ${n(s.agents.unreviewed)} not reviewed`, 'agents', data.agents_with_concerns > 0),
      t('AI apps', s.apps.total, `${n(s.apps.unsanctioned + s.apps.unreviewed)} not sanctioned`, 'apps'),
      t('AI browser extensions', s.extensions.total, `${n(s.extensions.unsanctioned + s.extensions.unreviewed)} not sanctioned`, 'extensions'),
      t('Installed AI software', s.software.total, `${n(s.software.unsanctioned)} unauthorized, ${n(s.software.unreviewed)} not reviewed`, 'software', s.software.unsanctioned > 0),
    ].join('');
  }

  function draw() {
    document.querySelectorAll('.ai-tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    $('ai-about').textContent = ABOUT[tab];
    const st = $('ai-state').value, q = $('ai-q').value.trim().toLowerCase();
    const rows = (data.sections[tab] || []).filter(r => (!st || (st === 'concerns' ? (r.concerns || []).length : r.state === st))
      && (!q || [r.name, r.owner, r.vendor, r.platform].filter(Boolean).join(' ').toLowerCase().includes(q)));
    const c = cols[tab];
    $('ai-table').innerHTML = rows.length
      ? `<table class="data-table"><thead><tr>${c.map(([h]) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${
          rows.map(r => `<tr>${c.map(([, f]) => `<td class="text-sm">${f(r)}</td>`).join('')}</tr>`).join('')}</tbody></table>`
        + `<p class="text-sm text-muted" style="padding:8px 14px;margin:0">${esc(n(rows.length))} shown</p>`
      : '<p class="text-muted text-sm" style="padding:24px;text-align:center">Nothing matches.</p>';
  }

  document.addEventListener('click', e => {
    const b = e.target.closest('.ai-tab, [data-go]');
    if (!b || !data) return;
    tab = b.dataset.tab || b.dataset.go;
    history.replaceState(null, '', `#${tab}`);
    draw();
  });
  $('ai-state').addEventListener('change', () => data && draw());
  $('ai-q').addEventListener('input', () => data && draw());

  (async () => {
    try {
      const r = await fetch('/api/v1/ai/inventory', { headers: { Accept: 'application/json' } });
      if (!r.ok) throw new Error(r.status);
      data = await r.json();
      tiles();
      draw();
    } catch (e) {
      $('ai-table').innerHTML = '<p class="text-muted text-sm" style="padding:24px;text-align:center">Could not load the AI inventory.</p>';
    }
  })();
})();
