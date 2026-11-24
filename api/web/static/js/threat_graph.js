// Cyber Threats > alert: the story (left: this alert and the alerts tied to it by host, user or process tree, repeats
// folded into one step) beside the attack map (right, attack_map.js). Click a step to map that alert; click a box to
// follow its path. Built from api/core/threat_graph.py; everything goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const SEVC = { critical: 'var(--severity-critical)', high: 'var(--severity-high)', medium: 'var(--severity-medium)',
                 low: 'var(--severity-low)', informational: 'var(--severity-info)' };
  const when = s => (s ? new Date(s).toLocaleString() : '');
  let map = null, shown = null;

  function steps(list, T) {
    $('agp-steps').innerHTML = list.map(s => {
      const times = s.count > 1 ? `${s.count} times, ${when(s.first)} to ${when(s.last)}` : when(s.first);
      return `<div role="button" tabindex="0" class="agp__step${s.current ? ' agp__step--on' : ''}" data-id="${esc(s.id)}" style="--sev:${SEVC[s.severity] || 'var(--border2)'}">
        <div class="agp__step-head"><span class="agp__tactic">${esc(s.tactic || s.technique || 'Alert')}</span>${T.sevChip(s.severity)}</div>
        <div class="agp__title">${esc(s.title || 'Alert')}${s.count > 1 ? ` <span class="chip chip--info" style="font-size:.7rem">&times;${esc(s.count)}</span>` : ''}</div>
        <div class="agp__meta">${esc(times)}</div>
        <div class="agp__meta">${esc(s.hostname || '')}${s.current ? '' : ` &middot; ${esc(s.why)}`}</div>
        <div class="agp__out"><span class="agp__dot${s.status === 'open' ? ' agp__dot--open' : ''}"></span>${s.status === 'open' ? 'Open' : 'Closed'}
          ${s.current ? '<span class="text-muted">&middot; this alert</span>' : `<a class="dt-link" style="margin-left:auto" href="${esc(T.href({ id: s.id }))}">See details &rsaquo;</a>`}</div>
        ${s.link ? `<div class="agp__out" style="justify-content:flex-end;margin-top:2px"><a class="dt-link" href="${esc(s.link)}" target="_blank" rel="noopener noreferrer">Show in CrowdStrike &#8599;</a></div>` : ''}
      </div>`;
    }).join('');
  }

  function title(a) {
    $('agp-title').textContent = `Attack path: ${a.title || 'alert'}${a.hostname ? ` on ${a.hostname}` : ''}`;
  }

  async function pick(id) {
    if (id === shown) return;
    document.querySelectorAll('.agp__step').forEach(b => b.classList.toggle('agp__step--on', b.dataset.id === id));
    const r = await fetch(`/api/v1/threat/alerts/graph?id=${encodeURIComponent(id)}`, { headers: { Accept: 'application/json' } });
    if (!r.ok) return;
    const g = await r.json();
    shown = id;
    title(g);
    map.draw(g.graph);
  }

  function render(a, T) {
    if (!a.graph || !a.graph.nodes.length) return;
    $('al-graph-panel').style.display = '';
    map = AttackMap.mount($('agp-map'));
    steps(a.steps || [], T);
    shown = a.id;
    title(a);
    map.draw(a.graph);
    const box = $('agp-steps');
    box.addEventListener('click', e => {
      if (e.target.closest('a')) return;
      const b = e.target.closest('.agp__step');
      if (b) pick(b.dataset.id);
    });
    box.addEventListener('keydown', e => {
      const b = e.target.closest('.agp__step');
      if (b && !e.target.closest('a') && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); pick(b.dataset.id); }
    });
  }

  window.ThreatGraph = { render };
})();
