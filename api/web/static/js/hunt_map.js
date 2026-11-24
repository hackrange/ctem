// Threat Hunt: each finding's attack map (api/hunt/graph.py) beside its steps, like the alert page. Click a step or a
// box to follow its path. HuntMap.mountAll(container, source) fills every [data-hunt-map] in it. Everything goes
// through esc().
window.HuntMap = (() => {
  async function one(box, source) {
    const idx = box.dataset.huntMap;
    let g;
    try {
      const r = await fetch(`/api/v1/hunt/graph/${encodeURIComponent(source)}/${encodeURIComponent(idx)}`, { headers: { Accept: 'application/json' } });
      if (!r.ok) throw new Error();
      g = await r.json();
    } catch (e) {
      box.style.display = 'none';
      return;
    }
    if (!g.nodes || !g.nodes.length) { box.style.display = 'none'; return; }
    const list = box.querySelector('.agp__steps');
    list.innerHTML = (g.steps || []).map(s => `<div role="button" tabindex="0" class="agp__step" data-node="${esc(s.id)}" style="--sev:var(--severity-high)">
        <div class="agp__step-head"><span class="agp__tactic">Step ${esc(s.n)}</span><span class="chip chip--info" style="font-size:.7rem">${esc(s.source || '')}</span></div>
        <div class="agp__title" style="font-weight:500">${esc(s.what)}</div>
        <div class="agp__meta">${esc(s.time || 'Time unknown')}${s.lookup ? ` &middot; evidence #${esc(s.lookup)}` : ''}</div></div>`).join('');
    const map = AttackMap.mount(box.querySelector('.agp__mapbox'), id => {
      list.querySelectorAll('.agp__step').forEach(c => c.classList.toggle('agp__step--on', c.dataset.node === id));
    });
    map.draw(g);
    const pick = c => { if (c) map.follow(c.dataset.node); };
    list.addEventListener('click', e => pick(e.target.closest('.agp__step')));
    list.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(e.target.closest('.agp__step')); }
    });
  }

  function mountAll(container, source) {
    if (!source || !window.AttackMap) return;
    container.querySelectorAll('[data-hunt-map]').forEach(b => one(b, source));
  }
  return { mountAll };
})();
