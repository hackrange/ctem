// A Location picker for list pages (admins and cyber): states, cities, offices and AD sites from /api/v1/locations.
// pick(card) narrows the page's filters; nothing shows for people the Sites API doesn't answer. Everything goes through esc().
window.LocationFilter = (() => {
  const KEYS = ['loc_state', 'loc_city', 'loc_office', 'loc_site'];
  async function mount(sel, card, reload) {
    let d;
    try {
      const r = await fetch('/api/v1/locations', { headers: { Accept: 'application/json' } });
      if (!r.ok) return;
      d = await r.json();
    } catch (e) { return; }
    if (!d.locations.length) return;
    const group = (label, items) => (items.length ? `<optgroup label="${esc(label)}">${items.map(([v, t]) => `<option value="${esc(v)}">${esc(t)}</option>`).join('')}</optgroup>` : '');
    sel.innerHTML = '<option value="">All locations</option>'
      + group('States', d.states.map(s => [`loc_state=${s}`, s]))
      + group('Cities', d.cities.map(c => { const [city, st] = c.split('|'); return [`loc_city=${city}|${st}`, [city, st].filter(Boolean).join(', ')]; }))
      + group('Offices', d.offices.map(o => [`loc_office=${o}`, o]))
      + group('AD sites', d.sites.map(s => [`loc_site=${s}`, s]));
    const now = KEYS.find(k => card[k]);
    if (now) sel.value = now === 'loc_city' ? `loc_city=${card.loc_city}|${card.loc_state || ''}` : `${now}=${card[now]}`;
    sel.hidden = false;
    sel.addEventListener('change', () => {
      KEYS.forEach(k => delete card[k]);
      const i = sel.value.indexOf('=');
      if (i > 0) {
        const k = sel.value.slice(0, i), v = sel.value.slice(i + 1);
        if (k === 'loc_city') { const [city, st] = v.split('|'); card.loc_city = city; if (st) card.loc_state = st; } else card[k] = v;
      }
      reload();
    });
  }
  // URL filters a Sites link can carry, shown as chips by the page
  const CHIPS = {
    loc_state: [/^[^<>\x00-\x1f]{1,128}$/, v => `State: ${v}`],
    loc_city: [/^[^<>\x00-\x1f]{1,128}$/, v => `City: ${v}`],
    loc_office: [/^[^<>\x00-\x1f]{1,128}$/, v => `Office: ${v}`],
    loc_site: [/^[^<>\x00-\x1f]{1,128}$/, v => `AD site: ${v}`],
    subnet: [/^[0-9A-Fa-f.:]{2,40}\/\d{1,3}$/, v => `Subnet: ${v}`],
  };
  return { mount, CHIPS };
})();
