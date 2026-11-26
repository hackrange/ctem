// Threat Hunt > IP Address Usage History (api/routes/ip_history.py). GMT by default; "Show in time zone" shows every
// time in the chosen zone and reads the times typed into the form in it too. Everything shown goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const url = new URLSearchParams(location.search);
  const GMT = 'UTC';
  let tz = url.get('tz') || localStorage.getItem('ih-tz') || GMT;
  let person = url.get('user') || '', asset = url.get('device') || '';

  // Time zones: GMT first, then every zone the browser knows
  const zones = (Intl.supportedValuesOf ? Intl.supportedValuesOf('timeZone') : ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'Europe/London'])
    .filter(z => z !== 'UTC');
  if (tz !== GMT && !zones.includes(tz)) tz = GMT;
  $('ih-tz').innerHTML = `<option value="${GMT}">GMT (UTC)</option>` + zones.map(z => `<option value="${esc(z)}">${esc(z.replace(/_/g, ' '))}</option>`).join('');
  $('ih-tz').value = tz;

  const zoneName = () => (tz === GMT ? 'GMT' : tz.replace(/_/g, ' '));
  // An instant shown in the chosen zone, with the zone's short name
  const show = iso => {
    if (!iso) return '--';
    return new Intl.DateTimeFormat('en-GB', { timeZone: tz, year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
      hour12: false, timeZoneName: 'short' }).format(new Date(iso));
  };
  // A wall-clock time typed into a datetime-local box, read in the chosen zone, as GMT ISO
  function toGmt(wall) {
    if (!wall) return '';
    const [d, t] = wall.split('T');
    const [y, mo, da] = d.split('-').map(Number), [h, mi] = (t || '00:00').split(':').map(Number);
    let guess = Date.UTC(y, mo - 1, da, h, mi);
    if (tz !== GMT) {
      for (let i = 0; i < 2; i++) {   // the zone's offset at that moment (daylight saving included)
        const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit',
          day: '2-digit', hour: '2-digit', minute: '2-digit' }).formatToParts(new Date(guess)).map(x => [x.type, x.value]));
        const asIfUtc = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute);
        guess += Date.UTC(y, mo - 1, da, h, mi) - asIfUtc;
      }
    }
    return new Date(guess).toISOString().replace('.000Z', 'Z');
  }
  // A GMT ISO back into the box's wall-clock form in the chosen zone
  function toWall(iso) {
    if (!iso) return '';
    const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit' }).formatToParts(new Date(iso)).map(x => [x.type, x.value]));
    return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}`;
  }
  const labels = () => document.querySelectorAll('[data-zone-label]').forEach(e => { e.textContent = zoneName(); });

  $('ih-ip').value = url.get('ip') || '';
  $('ih-scope').value = url.get('scope') === 'net' ? 'net' : 'exact';
  for (const k of ['at', 'from', 'to']) $(`ih-${k}`).value = toWall(url.get(k));
  labels();

  function filterNote(d) {
    const f = $('ih-filter');
    const bits = [];
    if (asset) bits.push(`asset ${d && d.sightings[0] ? d.sightings[0].asset.hostname_now || d.sightings[0].asset.hostname_then : ''}`);
    if (person) bits.push(`person ${d && d.sightings[0] ? d.sightings[0].person.name_now || d.sightings[0].person.name_then : ''}`);
    f.hidden = !bits.length;
    f.innerHTML = bits.length ? `Showing every address of the ${esc(bits.join(' and '))}. <button type="button" class="dt-link" style="background:none;border:0;padding:0;cursor:pointer" data-clear>Clear</button>` : '';
  }

  async function search() {
    const q = new URLSearchParams();
    const ip = $('ih-ip').value.trim();
    if (ip) q.set('ip', ip);
    if ($('ih-scope').value === 'net') q.set('scope', 'net');
    for (const k of ['at', 'from', 'to']) { const v = toGmt($(`ih-${k}`).value); if (v) q.set(k, v); }
    if (asset) q.set('device', asset);
    if (person) q.set('user', person);
    history.replaceState(null, '', `?${q}${tz !== GMT ? `&tz=${encodeURIComponent(tz)}` : ''}`);
    const box = $('ih-results');
    if (!ip && !asset && !person) { box.textContent = 'Search by an IP address.'; return; }
    box.textContent = 'Searching...';
    try {
      const r = await fetch(`/api/v1/ip-history?${q}&limit=500`, { headers: { Accept: 'application/json' } });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) { box.textContent = typeof d.detail === 'string' ? d.detail : 'That search did not work.'; return; }
      filterNote(d);
      $('ih-since').textContent = d.history_since ? `History kept since ${show(d.history_since)}` : 'No history recorded yet';
      $('ih-title').textContent = `Results (${d.total.toLocaleString()})`;
      if (!d.sightings.length) {
        box.textContent = d.history_since ? 'Nothing held that address in that time.' : 'No history recorded yet: it starts with the first hourly run.';
        return;
      }
      box.classList.remove('text-muted');
      box.innerHTML = `<table class="data-table" style="width:100%;font-size:13px"><thead><tr><th>Held from</th><th>Until</th><th>Address</th>
        <th>Asset</th><th>Person</th><th>How it was attributed</th></tr></thead><tbody>${d.sightings.map(s => `<tr>
        <td style="white-space:nowrap">${esc(show(s.first_seen))}</td><td style="white-space:nowrap">${esc(show(s.last_seen))}</td>
        <td class="text-mono">${esc(s.ip)} <span class="chip chip--${s.kind === 'public' ? 'medium' : 'info'}" style="font-size:.7rem">${s.kind === 'public' ? 'Public' : 'Private'}</span></td>
        <td>${s.asset.id && s.asset.exists ? `<a class="dt-link" href="/devices/${encodeURIComponent(s.asset.id)}">${esc(s.asset.hostname_then || s.asset.hostname_now || 'asset')}</a>` : esc(s.asset.hostname_then || '--')}
          ${s.asset.hostname_now && s.asset.hostname_now !== s.asset.hostname_then ? `<div class="text-muted">now ${esc(s.asset.hostname_now)}</div>` : ''}
          ${s.asset.type ? `<div class="text-muted">${esc(s.asset.type.replace(/_/g, ' '))}</div>` : ''}
          ${s.asset.id ? `<button type="button" class="dt-link" style="background:none;border:0;padding:0;cursor:pointer;font-size:12px" data-asset="${esc(s.asset.id)}">all its addresses</button>` : ''}</td>
        <td>${esc(s.person.name_then || s.person.name_now || '--')}${s.person.upn ? `<div class="text-muted text-mono">${esc(s.person.upn)}</div>` : ''}
          ${s.person.id ? `<button type="button" class="dt-link" style="background:none;border:0;padding:0;cursor:pointer;font-size:12px" data-person="${esc(s.person.id)}">all their addresses</button>` : ''}</td>
        <td class="text-muted">${esc(s.address_how || '')}<div>${esc(s.person_how || '')}</div>${s.sources ? `<div>Seen by: ${esc(s.sources)}</div>` : ''}</td></tr>`).join('')}</tbody></table>`;
    } catch (e) { box.textContent = 'That search did not work.'; }
  }

  $('ih-form').addEventListener('submit', e => { e.preventDefault(); search(); });
  $('ih-tz').addEventListener('change', () => {
    const typed = ['at', 'from', 'to'].map(k => toGmt($(`ih-${k}`).value));   // keep the same instants in the new zone
    tz = $('ih-tz').value;
    localStorage.setItem('ih-tz', tz);
    ['at', 'from', 'to'].forEach((k, i) => { $(`ih-${k}`).value = toWall(typed[i]); });
    labels();
    search();
  });
  $('ih-results').addEventListener('click', e => {
    const a = e.target.closest('[data-asset]'), p = e.target.closest('[data-person]');
    if (!a && !p) return;
    asset = a ? a.dataset.asset : '';
    person = p ? p.dataset.person : '';
    $('ih-ip').value = '';
    search();
  });
  $('ih-filter').addEventListener('click', e => { if (e.target.closest('[data-clear]')) { asset = person = ''; search(); } });
  if ($('ih-ip').value || asset || person) search();
})();
