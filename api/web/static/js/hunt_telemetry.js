// Threat Hunt > Telemetry: fleet stacks (each distinct process, domain, connection, logon and how many hosts did it)
// and the EDR's real-time events. Everything shown goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const n = v => Number(v || 0).toLocaleString();
  const KIND = { process: 'Process', dns: 'DNS', network: 'Connection', logon: 'Logon', logon_failed: 'Failed logon' };
  let sort = 'hosts', order = 'asc', pending = null, rareAt = 3;

  async function get(url, signal) {
    const r = await fetch(url, { headers: { Accept: 'application/json' }, signal });
    if (!r.ok) throw new Error(r.status);
    return r.json();
  }

  async function stacks() {
    if (pending) pending.abort();
    const mine = pending = new AbortController();
    const q = new URLSearchParams({ days: $('ht-days').value, sort, order, limit: 200 });
    if ($('ht-q').value.trim()) q.set('q', $('ht-q').value.trim());
    if ($('ht-kind').value) q.set('kind', $('ht-kind').value);
    if ($('ht-rare').checked) q.set('rare', 'true');
    if ($('ht-intel').checked) q.set('intel', 'true');
    try {
      const d = await get(`/api/v1/hunt/data/stacks?${q}`, mine.signal);
      if (mine !== pending) return;
      rareAt = d.rare_at;
      $('ht-total').textContent = `${n(d.total)} distinct over ${d.days} day${d.days === 1 ? '' : 's'}`;
      $('ht-rows').innerHTML = d.stacks.map(s => `<tr data-key="${esc(s.key)}" style="cursor:pointer">
          <td class="text-sm">${esc(KIND[s.kind] || s.kind)}</td>
          <td class="text-sm text-mono" style="max-width:520px;overflow-wrap:anywhere">${esc(s.value)}${s.sha256 ? `<div class="text-muted" style="font-size:.7rem">${esc(s.sha256)}</div>` : ''}</td>
          <td class="text-sm">${esc(n(s.hosts))}${s.hosts <= rareAt ? ' <span class="chip chip--medium" style="font-size:.65rem">rare</span>' : ''}</td>
          <td class="text-sm">${esc(n(s.events))}</td><td class="text-sm">${esc(s.days)}</td>
          <td class="text-sm text-muted">${s.last_seen ? esc(new Date(s.last_seen).toLocaleString()) : '--'}</td>
          <td>${s.intel ? '<span class="chip chip--critical">Match</span>' : ''}</td></tr>`).join('')
        || `<tr><td colspan="7" class="text-muted text-sm" style="text-align:center;padding:16px">${
          $('ht-q').value || $('ht-rare').checked || $('ht-intel').checked ? 'Nothing matches.' : 'No telemetry yet. It arrives from the shipper once Falcon Data Replicator is set up on the CrowdStrike source.'}</td></tr>`;
    } catch (e) {
      if (e.name !== 'AbortError') $('ht-rows').innerHTML = '<tr><td colspan="7" class="text-muted text-sm" style="text-align:center;padding:16px">Telemetry could not load.</td></tr>';
    }
  }

  async function detail(key) {
    const box = $('ht-detail');
    box.hidden = false;
    box.innerHTML = '<p class="text-muted text-sm">Loading...</p>';
    let d;
    try { d = await get(`/api/v1/hunt/data/stacks/${encodeURIComponent(key)}?days=${$('ht-days').value}`); } catch (e) { d = null; }
    if (!d) { box.innerHTML = '<p class="text-muted text-sm">Could not load it.</p>'; return; }
    const f = Object.entries(d.fields || {}).filter(([, v]) => v);
    box.innerHTML = `<div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start;flex-wrap:wrap">
        <div><h2 style="margin:0 0 4px;font-size:16px">${esc(KIND[d.kind] || d.kind)}: <span class="text-mono">${esc(d.value)}</span></h2>
          ${d.sha256 ? `<div class="text-sm text-mono text-muted">SHA-256 ${esc(d.sha256)}</div>` : ''}</div>
        <button type="button" class="btn btn--ghost btn--sm" id="ht-close">Close</button></div>
      ${d.intel ? `<div class="text-sm" style="margin:8px 0;padding:8px 10px;border-radius:8px;background:var(--accent-dim)"><b>Threat intel match</b>
        (${esc(d.intel.type)}, ${esc(d.intel.confidence || '')} confidence)${(d.intel.actors || []).length ? ` · adversaries: ${esc(d.intel.actors.join(', '))}` : ''}${
        (d.intel.malware || []).length ? ` · malware: ${esc(d.intel.malware.join(', '))}` : ''}</div>` : ''}
      ${f.length ? `<div class="text-sm" style="margin:6px 0">${f.map(([k, v]) => `<div><span class="text-muted">${esc(k.replace(/_/g, ' '))}:</span> <span class="text-mono">${esc(v)}</span></div>`).join('')}</div>` : ''}
      <div class="text-sm text-muted">Seen ${esc(d.days.map(x => `${x.day} (${n(x.hosts)} hosts)`).join(', '))}${d.capped ? ' · the first 200 hosts a day are listed' : ''}</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">${d.hosts.map(h => h.asset_id
        ? `<a class="chip chip--info" href="/devices/${encodeURIComponent(h.asset_id)}">${esc(h.hostname)}</a>`
        : `<span class="chip chip--info text-mono" title="Not an asset in CTEM yet">${esc(h.edr_id.slice(0, 12))}</span>`).join('')}</div>`;
    $('ht-close').onclick = () => { box.hidden = true; };
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function events() {
    const q = new URLSearchParams({ limit: 200 });
    if ($('he-q').value.trim()) q.set('q', $('he-q').value.trim());
    if ($('he-type').value) q.set('type', $('he-type').value);
    let d;
    try { d = await get(`/api/v1/hunt/data/events?${q}`); } catch (e) { d = null; }
    if (!d) { $('he-rows').innerHTML = '<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:16px">Events could not load.</td></tr>'; return; }
    const cur = $('he-type').value;
    $('he-type').innerHTML = '<option value="">Every type</option>' + d.types.map(t => `<option value="${esc(t)}"${t === cur ? ' selected' : ''}>${esc(t)}</option>`).join('');
    $('he-total').textContent = `${n(d.total)} events`;
    $('he-rows').innerHTML = d.events.map(e => `<tr><td class="text-sm text-muted nowrap">${esc(new Date(e.at).toLocaleString())}</td>
        <td class="text-sm">${esc(e.type)}</td><td class="text-sm">${esc(e.hostname || '')}</td><td class="text-sm">${esc(e.user || '')}</td>
        <td class="text-sm">${esc(e.severity || '')}</td><td class="text-sm">${esc(e.summary || '')}</td></tr>`).join('')
      || '<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:16px">No events yet. They arrive from the shipper\'s CrowdStrike source (Event stream).</td></tr>';
  }

  function tab(which) {
    ['stacks', 'events'].forEach(k => {
      $(`ht-tab-${k}`).setAttribute('aria-selected', String(k === which));
      $(`ht-${k}`).hidden = k !== which;
    });
    if (which === 'events') events();
  }
  $('ht-tab-stacks').onclick = () => tab('stacks');
  $('ht-tab-events').onclick = () => tab('events');
  let typing;
  $('ht-q').addEventListener('input', () => { clearTimeout(typing); typing = setTimeout(stacks, 300); });
  ['ht-kind', 'ht-days', 'ht-rare', 'ht-intel'].forEach(id => $(id).addEventListener('change', stacks));
  document.querySelectorAll('[data-sort]').forEach(b => b.addEventListener('click', () => {
    order = sort === b.dataset.sort ? (order === 'asc' ? 'desc' : 'asc') : (b.dataset.sort === 'value' ? 'asc' : 'desc');
    sort = b.dataset.sort;
    stacks();
  }));
  $('ht-rows').addEventListener('click', e => { const tr = e.target.closest('tr[data-key]'); if (tr) detail(tr.dataset.key); });
  let typing2;
  $('he-q').addEventListener('input', () => { clearTimeout(typing2); typing2 = setTimeout(events, 300); });
  $('he-type').addEventListener('change', events);
  stacks();
})();
