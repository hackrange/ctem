// Fixes: each patch, upgrade or rollup once, ranked by the risk it removes, with the vulnerabilities it resolves.
// Everything from the server goes through esc(); links are http(s) only and open in a new tab.
(() => {
  const $ = id => document.getElementById(id);
  const n = v => (v == null ? '--' : Number(v).toLocaleString());
  const init = new URLSearchParams(location.search);
  const KINDS = ['infra', 'code', 'all'];
  let kind = KINDS.includes(init.get('kind')) ? init.get('kind') : 'infra';
  let sev = ['kev', 'critical', 'exploitable'].includes(init.get('severity')) ? init.get('severity') : '';
  let sort = 'risk', offset = 0, picked = init.get('key') || '', pending = null;
  const LIMIT = 50;
  $('fx-q').value = init.get('q') || '';

  const press = (group, attr, val) => document.querySelectorAll(`#${group} [data-${attr}]`)
    .forEach(b => b.setAttribute('aria-pressed', String(b.dataset[attr] === val)));

  function remember() {
    const q = new URLSearchParams({ kind });
    if (sev) q.set('severity', sev);
    if ($('fx-q').value.trim()) q.set('q', $('fx-q').value.trim());
    if (picked) q.set('key', picked);
    history.replaceState(null, '', `?${q}`);
  }

  async function get(url) {
    const r = await fetch(url, { headers: { Accept: 'application/json' }, signal: pending && pending.signal });
    if (r.status === 401) { location.href = `/login?next=${encodeURIComponent(location.pathname + location.search)}`; return null; }
    if (!r.ok) throw new Error(r.status);
    return r.json();
  }

  async function load() {
    remember();
    if (pending) pending.abort();
    const mine = pending = new AbortController();
    const q = new URLSearchParams({ kind, sort, limit: LIMIT, offset });
    if (sev) q.set('severity', sev);
    if ($('fx-q').value.trim()) q.set('q', $('fx-q').value.trim());
    $('fx-rows').style.opacity = '.5';
    try {
      const d = await get(`/api/v1/fixes?${q}`);
      if (mine !== pending || !d) return;
      rows(d);
    } catch (e) {
      if (mine !== pending || e.name === 'AbortError') return;
      $('fx-rows').innerHTML = '<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:16px">Fixes could not load. Try again in a minute.</td></tr>';
    } finally {
      if (mine === pending) { pending = null; $('fx-rows').style.opacity = ''; }
    }
  }

  function rows(d) {
    $('fx-sum').innerHTML = `<span><b>${esc(n(d.total))}</b> fixes</span><span><b>${esc(n(d.findings_covered))}</b> findings they resolve</span>`
      + (d.scoped ? '<span>For the assets you can see</span>' : '');
    const top = Math.max(1, ...d.fixes.map(f => f.findings));
    $('fx-rows').innerHTML = d.fixes.map(f => `<tr data-key="${esc(f.key)}" class="${f.key === picked ? 'is-picked' : ''}" style="cursor:pointer">
        <td class="text-sm"><a class="dt-link" href="?kind=${kind}&key=${encodeURIComponent(f.key)}">${esc(f.title.slice(0, 110))}</a>
          ${f.kind === 'rollup' ? ' <span class="chip" style="font-size:.65rem" title="Supersedes older patches">rollup</span>' : ''}
          <div class="fx-bar" style="width:${Math.max(2, f.findings / top * 100).toFixed(1)}%" aria-hidden="true"></div></td>
        <td class="text-sm">${esc(n(f.vulns))}</td>
        <td class="text-sm">${f.kev ? `<span class="chip chip--critical" style="font-size:.65rem">${esc(n(f.kev))}</span>` : '0'}</td>
        <td class="text-sm">${f.critical ? `<span class="chip chip--critical" style="font-size:.65rem">${esc(n(f.critical))}</span>` : '0'}</td>
        <td class="text-sm">${esc(n(f.devices))}</td><td class="text-sm">${esc(n(f.findings))}</td></tr>`).join('')
      || `<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:16px">${
        d.total === 0 && !sev && !$('fx-q').value ? 'No fixes recorded yet. They arrive with each source\'s next full sync.' : 'No fixes match.'}</td></tr>`;
    const end = Math.min(offset + LIMIT, d.total);
    $('fx-page').textContent = d.total ? `${n(offset + 1)} to ${n(end)} of ${n(d.total)}` : '';
    $('fx-prev').disabled = offset === 0;
    $('fx-next').disabled = end >= d.total;
  }

  async function detail(key) {
    picked = key;
    remember();
    document.querySelectorAll('#fx-rows tr[data-key]').forEach(tr => tr.classList.toggle('is-picked', tr.dataset.key === key));
    const box = $('fx-detail');
    box.hidden = false;
    box.innerHTML = '<div class="text-muted text-sm">Loading...</div>';
    let d;
    try {
      const r = await fetch(`/api/v1/fixes/detail?key=${encodeURIComponent(key)}`, { headers: { Accept: 'application/json' } });
      d = r.ok ? await r.json() : null;
    } catch (e) { d = null; }
    if (picked !== key) return;
    if (!d || !d.ok) { box.innerHTML = `<div class="text-muted text-sm">${esc((d && d.error) || 'That fix could not load.')}</div>`; return; }
    const kev = d.vulns.filter(v => v.kev).length;
    box.innerHTML = `<div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start">
        <div><h2>${esc(d.title)}</h2>
          <div class="text-sm text-muted">${d.kind ? `${esc(d.kind)} · ` : ''}from ${esc(String(d.source).replace(/_/g, ' '))} ·
            resolves ${esc(n(d.vulns.length))} vulnerabilities${kev ? ` (${esc(n(kev))} known exploited)` : ''} on ${esc(n(d.devices))} assets</div></div>
        <div style="display:flex;gap:8px;flex-shrink:0">
          <a class="btn btn--primary btn--sm" href="/devices?asset=${d.source === 'github_code_review' ? 'repositories' : 'hosts'}&fix=${encodeURIComponent(d.key)}">View the ${esc(n(d.devices))} assets</a>
          <button type="button" class="btn btn--ghost btn--sm" id="fx-close">Close</button></div></div>
      ${d.steps ? `<div class="fx-steps">${esc(d.steps)}</div>` : ''}
      ${d.links.length ? `<div class="text-sm">${d.links.map(u => `<a class="dt-link" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u.replace(/^https?:\/\//, '').slice(0, 80))}</a>`).join('<br>')}</div>` : ''}
      <table class="data-table" style="margin-top:12px"><thead><tr><th>Vulnerability it resolves</th><th>CVSS</th><th>Assets</th></tr></thead><tbody>
      ${d.vulns.map(v => `<tr><td class="text-sm"><a class="dt-link" href="/vulns/${encodeURIComponent(v.id)}">${v.cve_id ? `<b>${esc(v.cve_id)}</b> ` : ''}${esc(v.title.slice(0, 100))}</a>
          ${v.kev ? ' <span class="chip chip--critical" style="font-size:.65rem">KEV</span>' : ''}${v.exploit ? ' <span class="chip chip--high" style="font-size:.65rem">exploit</span>' : ''}</td>
          <td class="text-sm">${esc(v.cvss ?? '--')}</td><td class="text-sm">${esc(n(v.devices))}</td></tr>`).join('')}</tbody></table>`;
    $('fx-close').addEventListener('click', () => { box.hidden = true; picked = ''; remember();
      document.querySelectorAll('#fx-rows tr.is-picked').forEach(tr => tr.classList.remove('is-picked')); });
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  $('fx-kind').addEventListener('click', e => {
    const b = e.target.closest('[data-kind]');
    if (!b || b.dataset.kind === kind) return;
    kind = b.dataset.kind; offset = 0; press('fx-kind', 'kind', kind); load();
  });
  $('fx-sev').addEventListener('click', e => {
    const b = e.target.closest('[data-sev]');
    if (!b || b.dataset.sev === sev) return;
    sev = b.dataset.sev; offset = 0; press('fx-sev', 'sev', sev); load();
  });
  document.querySelectorAll('[data-sort]').forEach(b => b.addEventListener('click', () => { sort = b.dataset.sort; offset = 0; load(); }));
  let typing;
  $('fx-q').addEventListener('input', () => { clearTimeout(typing); typing = setTimeout(() => { offset = 0; load(); }, 300); });
  $('fx-prev').addEventListener('click', () => { offset = Math.max(0, offset - LIMIT); load(); });
  $('fx-next').addEventListener('click', () => { offset += LIMIT; load(); });
  $('fx-rows').addEventListener('click', e => {
    const tr = e.target.closest('tr[data-key]');
    if (!tr) return;
    e.preventDefault();
    detail(tr.dataset.key);
  });

  press('fx-kind', 'kind', kind);
  press('fx-sev', 'sev', sev);
  load();
  if (picked) detail(picked);
})();
