// Attack Paths: click an exploit chain or a pivot point for its hosts' worst reachable findings and a link to each
// device; the pivot table sorts by any column. Everything goes through esc().
const APDetail = (() => {
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const GRADE = { critical: 'chip--critical', high: 'chip--high', medium: 'chip--medium', low: 'chip--low' };
  let rows = [], key = null, dir = -1;

  function findings(top) {
    if (!top || !top.length) return '<div class="text-muted ap-find">No reachable findings listed</div>';
    return top.map(f => `<div class="ap-find">${f.kev ? '<span class="chip chip--critical" style="font-size:.68rem">KEV</span> ' : ''}
      ${f.cve ? `<code>${esc(f.cve)}</code> ` : ''}${esc(f.title)}${f.cvss != null ? ` <span class="text-muted">CVSS ${esc(Number(f.cvss).toFixed(1))}</span>` : ''}</div>`).join('');
  }

  const deviceLink = (id, label) => (id && /^[0-9a-f-]{36}$/i.test(id)
    ? `<a class="dt-link" href="/devices/${encodeURIComponent(id)}">${esc(label)} &rsaquo;</a>` : esc(label));

  function side(label, h) {
    const name = h.hostname || h.ip || (h.device_id || '').slice(0, 8);
    return `<div style="margin-bottom:8px"><div class="text-sm"><span class="text-muted">${esc(label)}</span> ${deviceLink(h.device_id, name)}
      ${h.ip && h.hostname ? `<span class="text-muted">${esc(h.ip)}</span>` : ''}</div>${findings(h.top)}</div>`;
  }

  const value = (p, k) => (k === 'host' ? (p.hostname || p.ip_address || '').toLowerCase()
    : k === 'device_type' ? (p.device_type || '') : (p[k] ?? -1));

  function draw() {
    const tb = document.getElementById('pivot-tbody');
    const list = key ? [...rows].sort((a, b) => { const x = value(a, key), y = value(b, key); return (x < y ? -1 : x > y ? 1 : 0) * dir; }) : rows;
    tb.innerHTML = list.map((p, i) => `
      <tr class="ap-pivot" tabindex="0" data-i="${i}" aria-expanded="false">
        <td class="text-sm"><b>${esc(p.hostname || p.ip_address || '--')}</b>${p.ip_address && p.hostname ? `<br><span class="text-muted">${esc(p.ip_address)}</span>` : ''}</td>
        <td class="text-sm text-muted">${esc(p.device_type || '--')}</td>
        <td class="text-sm text-center">${esc(p.reachable_findings)}</td>
        <td class="text-sm text-center">${p.kev_findings > 0 ? `<span class="chip chip--critical">${esc(p.kev_findings)}</span>` : '<span class="text-muted">0</span>'}</td>
        <td>${p.risk_grade ? `<span class="chip ${GRADE[p.pivot_risk] || 'chip--info'}">${esc(p.risk_grade)}</span>` : '--'}</td>
      </tr>
      <tr class="ap-pivot-more-row" style="display:none"><td colspan="5" style="background:var(--surface)">
        ${findings(p.top)}<div style="margin-top:6px">${deviceLink(p.device_id, 'Open device')}</div></td></tr>`).join('');
    document.querySelectorAll('#pivot-table .ap-sort').forEach(th =>
      th.setAttribute('aria-sort', th.dataset.k === key ? (dir > 0 ? 'ascending' : 'descending') : 'none'));
  }

  function sortBy(k) {
    dir = key === k ? -dir : (k === 'host' || k === 'device_type' ? 1 : -1);   // numbers start biggest first
    key = k;
    draw();
  }

  function togglePivot(tr) {
    const more = tr.nextElementSibling, open = tr.getAttribute('aria-expanded') !== 'true';
    tr.setAttribute('aria-expanded', String(open));
    more.style.display = open ? '' : 'none';
  }

  function toggleChain(el) {
    el.classList.toggle('open');
    el.setAttribute('aria-expanded', String(el.classList.contains('open')));
  }

  document.addEventListener('click', e => {
    if (e.target.closest('a')) return;
    const th = e.target.closest('#pivot-table .ap-sort');
    if (th) { sortBy(th.dataset.k); return; }
    const tr = e.target.closest('tr.ap-pivot');
    if (tr) { togglePivot(tr); return; }
    const ch = e.target.closest('.ap-chain');
    if (ch) toggleChain(ch);
  });
  document.addEventListener('keydown', e => {
    if ((e.key !== 'Enter' && e.key !== ' ') || e.target.closest('a')) return;
    const t = e.target;
    if (t.matches('#pivot-table .ap-sort')) { e.preventDefault(); sortBy(t.dataset.k); }
    else if (t.matches('tr.ap-pivot')) { e.preventDefault(); togglePivot(t); }
    else if (t.matches('.ap-chain')) { e.preventDefault(); toggleChain(t); }
  });

  return { side, draw, pivots: list => { rows = list; } };
})();
