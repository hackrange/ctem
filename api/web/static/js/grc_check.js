// GRC > control check: what the check found to fix, paged and searchable. Everything goes through esc().
(() => {
  const type = decodeURIComponent(location.pathname.split('/').pop() || '');
  const API = `/api/v1/grc/checks/${encodeURIComponent(type)}`;
  const CHIP = { pass: 'chip--low', warning: 'chip--medium', fail: 'chip--critical', error: 'chip--high' };
  const LABEL = { device_type: 'Type', os: 'OS', cve_id: 'CVE', cvss: 'CVSS', kev: 'KEV', ad_last_logon: 'AD last logon', risk_grade: 'Risk grade' };
  let asset = '', table = null;
  // The SLA check's drill-down: the lists behind its numbers, filtered to findings past SLA
  const ASSET_LIST = { workstation: 'device_type=workstation', server: 'device_type=server', network: 'device_type=network_device',
                       cloud: 'asset=cloud', code: 'asset=repositories', web: 'asset=sites', unknown: 'device_type=unknown' };
  const n = v => Number(v || 0).toLocaleString();

  function drill(d) {
    const x = d.details || {};
    if (!x.by_asset) return;
    document.getElementById('ck-drill').hidden = false;
    document.getElementById('ck-links').innerHTML = [
      ['/devices?past_sla=1', 'Devices', 'Devices with a finding past SLA'], ['/vulns?past_sla=1', 'Findings', 'Vulnerabilities with a finding past SLA'],
      ['/vulns/fixes?kind=all&past_sla=1', 'Fixes', 'The fixes that clear past-SLA findings, ranked by the risk they remove']]
      .map(([h, t, title]) => `<a class="btn btn--ghost btn--sm" href="${h}" title="${esc(title)}">${esc(t)}</a>`).join('')
      + '<button type="button" class="btn btn--ghost btn--sm" id="ck-grade-btn" aria-expanded="false" title="Past-SLA findings by risk grade">Risk grade</button>';
    const g = document.getElementById('ck-grades');
    g.innerHTML = '<b>Past SLA by risk grade:</b> ' + (x.by_grade || []).map(r => `<a class="chip chip--${{ F: 'critical', D: 'high', C: 'medium', B: 'low', A: 'info' }[r.grade]}"
      style="text-decoration:none;margin-left:6px" href="/vulns?past_sla=1&grade=${esc(r.grade)}" title="Open the vulnerabilities">${esc(r.grade)} · ${esc(n(r.findings))}</a>`).join('');
    document.getElementById('ck-grade-btn').addEventListener('click', e => {
      g.hidden = !g.hidden;
      e.target.setAttribute('aria-expanded', String(!g.hidden));
    });
    document.getElementById('ck-assets').innerHTML = x.by_asset.map(r => `<div class="stat-tile" style="padding:10px 12px;border:1px solid var(--border);border-radius:6px;
        ${r.findings ? 'cursor:pointer' : 'opacity:.55'}" data-asset="${esc(r.kind)}" role="button" tabindex="${r.findings ? 0 : -1}" aria-pressed="false"
        title="Show only ${esc(r.label.toLowerCase())} in the list below">
      <div class="text-sm text-muted">${esc(r.label)}</div><div style="font-size:1.2rem;font-weight:700">${esc(n(r.findings))}</div>
      <div class="text-sm text-muted">findings on ${esc(n(r.assets))} asset${r.assets === 1 ? '' : 's'}</div>
      ${r.findings ? `<a class="text-sm dt-link" href="/devices?past_sla=1&${ASSET_LIST[r.kind]}" data-stop>Open these assets &rsaquo;</a>` : ''}</div>`).join('');
    document.getElementById('ck-assets').addEventListener('click', e => {
      if (e.target.closest('[data-stop]')) return;
      const t = e.target.closest('[data-asset]');
      if (!t || t.style.opacity) return;
      asset = asset === t.dataset.asset ? '' : t.dataset.asset;
      document.querySelectorAll('#ck-assets [data-asset]').forEach(el => el.setAttribute('aria-pressed', String(el.dataset.asset === asset)));
      document.getElementById('ck-list-title').textContent = asset ? `To remediate: ${t.querySelector('.text-muted').textContent}` : 'To remediate';
      if (table) table.reload(true);
    });
  }
  const label = k => LABEL[k] || k.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase());
  const when = s => (s ? new Date(s).toLocaleString() : '--');
  const cell = v => (v === true ? 'yes' : v === false ? 'no' : v === null || v === undefined || v === '' ? '--' : String(v));

  document.getElementById('ck-csv').href = `${API}/report?format=csv`;

  function header(d) {
    const c = d.check;
    document.title = `${c.name} -- open-ctem`;
    document.getElementById('ck-title').textContent = c.name;
    document.getElementById('ck-sub').textContent = `${c.check_type} · ${c.description}`;
    const rules = (d.curated_rules || []).map(r => esc(r.name)).join(', ');
    document.getElementById('ck-result').innerHTML = `
      <span class="chip ${CHIP[d.result] || 'chip--info'}">${esc(d.result)}</span> ${esc(d.summary)}
      <div class="text-muted" style="margin-top:6px">Measured ${esc(when(d.measured_at))}.
        ${esc(d.all_items.toLocaleString())} item${d.all_items === 1 ? '' : 's'} to remediate${d.truncated ? ' (list capped)' : ''}.
        ${rules ? `Scoped by curated rule: ${rules}.` : ''}</div>`;
  }

  async function start() {
    let first;
    try {
      const res = await fetch(`${API}/items?limit=1`, { headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error();
      first = await res.json();
    } catch (_) {
      document.getElementById('ck-title').textContent = 'Control check not found';
      document.getElementById('ck-result').textContent = 'This check is unknown or you do not have access to it.';
      return;
    }
    header(first);
    drill(first);
    if (!first.columns.length) {
      document.getElementById('ck-table').innerHTML = '<p class="text-muted text-sm" style="padding:16px">This check has no item list.</p>';
      return;
    }
    const columns = first.columns.map(k => ({
      key: k, label: label(k), sort: k,
      render: k === 'hostname' ? r => (r.device_id ? DataTable.R.link(`/devices/${encodeURIComponent(r.device_id)}`, r.hostname) : esc(cell(r.hostname)))
        : (k.endsWith('_seen') || k === 'first_detected') ? r => esc(r[k] ? new Date(r[k]).toLocaleDateString() : '--')
          : r => esc(cell(r[k])),
    }));
    table = DataTable.create({
      mount: document.getElementById('ck-table'), endpoint: `${API}/items`, listKey: 'items', columns,
      defaultSort: first.columns[0], defaultOrder: 'asc', pageSize: 50, syncUrl: true,
      emptyText: first.all_items ? 'No items match' : 'Nothing to remediate',
      params: () => ({ q: document.getElementById('ck-search').value.trim(), ...(asset ? { asset } : {}) }),
      rowHref: r => (r.device_id ? `/devices/${encodeURIComponent(r.device_id)}` : ''),
      onLoad: header,
    });
    let t;
    document.getElementById('ck-search').addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => table.reload(true), 300); });
  }
  start();
})();
