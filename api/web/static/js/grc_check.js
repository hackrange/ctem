// GRC > control check: what the check found to fix, paged and searchable. Everything goes through esc().
(() => {
  const type = decodeURIComponent(location.pathname.split('/').pop() || '');
  const API = `/api/v1/grc/checks/${encodeURIComponent(type)}`;
  const CHIP = { pass: 'chip--low', warning: 'chip--medium', fail: 'chip--critical', error: 'chip--high' };
  const LABEL = { device_type: 'Type', os: 'OS', cve_id: 'CVE', cvss: 'CVSS', kev: 'KEV', ad_last_logon: 'AD last logon' };
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
    const table = DataTable.create({
      mount: document.getElementById('ck-table'), endpoint: `${API}/items`, listKey: 'items', columns,
      defaultSort: first.columns[0], defaultOrder: 'asc', pageSize: 50, syncUrl: true,
      emptyText: first.all_items ? 'No items match' : 'Nothing to remediate',
      params: () => ({ q: document.getElementById('ck-search').value.trim() }),
      rowHref: r => (r.device_id ? `/devices/${encodeURIComponent(r.device_id)}` : ''),
      onLoad: header,
    });
    let t;
    document.getElementById('ck-search').addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => table.reload(true), 300); });
  }
  start();
})();
