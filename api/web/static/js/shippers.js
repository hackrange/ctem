// Shippers page: profiles, approval state, sealed secrets, installers.
const API = '/api/v1/collectors';
const SOURCES = {
  ldap: { label: 'LDAP / Active Directory', fields: [
    { key: 'host', label: 'Server', ph: 'dc001.acme.example', req: true },
    { key: 'port', label: 'Port (blank = auto)', type: 'number', ph: '636' },
    { key: 'tls', label: 'TLS', type: 'select', opts: [['', 'Auto (LDAPS, then StartTLS)'], ['ldaps', 'LDAPS'], ['starttls', 'StartTLS']] },
    { key: 'bind_user', label: 'Bind user', ph: 'ACME\\svc-ctem', req: true },
    { key: 'base_dn', label: 'Base DN (blank = detect)', ph: 'DC=acme,DC=example' },
  ], secrets: { password: 'Bind password' } },
  rapid7_console: { label: 'Rapid7 InsightVM console', fields: [
    { key: 'host', label: 'Console host', ph: 'console001.acme.example', req: true },
    { key: 'port', label: 'Port', type: 'number', ph: '3780' },
    { key: 'username', label: 'Username', ph: 'svc-ctem', req: true },
    { key: 'vuln_catalog_hours', label: 'Vuln catalog every (hours)', type: 'number', ph: '24' },
    { key: 'software_hours', label: 'Software every (hours, 0 = off)', type: 'number', ph: '24' },
  ], secrets: { password: 'Console password' } },
  crowdstrike: { label: 'CrowdStrike Falcon', fields: [
    { key: 'cloud', label: 'Cloud', type: 'select', opts: [['us-1', 'us-1'], ['us-2', 'us-2'], ['eu-1', 'eu-1'], ['us-gov-1', 'us-gov-1']] },
    { key: 'client_id', label: 'API client ID', ph: '32 hex characters', req: true },
    // Each Falcon product a checkbox (on is skipped with a note if it isn't licensed or the API client lacks its scope)
    ...[['policies', 'Policies (prevention, firewall, USB)'], ['posture', 'Zero Trust Assessment'], ['spotlight', 'Spotlight vulnerabilities'],
        ['discover', 'Discover applications'], ['alerts', 'Alerts (endpoint, identity...)'], ['intel', 'Intel indicators'],
        ['event_stream', 'Event stream (real time)']].map(([key, label]) => ({ key, label: `Pull ${label}`, type: 'onoff' })),
    { key: 'alert_updates', label: 'Alert updates from CTEM (needs Alerts: Write; approve on the box)', type: 'select', opts: [['', 'Off (read only)'], ['on', 'On: cyber and admin can close, classify and comment']] },
    { key: 'fdr', label: 'Falcon Data Replicator (hunting)', type: 'select', opts: [['off', 'Off'], ['on', 'On']] },
    { key: 'fdr_queue_url', label: 'FDR SQS queue URL', ph: 'https://sqs.us-west-1.amazonaws.com/123456789012/acme-fdr', wide: true },
    { key: 'fdr_region', label: 'FDR region', ph: 'us-west-1' },
    { key: 'fdr_access_key_id', label: 'FDR access key ID', ph: 'AKIA...' },
  ], secrets: { client_secret: 'API client secret', fdr_secret_key: 'FDR secret access key' } },
  splunk: { label: 'Splunk (local search head)', fields: [
    { key: 'host', label: 'Management host', ph: 'splunk001.acme.example', req: true },
    { key: 'port', label: 'Port', type: 'number', ph: '8089' },
    { key: 'username', label: 'Username', ph: 'svc-ctem', req: true },
    { key: 'query', label: 'Notable events SPL', ph: 'search index=wineventlog ... | table _time, host, source, _raw', wide: true },
    { key: 'max_events', label: 'Max events per run', type: 'number', ph: '5000' },
    { key: 'forward_alerts', label: 'Send CTEM alerts to Splunk', type: 'select', opts: [['off', 'Off'], ['hec', 'To the HEC'],
      ['file', 'To a file for a Universal Forwarder'], ['both', 'Both']] },
    { key: 'hec_host', label: 'HEC host (blank = the management host)', ph: 'splunk001.acme.example' },
    { key: 'hec_port', label: 'HEC port', type: 'number', ph: '8088' },
    { key: 'hec_index', label: 'HEC index (blank = the token\'s default)', ph: 'ctem' },
  ], secrets: { password: 'Splunk password', hec_token: 'HEC token (for CTEM alerts)' } },
  netprobe: { label: 'Network discovery (ping and common ports)', fields: [
    { key: 'cron', label: 'When (cron, UTC)', ph: '0 2 * * *  (02:00 every day)' },
    { key: 'ports', label: 'Ports (common ones only, up to 40)', ph: '21,22,23,25,53,80,443,445,3389,...', wide: true },
    { key: 'sweep_subnets', label: 'Sweep their /24s for unknown devices', type: 'select', opts: [['on', 'On'], ['off', 'Off (known addresses only)']] },
    { key: 'exclude_cidrs', label: 'Never touch (CIDRs; approved on the box)', ph: '10.40.0.0/16, 10.82.200.0/24', wide: true },
    { key: 'timeout_ms', label: 'Timeout per host (ms)', type: 'number', ph: '600' },
    { key: 'concurrency', label: 'Hosts at a time', type: 'number', ph: '32' },
    { key: 'max_hosts', label: 'Most addresses per run', type: 'number', ph: '4096' },
  ], secrets: {} },
};

// Each source can run on its own clock; blank follows the shipper's schedule
const EVERY = { key: 'schedule_minutes', label: 'Run every', type: 'select', num: true, opts: [['', 'Shipper schedule'],
  ...[5, 10, 15, 30, 60, 120, 240, 300, 360, 720, 1440].map(n => [String(n), n < 60 ? `${n} minutes` : `${n / 60} hour${n === 60 ? '' : 's'}`])] };
for (const [kind, def] of Object.entries(SOURCES)) if (kind !== 'netprobe') def.fields.push(EVERY);   // discovery runs on its cron

let _shippers = [];
let _editId = null;
let _sealing = null;
let _installFor = null;

async function api(path, opts = {}) {
  const res = await fetch(API + path, { headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, ...opts });
  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.detail || `Request failed (${res.status})`);
  }
  return res;
}

function chip(text, cls) { return `<span class="chip chip--${cls}">${esc(text)}</span>`; }

function ago(iso) {
  if (!iso) return 'never';
  const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  return m < 1 ? 'just now' : m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago`;
}

function sourceBlock(p, kind, m) {
  const def = SOURCES[kind];
  const s = m.settings || {};
  const where = (kind === 'crowdstrike' ? `cloud ${s.cloud}` : `${s.host}${s.port ? ':' + s.port : ''}`)
    + ` · every ${s.schedule_minutes || p.schedule_minutes} min`;
  const appr = m.approval === 'approved' ? chip('destination approved', 'low')
    : m.approval === 'pending' ? chip('waiting for approve on the box', 'medium') : chip('not enrolled yet', 'info');
  const secrets = Object.entries(def.secrets).map(([field, label]) => {
    const st = (m.secrets || {})[field] || {};
    const state = st.set ? (st.current_key ? `set ${ago(st.updated_at)} by ${esc(st.by || '?')}` : 'sealed to an old key, re-enter')
      : 'not set';
    const can = p.shipper ? '' : ' disabled title="Enroll the box first"';
    return `<div class="sh-row text-sm" style="margin-top:6px"><span>${esc(label)}: <b>${state}</b></span>
      <button class="btn btn--ghost btn--sm" data-action="secret" data-id="${esc(p.id)}" data-kind="${esc(kind)}"
        data-field="${esc(field)}"${can}>${st.set ? 'Rotate' : 'Set'}</button></div>`;
  }).join('');
  return `<div class="sh-src"><div class="sh-row" style="justify-content:space-between">
      <b>${esc(def.label)}</b>${m.enabled === false ? chip('disabled', 'info') : appr}</div>
    <div class="text-sm text-muted">${esc(where)}</div>${secrets}</div>`;
}

function card(p) {
  const sh = p.shipper;
  const status = !sh ? chip('waiting for install', 'medium')
    : sh.last_error ? chip('problem', 'critical') : chip('checking in', 'low');
  const box = !sh ? `<div class="text-sm text-muted">Download the installer and run it on the internal box.</div>`
    : `<div class="text-sm">Box <b>${esc(sh.host || '?')}</b> (${esc(sh.last_seen_ip || '?')}), last check-in ${ago(sh.last_seen)},
        agent ${esc(sh.agent_version || '?')}</div>
       <div class="text-sm text-muted">Key fingerprint <span class="sh-fp">${esc(ShipperCrypto.pretty(sh.key_fp))}</span></div>
       ${sh.last_error ? `<div class="text-sm" style="color:var(--severity-critical);margin-top:4px">${esc(sh.last_error)}</div>` : ''}`;
  const mods = Object.entries(p.modules || {}).map(([k, m]) => sourceBlock(p, k, m)).join('');
  return `<div class="panel" style="margin:0">
    <div class="sh-row" style="justify-content:space-between;margin-bottom:8px">
      <div><div style="font-weight:600;font-size:1.05rem">${esc(p.name)}</div>
        <div class="text-sm text-muted">every ${esc(p.schedule_minutes)} min, config v${esc(p.config_version)}</div></div>${status}</div>
    ${box}${mods}
    <div class="sh-row" style="margin-top:12px">
      <button class="btn btn--ghost btn--sm" data-action="edit" data-id="${esc(p.id)}">Edit</button>
      <button class="btn btn--ghost btn--sm" data-action="installer" data-id="${esc(p.id)}">${sh ? 'Re-install' : 'Download installer'}</button>
      ${sh ? `<button class="btn btn--ghost btn--sm" data-action="revoke" data-id="${esc(p.id)}">Revoke box</button>` : ''}
      <button class="btn btn--ghost btn--sm" style="color:var(--severity-critical)" data-action="delete" data-id="${esc(p.id)}">Delete</button>
    </div></div>`;
}

async function load() {
  const el = document.getElementById('shippers');
  try {
    _shippers = (await (await api('')).json()).shippers || [];
    el.innerHTML = _shippers.length ? _shippers.map(card).join('')
      : '<div class="panel text-muted" style="text-align:center;padding:32px">No shippers yet. Click <b>+ New shipper</b>.</div>';
  } catch (e) {
    el.innerHTML = '<div class="panel text-muted" style="text-align:center;padding:32px">Could not load shippers</div>';
  }
}

function field(kind, f, val) {
  const id = `f-${kind}-${f.key}`;
  const v = val == null ? '' : val;
  if (f.type === 'onoff') {   // "on" unless saved "off"; sent as on/off, the shipper's own setting
    return `<label class="sh-label" style="display:flex;align-items:center;gap:8px;cursor:pointer">
      <input id="${id}" type="checkbox"${String(v) === 'off' ? '' : ' checked'}> ${esc(f.label)}</label>`;
  }
  const input = f.type === 'select'
    ? `<select id="${id}" class="sh-input">${f.opts.map(([o, l]) => `<option value="${esc(o)}"${String(v) === o ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>`
    : `<input id="${id}" class="sh-input" type="${f.type || 'text'}" placeholder="${esc(f.ph || '')}" value="${esc(v)}" autocomplete="off">`;
  return `<label class="sh-label"${f.wide ? ' style="grid-column:1/-1"' : ''}>${esc(f.label)}${f.req ? ' *' : ''}${input}</label>`;
}

function openEditor(p) {
  _editId = p ? p.id : null;
  document.getElementById('sh-modal-title').textContent = p ? `Edit ${p.name}` : 'New shipper';
  const name = document.getElementById('sh-name');
  name.value = p ? p.name : '';
  name.disabled = !!p;
  document.getElementById('sh-schedule').value = String(p ? p.schedule_minutes : 60);
  document.getElementById('sh-sources').innerHTML = Object.entries(SOURCES).map(([kind, def]) => {
    const m = p && p.modules[kind];
    return `<div class="sh-src"><label class="sh-row" style="font-weight:600;cursor:pointer">
        <input type="checkbox" id="use-${kind}"${m ? ' checked' : ''}> ${esc(def.label)}</label>
      <div class="sh-src__grid">${def.fields.map(f => field(kind, f, m ? m.settings[f.key] : null)).join('')}</div></div>`;
  }).join('');
  document.getElementById('sh-error').style.display = 'none';
  document.getElementById('sh-modal').style.display = 'flex';
}

function collect() {
  const modules = {};
  for (const [kind, def] of Object.entries(SOURCES)) {
    if (!document.getElementById(`use-${kind}`).checked) continue;
    const s = {};
    for (const f of def.fields) {
      if (f.type === 'onoff') { s[f.key] = document.getElementById(`f-${kind}-${f.key}`).checked ? 'on' : 'off'; continue; }
      const raw = document.getElementById(`f-${kind}-${f.key}`).value.trim();
      if (raw === '') continue;
      s[f.key] = f.type === 'number' || f.num ? Number(raw) : raw;
    }
    modules[kind] = { enabled: true, settings: s };
  }
  return modules;
}

async function save() {
  const err = document.getElementById('sh-error');
  err.style.display = 'none';
  const body = { schedule_minutes: Number(document.getElementById('sh-schedule').value), modules: collect() };
  try {
    if (_editId) await api(`/${encodeURIComponent(_editId)}`, { method: 'PUT', body: JSON.stringify(body) });
    else await api('', { method: 'POST', body: JSON.stringify({ ...body, name: document.getElementById('sh-name').value.trim() }) });
    closeAll();
    toast(_editId ? 'Saved. Destination changes wait for approval on the box.' : 'Shipper created. Download its installer next.', 'ok');
    load();
  } catch (e) {
    err.textContent = e.message;
    err.style.display = 'block';
  }
}

function openSecret(btn) {
  const p = _shippers.find(x => x.id === btn.dataset.id);
  if (!p || !p.shipper) return;
  _sealing = { p, kind: btn.dataset.kind, field: btn.dataset.field };
  document.getElementById('sec-title').textContent = `${SOURCES[_sealing.kind].secrets[_sealing.field]} for ${p.name}`;
  document.getElementById('sec-fp').textContent = ShipperCrypto.pretty(p.shipper.key_fp).slice(0, 47) + '...';
  document.getElementById('sec-value').value = '';
  document.getElementById('sec-error').style.display = 'none';
  document.getElementById('sec-modal').style.display = 'flex';
  document.getElementById('sec-value').focus();
}

async function sealAndSave() {
  const box = document.getElementById('sec-value');
  const err = document.getElementById('sec-error');
  const { p, kind, field } = _sealing;
  try {
    if (!box.value) throw new Error('Type the secret first');
    const envelope = await ShipperCrypto.seal(p.shipper.public_key, p.shipper.key_fp, p.id, kind, field, box.value);
    box.value = '';  // plaintext doesn't hang around in the DOM
    await api(`/${encodeURIComponent(p.id)}/secrets`, { method: 'PUT', body: JSON.stringify({ secrets: [{ kind, field, envelope }] }) });
    closeAll();
    toast('Sealed and saved. The shipper picks it up at its next check-in.', 'ok');
    load();
  } catch (e) {
    err.textContent = e.message;
    err.style.display = 'block';
  }
}

async function download(path, body, fallbackName) {
  const res = await api(path, { method: 'POST', body: JSON.stringify(body || {}) });
  const name = (res.headers.get('content-disposition') || '').match(/filename="([^"]+)"/)?.[1] || fallbackName;
  const url = URL.createObjectURL(await res.blob());
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function downloadInstaller() {
  const err = document.getElementById('inst-error');
  const cidrs = document.getElementById('inst-cidrs').value.split(',').map(s => s.trim()).filter(Boolean);
  try {
    await download(`/${encodeURIComponent(_installFor)}/installer`, { allowed_cidrs: cidrs }, 'open-ctem-shipper.sh');
    closeAll();
    load();
  } catch (e) {
    err.textContent = e.message;
    err.style.display = 'block';
  }
}

function closeAll() {
  for (const id of ['sh-modal', 'sec-modal', 'inst-modal']) document.getElementById(id).style.display = 'none';
  document.getElementById('sec-value').value = '';
}

document.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('[data-action]');
  if (!btn) return;
  const id = btn.dataset.id;
  const p = _shippers.find(x => x.id === id);
  switch (btn.dataset.action) {
    case 'new': return openEditor(null);
    case 'edit': return openEditor(p);
    case 'close': return closeAll();
    case 'save': return save();
    case 'secret': return openSecret(btn);
    case 'seal': return sealAndSave();
    case 'download': return downloadInstaller();
    case 'installer':
      _installFor = id;
      document.getElementById('inst-cidrs').value = '';
      document.getElementById('inst-error').style.display = 'none';
      document.getElementById('inst-modal').style.display = 'flex';
      return;
    case 'generic-installer':
      return download('/installer', {}, 'open-ctem-shipper.sh').catch(e => toast(e.message, 'error'));
    case 'revoke':
      if (!confirm(`Revoke the box for ${p.name}? It stops shipping until you re-install.`)) return;
      return api(`/${encodeURIComponent(id)}/revoke`, { method: 'POST' }).then(load).catch(e => toast(e.message, 'error'));
    case 'delete':
      if (!confirm(`Delete ${p.name}, its box credential and its sealed secrets?`)) return;
      return api(`/${encodeURIComponent(id)}`, { method: 'DELETE' }).then(load).catch(e => toast(e.message, 'error'));
  }
});

document.addEventListener('DOMContentLoaded', load);
