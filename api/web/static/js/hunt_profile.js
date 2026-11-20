// Profile panel: everything known about one user, computer, or IP
const KIND_NAME = { user: 'Person / account', host: 'Computer', ip: 'IP address' };
const PALETTE = ['var(--severity-critical)', 'var(--severity-high)', 'var(--accent)', 'var(--severity-low)',
                 'var(--severity-info)', 'var(--text-muted)'];
const FACT_LABELS = {
  username: 'Account', ad_groups: 'Groups', is_service_account: 'Used by software (service account)',
  is_active: 'Enabled', is_locked: 'Locked out', last_login: 'Last sign-in seen', hostname: 'Computer',
  ip: 'IP address', os: 'Operating system', device_type: 'Type', last_login_user: 'Last person signed in',
  ad_joined: 'Joined to Active Directory', edr_active: 'Endpoint protection running', edr_vendor: 'Protection product',
  is_internet_exposed: 'Reachable from the internet', risk_grade: 'Risk grade', risk_score: 'Risk score', last_seen: 'Last check-in',
};
let profileTimer = null;
let profileSpec = null;

function profileShell() {
  let el = document.getElementById('profile-overlay');
  if (!el) {
    el = document.createElement('div');
    el.id = 'profile-overlay';
    el.className = 'modal-overlay';
    el.innerHTML = `<div class="modal-box profile-box" role="dialog" aria-modal="true" aria-labelledby="profile-title">
      <div class="modal-header"><h2 class="modal-title" id="profile-title"></h2>
        <button type="button" class="modal-close" id="profile-close" aria-label="Close">&times;</button></div>
      <div class="modal-body" id="profile-body"></div></div>`;
    document.body.appendChild(el);
    el.addEventListener('click', e => { if (e.target === el || e.target.id === 'profile-close') closeProfile(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeProfile(); });
  }
  el.style.display = 'flex';
  return el;
}

function closeProfile() {
  clearTimeout(profileTimer);
  const el = document.getElementById('profile-overlay');
  if (el) el.style.display = 'none';
}

async function openProfile(spec) {
  profileSpec = spec;
  profileShell();
  document.getElementById('profile-title').textContent = `${KIND_NAME[spec.kind] || ''}: ${spec.value}`;
  const body = document.getElementById('profile-body');
  body.innerHTML = '<p class="text-muted">Pulling together everything we know...</p>';
  try {
    const { task_id } = await api(`${API}/hunt/profile`, { method: 'POST', body: JSON.stringify({
      kind: spec.kind, value: spec.value, time_range: document.getElementById('hunt-range').value,
      first: spec.first || null, last: spec.last || null }) });
    pollProfile(task_id, Date.now(), spec);
  } catch (e) { body.textContent = e.message; }
}

function pollProfile(taskId, started, spec) {
  clearTimeout(profileTimer);
  profileTimer = setTimeout(async () => {
    if (spec !== profileSpec) return;
    const body = document.getElementById('profile-body');
    try {
      const d = await api(`${API}/hunt/result/${encodeURIComponent(taskId)}`);
      if (d.status === 'pending' || d.status === 'running') {
        if (Date.now() - started > 300000) throw new Error('This is taking too long. Try again in a minute.');
        return pollProfile(taskId, started, spec);
      }
      if (d.status !== 'complete') throw new Error('Could not build this profile.');
      body.innerHTML = renderProfile(d.result.profile);
    } catch (e) { body.textContent = e.message; }
  }, 1500);
}

function factsGrid(rec, extra) {
  const rows = Object.entries(rec || {}).filter(([, v]) => v !== null && v !== '' && !(Array.isArray(v) && !v.length));
  const fmt = v => Array.isArray(v) ? v.join(', ') : (v === true ? 'Yes' : v === false ? 'No' : v);
  const items = rows.map(([k, v]) => `<div><span class="text-muted text-sm">${esc(FACT_LABELS[k] || k)}</span><div>${esc(fmt(v))}</div></div>`);
  return items.length || extra ? `<div class="facts">${items.join('')}${extra || ''}</div>` : '<p class="text-sm text-muted">open-ctem has no record for this yet.</p>';
}

function trendChart(t) {
  if (!t || !t.days || !t.days.length) return '<p class="text-sm text-muted">No activity in this time range.</p>';
  const names = Object.keys(t.series);
  const max = Math.max(1, ...t.days.map((_, i) => names.reduce((a, n) => a + t.series[n][i], 0)));
  const bw = 100 / t.days.length;
  const bars = t.days.map((d, i) => {
    let y = 100;
    return names.map((n, j) => {
      const h = (t.series[n][i] / max) * 92;
      y -= h;
      return h ? `<rect x="${i * bw + bw * 0.15}" y="${y}" width="${bw * 0.7}" height="${h}" style="fill:${PALETTE[j % PALETTE.length]}"><title>${esc(d)}: ${esc(n)} ${t.series[n][i]}</title></rect>` : '';
    }).join('');
  }).join('');
  const legend = names.map((n, j) => `<span class="legend"><i style="background:${PALETTE[j % PALETTE.length]}"></i>${esc(n)} (${esc(t.totals[n])})</span>`).join('');
  return `<svg viewBox="0 0 100 100" preserveAspectRatio="none" class="trend" role="img" aria-label="Activity by day">${bars}</svg>
    <div class="trend-days text-sm text-muted"><span>${esc(t.days[0])}</span><span>${esc(t.days[t.days.length - 1])}</span></div><div>${legend}</div>`;
}

function chips(kind, items) {
  return (items || []).map(x => `<button type="button" class="pref-chip" data-profile="${ref({ kind, value: x.value })}">${esc(x.value)} <span class="text-muted">${esc(x.count)}</span></button>`).join('');
}

function section(title, html) { return html ? `<h4 class="profile-h">${esc(title)}</h4>${html}` : ''; }

function rowsTable(rows) {
  if (!rows || !rows.length) return '';
  return table({ columns: Object.keys(rows[0]), rows, count: rows.length });
}

function renderProfile(p) {
  const rel = p.related || {};
  const extra = p.computers && p.computers.length
    ? `<div><span class="text-muted text-sm">Computers they use</span><div>${p.computers.map(c => entityButton('host', c)).join(' ')}</div></div>` : '';
  const relHtml = [['host', 'Computers', rel.hosts], ['user', 'People / accounts', rel.users], ['ip', 'IP addresses', rel.ips]]
    .filter(([, , xs]) => xs && xs.length).map(([k, t, xs]) => `<div class="text-sm">${esc(t)}</div><div class="who">${chips(k, xs)}</div>`).join('');
  const spl = Object.values(p.spl || {});
  return `
    ${p.summary ? `<p class="hunt-summary">${esc(p.summary)}</p>` : ''}
    ${section('What we know', factsGrid(p.record, extra))}
    ${section('Activity by day', trendChart(p.trend))}
    ${section('Often seen with (click to look closer)', relHtml)}
    ${section(p.window_label ? `Notable events around the incident (${p.window_label})` : 'Notable events', p.events ? table({ ...p.events }) : '')}
    ${section('Vulnerabilities', rowsTable(p.vulns))}
    ${section('Attack paths', rowsTable(p.paths))}
    ${section('Alerts from security tools', rowsTable(p.alerts))}
    ${section('Identity alerts', rowsTable(p.identity))}
    ${section('Risk score over time', rowsTable(p.risk_history))}
    <div class="profile-actions"><button type="button" class="btn btn--primary btn--sm" data-ask="${ref(`What else did ${p.value} do?`)}">Hunt on this</button></div>
    ${spl.length ? `<details class="hunt-details"><summary>For Splunk hunting</summary>${spl.map(splBlock).join('')}</details>` : ''}`;
}

document.addEventListener('click', e => {
  const b = e.target.closest('button[data-ask]');
  if (b && document.getElementById('profile-overlay')) closeProfile();
}, true);
