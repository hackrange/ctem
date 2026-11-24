const API = '/api/v1';
const SURE = { high: "We're confident", medium: 'Likely', low: 'Possible, worth a look' };
const reg = [];
let huntStatus = {};
let currentSource = null;
let pollTimer = null;

const ref = v => { reg.push(v); return reg.length - 1; };
const $ = id => document.getElementById(id);

async function api(url, opts = {}) {
  const res = await fetch(url, { headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, ...opts });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const d = data.detail;
    throw new Error(Array.isArray(d) ? d.map(x => x.msg).join('; ') : (d || `Request failed (${res.status})`));
  }
  return data;
}

function status(msg, bad = false) {
  const el = $('hunt-status');
  el.hidden = !msg;
  el.className = 'hunt-status' + (bad ? ' hunt-status--error' : '');
  el.textContent = msg || '';
}

function busy(on) {
  const b = $('hunt-btn');
  b.disabled = on;
  b.textContent = on ? 'Hunting...' : 'Hunt';
}

async function loadStatus() {
  try {
    const s = await api(`${API}/hunt/status`);
    huntStatus = s;
    const chip = (t, cls) => `<span class="chip ${cls}">${esc(t)}</span>`;
    $('hunt-sources').innerHTML = [
      s.ai ? chip('AI on', 'chip--low') : chip('AI off: keyword search only', 'chip--medium'),
      s.splunk ? chip('Splunk', 'chip--info') : '',
      ...(s.tools || []).map(t => chip(t, 'chip--info')),
      chip('open-ctem data', 'chip--info'),
    ].join('');
  } catch { $('hunt-sources').textContent = ''; }
}

async function startHunt(question) {
  question = (question || $('hunt-query').value).trim();
  if (!question) return;
  $('hunt-query').value = question;
  busy(true);
  $('hunt-answer').innerHTML = '';
  status('Starting the hunt...');
  try {
    const { task_id } = await api(`${API}/hunt/query`, {
      method: 'POST', body: JSON.stringify({ query: question, time_range: $('hunt-range').value }),
    });
    poll(task_id, Date.now());
  } catch (e) { status(e.message, true); busy(false); }
}

async function runSearch(spl) {
  busy(true);
  $('hunt-answer').innerHTML = '';
  status('Running the search...');
  try {
    const { task_id } = await api(`${API}/hunt/search`, {
      method: 'POST', body: JSON.stringify({ spl, time_range: $('hunt-range').value }),
    });
    poll(task_id, Date.now());
  } catch (e) { status(e.message, true); busy(false); }
}

function poll(taskId, started) {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    try {
      const d = await api(`${API}/hunt/result/${encodeURIComponent(taskId)}`);
      if (d.status === 'pending' || d.status === 'running') {
        if (Date.now() - started > 600000) throw new Error('This is taking too long. Try a narrower question or time range.');
        status((d.stage || 'Waiting for a worker') + '...');
        return poll(taskId, started);
      }
      busy(false);
      if (d.status !== 'complete') throw new Error('The hunt failed. Please try again.');
      status('');
      currentSource = taskId;
      render(d.result || {});
      if ($('catalog-panel').style.display !== 'none') loadCatalog();
    } catch (e) { status(e.message, true); busy(false); }
  }, 2000);
}

const ENTITY_COLS = {
  host: ['host', 'ComputerName', 'WorkstationName', 'source_asset', 'destination_asset', 'hostname', 'h'],
  user: ['TargetUserName', 'SubjectUserName', 'UserName', 'username', 'user', 'u', 'last_login_user'],
  ip: ['IpAddress', 'aip', 'source_ip', 'destination_ip', 'ip', 'i', 'LocalAddressIP4', 'RemoteAddressIP4'],
};
const KIND_OF = Object.fromEntries(Object.entries(ENTITY_COLS).flatMap(([k, cols]) => cols.map(c => [c, k])));

function entityButton(kind, value, extra = {}) {
  return `<button type="button" class="entity-link" title="See everything about this" data-profile="${ref({ kind, value, ...extra })}">${esc(value)}</button>`;
}

// A single user, computer, or IP in a cell becomes a link to its profile
function cell(col, v) {
  const kind = KIND_OF[col];
  const s = String(v ?? '');
  if (!kind || !s || s === '-' || s.includes(', ') || s.length > 128) return esc(s);
  if (kind === 'ip' && !/^[0-9a-fA-F:.]+$/.test(s)) return esc(s);
  return entityButton(kind, s);
}

function table(lk) {
  if (lk.error) return `<p class="text-sm text-muted">${esc(lk.error)}</p>`;
  if (!lk.rows || !lk.rows.length) return '<p class="text-sm text-muted">Nothing found.</p>';
  const cols = lk.columns || [];
  return `<div class="table-wrap"><table class="data-table"><thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead>
    <tbody>${lk.rows.map(r => `<tr>${cols.map(c => `<td class="text-sm">${cell(c, r[c])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>
    ${lk.count > lk.rows.length ? `<p class="text-sm text-muted">Showing ${lk.rows.length} of ${lk.count}.</p>` : ''}`;
}

function splBlock(spl) {
  return `<div class="spl"><code>${esc(spl)}</code>
    <button type="button" class="btn btn--ghost btn--sm" data-copy="${ref(spl)}">Copy</button>
    <button type="button" class="btn btn--ghost btn--sm" data-run="${ref(spl)}">Run</button></div>`;
}

function lookupBlock(lk, n) {
  const where = lk.spl ? splBlock(lk.spl) : `<p class="text-sm text-muted">open-ctem ${esc(lk.table)} ${esc(JSON.stringify(lk.filters || {}))}</p>`;
  return `<details class="hunt-details"><summary>${n ? `#${n} ` : ''}${esc(lk.title)} &middot; ${esc(lk.source_label)} &middot; ${esc(lk.count)} rows</summary>
    ${lk.why ? `<p class="text-sm text-muted">${esc(lk.why)}</p>` : ''}${where}${table(lk)}</details>`;
}

function issueCard(issue, lookups, idx) {
  const who = issue.involved || {};
  const times = (issue.timeline || []).map(t => t.time).filter(Boolean);
  const win = times.length ? { first: times[0], last: times[times.length - 1] } : {};
  const people = [...(who.hosts || []).map(v => ['host', v]), ...(who.users || []).map(v => ['user', v]),
                  ...(who.ips || []).map(v => ['ip', v])];
  const evidence = (issue.lookups || []).map(n => lookups[n - 1] && lookupBlock(lookups[n - 1], n)).filter(Boolean);
  return `<div class="panel issue issue--${esc(issue.severity)}">
    <div class="issue__head"><span class="chip chip--${esc(issue.severity)}">${esc(issue.severity)}</span>
      <h3 class="issue__title">${esc(issue.title)}</h3>
      <span class="text-sm text-muted">${esc(SURE[issue.confidence] || '')}</span></div>
    <h4>What happened</h4><p>${esc(issue.what_happened)}</p>
    ${issue.why_it_matters ? `<h4>Why it matters</h4><p>${esc(issue.why_it_matters)}</p>` : ''}
    ${issue.timeline && issue.timeline.length ? `<h4>How it unfolded <span class="text-muted text-sm">(click a step or a box to follow its path)</span></h4>${currentSource
      ? `<div class="agp agp--hunt" data-hunt-map="${idx}"><div class="agp__steps"></div><div class="agp__mapbox"></div></div>`
      : flowDiagram(issue.timeline)}<details class="hunt-details"><summary>Step by step</summary><ol class="flow">${issue.timeline.map(t => `
      <li><span class="flow__time">${esc(t.time)}</span><span class="chip chip--info">${esc(t.source)}</span> ${esc(t.what)}</li>`).join('')}</ol></details>` : ''}
    ${people.length ? `<h4>Who and what was involved <span class="text-muted text-sm">(click for the full picture)</span></h4><div class="who">${people.map(([k, v]) =>
      `<button type="button" class="pref-chip" data-profile="${ref({ kind: k, value: v, ...win })}">${esc(v)}</button>`).join('')}</div>` : ''}
    ${issue.window_label ? `<p class="text-sm text-muted">Incident window: ${esc(issue.window_label)}</p>` : ''}
    ${issue.attack && issue.attack.length ? `<h4>Attack techniques (MITRE ATT&amp;CK)</h4><ul class="steps">${issue.attack.map(a =>
      `<li><a href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">${esc(a.id)}</a> ${esc(a.name)}${a.plain ? ` &middot; <span class="text-muted">${esc(a.plain)}</span>` : ''}</li>`).join('')}</ul>` : ''}
    ${issue.what_to_do && issue.what_to_do.length ? `<h4>What to do now</h4><ol class="steps">${issue.what_to_do.map(s => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}
    ${evidence.length ? `<details class="hunt-details"><summary>Show the evidence (${evidence.length})</summary>${evidence.join('')}</details>` : ''}
    ${issue.splunk && issue.splunk.length ? `<details class="hunt-details"><summary>For Splunk hunting</summary>${issue.splunk.map(splBlock).join('')}</details>` : ''}
    ${issueActions(idx)}
  </div>`;
}

function issueActions(idx) {
  if (!currentSource) return '';
  const t = huntStatus.tickets || {};
  const ticket = (method, label) => `<button type="button" class="btn btn--ghost btn--sm" data-ticket="${ref({ source: currentSource, issue: idx, method })}">${label}</button>`;
  return `<div class="issue-actions">
    <a class="btn btn--primary btn--sm" href="${API}/hunt/report/${encodeURIComponent(currentSource)}/${idx}/pdf" download>Generate report (PDF)</a>
    <a class="btn btn--ghost btn--sm" target="_blank" rel="noopener" href="${API}/hunt/report/${encodeURIComponent(currentSource)}/${idx}">Open as a page</a>
    ${t.api ? ticket('api', 'Create ServiceNow ticket') : ''}${t.email ? ticket('email', 'Email ServiceNow') : ''}
    <span class="text-sm text-muted" data-ticket-msg></span></div>`;
}

async function ticket(b) {
  const msg = b.parentElement.querySelector('[data-ticket-msg]');
  if (!b.dataset.armed) { b.dataset.armed = '1'; b.dataset.label = b.textContent; b.textContent = 'Click again to confirm'; return; }
  b.disabled = true;
  try {
    const out = await api(`${API}/hunt/ticket`, { method: 'POST', body: JSON.stringify(reg[+b.dataset.ticket]) });
    msg.textContent = out.method === 'api' ? `Ticket ${out.number || ''} created.` : `Sent to ${out.sent_to}. ServiceNow will open the ticket.`;
    b.textContent = 'Done';
  } catch (e) { msg.textContent = e.message; b.disabled = false; b.textContent = b.dataset.label; delete b.dataset.armed; }
}

function render(r) {
  const lookups = r.lookups || [];
  let html = '';
  if (r.mode === 'search') {
    html = `<div class="panel">${lookups.map(lk => `<p class="text-sm">${esc(lk.count)} rows</p>${table(lk)}`).join('')}</div>`;
  } else {
    if (r.summary) html += `<div class="panel"><p class="hunt-summary">${esc(r.summary)}</p>
      <p class="text-sm text-muted">Searched: ${esc((r.sources || []).join(', '))}</p></div>`;
    if (r.mode === 'ai') {
      html += (r.issues || []).length
        ? r.issues.map((i, n) => issueCard(i, lookups, n)).join('')
        : '<div class="panel"><p class="hunt-summary">Nothing suspicious turned up for this question and time range.</p></div>';
    } else {
      html += '<div class="panel"><p class="text-sm">AI is off, so here is what matched your words. Turn on an AI integration to get a plain-English story.</p></div>';
    }
    html += `<div class="panel"><details class="hunt-details" ${r.mode === 'ai' ? '' : 'open'}><summary>How we searched (${lookups.length} lookups)</summary>
      ${lookups.map((lk, i) => lookupBlock(lk, i + 1)).join('')}</details></div>`;
  }
  if ((r.notes || []).length) html += `<p class="text-sm text-muted">${r.notes.map(esc).join('<br>')}</p>`;
  $('hunt-answer').innerHTML = html;
  if (window.HuntMap) HuntMap.mountAll($('hunt-answer'), currentSource);
}

async function loadCatalog() {
  try {
    const d = await api(`${API}/hunt/splunk/catalog`);
    const item = s => `<div class="cat-item"><div class="cat-item__head"><strong>${esc(s.title)}</strong>
      <span><button type="button" class="btn btn--ghost btn--sm" data-run="${ref(s.spl)}">Run</button>
      <button type="button" class="btn btn--ghost btn--sm" data-copy="${ref(s.spl)}">Copy</button></span></div>
      ${s.description ? `<div class="text-muted text-sm">${esc(s.description)}</div>` : ''}
      <details class="hunt-details"><summary>Show search</summary><code class="text-sm">${esc(s.spl)}</code></details></div>`;
    const learned = d.learned || [], ready = d.catalog || [];
    $('spl-catalog').innerHTML = (learned.length ? `<h4>Learned from past hunts</h4>${learned.map(item).join('')}` : '') +
      (ready.length ? `<h4>Ready-made</h4>${ready.map(item).join('')}` : '<span>No catalog yet. Run a Splunk sync to build one.</span>');
  } catch { $('spl-catalog').textContent = 'Catalog unavailable.'; }
}

async function copy(text, btn) {
  try { await navigator.clipboard.writeText(text); btn.textContent = 'Copied'; }
  catch { btn.textContent = 'Copy failed'; }
  setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
}

document.addEventListener('click', e => {
  const b = e.target.closest('button');
  if (!b) return;
  if (b.id === 'hunt-btn') startHunt();
  else if (b.id === 'catalog-refresh') loadCatalog();
  else if (b.id === 'catalog-toggle') {
    const panel = $('catalog-panel');
    const show = panel.style.display === 'none';
    panel.style.display = show ? '' : 'none';
    b.setAttribute('aria-expanded', String(show));
    if (show) { loadCatalog(); panel.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  }
  else if (b.dataset.example) startHunt(b.dataset.example);
  else if (b.dataset.ask) startHunt(reg[+b.dataset.ask]);
  else if (b.dataset.run) runSearch(reg[+b.dataset.run]);
  else if (b.dataset.copy) copy(reg[+b.dataset.copy], b);
  else if (b.dataset.profile) openProfile(reg[+b.dataset.profile]);
  else if (b.dataset.ticket) ticket(b);
});
$('hunt-query').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); startHunt(); }
});
async function showWatch() {
  try {
    const w = await api(`${API}/hunt/watch`);
    currentSource = 'watch';
    render({ mode: 'ai', ...(w.result || {}), notes: [`From the hourly background check (${w.ran_at ? new Date(w.ran_at).toLocaleString() : 'not run yet'}). Only serious findings are kept.`] });
  } catch (e) { status(e.message, true); }
}

document.addEventListener('DOMContentLoaded', () => {
  loadStatus();
  if (location.hash === '#watch') showWatch();
});
