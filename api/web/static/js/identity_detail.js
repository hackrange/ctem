// Identity: click a row for its detail. An identity opens its own page (/identity/person); an ITDR alert, a posture
// finding or an app opens in a panel here (GET /api/v1/identity/threats/{id}, /posture/{id}, /saas-apps/{id}). Everything goes through esc().
(() => {
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const when = s => (s ? new Date(s).toLocaleString() : '--');
  const ID = /^[0-9a-f-]{36}$/i;
  const box = document.createElement('div');
  box.className = 'modal-overlay';
  box.style.display = 'none';
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-modal', 'true');
  box.innerHTML = `<div class="modal-box" style="max-width:720px"><div class="modal-header"><h2 class="modal-title" id="idd-title"></h2>
    <button type="button" class="modal-close" aria-label="Close">&times;</button></div><div class="modal-body" id="idd-body"></div></div>`;
  document.body.appendChild(box);
  const title = box.querySelector('#idd-title'), body = box.querySelector('#idd-body');
  const close = () => { box.style.display = 'none'; };
  box.addEventListener('click', e => { if (e.target === box || e.target.closest('.modal-close')) close(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });

  const grid = rows => `<dl style="display:grid;grid-template-columns:170px 1fr;gap:6px 14px;font-size:.86rem;margin:0 0 12px">${rows
    .filter(([, v]) => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && !v.length))
    .map(([k, v]) => `<dt class="text-muted">${esc(k)}</dt><dd style="margin:0;overflow-wrap:anywhere">${v}</dd>`).join('')}</dl>`;
  const person = (p, masked, identityId) => {
    const name = p ? `<b>${esc(p.name)}</b> &middot; ${esc(p.email || '')}` : esc(masked || '--');
    return identityId ? `${name} <a class="dt-link" href="/identity/person?id=${encodeURIComponent(identityId)}">Open identity &rsaquo;</a>` : name;
  };

  function posture(f) {
    title.textContent = f.title || 'Posture finding';
    body.innerHTML = grid([
      ['Severity', esc(f.severity)], ['Type', esc((f.finding_type || '').replace(/_/g, ' '))], ['Source', esc(f.source)],
      ['App', esc(f.app_name)], ['Identity', f.person || f.user_display ? person(f.person, f.user_display, f.identity_id) : ''],
      ['Affected', esc(f.affected_count)], ['Detected', esc(when(f.detected_at))],
      ['Status', f.is_resolved ? `Resolved ${esc(when(f.resolved_at))}` : 'Open'], ['Reference', `<code>${esc(f.external_id)}</code>`],
    ]) + (f.description ? `<div class="ud-h" style="font-size:.78rem;text-transform:uppercase;color:var(--text-muted);font-weight:700;margin:12px 0 6px">What was found</div>
      <p style="white-space:pre-wrap;overflow-wrap:anywhere;font-size:.88rem;margin:0">${esc(f.description)}</p>` : '');
  }

  function scopes(o) {
    if (!o) return '';
    if (Array.isArray(o)) return o.map(x => `<code style="margin:0 4px 4px 0;display:inline-block">${esc(typeof x === 'object' ? JSON.stringify(x) : x)}</code>`).join('');
    return Object.entries(o).filter(([, v]) => v !== null && v !== '' && !(Array.isArray(v) && !v.length))
      .map(([k, v]) => `<div><span class="text-muted">${esc(k.replace(/_/g, ' '))}:</span> ${Array.isArray(v) ? v.map(x => `<code>${esc(typeof x === 'object' ? JSON.stringify(x) : x)}</code>`).join(' ') : esc(typeof v === 'object' ? JSON.stringify(v) : v)}</div>`).join('');
  }

  function app(a) {
    title.textContent = a.app_name || 'App';
    body.innerHTML = grid([
      ['Kind', esc(a.source === 'grip_ai_agent' ? 'AI agent' : a.source === 'grip_extension' ? 'Browser extension' : a.is_shadow_ai ? 'AI app' : 'SaaS app')],
      ['Vendor / domain', esc(a.vendor)], ['Category', esc(a.app_category)], ['Risk', `${esc(a.risk_level)}${a.risk_score != null ? ` (${esc(Math.round(a.risk_score))})` : ''}`],
      ['Users', esc(a.user_count)], ['Sanctioned', a.is_sanctioned ? 'Yes' : 'No'], ['Source', esc(a.source)],
      ['First seen by CTEM', esc(when(a.first_seen))], ['Last used', esc(when(a.last_seen))],
      ['OAuth scopes', scopes(a.oauth_scopes)], ['Data and details', scopes(a.data_access)],
    ]);
  }

  // An ITDR alert: where it came from, what the identity provider decided and why, how often it repeated, and who
  function threat(t) {
    title.textContent = t.title || 'ITDR alert';
    const d = t.details || {}, L = t.labels || {};
    const repeats = t.count > 1 ? `${esc(t.count)} times, ${esc(when(t.detected_at))} to ${esc(when(d.last_seen))}` : esc(when(t.detected_at));
    body.innerHTML = grid([
      ['Severity', esc(t.severity)], ['Type', esc((t.threat_type || '').replace(/_/g, ' '))], ['Source', esc(t.source)],
      ['App', esc(t.app_name)], ['Identity', t.person || t.user_display ? person(t.person, t.user_display, t.identity_id)
        : '<span class="text-muted">None: the request was stopped before anyone signed in</span>'],
      ['Source IP', t.source_ip ? `<code>${esc(t.source_ip)}</code>` : ''], ['Country', esc(t.country)],
      ['Outcome', esc(d.outcome)], ...['reason', 'risk', 'asOrg', 'isProxy', 'zone', 'eventType', 'severity'].map(k => [L[k] || k, esc(d[k])]),
      ['Seen', repeats], ['MITRE', t.mitre_technique_id ? `<code>${esc(t.mitre_technique_id)}</code>` : ''],
      ['Status', esc(t.status)], ['User agent', d.userAgent ? `<span class="text-sm">${esc(d.userAgent)}</span>` : ''],
    ]) + (t.description ? `<p style="white-space:pre-wrap;overflow-wrap:anywhere;font-size:.88rem;margin:0">${esc(t.description)}</p>` : '');
  }

  async function open(kind, id) {
    if (!ID.test(id || '')) return;
    if (kind === 'identity') { location.href = `/identity/person?id=${encodeURIComponent(id)}`; return; }
    box.style.display = 'flex';
    title.textContent = 'Loading...';
    body.textContent = '';
    try {
      const path = { posture: 'posture', threat: 'threats' }[kind] || 'saas-apps';
      const r = await fetch(`/api/v1/identity/${path}/${encodeURIComponent(id)}`, { headers: { Accept: 'application/json' } });
      if (!r.ok) throw new Error(r.status === 404 ? 'Not found' : r.statusText);
      ({ posture, threat }[kind] || app)(await r.json());
    } catch (e) { title.textContent = 'Could not load this'; body.textContent = e.message; }
  }

  const row = e => e.target.closest('tr.id-row[data-kind]');
  document.addEventListener('click', e => {
    const tr = row(e);
    if (tr && tr.dataset.kind && !e.target.closest('a, button')) open(tr.dataset.kind, tr.dataset.id);
  });
  document.addEventListener('keydown', e => {
    const tr = row(e);
    if (tr && tr.dataset.kind && e.key === 'Enter') open(tr.dataset.kind, tr.dataset.id);
  });
})();
