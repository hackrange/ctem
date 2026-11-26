// Discovered Users: click a person for everything CTEM knows about them (GET /api/v1/directory/users/{id}).
(function () {
  const box = document.getElementById('user-detail');
  const body = document.getElementById('ud-body');
  const title = document.getElementById('ud-title');
  if (!box) return;
  const close = () => { box.style.display = 'none'; };
  document.getElementById('ud-close').addEventListener('click', close);
  box.addEventListener('click', e => { if (e.target === box) close(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });

  const dash = '<span class="text-muted">--</span>';
  const v = x => (x == null || x === '' ? dash : esc(x));
  const day = x => (x ? esc(new Date(x).toLocaleString()) : dash);
  const row = (k, val) => `<dt>${esc(k)}</dt><dd style="margin:0">${val}</dd>`;
  const gname = g => { const m = /^CN=((?:\\,|[^,])+)/i.exec(String(g || '')); return m ? m[1].replace(/\\,/g, ',') : String(g || ''); };

  function render(u) {
    const ad = u.ad || {};
    const w = u.where || {};
    const name = [u.first_name, u.last_name].filter(Boolean).join(' ') || u.display_name || u.username;
    title.textContent = name;
    // nosemgrep: javascript.browser.security.insertadjacenthtml.insertAdjacentHTML -- IdvBadge escapes everything; its only input is a date
    if (u.idv_verified_at && window.IdvBadge) title.insertAdjacentHTML('beforeend', IdvBadge.html(u.idv_verified_at, false));
    // nosemgrep: javascript.browser.security.insertadjacenthtml.insertAdjacentHTML -- IdvSend.button escapes the id and name
    if (window.IdvSend) title.insertAdjacentHTML('beforeend', IdvSend.button(u.id, name));
    let left = dash;
    if (ad.pwd_never_expires) left = 'Never expires';
    else if (ad.pwd_days_left != null) left = ad.pwd_days_left < 0 ? `Expired ${esc(-ad.pwd_days_left)} days ago` : `${esc(ad.pwd_days_left)} days left`;
    else if (ad.pwd_expired) left = 'Expired';
    const status = [ad.disabled && 'Disabled', ad.locked_out && 'Locked out', ad.pwd_expired && 'Password expired',
                    ad.pwd_never_expires && 'Password never expires'].filter(Boolean).join(', ') || (u.ad ? 'OK' : dash);
    const factors = u.risk_factors && typeof u.risk_factors === 'object'
      ? Object.entries(Array.isArray(u.risk_factors) ? Object.assign({}, u.risk_factors) : u.risk_factors)
          .map(([k, x]) => `<li>${esc(k)}: ${esc(typeof x === 'object' ? JSON.stringify(x) : x)}</li>`).join('') : '';
    const groups = (u.ad_groups || []).map(g => `<span class="chip chip--info" style="font-size:.7rem;margin:0 4px 4px 0" title="${esc(g)}">${esc(gname(g))}</span>`).join('');
    const devices = (u.devices || []).map(d => `<tr><td><a href="/devices/${encodeURIComponent(d.id)}">${esc(d.hostname)}</a></td>
        <td class="text-mono text-sm">${v(d.ip)}</td><td class="text-sm">${v(d.type)}</td><td class="text-sm">${esc(d.how)}</td>
        <td class="text-sm">${day(d.last_seen)}</td></tr>`).join('');
    body.innerHTML = `
      <div class="ud-h">Person</div>
      <dl class="ud-grid">
        ${row('Username', `<span class="text-mono">${esc(u.username)}</span>`)}${row('UPN', v(u.upn))}${row('Email', v(u.email_display))}
        ${row('Title', v(u.title))}${row('Department', v(w.department))}${row('Phone', v(u.phone))}${row('Mobile', v(u.mobile))}
        ${row('Office', v([w.office, w.city, w.state, w.postal_code].filter(Boolean).join(', ')))}
        ${row('Service account', u.is_service_account ? 'Yes' : 'No')}
      </dl>
      <div class="ud-h">AD account</div>
      <dl class="ud-grid">
        ${row('Status', esc(status))}${row('Last logon', day(ad.last_logon))}${row('Password set', day(ad.pwd_last_set))}
        ${row('Password expires', ad.pwd_expires ? `${day(ad.pwd_expires)} <span class="text-muted">(${left})</span>` : left)}
      </dl>
      <div class="ud-h">Risk</div>
      <dl class="ud-grid">
        ${row('Grade', v(u.risk_grade))}${row('Score', u.risk_score != null ? esc(Math.round(u.risk_score)) : dash)}${row('Scored', day(u.risk_at))}
      </dl>
      ${factors ? `<ul class="text-sm" style="margin:0 0 12px 18px">${factors}</ul>` : ''}
      <div class="ud-h">AD groups (${esc((u.ad_groups || []).length)})</div>
      <div>${groups || dash}</div>
      <div class="ud-h">Machines (${esc((u.devices || []).length)})</div>
      ${devices ? `<table class="data-table"><thead><tr><th>Host</th><th>IP</th><th>Type</th><th>How</th><th>Last seen</th></tr></thead><tbody>${devices}</tbody></table>` : dash}`;
  }

  async function open(id) {
    box.style.display = 'flex';
    title.textContent = 'User';
    body.textContent = 'Loading...';
    try {
      const r = await fetch(`/api/v1/directory/users/${encodeURIComponent(id)}`, { headers: { Accept: 'application/json' } });
      if (!r.ok) throw new Error(r.status === 404 ? 'Not found' : r.statusText);
      render(await r.json());
    } catch (e) { body.textContent = `Could not load this person: ${e.message}`; }
  }
  const tb = document.getElementById('users-tbody');
  tb.addEventListener('click', e => { const tr = e.target.closest('tr[data-user]'); if (tr && !e.target.closest('a')) open(tr.dataset.user); });
  tb.addEventListener('keydown', e => { const tr = e.target.closest('tr[data-user]'); if (tr && e.key === 'Enter') open(tr.dataset.user); });
  // Linked from elsewhere (Identity > a person): /users?person=<id> opens that person
  const linked = new URLSearchParams(location.search).get('person');
  if (linked && /^[0-9a-f-]{36}$/i.test(linked)) open(linked);
})();
