// Admin > Roles: click a role to see who holds it. Everything shown goes through esc().
(() => {
  let dlg;
  function modal() {
    if (dlg) return dlg;
    dlg = document.createElement('dialog');
    dlg.className = 'modal modal--wide';
    dlg.setAttribute('aria-labelledby', 'rm-title');
    dlg.innerHTML = `<div style="padding:16px 24px;max-height:85vh;overflow:auto">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <h2 id="rm-title" class="panel__title" style="margin:0">Role members</h2>
        <button type="button" class="btn btn--ghost btn--sm" data-close aria-label="Close">&#10005;</button></div>
      <div id="rm-body" style="margin-top:8px"></div></div>`;
    dlg.addEventListener('click', e => { if (e.target === dlg || e.target.closest('[data-close]')) dlg.close(); });
    document.body.appendChild(dlg);
    return dlg;
  }
  async function show(name) {
    const m = modal(), body = m.querySelector('#rm-body');
    body.textContent = 'Loading...';
    m.showModal();
    try {
      const r = await fetch(`/api/v1/admin/roles/${encodeURIComponent(name)}/members`, { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
      if (!r.ok) throw new Error();
      const d = await r.json();
      m.querySelector('#rm-title').textContent = `${d.role.display_name || d.role.name} (${d.members.length}${d.more ? '+' : ''})`;
      body.innerHTML = `${d.role.description ? `<p class="text-sm text-muted" style="margin:0 0 8px">${esc(d.role.description)}</p>` : ''}${
        d.members.length ? `<table class="data-table" style="width:100%;font-size:13px"><thead><tr><th>Username</th><th>Name</th><th>Email</th>
          <th>Kind</th><th>Status</th><th>Last sign-in</th></tr></thead><tbody>${d.members.map(u => `<tr>
          <td><b>${esc(u.username)}</b></td><td>${esc(u.name || '--')}</td><td class="text-muted">${esc(u.email || '--')}</td><td>${esc(u.kind)}</td>
          <td>${u.active ? '<span class="chip chip--low">Active</span>' : '<span class="chip chip--info">Disabled</span>'}</td>
          <td class="text-muted">${esc(u.last_login ? new Date(u.last_login).toLocaleString() : 'Never')}</td></tr>`).join('')}</tbody></table>`
          : '<p class="text-sm text-muted">No one holds this role.</p>'}
        <p class="text-sm text-muted" style="margin:10px 0 0">Change someone's roles under Users > Edit.</p>`;
    } catch (e) { body.textContent = "Couldn't load this role's members."; }
  }
  document.addEventListener('click', e => {
    const b = e.target.closest('[data-role-members]');
    if (b) show(b.dataset.roleMembers);
  });
})();
