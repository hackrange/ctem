const API = '/api/v1';
let _availableRoles = [];
let _editUserId = null;
let _auditCursor = null;

// ── Tabs ──────────────────────────────────────────────────────────────────────

const PANES = ['users','tokens','roles','rules','tags','risk','branding','audit', 'ai', 'util'];
function switchTab(name) {
  PANES.forEach(p => {
    document.getElementById('pane-'+p).style.display = p === name ? '' : 'none';
    document.getElementById('tab-'+p).classList.toggle('is-active', p === name);
  });
  if (name === 'tokens' && !document.getElementById('admin-tokens-tbody').dataset.loaded) loadAdminTokens();
  if (name === 'roles' && !document.getElementById('roles-tbody').dataset.loaded) loadRoles();
  if (name === 'audit' && !document.getElementById('audit-tbody').dataset.loaded) loadAudit();
  if (name === 'branding') loadBranding();
  if (name === 'ai' && window.AIUsage) AIUsage.load();
  if (name === 'rules' && window.CuratedRules) CuratedRules.load();
  if (name === 'tags' && window.TagRoles) TagRoles.load();
  if (name === 'risk' && window.RiskModel) RiskModel.load();
  if (name === 'util' && window.AdminUtilization) AdminUtilization.load();
}

// Tabs are links (/admin#roles) so the SSO page and bookmarks can open one directly
document.addEventListener('click', e => {
  const t = e.target.closest('[data-tab]');
  if (!t) return;
  e.preventDefault();
  switchTab(t.dataset.tab);
  history.replaceState(null, '', '#' + t.dataset.tab);
});
document.addEventListener('DOMContentLoaded', () => {
  const want = location.hash.slice(1);
  if (want !== 'users' && PANES.includes(want)) switchTab(want);
});

// ── Data loaders ──────────────────────────────────────────────────────────────

async function fetchJson(url, opts, retried) {
  const res = await fetch(url, { headers: { Accept: 'application/json' }, ...opts });
  if (res.status === 403 && res.headers.get('X-Step-Up') === 'required' && !retried && window.AdminStepUp) {
    await AdminStepUp.ask((res.headers.get('X-Step-Up-Needs') || 'password').split(','));
    return fetchJson(url, opts, true);   // once confirmed, the same request again
  }
  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.detail || res.statusText);
  }
  return res.json();
}

async function loadUsers() {
  try {
    const [data, rolesData] = await Promise.all([
      fetchJson(`${API}/admin/users`),
      fetchJson(`${API}/admin/roles`),
    ]);
    _availableRoles = rolesData.roles || [];
    const users = data.users || [];
    document.getElementById('users-tbody').innerHTML = users.map(u => `
      <tr>
        <td style="font-weight:600">${esc(u.username)}${u.is_local ? '' : ' <span class="chip chip--info" style="font-size:.65rem">SSO</span>'}${u.needs_repair ? ' <span class="chip chip--critical" style="font-size:.65rem" title="Its sign-in details or roles were changed outside CTEM, so it can\'t sign in until it is repaired">Changed outside CTEM</span>' : ''}</td>
        <td class="text-muted text-sm">${esc(u.email_display || '') || '<span class="text-muted">--</span>'}</td>
        <td>${(u.roles || []).map(r => `<span class="chip chip--info">${esc(r.role_name)}</span>`).join(' ') || '<span class="text-muted text-sm">--</span>'}</td>
        <td>${u.totp_enabled ? '<span style="color:var(--severity-low)">&#10003; On</span>' : '<span class="text-muted text-sm">Off</span>'}</td>
        <td>${u.is_active ? '<span style="color:var(--severity-low)">Active</span>' : '<span style="color:var(--severity-critical)">Inactive</span>'}</td>
        <td class="text-muted text-sm">${u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}</td>
        <td>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            ${u.needs_repair ? `<button class="btn btn--ghost btn--sm" style="color:var(--severity-critical)" onclick="repairUser(${esc(JSON.stringify(u.id))},${esc(JSON.stringify(u.username))},${!!u.is_local})">Repair</button>` : `<button class="btn btn--ghost btn--sm" onclick="openEditModal(${esc(JSON.stringify(u))})">Edit</button>`}
            <button class="btn btn--ghost btn--sm" style="color:var(--severity-${u.is_active ? 'critical' : 'low'})"
              onclick="toggleUser(${esc(JSON.stringify(u.id))},${esc(JSON.stringify(u.username))},${!!u.is_active})">${u.is_active ? 'Deactivate' : 'Activate'}</button>
            ${u.is_active && !u.is_locked && !(u.roles || []).some(r => r.role_name === 'admin') ? `<button class="btn btn--ghost btn--sm" title="See CTEM as this person sees it (read-only, 30 minutes)" onclick="viewAs(${esc(JSON.stringify(u.id))},${esc(JSON.stringify(u.username))})">View as</button>` : ''}
            ${!u.is_active ? `<button class="btn btn--ghost btn--sm" style="color:var(--severity-critical)" onclick="deleteUser(${esc(JSON.stringify(u.id))},${esc(JSON.stringify(u.username))})">Delete</button>` : ''}
          </div>
        </td>
      </tr>
    `).join('') || '<tr><td colspan="7" class="text-muted text-sm" style="text-align:center;padding:20px">No users</td></tr>';
  } catch (e) { console.error(e); }
}

async function loadAdminTokens() {
  try {
    const data = await fetchJson(`${API}/tokens/admin/all`);
    document.getElementById('admin-tokens-tbody').dataset.loaded = '1';
    const tokens = data.tokens || [];
    document.getElementById('admin-tokens-tbody').innerHTML = tokens.map(t => `
      <tr>
        <td class="text-sm">${esc(t.username || t.user_id)}</td>
        <td style="font-weight:500">${esc(t.name)}</td>
        <td class="text-mono text-sm">${(t.allowed_ips || []).slice(0,2).map(esc).join(', ') || '--'}</td>
        <td class="text-sm">${t.rate_limit_per_minute ? t.rate_limit_per_minute + '/min' : '<span class="text-muted">global</span>'}</td>
        <td class="text-muted text-sm">${t.last_used ? new Date(t.last_used).toLocaleString() : 'Never'}</td>
        <td>
          <button class="btn btn--ghost btn--sm" style="color:var(--severity-critical)"
            onclick="revokeTokenAdmin('${esc(t.id)}')">Revoke</button>
        </td>
      </tr>
    `).join('') || '<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:20px">No active tokens</td></tr>';
  } catch (_) {}
}

async function loadRoles() {
  try {
    const data = await fetchJson(`${API}/admin/roles`);
    document.getElementById('roles-tbody').dataset.loaded = '1';
    document.getElementById('roles-tbody').innerHTML = (data.roles || []).map(r => `
      <tr>
        <td style="font-weight:500"><button type="button" class="dt-link" style="background:none;border:0;padding:0;cursor:pointer" data-role-members="${esc(r.name)}" title="See who holds this role"><code>${esc(r.name)}</code></button></td>
        <td>${esc(r.display_name)}</td>
        <td>${r.is_builtin ? '<span class="chip chip--info">Built-in</span>' : '<span class="chip">Custom</span>'}</td>
      </tr>
    `).join('');
  } catch (_) {}
}

let _auditEntries = [];
async function loadAudit(append=false) {
  try {
    const url = _auditCursor ? `${API}/admin/audit?limit=50&cursor=${encodeURIComponent(_auditCursor)}` : `${API}/admin/audit?limit=50`;
    const data = await fetchJson(url);
    document.getElementById('audit-tbody').dataset.loaded = '1';
    _auditCursor = data.next_cursor || null;
    document.getElementById('audit-more-btn').style.display = _auditCursor ? '' : 'none';
    const rows = data.entries || [];
    const html = rows.map(e => `
      <tr>
        <td class="text-muted text-sm">${new Date(e.at).toLocaleString()}</td>
        <td class="text-sm">${esc(e.actor)}</td>
        <td class="text-sm"><code>${esc(e.action)}</code></td>
        <td class="text-muted text-sm">${esc(e.resource || '')}</td>
        <td class="text-sm">${esc(e.detail || '')}</td>
      </tr>
    `).join('');
    if (append) {
      document.getElementById('audit-tbody').insertAdjacentHTML('beforeend', html);
    } else {
      document.getElementById('audit-tbody').innerHTML = html || '<tr><td colspan="5" class="text-muted text-sm" style="text-align:center;padding:20px">No audit entries</td></tr>';
    }
  } catch (_) {
    document.getElementById('audit-tbody').innerHTML = '<tr><td colspan="5" class="text-muted text-sm" style="text-align:center;padding:20px">Could not load the audit log</td></tr>';
  }
}
function loadMoreAudit() { loadAudit(true); }

// ── Branding ──────────────────────────────────────────────────────────────────

async function loadBranding() {
  try {
    const data = await fetchJson(`${API}/admin/branding`);
    if (data.title) document.getElementById('brand-title').value = data.title;
    if (data.accent_color) {
      document.getElementById('brand-color').value = data.accent_color;
      document.getElementById('brand-color-hex').value = data.accent_color;
      document.getElementById('brand-color-preview').style.background = data.accent_color;
    }
    if (data.logo_url) {
      document.getElementById('brand-logo').value = data.logo_url;
      previewLogoUrl(data.logo_url);
    }
    if (data.org_name) document.getElementById('brand-org').value = data.org_name;
    document.getElementById('brand-login-logo').value = data.login_logo_url || '';
    _setLogoPreview(data.login_logo_url || null, 'brand-login-logo');
    document.getElementById('brand-favicon').value = data.favicon_url || '';
    _setLogoPreview(data.favicon_url || null, 'brand-favicon');
  } catch (_) {}
}

function _setLogoPreview(src, field = 'brand-logo') {
  const el = document.getElementById(`${field}-preview`);
  if (src) {
    el.innerHTML = `<img src="${esc(src)}" style="width:100%;height:100%;object-fit:contain">`;
  } else {
    el.innerHTML = `<span class="text-muted text-sm">None</span>`;
  }
}

function previewLogoUrl(val) {
  _setLogoPreview(val || null);
}

function clearLogo(field) {
  document.getElementById(field).value = '';
  _setLogoPreview(null, field);
}

function handleLogoUpload(input, field = 'brand-logo') {
  const file = input.files[0];
  if (!file) return;
  if (file.size > 512 * 1024) { toast('Logo must be under 512 KB', 'error'); return; }
  if (!['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(file.type)) { toast('Use a PNG, JPEG, WebP or GIF image', 'error'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    const dataUrl = e.target.result;
    document.getElementById(field).value = dataUrl;
    _setLogoPreview(dataUrl, field);
    toast('Logo ready. Click Save to use it.', 'success');
  };
  reader.readAsDataURL(file);
}

// Favicon: PNG or ICO up to 128 KB (the server checks the bytes too)
function handleFaviconUpload(input) {
  const file = input.files[0];
  if (!file) return;
  if (file.size > 128 * 1024) { toast('A favicon must be under 128 KB', 'error'); return; }
  const ico = /\.ico$/i.test(file.name);
  if (!['image/png', 'image/x-icon', 'image/vnd.microsoft.icon'].includes(file.type) && !ico) { toast('Use a PNG or ICO file', 'error'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    let dataUrl = e.target.result;
    if (ico && !/^data:image\/(x-icon|vnd\.microsoft\.icon);/.test(dataUrl)) dataUrl = dataUrl.replace(/^data:[^;,]*;/, 'data:image/x-icon;');
    document.getElementById('brand-favicon').value = dataUrl;
    _setLogoPreview(dataUrl, 'brand-favicon');
    toast('Favicon ready. Click Save to use it.', 'success');
  };
  reader.readAsDataURL(file);
}

function syncColorPicker(val) {
  if (/^#[0-9a-fA-F]{6}$/.test(val)) {
    document.getElementById('brand-color').value = val;
    document.getElementById('brand-color-preview').style.background = val;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('brand-color').addEventListener('input', e => {
    document.getElementById('brand-color-hex').value = e.target.value;
    document.getElementById('brand-color-preview').style.background = e.target.value;
  });
});

async function saveBranding() {
  const payload = {
    title: document.getElementById('brand-title').value.trim() || null,
    accent_color: document.getElementById('brand-color-hex').value.trim() || document.getElementById('brand-color').value,
    logo_url: document.getElementById('brand-logo').value.trim() || null,
    login_logo_url: document.getElementById('brand-login-logo').value.trim() || '',
    favicon_url: document.getElementById('brand-favicon').value.trim() || '',
    org_name: document.getElementById('brand-org').value.trim() || null,
  };
  try {
    await fetchJson(`${API}/admin/branding`, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    toast('Branding saved. Reload to see changes.', 'success');
  } catch (e) { toast(e.message, 'error'); }
}

async function resetBranding() {
  try {
    await fetchJson(`${API}/admin/branding`, { method: 'DELETE' });
    document.getElementById('brand-title').value = '';
    document.getElementById('brand-color').value = '#f5a623';
    document.getElementById('brand-color-hex').value = '#f5a623';
    document.getElementById('brand-color-preview').style.background = '#f5a623';
    document.getElementById('brand-logo').value = '';
    _setLogoPreview(null);
    clearLogo('brand-login-logo');
    document.getElementById('brand-org').value = '';
    toast('Branding reset to defaults. Reload to see changes.', 'success');
  } catch (e) { toast(e.message, 'error'); }
}

// ── Add user modal ────────────────────────────────────────────────────────────

function openAddUserModal() {
  _renderRoleToggles('new-roles-list', []);
  document.getElementById('new-username').value = '';
  document.getElementById('new-email').value = '';
  document.getElementById('new-password').value = '';
  document.getElementById('add-user-modal').style.display = 'flex';
}
function closeAddUserModal() { document.getElementById('add-user-modal').style.display = 'none'; }

async function createUser() {
  const username = document.getElementById('new-username').value.trim();
  const email = document.getElementById('new-email').value.trim();
  const password = document.getElementById('new-password').value;
  const roles = _selectedRoles('new-roles-list');
  if (!username || !password) { toast('Username and password are required', 'error'); return; }
  try {
    await fetchJson(`${API}/admin/users`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ username, email: email || null, password, roles: roles.length ? roles : ['read_only'] }),
    });
    closeAddUserModal();
    loadUsers();
    toast(`User ${username} created`, 'success');
  } catch (e) { toast(e.message, 'error'); }
}

// ── Edit user modal ───────────────────────────────────────────────────────────

function openEditModal(u) {
  _editUserId = u.id;
  document.getElementById('edit-modal-title').textContent = `Edit: ${u.username}`;
  document.getElementById('edit-user-id').value = u.id;
  document.getElementById('edit-email').value = u.email_display || '';
  document.getElementById('edit-password').value = '';
  document.getElementById('edit-page-tags').value = (u.page_tags || []).join(', ');
  _renderRoleToggles('edit-roles-list', (u.roles||[]).map(r=>r.role_name));
  _updateTotpUi(u.totp_enabled);
  document.getElementById('totp-setup-result').style.display = 'none';
  document.getElementById('edit-user-modal').style.display = 'flex';
  UserAccess.open(u.id);
}
function closeEditModal() {
  document.getElementById('edit-user-modal').style.display = 'none';
  _editUserId = null;
}

function _updateTotpUi(enabled) {
  const statusEl = document.getElementById('edit-totp-status');
  statusEl.innerHTML = enabled
    ? '<span style="color:var(--severity-low)">&#10003; Enabled</span>'
    : '<span class="text-muted">Not configured</span>';
  document.getElementById('edit-totp-setup-btn').textContent = enabled ? 'Regenerate TOTP' : 'Generate TOTP';
  document.getElementById('edit-totp-remove-btn').style.display = enabled ? '' : 'none';
}

async function saveEditUser() {
  const id = document.getElementById('edit-user-id').value;
  const email = document.getElementById('edit-email').value.trim();
  const password = document.getElementById('edit-password').value;
  const roles = _selectedRoles('edit-roles-list');
  const pageTags = document.getElementById('edit-page-tags').value
    .split(',').map(t=>t.trim().toLowerCase()).filter(Boolean);

  try {
    await fetchJson(`${API}/admin/users/${id}`, {
      method: 'PATCH', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ email: email || null, password: password || null }),
    });
    if (roles.length) {
      await fetchJson(`${API}/admin/users/${id}/roles`, {
        method: 'PATCH', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ roles }),
      });
    }
    await fetchJson(`${API}/admin/users/${id}/page-tags`, {
      method: 'PATCH', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ page_tags: pageTags }),
    });
    await UserAccess.save(id);
    closeEditModal();
    loadUsers();
    toast('User updated', 'success');
  } catch (e) { toast(e.message, 'error'); }
}

async function setupTotp() {
  try {
    const data = await fetchJson(`${API}/admin/users/${_editUserId}/totp/setup`, { method: 'POST' });
    _updateTotpUi(true);
    const container = document.getElementById('totp-qr-container');
    container.innerHTML = data.qr_png
      ? `<img src="${data.qr_png}" alt="QR code" width="160" height="160" style="border-radius:4px">`
      : `<span class="text-muted text-sm">Scan via authenticator app</span>`;
    document.getElementById('totp-secret-display').textContent = data.secret;
    document.getElementById('totp-setup-result').style.display = '';
    loadUsers();
  } catch (e) { toast(e.message, 'error'); }
}

function copyTotpSecret() {
  const secret = document.getElementById('totp-secret-display').textContent;
  navigator.clipboard.writeText(secret).catch(() => {
    // fallback: select the text
    const el = document.getElementById('totp-secret-display');
    const range = document.createRange();
    range.selectNodeContents(el);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(range);
  });
  toast('Secret copied', 'success');
}

async function removeTotp() {
  try {
    await fetchJson(`${API}/admin/users/${_editUserId}/totp`, { method: 'DELETE' });
    _updateTotpUi(false);
    document.getElementById('totp-setup-result').style.display = 'none';
    loadUsers();
    toast('TOTP removed', 'success');
  } catch (e) { toast(e.message, 'error'); }
}

// ── Role toggles ──────────────────────────────────────────────────────────────

function _renderRoleToggles(containerId, activeRoles) {
  const el = document.getElementById(containerId);
  el.innerHTML = _availableRoles.map(r => {
    const on = activeRoles.includes(r.name);
    return `<button type="button" class="role-toggle ${on ? 'role-toggle--on' : ''}"
      data-role="${esc(r.name)}" onclick="this.classList.toggle('role-toggle--on')"
      title="${esc(r.display_name)}">${esc(r.display_name)}</button>`;
  }).join('');
}

function _selectedRoles(containerId) {
  return [...document.getElementById(containerId).querySelectorAll('.role-toggle--on')]
    .map(b => b.dataset.role);
}

// ── Misc actions ──────────────────────────────────────────────────────────────

async function viewAs(id, username) {
  const reason = prompt(`View CTEM as ${username}? It is read-only, ends after 30 minutes, and is recorded in the Audit Log.\n\nWhy (for the Audit Log):`);
  if (reason == null) return;
  if (reason.trim().length < 4) { toast('Give a short reason (4 characters or more)', 'error'); return; }
  try {
    await fetchJson(`${API}/admin/users/${id}/impersonate`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ reason: reason.trim() }) });
    location.href = '/';
  } catch (e) { toast(e.message || 'Could not start viewing as', 'error'); }
}

async function deleteUser(id, username) {
  if (!confirm(`Permanently delete user "${username}"? This cannot be undone.`)) return;
  try {
    await fetchJson(`${API}/admin/users/${id}`, { method: 'DELETE' });
    loadUsers();
    toast(`User ${username} deleted`, 'success');
  } catch (e) { toast(e.message, 'error'); }
}

async function toggleUser(id, username, isActive) {
  if (!confirm(`${isActive ? 'Deactivate' : 'Activate'} user ${username}?`)) return;
  await fetchJson(`${API}/admin/users/${id}/toggle`, { method: 'PATCH' });
  loadUsers();
}

async function revokeTokenAdmin(id) {
  if (!confirm('Revoke this token?')) return;
  await fetchJson(`${API}/tokens/${id}`, { method: 'DELETE' });
  loadAdminTokens();
}

function openCreateRoleModal() {
  document.getElementById('role-name').value = '';
  document.getElementById('role-display').value = '';
  document.getElementById('role-desc').value = '';
  document.getElementById('create-role-modal').style.display = 'flex';
}
function closeCreateRoleModal() { document.getElementById('create-role-modal').style.display = 'none'; }

async function createRole() {
  const name = document.getElementById('role-name').value.trim();
  const displayName = document.getElementById('role-display').value.trim();
  const description = document.getElementById('role-desc').value.trim();
  if (!name || !displayName) { toast('Role name and display name are required', 'error'); return; }
  if (!/^[a-z0-9_]+$/.test(name)) { toast('Role name: lowercase letters, numbers and underscores only', 'error'); return; }
  try {
    await fetchJson(`${API}/admin/roles`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ name, display_name: displayName, description: description || null }),
    });
    closeCreateRoleModal();
    _availableRoles = [];
    document.getElementById('roles-tbody').dataset.loaded = '';
    loadRoles();
    loadUsers();
    toast(`Role "${displayName}" created`, 'success');
  } catch (e) { toast(e.message, 'error'); }
}

document.addEventListener('DOMContentLoaded', loadUsers);

// An account changed outside CTEM: nothing it held is trusted. Its roles and state are chosen again, a local one gets
// a new one-time password, and its authenticator (and an SSO identity link) go. Needs a fresh "confirm it's you".
async function repairUser(id, username, isLocal) {
  const roles = prompt(`Repair ${username}: its sign-in details or roles were changed outside CTEM.\n\nRoles to give it (comma separated, e.g. read_only):`, 'read_only');
  if (roles === null) return;
  let password = null;
  if (isLocal) {
    password = prompt('A new one-time password (12+ characters); they replace it at their next sign-in:');
    if (!password) return;
  }
  const active = confirm('Leave the account active? (Cancel keeps it inactive until you activate it.)');
  try {
    await fetchJson(`${API}/admin/users/${encodeURIComponent(id)}/repair`, { method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ roles: roles.split(',').map(r => r.trim()).filter(Boolean), active, password }) });
    toast(`${username} repaired`, 'success');
    loadUsers();
  } catch (e) {
    toast(e.message || 'Repair failed', 'error');
  }
}
