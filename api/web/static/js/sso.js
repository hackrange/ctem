// Single sign-on wizard: provider, setup steps, connection, access.
(() => {
  const API = '/api/v1/admin/sso';
  let state = null;
  let provider = null;
  const $ = id => document.getElementById(id);

  async function call(method, body, path = '') {
    const res = await fetch(API + path, {
      method, headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'Check the highlighted settings and try again');
    return d;
  }

  function warnings() {
    const w = [];
    if (state.public_url_missing) w.push('PUBLIC_URL isn\'t set on the server, so CTEM can\'t build its redirect URI. Set it before turning SSO on.');
    if (state.env.oidc) w.push('OIDC_ISSUER and OIDC_CLIENT_ID are set in the server environment; those win over this page until removed.');
    if (state.env.auth_mode) w.push(`AUTH_MODE=${state.env.auth_mode} is set in the server environment and overrides the sign-in option here. ` +
      'Remove it (or set it to both) to let this page decide.');
    $('sso-warnings').innerHTML = w.map(t => `<div class="panel sso-warn text-sm">${esc(t)}</div>`).join('');
  }

  function renderProviders() {
    $('sso-providers').innerHTML = state.providers.map(p => `
      <button class="sso-card${provider && provider.key === p.key ? ' active' : ''}" data-provider="${esc(p.key)}">
        <b>${esc(p.label)}</b></button>`).join('');
  }

  function choose(key) {
    provider = state.providers.find(p => p.key === key);
    if (!provider) return;
    renderProviders();
    $('sso-provider-name').textContent = provider.label;
    $('sso-redirect').textContent = state.redirect_uri;
    $('sso-signout').textContent = state.signout_uri;
    $('sso-steps').innerHTML = provider.steps.map(s => `<li>${esc(s)}</li>`).join('');
    const saved = state.config.provider === key ? (state.config.fields || {}) : {};
    $('sso-fields').innerHTML = provider.fields.map(f => {
      const val = saved[f.key] || '';
      const input = f.options
        ? `<select id="f-${esc(f.key)}" class="sso-input">${Object.entries(f.options).map(([k, v]) =>
            `<option value="${esc(k)}"${val === k ? ' selected' : ''}>${esc(v)} (auth.pingone.${esc(k)})</option>`).join('')}</select>`
        : `<input id="f-${esc(f.key)}" class="sso-input" value="${esc(val)}" placeholder="${esc(f.placeholder || '')}" autocomplete="off" maxlength="256">`;
      return `<label class="sso-label">${esc(f.label)}${input}<span class="sso-help">${esc(f.help || '')}</span></label>`;
    }).join('');
    const same = state.config.provider === key;
    $('sso-client-id').value = same ? (state.config.client_id || '') : '';
    $('sso-client-secret').value = '';
    $('sso-client-secret').placeholder = same && state.config.client_secret_set ? 'Saved. Leave blank to keep it' : 'Paste the client secret';
    if (!same && !$('sso-button').value) $('sso-button').placeholder = `Sign in with ${provider.label}`;
    for (const id of ['sso-setup', 'sso-connect', 'sso-access']) $(id).style.display = '';
    $('sso-test-result').innerHTML = '';
  }

  function form() {
    const fields = {};
    for (const f of provider.fields) fields[f.key] = $(`f-${f.key}`).value.trim();
    return {
      provider: provider.key, fields, client_id: $('sso-client-id').value.trim(),
      client_secret: $('sso-client-secret').value || '__KEEP__', default_role: $('sso-default-role').value,
      no_access_message: $('sso-message').value, mode: $('sso-mode').value,
      button_label: $('sso-button').value.trim(), enabled: $('sso-enabled').checked,
    };
  }

  function showError(msg) {
    $('sso-error').textContent = msg || '';
    $('sso-error').style.display = msg ? 'block' : 'none';
  }

  async function test() {
    showError('');
    $('sso-test-result').textContent = 'Testing...';
    try {
      const d = await call('POST', form(), '/test');
      $('sso-test-result').innerHTML = d.checks.map(c =>
        `<div>${c.ok ? '&#10003;' : '&#10007;'} <b>${esc(c.name)}</b>: ${esc(c.detail)}</div>`).join('') +
        (d.next ? `<div class="text-muted" style="margin-top:6px">${esc(d.next)}</div>` : '');
    } catch (e) {
      $('sso-test-result').innerHTML = '';
      showError(e.message);
    }
  }

  async function save() {
    showError('');
    try {
      const d = await call('PUT', form());
      $('sso-client-secret').value = '';  // never leave the secret sitting in the page
      toast(d.warning || 'Saved. Try signing in from a private window.', d.warning ? 'info' : 'ok');
      await load(provider.key);
    } catch (e) {
      showError(e.message);
    }
  }

  async function load(keep) {
    state = await call('GET');
    warnings();
    const c = state.config;
    $('sso-default-role').innerHTML = state.roles.map(r =>
      `<option value="${esc(r)}"${(c.default_role || state.defaults.default_role) === r ? ' selected' : ''}>${esc(r.replace(/_/g, ' '))}</option>`).join('');
    $('sso-message').value = c.no_access_message || state.defaults.no_access_message;
    $('sso-mode').value = c.mode || state.defaults.mode;
    $('sso-button').value = c.button_label || '';
    $('sso-enabled').checked = !!c.enabled;
    renderProviders();
    if (keep || c.provider) choose(keep || c.provider);
  }

  document.addEventListener('click', ev => {
    const card = ev.target.closest('[data-provider]');
    if (card) return choose(card.dataset.provider);
    const copy = ev.target.closest('[data-copy]');
    if (copy) {
      navigator.clipboard?.writeText($(copy.dataset.copy).textContent).then(() => toast('Copied', 'ok'));
      return;
    }
    if (ev.target.id === 'sso-test') return test();
    if (ev.target.id === 'sso-save') return save();
  });

  document.addEventListener('DOMContentLoaded', () => load().catch(() => {
    $('sso-providers').innerHTML = '<div class="text-muted text-sm">Couldn\'t load single sign-on settings</div>';
  }));
})();
