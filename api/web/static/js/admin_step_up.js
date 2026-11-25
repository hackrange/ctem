// Admin > Users: the "confirm it's you" step-up before granting admin, setting another account's password, or
// replacing or removing its authenticator. Same check (and the same 10-minute pass) as Admin > Maintenance.
window.AdminStepUp = (() => {
  const $ = id => document.getElementById(id);
  const show = (id, on) => { $(id).style.display = on ? '' : 'none'; };
  let pending = null;

  function ask(needs) {
    return new Promise((resolve, reject) => {
      const want = needs.filter(n => n === 'password' || n === 'code');
      show('admin-su-password', want.includes('password'));
      show('admin-su-code', want.includes('code'));
      show('admin-su-sso', !want.length);
      $('admin-su-password').value = ''; $('admin-su-code').value = ''; $('admin-su-err').textContent = '';
      pending = { resolve, reject };
      $('admin-stepup-modal').style.display = 'flex';
      (want.includes('password') ? $('admin-su-password') : $('admin-su-code')).focus();
    });
  }

  async function confirm() {
    const res = await fetch('/api/v1/admin/maintenance/step-up', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ password: $('admin-su-password').value, code: $('admin-su-code').value }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      $('admin-su-err').textContent = typeof d.detail === 'string' ? d.detail : 'That did not work. Try again.';
      return;
    }
    show('admin-stepup-modal', false);
    const p = pending; pending = null;
    if (p) p.resolve();
  }

  function cancel() {
    show('admin-stepup-modal', false);
    const p = pending; pending = null;
    if (p) p.reject(new Error('Cancelled'));
  }

  document.addEventListener('DOMContentLoaded', () => {
    $('admin-su-go').addEventListener('click', confirm);
    document.querySelectorAll('[data-su-cancel]').forEach(b => b.addEventListener('click', cancel));
    for (const id of ['admin-su-password', 'admin-su-code']) {
      $(id).addEventListener('keydown', e => { if (e.key === 'Enter') confirm(); });
    }
  });
  return { ask };
})();
