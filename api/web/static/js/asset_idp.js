// The asset page's Identity tab (admins and cyber): who signs in on this computer according to the identity
// provider (Okta), how to reach them (the phone their MFA codes go to beats any directory field), their MFA, and
// the computer's posture as Okta Verify saw it. The tab appears only when there's something to show. Everything goes through esc().
window.AssetIdp = (() => {
  const FACTOR = { sms: 'SMS', call: 'Voice call', push: 'Okta Verify push', signed_nonce: 'Okta FastPass', webauthn: 'Security key or biometrics',
                   'token:software:totp': 'Authenticator app', 'token:hardware': 'Hardware token', email: 'Email', question: 'Security question',
                   u2f: 'Security key' };
  const STRONG = new Set(['push', 'signed_nonce', 'webauthn', 'u2f', 'token:software:totp', 'token:hardware']);
  const WHY = { assigned: 'Assigned', detected: 'Detected user' };
  const day = t => (t ? esc(new Date(t).toLocaleString()) : '--');
  const row = (k, v) => `<span class="text-muted">${esc(k)}</span><span>${v}</span>`;
  const tel = p => (p ? `<a class="dt-link text-mono" href="tel:${esc(String(p).replace(/[^0-9+]/g, ''))}">${esc(p)}</a>` : '--');

  function factors(list) {
    if (list == null) return '<span class="text-muted">Not read yet</span>';
    if (!list.length) return '<span class="chip chip--critical" style="font-size:.7rem">No MFA factor</span>';
    const weak = !list.some(f => STRONG.has(f));
    return list.map(f => `<span class="chip ${STRONG.has(f) ? 'chip--low' : 'chip--medium'}" style="font-size:.7rem">${esc(FACTOR[f] || f)}</span>`).join(' ')
      + (weak ? ' <span class="text-sm" style="color:var(--severity-high)">phishable factors only</span>' : '');
  }

  function person(p) {
    const phone = p.mfa_phone
      ? `${tel(p.mfa_phone)} <span class="chip chip--low" style="font-size:.65rem" title="The person proved they hold this phone when enrolling MFA">${p.mfa_phone_kind === 'call' ? 'MFA voice' : 'MFA SMS'}</span>`
      : '--';
    return `<div style="border-top:1px solid var(--border);padding:10px 14px">
      <div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px"><b>${esc(p.name)}</b>${window.IdvBadge ? IdvBadge.html(p.idv_verified_at, true) : ''}
        <span class="chip chip--info" style="font-size:.65rem">${esc(WHY[p.why] || p.why)}</span>
        ${p.account_status && p.account_status !== 'ACTIVE' ? `<span class="chip chip--medium" style="font-size:.65rem">${esc(p.account_status)}</span>` : ''}</div>
      <div class="text-sm" style="display:grid;grid-template-columns:150px minmax(0,1fr);gap:4px 10px;margin-top:6px">
        ${row('UPN', `<span class="text-mono">${esc(p.upn || '--')}</span>`)}
        ${p.title || p.department ? row('Role', esc([p.title, p.department].filter(Boolean).join(', '))) : ''}
        ${row('Contact phone', phone)}
        ${row('Mobile (directory)', tel(p.mobile))}
        ${row('Office phone', tel(p.phone))}
        ${row('Email', p.email ? `<a class="dt-link" href="mailto:${esc(p.email)}">${esc(p.email)}</a>` : '--')}
        ${row('MFA', factors(p.factors))}
        ${row('Last identity sign-in', day(p.last_login))}
      </div></div>`;
  }

  function device(d, ownerFromIdp) {
    if (!d) return '';
    const yes = (v, good) => (v == null ? '--' : `<span class="chip ${v === good ? 'chip--low' : 'chip--medium'}" style="font-size:.7rem">${v ? 'Yes' : 'No'}</span>`);
    const enc = d.disk_encryption == null ? '--' : `<span class="chip ${d.disk_encryption === 'NONE' ? 'chip--critical' : 'chip--low'}" style="font-size:.7rem">${esc(d.disk_encryption.replace(/_/g, ' ').toLowerCase())}</span>`;
    return `<div class="text-sm" style="display:grid;grid-template-columns:150px minmax(0,1fr);gap:4px 10px;padding:10px 14px">
      ${row('Status', esc(d.status || '--'))}
      ${row('Platform', esc([d.platform, d.os_version].filter(Boolean).join(' ') || '--'))}
      ${row('Hardware', esc([d.manufacturer, d.model].filter(Boolean).join(' ') || '--'))}
      ${row('Serial number', `<span class="text-mono">${esc(d.serial || '--')}</span>`)}
      ${row('Disk encryption', enc)}
      ${row('Secure hardware (TPM)', yes(d.secure_hardware, true))}
      ${row('Managed device', yes(d.managed, true))}
      ${row('Screen lock', esc((d.screen_lock || '--').toLowerCase()))}
      ${row('Registered', day(d.registered))}
      ${row('Last updated', day(d.updated))}
      ${ownerFromIdp ? row('Detected user', 'from the identity provider (no EDR sign-in history for this computer)') : ''}
    </div>`;
  }

  async function mount(id) {
    let d;
    try {
      const r = await fetch(`/api/v1/devices/${encodeURIComponent(id)}/identity`, { headers: { Accept: 'application/json' } });
      d = r.ok ? await r.json() : null;   // 404 for anyone but admins and cyber: no tab
    } catch (e) { d = null; }
    if (!d || (!d.device && !d.people.length)) return;
    const panel = AssetEdr.addTab('identity', 'Identity');
    if (!panel) return;
    panel.innerHTML = `<div class="panel__header"><span class="panel__title">People on this computer</span></div>
      ${d.people.map(person).join('') || '<p class="text-sm text-muted" style="margin:10px 14px">No one matched in the directory.</p>'}
      ${d.device ? `<div class="panel__header" style="border-top:1px solid var(--border)"><span class="panel__title">Identity provider device record</span></div>${device(d.device, d.owner_from_idp)}` : ''}`;
    if (location.hash === '#identity') AssetSoftware.show('identity');
  }
  return { mount };
})();
