// Admin > Maintenance: backups, daily schedule, activity, and the "confirm it's you" step-up.
// The host agent does the work; this page queues requests and watches them finish.
(() => {
  const API = '/api/v1/admin/maintenance';
  const $ = id => document.getElementById(id);
  const MT = window.MT = { state: null, API };

  // ── helpers ────────────────────────────────────────────────────────────────
  MT.bytes = n => {
    if (n == null) return '-';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i && n < 10 ? 1 : 0)} ${u[i]}`;
  };
  MT.when = ts => ts ? new Date(ts * 1000).toLocaleString() : '-';
  MT.ago = ts => {
    if (!ts) return 'never';
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 90) return 'just now';
    if (s < 5400) return `${Math.round(s / 60)} minutes ago`;
    if (s < 129600) return `${Math.round(s / 3600)} hours ago`;
    return `${Math.round(s / 86400)} days ago`;
  };
  const show = (id, on) => { $(id).style.display = on ? '' : 'none'; };
  MT.show = show;

  MT.call = async (method, path, body, retried) => {
    const res = await fetch(API + path, {
      method, headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const d = await res.json().catch(() => ({}));
    if (res.status === 403 && res.headers.get('X-Step-Up') === 'required' && !retried) {
      await MT.stepUp();
      return MT.call(method, path, body, true);
    }
    if (!res.ok) {
      const e = new Error(typeof d.detail === 'string' ? d.detail : 'That did not work. Try again.');
      e.status = res.status;
      throw e;
    }
    return d;
  };

  // ── confirm it's you ───────────────────────────────────────────────────────
  let pending = null;
  MT.stepUp = () => new Promise((resolve, reject) => {
    const needs = (MT.state && MT.state.step_up.needs) || ['password'];
    show('mt-su-password', needs.includes('password'));
    show('mt-su-code', needs.includes('code'));
    show('mt-su-sso', !needs.length);
    $('mt-su-password').value = ''; $('mt-su-code').value = ''; $('mt-su-err').textContent = '';
    pending = { resolve, reject };
    show('mt-stepup-modal', true);
    (needs.includes('password') ? $('mt-su-password') : $('mt-su-code')).focus();
  });
  MT.ensureStepUp = async () => {
    const until = MT.state && MT.state.step_up.until;
    if (until && until - Date.now() / 1000 > 30) return;
    await MT.stepUp();
  };
  async function confirmStepUp() {
    try {
      const d = await MT.call('POST', '/step-up', { password: $('mt-su-password').value, code: $('mt-su-code').value }, true);
      if (MT.state) MT.state.step_up.until = d.until;
      show('mt-stepup-modal', false);
      const p = pending; pending = null;
      if (p) p.resolve();
    } catch (e) { $('mt-su-err').textContent = e.message; }
  }
  function closeModal(id) {
    show(id, false);
    if (id === 'mt-stepup-modal' && pending) { const p = pending; pending = null; p.reject(new Error('cancelled')); }
  }

  // ── rendering ──────────────────────────────────────────────────────────────
  const KIND = { manual: 'By hand', scheduled: 'Daily', safety: 'Safety (before a restore)', uploaded: 'Uploaded', other: 'Copied in' };
  const PW = { default: 'Server password', custom: 'Its own password', unknown: 'Unknown' };
  const ACTION = { backup: 'Backup', restore: 'Restore', delete: 'Delete backup', schedule: 'Change schedule', unknown: 'Request' };
  const STATUS = { ok: ['mt-ok', 'Done'], failed: ['mt-bad', 'Failed'], running: ['mt-meh', 'Running'], queued: ['mt-meh', 'Waiting'] };

  function alerts(s) {
    const a = [];
    if (!s.agent.installed) {
      a.push(`The maintenance agent isn't set up on this server yet, so nothing here can run. On the server, run:
        <code>${esc(s.setup_command)}</code>`);
    } else if (!s.agent.alive) {
      a.push('The maintenance agent has not checked in for over 15 minutes. On the server, check <code>systemctl status ctem-maintenance.timer</code>.');
    }
    if (s.stale) a.push('Daily backups are on, but the newest backup is more than 26 hours old. Check Recent activity below.');
    if (s.agent.installed && s.agent.default_password !== 'ok') {
      a.push('BACKUP_ENCRYPTION_PASSWORD in the server\'s .env is missing or too weak, so daily backups can\'t run. ' +
        'Set it (16+ characters), or give each backup its own password.');
    }
    $('mt-alerts').innerHTML = a.map(t => `<div class="panel mt-panel mt-warn">${t}</div>`).join('');
  }

  function cards(s) {
    const ag = s.agent;
    $('mt-agent').innerHTML = !ag.installed ? '<span class="mt-bad">Not set up</span>'
      : !ag.alive ? '<span class="mt-bad">Not responding</span>'
      : ag.busy ? '<span class="mt-meh">Working</span>' : `<span class="mt-ok">Ready</span> <span class="text-sm text-muted">checked in ${esc(MT.ago(ag.heartbeat))}</span>`;
    $('mt-newest').innerHTML = s.newest_backup ? `${esc(MT.ago(s.newest_backup))}` : '<span class="mt-meh">None yet</span>';
    $('mt-disk').textContent = ag.disk_free == null ? '-' : `${MT.bytes(ag.disk_free)} of ${MT.bytes(ag.disk_total)}`;
    const dp = { ok: ['mt-ok', 'Set'], weak: ['mt-bad', 'Too weak'], missing: ['mt-bad', 'Missing'], unknown: ['text-muted', 'Unknown'] }[ag.default_password];
    $('mt-defpw').innerHTML = `<span class="${dp[0]}">${dp[1]}</span>`;
  }

  function backups(s) {
    $('mt-backups').innerHTML = s.backups.length ? s.backups.map(b => `<tr>
        <td><code>${esc(b.name)}</code></td><td>${esc(MT.when(b.modified))}</td><td>${esc(MT.bytes(b.size))}</td>
        <td>${esc(KIND[b.kind] || b.kind)}${b.by && b.by !== 'schedule' ? ` <span class="text-muted text-sm">by ${esc(b.by)}</span>` : ''}</td>
        <td>${esc(PW[b.password] || '')}</td>
        <td style="white-space:nowrap"><button class="btn btn--ghost btn--sm" data-dl="${esc(b.name)}">Download</button>
          <button class="btn btn--ghost btn--sm" data-del="${esc(b.name)}">Delete</button></td></tr>`).join('')
      : '<tr><td colspan="6" class="text-muted text-sm mt-empty">No backups yet.</td></tr>';
  }

  function schedule(s) {
    const sc = s.schedule;
    if (!$('mt-sched-hour').options.length) {
      $('mt-sched-hour').innerHTML = Array.from({ length: 24 }, (_, h) => `<option value="${h}">${String(h).padStart(2, '0')}:00 UTC</option>`).join('');
    }
    if (!MT.schedTouched) {
      $('mt-sched-on').checked = sc.enabled;
      $('mt-sched-hour').value = String(sc.hour);
      $('mt-sched-keep').value = String(sc.keep);
    }
    localHour();
    $('mt-sched-last').textContent = sc.last_attempt
      ? `Last daily run ${MT.ago(sc.last_attempt)}: ${sc.last_ok ? 'worked' : 'failed'}.` : '';
  }
  function localHour() {
    const d = new Date(); d.setUTCHours(Number($('mt-sched-hour').value), 0, 0, 0);
    $('mt-sched-local').textContent = `(${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} your time)`;
  }

  function jobs(s) {
    $('mt-jobs').innerHTML = s.jobs.length ? s.jobs.map(j => {
      const st = STATUS[j.status] || ['text-muted', j.status || ''];
      const what = `${ACTION[j.action] || 'Request'}${j.file ? ` <code>${esc(j.file)}</code>` : ''}`;
      return `<tr><td>${esc(MT.when(j.started))}</td><td>${what}</td><td>${esc(j.by || '')}</td>
        <td><span class="${st[0]}">${esc(st[1])}</span> <span class="text-sm">${esc(j.message || '')}</span></td>
        <td><button class="btn btn--ghost btn--sm" data-log="${esc(j.id)}">Log</button></td></tr>`;
    }).join('') : '<tr><td colspan="5" class="text-muted text-sm mt-empty">Nothing yet.</td></tr>';
  }

  MT.refresh = async () => {
    try {
      const s = await MT.call('GET', '');
      MT.state = s;
      alerts(s); cards(s); backups(s); schedule(s); jobs(s);
      if (MT.onState) MT.onState(s);
    } catch (e) { $('mt-alerts').innerHTML = `<div class="panel mt-panel mt-warn">${esc(e.message)}</div>`; }
    clearTimeout(MT.timer);
    const busy = MT.state && (MT.state.agent.busy || MT.state.jobs.some(j => j.status === 'running' || j.status === 'queued'));
    MT.timer = setTimeout(MT.refresh, busy ? 5000 : 30000);
  };

  // ── actions ────────────────────────────────────────────────────────────────
  async function startBackup() {
    const mode = document.querySelector('input[name="mt-pwmode"]:checked').value;
    const body = { password_mode: mode };
    if (mode === 'custom') { body.password = $('mt-pw1').value; body.confirm = $('mt-pw2').value; }
    try {
      await MT.call('POST', '/backups', body);
      $('mt-pw1').value = ''; $('mt-pw2').value = '';
      show('mt-backup-modal', false);
      toast('Backup started. It shows up in the list when it is done.', 'ok');
      MT.refresh();
    } catch (e) { $('mt-backup-err').textContent = e.message; }
  }

  async function download(name) {
    try {
      await MT.ensureStepUp();
      window.location.href = `${API}/backups/${encodeURIComponent(name)}/download`;
    } catch (e) { if (e.message !== 'cancelled') toast(e.message, 'error'); }
  }

  async function remove(name) {
    if (!confirm(`Delete ${name}? It can't be brought back.`)) return;
    try {
      await MT.call('DELETE', `/backups/${encodeURIComponent(name)}`);
      toast('Deleting the backup...', 'ok');
      setTimeout(MT.refresh, 1500);
    } catch (e) { if (e.message !== 'cancelled') toast(e.message, 'error'); }
  }

  async function saveSchedule() {
    const body = { enabled: $('mt-sched-on').checked, hour: Number($('mt-sched-hour').value), keep: Number($('mt-sched-keep').value) };
    try {
      await MT.call('PUT', '/schedule', body);
      MT.schedTouched = false;
      toast('Schedule saved.', 'ok');
      setTimeout(MT.refresh, 1500);
    } catch (e) { if (e.message !== 'cancelled') toast(e.message, 'error'); }
  }

  async function showLog(jid) {
    try {
      const d = await MT.call('GET', `/jobs/${encodeURIComponent(jid)}`);
      $('mt-log-title').textContent = `${ACTION[d.job.action] || 'Job'}: ${(STATUS[d.job.status] || ['', d.job.status])[1]}`;
      $('mt-log-body').textContent = d.log || d.job.message || 'No output.';
      show('mt-log-modal', true);
    } catch (e) { toast(e.message, 'error'); }
  }

  function subTab(name) {
    for (const t of ['backups', 'restore']) {
      show(`sub-${t}`, t === name);
      document.querySelector(`[data-sub="${t}"]`).classList.toggle('is-active', t === name);
    }
  }

  // ── wiring ─────────────────────────────────────────────────────────────────
  document.addEventListener('click', e => {
    const t = e.target.closest('[data-close],[data-dl],[data-del],[data-log],[data-sub]');
    if (!t) return;
    if (t.dataset.close) closeModal(t.dataset.close);
    else if (t.dataset.dl) download(t.dataset.dl);
    else if (t.dataset.del) remove(t.dataset.del);
    else if (t.dataset.log) showLog(t.dataset.log);
    else if (t.dataset.sub) { e.preventDefault(); history.replaceState(null, '', `#${t.dataset.sub}`); subTab(t.dataset.sub); }
  });
  $('mt-new-backup').addEventListener('click', () => { $('mt-backup-err').textContent = ''; show('mt-backup-modal', true); });
  document.querySelectorAll('input[name="mt-pwmode"]').forEach(r => r.addEventListener('change', () =>
    show('mt-custom-pw', document.querySelector('input[name="mt-pwmode"]:checked').value === 'custom')));
  $('mt-backup-go').addEventListener('click', startBackup);
  $('mt-su-go').addEventListener('click', confirmStepUp);
  for (const id of ['mt-su-password', 'mt-su-code']) {
    $(id).addEventListener('keydown', e => { if (e.key === 'Enter') confirmStepUp(); });
  }
  for (const id of ['mt-sched-on', 'mt-sched-hour', 'mt-sched-keep']) {
    $(id).addEventListener('change', () => { MT.schedTouched = true; localHour(); });
  }
  $('mt-sched-save').addEventListener('click', saveSchedule);

  subTab(location.hash === '#restore' ? 'restore' : 'backups');
  MT.refresh();
})();
