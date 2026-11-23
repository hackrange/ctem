// Admin > Maintenance > Restore: pick or upload a backup, check it opens, restore it, and follow along.
(() => {
  const MT = window.MT;
  const $ = id => document.getElementById(id);
  let checked = null;   // the source the manifest preview was made for

  function sources(s) {
    const sel = $('mt-r-source');
    const keep = sel.value;
    const opts = [
      ...s.uploads.map(u => [`uploads|${u.name}`, `Uploaded ${MT.when(u.modified)} (${MT.bytes(u.size)})`]),
      ...s.backups.map(b => [`backups|${b.name}`, `${b.name} (${MT.bytes(b.size)})`]),
    ];
    sel.innerHTML = opts.length ? opts.map(([v, t]) => `<option value="${esc(v)}">${esc(t)}</option>`).join('')
      : '<option value="">No backups on this server yet. Upload one below.</option>';
    if (opts.some(([v]) => v === keep)) sel.value = keep;
    MT.show('mt-restore-off', s.agent.installed && !s.agent.ui_restore);
  }
  const prevOnState = MT.onState;
  MT.onState = s => { if (prevOnState) prevOnState(s); sources(s); };

  function picked() {
    const v = $('mt-r-source').value;
    const i = v.indexOf('|');
    return i < 0 ? null : { source: v.slice(0, i), name: v.slice(i + 1) };
  }

  function resetCheck() {
    checked = null;
    $('mt-r-manifest').innerHTML = '';
    MT.show('mt-r-go-panel', false);
    $('mt-r-confirm').value = '';
    $('mt-r-go').disabled = true;
  }

  // ── upload ─────────────────────────────────────────────────────────────────
  function upload(file) {
    const status = $('mt-upload-status');
    const max = MT.state ? MT.state.upload_max_bytes : 0;
    if (max && file.size > max) { status.textContent = `That file is over the ${MT.bytes(max)} limit. Copy it to the server instead.`; return; }
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${MT.API}/uploads`);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.setRequestHeader('Accept', 'application/json');
    xhr.upload.onprogress = e => {
      if (e.lengthComputable) status.textContent = `Uploading ${MT.bytes(e.loaded)} of ${MT.bytes(e.total)} (${Math.floor(e.loaded / e.total * 100)}%)`;
    };
    xhr.onload = async () => {
      let d = {};
      try { d = JSON.parse(xhr.responseText); } catch (_) { /* nginx error pages aren't JSON */ }
      if (xhr.status !== 200) {
        status.textContent = typeof d.detail === 'string' ? d.detail
          : xhr.status === 413 ? 'The upload is too big for the web server in front of open-ctem. Copy it to the server instead.'
          : 'The upload failed.';
        return;
      }
      status.textContent = `Uploaded ${file.name}.`;
      await MT.refresh();
      $('mt-r-source').value = `uploads|${d.name}`;
      resetCheck();
    };
    xhr.onerror = () => { status.textContent = 'The upload stopped. Check the connection and try again.'; };
    status.textContent = 'Starting upload...';
    xhr.send(file);
  }

  // ── check, then restore ────────────────────────────────────────────────────
  const LABELS = [['created_utc', 'Taken (UTC)'], ['host', 'From server'], ['app_version', 'open-ctem version'],
    ['git_commit', 'Code commit'], ['timescaledb', 'TimescaleDB'], ['db_name', 'Database']];

  async function check() {
    const src = picked();
    if (!src) return;
    resetCheck();
    $('mt-r-manifest').innerHTML = '<p class="mt-help">Opening the backup...</p>';
    try {
      const d = await MT.call('POST', '/restore/check', { ...src, password: $('mt-r-password').value });
      const m = d.manifest;
      const rows = LABELS.map(([k, label]) => `<dt>${esc(label)}</dt><dd>${esc(k === 'git_commit' ? m[k].slice(0, 12) : m[k]) || '-'}</dd>`).join('');
      const note = d.same_commit ? '' : `<p class="mt-help">This server runs code ${esc((d.server_commit || 'unknown').slice(0, 12))}.
        A backup from older code restores fine; one from newer code is refused, so update open-ctem first.</p>`;
      $('mt-r-manifest').innerHTML = `<p class="mt-ok">The password opens this backup.</p><dl class="mt-manifest">${rows}</dl>${note}`;
      checked = `${src.source}|${src.name}`;
      MT.show('mt-r-go-panel', !!(MT.state && MT.state.agent.ui_restore));
    } catch (e) {
      $('mt-r-manifest').innerHTML = e.message === 'cancelled' ? '' : `<p class="mt-bad">${esc(e.message)}</p>`;
    }
  }

  async function restore() {
    const src = picked();
    if (!src || checked !== `${src.source}|${src.name}` || $('mt-r-confirm').value !== 'RESTORE') return;
    $('mt-r-go').disabled = true;
    try {
      const d = await MT.call('POST', '/restore', { ...src, password: $('mt-r-password').value, confirm: 'RESTORE' });
      $('mt-r-password').value = '';
      resetCheck();
      follow(d.job);
    } catch (e) {
      if (e.message !== 'cancelled') toast(e.message, 'error');
      $('mt-r-go').disabled = false;
    }
  }

  // The app goes down partway through, and the restored server may not know this session
  function follow(jid) {
    MT.show('mt-r-progress', true);
    const state = $('mt-r-state');
    let misses = 0;
    const tick = async () => {
      let res;
      try {
        res = await fetch(`${MT.API}/jobs/${encodeURIComponent(jid)}`, { headers: { Accept: 'application/json' } });
      } catch (_) { res = null; }
      if (!res || res.status >= 500) {
        misses++;
        state.innerHTML = '<span class="mt-meh">The app is restarting while the restore runs. This page keeps checking...</span>';
        return setTimeout(tick, 5000);
      }
      if (res.status === 401 || res.redirected) {
        state.innerHTML = 'The server is back, running the restored data, which signs this session out. ' +
          '<a href="/login?next=%2Fadmin%2Fmaintenance">Sign in again</a> and check Recent activity for the result.';
        return;
      }
      const d = await res.json().catch(() => null);
      if (!d || !d.job) return setTimeout(tick, 3000);
      $('mt-r-log').textContent = d.log || '';
      $('mt-r-log').scrollTop = $('mt-r-log').scrollHeight;
      if (d.job.status === 'ok') {
        state.innerHTML = '<span class="mt-ok">Restore finished.</span> Reload the page; you may need to sign in again.';
        return;
      }
      if (d.job.status === 'failed') {
        state.innerHTML = `<span class="mt-bad">Restore failed:</span> ${esc(d.job.message || '')}`;
        MT.refresh();
        return;
      }
      state.innerHTML = `<span class="mt-meh">${d.job.status === 'queued' ? 'Waiting for the agent...' : 'Restoring...'}</span>` +
        (misses ? ' <span class="text-sm text-muted">(the app restarted once already)</span>' : '');
      setTimeout(tick, 3000);
    };
    tick();
  }

  $('mt-upload').addEventListener('change', e => { if (e.target.files[0]) upload(e.target.files[0]); e.target.value = ''; });
  $('mt-r-source').addEventListener('change', resetCheck);
  $('mt-r-check').addEventListener('click', check);
  $('mt-r-password').addEventListener('keydown', e => { if (e.key === 'Enter') check(); });
  $('mt-r-confirm').addEventListener('input', () => { $('mt-r-go').disabled = $('mt-r-confirm').value !== 'RESTORE'; });
  $('mt-r-go').addEventListener('click', restore);
})();
