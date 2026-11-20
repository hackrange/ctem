// Assign a device to the person who's supposed to use it. Server checks devices:write and device access.
(function () {
  const API = '/api/v1/devices';

  async function send(method, url, body) {
    const res = await fetch(url, {
      method, headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 403) throw new Error('Only admin and inventory roles can change this');
    if (!res.ok) throw new Error('Could not save the assignment');
  }

  async function assign(deviceId, userId, note) {
    await send('PUT', `${API}/${encodeURIComponent(deviceId)}/assignment`, { user_id: userId, note: note || null });
  }

  async function unassign(deviceId) {
    await send('DELETE', `${API}/${encodeURIComponent(deviceId)}/assignment`);
  }

  // Small picker: type 2+ letters, pick a directory user, optional note
  function open(device, onDone) {
    const wrap = document.createElement('div');
    wrap.className = 'sh-modal';
    wrap.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:1000';
    wrap.innerHTML = `
      <div class="panel" style="width:min(440px,92vw);padding:18px" role="dialog" aria-modal="true" aria-label="Assign device">
        <h3 style="margin:0 0 4px;font-size:1rem">Assign ${esc(device.hostname || 'device')}</h3>
        <p class="text-sm text-muted" style="margin:0 0 12px">Who is supposed to use this machine? Syncs never change this.</p>
        <input class="search-bar" id="da-q" type="search" placeholder="Search username..." autocomplete="off" style="width:100%">
        <div id="da-list" style="max-height:220px;overflow:auto;margin:8px 0"></div>
        <input class="search-bar" id="da-note" type="text" maxlength="256" placeholder="Note (optional)" style="width:100%">
        <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:12px">
          <button type="button" class="btn btn--ghost btn--sm" data-x>Cancel</button>
        </div>
      </div>`;
    document.body.appendChild(wrap);
    const close = () => wrap.remove();
    wrap.addEventListener('click', e => { if (e.target === wrap || e.target.hasAttribute('data-x')) close(); });
    const q = wrap.querySelector('#da-q'), list = wrap.querySelector('#da-list');
    let timer, seq = 0;
    q.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        const term = q.value.trim(), mine = ++seq;
        if (term.length < 2) { list.innerHTML = ''; return; }
        try {
          const res = await fetch(`${API}/assignable-users?q=${encodeURIComponent(term)}`, { headers: { Accept: 'application/json' } });
          if (res.status === 403) throw new Error('Only admin and inventory roles can change this');
          const data = res.ok ? await res.json() : { users: [] };
          if (mine !== seq) return;
          list.innerHTML = (data.users || []).map(u => `
            <button type="button" class="btn btn--ghost btn--sm" data-id="${esc(u.id)}" style="display:block;width:100%;text-align:left;margin:2px 0">
              <strong>${esc(u.username)}</strong> <span class="text-muted">${esc(u.name !== u.username ? u.name : '')}${u.title ? ' - ' + esc(u.title) : ''}</span>
            </button>`).join('') || '<p class="text-sm text-muted">No directory users match</p>';
        } catch (e) { list.innerHTML = `<p class="text-sm text-muted">${esc(e.message)}</p>`; }
      }, 250);
    });
    list.addEventListener('click', async e => {
      const b = e.target.closest('button[data-id]');
      if (!b) return;
      try {
        await assign(device.id, b.dataset.id, wrap.querySelector('#da-note').value.trim());
        close();
        toast('Assigned', 'success');
        onDone && onDone();
      } catch (err) { toast(err.message, 'error'); }
    });
    q.focus();
  }

  async function confirmDetected(device, onDone) {
    try {
      await assign(device.id, device.detected_user_id);
      toast(`Assigned to ${device.detected_user}`, 'success');
      onDone && onDone();
    } catch (err) { toast(err.message, 'error'); }
  }

  async function remove(device, onDone) {
    try {
      await unassign(device.id);
      toast('Assignment removed', 'success');
      onDone && onDone();
    } catch (err) { toast(err.message, 'error'); }
  }

  const LABELS = { shipped: ['Shipped', 'info'], lost: ['Lost', 'high'], stolen: ['Stolen', 'critical'], returned: ['Returned', 'low'] };
  const CARRIERS = {
    ups: ['UPS', n => `https://www.ups.com/track?tracknum=${encodeURIComponent(n)}`],
    fedex: ['FedEx', n => `https://www.fedex.com/fedextrack/?trknbr=${encodeURIComponent(n)}`],
    usps: ['USPS', n => `https://tools.usps.com/go/TrackConfirmAction?tLabels=${encodeURIComponent(n)}`],
    dhl: ['DHL', n => `https://www.dhl.com/global-en/home/tracking.html?tracking-id=${encodeURIComponent(n)}&submit=1`],
  };

  function trackingLink(st) {
    const c = st && CARRIERS[st.carrier];
    if (!c || !st.tracking_number) return '';
    return `<a class="dt-link" href="${esc(c[1](st.tracking_number))}" target="_blank" rel="noopener noreferrer">${esc(c[0])} ${esc(st.tracking_number)}</a>`;
  }

  function statusChip(st, withTracking) {
    if (!st || !LABELS[st.status]) return '';
    const [label, cls] = LABELS[st.status];
    const carrier = CARRIERS[st.carrier] ? ` via ${CARRIERS[st.carrier][0]} ${st.tracking_number}` : '';
    const who = `${st.by || '?'}${st.at ? ', ' + new Date(st.at).toLocaleDateString() : ''}${carrier}${st.note ? ': ' + st.note : ''}`;
    return `<span class="chip chip--${cls}" style="font-size:.7rem" title="${esc(who)}">${esc(label)}</span>`
      + (withTracking ? ' ' + trackingLink(st) : '');
  }

  async function setStatus(device, body, onDone) {
    try {
      const res = await fetch(`${API}/${encodeURIComponent(device.id)}/status`, {
        method: 'PUT', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      if (res.status === 403) throw new Error('Only admin and inventory roles can change this');
      if (res.status === 422) throw new Error(body.status === 'shipped' ? 'Shipped needs a carrier and a valid tracking number' : 'Check the status details');
      if (!res.ok) throw new Error('Could not save the status');
      toast(body.status ? `Marked ${LABELS[body.status][0].toLowerCase()}` : 'Back in normal use', 'success');
      onDone && onDone();
    } catch (err) { toast(err.message, 'error'); }
  }

  window.DeviceAssign = { open, confirmDetected, remove, setStatus, statusChip, CARRIERS };
})();
