// Caller verification panel, framed in the service desk's ticket (api/routes/desk_embed.py).
// The launch token arrives in the URL fragment (never sent to a server); it is cleared at once and traded for a
// session key held only in this script's memory and sent as X-Desk-Key. No cookies, no storage. The page's policy
// allows no inline script or style, so everything here is built with DOM calls and classes; text is set with
// textContent, never as markup. The result is posted to the ticket only at the exact origin CTEM recorded.
(() => {
  const root = document.getElementById('desk');
  const API = '/api/v1/idv/desk';
  let key = null, info = null, picked = null, timer = null, lastResult = null;

  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const clear = n => { while (n.firstChild) n.removeChild(n.firstChild); };
  const day = s => (s ? new Date(s).toLocaleString() : '');

  async function call(path, opts = {}) {
    const r = await fetch(API + path, { ...opts, credentials: 'omit', cache: 'no-store',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...(key ? { 'X-Desk-Key': key } : {}) } });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(typeof d.detail === 'string' ? d.detail : 'That did not go through.'); e.status = r.status; throw e; }
    return d;
  }

  function fatal(msg) {
    clear(root);
    root.appendChild(el('div', 'desk-banner desk-banner--error', msg));
    if (timer) clearInterval(timer);
  }

  // ── start: trade the launch token ──────────────────────────────────────────
  async function start() {
    const launch = location.hash.slice(1);
    history.replaceState(null, '', location.pathname);   // the fragment is gone from the address and history
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(launch)) { fatal('Open this panel from a ticket.'); return; }
    try {
      info = await call('/exchange', { method: 'POST', body: JSON.stringify({ launch }) });
    } catch (e) { fatal(e.message); return; }
    key = info.key;
    layout();
    if (info.caller) { search.input.value = info.caller; lookup(); }
  }

  // ── layout ─────────────────────────────────────────────────────────────────
  const search = {};
  let personBox, statusBox;
  function layout() {
    clear(root);
    const head = el('header', 'desk-head');
    head.appendChild(el('h1', 'desk-title', 'Caller verification'));
    head.appendChild(el('span', 'desk-muted', `${info.ticket} · ${info.analyst}`));
    root.appendChild(head);
    const form = el('form', 'desk-search');
    search.input = el('input', 'desk-input');
    Object.assign(search.input, { type: 'search', placeholder: 'Caller name, username or email', maxLength: 64, autocomplete: 'off' });
    search.input.setAttribute('aria-label', 'Find the caller');
    const go = el('button', 'desk-btn', 'Find');
    go.type = 'submit';
    form.append(search.input, go);
    form.addEventListener('submit', e => { e.preventDefault(); lookup(); });
    search.results = el('ul', 'desk-results');
    root.append(form, search.results);
    personBox = el('section', 'desk-person');
    statusBox = el('section', 'desk-status');
    personBox.hidden = statusBox.hidden = true;
    root.append(personBox, statusBox);
  }

  async function lookup() {
    const q = search.input.value.trim();
    clear(search.results);
    if (q.length < 2) return;
    try {
      const d = await call(`/s/lookup?q=${encodeURIComponent(q)}`);
      if (!d.people.length) search.results.appendChild(el('li', 'desk-muted', 'No one found. Check the spelling, or try their username.'));
      for (const p of d.people) {
        const li = el('li'), b = el('button', 'desk-result');
        b.type = 'button';
        b.append(el('b', null, p.name), el('span', 'desk-muted', [p.title, p.department, p.username].filter(Boolean).join(' · ')));
        if (p.verified_at) b.appendChild(el('span', 'desk-chip desk-chip--ok', 'IDV'));
        b.addEventListener('click', () => choose(p.id));
        li.appendChild(b);
        search.results.appendChild(li);
      }
    } catch (e) { search.results.appendChild(el('li', 'desk-error', e.message)); if (e.status === 401) fatal(e.message); }
  }

  // ── the caller's card and the send ─────────────────────────────────────────
  async function choose(id) {
    clear(search.results);
    try { picked = await call(`/s/person/${encodeURIComponent(id)}`); } catch (e) { fatal(e.message); return; }
    clear(personBox);
    personBox.hidden = false;
    statusBox.hidden = true;
    personBox.appendChild(el('h2', 'desk-name', picked.name));
    personBox.appendChild(el('p', 'desk-muted', [picked.title, picked.department, picked.username].filter(Boolean).join(' · ')));
    personBox.appendChild(el('p', picked.verified_at ? 'desk-ok' : 'desk-muted',
      picked.verified_at ? `Last verified ${day(picked.verified_at)}` : 'Not verified before'));
    if (picked.blocked || (picked.missing || []).length) {
      personBox.appendChild(el('div', 'desk-banner desk-banner--error',
        picked.blocked ? `A link can't go to this person: ${picked.blocked}.` : `Can't send yet: ${picked.missing.join('; ')}.`));
      return;
    }
    const usable = picked.channels.filter(c => c.available);
    if (!usable.length) {
      personBox.appendChild(el('div', 'desk-banner desk-banner--error', 'No verified MFA phone or email for this person. Verify them another way.'));
      return;
    }
    const p = picked.plan || { kind: 'id_selfie', why: '' };
    const plan = el('div', 'desk-plan');
    plan.appendChild(el('b', null, p.persona_decides ? 'Persona decides what they verify with'
      : `They will verify with: ${p.kind === 'selfie' ? 'a selfie' : 'a government ID and a selfie'}`));
    const idTxt = p.active_id ? ` On file: ${p.active_id.id_type || 'Government ID'}${p.active_id.country ? ` (${p.active_id.country})` : ''}${
      p.active_id.at ? `, verified ${new Date(p.active_id.at).toLocaleDateString()}` : ''}.` : '';
    plan.appendChild(el('span', 'desk-muted', ` ${p.why || ''}${idTxt}`));
    if (p.warning) plan.appendChild(el('span', 'desk-error', p.warning));
    let full = null;
    if (p.kind === 'selfie' && !p.persona_decides) {
      const lab = el('label', 'desk-channel');
      full = el('input');
      full.type = 'checkbox';
      lab.append(full, el('span', null, 'Require a government ID and a selfie instead'));
      plan.appendChild(lab);
    }
    personBox.appendChild(plan);
    const list = el('div', 'desk-channels');
    usable.forEach((c, i) => {
      const lab = el('label', 'desk-channel'), r = el('input');
      Object.assign(r, { type: 'radio', name: 'desk-ch', value: c.channel, checked: i === 0 });
      r.dataset.recent = c.recent ? '1' : '';
      const txt = el('span');
      txt.append(el('b', null, c.channel === 'sms' ? 'Text' : 'Email'), document.createTextNode(` to ${c.shown} `),
        el('span', 'desk-muted', `(${c.source}${c.since ? `, since ${new Date(c.since).toLocaleDateString()}` : ''})`));
      if (c.recent) txt.appendChild(el('span', 'desk-chip desk-chip--warn', c.since ? 'changed in the last 7 days' : 'enrollment date unknown'));
      lab.append(r, txt);
      list.appendChild(lab);
    });
    const confirm = el('label', 'desk-confirm'), box = el('input');
    box.type = 'checkbox';
    confirm.append(box, el('span', null, 'This contact changed recently, as in an account takeover. I confirmed it is theirs another way.'));
    const sync = () => { const p = list.querySelector('input:checked'); confirm.hidden = !(p && p.dataset.recent); };
    list.addEventListener('change', sync);
    const send = el('button', 'desk-btn desk-btn--primary', 'Send verification link');
    send.type = 'button';
    const msg = el('p', 'desk-error');
    send.addEventListener('click', async () => {
      const p = list.querySelector('input:checked');
      if (p.dataset.recent && !box.checked) { msg.textContent = 'Tick the box once you have confirmed the contact.'; return; }
      send.disabled = true;
      msg.textContent = '';
      try {
        await call('/s/send', { method: 'POST', body: JSON.stringify({ person: picked.id, channel: p.value, confirm_recent: !!(p.dataset.recent && box.checked),
                                                     kind: full && full.checked ? 'id_selfie' : 'auto' }) });
        watch();
      } catch (e) { msg.textContent = e.message; send.disabled = false; if (e.status === 401) fatal(e.message); }
    });
    personBox.append(list, confirm, send, msg);
    sync();
  }

  // ── live status ────────────────────────────────────────────────────────────
  function watch() {
    statusBox.hidden = false;
    lastResult = null;
    poll();
    if (timer) clearInterval(timer);
    timer = setInterval(poll, 2500);
  }

  async function poll() {
    let d;
    try { d = await call('/s/status'); } catch (e) { if (e.status === 401) fatal(e.message); return; }
    clear(statusBox);
    const ol = el('ol', 'desk-steps');
    for (const s of d.steps || []) {
      const li = el('li', `desk-step${s.done ? ' desk-step--done' : ''}`, s.label);
      ol.appendChild(li);
    }
    statusBox.appendChild(ol);
    if (d.result) {
      const kind = { verified: 'ok', failed: 'error', error: 'error', warning: 'warn' }[d.result.kind] || 'warn';
      const b = el('div', `desk-banner desk-banner--${kind}`);
      b.append(el('strong', 'desk-banner__title', d.result.title), el('span', null, d.result.detail || ''));
      if (d.result.next) b.appendChild(el('span', 'desk-next', d.result.next));
      statusBox.appendChild(b);
      clearInterval(timer);
      if (lastResult !== d.result.kind) {
        lastResult = d.result.kind;
        // to the ticket, at its exact origin only; the ticket's server can confirm it with its token
        if (window.parent !== window && info.parent_origin) {
          window.parent.postMessage({ type: 'ctem.idv.result', ticket: info.ticket, result: d.result.kind, title: d.result.title,
                                      detail: d.result.detail || '', at: new Date().toISOString() }, info.parent_origin);
        }
      }
      const again = el('button', 'desk-btn', 'Verify another caller');
      again.type = 'button';
      again.addEventListener('click', () => { personBox.hidden = statusBox.hidden = true; search.input.value = ''; search.input.focus(); });
      statusBox.appendChild(again);
    } else if (d.link_expires_at) {
      statusBox.appendChild(el('p', 'desk-muted', `Waiting for the caller. The link works until ${day(d.link_expires_at)}.`));
    }
  }

  start();
})();
