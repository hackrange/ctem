// Settings > Integrations: Pause syncing (admins). While paused no scheduled sync starts, Sync Now is refused and
// on-prem shippers send again on their next run; syncs already running finish. A pause can end on its own.
(() => {
  const $ = id => document.getElementById(id);
  const API = '/api/v1/integrations/sync-pause';
  const LABEL = { 30: '30 minutes', 60: '1 hour', 240: '4 hours' };
  const head = document.querySelector('.page-header');
  if (!head) return;
  let durations = [30, 60, 240];

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'btn btn--ghost btn--sm';
  btn.id = 'sp-btn';
  btn.hidden = true;
  const add = head.querySelector(':scope > button');
  const group = document.createElement('div');   // beside "+ Add Integration", not spread across the header
  group.style.cssText = 'display:flex;gap:8px;align-items:flex-start';
  if (add) head.replaceChild(group, add);
  else head.appendChild(group);
  group.append(btn, ...(add ? [add] : []));

  const bar = document.createElement('div');
  bar.id = 'sp-bar';
  bar.setAttribute('role', 'status');
  bar.hidden = true;
  bar.style.cssText = 'margin:0 0 14px;padding:10px 14px;border:1px solid var(--severity-medium);border-radius:6px;background:var(--surface);display:flex;gap:12px;align-items:center;flex-wrap:wrap';
  head.insertAdjacentElement('afterend', bar);

  const when = s => new Date(s).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

  function draw(p) {
    btn.hidden = false;
    if (p) {
      btn.textContent = 'Resume syncing';
      btn.onclick = () => send({ paused: false });
      bar.hidden = false;
      bar.innerHTML = `<span>&#9208; <b>Integration syncing is paused</b> by ${esc(p.by || 'an admin')} since ${esc(when(p.at))}.
        ${p.until ? `It resumes on its own at ${esc(when(p.until))}.` : 'It stays paused until someone resumes it.'}
        No sync starts and shippers send again on their next run; syncs already running finish.</span>
        <button type="button" class="btn btn--primary btn--sm" id="sp-resume">Resume syncing</button><span class="text-sm" id="sp-msg"></span>`;
      $('sp-resume').onclick = () => send({ paused: false });
    } else {
      btn.textContent = 'Pause syncing';
      btn.onclick = choose;
      bar.hidden = true;
      bar.innerHTML = '';
    }
  }

  function choose() {
    bar.hidden = false;
    bar.innerHTML = `<span><b>Pause all integration syncing</b> for</span>
      ${durations.map((m, i) => `<label class="text-sm" style="display:flex;gap:4px;align-items:center"><input type="radio" name="sp-for" value="${m}"${i === 0 ? ' checked' : ''}>${esc(LABEL[m] || `${m} minutes`)}</label>`).join('')}
      <label class="text-sm" style="display:flex;gap:4px;align-items:center"><input type="radio" name="sp-for" value="">until I resume</label>
      <button type="button" class="btn btn--primary btn--sm" id="sp-go">Pause</button>
      <button type="button" class="btn btn--ghost btn--sm" id="sp-cancel">Cancel</button><span class="text-sm" id="sp-msg"></span>
      <div class="text-sm text-muted" style="flex-basis:100%">No scheduled sync starts, Sync Now is refused and on-prem shippers send again on their next run. Syncs already running finish.</div>`;
    $('sp-cancel').onclick = load;
    $('sp-go').onclick = () => {
      const v = (bar.querySelector('input[name="sp-for"]:checked') || {}).value;
      send({ paused: true, minutes: v ? Number(v) : null });
    };
  }

  async function send(body) {
    bar.querySelectorAll('button').forEach(b => { b.disabled = true; });
    btn.disabled = true;
    try {
      const r = await fetch(API, { method: 'PUT', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'That did not work. Try again.');
      draw(d.paused);
    } catch (e) {
      const m = $('sp-msg');
      if (m) { m.textContent = e.message; m.style.color = 'var(--severity-critical)'; }
      bar.querySelectorAll('button').forEach(b => { b.disabled = false; });
    } finally { btn.disabled = false; }
  }

  async function load() {
    try {
      const r = await fetch(API, { headers: { Accept: 'application/json' } });
      if (!r.ok) return;   // not an admin: no button
      const d = await r.json();
      durations = d.durations || durations;
      if (bar.querySelector('#sp-go')) return;   // they're choosing: leave the choice open
      draw(d.paused);
    } catch (e) { /* the page still works; the button comes back on the next check */ }
  }
  load();
  setInterval(load, 60000);   // a timed pause ending on its own shows here within a minute
})();
