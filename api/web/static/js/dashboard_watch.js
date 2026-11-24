// Dashboard: what the hourly background hunt flagged. Hidden for roles that can't hunt. Anyone can hide a finding for
// themselves (kept on their account, api/core/hidden.py); nobody else's view changes.
(function () {
  const panel = document.getElementById('watch-panel');
  if (!panel) return;
  let showHidden = false;
  const hide = async (key, hidden) => {
    await fetch('/api/v1/me/hidden', { method: 'PUT', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
                                       body: JSON.stringify({ kind: 'watch', id: key, hidden }) }).catch(() => null);
    load();
  };
  async function load() {
    let w;
    try {
      const res = await fetch(`/api/v1/hunt/watch${showHidden ? '?show_hidden=true' : ''}`, { headers: { Accept: 'application/json' } });
      if (!res.ok) return;
      w = await res.json();
    } catch { return; }
    const issues = (w.result && w.result.issues) || [];
    const when = w.ran_at ? new Date(w.ran_at).toLocaleString() : 'not yet';
    const n = w.hidden_count || 0;
    const hiddenNote = n ? ` ${esc(n)} hidden by you &middot; <a href="#" data-toggle>${showHidden ? 'hide them again' : 'show'}</a>.` : '';
    const body = document.getElementById('watch-body');
    body.innerHTML = issues.length
      ? issues.map(i => `<div class="watch-item" style="${i.hidden ? 'opacity:.55' : ''}">
          <span class="chip chip--${esc(i.severity)}">${esc(i.severity)}</span>
          <a class="watch-item__text" href="/hunt#watch" style="flex:1;color:inherit;text-decoration:none"><strong>${esc(i.title)}</strong>
            <span class="text-sm text-muted">${esc((i.what_happened || '').split('. ')[0])}${i.window_label ? ` &middot; ${esc(i.window_label)}` : ''}</span></a>
          ${i.key ? `<button type="button" class="btn btn--ghost btn--sm" data-key="${esc(i.key)}" data-hidden="${i.hidden ? '1' : ''}"
            title="${i.hidden ? 'Show it again' : 'Hide it for you only'}">${i.hidden ? 'Unhide' : 'Hide'}</button>` : ''}</div>`).join('')
        + `<p class="text-sm text-muted watch-foot">Checked ${esc(when)}. Only serious findings are shown here.${hiddenNote}</p>`
      : `<p class="text-sm text-muted watch-foot">${esc(w.note || 'Nothing suspicious in the last 7 days.')} Checked ${esc(when)}.${hiddenNote}</p>`;
    body.querySelectorAll('[data-key]').forEach(b => b.addEventListener('click', () => hide(b.dataset.key, !b.dataset.hidden)));
    const t = body.querySelector('[data-toggle]');
    if (t) t.addEventListener('click', e => { e.preventDefault(); showHidden = !showHidden; load(); });
    panel.style.display = '';
  }
  load();
})();
