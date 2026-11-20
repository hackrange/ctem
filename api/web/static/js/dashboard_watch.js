// Dashboard: what the hourly background hunt flagged. Hidden for roles that can't hunt.
(async function () {
  const panel = document.getElementById('watch-panel');
  if (!panel) return;
  let w;
  try {
    const res = await fetch('/api/v1/hunt/watch', { headers: { Accept: 'application/json' } });
    if (!res.ok) return;
    w = await res.json();
  } catch { return; }
  const issues = (w.result && w.result.issues) || [];
  const when = w.ran_at ? new Date(w.ran_at).toLocaleString() : 'not yet';
  const body = document.getElementById('watch-body');
  body.innerHTML = issues.length
    ? issues.map(i => `<a class="watch-item" href="/hunt#watch">
        <span class="chip chip--${esc(i.severity)}">${esc(i.severity)}</span>
        <span class="watch-item__text"><strong>${esc(i.title)}</strong>
          <span class="text-sm text-muted">${esc((i.what_happened || '').split('. ')[0])}${i.window_label ? ` &middot; ${esc(i.window_label)}` : ''}</span></span></a>`).join('')
      + `<p class="text-sm text-muted watch-foot">Checked ${esc(when)}. Only serious findings are shown here.</p>`
    : `<p class="text-sm text-muted watch-foot">${esc(w.note || 'Nothing suspicious in the last 7 days.')} Checked ${esc(when)}.</p>`;
  panel.style.display = '';
})();
