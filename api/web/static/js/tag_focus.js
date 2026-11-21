// Tag focus: a tag filter (owner, application, environment...) that follows you through the device pages
// in this browser tab. Set from the dashboard filters or a /devices?tag=... link; cleared from its chip.
(() => {
  const KEY = 'ctem.tagFocus';
  const clean = list => [...new Set((list || []).filter(t => typeof t === 'string' && t && t.length <= 128))].slice(0, 10);

  function get() {
    try { return clean(JSON.parse(sessionStorage.getItem(KEY) || '[]')); } catch (e) { return []; }
  }
  function set(list) {
    const v = clean(list);
    try { v.length ? sessionStorage.setItem(KEY, JSON.stringify(v)) : sessionStorage.removeItem(KEY); } catch (e) { /* private mode */ }
    window.dispatchEvent(new Event('tag-focus-changed'));
    linkDevices();
    return v;
  }
  // Labels come from Admin > Tag mapping ("Executive owner: Jeffrey Davis"); cached for the tab
  const LABELS = 'ctem.tagLabels';
  function labels() {
    try { return JSON.parse(sessionStorage.getItem(LABELS) || '{}') || {}; } catch (e) { return {}; }
  }
  function label(t) {
    const known = labels()[t];
    return known || t.replace(/^[a-z0-9]+:/i, '');
  }
  async function resolve(tags) {
    const have = labels(), todo = tags.filter(t => !(t in have));
    if (!todo.length) return false;
    try {
      const r = await fetch('/api/v1/tag-roles/resolve', { method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ tags: todo }) });
      const d = await r.json();
      (d.tags || []).forEach(x => { have[x.tag] = x.role_name ? `${x.role_name}: ${x.value}` : x.value; });
      try { sessionStorage.setItem(LABELS, JSON.stringify(have)); } catch (e) { /* private mode */ }
      return true;
    } catch (e) { return false; }
  }
  function devicesUrl(extra) {
    const p = new URLSearchParams(extra || {});
    get().forEach(t => p.append('tag', t));
    return `/devices${p.toString() ? '?' + p : ''}`;
  }
  // The sidebar's Devices link (and any element marked data-tag-focus-link) keeps the focus
  function linkDevices() {
    document.querySelectorAll('a.sidebar__link[href^="/devices"], a[data-tag-focus-link]').forEach(a => { a.href = devicesUrl(); });
  }
  // Chips for a container: the focused tags, each with a remove button, plus an optional lead-in
  function chips(box, lead) {
    const tags = get();
    box.hidden = !tags.length;
    box.innerHTML = tags.length ? `<span class="filter-bar__label">${esc(lead || 'Tag')}</span>` + tags.map((t, i) =>
      `<span class="chip chip--info">${esc(label(t).toUpperCase())}
        <button type="button" class="btn btn--ghost btn--sm" data-untag="${i}" aria-label="Remove this tag filter" title="Remove">&#10005;</button></span>`).join(' ') : '';
    if (tags.length && !box.dataset.resolving) {
      box.dataset.resolving = '1';
      resolve(tags).then(changed => { delete box.dataset.resolving; if (changed) chips(box, lead); });
    }
    if (!box.dataset.wired) {
      box.dataset.wired = '1';
      box.addEventListener('click', e => {
        const b = e.target.closest('button[data-untag]');
        if (!b) return;
        const next = get();
        next.splice(Number(b.dataset.untag), 1);
        set(next);
        chips(box, lead);
      });
    }
  }

  window.TagFocus = { get, set, label, devicesUrl, chips };
  document.addEventListener('DOMContentLoaded', linkDevices);
})();
