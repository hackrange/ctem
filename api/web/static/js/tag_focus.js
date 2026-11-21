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
  function label(t) {
    const m = t.match(/^owner:(E|T|A)-O:\s*(.*)$/);
    const ROLE = { E: 'Executive owner', T: 'Technical owner', A: 'Application owner' };
    if (m) return `${ROLE[m[1]]}: ${m[2]}`;
    return t.replace(/^(r7|location):/, '');
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
