// The IDV badge: a small green certificate beside a person's name when they have passed an identity verification
// (Persona). withDate puts the last verification date under it (the computer's Identity tab). Everything goes through esc().
window.IdvBadge = (() => {
  const ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">'
    + '<rect x="3" y="3" width="18" height="13" rx="2"/><path d="M7 8h6M7 11h4"/><circle cx="16.5" cy="15.5" r="3"/>'
    + '<path d="M15 18.2l-.8 3.3 2.3-1.3 2.3 1.3-.8-3.3"/></svg>';
  function html(at, withDate) {
    if (!at) return '';
    const d = new Date(at);
    if (isNaN(d)) return '';
    const day = d.toLocaleDateString();
    const tip = `Identity verified (Persona) on ${day}`;
    return `<span class="idv-badge${withDate ? ' idv-badge--dated' : ''}" title="${esc(tip)}" aria-label="${esc(tip)}">`
      + `<span class="idv-badge__mark">${ICON}<b>IDV</b></span>`
      + (withDate ? `<span class="idv-badge__date">${esc(day)}</span>` : '') + '</span>';
  }
  return { html };
})();
