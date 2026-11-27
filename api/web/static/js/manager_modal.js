// A person's manager (from the directory, api/core/manager.py): a link that opens their first and last name, email,
// title and department, with a way to their record in Discovered Users. Used on Discovered Users and an asset's
// Details (its detected user). Everything goes through esc().
window.Manager = (() => {
  const seen = [];
  const name = m => [m.first_name, m.last_name].filter(Boolean).join(' ') || m.display_name || m.name || 'Manager';

  // A link for the manager, or a plain name when the directory names someone CTEM hasn't seen, or nothing
  function link(m) {
    if (!m) return '';
    if (!m.found) return m.name ? `${esc(m.name)} <span class="text-muted text-sm">(not in the directory CTEM has)</span>` : '';
    seen.push(m);
    return `<a href="#" class="dt-link" data-manager="${seen.length - 1}">${esc(name(m))}</a>`;
  }

  function open(m) {
    let box = document.getElementById('mgr-modal');
    if (!box) {
      box = document.createElement('div');
      box.id = 'mgr-modal';
      box.className = 'modal-overlay';
      box.setAttribute('role', 'dialog');
      box.setAttribute('aria-modal', 'true');
      box.setAttribute('aria-labelledby', 'mgr-title');
      box.innerHTML = `<div class="modal-box" style="max-width:480px"><div class="modal-header"><h2 class="modal-title" id="mgr-title">Manager</h2>
        <button type="button" class="modal-close" aria-label="Close">&times;</button></div><div class="modal-body" id="mgr-body"></div></div>`;
      document.body.appendChild(box);
      box.addEventListener('click', e => { if (e.target === box || e.target.closest('.modal-close')) box.style.display = 'none'; });
      document.addEventListener('keydown', e => { if (e.key === 'Escape') box.style.display = 'none'; });
    }
    const row = (k, v) => (v ? `<dt class="text-muted">${esc(k)}</dt><dd style="margin:0;overflow-wrap:anywhere">${v}</dd>` : '');
    const mail = m.email && /^[^\s@<>"]+@[^\s@<>"]+$/.test(m.email) ? `<a class="dt-link" href="mailto:${encodeURIComponent(m.email).replace('%40', '@')}">${esc(m.email)}</a>` : esc(m.email || '');
    box.querySelector('#mgr-body').innerHTML = `<dl style="display:grid;grid-template-columns:110px 1fr;gap:6px 14px;font-size:.9rem;margin:0 0 12px">
        ${row('First name', esc(m.first_name || ''))}${row('Last name', esc(m.last_name || ''))}${row('Email', mail)}
        ${row('Title', esc(m.title || ''))}${row('Department', esc(m.department || ''))}</dl>
      <a class="btn btn--ghost btn--sm" href="/users?person=${encodeURIComponent(m.id)}">Open in Discovered Users &rsaquo;</a>`;
    box.style.display = 'flex';
  }

  document.addEventListener('click', e => {
    const a = e.target.closest('a[data-manager]');
    if (!a) return;
    e.preventDefault();
    const m = seen[Number(a.dataset.manager)];
    if (m) open(m);
  });
  return { link };
})();
