// Long tables: a <tbody data-collapse="10"> shows its first rows and a "Show all N" row that expands it.
// Re-applies whenever the page re-renders the rows (a MutationObserver), and remembers an expanded table.
(() => {
  function apply(tb) {
    const n = Number(tb.dataset.collapse) || 10;
    const rows = [...tb.rows].filter(r => !r.classList.contains('collapse-more'));
    tb.querySelectorAll('tr.collapse-more').forEach(r => r.remove());
    const open = tb.dataset.expanded === '1';
    rows.forEach((r, i) => { r.hidden = !open && i >= n; });
    if (rows.length <= n) return;
    const tr = document.createElement('tr');
    tr.className = 'collapse-more';
    const td = document.createElement('td');
    td.colSpan = Math.max(1, ...rows.map(r => r.cells.length));
    td.style.textAlign = 'center';
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn--ghost btn--sm';
    b.textContent = open ? 'Show fewer' : `Show all ${rows.length}`;
    b.addEventListener('click', e => { e.stopPropagation(); tb.dataset.expanded = open ? '0' : '1'; apply(tb); });
    td.appendChild(b);
    tr.appendChild(td);
    tb.appendChild(tr);
  }
  function watch(tb) {
    // Our own edits must not wake the observer again: pause it while applying, drop what it queued
    const mo = new MutationObserver(() => run());
    function run() { mo.disconnect(); apply(tb); mo.takeRecords(); mo.observe(tb, { childList: true }); }
    run();
  }
  document.addEventListener('DOMContentLoaded', () => document.querySelectorAll('tbody[data-collapse]').forEach(watch));
})();
