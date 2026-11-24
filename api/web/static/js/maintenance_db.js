// Admin > Maintenance > Database: table sizes, dead rows, last vacuum and analyze, and the last upkeep run
// (api/core/db_maintenance.py). Everything goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const n = v => Number(v || 0).toLocaleString();
  const when = s => (s ? new Date(s).toLocaleString() : 'never');

  async function load() {
    const r = await fetch('/api/v1/admin/maintenance/database', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
    if (!r.ok) { $('mt-db').innerHTML = '<tr><td colspan="6" class="text-muted text-sm">Could not load database details.</td></tr>'; return; }
    const d = await r.json();
    if (!d.available) { $('mt-db').innerHTML = '<tr><td colspan="6" class="text-muted text-sm">Only shown on PostgreSQL.</td></tr>'; return; }
    $('mt-db').innerHTML = (d.tables || []).map(t => `<tr><td class="text-mono text-sm">${esc(t.table)}</td><td>${esc(n(t.rows))}</td>
      <td>${esc(n(t.mb))} MB</td><td>${esc(n(t.dead))} <span class="text-muted text-sm">(${esc(t.dead_pct)}%)</span></td>
      <td class="text-sm">${esc(when(t.vacuumed))}</td><td class="text-sm">${esc(when(t.analyzed))}</td></tr>`).join('');
    const l = d.last_run;
    $('mt-db-last').textContent = `Database ${n(d.database_mb)} MB. ` + (l
      ? `Last upkeep ${when(l.at)}: ${l.vacuumed.length} vacuumed, ${l.analyzed.length} analyzed, ${l.reindexed.length} indexes rebuilt` +
        (l.errors.length ? `, ${l.errors.length} skipped` : '') + ` in ${l.took_s}s.`
      : 'No upkeep has run yet.');
  }

  $('mt-db-run').addEventListener('click', async e => {
    e.target.disabled = true;
    const r = await fetch('/api/v1/admin/maintenance/database/run', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json' } });
    e.target.textContent = r.ok ? 'Started; reload in a few minutes' : 'Could not start it';
  });
  load();
})();
