// Admin > Data retention (api/routes/retention_settings.py). Everything shown goes through esc() or textContent.
(() => {
  const $ = id => document.getElementById(id);
  async function load() {
    const r = await fetch('/api/v1/retention', { headers: { Accept: 'application/json' } });
    if (!r.ok) { $('ret-msg').textContent = 'Couldn\'t load the settings.'; return; }
    const d = await r.json();
    $('ret-enabled').checked = d.enabled;
    $('ret-days').value = d.stale_host_days;
    $('ret-probe').value = d.probe_within_days;
    $('ret-fixed').value = d.remediated_days;
    $('ret-ip').value = d.ip_history_days;
    const ih = d.ip_history || {};
    $('ret-ip-now').textContent = `Which asset and person held each address, and when (GMT). Investigations can look back only as far as this keeps. Right now: ${
      Number(ih.spans || 0).toLocaleString()} spans${ih.oldest ? `, the oldest from ${new Date(ih.oldest).toISOString().slice(0, 10)}` : ''}.`;
    $('ret-fixed-now').innerHTML = `Right now: <b>${esc(d.remediated_due)}</b> remediated findings are older than that and will be summarized and removed at the next run.`;
    $('ret-now').innerHTML = `Right now: <b>${esc(d.now.unseen_with_findings)}</b> hosts with findings haven't been seen in ${esc(d.stale_host_days)} days;
      <b>${esc(d.now.confirmed_offline)}</b> of them have been silent to the network probe long enough to count as gone (those lose their findings at the next daily run, 03:30 UTC).`;
  }
  $('ret-form').addEventListener('submit', async e => {
    e.preventDefault();
    const body = { enabled: $('ret-enabled').checked, stale_host_days: Number($('ret-days').value), probe_within_days: Number($('ret-probe').value), remediated_days: Number($('ret-fixed').value), ip_history_days: Number($('ret-ip').value) };
    const r = await fetch('/api/v1/retention', { method: 'PUT', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    $('ret-msg').textContent = r.ok ? 'Saved.' : (typeof d.detail === 'string' ? d.detail : 'Check the numbers: days 7-365, probe 1-30, remediated 30-365, IP history 30-3650.');
    if (r.ok) load();
  });
  load();
})();
