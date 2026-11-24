// Admin > Users > View as: the banner while an admin sees CTEM as someone else (read-only, 30 minutes at most).
(function () {
  const bar = document.getElementById('view-as-banner');
  if (!bar) return;
  const until = parseInt(bar.dataset.until, 10);
  const at = document.getElementById('view-as-until');
  if (at && until) at.textContent = new Date(until * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  document.getElementById('view-as-stop').addEventListener('click', async () => {
    await fetch('/api/v1/impersonate/stop', { method: 'POST', headers: { Accept: 'application/json' } }).catch(() => null);
    location.href = '/admin';
  });
  if (until) setTimeout(() => location.reload(), Math.max(until * 1000 - Date.now() + 1500, 1000));
})();
