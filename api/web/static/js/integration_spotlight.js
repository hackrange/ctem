// Settings > Integrations: a shipper-fed CrowdStrike card's "Pull Spotlight vulnerabilities" checkbox (admins). It is
// the shipper's own Spotlight setting (the same switch as on the Shippers page); the box picks it up on its next
// check-in, and CTEM ignores Spotlight data while it's off.
(() => {
  window.spotlightBox = i => (typeof i.spotlight === 'boolean'
    ? `<label class="text-sm" style="display:flex;gap:8px;align-items:center;margin:-4px 0 12px;cursor:pointer"
        title="The shipper's CrowdStrike Spotlight setting; it takes effect at the shipper's next check-in">
        <input type="checkbox" data-spotlight="${esc(i.id)}"${i.spotlight ? ' checked' : ''}> Pull Spotlight vulnerabilities
        <span class="text-muted" data-spotlight-msg="${esc(i.id)}"></span></label>`
    : '');

  document.addEventListener('change', async e => {
    const box = e.target.closest('input[data-spotlight]');
    if (!box) return;
    const id = box.dataset.spotlight, on = box.checked;
    const msg = document.querySelector(`[data-spotlight-msg="${CSS.escape(id)}"]`);
    box.disabled = true;
    try {
      const r = await fetch(`/api/v1/integrations/${encodeURIComponent(id)}/spotlight`, { method: 'PUT',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ enabled: on }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'That did not save. Try again.');
      if (msg) { msg.textContent = on ? 'On from the next check-in' : 'Off from the next check-in'; msg.style.color = ''; }
    } catch (err) {
      box.checked = !on;
      if (msg) { msg.textContent = err.message; msg.style.color = 'var(--severity-critical)'; }
    } finally { box.disabled = false; }
  });
})();
