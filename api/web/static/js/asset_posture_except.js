// A device's Posture tab: except a failing check on this device, one of its tags, every device of its type, or
// everywhere, with a reason and an end date (POST /api/v1/posture-exceptions); remove an exception from its check.
// Everything goes through esc().
window.PostureExcept = (() => {
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const inDays = n => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);
  const TYPE = t => (t || 'device').replace(/_/g, ' ');

  function cell(s) {
    if (s.excepted) {
      const x = s.excepted;
      return `<div class="text-muted" style="font-size:.78rem">${esc(x.scope)} &middot; until ${esc(x.until)} &middot; ${esc(x.by)}</div>
        <div style="font-size:.78rem;overflow-wrap:anywhere">${esc(x.reason)}</div>
        <button type="button" class="btn btn--ghost btn--sm" data-pe-remove="${esc(x.id)}" style="margin-top:4px">Remove</button>`;
    }
    return s.passed === false ? `<button type="button" class="btn btn--ghost btn--sm" data-pe-add="${esc(s.name)}">Except&hellip;</button>` : '';
  }

  function form(check, d) {
    const tags = (d.tags || []).map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('');
    return `<div class="pe-form" style="border:1px solid var(--border);border-radius:8px;padding:12px;margin:6px 0;background:var(--surface)">
      <div style="font-weight:600;margin-bottom:8px">Except &ldquo;${esc(check)}&rdquo;</div>
      <div style="display:flex;flex-direction:column;gap:6px;font-size:.86rem">
        <label><input type="radio" name="pe-scope" value="device" checked> On this device only</label>
        <label style="display:flex;gap:6px;align-items:center"><input type="radio" name="pe-scope" value="tag"${tags ? '' : ' disabled'}>
          On every device tagged <select class="filter-select" data-pe="tag"${tags ? '' : ' disabled'}>${tags || '<option>This device has no tags</option>'}</select></label>
        <label><input type="radio" name="pe-scope" value="type"${d.device_type ? '' : ' disabled'}> On every ${esc(TYPE(d.device_type))}</label>
        <label><input type="radio" name="pe-scope" value="all"> On every device</label>
      </div>
      <label class="text-sm" style="display:block;margin-top:10px">Why this is acceptable (at least 10 characters)
        <textarea data-pe="reason" rows="2" maxlength="1000" style="width:100%;margin-top:4px"></textarea></label>
      <label class="text-sm">Until <input type="date" data-pe="until" value="${inDays(90)}" min="${inDays(1)}" max="${inDays(366)}"></label>
      <div style="display:flex;gap:8px;align-items:center;margin-top:10px">
        <button type="button" class="btn btn--primary btn--sm" data-pe-save="1">Save exception</button>
        <button type="button" class="btn btn--ghost btn--sm" data-pe-cancel="1">Cancel</button>
        <span class="text-sm" data-pe="msg"></span></div></div>`;
  }

  async function call(url, opts) {
    const r = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, ...opts });
    const b = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(typeof b.detail === 'string' ? b.detail : 'The server refused that.');
    return b;
  }

  function wire(panel, d, id, redraw) {
    if (panel.dataset.peWired) return;   // redrawing the tab keeps the one listener
    panel.dataset.peWired = '1';
    panel.addEventListener('click', async e => {
      const add = e.target.closest('[data-pe-add]'), rm = e.target.closest('[data-pe-remove]');
      if (add) {
        panel.querySelectorAll('.pe-form').forEach(f => f.remove());
        const row = add.closest('tr'), tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="5">${form(add.dataset.peAdd, d)}</td>`;
        tr.dataset.check = add.dataset.peAdd;
        row.after(tr);
        tr.querySelector('[data-pe="reason"]').focus();
        return;
      }
      if (e.target.closest('[data-pe-cancel]')) { e.target.closest('tr').remove(); return; }
      if (e.target.closest('[data-pe-save]')) {
        const tr = e.target.closest('tr'), q = k => tr.querySelector(`[data-pe="${k}"]`);
        const scope = tr.querySelector('input[name="pe-scope"]:checked').value;
        const body = { check: tr.dataset.check, scope, reason: q('reason').value.trim(), expires_on: q('until').value };
        if (scope === 'device') body.device_id = id;
        if (scope === 'tag') body.tag_id = q('tag').value;
        if (scope === 'type') body.device_type = d.device_type;
        try { await call('/api/v1/posture-exceptions', { method: 'POST', body: JSON.stringify(body) }); redraw(); }
        catch (err) { q('msg').textContent = err.message; q('msg').style.color = 'var(--severity-critical)'; }
        return;
      }
      if (rm) {
        if (!confirm('Remove this exception? The check counts as failing again wherever it applied.')) return;
        try { await call(`/api/v1/posture-exceptions/${encodeURIComponent(rm.dataset.peRemove)}`, { method: 'DELETE' }); redraw(); }
        catch (err) { alert(err.message); }
      }
    });
  }
  return { cell, wire };
})();
