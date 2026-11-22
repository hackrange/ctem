// Dashboard data scope: by default every widget shows each viewer only the data they may see. Admins and cyber can
// let a dashboard show everyone all the data, for a time; anyone else asks, and an admin or cyber approves (with a
// time limit) or denies. The server only honors it for the widgets as published, and puts it back up for approval
// when anyone else changes or publishes it.
window.DashAccess = (() => {
  const DAYS = [[1, '1 day'], [7, '7 days'], [30, '30 days'], [90, '90 days'], [365, '1 year'], ['', 'No end']];
  const days = (id, pick = 30) => `<select id="${id}" class="filter-select" aria-label="For how long">${DAYS.map(([v, l]) =>
    `<option value="${v}"${String(v) === String(pick) ? ' selected' : ''}>${l}</option>`).join('')}</select>`;
  const when = iso => new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  const wide = dash => dash.data_scope === 'everything';

  function field(dash) {
    const req = dash.scope_request;
    const now = wide(dash) ? `Shows all the data${dash.scope_until ? ` until ${esc(when(dash.scope_until))}` : ''}.` : '';
    if (!dash.can_widen) {
      return `<span class="form-label" style="margin-top:12px;display:block">Data shown</span>
        <label class="tk-radio" style="margin:4px 0"><input type="radio" name="dbs-scope" value="viewer"${wide(dash) || req ? '' : ' checked'}>
          Each viewer's own access</label>
        <label class="tk-radio" style="margin:4px 0"><input type="radio" name="dbs-scope" value="everything"${wide(dash) || req ? ' checked' : ''}>
          Everything, for everyone it's shared with <span class="text-muted">(needs approval by cyber or an admin)</span></label>
        <p class="text-sm text-muted" style="margin:4px 0 0 22px">${req ? `<b>Waiting for approval</b> (asked ${esc(when(req.at))}).`
          : now || 'Until it is approved, everyone sees only the data they are allowed to see.'}
          ${wide(dash) ? ' Changing it puts it back up for approval.' : ''}</p>`;
    }
    return `<span class="form-label" style="margin-top:12px;display:block">Data shown</span>
      <label class="tk-radio" style="margin:4px 0"><input type="radio" name="dbs-scope" value="viewer"${wide(dash) ? '' : ' checked'}>
        Each viewer's own access <span class="text-muted">(recommended)</span></label>
      <label class="tk-radio" style="margin:4px 0;display:flex;align-items:center;gap:6px"><input type="radio" name="dbs-scope" value="everything"${wide(dash) ? ' checked' : ''}>
        Everything, for everyone it's shared with, for ${days('dbs-days', '')}</label>
      <p class="text-sm text-muted" style="margin:4px 0 0 22px">${now ? `${now} ` : ''}Everything ignores each viewer's data access for these widgets as
        published, so people limited to their own assets see the whole picture here. If anyone other than an admin or cyber
        changes or publishes it, it goes back to each viewer's own access until approved again.</p>`;
  }

  function value(dash) {
    const pick = document.querySelector('input[name="dbs-scope"]:checked');
    if (!pick) return {};
    const out = { data_scope: pick.value };
    const d = document.getElementById('dbs-days');
    if (dash.can_widen && pick.value === 'everything' && d && d.value) out.scope_days = Number(d.value);
    return out;
  }

  // Under the title, so viewers know what they are looking at
  const note = dash => (wide(dash) ? `Shows all the data${dash.scope_until ? ` until ${when(dash.scope_until)}` : ''}` : '');

  // The request, for whoever decides it (and its status, for the person who asked)
  function bar(dash, id, reload) {
    const box = document.getElementById('db-scope');
    if (!box) return;
    const req = dash.scope_request;
    box.hidden = !req;
    box.style.display = req ? 'flex' : 'none';   // its inline flex would otherwise win over [hidden]
    if (!req) { box.innerHTML = ''; return; }
    if (!dash.can_widen) {
      box.innerHTML = '<span><b>Waiting for approval:</b> you asked for this dashboard to show everyone all the data. Until cyber or an admin approves, everyone sees only what they may see.</span>';
      return;
    }
    box.innerHTML = `<span><b>${esc(req.by)}</b> asked for this dashboard to show everyone it's shared with <b>all the data</b>
        (${esc(req.why || 'asked for it')}, ${esc(when(req.at))}). Check the published widgets, then:</span>
      <span style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">Approve for ${days('dbx-days', 30)}
        <button type="button" class="btn btn--primary btn--sm" id="dbx-ok">Approve</button>
        <button type="button" class="btn btn--ghost btn--sm" id="dbx-no">Deny</button><span id="dbx-msg" class="text-sm"></span></span>`;
    const send = async (what, btn) => {
      btn.disabled = true;
      const v = document.getElementById('dbx-days').value;
      const r = await DashRender.api('POST', `/api/v1/dashboards/${id}/scope/${what}`, { days: v ? Number(v) : null });
      btn.disabled = false;
      if (!r.ok) { document.getElementById('dbx-msg').textContent = r.error || 'Could not save'; return; }
      reload();
    };
    document.getElementById('dbx-ok').onclick = e => send('approve', e.target);
    document.getElementById('dbx-no').onclick = e => send('deny', e.target);
  }

  return { field, value, note, bar };
})();
