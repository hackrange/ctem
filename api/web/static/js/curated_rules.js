// Admin > Curated Rules: list, write (JSON or plain English with AI), preview, save. Everything goes through esc().
(() => {
  const BASE = '/api/v1/rules';
  const pane = () => document.getElementById('pane-rules');
  let rules = [], schema = null, editing = null;

  async function call(method, path, body) {
    const res = await fetch(BASE + path, { method, headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
                                           body: body === undefined ? undefined : JSON.stringify(body) });
    if (res.status === 204) return {};
    const d = await res.json().catch(() => ({}));
    if (!res.ok) {
      const errs = (d.detail && d.detail.errors) || [];
      throw new Error(errs.join('; ') || (res.status === 409 ? 'Another rule already sets that threshold differently.' : 'The server refused that change.'));
    }
    return d;
  }

  const example = check => ({ schema: 'open-ctem/curated-rule@1', name: 'EDR coverage: no printers or network devices',
    description: "Printers, switches and firewalls can't run the EDR agent.", check: check || 'ctem_edr_coverage',
    scope: { exclude: { device_types: ['network_device'], os_contains: ['printer', 'ricoh', 'xerox', 'fortigate'] } } });

  const exampleCheck = () => ({ schema: 'open-ctem/custom-check@1', name: 'Servers with a vulnerability scan',
    id: 'scanned_servers', description: 'Share of servers that a vulnerability scanner reports.', measure: 'percent',
    population: { device_types: ['server'] }, match: { sources: ['rapid7_insightvm', 'qualys', 'tanium', 'msdefender'] },
    thresholds: { pass_at: 95, warn_at: 85 } });
  const isCheck = d => d && d.schema === 'open-ctem/custom-check@1';

  function scopeText(doc) {
    const part = (f, sep = '; ') => Object.entries(f || {}).map(([k, v]) => `${k.replace(/_/g, ' ')}: ${Array.isArray(v) ? v.join(', ') : v}`).join(sep);
    if (isCheck(doc)) {
      const pop = part(doc.population);
      return `new check: ${doc.measure === 'count' ? 'count' : '% of'} ${pop ? `devices with ${pop}` : 'all devices'} that match ${part(doc.match)}`;
    }
    const s = doc.scope || {};
    return [s.include && `only ${part(s.include)}`, s.exclude && (Array.isArray(s.exclude) ? `not (${s.exclude.map(b => part(b, ' and ')).join(') or (')})` : `not ${part(s.exclude, ' or ')}`),
            Object.keys(doc.thresholds || {}).length && `thresholds ${part(doc.thresholds)}`].filter(Boolean).join(' &middot; ');
  }

  function render() {
    const checks = (schema && schema['x-checks']) || {};
    pane().innerHTML = `
      <div class="panel" style="margin-bottom:16px">
        <div class="panel__header" style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
          <span class="panel__title">Curated rules</span>
          <span style="display:flex;gap:8px">
            <a class="btn btn--ghost btn--sm" href="${BASE}/schema" target="_blank" rel="noopener">JSON schema</a>
            <button type="button" class="btn btn--ghost btn--sm" data-cr="new-check">+ New check</button>
            <button type="button" class="btn btn--primary btn--sm" data-cr="new">+ New rule</button>
          </span>
        </div>
        <div class="panel__body text-sm text-muted">Rules change what a control check counts, such as which devices EDR coverage
          measures, or its thresholds within the check's own limits. A rule can also create a new control check
          (open-ctem/custom-check@1) that the GRC page and FairTPRM use like a built-in one. They never run code or change stored data.
          Every result records the rules that shaped it, and every change is in the audit log.</div>
      </div>
      <div class="panel" style="padding:0;margin-bottom:16px">
        <table class="data-table data-table--striped">
          <thead><tr><th>Rule</th><th>Check</th><th>What it does</th><th>Version</th><th>Enabled</th><th></th></tr></thead>
          <tbody>${rules.map(r => `<tr>
            <td class="text-sm"><b>${esc(r.name)}</b><br><span class="text-muted" style="font-size:.75rem">${esc(r.document.description || '')}</span></td>
            <td class="text-sm">${esc(isCheck(r.document) ? `New: ${r.name}` : (checks[r.check] || {}).name || r.check)}<br><span class="text-muted text-mono" style="font-size:.75rem">${esc(r.check)}</span></td>
            <td class="text-sm">${esc(scopeText(r.document)).replace(/&amp;middot;/g, '&middot;')}</td>
            <td class="text-sm">v${esc(r.version)}<br><span class="text-muted" style="font-size:.75rem">${esc(r.updated_by || '')}</span></td>
            <td><label class="text-sm"><input type="checkbox" data-cr-toggle="${esc(r.id)}" ${r.enabled ? 'checked' : ''}> on</label></td>
            <td style="white-space:nowrap"><button type="button" class="btn-link" data-cr-edit="${esc(r.id)}">edit</button>
              &middot; <button type="button" class="btn-link" data-cr-del="${esc(r.id)}">delete</button></td></tr>`).join('')
            || '<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:16px">No curated rules yet</td></tr>'}</tbody>
        </table>
      </div>
      <div id="cr-editor"></div>`;
  }

  function editor(rule, starter) {
    editing = rule ? rule.id : null;
    const box = document.getElementById('cr-editor');
    box.innerHTML = `<div class="panel">
      <div class="panel__header"><span class="panel__title">${rule ? `Edit: ${esc(rule.name)}` : 'New rule'}</span></div>
      <div class="panel__body" style="display:flex;flex-direction:column;gap:10px">
        <label class="text-sm" style="font-weight:600">Describe it (AI drafts the JSON when AI is configured)
          <div style="display:flex;gap:8px;margin-top:4px">
            <input id="cr-text" class="input" style="flex:1" maxlength="2000"
              placeholder="For ctem_edr_coverage, only count workstations and servers">
            <button type="button" class="btn btn--ghost btn--sm" data-cr="draft">Draft with AI</button>
          </div></label>
        <label class="text-sm" style="font-weight:600">Rule JSON (open-ctem/curated-rule@1, or open-ctem/custom-check@1 for a new check)
          <textarea id="cr-json" class="input text-mono" rows="14" spellcheck="false" style="width:100%;margin-top:4px;font-size:.8rem">${esc(JSON.stringify(rule ? rule.document : (starter || example()), null, 2))}</textarea></label>
        <div id="cr-msg" class="text-sm"></div>
        <div id="cr-preview" class="text-sm"></div>
        <div style="display:flex;gap:8px;justify-content:flex-end">
          <button type="button" class="btn btn--ghost btn--sm" data-cr="cancel">Cancel</button>
          <button type="button" class="btn btn--ghost btn--sm" data-cr="preview">Preview</button>
          <button type="button" class="btn btn--primary btn--sm" data-cr="save">Save rule</button>
        </div>
      </div></div>`;
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function say(text, bad) {
    const m = document.getElementById('cr-msg');
    m.style.color = bad ? 'var(--severity-critical)' : 'var(--fg-muted)';
    m.innerHTML = text;
  }

  function doc() {
    try { return JSON.parse(document.getElementById('cr-json').value); }
    catch (_) { say('That isn\'t valid JSON yet.', true); return null; }
  }

  const list = errs => `<ul style="margin:4px 0 0 18px">${errs.map(e => `<li>${esc(e)}</li>`).join('')}</ul>`;

  async function preview() {
    const d = doc();
    if (!d) return;
    say('Checking...');
    const p = await call('POST', '/preview', { document: d, rule_id: editing });
    if (p.errors) { say(`Fix these first:${list(p.errors)}`, true); return; }
    if (p.kind === 'check') {
      say(p.problem ? esc(p.problem) : `Valid check: ${esc(p.check_type)}.`, !!p.problem);
      document.getElementById('cr-preview').innerHTML = `<div style="border:1px solid var(--border);border-radius:6px;padding:10px 12px">
        <div><b>It would report:</b> ${esc(p.after.result)}: ${esc(p.after.summary)}</div>
        <div style="margin-top:6px" class="text-muted">${esc(p.listed.toLocaleString())} device${p.listed === 1 ? '' : 's'} to remediate${p.sample.length
          ? `, such as ${p.sample.slice(0, 8).map(x => `${esc(x.hostname)} (${esc(x.device_type || '?')})`).join(', ')}` : ''}.</div></div>`;
      return;
    }
    say(p.problem ? esc(p.problem) : 'Valid rule.', !!p.problem);
    const dv = p.devices;
    document.getElementById('cr-preview').innerHTML = `<div style="border:1px solid var(--border);border-radius:6px;padding:10px 12px">
      <div><b>Now:</b> ${esc(p.before.result)}: ${esc(p.before.summary)}</div>
      <div style="margin-top:4px"><b>With this rule:</b> ${esc(p.after.result)}: ${esc(p.after.summary)}</div>
      ${dv ? `<div style="margin-top:6px" class="text-muted">${esc(dv.in_scope.toLocaleString())} of ${esc(dv.total.toLocaleString())} devices in scope;
        ${esc(dv.out_of_scope.toLocaleString())} left out${dv.out_of_scope_sample.length ? `, such as ${dv.out_of_scope_sample.slice(0, 8)
          .map(x => `${esc(x.hostname)} (${esc(x.device_type || '?')})`).join(', ')}` : ''}.</div>` : ''}</div>`;
  }

  async function save() {
    const d = doc();
    if (!d) return;
    const v = await call('POST', '/validate', { document: d, rule_id: editing });
    if (!v.valid) { say(`Fix these first:${list(v.errors)}`, true); return; }
    const r = await (editing ? call('PUT', `/${encodeURIComponent(editing)}`, { document: v.document })
                             : call('POST', '', { document: v.document }));
    await load();
    measured(r);
  }

  // Saving re-runs the check at once; say what it measures now (the GRC page shows the same result)
  function measured(r) {
    const box = document.getElementById('cr-editor');
    if (!box || !r || !r.measured) return;
    box.innerHTML = `<div class="panel"><div class="panel__body text-sm">Saved. The check was re-run:
      <b>${esc(r.measured.result)}</b>: ${esc(r.measured.summary)}</div></div>`;
  }

  async function draft() {
    const text = document.getElementById('cr-text').value.trim();
    if (text.length < 5) { say('Describe the rule first.', true); return; }
    say('Asking the AI...');
    const r = await call('POST', '/draft', { text });
    if (!r.available) { say('No AI integration is configured. Write the JSON below, or add one under Integrations.', true); return; }
    if (!r.document) { say(esc(r.error || 'No draft.'), true); return; }
    document.getElementById('cr-json').value = JSON.stringify(r.document, null, 2);
    say(r.errors && r.errors.length ? `Draft needs fixing:${list(r.errors)}` : 'Draft ready. Preview it, then save.', !!(r.errors && r.errors.length));
  }

  async function load() {
    try {
      [schema, { rules }] = await Promise.all([schema ? schema : call('GET', '/schema'), call('GET', '')]);
      render();
    } catch (e) {
      pane().innerHTML = `<p class="text-muted text-sm">Curated rules unavailable: ${esc(e.message)}</p>`;
    }
  }

  document.addEventListener('click', async e => {
    if (!pane() || !pane().contains(e.target)) return;
    const b = e.target.closest('[data-cr],[data-cr-edit],[data-cr-del]');
    if (!b) return;
    try {
      if (b.dataset.cr === 'new') editor(null);
      else if (b.dataset.cr === 'new-check') editor(null, exampleCheck());
      else if (b.dataset.cr === 'cancel') document.getElementById('cr-editor').innerHTML = '';
      else if (b.dataset.cr === 'preview') await preview();
      else if (b.dataset.cr === 'save') await save();
      else if (b.dataset.cr === 'draft') await draft();
      else if (b.dataset.crEdit) editor(rules.find(r => r.id === b.dataset.crEdit));
      else if (b.dataset.crDel && confirm('Delete this rule? Checks go back to counting everything it scoped out.')) {
        await call('DELETE', `/${encodeURIComponent(b.dataset.crDel)}`);
        await load();
      }
    } catch (err) {
      if (document.getElementById('cr-msg')) say(esc(err.message), true); else alert(err.message);
    }
  });
  document.addEventListener('change', async e => {
    const t = e.target.closest('[data-cr-toggle]');
    if (!t) return;
    try { const r = await call('PUT', `/${encodeURIComponent(t.dataset.crToggle)}/enabled`, { enabled: t.checked }); await load(); measured(r); }
    catch (err) { alert(err.message); t.checked = !t.checked; }
  });

  window.CuratedRules = { load };
})();
