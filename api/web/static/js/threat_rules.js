// Admin > Threat Curated Rules (api/routes/threat_rules.py). Everything shown goes through esc() or textContent.
(() => {
  const $ = id => document.getElementById(id);
  const API = '/api/v1/threat-rules';
  const STATUS = { learned: ['Learned, not reviewed', 'chip--medium'], reviewed: ['Reviewed', 'chip--low'], manual: ['Manual', 'chip--info'] };
  let rules = [], editing = null;
  const call = async (path, method, body) => {
    const r = await fetch(API + path, { method, headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'Check the rule: names up to 120 characters, match as JSON.');
    return d;
  };
  const summary = r => {
    const m = r.match || {};
    if (r.kind === 'splunk') return `Splunk: ${m.spl || ''}`;
    return [m.technique_ids && m.technique_ids.length && `MITRE ${m.technique_ids.join(', ')}`, m.title_any && m.title_any.length && `title has ${m.title_any.join(' or ')}`,
            m.title_all && m.title_all.length && `title has all of ${m.title_all.join(', ')}`, m.sources && m.sources.length && `from ${m.sources.join(', ')}`,
            m.min_hosts > 1 && `on ${m.min_hosts}+ hosts`, m.min_alerts > 1 && `${m.min_alerts}+ alerts`].filter(Boolean).join('; ');
  };
  async function load() {
    try { rules = (await call('', 'GET')).rules; } catch (e) { $('tr-body').innerHTML = `<p class="text-sm" style="padding:14px">${esc(e.message)}</p>`; return; }
    const learned = rules.filter(r => r.status === 'learned').length;
    $('tr-body').innerHTML = !rules.length
      ? '<p class="text-sm text-muted" style="padding:14px">No rules yet. They appear as the AI finds high-fidelity issues on the dashboard check and the Hunt page, or add one.</p>'
      : `${learned ? `<p class="text-sm" style="padding:10px 14px 0"><b>${esc(learned)}</b> learned rule${learned === 1 ? '' : 's'} waiting for review (already active).</p>` : ''}
        <table class="data-table"><thead><tr><th>Rule</th><th>Matches</th><th>Severity</th><th>Status</th><th>Hits</th><th>Last hit</th><th>On</th><th></th></tr></thead><tbody>
        ${rules.map((r, i) => `<tr><td class="text-sm"><b>${esc(r.name)}</b>${r.description ? `<div class="text-muted" style="font-size:.75rem">${esc(r.description)}</div>` : ''}
            ${r.learned_from ? `<div class="text-muted" style="font-size:.7rem">Learned from: ${esc(r.learned_from.slice(0, 120))}</div>` : ''}</td>
          <td class="text-sm text-mono" style="max-width:340px;overflow-wrap:anywhere">${esc(summary(r))}</td>
          <td><span class="chip chip--${esc(r.severity)}">${esc(r.severity)}</span></td>
          <td><span class="chip ${(STATUS[r.status] || ['', ''])[1]}" style="font-size:.7rem">${esc((STATUS[r.status] || [r.status])[0])}</span></td>
          <td class="text-sm">${esc(r.hits)}</td><td class="text-sm text-muted">${r.last_hit_at ? esc(new Date(r.last_hit_at).toLocaleString()) : 'never'}</td>
          <td><input type="checkbox" data-on="${i}" ${r.enabled ? 'checked' : ''} aria-label="Enabled"></td>
          <td style="white-space:nowrap">${r.status === 'learned' ? `<button type="button" class="btn btn--ghost btn--sm" data-review="${i}">Mark reviewed</button>` : ''}
            <button type="button" class="btn btn--ghost btn--sm" data-test="${i}">Test</button>
            <button type="button" class="btn btn--ghost btn--sm" data-edit="${i}">Edit</button>
            <button type="button" class="btn btn--ghost btn--sm" data-del="${i}">Delete</button>
            <div class="text-sm" data-out="${i}"></div></td></tr>`).join('')}</tbody></table>`;
  }
  function open(r) {
    editing = r || null;
    $('tr-edit').hidden = false;
    $('tr-edit-title').textContent = r ? `Edit: ${r.name}` : 'Add a rule';
    $('tr-name').value = r ? r.name : '';
    $('tr-kind').value = r ? r.kind : 'alert';
    $('tr-kind').disabled = !!r;
    $('tr-sev').value = r ? r.severity : 'high';
    $('tr-enabled').checked = r ? r.enabled : true;
    $('tr-match').value = JSON.stringify(r ? r.match : { technique_ids: [], title_any: [], sources: [], min_hosts: 1 }, null, 1);
    $('tr-desc').value = r ? (r.description || '') : '';
    $('tr-todo').value = r ? (r.what_to_do || []).join('\n') : '';
    $('tr-msg').textContent = '';
    $('tr-name').focus();
  }
  $('tr-body').addEventListener('click', async e => {
    const b = e.target.closest('button');
    if (!b) return;
    const i = Number(b.dataset.review ?? b.dataset.test ?? b.dataset.edit ?? b.dataset.del);
    const r = rules[i];
    if (!r) return;
    const out = $('tr-body').querySelector(`[data-out="${i}"]`);
    try {
      if ('review' in b.dataset) { await call(`/${r.id}`, 'PUT', { reviewed: true }); return load(); }
      if ('edit' in b.dataset) return open(r);
      if ('del' in b.dataset) { if (!confirm(`Delete the rule "${r.name}"?`)) return; await call(`/${r.id}`, 'DELETE'); return load(); }
      if ('test' in b.dataset) {
        const t = await call(`/${r.id}/test`, 'POST');
        out.textContent = t.supported ? `Last 7 days: ${t.alerts} alerts on ${t.hosts} hosts; ${t.would_fire ? 'it would fire' : 'it would not fire'}.` : t.note;
      }
    } catch (err) { out.textContent = err.message; }
  });
  $('tr-body').addEventListener('change', async e => {
    const c = e.target.closest('[data-on]');
    if (!c) return;
    try { await call(`/${rules[Number(c.dataset.on)].id}`, 'PUT', { enabled: c.checked }); } catch (err) { c.checked = !c.checked; alert(err.message); }
  });
  $('tr-new').addEventListener('click', () => open(null));
  $('tr-cancel').addEventListener('click', () => { $('tr-edit').hidden = true; });
  $('tr-form').addEventListener('submit', async e => {
    e.preventDefault();
    let match;
    try { match = JSON.parse($('tr-match').value || '{}'); } catch { $('tr-msg').textContent = 'The match isn\'t valid JSON.'; return; }
    const body = { name: $('tr-name').value.trim(), match, severity: $('tr-sev').value, description: $('tr-desc').value.trim() || null,
                   what_to_do: $('tr-todo').value.split('\n').map(s => s.trim()).filter(Boolean), enabled: $('tr-enabled').checked };
    try {
      if (editing) await call(`/${editing.id}`, 'PUT', body); else await call('', 'POST', { ...body, kind: $('tr-kind').value });
      $('tr-edit').hidden = true;
      load();
    } catch (err) { $('tr-msg').textContent = err.message; }
  });
  load();
})();
