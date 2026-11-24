// Cyber Threats > alert: the AI's first read (api/core/threat_explain.py), when an AI integration is enabled. Asked
// once and saved; Refresh asks again. The AI's words are untrusted text: everything goes through esc().
(() => {
  const $ = id => document.getElementById(id);
  const VERDICT = { likely_malicious: ['chip--critical', 'Likely malicious'], suspicious: ['chip--high', 'Suspicious'],
                    likely_benign: ['chip--low', 'Likely benign'], unclear: ['chip--info', 'Unclear'] };
  const list = (title, items) => (items && items.length
    ? `<div style="margin-top:8px"><b class="text-sm">${esc(title)}</b><ul style="margin:4px 0 0 18px">${items.map(x => `<li class="text-sm">${esc(x)}</li>`).join('')}</ul></div>` : '');

  function show(r) {
    const v = VERDICT[r.verdict] || VERDICT.unclear;
    $('al-ai').innerHTML = `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:6px">
        <span class="chip ${v[0]}">${esc(v[1])}</span>
        ${r.stale ? '<span class="text-sm text-muted">The alert or its story changed since this read.</span>' : ''}
        <button type="button" class="btn btn--ghost btn--sm" id="al-ai-again" style="margin-left:auto">Refresh</button></div>
      <p style="margin:0">${esc(r.summary)}</p>${list('Why', r.why)}${list('Check next', r.next_steps)}
      <p class="text-sm text-muted" style="margin:10px 0 0">An AI's first read from the alert's names and MITRE data only (no command
        lines, users, paths, addresses or hashes)${r.at ? `, ${esc(new Date(r.at).toLocaleString())}` : ''}. Check it before acting on it.</p>`;
  }

  async function ask(id, fresh) {
    $('al-ai').innerHTML = '<p class="text-sm text-muted" style="margin:0">Asking the AI for a first read of this alert...</p>';
    try {
      const r = await fetch('/api/v1/threat/alerts/explain', { method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ id, fresh }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok || !d.available) throw new Error(d.error || 'The AI read isn\'t available right now.');
      if (d.error) throw new Error(d.error);
      show(d.read);
    } catch (err) {
      $('al-ai').innerHTML = `<p class="text-sm text-muted" style="margin:0">${esc(err.message)}</p>`;
    }
  }

  function render(a) {
    const ai = a.ai || {};
    if (!ai.available) return;
    $('al-ai-panel').style.display = '';
    $('al-ai').addEventListener('click', e => { if (e.target.id === 'al-ai-again') ask(a.id, true); });
    if (ai.read) show(ai.read);
    else ask(a.id, false);
  }

  window.AlertAI = { render };
})();
