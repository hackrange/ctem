// Admin > AI Usage: month-to-date spend vs limits, daily chart, breakdowns, prices and limits form.
(function () {
  const API = '/api/v1/admin/ai-usage';
  const PURPOSES = { hunt: 'Threat hunt', threat_analysis: 'Alert analysis', test: 'Connection test', general: 'Other' };
  let days = 30;
  let loaded = false;

  const n = v => Number(v || 0).toLocaleString();
  const money = v => v == null ? '<span class="text-muted">unpriced</span>'
    : '$' + Number(v).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: v < 1 ? 4 : 2 });
  const pane = () => document.getElementById('pane-ai');

  function bar(pct) {
    if (pct == null) return '';
    const p = Math.min(100, pct);
    const color = pct >= 100 ? 'var(--severity-critical)' : pct >= 80 ? 'var(--severity-high)' : 'var(--accent)';
    return `<div class="ai-meter" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${p}">
      <div style="width:${p}%;background:${color}"></div></div>`;
  }

  function tile(label, value, sub, meter) {
    return `<div class="ai-tile"><p class="ai-tile__label">${esc(label)}</p><p class="ai-tile__value">${value}</p>
      ${meter || ''}<p class="ai-tile__sub">${sub}</p></div>`;
  }

  function chart(daily, useCost) {
    if (!daily.length) return '<p class="text-muted text-sm" style="padding:16px">No AI calls in this window.</p>';
    const W = 760, H = 180, padL = 56, padB = 22, padT = 10;
    const vals = daily.map(d => useCost ? (d.cost || 0) : d.tokens);
    const max = Math.max(...vals) || 1;
    const step = (W - padL) / daily.length;
    const bw = Math.max(1, step - 2);  // 2px gap between bars
    const fmt = v => useCost ? '$' + (v >= 100 ? Math.round(v) : v.toFixed(2)) : (v >= 1e6 ? (v / 1e6).toFixed(1) + 'M' : v >= 1e3 ? Math.round(v / 1e3) + 'k' : String(v));
    const grid = [0, 0.5, 1].map(f => {
      const y = padT + (H - padT - padB) * (1 - f);
      return `<line x1="${padL}" x2="${W}" y1="${y}" y2="${y}" stroke="var(--border)" stroke-width="1"/>
        <text x="${padL - 6}" y="${y + 4}" text-anchor="end" class="ai-axis">${esc(fmt(max * f))}</text>`;
    }).join('');
    const bars = daily.map((d, i) => {
      const v = vals[i];
      const h = Math.max(v > 0 ? 2 : 0, (H - padT - padB) * v / max);
      const x = padL + i * step + 1;
      const y = H - padB - h;
      const r = Math.min(4, bw / 2, h);
      const tip = `${d.date}: ${useCost ? '$' + (d.cost || 0).toFixed(4) : n(d.tokens) + ' tokens'} (${n(d.calls)} calls)`;
      // Wide transparent hit target, then the visible bar with rounded top
      return `<g class="ai-bar" tabindex="0"><title>${esc(tip)}</title>
        <rect x="${padL + i * step}" y="${padT}" width="${step}" height="${H - padT - padB}" fill="transparent"/>
        <path d="M${x},${H - padB} v${-(h - r)} q0,${-r} ${r},${-r} h${bw - 2 * r} q${r},0 ${r},${r} v${h - r} z" fill="var(--accent)"/></g>`;
    }).join('');
    const first = daily[0].date, last = daily[daily.length - 1].date;
    return `<svg viewBox="0 0 ${W} ${H}" class="ai-chart" role="img" aria-label="${esc(useCost ? 'Daily AI cost' : 'Daily AI tokens')} from ${esc(first)} to ${esc(last)}">
      ${grid}${bars}
      <text x="${padL}" y="${H - 6}" class="ai-axis">${esc(first)}</text>
      <text x="${W}" y="${H - 6}" text-anchor="end" class="ai-axis">${esc(last)}</text></svg>`;
  }

  function table(head, rows) {
    return `<div class="dt-scroll"><table class="data-table"><thead><tr>${head.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead>
      <tbody>${rows.join('') || `<tr><td colspan="${head.length}" class="text-muted text-sm" style="text-align:center;padding:16px">No usage yet</td></tr>`}</tbody></table></div>`;
  }

  const tokenCells = r => `<td>${n(r.input)}</td><td>${n(r.output)}</td><td>${n(r.cache_read)}</td><td>${n(r.cache_write)}</td>`;

  function render(d) {
    const m = d.month;
    const s = d.settings;
    const useCost = d.daily.some(x => x.cost != null);
    const field = (key, label, hint) => `<label class="form-group"><span class="form-label">${esc(label)}</span>
      <input class="form-input" name="${key}" value="${esc(s[key])}" inputmode="decimal" maxlength="16" placeholder="${esc(hint)}"></label>`;
    pane().innerHTML = `
      <div class="ai-head">
        <p class="text-muted text-sm" style="margin:0">Every AI call is metered (token counts only, never prompt text). Resets ${esc(m.resets)} (UTC).</p>
        <select class="filter-select" id="ai-days" aria-label="Window">
          ${[7, 30, 90, 365].map(v => `<option value="${v}" ${v === days ? 'selected' : ''}>Last ${v} days</option>`).join('')}
        </select>
      </div>
      <div class="ai-tiles">
        ${tile('Cost this month', money(m.cost), m.cost_limit != null ? `of ${money(m.cost_limit)} limit (${m.cost_percent}%)` : 'No cost limit set', bar(m.cost_percent))}
        ${tile('Tokens this month', n(m.tokens), m.token_limit != null ? `of ${n(m.token_limit)} limit (${m.token_percent}%)` : 'No token limit set', bar(m.token_percent))}
        ${tile('Month-end forecast', money(m.forecast_cost), `${n(m.forecast_tokens)} tokens at the current daily rate`)}
        ${tile(`Calls, last ${d.days} days`, n(d.totals.calls), `${n(d.totals.failed)} failed${m.unpriced_calls ? ` &middot; ${n(m.unpriced_calls)} unpriced this month` : ''}`)}
      </div>
      <div class="panel" style="margin-top:16px"><div class="panel__header"><span class="panel__title">${useCost ? 'Daily cost (USD)' : 'Daily tokens'}</span></div>
        <div class="panel__body">${chart(d.daily, useCost)}
          <details style="margin-top:8px"><summary class="text-sm text-muted">Show as table</summary>
          ${table(['Date', 'Calls', 'Failed', 'Input', 'Output', 'Cache read', 'Cache write', 'Cost'],
            d.daily.slice().reverse().map(r => `<tr><td>${esc(r.date)}</td><td>${n(r.calls)}</td><td>${n(r.failed)}</td>${tokenCells(r)}<td>${money(r.cost)}</td></tr>`))}
          </details></div></div>
      <div class="panel" style="margin-top:16px;padding:0"><div class="panel__header"><span class="panel__title">By model</span></div>
        ${table(['Provider', 'Model', 'Calls', 'Failed', 'Input', 'Output', 'Cache read', 'Cache write', 'Cost', 'Priced from'],
          d.by_model.map(r => `<tr><td>${esc(r.provider)}</td><td class="text-mono text-sm">${esc(r.model || '--')}</td><td>${n(r.calls)}</td><td>${n(r.failed)}</td>${tokenCells(r)}<td>${money(r.cost)}</td>
            <td class="text-sm text-muted">${r.price_source === 'claude' ? 'Claude list price' : r.price_source === 'custom' ? 'Custom prices' : 'Not priced'}</td></tr>`))}</div>
      <div class="panel" style="margin-top:16px;padding:0"><div class="panel__header"><span class="panel__title">By feature</span></div>
        ${table(['Feature', 'Calls', 'Failed', 'Input', 'Output', 'Cache read', 'Cache write', 'Cost'],
          d.by_purpose.map(r => `<tr><td>${esc(PURPOSES[r.purpose] || r.purpose)}</td><td>${n(r.calls)}</td><td>${n(r.failed)}</td>${tokenCells(r)}<td>${money(r.cost)}</td></tr>`))}</div>
      <form class="panel" id="ai-settings" style="margin-top:16px">
        <div class="panel__header"><span class="panel__title">Monthly limit and prices</span></div>
        <div class="panel__body">
          <p class="text-sm text-muted" style="margin-top:0">When a limit is reached, AI features stop until the 1st (UTC): hunts fall back to keyword searches and alert analysis is skipped. Blank means no limit; 0 turns AI off.</p>
          <div class="ai-form-grid">${field('monthly_cost_limit', 'Monthly cost limit (USD)', 'e.g. 50')}${field('monthly_token_limit', 'Monthly token limit', 'e.g. 5000000')}</div>
          <p class="text-sm" style="margin:12px 0 4px"><strong>Custom API prices</strong> <span class="text-muted">(USD per million tokens)</span></p>
          <p class="text-sm text-muted" style="margin-top:0">Used for custom and OpenAI-compatible providers, Amazon Bedrock (whose prices are set by AWS), and any model not in the Claude price list. Without them, Claude models use Anthropic list prices.</p>
          <div class="ai-form-grid">${field('price_input', 'Input', 'e.g. 3')}${field('price_output', 'Output', 'e.g. 15')}${field('price_cache_read', 'Cache read', 'optional')}${field('price_cache_write', 'Cache write', 'optional')}</div>
          <div style="display:flex;align-items:center;gap:10px;margin-top:8px">
            <button class="btn btn--primary btn--sm" type="submit">Save</button><span id="ai-save-status" class="text-sm" role="status"></span></div>
          <details style="margin-top:16px"><summary class="text-sm text-muted">Claude list prices used (as of ${esc(d.claude_prices.as_of)})</summary>
            ${table(['Model', 'Input', 'Output', 'Cache read', 'Cache write'],
              d.claude_prices.models.map(p => `<tr><td class="text-mono text-sm">${esc(p.model)}</td><td>$${esc(p.input)}</td><td>$${esc(p.output)}</td><td>$${esc(p.cache_read)}</td><td>$${esc(p.cache_write)}</td></tr>`))}
          </details>
        </div>
      </form>`;
    document.getElementById('ai-days').addEventListener('change', e => { days = +e.target.value; load(true); });
    document.getElementById('ai-settings').addEventListener('submit', save);
  }

  async function save(e) {
    e.preventDefault();
    const status = document.getElementById('ai-save-status');
    const body = Object.fromEntries(new FormData(e.target).entries());
    status.textContent = 'Saving...';
    try {
      const res = await fetch(`${API}/settings`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Could not save');
      status.textContent = data.changed.length ? 'Saved' : 'No changes';
      load(true);
    } catch (err) {
      status.textContent = err.message;
    }
  }

  async function load(force) {
    if (loaded && !force) return;
    loaded = true;
    if (!pane().innerHTML) pane().innerHTML = '<p class="text-muted text-sm" style="padding:16px">Loading...</p>';
    try {
      const res = await fetch(`${API}?days=${days}`, { headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error();
      render(await res.json());
    } catch {
      pane().innerHTML = '<p class="text-muted text-sm" style="padding:16px">Could not load AI usage.</p>';
      loaded = false;
    }
  }

  window.AIUsage = { load };
})();
