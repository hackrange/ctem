// Admin > Risk model: how each finding is scored. Risk-based (likelihood x reachability x impact, then protections)
// or the classic CVE-weighted score; the weights and the reachability ladder; Reset brings back the defaults.
// Saving rescores the whole fleet. Everything shown goes through esc().
window.RiskModel = (() => {
  const BASE = '/api/v1/admin/risk-model';
  const pane = () => document.getElementById('pane-risk');
  const LABELS = {
    weights: { likelihood: 'Likelihood', reachability: 'Reachability', impact: 'Impact' },
    likelihood: { kev: 'Known exploited (KEV)', pentest_proved: 'A pentest exploited it here', threat_actors: 'Adversaries use it',
                  epss_full: 'EPSS that counts as certain', epss_curve: 'EPSS curve (lower lifts small EPSS scores more)',
                  no_epss_cvss: 'No EPSS yet: CVSS counts for' },
    reachability: { pentest_proved: 'A pentest reached and exploited it', internet_listening: 'Listening service, internet-facing host',
                    listening: 'Listening service, internal', client_workstation: 'Client-side flaw on a workstation',
                    client_server: 'Client-side flaw on a server', adjacent: 'Needs the same network segment',
                    local: 'Needs local access first', physical: 'Needs physical access', unknown: 'No evidence either way',
                    not_reachable: 'A pentest found it closed or not exploitable',
                    internet_unknown: 'Internet-facing host, service unknown' },
    impact: { severity: 'Severity (CVSS)', criticality: 'Asset criticality' },
  };
  const HELP = {
    weights: 'How much each dimension counts. They combine as a weighted geometric mean: a flaw that is unlikely or unreachable stays low however severe it is.',
    likelihood: 'How likely the flaw is to be exploited at all. The strongest signal present wins.',
    reachability: 'Whether an attacker can get to the flaw on this host, from the strongest evidence present. Firewall rules and segmentation scale it down further.',
    impact: 'What it would cost: the flaw\'s severity and the asset\'s criticality, in these proportions.',
  };
  let data = null;

  async function call(method, path = '', body) {
    const r = await fetch(BASE + path, { method, credentials: 'same-origin',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    if (r.status === 422) throw new Error('Each value is a number from 0 to 1.');
    if (!r.ok) throw new Error('The server refused that change.');
    return r.json();
  }

  function group(name, values, defaults) {
    const rows = Object.keys(LABELS[name]).map(k => `
      <label style="display:grid;grid-template-columns:minmax(0,1fr) 90px 70px;gap:8px;align-items:center;margin:4px 0">
        <span class="text-sm">${esc(LABELS[name][k])}</span>
        <input type="number" class="form-input" data-g="${esc(name)}" data-k="${esc(k)}" min="${k === 'epss_curve' ? 0.05 : k === 'epss_full' ? 0.01 : 0}" max="1" step="0.01"
               value="${esc(String(values[k]))}" aria-label="${esc(LABELS[name][k])}">
        <span class="text-sm text-muted" title="Default">${esc(String(defaults[k]))}</span>
      </label>`).join('');
    return `<fieldset style="border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin:0 0 12px">
      <legend class="text-sm" style="font-weight:600;padding:0 4px">${esc(name.charAt(0).toUpperCase() + name.slice(1))}</legend>
      <p class="text-sm text-muted" style="margin:0 0 6px">${esc(HELP[name])}</p>
      <div class="text-sm text-muted" style="display:grid;grid-template-columns:minmax(0,1fr) 90px 70px;gap:8px"><span></span><span>Value</span><span>Default</span></div>
      ${rows}</fieldset>`;
  }

  function render() {
    const s = data.settings, d = data.defaults;
    pane().innerHTML = `<div class="panel" style="padding:16px;max-width:820px">
      <h2 class="panel__title" style="margin:0 0 6px">Risk model</h2>
      <p class="text-sm text-muted" style="margin:0 0 12px">How each finding is scored. Risk-based scoring ranks by how likely a flaw
        is to be exploited, whether an attacker can reach it on that host, and what it would cost, then by the protections in place
        (the EDR and what its policy blocks). The classic model weighs the CVE itself. Saving rescores every device; that takes a few minutes.</p>
      <label class="tk-radio" style="margin-bottom:12px"><input type="checkbox" id="rm-on"${s.enabled ? ' checked' : ''}> Risk-based scoring
        <span class="text-sm text-muted">(off: the classic CVE-weighted score)</span></label>
      ${group('weights', s.weights, d.weights)}${group('likelihood', s.likelihood, d.likelihood)}
      ${group('reachability', s.reachability, d.reachability)}${group('impact', s.impact, d.impact)}
      <p id="rm-msg" class="text-sm" role="status" style="min-height:1.2em"></p>
      <div style="display:flex;gap:8px">
        <button type="button" class="btn btn--primary btn--sm" id="rm-save">Save and rescore</button>
        <button type="button" class="btn btn--ghost btn--sm" id="rm-reset"${data.is_default ? ' disabled' : ''}>Reset to defaults</button>
      </div></div>`;
    document.getElementById('rm-save').onclick = save;
    document.getElementById('rm-reset').onclick = reset;
  }

  function collect() {
    const out = { enabled: document.getElementById('rm-on').checked, weights: {}, likelihood: {}, reachability: {}, impact: {} };
    let blank = null;
    pane().querySelectorAll('input[data-g]').forEach(i => {
      if (i.value.trim() === '' || !Number.isFinite(Number(i.value))) blank = blank || i;
      out[i.dataset.g][i.dataset.k] = Number(i.value);
    });
    if (blank) { blank.focus(); throw new Error('Every field needs a number from 0 to 1.'); }
    return out;
  }

  async function act(fn, done) {
    const msg = document.getElementById('rm-msg');
    msg.style.color = 'var(--text-muted)';
    msg.textContent = 'Saving...';
    try {
      data = await fn();
      render();
      document.getElementById('rm-msg').textContent = done;
    } catch (e) {
      msg.style.color = 'var(--severity-critical)';
      msg.textContent = e.message;
    }
  }

  const save = () => act(async () => call('PUT', '', collect()), 'Saved. Every device is being rescored.');
  const reset = () => {
    if (!confirm('Put every value back to its default and rescore every device?')) return;
    act(() => call('POST', '/reset'), 'Back to the defaults. Every device is being rescored.');
  };

  async function load() {
    try {
      data = await call('GET');
      render();
    } catch (e) {
      pane().innerHTML = `<p class="text-sm text-muted" style="padding:14px">${esc(e.message)}</p>`;
    }
  }
  return { load };
})();
