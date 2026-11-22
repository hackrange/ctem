// Admin > Users > Edit > Data access: "this person sees assets where <tag role> is A or B", with a live preview.
// Values are typed or picked from the ones in use; Enter, comma or Tab adds one. Everything shown goes through esc().
window.UserAccess = (() => {
  const API = '/api/v1/admin/users';
  let opts = null, rules = [], userId = null, timer = null;
  const $ = id => document.getElementById(id);

  async function json(url, init) {
    const r = await fetch(url, { headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, ...init });
    if (!r.ok) throw new Error(r.status === 422 ? 'Check the values: up to 256 characters each, without < or >.' : 'Data access could not be saved.');
    return r.json();
  }

  const roleName = k => ((opts && opts.roles.find(r => r.key === k)) || { name: k }).name;

  // The copyable form: key = "value" OR key = "value". Keys are the tag role keys (or their names); "tag" is one
  // exact tag. Paste it on another user and Apply to give them the same access.
  const quote = v => `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  const toText = list => list.flatMap(r => r.values.map(v => `${r.role} = ${quote(v)}`)).join(' OR ');
  function fromText(text) {
    const out = [], errs = [];
    const keyOf = k => {
      const t = k.trim().toLowerCase();
      const hit = opts.roles.find(r => r.key === t || r.name.toLowerCase() === t || r.name.toLowerCase().replace(/\s+/g, '_') === t);
      return hit ? hit.key : null;
    };
    const re = /\s*([A-Za-z][\w ]{0,63}?)\s*(?:=|\bis\b)\s*"((?:[^"\\]|\\.)*)"\s*(?:\bOR\b|$)/giy;
    let m, at = 0;
    const src = text.trim();
    while (at < src.length && (re.lastIndex = at, m = re.exec(src))) {
      const key = keyOf(m[1]), val = m[2].replace(/\\(.)/g, '$1').trim();
      if (!key) errs.push(`Unknown tag role "${m[1].trim()}"`);
      else if (!val || val.length > 256 || /[<>]/.test(val)) errs.push(`Check the value for ${m[1].trim()}`);
      else {
        let r = out.find(x => x.role === key);
        if (!r) out.push(r = { role: key, values: [] });
        if (!r.values.some(x => x.toLowerCase() === val.toLowerCase())) r.values.push(val);
      }
      at = re.lastIndex;
    }
    if (src && at < src.length) errs.push(`Couldn't read: ${src.slice(at, at + 40)}. Use role = "value" joined by OR.`);
    return { rules: out, errs };
  }

  function draw() {
    const box = $('ua-rules');
    if (!rules.length) {
      box.innerHTML = '<p class="text-muted text-sm" style="margin:4px 0">No rules: this person sees only what their roles and assignments give.</p>';
    } else {
      box.innerHTML = rules.map((r, i) => `<div class="ua-rule" data-i="${i}">
          <div class="ua-rule__head">
            ${i ? '<span class="ua-or">OR</span>' : ''}
            <select class="filter-select" data-role aria-label="Tag role">${opts.roles.map(o =>
              `<option value="${esc(o.key)}"${o.key === r.role ? ' selected' : ''}>${esc(o.name)}</option>`).join('')}</select>
            <span class="text-sm text-muted">is</span>
            <button type="button" class="btn btn--ghost btn--sm" data-drop aria-label="Remove this rule">Remove</button>
          </div>
          ${r.role === 'all' ? '<div class="ua-values"><span class="chip chip--high">every asset, tagged or not</span></div>' : `<div class="ua-values">${r.values.map((v, j) => `${j ? '<span class="ua-or ua-or--small">or</span>' : ''}<span class="chip chip--medium">${esc(v)}
              <button type="button" class="ua-x" data-unval="${j}" aria-label="Remove ${esc(v)}">&times;</button></span>`).join('')}
            <input class="form-input ua-input" data-add list="ua-list-${i}" placeholder="${r.values.length ? 'Another value' : 'A name, email or pattern like *@acme.example, then Enter'}" maxlength="256">
            <datalist id="ua-list-${i}">${((opts.values || {})[r.role] || []).slice(0, 300).map(v => `<option value="${esc(v)}">`).join('')}</datalist>
          </div>`}</div>`).join('');
    }
    if (document.activeElement !== $('ua-text')) $('ua-text').value = toText(complete());
    $('ua-text-msg').textContent = '';
    preview();
  }

  function addValue(i, raw) {
    const r = rules[i];
    raw.split(/[,;]/).map(v => v.trim()).filter(Boolean).forEach(v => {
      if (v.length <= 256 && !/[<>]/.test(v) && !r.values.some(x => x.toLowerCase() === v.toLowerCase())) r.values.push(v);
    });
  }

  function wire() {
    const box = $('ua-rules');
    box.addEventListener('change', e => {
      const row = e.target.closest('.ua-rule');
      if (row && e.target.matches('[data-role]')) {
        const r = rules[+row.dataset.i], was = r.role;
        r.role = e.target.value;
        if (r.role === 'all') r.values = ['*'];            // every asset: nothing to pick
        else if (was === 'all') r.values = [];
        draw();
      }
      if (row && e.target.matches('[data-add]') && e.target.value.trim()) {   // a suggestion picked from the list
        addValue(+row.dataset.i, e.target.value); draw();
        box.querySelector(`.ua-rule[data-i="${row.dataset.i}"] [data-add]`)?.focus();
      }
    });
    box.addEventListener('keydown', e => {
      if (!e.target.matches('[data-add]')) return;
      const row = e.target.closest('.ua-rule');
      if (['Enter', ',', 'Tab'].includes(e.key) && e.target.value.trim()) {
        e.preventDefault();
        addValue(+row.dataset.i, e.target.value);
        draw();
        box.querySelector(`.ua-rule[data-i="${row.dataset.i}"] [data-add]`)?.focus();
      } else if (e.key === 'Backspace' && !e.target.value && rules[+row.dataset.i].values.length) {
        rules[+row.dataset.i].values.pop(); draw();
        box.querySelector(`.ua-rule[data-i="${row.dataset.i}"] [data-add]`)?.focus();
      }
    });
    box.addEventListener('click', e => {
      const row = e.target.closest('.ua-rule');
      if (!row) return;
      const i = +row.dataset.i;
      if (e.target.closest('[data-drop]')) { rules.splice(i, 1); draw(); }
      const x = e.target.closest('[data-unval]');
      if (x) { rules[i].values.splice(+x.dataset.unval, 1); draw(); }
    });
    $('ua-apply').addEventListener('click', () => {
      const { rules: got, errs } = fromText($('ua-text').value);
      if (errs.length) { $('ua-text-msg').textContent = errs[0]; return; }
      rules = got;
      $('ua-text').blur();
      draw();
      $('ua-text-msg').textContent = got.length ? 'Applied. Save to keep it.' : 'Cleared. Save to keep it.';
    });
    $('ua-copy').addEventListener('click', async () => {
      $('ua-text').value = toText(complete());
      try { await navigator.clipboard.writeText($('ua-text').value); $('ua-text-msg').textContent = 'Copied. Paste it on another user and Apply.'; }
      catch (e) { $('ua-text').select(); $('ua-text-msg').textContent = 'Press Ctrl+C to copy.'; }
    });
    $('ua-add').addEventListener('click', () => {
      const first = opts.roles.find(r => r.key === 'executive_owner') || opts.roles[1] || opts.roles[0];
      rules.push({ role: first.key, values: [] });
      draw();
      $('ua-rules').querySelector('.ua-rule:last-child [data-add]')?.focus();
    });
  }

  // What the rules match right now, as you type them
  function preview() {
    clearTimeout(timer);
    const live = complete();
    if (!live.length) { $('ua-preview').textContent = ''; return; }
    $('ua-preview').textContent = 'Checking...';
    timer = setTimeout(async () => {
      try {
        const p = await json(`${API}/access/preview`, { method: 'POST', body: JSON.stringify({ rules: live }) });
        $('ua-preview').innerHTML = p.all
          ? `<b>Every asset</b> (${esc(p.assets.toLocaleString())} today, tagged or not). <span class="text-muted">What they can change still comes from their roles.</span>`
          : p.tags
          ? `Matches <b>${esc(p.tags.toLocaleString())}</b> tag${p.tags === 1 ? '' : 's'} on <b>${esc(p.assets.toLocaleString())}</b> asset${p.assets === 1 ? '' : 's'}: <span class="text-muted">${esc(p.sample.join(', '))}${p.tags > p.sample.length ? '...' : ''}</span>`
          : '<span style="color:var(--severity-high)">Matches no tags yet.</span> <span class="text-muted">It will apply as soon as a tag with that value appears.</span>';
      } catch (e) { $('ua-preview').textContent = ''; }
    }, 300);
  }

  const complete = () => rules.filter(r => r.values.length).map(r => ({ role: r.role, values: r.values }));

  async function open(id) {
    userId = id;
    rules = [];
    $('ua-rules').innerHTML = '<p class="text-muted text-sm">Loading...</p>';
    $('ua-note').hidden = true;
    try {
      if (!opts) { opts = await json(`${API}/access/options`); wire(); }
      const d = await json(`${API}/${encodeURIComponent(id)}/access`);
      if (userId !== id) return;
      rules = d.rules.map(r => ({ role: r.role, values: [...r.values] }));
      $('ua-note').hidden = !d.sees_everything;
      draw();
    } catch (e) {
      $('ua-rules').innerHTML = '<p class="text-muted text-sm">Data access could not load.</p>';
    }
  }

  async function save(id) {
    if (!opts || id !== userId) return;
    // a value still in a box counts, so nobody loses what they typed by pressing Save
    document.querySelectorAll('#ua-rules [data-add]').forEach(inp => {
      const i = +inp.closest('.ua-rule').dataset.i;
      if (inp.value.trim()) addValue(i, inp.value);
    });
    const r = await json(`${API}/${encodeURIComponent(id)}/access`, { method: 'PUT', body: JSON.stringify({ rules: complete() }) });
    if (!r.ok) throw new Error(r.error || 'Data access could not be saved.');
  }

  return { open, save };
})();
