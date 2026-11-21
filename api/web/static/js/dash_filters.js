// Widget filters: "only count devices where ..." rows on tags, tag-mapping roles (Executive owner, Application...),
// sources, device type, OS family, criticality and risk grade, matched all (AND) or any (OR). The server checks
// every field, op and value again; this only builds the list.
(function () {
  const OPS = {
    tag: [['is', 'has tag'], ['is_not', "doesn't have tag"], ['starts_with', 'has a tag starting with'], ['not_starts_with', 'has no tag starting with']],
    role: [['is', 'is'], ['is_not', 'is not'], ['any', 'is set'], ['none', "isn't set"]],
    source: [['is', 'reported by'], ['is_not', 'not reported by']],
    device_type: [['is', 'is'], ['is_not', 'is not']],
    os_family: [['is', 'is'], ['is_not', 'is not']],
    criticality: [['is', 'is'], ['is_not', 'is not']],
    grade: [['is', 'is'], ['is_not', 'is not']],
    access: [['mine', 'only devices I have access to']],
  };
  const NO_VALUE = new Set(['any', 'none', 'mine']);
  let tagNames = null;   // loaded once, for the tag suggestions

  async function loadTags() {
    if (tagNames) return tagNames;
    try {
      const r = await fetch('/api/v1/tags?in_use=true&limit=2000', { headers: { Accept: 'application/json' } });
      tagNames = r.ok ? (await r.json()).tags.map(t => t.name) : [];
    } catch (e) { tagNames = []; }
    return tagNames;
  }

  // el: container. o: filter_options from the catalog. initial: {filters, match}. onChange(): something changed.
  function mount(el, o, initial, onChange) {
    o = o || { roles: [], sources: [], device_types: [], os_families: [], grades: [] };
    const fields = [['tag', 'Tag'], ...o.roles.map(r => [`role:${r.key}`, r.name]), ['source', 'Source (tool)'],
                    ['device_type', 'Device type'], ['os_family', 'OS family'], ['criticality', 'Criticality'], ['grade', 'Risk grade'],
                    ['access', 'My access (tags I am granted)']];
    const listId = `dwf-${Math.random().toString(36).slice(2, 8)}`;
    let rows = (initial.filters || []).map(f => ({ ...f }));
    el.innerHTML = `<div class="dwf">
      <div class="dwf__head"><span class="form-label" style="margin:0">Only count devices where</span>
        <select class="form-input dwf__match" aria-label="Match"><option value="all">all of these match</option><option value="any">any of these match</option></select></div>
      <div class="dwf__rows"></div>
      <button type="button" class="btn btn--ghost btn--sm dwf__add">+ Add a condition</button>
      <datalist id="${listId}-tags"></datalist></div>`;
    const box = el.querySelector('.dwf__rows');
    el.querySelector('.dwf__match').value = initial.match === 'any' ? 'any' : 'all';

    const key = f => (f.field === 'role' ? `role:${f.role}` : f.field);
    function valueInput(f, i) {
      if (NO_VALUE.has(f.op)) return '';
      const v = esc(f.value || '');
      const sel = list => `<select class="form-input" data-v="${i}"><option value="">Pick one</option>${list.map(([val, lab]) =>
        `<option value="${esc(val)}"${val === f.value ? ' selected' : ''}>${esc(lab)}</option>`).join('')}</select>`;
      if (f.field === 'source') return sel(o.sources.map(s => [s.value, s.label]));
      if (f.field === 'device_type') return sel(o.device_types.map(t => [t, t.replace(/_/g, ' ')]));
      if (f.field === 'os_family') return sel(o.os_families.map(x => [x.value, x.label]));
      if (f.field === 'grade') return sel(o.grades.map(g => [g, `Grade ${g}`]));
      if (f.field === 'criticality') return sel(['Very High', 'High', 'Medium', 'Low', 'Very Low'].map(c => [c, c]));
      if (f.field === 'role') {
        const r = o.roles.find(x => x.key === f.role);
        return `<input class="form-input" data-v="${i}" value="${v}" maxlength="128" list="${listId}-r${i}" placeholder="Name">
          <datalist id="${listId}-r${i}">${(r ? r.values : []).map(x => `<option value="${esc(x)}">`).join('')}</datalist>`;
      }
      return `<input class="form-input" data-v="${i}" value="${v}" maxlength="128" list="${listId}-tags" placeholder="Tag name">`;
    }
    function draw() {
      box.innerHTML = rows.map((f, i) => `<div class="dwf__row">
        <select class="form-input" data-f="${i}" aria-label="Field">${fields.map(([k, l]) => `<option value="${esc(k)}"${k === key(f) ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>
        <select class="form-input" data-o="${i}" aria-label="Condition">${OPS[f.field].map(([k, l]) => `<option value="${k}"${k === f.op ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>
        ${valueInput(f, i)}
        <button type="button" class="dw-tool" data-x="${i}" title="Remove" aria-label="Remove condition">&#10005;</button></div>`).join('')
        || '<div class="text-sm text-muted">No conditions: every device you can see counts.</div>';
      el.querySelector('.dwf__match').hidden = rows.length < 2;
    }
    function changed() { onChange && onChange(); }
    box.addEventListener('change', e => {
      const t = e.target;
      if (t.dataset.f != null) {
        const [field, role] = t.value.split(':');
        rows[+t.dataset.f] = { field, op: OPS[field][0][0], ...(role ? { role } : {}) };
        draw();
        if (field === 'tag') loadTags().then(n => { el.querySelector(`#${listId}-tags`).innerHTML = n.slice(0, 2000).map(x => `<option value="${esc(x)}">`).join(''); });
      } else if (t.dataset.o != null) { rows[+t.dataset.o].op = t.value; draw(); }
      else if (t.dataset.v != null) rows[+t.dataset.v].value = t.value.trim();
      changed();
    });
    box.addEventListener('input', e => { if (e.target.dataset.v != null) rows[+e.target.dataset.v].value = e.target.value.trim(); });
    box.addEventListener('click', e => { const x = e.target.closest('[data-x]'); if (x) { rows.splice(+x.dataset.x, 1); draw(); changed(); } });
    el.querySelector('.dwf__add').onclick = () => { rows.push({ field: 'tag', op: 'is', value: '' }); draw(); loadTags().then(n => {
      el.querySelector(`#${listId}-tags`).innerHTML = n.slice(0, 2000).map(x => `<option value="${esc(x)}">`).join(''); }); };
    el.querySelector('.dwf__match').onchange = changed;
    draw();
    if (rows.some(f => f.field === 'tag')) loadTags().then(n => { el.querySelector(`#${listId}-tags`).innerHTML = n.map(x => `<option value="${esc(x)}">`).join(''); });
    return {
      get: () => ({ filters: rows.filter(f => NO_VALUE.has(f.op) || f.value).map(f => ({ ...f })),
                    filter_match: el.querySelector('.dwf__match').value }),
    };
  }

  // "Executive owner is Jeffrey Davis and Source reported by crowdstrike", for the widget's filter badge
  function describe(w, o) {
    const fl = (w && w.filters) || [];
    if (!fl.length) return '';
    const name = f => (f.field === 'access' ? 'My access:' : f.field === 'role' ? ((o && o.roles.find(r => r.key === f.role)) || {}).name || f.role : f.field.replace(/_/g, ' '));
    const op = f => (OPS[f.field].find(x => x[0] === f.op) || [, f.op])[1];
    return fl.map(f => `${name(f)} ${op(f)}${f.value ? ` ${f.value}` : ''}`).join(w.filter_match === 'any' ? ' or ' : ' and ');
  }

  window.DashFilters = { mount, describe };
})();
