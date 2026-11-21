// Server-side paged, sortable, exportable table. All cell HTML goes through esc().
// Usage: DataTable.create({ mount, endpoint, listKey, columns, ... }) -> { reload(resetPage) }
(function () {
  const SIZES = [25, 50, 100, 200];

  function fmtInt(n) { return Number(n || 0).toLocaleString(); }

  function create(opts) {
    const urlState = opts.syncUrl ? new URLSearchParams(location.search) : new URLSearchParams();
    const st = {
      sort: urlState.get('sort') || opts.defaultSort || '',
      order: urlState.get('order') || opts.defaultOrder || 'desc',
      size: SIZES.includes(+urlState.get('size')) ? +urlState.get('size') : (opts.pageSize || 50),
      page: Math.max(1, parseInt(urlState.get('page') || '1', 10) || 1),
      total: 0,
      seq: 0,
    };
    const mount = opts.mount;
    mount.innerHTML = `
      <div class="dt-pager dt-pager--top"></div>
      <div class="dt-scroll"><table class="data-table">
        <thead><tr>${opts.columns.map((c, i) =>
          `<th data-i="${i}" ${c.sort ? 'class="dt-sortable" tabindex="0"' : ''}>${c.head || esc(c.label)}</th>`).join('')}</tr></thead>
        <tbody><tr><td colspan="${opts.columns.length}" class="text-muted text-sm" style="text-align:center;padding:24px">Loading...</td></tr></tbody>
      </table></div>
      <div class="dt-pager dt-pager--bottom"></div>`;
    const tbody = mount.querySelector('tbody');
    const ths = mount.querySelectorAll('th');

    ths.forEach(th => {
      const col = opts.columns[+th.dataset.i];
      if (!col.sort) return;
      const toggle = () => {
        if (st.sort === col.sort) st.order = st.order === 'asc' ? 'desc' : 'asc';
        else { st.sort = col.sort; st.order = col.firstOrder || 'asc'; }
        st.page = 1;
        load();
      };
      th.addEventListener('click', toggle);
      th.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    });

    function query(withPaging) {
      const p = new URLSearchParams();
      const extra = opts.params ? opts.params() : {};
      Object.entries(extra).forEach(([k, v]) => {
        if (Array.isArray(v)) v.filter(x => x !== '' && x != null).forEach(x => p.append(k, x));   // repeatable, e.g. tag
        else if (v !== '' && v != null) p.set(k, v);
      });
      if (st.sort) { p.set('sort', st.sort); p.set('order', st.order); }
      if (withPaging) { p.set('limit', st.size); p.set('offset', (st.page - 1) * st.size); }
      return p;
    }

    function pages() { return Math.max(1, Math.ceil(st.total / st.size)); }

    // 1 ... 4 [5] 6 ... 280
    function pageList(cur, last) {
      const want = new Set([1, last, cur - 1, cur, cur + 1].filter(n => n >= 1 && n <= last));
      const out = [];
      [...want].sort((a, b) => a - b).forEach((n, i, arr) => {
        if (i && n - arr[i - 1] > 1) out.push(null);
        out.push(n);
      });
      return out;
    }

    function renderPagers(count) {
      const start = st.total ? (st.page - 1) * st.size + 1 : 0;
      const end = (st.page - 1) * st.size + count;
      const last = pages();
      const info = st.total
        ? `Showing <strong>${fmtInt(start)}&ndash;${fmtInt(end)}</strong> of <strong>${fmtInt(st.total)}</strong>`
        : 'No results';
      const btn = (n, label, aria, extra = '') => `<button type="button" class="dt-page ${extra}" data-page="${n}" aria-label="${aria}"`
        + `${n === st.page && !extra.includes('arrow') ? ' aria-current="page"' : ''}`
        + `${(n < 1 || n > last || (n === st.page && !extra.includes('arrow'))) ? ' disabled' : ''}>${label}</button>`;
      const nav = `
        <nav class="dt-pages" aria-label="Pagination">
          ${btn(st.page - 1, '&lsaquo;', 'Previous page', 'dt-page--arrow')}
          ${pageList(st.page, last).map(n => n === null ? '<span class="dt-gap">&hellip;</span>'
            : btn(n, fmtInt(n), `Page ${n}`, n === st.page ? 'is-current' : '')).join('')}
          ${btn(st.page + 1, '&rsaquo;', 'Next page', 'dt-page--arrow')}
        </nav>`;
      const size = `
        <label class="dt-pager__size">Rows per page
          <select data-size>${SIZES.map(s => `<option value="${s}" ${s === st.size ? 'selected' : ''}>${s}</option>`).join('')}</select>
        </label>`;
      mount.querySelectorAll('.dt-pager').forEach((bar, i) => {
        const exp = i === 0 && opts.exportUrl ? '<a class="btn btn--ghost btn--sm" data-export href="#">Export CSV</a>' : '';
        bar.innerHTML = `<div class="dt-pager__info"><span>${info}</span>${exp}</div>`
          + `<div class="dt-pager__right">${size}${last > 1 ? nav : ''}</div>`;
      });
    }

    mount.addEventListener('click', e => {
      const btn = e.target.closest('button[data-page]');
      if (btn && !btn.disabled) {
        st.page = Math.min(pages(), Math.max(1, +btn.dataset.page));
        load();
      }
      const ex = e.target.closest('[data-export]');
      if (ex) {
        e.preventDefault();
        location.href = `${opts.exportUrl}?${query(false)}`;  // same filters + sort, every row
      }
    });
    mount.addEventListener('change', e => {
      const sel = e.target.closest('select[data-size]');
      if (!sel) return;
      st.size = +sel.value;
      st.page = 1;
      load();
    });

    function syncUrl() {
      if (!opts.syncUrl) return;
      const p = query(false);
      if (st.page > 1) p.set('page', st.page);
      if (st.size !== (opts.pageSize || 50)) p.set('size', st.size);
      history.replaceState(null, '', `${location.pathname}${p.toString() ? '?' + p : ''}`);
    }

    async function load() {
      const seq = ++st.seq;
      ths.forEach(th => {
        const col = opts.columns[+th.dataset.i];
        if (col.sort) th.setAttribute('aria-sort', col.sort === st.sort ? (st.order === 'asc' ? 'ascending' : 'descending') : 'none');
      });
      syncUrl();
      try {
        const res = await fetch(`${opts.endpoint}?${query(true)}`, { headers: { Accept: 'application/json' } });
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        if (seq !== st.seq) return;  // a newer request already won
        const rows = data[opts.listKey] || [];
        st.rows = rows;
        st.total = data.total || 0;
        if (!rows.length && st.page > 1 && st.total) { st.page = pages(); return load(); }
        tbody.innerHTML = rows.map(r => {
          const href = opts.rowHref ? opts.rowHref(r) : '';
          return `<tr ${href ? `data-href="${esc(href)}"` : ''}>${opts.columns.map(c => `<td>${c.render ? c.render(r) : esc(r[c.key] ?? '--')}</td>`).join('')}</tr>`;
        }).join('') || `<tr><td colspan="${opts.columns.length}" class="text-muted text-sm" style="text-align:center;padding:24px">${esc(opts.emptyText || 'Nothing found')}</td></tr>`;
        renderPagers(rows.length);
        if (opts.onLoad) opts.onLoad(data);
      } catch {
        if (seq !== st.seq) return;
        tbody.innerHTML = `<tr><td colspan="${opts.columns.length}" class="text-muted" style="text-align:center;padding:24px">Error loading data</td></tr>`;
      }
    }

    tbody.addEventListener('click', e => {
      if (e.target.closest('a,button,input,select')) return;
      const tr = e.target.closest('tr[data-href]');
      if (tr) location.href = tr.dataset.href;
    });

    load();
    return { reload(resetPage = true) { if (resetPage) st.page = 1; load(); }, rows: () => st.rows || [] };
  }

  // Shared cell renderers
  const R = {
    grade(g) {
      const m = { F: 'critical', D: 'high', C: 'medium', B: 'low', A: 'info' };
      return g ? `<span class="chip chip--${m[g] || 'info'}">${esc(g)}</span>` : '<span class="text-muted">--</span>';
    },
    // "(F 87.3 → A 0)": original grade/score, then what it is after an adjustment such as EDR containment
    adjusted(rawGrade, rawScore, grade, score) {
      const fmt = (g, n) => `${esc(g || '?')} ${n == null ? '--' : esc(Number(n).toFixed(n % 1 ? 1 : 0))}`;
      return `<span class="text-sm text-muted" title="Original score, then the score after containment">(${fmt(rawGrade, rawScore)} &rarr; ${fmt(grade, score)})</span>`;
    },
    // "3 days ago (EDR)": the freshest sign of life from any tool; the hover lists each tool's own date
    seenAgo(d) {
      if (!d.last_seen) return '<span class="text-muted">Never</span>';
      const days = Math.max(0, Math.floor((Date.now() - new Date(d.last_seen).getTime()) / 86400000));
      const text = days === 0 ? 'Today' : days === 1 ? '1 day ago' : `${days.toLocaleString()} days ago`;
      const each = Object.entries(d.seen_by || {}).map(([k, v]) => `${k}: ${new Date(v).toLocaleString()}`).join('\n');
      return `<span title="${esc(each)}">${esc(text)}</span>${d.last_seen_by ? ` <span class="text-sm text-muted">${esc(d.last_seen_by)}</span>` : ''}`;
    },
    // Where the scanner found a finding and what its CVSS vector needs; the hover text is the score's reason
    reach(f) {
      const why = f.reach ? ` title="${esc(f.reach)}"` : '';
      const chip = (cls, text) => `<span class="chip chip--${cls}" style="font-size:.7rem"${why}>${esc(text)}</span>`;
      const av = { physical: 'PHYSICAL ACCESS', local: 'LOCAL ACCESS', adjacent: 'ADJACENT NETWORK' }[f.attack_vector];
      if (f.exposure === 'listening' && !av) return chip('high', `LISTENING${f.ports ? ' ' + f.ports.toUpperCase() : ''}`);
      if (av) return chip('low', av);
      if (f.exposure === 'local') return chip('low', 'LOCAL CHECK');
      return '<span class="text-muted" title="The scanner didn\'t say where it found this">--</span>';
    },
    bool(v) {
      return v ? '<span style="color:var(--severity-low)">&#10003;</span>'
               : '<span style="color:var(--severity-critical)">&#10007;</span>';
    },
    score(s) {
      if (s == null) return '<span class="text-muted">--</span>';
      const c = s >= 80 ? 'critical' : s >= 60 ? 'high' : s >= 40 ? 'medium' : 'low';
      return `<div style="display:flex;align-items:center;gap:6px"><div class="score-bar" style="width:50px"><div class="score-bar__fill" style="width:${Math.min(100, +s)}%;background:var(--severity-${c})"></div></div><span class="text-sm">${esc(s)}</span></div>`;
    },
    date(iso) { return iso ? esc(new Date(iso).toLocaleDateString()) : '<span class="text-muted">--</span>'; },
    link(href, text) { return `<a class="dt-link" href="${esc(href)}">${esc(text || '--')}</a>`; },
    num: fmtInt,
  };

  window.DataTable = { create, R };
})();
