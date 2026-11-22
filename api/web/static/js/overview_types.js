// Security Overview tabs: Infrastructure (hosts), Code (repositories), Web apps (sites), or All side by side.
// Each tab narrows the overview's data to its kind of asset and names things the way that team does; the choice
// is remembered per browser. Everything shown goes through esc().
window.OverviewTypes = (() => {
  const T = {
    infra: { asset: 'hosts', noun: 'devices', Noun: 'Devices', top: 'Top Risk Devices', by: 'environment',
             byTitle: 'Exposure by Environment', byCol: 'Environment', last: 'EDR', affected: 'Affected devices', name: 'Infrastructure' },
    code: { asset: 'repositories', noun: 'repositories', Noun: 'Repositories', top: 'Top Risk Repositories', by: 'application',
            byTitle: 'Exposure by Application', byCol: 'Application', last: 'Open findings', affected: 'Affected repositories', name: 'Code' },
    web: { asset: 'sites', noun: 'sites', Noun: 'Sites', top: 'Top Risk Sites', by: 'environment',
           byTitle: 'Exposure by Environment', byCol: 'Environment', last: 'Internet facing', affected: 'Affected sites', name: 'Web apps' },
  };
  const KINDS = ['infra', 'code', 'web', 'all'];
  const fromUrl = new URLSearchParams(location.search).get('type');
  const saved = (() => { try { return localStorage.getItem('ctem.overviewType'); } catch (e) { return null; } })();
  let kind = KINDS.includes(fromUrl) ? fromUrl : KINDS.includes(saved) ? saved : 'infra';
  const $ = id => document.getElementById(id);
  const set = (id, text) => { const el = $(id); if (el) el.textContent = text; };

  function apply() {
    document.querySelectorAll('#ov-kind [data-kind]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.kind === kind)));
    const all = kind === 'all';
    ['summary-cards', 'ov-cols', 'ov-kev'].forEach(id => { if ($(id)) $(id).hidden = all; });
    $('overview-all').hidden = !all;
    if (all) return;
    const t = T[kind];
    ['f', 'd', 'c'].forEach(g => set(`lbl-${g}`, `Grade ${g.toUpperCase()} ${t.noun}`));
    set('eye-total', `Total ${t.Noun}`);
    set('top-title', t.top);
    set('top-th-name', kind === 'code' ? 'Repository' : kind === 'web' ? 'Site' : 'Hostname');
    set('top-th-last', t.last);
    set('env-title', t.byTitle);
    set('env-th-name', t.byCol);
    set('env-th-count', t.Noun);
    set('kev-th-affected', t.affected);
    $('card-itdr').hidden = kind !== 'infra';           // identity tiles belong to the infrastructure view
    $('card-shadow').hidden = kind !== 'infra';
    $('card-exposed').hidden = kind === 'infra';
    set('lbl-exposed', kind === 'code' ? 'Behind a live site' : 'Internet facing');
    $('top-viewall').href = `/devices?asset=${t.asset}`;
  }

  function pick(k, onChange) {
    if (!KINDS.includes(k) || k === kind) return;
    kind = k;
    try { localStorage.setItem('ctem.overviewType', k); } catch (e) { /* still works, just not remembered */ }
    apply();
    onChange();
  }

  // The Infrastructure, Code and Web apps columns of the All view, from each one's summary and top three
  function allView(cols) {
    const n = v => Number(v || 0).toLocaleString();
    const row = (l, v, href) => `<div class="vd-col__row"><span>${esc(l)}</span><b>${href ? `<a class="dt-link" href="${esc(href)}">${esc(n(v))}</a>` : esc(n(v))}</b></div>`;
    return cols.map(({ k, sum, top }) => {
      const t = T[k];
      if (!sum) return `<section class="vd-col"><h2>${esc(t.name)}</h2><p class="vd-col__note">Couldn't load.</p></section>`;
      const base = `/devices?asset=${t.asset}`;
      return `<section class="vd-col"><div style="display:flex;justify-content:space-between;align-items:baseline">
          <h2>${esc(t.name)}</h2><button type="button" class="btn btn--ghost btn--sm" data-open="${k}">Open tab</button></div>
        ${row(`Total ${t.noun}`, sum.total, base)}${row(`Grade F ${t.noun}`, sum.grades.F, `${base}&grade=F`)}
        ${row(`Grade D ${t.noun}`, sum.grades.D, `${base}&grade=D`)}${row('With known exploited (KEV)', sum.kev_devices, `${base}&sort=kev_findings&order=desc`)}
        ${k === 'infra' ? '' : row(k === 'code' ? 'Behind a live site' : 'Internet facing', sum.internet_exposed)}
        <div class="text-sm text-muted" style="margin-top:4px">Riskiest</div>
        ${(top || []).slice(0, 3).map(d => `<div class="vd-col__row"><a class="dt-link" href="/devices/${encodeURIComponent(d.id)}">${esc(d.hostname)}</a><b>${esc(d.risk_grade || '-')}</b></div>`).join('') || '<div class="text-muted text-sm">None</div>'}
      </section>`;
    }).join('') + '<p class="vd-col__note" style="grid-column:1/-1">Shown side by side and never added together: different work for different teams.</p>';
  }

  return { kind: () => kind, t: () => T[kind] || T.infra, T, apply, pick, allView };
})();
