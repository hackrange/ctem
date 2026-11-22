// Asset trend: a small 30-day line of open findings in the lower right of the Details panel, in the organization's
// Header Accent Color (Admin > Branding, the --accent variable). It never makes the panel taller: it takes the last
// free cell of the details grid, or sits in the panel header when the last row is full. Clicking it opens a larger
// chart (open, critical, high, and the risk score where there is history) in a dialog that closes only from its
// Close button. Everything shown goes through esc().
window.AssetTrend = (() => {
  const $ = id => document.getElementById(id);
  const RANGES = [30, 90, 180, 365];
  let deviceId = null, label = '', chart = null, cache = {};
  const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const accent = () => css('--accent') || '#f5a623';

  async function load(days) {
    if (cache[days]) return cache[days];
    const r = await fetch(`/api/v1/devices/${encodeURIComponent(deviceId)}/trend?days=${days}`, { headers: { Accept: 'application/json' } });
    if (!r.ok) return null;
    return (cache[days] = await r.json());
  }

  // A square chart (as tall as it is wide): the line with a light fill under it, in the accent color
  function spark(values, w = 150, h = 150) {
    if (!values.length) return '';
    const hi = Math.max(...values), lo = Math.min(...values), span = (hi - lo) || 1;
    const xy = values.map((v, i) => [i / Math.max(1, values.length - 1) * w, h - 4 - (v - lo) / span * (h - 10)]);
    const pts = xy.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
    const c = esc(accent());
    return `<svg class="dev-trend__chart" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" aria-hidden="true" preserveAspectRatio="none">
      <polygon points="0,${h} ${pts} ${w},${h}" fill="${c}" fill-opacity="0.12"/>
      <polyline points="${pts}" fill="none" stroke="${c}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/></svg>`;
  }

  function place(box) {
    const dl = $('dev-info');
    box.classList.add('dev-trend--cell');
    dl.appendChild(box);
    const items = [...dl.children].filter(x => x !== box);
    const last = items[items.length - 1];
    // a new row means the last row was full: sit in the header instead, so the panel keeps its height
    if (last && box.offsetTop > last.offsetTop + last.offsetHeight - 4) {
      box.classList.remove('dev-trend--cell');
      box.classList.add('dev-trend--head');
      document.querySelector('#dev-info-panel .panel__header').appendChild(box);
    }
  }

  async function mount(id, name) {
    deviceId = id;
    label = name || '';
    cache = {};
    document.querySelectorAll('.dev-trend').forEach(x => x.remove());
    const d = await load(30);
    if (!d || !d.open) return;   // no access to findings (inventory), or nothing to draw
    const nowOpen = d.open[d.open.length - 1], then = d.open[0];
    const change = nowOpen - then;
    const box = document.createElement('button');
    box.type = 'button';
    box.className = 'dev-trend';
    box.title = 'Open findings over the last 30 days. Click to expand.';
    box.setAttribute('aria-label', `Open findings trend, 30 days: ${nowOpen} now, ${change >= 0 ? 'up' : 'down'} ${Math.abs(change)}. Expand`);
    box.innerHTML = `<span class="dev-trend__label text-sm text-muted">Open findings · 30d</span>
        <span class="dev-trend__top"><b>${esc(nowOpen.toLocaleString())}</b><span class="text-sm ${change > 0 ? 'dev-trend__up' : change < 0 ? 'dev-trend__down' : 'text-muted'}">${
          change ? `${change > 0 ? '+' : ''}${esc(change.toLocaleString())}` : '±0'}</span></span>${spark(d.open)}`;
    box.addEventListener('click', () => open(30));
    place(box);
  }

  function dialog() {
    let wrap = $('trend-dialog');
    if (wrap) return wrap;
    wrap = document.createElement('div');
    wrap.id = 'trend-dialog';
    wrap.className = 'tk-backdrop';
    wrap.setAttribute('role', 'dialog');
    wrap.setAttribute('aria-modal', 'true');
    wrap.setAttribute('aria-labelledby', 'trend-title');
    wrap.innerHTML = `<div class="tk-dialog" style="max-width:920px;width:94vw">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
          <h2 class="tk-title" id="trend-title" style="margin:0"></h2>
          <div class="dev-trend__ranges" role="group" aria-label="Range">${RANGES.map(r =>
            `<button type="button" data-range="${r}" aria-pressed="false">${r === 365 ? '1 year' : `${r} days`}</button>`).join('')}</div>
        </div>
        <p class="tk-sub" id="trend-sub" style="margin:6px 0 0"></p>
        <div id="trend-chart" style="height:360px;margin-top:10px"></div>
        <div style="display:flex;justify-content:flex-end;margin-top:12px">
          <button type="button" class="btn btn--primary btn--sm" id="trend-close">Close</button></div></div>`;
    document.body.appendChild(wrap);
    $('trend-close').onclick = () => { wrap.classList.remove('is-open'); };   // only its own button closes it
    wrap.querySelector('.dev-trend__ranges').addEventListener('click', e => {
      const b = e.target.closest('[data-range]');
      if (b) draw(Number(b.dataset.range));
    });
    return wrap;
  }

  async function draw(days) {
    document.querySelectorAll('#trend-dialog [data-range]').forEach(b => b.setAttribute('aria-pressed', String(Number(b.dataset.range) === days)));
    $('trend-sub').textContent = 'Loading...';
    const d = await load(days);
    if (!d) { $('trend-sub').textContent = 'The trend could not load.'; return; }
    const hasScore = d.score.some(v => v != null);
    $('trend-sub').textContent = `Open findings each day over the last ${days === 365 ? 'year' : `${days} days`}, from when each was first found until it was fixed`
      + (hasScore ? ', with the risk score' : '') + '.';
    if (!window.echarts) return;
    if (!chart) {
      chart = echarts.init($('trend-chart'));
      new ResizeObserver(() => chart && chart.resize()).observe($('trend-chart'));
    }
    const fg = css('--fg') || '#333', muted = css('--fg-muted') || '#888', grid = css('--border') || '#ddd';
    const line = (name, data, color, extra = {}) => ({ name, type: 'line', data, symbol: 'none', smooth: 0.2,
                                                       lineStyle: { width: 2, color }, itemStyle: { color }, ...extra });
    const series = [
      line('Open', d.open, accent(), { areaStyle: { opacity: 0.12, color: accent() } }),
      line('Critical', d.critical, css('--severity-critical') || '#dc2626'),
      line('High', d.high, css('--severity-high') || '#ea580c'),
    ];
    if (hasScore) series.push(line('Risk score', d.score, muted, { yAxisIndex: 1, connectNulls: true, lineStyle: { width: 1.5, type: 'dashed', color: muted } }));
    chart.setOption({
      backgroundColor: 'transparent', textStyle: { color: fg },
      tooltip: { trigger: 'axis' }, legend: { textStyle: { color: fg }, top: 0 },
      grid: { left: 48, right: hasScore ? 48 : 16, top: 36, bottom: 30 },
      xAxis: { type: 'category', data: d.days, boundaryGap: false, axisLabel: { color: muted }, axisLine: { lineStyle: { color: grid } } },
      yAxis: [{ type: 'value', name: 'findings', minInterval: 1, axisLabel: { color: muted }, nameTextStyle: { color: muted }, splitLine: { lineStyle: { color: grid } } },
              ...(hasScore ? [{ type: 'value', name: 'score', min: 0, max: 100, axisLabel: { color: muted }, nameTextStyle: { color: muted }, splitLine: { show: false } }] : [])],
      series,
    }, true);
  }

  function open(days) {
    const wrap = dialog();
    $('trend-title').textContent = `Trend${label ? `: ${label}` : ''}`;
    wrap.classList.add('is-open');
    $('trend-close').focus();
    draw(days);
  }

  return { mount, series: spark };
})();
