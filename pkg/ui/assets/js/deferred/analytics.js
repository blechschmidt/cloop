// ── Analytics dashboard ────────────────────────────────────────
//
// Five charts and the epics panel over a date range: task status, velocity,
// burn-down, cost trend and provider latency. Fetched on the tab's first open
// since Task 20456, markup included; it was 19-analytics.js. The charts are
// drawn by chart.js, which this panel fetches through ensureChartLib (Task
// 20289): opening the tab costs two scripts the first time, none after.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory. open() reads the
// figures afresh on every visit. schedule() is what the bundle's realtime
// handler calls, through panelIf, on any push that could change a chart: it
// coalesces a burst into one fetch, and does nothing unless the tab is on
// screen (Task 20126). Chart status: while chart.js is in flight the cards are
// hidden behind "Loading charts…", and a failed load or data fetch says which
// and offers Retry — over a slow link a silent set of blank cards is
// indistinguishable from "no data".
(function () {
  'use strict';

  window.cloopAnalyticsPanel = function (h) {
    const {api, esc, pUrl} = h;

    // Chart.js instances — stored so we can destroy+recreate on refresh.
    let _chartDonut = null, _chartVelocity = null, _chartBurndown = null,
        _chartCost = null, _chartLatency = null;

    // Debounce timer for WS-event-driven analytics refresh. The dashboard used
    // to poll /api/analytics every 30s; refreshes are now pushed by the server
    // via task_update / task_added / task_deleted / task_mutation / run_state /
    // step_output / provider_call events, coalesced through this debounce so a
    // burst of events makes at most one fetch (Task 20126).
    let _analyticsRefreshTimer = null;
    function _scheduleAnalyticsRefresh() {
      if (h.tab() !== 'analytics') return;
      if (_analyticsRefreshTimer) clearTimeout(_analyticsRefreshTimer);
      _analyticsRefreshTimer = setTimeout(() => {
        _analyticsRefreshTimer = null;
        try { loadAnalytics(); } catch(_) {}
      }, 500);
    }

    // Palette for multi-provider datasets.
    const _paletteBg   = ['rgba(88,166,255,.7)','rgba(63,185,80,.7)','rgba(188,140,255,.7)','rgba(57,197,207,.7)','rgba(248,81,73,.7)','rgba(210,153,34,.7)'];
    const _paletteLine = ['#58a6ff','#3fb950','#bc8cff','#39c5cf','#f85149','#d29922'];

    function resetRange() {
      const to   = new Date();
      const from = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const fmt = d => d.toISOString().slice(0,10);
      const fi = document.getElementById('analyticsFrom');
      const ti = document.getElementById('analyticsTo');
      if (fi) fi.value = fmt(from);
      if (ti) ti.value = fmt(to);
      loadAnalytics();
    }

    // _setChartStatus drives the banner above the canvases (Task 20289).
    //
    // `state` is one of:
    //   'loading'    — chart.js is in flight; the cards are hidden so the user is
    //                  not looking at five blank boxes with no explanation.
    //   'ready'      — hide the banner, show the cards.
    //   'lib-error'  — the library never arrived. Offer a retry.
    //   'data-error' — the library is fine but /api/analytics failed. Also
    //                  retryable, and worth distinguishing: the two have different
    //                  causes and the message should not blame the wrong one.
    function _setChartStatus(state, detail) {
      const box   = document.getElementById('analyticsChartStatus');
      const text  = document.getElementById('analyticsChartStatusText');
      const retry = document.getElementById('analyticsChartRetry');
      const cards = document.getElementById('analyticsCharts');

      if (cards) cards.style.display = (state === 'ready') ? '' : 'none';
      if (!box || !text || !retry) return;

      if (state === 'ready') {
        box.style.display = 'none';
        return;
      }
      box.style.display = 'flex';
      if (state === 'loading') {
        text.textContent = 'Loading charts…';
        retry.style.display = 'none';
        return;
      }
      const why = (detail && detail.message) ? detail.message : String(detail || 'unknown error');
      text.textContent = (state === 'lib-error')
        ? 'Charts could not be loaded: ' + why + '.'
        : 'Chart data could not be loaded: ' + why + '.';
      retry.style.display = '';
    }

    // The banner's Retry button is load(): ensureChartLib() forgets a failed load,
    // so it genuinely re-fetches rather than replaying the rejection.

    function loadAnalytics() {
      // Initialise date pickers if empty.
      const fi = document.getElementById('analyticsFrom');
      const ti = document.getElementById('analyticsTo');
      if (fi && !fi.value) {
        const from = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        fi.value = from.toISOString().slice(0,10);
      }
      if (ti && !ti.value) {
        ti.value = new Date().toISOString().slice(0,10);
      }

      const fromVal = fi ? fi.value : '';
      const toVal   = ti ? ti.value : '';
      const qs = (fromVal ? '&from=' + fromVal : '') + (toVal ? '&to=' + toVal : '');

      // Chart.js is fetched here rather than in the document head (Task 20289), so
      // the ~200 KiB only costs the sessions that actually open this tab. Already
      // loaded — the usual case on a second visit — resolves synchronously and the
      // banner never becomes visible.
      if (!window.Chart) _setChartStatus('loading');
      window.ensureChartLib().then(
        () => api(pUrl('/api/analytics?' + qs))
          .then(d => { _setChartStatus('ready'); _renderAnalytics(d); })
          .catch(err => { console.warn('analytics data error', err); _setChartStatus('data-error', err); }),
        err => { console.warn('chart library error', err); _setChartStatus('lib-error', err); }
      );

      // Load epics panel separately (no date filter needed, and no chart library:
      // it renders as plain DOM, so it still appears when chart.js cannot be had).
      api(pUrl('/api/epics')).then(d => {
        _renderEpics(d);
      }).catch(() => {});
      // Task 20126: no client-side polling — refreshes arrive via WS events
      // (see _scheduleAnalyticsRefresh in handleRealtimeMsg dispatch).
    }

    function _destroyChart(ch) {
      try { if (ch) ch.destroy(); } catch(_) {}
      return null;
    }

    function _analyticsColors() {
      const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
      return {
        text:   isDark ? '#e6edf3' : '#1f2328',
        muted:  isDark ? '#8b949e' : '#656d76',
        grid:   isDark ? 'rgba(48,54,61,.6)' : 'rgba(208,215,222,.6)',
      };
    }

    function _renderAnalytics(d) {
      const clr = _analyticsColors();
      const tickOpts = { color: clr.muted, font: { size: 11 } };
      const gridOpts = { color: clr.grid };
      const legendOpts = { labels: { color: clr.text, font: { size: 11 }, boxWidth: 12 } };

      // ── Status Donut ──────────────────────────────────────────────
      _chartDonut = _destroyChart(_chartDonut);
      const donutCtx = document.getElementById('chartStatusDonut');
      if (donutCtx && d.status_donut) {
        const nonzero = d.status_donut.values.some(v => v > 0);
        donutCtx.closest('div').style.display = nonzero ? '' : 'none';
        if (nonzero) {
          _chartDonut = new Chart(donutCtx, {
            type: 'doughnut',
            data: {
              labels: d.status_donut.labels,
              datasets: [{
                data: d.status_donut.values,
                backgroundColor: ['#8b949e','#39c5cf','#3fb950','#f85149','#d29922','#bc8cff'],
                borderWidth: 0,
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              cutout: '60%',
              plugins: { legend: legendOpts, tooltip: { callbacks: {
                label: ctx => ' ' + ctx.label + ': ' + ctx.raw
              }}}
            }
          });
        }
      }

      // ── Velocity Sparkline ────────────────────────────────────────
      _chartVelocity = _destroyChart(_chartVelocity);
      const velCtx = document.getElementById('chartVelocity');
      if (velCtx && d.velocity) {
        _chartVelocity = new Chart(velCtx, {
          type: 'bar',
          data: {
            labels: d.velocity.labels.map(l => l.slice(5)), // MM-DD
            datasets: [{
              label: 'Tasks completed',
              data: d.velocity.values,
              backgroundColor: 'rgba(88,166,255,.6)',
              borderColor: '#58a6ff',
              borderWidth: 1,
              borderRadius: 3,
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { ticks: { ...tickOpts, maxRotation: 45 }, grid: gridOpts },
              y: { ticks: { ...tickOpts, stepSize: 1 }, grid: gridOpts, beginAtZero: true }
            }
          }
        });
      }

      // ── Burndown ──────────────────────────────────────────────────
      _chartBurndown = _destroyChart(_chartBurndown);
      const bdCtx = document.getElementById('chartBurndown');
      if (bdCtx && d.burndown) {
        _chartBurndown = new Chart(bdCtx, {
          type: 'line',
          data: {
            labels: d.burndown.labels.map(l => l.slice(5)),
            datasets: [
              {
                label: 'Done (cumulative)',
                data: d.burndown.done_cumulative,
                borderColor: '#3fb950',
                backgroundColor: 'rgba(63,185,80,.15)',
                fill: true,
                tension: 0.3,
                pointRadius: 2,
              },
              {
                label: 'Remaining',
                data: d.burndown.remaining,
                borderColor: '#f85149',
                backgroundColor: 'rgba(248,81,73,.1)',
                fill: true,
                tension: 0.3,
                pointRadius: 2,
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: legendOpts },
            scales: {
              x: { ticks: { ...tickOpts, maxRotation: 45 }, grid: gridOpts },
              y: { ticks: tickOpts, grid: gridOpts, beginAtZero: true }
            }
          }
        });
      }

      // ── Cost Trend ────────────────────────────────────────────────
      _chartCost = _destroyChart(_chartCost);
      const costCtx = document.getElementById('chartCostTrend');
      if (costCtx && d.cost_trend) {
        const datasets = (d.cost_trend.datasets || []).map((ds, i) => ({
          label: ds.provider,
          data: ds.values,
          borderColor: _paletteLine[i % _paletteLine.length],
          backgroundColor: _paletteBg[i % _paletteBg.length],
          fill: false,
          tension: 0.3,
          pointRadius: 2,
        }));
        if (datasets.length === 0) {
          datasets.push({
            label: 'No data',
            data: (d.cost_trend.labels || []).map(() => 0),
            borderColor: clr.muted,
            fill: false,
            tension: 0,
            pointRadius: 0,
          });
        }
        _chartCost = new Chart(costCtx, {
          type: 'line',
          data: { labels: (d.cost_trend.labels || []).map(l => l.slice(5)), datasets },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: legendOpts },
            scales: {
              x: { ticks: { ...tickOpts, maxRotation: 45 }, grid: gridOpts },
              y: { ticks: { ...tickOpts, callback: v => '$' + v.toFixed(4) }, grid: gridOpts, beginAtZero: true }
            }
          }
        });
      }

      // ── Latency Histogram ─────────────────────────────────────────
      _chartLatency = _destroyChart(_chartLatency);
      const latCtx = document.getElementById('chartLatency');
      const latEmpty = document.getElementById('analyticsLatencyEmpty');
      const hasLatency = d.latency && d.latency.datasets && d.latency.datasets.length > 0;
      if (latEmpty) latEmpty.style.display = hasLatency ? 'none' : 'block';
      if (latCtx && hasLatency) {
        const datasets = d.latency.datasets.map((ds, i) => ({
          label: ds.provider,
          data: ds.counts,
          backgroundColor: _paletteBg[i % _paletteBg.length],
          borderColor: _paletteLine[i % _paletteLine.length],
          borderWidth: 1,
          borderRadius: 3,
        }));
        _chartLatency = new Chart(latCtx, {
          type: 'bar',
          data: { labels: d.latency.buckets, datasets },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: legendOpts },
            scales: {
              x: { ticks: tickOpts, grid: gridOpts },
              y: { ticks: { ...tickOpts, stepSize: 1 }, grid: gridOpts, beginAtZero: true }
            }
          }
        });
      }

      // Empty state.
      const anyData = (d.burndown && d.burndown.done_cumulative && d.burndown.done_cumulative.some(v => v > 0)) ||
                      hasLatency ||
                      (d.cost_trend && d.cost_trend.datasets && d.cost_trend.datasets.length > 0);
      const emptyEl = document.getElementById('analyticsEmpty');
      if (emptyEl) emptyEl.style.display = anyData ? 'none' : 'block';

      // Last-refresh timestamp.
      const lr = document.getElementById('analyticsLastRefresh');
      if (lr) lr.textContent = 'Last refreshed: ' + new Date().toLocaleTimeString();
    }

    // ── Epics panel renderer ───────────────────────────────────────
    function _renderEpics(d) {
      const card = document.getElementById('epicsCard');
      const list = document.getElementById('epicsList');
      if (!card || !list) return;

      const epics = (d && d.epics) || [];
      if (epics.length === 0) {
        card.style.display = 'none';
        return;
      }

      const epicPalette = [
        '#58a6ff', '#3fb950', '#f78166', '#d2a8ff', '#ffa657', '#79c0ff', '#ff7b72',
      ];

      let html = '';
      epics.forEach((ep, i) => {
        const color = epicPalette[i % epicPalette.length];
        const total = ep.total || 0;
        const done  = ep.done  || 0;
        const pct   = total > 0 ? Math.round(done * 100 / total) : 0;
        const desc  = ep.description || '';

        html += '<div style="margin-bottom:14px">';
        html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">';
        html += '<span style="font-size:13px;font-weight:600;color:' + color + '">' + esc(ep.name) + '</span>';
        html += '<span style="font-size:11px;color:var(--muted)">' + done + ' / ' + total + ' done &nbsp;(' + pct + '%)</span>';
        html += '</div>';
        if (desc) {
          html += '<div style="font-size:11px;color:var(--muted);margin-bottom:5px">' + esc(desc) + '</div>';
        }
        // Progress bar
        html += '<div style="height:8px;background:var(--border);border-radius:4px;overflow:hidden">';
        html += '<div style="height:100%;width:' + pct + '%;background:' + color + ';border-radius:4px;transition:width .3s"></div>';
        html += '</div>';
        // Stat badges
        html += '<div style="display:flex;gap:8px;margin-top:4px;flex-wrap:wrap">';
        if (ep.pending  > 0) html += '<span style="font-size:10px;color:var(--muted)">' + ep.pending  + ' pending</span>';
        if (ep.failed   > 0) html += '<span style="font-size:10px;color:#f78166">'      + ep.failed   + ' failed</span>';
        if (ep.skipped  > 0) html += '<span style="font-size:10px;color:var(--muted)">' + ep.skipped  + ' skipped</span>';
        html += '</div>';
        html += '</div>';
      });

      list.innerHTML = html;
      card.style.display = '';
    }

    return h.mount({open: loadAnalytics, load: loadAnalytics, resetRange, schedule: _scheduleAnalyticsRefresh}, 'analytics', `
    <div class="section">
      <div class="section-title" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        Analytics
        <div style="display:flex;align-items:center;gap:8px;margin-left:auto;flex-wrap:wrap">
          <label style="font-size:12px;color:var(--muted)">From:</label>
          <input type="date" id="analyticsFrom" class="form-input" style="width:140px;padding:4px 8px;font-size:12px" data-change="load">
          <label style="font-size:12px;color:var(--muted)">To:</label>
          <input type="date" id="analyticsTo" class="form-input" style="width:140px;padding:4px 8px;font-size:12px" data-change="load">
          <button class="btn" style="padding:4px 10px;font-size:12px" data-act="resetRange">Last 30d</button>
          <button class="btn" style="padding:4px 10px;font-size:12px" data-act="load">&#8635; Refresh</button>
        </div>
      </div>

      <div id="analyticsChartStatus" role="status" style="display:none;margin-top:16px;padding:12px 14px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);font-size:12.5px;color:var(--muted);align-items:center;gap:10px;flex-wrap:wrap">
        <span id="analyticsChartStatusText">Loading charts…</span>
        <button class="btn" id="analyticsChartRetry" style="display:none;padding:3px 10px;font-size:11px" data-act="load">Retry</button>
      </div>

      <div id="analyticsCharts">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px" class="analytics-grid">
        <div class="analytics-card">
          <div class="analytics-card-title">Task Status</div>
          <div style="position:relative;height:220px;display:flex;align-items:center;justify-content:center">
            <canvas id="chartStatusDonut" aria-label="Task status donut chart" role="img"></canvas>
          </div>
        </div>
        <div class="analytics-card">
          <div class="analytics-card-title">Velocity — Tasks/Day (last 14 days)</div>
          <div style="position:relative;height:220px">
            <canvas id="chartVelocity" aria-label="Velocity sparkline chart" role="img"></canvas>
          </div>
        </div>
      </div>

      <div style="margin-top:16px">
        <div class="analytics-card">
          <div class="analytics-card-title">Task Burn-Down</div>
          <div style="position:relative;height:240px">
            <canvas id="chartBurndown" aria-label="Task burndown chart" role="img"></canvas>
          </div>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px" class="analytics-grid">
        <div class="analytics-card">
          <div class="analytics-card-title">Provider Cost Trend (USD/day)</div>
          <div style="position:relative;height:240px">
            <canvas id="chartCostTrend" aria-label="Provider cost trend chart" role="img"></canvas>
          </div>
        </div>
        <div class="analytics-card">
          <div class="analytics-card-title">Per-Provider Latency Histogram</div>
          <div style="position:relative;height:240px">
            <canvas id="chartLatency" aria-label="Per-provider latency histogram" role="img"></canvas>
          </div>
          <div id="analyticsLatencyEmpty" style="display:none;color:var(--muted);font-size:12px;text-align:center;padding:8px 0">
            No latency data yet — run tasks to populate.
          </div>
        </div>
      </div>
      </div>

      <div style="margin-top:16px">
        <div class="analytics-card" id="epicsCard" style="display:none">
          <div class="analytics-card-title">Epic Progress</div>
          <div id="epicsList" style="padding:4px 0"></div>
        </div>
      </div>

      <div id="analyticsEmpty" style="display:none;color:var(--muted);font-size:13px;padding:16px 0;text-align:center">
        No data yet for the selected date range. Run some tasks to see analytics.
      </div>
      <div style="color:var(--muted);font-size:11px;margin-top:10px;text-align:right" id="analyticsLastRefresh"></div>
    </div>
    `);
  };
})();
