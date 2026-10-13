// ── Timeline (Gantt) tab ─────────────────────────────────────────────────────
//
// The Gantt chart of a project's plan: one bar per task from its start to its
// end, dependency arrows, and a "now" cursor. Fetched on the tab's first open
// since Task 20427, markup included — first paint has no room for a chart most
// sessions never open, and its place in the bundle paid for the approvals badge
// that every session needs. It was the first half of 11-timeline.js.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls —
// tl reads the shared plan and the filter bar — and the only name it puts on
// window is the factory. open() runs on every visit and whenever the bundle's
// loadTimeline() asks for a redraw: a state change, a filter, a theme toggle.
(function () {
  'use strict';

  window.cloopTimelinePanel = function (h) {
    const {api, esc, pUrl, tl} = h;

    function load() {
      return api(pUrl('/api/timeline')).then(data => {
        renderTimeline(data);
      }).catch(() => {
        const el = document.getElementById('timelineStatus');
        if (el) el.textContent = 'Failed to load timeline.';
      });
    }

    function renderTimeline(data) {
      // Apply filter bar: restrict to matching task IDs.
      let bars = data.bars || [];
      const appState = tl.state();
      if (tl.active() && appState && appState.plan && appState.plan.tasks) {
        const filteredIds = new Set(tl.apply(appState.plan.tasks).map(t => t.id));
        bars = bars.filter(b => filteredIds.has(b.taskId));
        tl.badge(bars.length, (data.bars||[]).length);
      } else {
        tl.badge((data.bars||[]).length, (data.bars||[]).length);
      }
      const nowStr = data.now;

      const chartWrap = document.getElementById('timelineChart');
      const emptyEl   = document.getElementById('timelineEmpty');
      const legendEl  = document.getElementById('timelineLegend');
      const statusEl  = document.getElementById('timelineStatus');

      if (!bars.length) {
        chartWrap.style.display = 'none';
        if (emptyEl) emptyEl.style.display = '';
        if (legendEl) legendEl.style.display = 'none';
        if (statusEl) statusEl.textContent = '';
        return;
      }

      if (emptyEl) emptyEl.style.display = 'none';
      chartWrap.style.display = '';
      if (legendEl) legendEl.style.display = 'flex';

      // Time range.
      let earliest = new Date(bars[0].start);
      let latest   = new Date(bars[0].end);
      bars.forEach(b => {
        const s = new Date(b.start), e = new Date(b.end);
        if (s < earliest) earliest = s;
        if (e > latest)   latest   = e;
      });
      // Snap earliest to 30-min boundary.
      const snapMs = 30 * 60 * 1000;
      earliest = new Date(Math.floor(earliest.getTime() / snapMs) * snapMs);
      // Ensure at least 1-hour window.
      if (latest - earliest < 60 * 60 * 1000) {
        latest = new Date(earliest.getTime() + 60 * 60 * 1000);
      }
      // Pad right by one tick.
      latest = new Date(latest.getTime() + snapMs);

      const totalMs = latest - earliest;

      // SVG layout constants.
      const PAD_LEFT   = 230;
      const PAD_RIGHT  = 20;
      const PAD_TOP    = 44;
      const ROW_H      = 38;
      const BAR_PAD    = 7;
      const BAR_H      = ROW_H - BAR_PAD * 2;
      const CHART_W    = Math.max(700, chartWrap.clientWidth - PAD_LEFT - PAD_RIGHT - 2);
      const SVG_W      = PAD_LEFT + CHART_W + PAD_RIGHT;
      const SVG_H      = PAD_TOP + bars.length * ROW_H + 20;

      const msToX = (ms) => PAD_LEFT + (ms / totalMs) * CHART_W;
      const tsToX = (ts) => msToX(new Date(ts) - earliest);

      // Build id → bar index map for dependency arrows.
      const idxMap = {};
      bars.forEach((b, i) => { idxMap[b.taskId] = i; });

      // Color by status.
      function barColor(status) {
        switch (status) {
          case 'done':        return '#22c55e';
          case 'in_progress': return '#3b82f6';
          case 'failed':      return '#ef4444';
          case 'timed_out':   return '#f97316';
          case 'skipped':     return '#6b7280';
          default:            return '#9ca3af'; // pending
        }
      }

      function statusLabel(status) {
        switch (status) {
          case 'in_progress': return 'In Progress';
          case 'timed_out':   return 'Timed Out';
          default:            return status.charAt(0).toUpperCase() + status.slice(1);
        }
      }

      function fmtMins(m) {
        if (!m) return '—';
        const h = Math.floor(m / 60), mm = m % 60;
        return h ? h + 'h ' + mm + 'm' : mm + 'm';
      }

      // Read CSS custom properties for theme-aware SVG colors.
      const _cs = getComputedStyle(document.documentElement);
      const svgBg      = _cs.getPropertyValue('--bg').trim()      || '#0d1117';
      const svgSurface = _cs.getPropertyValue('--surface').trim() || '#161b22';
      const svgMuted   = _cs.getPropertyValue('--muted').trim()   || '#8b949e';

      // Build SVG as a string for simplicity (avoids DOM thrash on re-renders).
      let svg = `<svg width="${SVG_W}" height="${SVG_H}" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit">`;

      // Arrow marker definition.
      svg += `<defs>
        <marker id="arrowhead" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
          <polygon points="0 0, 7 3.5, 0 7" fill="${svgMuted}" opacity="0.7"/>
        </marker>
      </defs>`;

      // Background.
      svg += `<rect width="${SVG_W}" height="${SVG_H}" fill="${svgBg}"/>`;

      // Tick marks and vertical grid lines.
      const tickIntervalMs = 30 * 60 * 1000; // 30 min
      const labelEvery = 2; // label every 2 ticks (= 1 hour)
      let tick = earliest.getTime(), tickCount = 0;
      while (tick <= latest.getTime()) {
        const x = msToX(tick - earliest.getTime());
        svg += `<line x1="${x.toFixed(1)}" y1="${PAD_TOP}" x2="${x.toFixed(1)}" y2="${SVG_H - 10}" class="tl-grid-line"/>`;
        if (tickCount % labelEvery === 0) {
          const d = new Date(tick);
          const label = d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0');
          svg += `<text x="${x.toFixed(1)}" y="${PAD_TOP - 8}" class="tl-tick-label" text-anchor="middle">${label}</text>`;
        }
        tick += tickIntervalMs;
        tickCount++;
      }

      // Date label.
      svg += `<text x="${PAD_LEFT}" y="14" font-size="11" fill="${svgMuted}">${earliest.toLocaleDateString()}</text>`;

      // Task rows.
      bars.forEach((b, i) => {
        const y = PAD_TOP + i * ROW_H;
        const rowFill = i % 2 === 0 ? svgSurface : svgBg;
        svg += `<rect x="0" y="${y}" width="${SVG_W}" height="${ROW_H}" fill="${rowFill}"/>`;

        // Label (truncated to ~28 chars).
        let label = `[${b.taskId}] ${b.title}`;
        if (label.length > 30) label = label.slice(0, 29) + '…';
        // Escape HTML entities in the label.
        const safeLabel = label.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        svg += `<text x="${PAD_LEFT - 8}" y="${y + ROW_H / 2 + 4}" class="tl-task-label" text-anchor="end">${safeLabel}</text>`;

        // Bar.
        const bx = tsToX(b.start);
        const bxEnd = tsToX(b.end);
        const bw = Math.max(4, bxEnd - bx);
        const by = y + BAR_PAD;
        const color = barColor(b.status);

        // We encode tooltip data as data-* attributes; JS attaches mouseover.
        // They are read back decoded, so the tooltip escapes them again
        // before parsing them as markup: a task title is user text.
        const tipTitle = `[${b.taskId}] ${b.title}`.replace(/"/g, '&quot;');
        const assignee = b.assignee ? `Assignee: ${b.assignee}` : '';
        const est  = fmtMins(b.estimatedMinutes);
        const act  = fmtMins(b.actualMinutes);
        const sl   = statusLabel(b.status);
        const tipMeta = `${sl}${assignee ? ' · ' + assignee : ''} | Est: ${est} · Actual: ${act}`.replace(/"/g, '&quot;');

        svg += `<rect class="tl-bar" x="${bx.toFixed(1)}" y="${by}" width="${bw.toFixed(1)}" height="${BAR_H}"
          rx="4" ry="4" fill="${color}"
          data-title="${tipTitle}" data-meta="${tipMeta}"/>`;
      });

      // Dependency arrows — drawn after rows so they appear on top.
      // For each task with dependencies, draw a path from dep's bar end to this task's bar start.
      bars.forEach((b, i) => {
        if (!b.dependsOn || !b.dependsOn.length) return;
        const y2 = PAD_TOP + i * ROW_H + ROW_H / 2; // mid of current bar row
        const x2 = tsToX(b.start); // start of current bar

        b.dependsOn.forEach(depId => {
          const depIdx = idxMap[depId];
          if (depIdx === undefined) return;
          const dep = bars[depIdx];
          const y1 = PAD_TOP + depIdx * ROW_H + ROW_H / 2; // mid of dep row
          const x1 = tsToX(dep.end); // end of dep bar

          // Cubic bezier: exit right from dep end, enter left of current start.
          const cx1 = x1 + Math.abs(x2 - x1) * 0.4 + 10;
          const cx2 = x2 - Math.abs(x2 - x1) * 0.4 - 10;
          svg += `<path class="tl-dep-arrow" d="M${x1.toFixed(1)},${y1.toFixed(1)} C${cx1.toFixed(1)},${y1.toFixed(1)} ${cx2.toFixed(1)},${y2.toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}"/>`;
        });
      });

      // 'Now' cursor.
      const nowX = tsToX(nowStr);
      if (nowX >= PAD_LEFT && nowX <= PAD_LEFT + CHART_W) {
        svg += `<line x1="${nowX.toFixed(1)}" y1="${PAD_TOP - 2}" x2="${nowX.toFixed(1)}" y2="${SVG_H - 10}" class="tl-now-line"/>`;
        svg += `<text x="${nowX.toFixed(1)}" y="${PAD_TOP - 12}" font-size="10" fill="#f87171" text-anchor="middle">now</text>`;
      }

      svg += '</svg>';

      chartWrap.innerHTML = svg;

      // Attach tooltip handlers to bars.
      const tip = document.getElementById('tlTooltip');
      chartWrap.querySelectorAll('.tl-bar').forEach(bar => {
        bar.addEventListener('mouseenter', () => {
          tip.innerHTML = '<strong>' + esc(bar.dataset.title) + '</strong><div class="tl-tip-row">' + esc(bar.dataset.meta) + '</div>';
          tip.style.display = 'block';
        });
        bar.addEventListener('mousemove', (e) => {
          const x = e.clientX + 14;
          const y = e.clientY - 10;
          const tw = tip.offsetWidth;
          const ww = window.innerWidth;
          tip.style.left = (x + tw > ww ? e.clientX - tw - 14 : x) + 'px';
          tip.style.top  = y + 'px';
        });
        bar.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
      });

      if (statusEl) statusEl.textContent = bars.length + ' task' + (bars.length !== 1 ? 's' : '');
    }

    return h.mount({open: load, load}, 'timeline', `
    <div class="timeline-toolbar">
      <span class="section-title" style="margin:0">Gantt Chart</span>
      <button class="btn" style="padding:3px 10px;font-size:11px" data-act="load">Refresh</button>
      <span id="timelineStatus" style="font-size:11px;color:var(--muted)"></span>
    </div>
    <div id="timelineEmpty" class="empty-state" style="display:none">
      <h3>No tasks yet</h3>
      <p>Run <code>cloop run --pm</code> to generate a task plan, then return here to see the Gantt chart.</p>
    </div>
    <div id="timelineChart" class="timeline-chart-wrap">
      <div style="color:var(--muted);font-size:12px;padding:20px 0">Loading timeline...</div>
    </div>
    <div class="timeline-legend" id="timelineLegend" style="display:none">
      <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#22c55e"></div>Done</div>
      <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#3b82f6"></div>In Progress</div>
      <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#9ca3af"></div>Pending</div>
      <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#ef4444"></div>Failed</div>
      <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#f97316"></div>Timed Out</div>
      <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#6b7280"></div>Skipped</div>
      <div class="tl-legend-item"><div class="tl-legend-dot" style="background:#f87171;width:2px;height:14px;border-radius:1px"></div>Now</div>
    </div>
    <!-- Tooltip -->
    <div id="tlTooltip" class="tl-tooltip"></div>
    `);
  };
})();
