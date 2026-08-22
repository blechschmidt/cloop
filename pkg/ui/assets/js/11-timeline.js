// ── Timeline (Gantt) tab ─────────────────────────────────────────────────────

window.loadTimeline = function() { loadTimeline(); };

function loadTimeline() {
  api(pUrl('/api/timeline')).then(data => {
    renderTimeline(data);
  }).catch(() => {
    document.getElementById('timelineStatus').textContent = 'Failed to load timeline.';
  });
}

function renderTimeline(data) {
  // Apply filter bar: restrict to matching task IDs.
  let bars = data.bars || [];
  if (_filterActive() && appState && appState.plan && appState.plan.tasks) {
    const filteredIds = new Set(applyFilters(appState.plan.tasks).map(t => t.id));
    bars = bars.filter(b => filteredIds.has(b.taskId));
    updateFilterBadge(bars.length, (data.bars||[]).length);
  } else {
    updateFilterBadge((data.bars||[]).length, (data.bars||[]).length);
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
      tip.innerHTML = `<strong>${bar.dataset.title}</strong><div class="tl-tip-row">${bar.dataset.meta}</div>`;
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

// ── Actions ─────────────────────────────────────────────────────────────────

window.refreshState = function() {
  api(pUrl('/api/state')).then(s => { render(s); toast('Refreshed', 'ok'); }).catch(() => toast('Load failed', 'err'));
};

// updateRunButtonState shows the Run button when not running, Stop when running.
function updateRunButtonState(running) {
  const showIds = running ? ['ctrlStop'] : ['ctrlRun'];
  const hideIds = running ? ['ctrlRun'] : ['ctrlStop'];
  showIds.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = ''; });
  hideIds.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; });
}

// Run-state changes are pushed by the server as 'run_state' WebSocket events
// (see handleRealtimeMsg). No polling required.

// apiRun starts a run. All run options are read by the server from persisted
// project state — toggle them via the Active Options badges or Provider card.
window.apiRun = function() {
  api(pUrl('/api/run'), {}).then(d => {
    if (d.ok) {
      toast('Started: '+d.command, 'ok');
      updateRunButtonState(true);
    } else {
      toast(d.error||'Failed to start', 'err');
    }
  }).catch(() => toast('Request failed', 'err'));
};

window.apiStop = function() {
  // pUrl scopes the stop to the selected project (?project_idx=N) — without
  // it the server falls back to its own WorkDir, so pressing Stop on any
  // other project's page could never find that project's run (Task 20153).
  api(pUrl('/api/stop'), {}).then(d => {
    toast(d.message || (d.ok ? 'Pause signal sent' : 'Stop failed'), d.ok ? 'ok' : 'err');
    if (d.ok) updateRunButtonState(false);
    // Final running flag is pushed via the 'run_state' WS event when the
    // child process actually exits or the projects watcher samples PID
    // liveness; no client-side poll required.
  }).catch(() => toast('Request failed', 'err'));
};

// ── Init ─────────────────────────────────────────────────────────────────────

window.submitInit = function() {
  const goal = document.getElementById('initGoal').value.trim();
  if (!goal) { toast('Goal is required', 'err'); return; }
  api(pUrl('/api/init'), {
    goal:         goal,
    provider:     document.getElementById('initProvider').value,
    model:        document.getElementById('initModel').value,
    effort:       (document.getElementById('initEffort') || {}).value || '',
    maxSteps:     parseInt(document.getElementById('initMaxSteps').value)||0,
    instructions: document.getElementById('initInstructions').value.trim(),
    pmMode:       document.getElementById('initPMMode').checked,
  }).then(d => {
    if (d.ok) { toast('Project initialized!', 'ok'); refreshState(); }
    else toast(d.error||'Init failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

