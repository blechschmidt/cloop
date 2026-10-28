// ── Risk Matrix tab ───────────────────────────────────────────────────────────
//
// The plan's pending tasks on a risk/impact grid from their cached scores, as a
// canvas quadrant and a table. Fetched on the tab's first open since Task
// 20456, markup included; it was 10-risk-matrix.js.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory. open() reads the scores
// afresh on every visit.
(function () {
  'use strict';

  window.cloopRiskMatrixPanel = function (h) {
    const {api, esc, pUrl} = h;

    function loadRiskMatrix() {
      const status  = document.getElementById('rmStatus');
      const empty   = document.getElementById('rmEmpty');
      const noTasks = document.getElementById('rmNoTasks');
      const wrap    = document.getElementById('rmChartWrap');
      const tbl     = document.getElementById('rmTable');
      const tbody   = document.getElementById('rmTableBody');
      if (status) status.textContent = 'Loading…';
      if (empty)   empty.style.display   = 'none';
      if (noTasks) noTasks.style.display = 'none';
      if (wrap)    wrap.style.display    = 'none';
      if (tbl)     tbl.style.display     = 'none';

      return api(pUrl('/api/risk-matrix')).then(data => {
        if (status) status.textContent = '';
        const entries = data.entries || [];

        if (entries.length === 0) {
          if (noTasks) noTasks.style.display = 'flex';
          return;
        }

        // Check if any task has cached scores.
        const hasScores = entries.some(e => e.risk_score > 0 && e.impact_score > 0);
        if (!hasScores) {
          if (empty) empty.style.display = 'flex';
          return;
        }

        // Draw canvas chart.
        if (wrap) wrap.style.display = 'block';
        renderRiskMatrixCanvas(entries);

        // Populate table.
        if (tbl) tbl.style.display = 'block';
        if (tbody) {
          const qColors = { Critical:'#ef4444', Mitigate:'#f97316', Leverage:'#22c55e', Defer:'#9ca3af' };
          const td = 'padding:5px 10px;border-bottom:1px solid var(--border)';
          tbody.innerHTML = entries.filter(function(e){ return e.risk_score > 0; }).map(function(e) {
            const col = qColors[e.quadrant] || '#9ca3af';
            const title = e.task_title.length > 60 ? e.task_title.slice(0,57) + '\u2026' : e.task_title;
            return '<tr>' +
              '<td style="'+td+'">#'+e.task_id+'</td>' +
              '<td style="'+td+'">'+esc(title)+'</td>' +
              '<td style="'+td+';text-align:center">'+e.risk_score+'/10</td>' +
              '<td style="'+td+';text-align:center">'+e.impact_score+'/10</td>' +
              '<td style="'+td+';color:'+col+';font-weight:500">'+(e.quadrant||'\u2014')+'</td>' +
              '</tr>';
          }).join('');
        }
      }).catch(() => {
        if (status) status.textContent = 'Failed to load';
      });
    }

    function renderRiskMatrixCanvas(entries) {
      const canvas = document.getElementById('rmCanvas');
      if (!canvas) return;

      const dpr = window.devicePixelRatio || 1;
      const W = Math.min(640, window.innerWidth - 40);
      const H = Math.round(W * 0.75);
      canvas.width  = W * dpr;
      canvas.height = H * dpr;
      canvas.style.width  = W + 'px';
      canvas.style.height = H + 'px';

      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);

      const PAD = { top: 28, right: 16, bottom: 44, left: 44 };
      const pw = W - PAD.left - PAD.right;
      const ph = H - PAD.top  - PAD.bottom;
      const MID_X = PAD.left + pw * 0.5;
      const MID_Y = PAD.top  + ph * 0.5;

      // Detect theme.
      const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
      const textCol = isDark ? '#94a3b8' : '#64748b';
      const borderCol = isDark ? '#334155' : '#cbd5e1';

      // Quadrant backgrounds.
      const quads = [
        { x: PAD.left, y: PAD.top,  w: MID_X-PAD.left, h: MID_Y-PAD.top,   color:'rgba(249,115,22,0.10)', label:'MITIGATE', lx: PAD.left+6,  ly: PAD.top+14  },
        { x: MID_X,    y: PAD.top,  w: PAD.left+pw-MID_X, h: MID_Y-PAD.top, color:'rgba(239,68,68,0.14)',  label:'CRITICAL', lx: MID_X+6,     ly: PAD.top+14  },
        { x: PAD.left, y: MID_Y,    w: MID_X-PAD.left, h: PAD.top+ph-MID_Y, color:'rgba(107,114,128,0.08)',label:'DEFER',    lx: PAD.left+6,  ly: MID_Y+14    },
        { x: MID_X,    y: MID_Y,    w: PAD.left+pw-MID_X, h: PAD.top+ph-MID_Y,color:'rgba(34,197,94,0.10)',label:'LEVERAGE', lx: MID_X+6,     ly: MID_Y+14    },
      ];
      for (const q of quads) {
        ctx.fillStyle = q.color;
        ctx.fillRect(q.x, q.y, q.w, q.h);
        ctx.fillStyle = isDark ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.2)';
        ctx.font = 'bold 10px system-ui';
        ctx.fillText(q.label, q.lx, q.ly);
      }

      // Axes.
      ctx.strokeStyle = borderCol;
      ctx.lineWidth = 1;
      ctx.strokeRect(PAD.left, PAD.top, pw, ph);
      ctx.setLineDash([4,4]);
      ctx.beginPath(); ctx.moveTo(MID_X, PAD.top); ctx.lineTo(MID_X, PAD.top+ph); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(PAD.left, MID_Y); ctx.lineTo(PAD.left+pw, MID_Y); ctx.stroke();
      ctx.setLineDash([]);

      // Axis ticks.
      ctx.fillStyle = textCol;
      ctx.font = '10px system-ui';
      for (let v = 1; v <= 10; v++) {
        const x = PAD.left + (v-1)/9 * pw;
        ctx.fillText(v, x - (v >= 10 ? 5 : 3), PAD.top + ph + 14);
      }
      for (let v = 1; v <= 10; v++) {
        const y = PAD.top + ph - (v-1)/9 * ph;
        ctx.fillText(v, PAD.left - (v >= 10 ? 20 : 14), y + 4);
      }

      // Axis labels.
      ctx.fillStyle = isDark ? '#cbd5e1' : '#475569';
      ctx.font = '11px system-ui';
      ctx.fillText('Impact \u2192', PAD.left + pw/2 - 20, H - 4);
      ctx.save();
      ctx.translate(12, PAD.top + ph/2 + 24);
      ctx.rotate(-Math.PI/2);
      ctx.fillText('Risk \u2192', 0, 0);
      ctx.restore();

      // Plot points.
      const dotColors = { Critical:'#ef4444', Mitigate:'#f97316', Leverage:'#22c55e', Defer:'#9ca3af' };
      const placed = [];
      for (const e of entries) {
        if (!e.risk_score || !e.impact_score) continue;
        let x = PAD.left + (e.impact_score-1)/9 * pw;
        let y = PAD.top  + ph - (e.risk_score-1)/9 * ph;
        // Nudge overlapping labels.
        let tries = 0;
        while (placed.some(p => Math.abs(p.x-x) < 20 && Math.abs(p.y-y) < 14) && tries < 8) {
          x += 16; tries++;
        }
        placed.push({x, y});
        const col = dotColors[e.quadrant] || '#94a3b8';
        ctx.fillStyle = col;
        ctx.beginPath();
        ctx.arc(x, y, 5, 0, 2*Math.PI);
        ctx.fill();
        ctx.fillStyle = col;
        ctx.font = 'bold 10px system-ui';
        ctx.fillText('#' + e.task_id, x + 7, y + 4);
      }
    }

    return h.mount({open: loadRiskMatrix, load: loadRiskMatrix}, 'risk-matrix', `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap">
      <span class="section-title" style="margin:0">Risk Matrix</span>
      <button class="btn" style="padding:3px 10px;font-size:11px" data-act="load">Refresh</button>
      <span id="rmStatus" style="font-size:11px;color:var(--muted)"></span>
    </div>
    <div id="rmEmpty" class="empty-state" style="display:none">
      <h3>No cached scores</h3>
      <p>Run <code>cloop task ai-risk-matrix --apply</code> to score and cache risk/impact data, then refresh.</p>
    </div>
    <div id="rmNoTasks" class="empty-state" style="display:none">
      <h3>No active tasks</h3>
      <p>All tasks are complete or no plan has been created yet.</p>
    </div>
    <div id="rmChartWrap" style="display:none">
      <canvas id="rmCanvas" style="border-radius:8px;display:block;max-width:100%"></canvas>
      <div style="display:flex;gap:14px;margin-top:10px;flex-wrap:wrap" id="rmLegend">
        <div style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted)"><div style="width:12px;height:12px;border-radius:3px;background:rgba(239,68,68,0.25);border:1px solid #ef4444"></div>Critical</div>
        <div style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted)"><div style="width:12px;height:12px;border-radius:3px;background:rgba(249,115,22,0.25);border:1px solid #f97316"></div>Mitigate</div>
        <div style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted)"><div style="width:12px;height:12px;border-radius:3px;background:rgba(34,197,94,0.25);border:1px solid #22c55e"></div>Leverage</div>
        <div style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted)"><div style="width:12px;height:12px;border-radius:3px;background:rgba(107,114,128,0.25);border:1px solid #6b7280"></div>Defer</div>
      </div>
      <p style="font-size:11px;color:var(--muted);margin-top:8px">Tip: Run <code>cloop task ai-risk-matrix --apply</code> to refresh scores.</p>
    </div>
    <div id="rmTable" class="table-scroll" style="display:none;margin-top:18px;overflow-x:auto">
      <table style="border-collapse:collapse;width:100%;font-size:13px">
        <thead>
          <tr>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">#</th>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">Task</th>
            <th style="text-align:center;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">Risk</th>
            <th style="text-align:center;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">Impact</th>
            <th style="text-align:left;padding:6px 10px;background:var(--surface);color:var(--muted);font-weight:500">Quadrant</th>
          </tr>
        </thead>
        <tbody id="rmTableBody"></tbody>
      </table>
    </div>
    `);
  };
})();
