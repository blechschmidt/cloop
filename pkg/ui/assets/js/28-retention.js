// ── Disk & Retention panel (Task 20229) ─────────────────────────────────────
//
// Answers the question nothing in cloop could previously answer: where is this
// project's disk going, and is anything going to reclaim it.
//
// Two of the three numbers here are invisible to every other tool an operator
// has. `du` cannot see SQLite's freelist — the hub this was built on had a
// 2.3 GB state.db that was 87% dead pages — and nobody counts files in
// .cloop/plan-history until it is already 2 GB across four thousand of them.
// So the panel leads with the breakdown and the reclaimable estimate, then
// says what the janitor will do about it and when, because "87% reclaimable"
// means something very different depending on whether a pass runs tonight.
//
// Read-only by design. Changing retention means editing config, which the rest
// of this tab already does; a second way to write the same keys would be a
// second thing to keep in sync.

function _duFmtBytes(n) {
  if (n === null || n === undefined) return '—';
  const KB = 1024, MB = KB * 1024, GB = MB * 1024;
  if (n < KB) return n + ' B';
  if (n < MB) return (n / KB).toFixed(1) + ' KB';
  if (n < GB) return (n / MB).toFixed(1) + ' MB';
  return (n / GB).toFixed(2) + ' GB';
}

// _duFmtAgo renders an RFC3339 instant as a relative time. Past and future
// both occur here: last_run is behind us, next_due ahead.
function _duFmtAgo(iso) {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (isNaN(then)) return '—';
  const secs = Math.round((Date.now() - then) / 1000);
  const ahead = secs < 0;
  let n = Math.abs(secs), unit = 's';
  if (n >= 86400) { n = Math.round(n / 86400); unit = 'd'; }
  else if (n >= 3600) { n = Math.round(n / 3600); unit = 'h'; }
  else if (n >= 60) { n = Math.round(n / 60); unit = 'm'; }
  return ahead ? ('in ' + n + unit) : (n + unit + ' ago');
}

// _duAdvice is the one-line "what governs this" note per entry. The breakdown
// is only actionable if each row says which knob controls it.
const _duAdvice = {
  'plan-history': 'bounded by retention.keep_snapshots',
  'audit-archive': 'sealed audit exports — retention limits are off by default',
  'state.db': 'reclaimed by VACUUM; see the freelist figure',
  'state.db-wal': 'write-ahead log, folded into state.db at the next checkpoint',
  'tasks': 'task artifacts — bounded by cloop compact',
  'artifacts': 'live task output — bounded by cloop compact',
  'task-checkpoints': 'resume points — bounded by cloop compact',
};

window.loadDiskUsage = function() {
  return api(pUrl('/api/disk-usage'))
    .then(d => { _renderDiskUsage(d || {}); return d; })
    .catch(err => {
      const el = document.getElementById('diskUsageBody');
      if (el) {
        el.innerHTML = '<div class="empty-state"><p>Could not load disk usage: ' +
          escapeHtml(err && err.message ? err.message : String(err)) + '</p></div>';
      }
    });
};

function _renderDiskUsage(d) {
  const el = document.getElementById('diskUsageBody');
  if (!el) return;

  const entries = Array.isArray(d.entries) ? d.entries : [];
  const pol = d.policy || {};
  const total = d.total_bytes || 0;

  let html = '';

  // Headline: total, and the part of it that is not really data.
  html += '<div class="du-headline">';
  html += '<div class="du-stat"><div class="du-stat-val">' + _duFmtBytes(total) +
          '</div><div class="du-stat-label">.cloop total</div></div>';

  if (d.db_error) {
    html += '<div class="du-stat"><div class="du-stat-val">—</div>' +
            '<div class="du-stat-label">reclaimable (' + escapeHtml(d.db_error) + ')</div></div>';
  } else if (d.db_bytes) {
    const pct = Math.round((d.free_ratio || 0) * 100);
    const warn = d.free_ratio >= (pol.vacuum_free_ratio || 0.3);
    html += '<div class="du-stat"><div class="du-stat-val' + (warn ? ' du-warn' : '') + '">' +
            _duFmtBytes(d.reclaimable_bytes || 0) + '</div>' +
            '<div class="du-stat-label">reclaimable by VACUUM (' + pct + '% of state.db)</div></div>';
  }
  html += '</div>';

  // Per-entry breakdown, largest first (the server sorts it).
  if (!entries.length) {
    html += '<div class="empty-state"><p>Nothing in .cloop yet.</p></div>';
  } else {
    html += '<table class="audit-table du-table"><thead><tr>' +
            '<th>Entry</th><th class="du-num">Size</th><th class="du-num">Files</th><th>Retention</th>' +
            '</tr></thead><tbody>';
    for (const e of entries) {
      const share = total > 0 ? (e.bytes / total) * 100 : 0;
      html += '<tr>' +
        '<td><span class="du-bar" style="width:' + Math.max(2, Math.round(share)) + '%"></span>' +
        escapeHtml(e.name) + '</td>' +
        '<td class="du-num">' + _duFmtBytes(e.bytes) + '</td>' +
        '<td class="du-num">' + (e.is_dir ? e.files : '') + '</td>' +
        '<td class="du-note">' + escapeHtml(_duAdvice[e.name] || '') + '</td>' +
        '</tr>';
    }
    html += '</tbody></table>';
  }

  // What the janitor will do, and when.
  html += '<div class="du-policy">';
  if (!pol.enabled) {
    html += '<strong class="du-warn">Retention is disabled.</strong> Nothing reclaims this ' +
            'directory automatically — it grows until the disk fills. Remove ' +
            '<code>retention.enabled: false</code> from .cloop/config.yaml to re-enable it.';
  } else {
    html += '<strong>Retention is on.</strong> A pass runs every ' +
            (pol.interval_hours || 24) + 'h, keeping the newest ' +
            (pol.keep_snapshots || 0) + ' plan snapshots and vacuuming once the freelist ' +
            'passes ' + Math.round((pol.vacuum_free_ratio || 0.3) * 100) + '% of the database.';
    if (pol.archive_max_bytes || pol.archive_max_age_days) {
      html += ' Audit seals are capped at ' +
              (pol.archive_max_bytes ? _duFmtBytes(pol.archive_max_bytes) : 'no size limit') +
              (pol.archive_max_age_days ? ' / ' + pol.archive_max_age_days + ' days' : '') + '.';
    } else {
      html += ' Audit seals are kept indefinitely (each is the only copy of the rows it holds).';
    }
    html += '<br><span class="du-note">Last pass: ' + _duFmtAgo(d.last_run) +
            ' · Next due: ' + _duFmtAgo(d.next_due);
    if (d.will_vacuum) {
      html += ' · <strong>the next pass will VACUUM</strong>';
    }
    html += '</span>';
  }
  html += '</div>';

  el.innerHTML = html;
}
