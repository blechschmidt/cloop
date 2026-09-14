// ── Running build (Task 20249) ───────────────────────────────────────────────
//
// Surfaces which build of cloop is actually serving this page, on three
// surfaces that answer three different versions of the same question:
//
//   * the footer chip — "what am I looking at right now", visible from every
//     tab without navigating anywhere;
//   * the Settings panel — the full provenance, for when the chip prompted a
//     real question;
//   * the stale banner — "the thing you are looking at is no longer what the
//     server is running", which is the case nobody can spot unaided.
//
// That last one is the reason this is not just a version string in a corner.
// The dashboard is a single-page app that people leave open for days, and the
// reference deployment rebuilds and restarts on a timer. A redeploy therefore
// lands while tabs are open, and those tabs keep running the *old* JavaScript
// against the *new* server indefinitely — which surfaces as phantom bugs that
// nobody can reproduce, because a reload silently fixes them.
//
// The check costs nothing and never polls. A restart necessarily drops every
// WebSocket, so reconnect is already the exact moment the server might have
// changed underneath us: 04-realtime.js calls refreshBuildInfo() from its
// onopen handler and we compare one fingerprint against the one we booted with.

// _buildBooted is the build_id the page was first served by, and _buildInfo the
// last full report. Both stay null until the first fetch answers.
let _buildBooted = null;
let _buildInfo = null;
// Latches once the banner is up: a flapping connection must not re-show a
// notice the user has already dismissed.
let _buildStaleShown = false;

// _buildFmtAge renders a duration the way an operator reads it — coarse and
// immediately comparable, not precise. "3 days" is the useful answer; the exact
// second is noise that makes the number harder to scan.
function _buildFmtAge(sec) {
  if (sec === null || sec === undefined) return null;
  const s = Math.max(0, Math.floor(sec));
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm';
  const h = Math.floor(m / 60);
  if (h < 48) return h + 'h';
  return Math.floor(h / 24) + 'd';
}

// _buildStalenessClass flags a build old enough to be worth a second look.
// The reference hub redeploys daily, so anything past ~36h means the deploy
// has probably been failing — the exact condition this panel exists to catch.
function _buildStalenessClass(ageSec) {
  if (ageSec === null || ageSec === undefined) return '';
  if (ageSec > 60 * 60 * 36) return 'build-warn';
  return '';
}

// _buildLabel renders the short identity used in the footer chip.
function _buildLabel(d) {
  if (!d) return '';
  return d.identified ? d.version : 'unidentified build';
}

// window.refreshBuildInfo fetches the current build and updates every surface.
// Returns the report so callers can chain; never rejects, because a dashboard
// that cannot reach this endpoint should lose a footer chip, not a tab.
window.refreshBuildInfo = function() {
  return api('/api/version').then(d => {
    if (!d || !d.build_id) return null;
    _buildInfo = d;
    if (_buildBooted === null) _buildBooted = d.build_id;
    _buildRenderChip(d);
    _buildRenderPanel(d);
    _buildCheckStale(d);
    return d;
  }).catch(() => null);
};

// window.loadBuildInfo is the Settings tab's entry point.
window.loadBuildInfo = function() { return window.refreshBuildInfo(); };

// _buildCheckStale compares the running build against the one that served this
// page and raises a persistent banner when they differ.
//
// Persistent rather than a toast: it is the one notice that stays true until
// acted on, and a 3-second toast is exactly what a user who stepped away misses.
function _buildCheckStale(d) {
  if (_buildStaleShown || _buildBooted === null || d.build_id === _buildBooted) return;
  const banner = document.getElementById('buildStaleBanner');
  if (!banner) return;
  const label = document.getElementById('buildStaleText');
  if (label) {
    label.textContent = d.identified
      ? 'cloop ' + d.version + ' is now running — this page is still on the previous build.'
      : 'A new build of cloop is now running — this page is still on the previous one.';
  }
  banner.style.display = 'flex';
  _buildStaleShown = true;
}

// window.reloadForNewBuild does a cache-busting reload. index.html is served
// no-cache so a plain reload already re-reads it, and every asset it names is
// content-hashed — the new shell therefore names new URLs and nothing stale can
// survive. location.reload() is enough; the explicit call documents why.
window.reloadForNewBuild = function() { location.reload(); };

// window.dismissBuildStale hides the banner without reloading, for someone
// mid-edit who does not want to lose a form. The banner does not come back for
// this page: having decided once, being asked again on every reconnect would
// be worse than not being told.
window.dismissBuildStale = function() {
  const banner = document.getElementById('buildStaleBanner');
  if (banner) banner.style.display = 'none';
};

// _buildRenderChip writes the compact footer identity.
function _buildRenderChip(d) {
  const el = document.getElementById('buildChip');
  if (!el) return;
  const age = _buildFmtAge(d.build_age_seconds);
  let text = 'cloop ' + _buildLabel(d);
  if (age) text += ' · ' + age;
  el.textContent = text;
  // toggle, not className assignment: the element carries `build-chip` from the
  // markup, which is what right-aligns it in the footer. Overwriting className
  // would silently drop that and leave the chip butted against the shortcut
  // hints.
  el.classList.toggle('build-warn', _buildStalenessClass(d.build_age_seconds) !== '');
  // The chip is deliberately terse; the tooltip carries the rest for a hover
  // that costs no layout.
  const parts = [];
  if (d.revision) parts.push('revision ' + d.revision.slice(0, 12) + (d.modified ? ' (modified)' : ''));
  if (d.built_at) parts.push((d.built_at_source === 'binary' ? 'binary written ' : 'committed ') + d.built_at);
  parts.push('up ' + (_buildFmtAge(d.uptime_seconds) || '0s'));
  parts.push(d.go + ' ' + d.os + '/' + d.arch);
  el.title = parts.join('\n');
}

// _buildRenderPanel draws the Settings section.
function _buildRenderPanel(d) {
  const el = document.getElementById('buildInfoBody');
  if (!el) return;

  const rows = [];
  rows.push(['Version', d.identified
    ? esc(d.version)
    : '<span class="build-warn">' + esc(d.version) + '</span> — unidentified']);

  if (d.revision) {
    rows.push(['Revision', '<code>' + esc(d.revision.slice(0, 12)) + '</code>' +
      (d.modified ? ' <span class="build-warn">+ uncommitted changes</span>' : '')]);
  }

  if (d.built_at) {
    const age = _buildFmtAge(d.build_age_seconds);
    // Label the timestamp with what it actually measures. An executable's
    // mtime is when the file was written, not when the code was compiled, and
    // presenting it as a build date would be a precise-looking fiction.
    const what = d.built_at_source === 'binary' ? 'Binary written' : 'Committed';
    rows.push([what, '<span class="' + _buildStalenessClass(d.build_age_seconds) + '">' +
      esc(d.built_at) + (age ? ' (' + esc(age) + ' ago)' : '') + '</span>']);
  }

  rows.push(['Started', esc(d.started_at) + ' (up ' + esc(_buildFmtAge(d.uptime_seconds) || '0s') + ')']);
  rows.push(['Toolchain', esc(d.go) + ' · ' + esc(d.os) + '/' + esc(d.arch)]);
  rows.push(['Executor protocol', 'v' + esc(d.protocol) + ' (accepts v' + esc(d.min_protocol) + ' and newer)']);
  rows.push(['Build ID', '<code>' + esc(d.build_id) + '</code>']);

  let html = '<table class="audit-table build-table"><tbody>';
  for (const [k, v] of rows) {
    html += '<tr><th>' + esc(k) + '</th><td>' + v + '</td></tr>';
  }
  html += '</tbody></table>';

  // The unidentified case needs more than a red word: it is a property of how
  // the binary was built, and the reader cannot act on it without knowing that.
  if (!d.identified) {
    html += '<div class="build-note"><strong>This build cannot identify itself.</strong> ' +
      'It carries neither a release stamp nor version-control metadata, so it reports the ' +
      'generic <code>dev</code> and is indistinguishable from any other unstamped build. ' +
      'Builds made outside a git checkout — from a <code>git archive</code> export, for ' +
      'instance — need <code>-ldflags "-X ' +
      'github.com/blechschmidt/cloop/pkg/version.Version=..."</code> to say what they are. ' +
      'Until then the timestamp above is the only evidence of how recent this deployment is.' +
      '</div>';
  }

  el.innerHTML = html;
}

// Boot: fetch once so the footer chip is populated and _buildBooted records the
// build that served this page, which every later comparison is made against.
document.addEventListener('DOMContentLoaded', () => { window.refreshBuildInfo(); });
