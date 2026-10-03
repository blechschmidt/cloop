// ── Firewall rule sets (Task 20363) ─────────────────────────────────────────
//
// Two stored levels of the IP-layer egress firewall, each a rule set in the
// form the virtual-executor dialog already uses — allowlist, denylist, the
// public-Internet switch, ports, resolvers:
//
//   a device's, set by an admin from its card in the Executors tab: the most
//   any sandbox on it may reach, its virtual executors' included;
//   a project's, set by its maintainers on the Overview page beside the rules
//   that govern it, and only ever a narrowing of them.
//
// The hub checks every save against the levels above it and answers a
// widening with 409 and one reason per thing outside, which is shown on the
// form. A device saved narrower narrows what was saved under it, and says so.
//
// _fwForm, _fwRead and fwSync are shared by both: one form, one reading of it,
// one sentence for what it lets through. The IDs are a fixed prefix plus a
// field name, so nothing user-typed reaches an attribute.

// _fwSum renders a rule set as the clause after "In effect:". null is no
// firewall at all.
function _fwSum(r) {
  if (!r) return 'unfiltered';
  const to = [], dns = r.resolvers || [], ports = r.allow_ports || [], deny = r.deny_cidrs || [];
  if (r.allow_public_internet) to.push('the public Internet');
  if ((r.allow_cidrs || []).length) to.push(r.allow_cidrs.join(', '));
  if (!to.length && !dns.length) return 'no network: nothing is reachable';
  let s = to.length ? 'TCP to ' + to.join(' and ') + ' on '
    + (ports.length ? 'port' + (ports.length > 1 ? 's ' : ' ') + ports.join(', ') : 'any port') : 'DNS only';
  if (dns.length) s += (to.length ? '; DNS via ' : ', via ') + dns.join(', ');
  if (deny.length) s += '; never ' + deny.join(', ');
  return s;
}

// _fwForm renders the five fields under prefix p, filled from r.
function _fwForm(p, r) {
  r = r || {};
  const ev = ' oninput="fwSync(\'' + p + '\')"';
  const field = (k, label, v, hint, rows) => '<div class="form-group"><label class="form-label">' + label + '</label>'
    + (rows ? '<textarea class="form-input" rows="' + rows + '" id="' + p + k + '"' + ev + '>' + esc(v) + '</textarea>'
      : '<input class="form-input" id="' + p + k + '" value="' + esc(v) + '"' + ev + '>')
    + '<div class="form-hint">' + hint + '</div></div>';
  return '<label class="sec-own-opt"><input type="checkbox" id="' + p + 'Pub"' + (r.allow_public_internet ? ' checked' : '')
    + ' onchange="fwSync(\'' + p + '\')"><span><strong>Allow the public Internet</strong> — every public address; '
    + 'private, link-local and metadata ranges stay closed unless the allowlist names them.</span></label>'
    + '<div class="form-row">' + field('Allow', 'Allowlist', (r.allow_cidrs || []).join('\n'), 'Also reachable.', 2)
    + field('Deny', 'Denylist', (r.deny_cidrs || []).join('\n'), 'Never reachable, over any protocol.', 2) + '</div>'
    + '<div class="form-row">' + field('Ports', 'Ports', (r.allow_ports || []).join(', '), 'TCP ports; empty means every port.')
    + field('Dns', 'DNS resolvers', (r.resolvers || []).join(', '), 'Reachable on UDP and TCP.') + '</div>'
    + '<div class="evx-sum" id="' + p + 'Sum"></div>';
}

// _fwRead reads the form under prefix p into a PUT body.
function _fwRead(p) {
  const list = k => ((document.getElementById(p + k) || {}).value || '').split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
  return {
    allow_public_internet: !!(document.getElementById(p + 'Pub') || {}).checked,
    allow_cidrs: list('Allow'), deny_cidrs: list('Deny'),
    allow_ports: list('Ports').map(Number), resolvers: list('Dns'),
  };
}

window.fwSync = function(p) {
  const s = document.getElementById(p + 'Sum');
  if (s) s.textContent = 'In effect: ' + _fwSum(_fwRead(p)) + '. Everything else is dropped.';
};

// _fwRefusal renders a refused save: the hub's sentence, or its reasons.
function _fwRefusal(d) {
  const why = (d && d.reasons && d.reasons.length) ? d.reasons : [(d && d.error) || 'Save failed'];
  return '<div class="form-hint" style="color:var(--red)">' + why.map(esc).join('<br>') + '</div>';
}

// ── A device's rule set ─────────────────────────────────────────────────────

// efwTarget is the executor the dialog edits, held by ID for the reason
// execLimitsTarget is: the list may reorder while the dialog is open.
let efwTarget = null;

window.openExecutorFirewall = function(idx) {
  const ex = _execAt(idx);
  if (!ex) return;
  efwTarget = {id: ex.id, name: ex.name || ex.id};
  document.getElementById('efwBody').innerHTML = '<div class="form-hint">Loading…</div>';
  openOverlay('executor-firewall-overlay', {dismiss: closeExecutorFirewall});
  api('/api/executors/' + encodeURIComponent(ex.id) + '/firewall')
    .then(d => _efwRender(d, ''))
    .catch(e => _efwRender({error: _execDetailErrText(e)}, ''));
};

window.closeExecutorFirewall = function() {
  closeOverlay('executor-firewall-overlay');
  efwTarget = null;
};

function _efwRender(d, note) {
  const body = document.getElementById('efwBody');
  if (!body || !efwTarget) return;
  if (!d || d.error) { body.innerHTML = _fwRefusal(d); return; }
  efwTarget.configured = d.configured;
  let h = '<div class="form-hint">The most any sandbox on ' + esc(efwTarget.name) + ' may reach. Its virtual '
    + 'executors’ firewalls and its projects’ rules can only narrow this. '
    + (d.configured ? 'Set by ' + esc(d.set_by || 'an admin') + '.' : '<b>No rule set: nothing here bounds it.</b>') + '</div>';
  if (d.config) h += '<div class="form-hint">Its configuration file allows at most: ' + esc(_fwSum(d.config)) + '.</div>';
  if (d.warning) h += '<div class="form-hint" style="color:var(--yellow)">&#9888; ' + esc(d.warning) + '</div>';
  h += note + '<div id="efwWarn"></div>';
  h += _fwForm('efw', d.configured ? d.rules : {allow_public_internet: true, allow_ports: [443], resolvers: ['1.1.1.1']});
  const kids = d.children || [];
  if (kids.length) {
    h += '<div class="form-hint">Bounded by it: ' + kids.map(c => esc(c.kind === 'virtual' ? (c.name || c.id) : c.id)
      + (c.fits ? '' : ' <b style="color:var(--red)" title="' + esc((c.reasons || []).join('; ')) + '">(exceeds it)</b>'))
      .join(', ') + '</div>';
  }
  h += '<div class="modal-footer">'
    + (d.configured ? '<button class="btn danger" onclick="clearExecutorFirewall()">Remove rules</button>' : '')
    + '<button class="btn" onclick="closeExecutorFirewall()">Close</button>'
    + '<button class="btn primary" onclick="saveExecutorFirewall()">Save</button></div>';
  body.innerHTML = h;
  fwSync('efw');
}

function _efwSave(payload) {
  const t = efwTarget;
  if (!t) return;
  apiMethod('PUT', '/api/executors/' + encodeURIComponent(t.id) + '/firewall', payload)
    .then(d => {
      if (!d || d.error) {
        const w = document.getElementById('efwWarn');
        if (w) w.innerHTML = _fwRefusal(d);
        return;
      }
      const n = d.constrained || [];
      _efwRender(d, n.length ? '<div class="form-hint" style="color:var(--yellow)">Narrowed to fit: '
        + n.map(c => '<b>' + esc(c.name || c.subject) + '</b> — ' + esc((c.notes || []).join('; '))).join('<br>')
        + '</div>' : '');
      toast(payload.clear ? 'Firewall removed from ' + t.name
        : 'Firewall saved for ' + t.name + (n.length ? ' · ' + n.length + ' rule set(s) narrowed' : ''), 'ok');
      loadExecutors();
    })
    .catch(e => toast(_execDetailErrText(e) || 'Save failed', 'err'));
}

window.saveExecutorFirewall = function() { _efwSave(_fwRead('efw')); };

window.clearExecutorFirewall = function() {
  if (efwTarget && confirm('Remove the firewall rule set on ' + efwTarget.name + '?\n\nIts sandboxes will be '
      + 'bounded only by their own firewalls and its configuration.')) {
    _efwSave({clear: true});
  }
};

// ── A project's rule set ────────────────────────────────────────────────────

// loadProjectFirewall renders the Overview card: the levels that govern this
// project, read-only, beside the rule set its maintainers may narrow them to.
// Hidden with no project in view, for a feature (it runs under its parent's
// rules, edited there), and for anyone the hub does not let edit it.
window.loadProjectFirewall = function() {
  const panel = document.getElementById('projectFirewallPanel');
  if (!panel) return Promise.resolve();
  if ((isMultiProject && selectedProjectIdx === null) || isFeatureSelected() || !can('config.write')) {
    panel.style.display = 'none';
    return Promise.resolve();
  }
  // The project the answer is for. A switch while the request is in flight
  // must not paint one project's rules under the next one's name — or let a
  // save write them there — so a late answer is dropped.
  const idx = selectedProjectIdx;
  // The hub answers a reader who may not change the project with
  // visible:false rather than a refusal, so this never draws an error toast —
  // the gate above can run before /api/me has said who is asking.
  return api(pUrl('/api/firewall')).then(d => {
    if (idx !== selectedProjectIdx) return;
    if (!d || d.error || !d.visible) { panel.style.display = 'none'; return; }
    // loadExecutors calls in on every fleet event. Redrawing a form someone is
    // typing into would throw their edit away, and with it the refusal of what
    // they last tried to save, so while they are at it only the read-only
    // parts move. A hidden card is being edited by nobody.
    const shown = panel.style.display !== 'none';
    panel.style.display = '';
    if (shown && pfwIdx === idx && _pfwEditing()) { _pfwRefresh(d); return; }
    pfwIdx = idx;
    _pfwRender(d, '');
  }).catch(() => { panel.style.display = 'none'; });
};

// pfwIdx is the project the card was rendered for; a save refuses to go
// anywhere else.
let pfwIdx = null;

// pfwShown is the form as last rendered, read back the way a save reads it;
// null before the first render.
let pfwShown = null;

function _pfwReading() { return JSON.stringify(_fwRead('pfw')); }

// _pfwEditing says whether the form holds something its last render did not
// put there, or the caret.
function _pfwEditing() {
  if (pfwShown === null) return false;
  const body = document.getElementById('projectFirewallBody'), a = document.activeElement;
  if (body && a && a !== body && /^(INPUT|TEXTAREA)$/.test(a.tagName || '') && body.contains(a)) return true;
  return _pfwReading() !== pfwShown;
}

// _pfwGoverning is the card's read-only half: the levels above the project.
function _pfwGoverning(d) {
  let h = '<div class="form-label">Governing rules</div>';
  h += (d.levels || []).length ? d.levels.map(l => '<div class="form-hint"><b>' + esc(l.name) + '</b>: '
    + esc(_fwSum(l.rules)) + '</div>').join('')
    : '<div class="form-hint">Nothing bounds this project’s executor' + (d.executor_id ? ' (' + esc(d.executor_id) + ')' : '') + '.</div>';
  if (d.governing) h += '<div class="form-hint">Together: <b>' + esc(_fwSum(d.governing)) + '</b>.</div>';
  return h;
}

// _pfwState says whose the project's rules are and whether they still fit.
function _pfwState(d) {
  let h = '<div class="form-label">This project’s rules</div><div class="form-hint">'
    + (d.configured ? 'Set by ' + esc(d.set_by || 'a maintainer') + '. ' : 'None: runs get the governing rules. ')
    + 'May only narrow the rules beside it.</div>';
  if (!d.fits) h += '<div class="form-hint" style="color:var(--red)">These reach further than the governing rules, '
    + 'so runs are refused: ' + esc((d.reasons || []).join('; ')) + '</div>';
  if (d.warning) h += '<div class="form-hint" style="color:var(--yellow)">&#9888; ' + esc(d.warning) + '</div>';
  return h;
}

function _pfwRender(d, note) {
  const body = document.getElementById('projectFirewallBody');
  if (!body) return;
  body.innerHTML = '<div class="form-row"><div id="pfwGov" style="flex:1;min-width:220px">' + _pfwGoverning(d) + '</div>'
    + '<div style="flex:2;min-width:280px"><div id="pfwState">' + _pfwState(d) + '</div>'
    + note + '<div id="pfwWarn"></div>' + _fwForm('pfw', d.configured ? d.rules : (d.governing || {}))
    + '<div class="modal-footer">'
    + (d.configured ? '<button class="btn danger" onclick="clearProjectFirewall()">Remove rules</button>' : '')
    + '<button class="btn primary" onclick="saveProjectFirewall()">Save rules</button></div></div></div>';
  fwSync('pfw');
  pfwShown = _pfwReading();
}

// _pfwRefresh brings a card being edited up to date around its form.
function _pfwRefresh(d) {
  const gov = document.getElementById('pfwGov'), st = document.getElementById('pfwState');
  if (gov) gov.innerHTML = _pfwGoverning(d);
  if (st) st.innerHTML = _pfwState(d);
}

function _pfwSave(payload) {
  if (pfwIdx !== selectedProjectIdx) { loadProjectFirewall(); return; }
  apiMethod('PUT', pUrl('/api/firewall'), payload)
    .then(d => {
      if (!d || d.error) {
        const w = document.getElementById('pfwWarn');
        if (w) w.innerHTML = _fwRefusal(d);
        return;
      }
      _pfwRender(d, '');
      toast(payload.clear ? 'Project firewall removed' : 'Project firewall saved', 'ok');
    })
    .catch(e => toast(_execDetailErrText(e) || 'Save failed', 'err'));
}

window.saveProjectFirewall = function() { _pfwSave(_fwRead('pfw')); };

window.clearProjectFirewall = function() {
  if (confirm('Remove this project’s firewall rules?\n\nIts runs will get the governing rules.')) _pfwSave({clear: true});
};
