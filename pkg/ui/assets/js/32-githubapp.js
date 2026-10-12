// GitHub App connection and per-project repository assignment (Task 20306).
//
// Two panels, because the feature has two audiences. An admin connects the App
// once on the Settings tab — that stores a signing key and is hub-wide. A
// project's maintainer then assigns repositories to their project from the
// Overview tab, choosing from the installation's own inventory rather than
// typing names. The Overview's is here; the Settings one is fetched with that
// tab (deferred/settings.js, Task 20386).
//
// The inventory is the whole point of asking GitHub rather than the operator.
// An installation ID lives in a settings URL; a repository list lives nowhere
// the operator can copy from; and both, typed by hand, are wrong in ways
// nothing notices until a clone 404s inside a sandbox.
//
// Every control here is an action of the dashboard's registry that runs only
// from inside this panel (see Wiring). Repository names and account logins are
// attacker-influenced strings (anyone who can name a repo can choose what is
// in it), and an onclick built by concatenation is how that becomes markup —
// see the recurring bug class in this dashboard's history.

const ghAppState = {
  apps: [],            // the Apps this project may be assigned repositories from
  assignments: [],     // this project's live grants
  repos: [],           // inventory of the app selected in the assign form
  reposFor: '',        // which app id `repos` belongs to
  gitProxy: null,      // can this hub enforce a branch restriction (Task 20340)
  editing: '',         // grant id whose access row is open for editing
};

// ---------------------------------------------------------------------------
// Project overview: assign repositories
// ---------------------------------------------------------------------------

// ghAppProjectIdx is the index these routes address. See loadProjectRepositories
// for why null means index 0 rather than "no project".
function ghAppProjectIdx() {
  return selectedProjectIdx === null ? 0 : selectedProjectIdx;
}

// loadProjectRepositories renders what this project may reach.
window.loadProjectRepositories = function() {
  const panel = document.getElementById('projectReposPanel');
  if (!panel) return Promise.resolve();
  // On a multi-project hub with nothing selected the Overview tab is the
  // fleet view, and "which repositories may this project reach" has no
  // subject — so the panel hides. On a single-project hub selectedProjectIdx
  // is null *because there is only one*, and index 0 is it. Conflating the
  // two hid the panel on exactly the common deployment.
  // A feature holds its project's grants (Task 20341); they are edited there.
  if ((isMultiProject && selectedProjectIdx === null) || isFeatureSelected()) {
    panel.style.display = 'none';
    return Promise.resolve();
  }
  panel.style.display = '';

  return apiMethod('GET', '/api/projects/' + ghAppProjectIdx() + '/repositories')
    .then(d => {
      if (!d || d.error) {
        // A hub with no secret store is the common case here, and it is not a
        // fault: say so quietly rather than painting an error.
        const body = document.getElementById('projectReposBody');
        if (body) body.innerHTML = '<div class="empty-state"><p>' +
          esc((d && d.error) || 'unavailable') + '</p></div>';
        return;
      }
      ghAppState.apps = d.apps || [];
      ghAppState.assignments = d.assignments || [];
      ghAppState.gitProxy = d.git_proxy || null;
      ghAppRenderAssignments();
    }).catch(() => {});
};

// Branch restrictions (Task 20340). Only the git proxy can enforce one, so the
// panel says what it amounts to on this hub. Rationale: githubapp_branches_test.go.

// ghAppBranchList splits on commas or whitespace; a branch name holds neither.
function ghAppBranchList(raw) {
  return String(raw || '').split(/[\s,]+/).filter(v => v !== '');
}

function ghAppBranchHint() {
  const gp = ghAppState.gitProxy || {};
  if (gp.running) {
    const refs = (gp.push_refs || []).map(r => r.replace(/^refs\/heads\//, ''));
    const all = refs.indexOf('**') >= 0 || (gp.push_refs || []).indexOf('refs/**') >= 0;
    return '&#128274; cloop\'s git proxy refuses a push to any other branch, outside the sandbox. ' +
      '<code>*</code> stays within one path segment; a trailing <code>/**</code> covers any depth. ' +
      'Leave empty to allow ' + (all ? 'every branch.' :
        'every branch this hub allows: ' + refs.map(r => '<code>' + esc(r) + '</code>').join(', ') +
        ' — a branch listed here must fall inside that too.');
  }
  if (gp.required) {
    return '<span style="color:var(--yellow)">&#9888; The git proxy is configured but not running, ' +
      'so no GitHub access is delivered from this hub until it is.</span>';
  }
  return '<span style="color:var(--yellow)">&#9888; This hub runs no git proxy, and nothing else can ' +
    'hold a push to particular branches. With branches set, a GitHub App grant is delivered ' +
    '<strong>read-only</strong> and a personal token not at all, until an admin enables ' +
    '<code>executors.git_proxy</code>.</span>';
}

function ghAppBranchCell(a) {
  if (a.access !== 'write') return '';
  const br = a.branches || [];
  let html = '<div style="font-size:11px;margin-top:4px">' + (br.length
    ? 'branches: ' + br.map(b => '<code>' + esc(b) + '</code>').join(' ')
    : '<span style="color:var(--muted)">any branch the hub allows</span>') + '</div>';
  const note = {
    proxy: ['ok', '&#128274; enforced by the git proxy'],
    read_only: ['warn', '&#9888; read-only here: no git proxy to enforce branches'],
    not_delivered: ['warn', '&#9888; not delivered: no git proxy to enforce branches'],
    unavailable: ['warn', '&#9888; not delivered: git proxy configured but down'],
  }[a.branch_enforcement];
  if (note) {
    html += '<div style="font-size:11px;margin-top:2px;color:var(--' +
      (note[0] === 'ok' ? 'green' : 'yellow') + ')">' + note[1] + '</div>';
  }
  return html;
}

// ghAppEditRow edits one assignment; saving replaces its grant (grants are immutable).
function ghAppEditRow(a) {
  const write = a.access === 'write';
  return '<tr class="gh-edit-row"><td colspan="5" style="background:var(--hover-bg)">' +
    '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
      '<select class="input gh-edit-access" data-action-change="ghEditAccess" style="max-width:150px">' +
        '<option value="read"' + (write ? '' : ' selected') + '>Read only</option>' +
        '<option value="write"' + (write ? ' selected' : '') + '>Read and write</option>' +
      '</select>' +
      '<input class="input gh-edit-branches" style="flex:1;min-width:200px' + (write ? '' : ';display:none') +
        '" placeholder="Push to branches — e.g. cloop/*, feature/**" value="' +
        esc((a.branches || []).join(', ')) + '">' +
      '<button class="btn btn-sm btn-primary" data-action="ghSave" data-arg="' + esc(a.grant_id) + '">Save</button>' +
      '<button class="btn btn-sm" data-action="ghCancel">Cancel</button>' +
    '</div>' +
    '<div class="gh-branch-hint" style="font-size:11px;color:var(--muted);margin-top:6px' +
      (write ? '' : ';display:none') + '">' + ghAppBranchHint() + '</div>' +
    '<div style="font-size:11px;color:var(--muted);margin-top:4px">Saving replaces the grant: ' +
      'a run in progress loses the old access at once and receives the new at its next lease.</div>' +
    '</td></tr>';
}

function ghAppRenderAssignments() {
  const body = document.getElementById('projectReposBody');
  if (!body) return;
  const rows = ghAppState.assignments;
  const canGrant = typeof can !== 'function' || can('secret.grant');

  let html = '';
  if (!rows.length) {
    html += '<div class="empty-state"><p>This project has no repository access. ' +
      (canGrant
        ? 'Assign some below — cloop can then clone and push to them without the token ever entering the sandbox.'
        : 'Ask a maintainer to assign some.') +
      '</p></div>';
  } else {
    html += '<table class="data-table" style="width:100%"><thead><tr>' +
      '<th>Repositories</th><th>Access</th><th>Via</th><th>Expires</th><th></th>' +
      '</tr></thead><tbody>' +
      rows.map(a => {
        const repos = (a.repos || []).map(r => '<code>' + esc(r) + '</code>').join(' ');
        const exp = a.expires_at && !a.expires_at.startsWith('0001-')
          ? esc(new Date(a.expires_at).toLocaleString()) : 'no expiry';
        const revoke = canGrant
          ? '<button class="btn btn-sm btn-danger" data-action="ghRevoke" data-arg="' + esc(a.grant_id) + '">Revoke</button>'
          : '';
        // A wildcard grant reaching this project is edited where it was made.
        const edit = canGrant && a.replaceable
          ? '<button class="btn btn-sm" data-action="ghEdit" data-arg="' + esc(a.grant_id) + '">Edit</button> '
          : '';
        return '<tr><td>' + repos + '</td>' +
          '<td><span class="badge ' + (a.access === 'write' ? 'running' : 'complete') +
            '" style="font-size:10px">' + esc(a.access) + '</span>' + ghAppBranchCell(a) + '</td>' +
          '<td>' + esc(a.secret_name) + ' <span style="font-size:10px;color:var(--muted)">' +
            esc(a.kind) + '</span></td>' +
          '<td style="font-size:11px">' + exp + '</td>' +
          '<td style="text-align:right;white-space:nowrap">' + edit + revoke + '</td></tr>' +
          (ghAppState.editing === a.grant_id ? ghAppEditRow(a) : '');
      }).join('') +
      '</tbody></table>';
  }

  if (canGrant) {
    const apps = ghAppState.apps;
    if (!apps.length) {
      html += '<div style="font-size:12px;color:var(--muted);margin-top:10px">' +
        'No GitHub App is available. Connect one under ' +
        '<strong>Settings → GitHub Apps</strong>.</div>';
    } else {
      html += '<div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border)">' +
        '<div style="font-weight:600;margin-bottom:8px">Assign repositories</div>' +
        '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
          '<select id="ghAssignApp" class="input" style="max-width:220px">' +
            apps.map(a => '<option value="' + esc(a.id) + '">' + esc(a.name) + '</option>').join('') +
          '</select>' +
          '<select id="ghAssignAccess" class="input" data-action-change="ghAccess" style="max-width:150px">' +
            '<option value="read">Read only</option>' +
            '<option value="write">Read and write</option>' +
          '</select>' +
          '<button class="btn btn-sm" data-action="ghLoad">List repositories</button>' +
        '</div>' +
        '<div id="ghAssignBranchGroup" style="display:none;margin-top:8px">' +
          '<input id="ghAssignBranches" class="input" style="width:100%" ' +
            'placeholder="Push to branches (optional) — e.g. cloop/*, feature/**">' +
          '<div class="gh-branch-hint" style="font-size:11px;color:var(--muted);margin-top:4px">' +
            ghAppBranchHint() + '</div>' +
        '</div>' +
        '<div id="ghAssignRepos" style="margin-top:10px"></div>' +
      '</div>';
    }
  }
  body.innerHTML = html;
}

// ghAppLoadRepos fetches the chosen App's inventory and renders it as a picker.
function ghAppLoadRepos() {
  const sel = document.getElementById('ghAssignApp');
  const out = document.getElementById('ghAssignRepos');
  if (!sel || !out) return;
  const secret = sel.value;
  out.innerHTML = '<div style="font-size:12px;color:var(--muted)">Asking GitHub…</div>';

  apiMethod('GET', '/api/projects/' + ghAppProjectIdx() +
    '/repositories/available?secret=' + encodeURIComponent(secret))
    .then(d => {
      if (!d || d.error) {
        out.innerHTML = '<div style="color:var(--danger);font-size:12px">' +
          esc((d && d.error) || 'could not list repositories') + '</div>';
        return;
      }
      ghAppState.repos = d.repositories || [];
      ghAppState.reposFor = secret;
      if (!ghAppState.repos.length) {
        out.innerHTML = '<div style="font-size:12px;color:var(--muted)">' +
          'This installation covers no repositories. Add some to the App installation on GitHub.' +
          '</div>';
        return;
      }
      out.innerHTML =
        '<div style="max-height:220px;overflow:auto;border:1px solid var(--border);' +
        'border-radius:6px;padding:8px">' +
        ghAppState.repos.map((r, i) =>
          '<label style="display:flex;align-items:center;gap:8px;padding:3px 0;font-size:13px">' +
            '<input type="checkbox" class="gh-repo-check" value="' + esc(r.full_name) + '">' +
            '<span>' + esc(r.full_name) + '</span>' +
            (r.private ? '<span class="badge unknown" style="font-size:9px">private</span>' : '') +
          '</label>').join('') +
        '</div>' +
        '<button class="btn btn-sm btn-primary" data-action="ghSubmit" style="margin-top:8px">' +
        'Grant access</button>';
    }).catch(e => {
      out.innerHTML = '<div style="color:var(--danger);font-size:12px">' +
        esc(String(e && e.message ? e.message : e)) + '</div>';
    });
}

function ghAppSubmitAssignment() {
  const sel = document.getElementById('ghAssignApp');
  const acc = document.getElementById('ghAssignAccess');
  if (!sel) return;
  const repos = Array.from(document.querySelectorAll('.gh-repo-check'))
    .filter(c => c.checked).map(c => c.value);
  if (!repos.length) { toast('Tick at least one repository', 'error'); return; }

  const access = (acc && acc.value) || 'read';
  const branches = access === 'write'
    ? ghAppBranchList((document.getElementById('ghAssignBranches') || {}).value) : [];
  apiMethod('POST', '/api/projects/' + ghAppProjectIdx() + '/repositories', {
    secret: sel.value,
    repos: repos,
    access: access,
    branches: branches,
  }).then(d => {
    if (!d || d.error) { toast((d && d.error) || 'could not assign', 'error'); return; }
    toast('Granted ' + repos.length + ' repositor' + (repos.length === 1 ? 'y' : 'ies'), 'success');
    loadProjectRepositories();
  }).catch(e => toast(String(e && e.message ? e.message : e), 'error'));
}

function ghAppSaveEdit(grantID, row) {
  const a = ghAppState.assignments.find(x => x.grant_id === grantID);
  if (!a || !row) return;
  const access = (row.querySelector('.gh-edit-access') || {}).value || a.access;
  const branches = access === 'write'
    ? ghAppBranchList((row.querySelector('.gh-edit-branches') || {}).value) : [];
  apiMethod('POST', '/api/projects/' + ghAppProjectIdx() + '/repositories', {
    secret: a.secret_id,
    repos: a.repos,
    access: access,
    branches: branches,
    replaces: grantID,
  }).then(d => {
    if (!d || d.error) { toast((d && d.error) || 'could not change access', 'error'); return; }
    ghAppState.editing = '';
    toast('Access updated', 'success');
    loadProjectRepositories();
  }).catch(e => toast(String(e && e.message ? e.message : e), 'error'));
}

// ghAppRevoke takes a grant away, once the user confirms which. A grant the
// panel is not showing is not revoked from here.
function ghAppRevoke(grantID) {
  const a = ghAppState.assignments.find(x => x.grant_id === grantID);
  if (!a || !confirm('Revoke this project\'s access to ' + (a.repos || []).join(', ') +
    '?\n\nA run in progress loses it at once.')) return;
  apiMethod('DELETE', '/api/projects/' + ghAppProjectIdx() +
    '/repositories?grant=' + encodeURIComponent(grantID))
    .then(d => {
      if (!d || d.error) { toast((d && d.error) || 'could not revoke', 'error'); return; }
      toast('Access revoked', 'success');
      loadProjectRepositories();
    }).catch(e => toast(String(e && e.message ? e.message : e), 'error'));
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

// Each control is an action of 00-core.js's registry, and runs only from
// inside this panel (Task 20422). The panel used to route its own data-gh-*
// attributes from one listener on the whole document, so an element carrying
// one anywhere on the page — markup injected into a task's output, say —
// revoked a repository grant when clicked.
const ghPanel = fn => function(ev) { if (this.closest('#projectReposPanel')) return fn.call(this, ev); };
ACTIONS.ghRevoke = ghPanel(function() { ghAppRevoke(this.dataset.arg); });
ACTIONS.ghLoad = ghPanel(ghAppLoadRepos);
ACTIONS.ghSubmit = ghPanel(ghAppSubmitAssignment);
ACTIONS.ghEdit = ghPanel(function() { ghAppState.editing = this.dataset.arg; ghAppRenderAssignments(); });
ACTIONS.ghCancel = ghPanel(function() { ghAppState.editing = ''; ghAppRenderAssignments(); });
ACTIONS.ghSave = ghPanel(function() { ghAppSaveEdit(this.dataset.arg, this.closest('tr')); });
// The access level shows or hides its branch field; change, so keyboards work too.
ACTIONS.ghAccess = ghPanel(function() {
  const g = document.getElementById('ghAssignBranchGroup');
  if (g) g.style.display = this.value === 'write' ? '' : 'none';
});
ACTIONS.ghEditAccess = ghPanel(function() {
  const row = this.closest('tr');
  ['.gh-edit-branches', '.gh-branch-hint'].forEach(q => {
    const el = row && row.querySelector(q);
    if (el) el.style.display = this.value === 'write' ? '' : 'none';
  });
});
