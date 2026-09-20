// GitHub App connection and per-project repository assignment (Task 20306).
//
// Two panels, because the feature has two audiences. An admin connects the App
// once on the Settings tab — that stores a signing key and is hub-wide. A
// project's maintainer then assigns repositories to their project from the
// Overview tab, choosing from the installation's own inventory rather than
// typing names.
//
// The inventory is the whole point of asking GitHub rather than the operator.
// An installation ID lives in a settings URL; a repository list lives nowhere
// the operator can copy from; and both, typed by hand, are wrong in ways
// nothing notices until a clone 404s inside a sandbox.
//
// Every listener here is attached rather than inlined. Repository names and
// account logins are attacker-influenced strings (anyone who can name a repo
// can choose what is in it), and an onclick built by concatenation is how that
// becomes markup — see the recurring bug class in this dashboard's history.

const ghAppState = {
  installations: [],   // discovered, awaiting a choice
  connectKey: '',      // the pasted PEM, held only until the secret is minted
  connectAppID: '',
  connectBaseURL: '',
  apps: [],            // stored github_app secrets
  assignments: [],     // this project's live grants
  repos: [],           // inventory of the app selected in the assign form
  reposFor: '',        // which app id `repos` belongs to
};

// ---------------------------------------------------------------------------
// Settings: connect an App
// ---------------------------------------------------------------------------

// ghAppDiscover asks the hub where the pasted App is installed.
//
// Nothing is stored by this call. The key stays in ghAppState until the
// operator picks an installation and the secret is minted, and is dropped
// immediately afterwards.
window.ghAppDiscover = function() {
  const appID = (document.getElementById('ghAppId') || {}).value || '';
  const key = (document.getElementById('ghAppKey') || {}).value || '';
  const baseURL = (document.getElementById('ghAppBaseUrl') || {}).value || '';
  if (!appID.trim() || !key.trim()) {
    toast('App ID and private key are both required', 'error');
    return;
  }
  const out = document.getElementById('ghAppInstallations');
  if (out) out.innerHTML = '<div class="empty-state"><p>Asking GitHub…</p></div>';

  api('/api/github-app/installations', {
    app_id: appID.trim(),
    private_key: key,
    base_url: baseURL.trim(),
  }).then(d => {
    if (!d || d.error) {
      if (out) out.innerHTML = '<div style="color:var(--danger);font-size:12px">' +
        esc((d && d.error) || 'discovery failed') + '</div>';
      return;
    }
    ghAppState.installations = d.installations || [];
    ghAppState.connectKey = key;
    ghAppState.connectAppID = appID.trim();
    ghAppState.connectBaseURL = baseURL.trim();
    ghAppRenderInstallations();
  }).catch(e => {
    if (out) out.innerHTML = '<div style="color:var(--danger);font-size:12px">' +
      esc(String(e && e.message ? e.message : e)) + '</div>';
  });
};

function ghAppRenderInstallations() {
  const out = document.getElementById('ghAppInstallations');
  if (!out) return;
  const list = ghAppState.installations;
  if (!list.length) {
    out.innerHTML = '<div class="empty-state"><p>This App is not installed anywhere yet.</p></div>';
    return;
  }
  // "all" vs "selected" is worth showing: an operator who cannot reach a
  // repository needs to know whether to widen the installation or tick a box.
  out.innerHTML =
    '<div style="font-size:12px;color:var(--muted);margin-bottom:6px">' +
    'Choose the account whose repositories cloop should reach:</div>' +
    list.map(i =>
      '<div class="gh-install-row" style="display:flex;align-items:center;gap:10px;padding:6px 0">' +
        '<button class="btn btn-sm" data-gh-install="' + esc(String(i.id)) + '">Use</button>' +
        '<div><strong>' + esc(i.account) + '</strong> ' +
          '<span class="badge unknown" style="font-size:10px">' + esc(i.account_type) + '</span> ' +
          '<span style="font-size:11px;color:var(--muted)">installation ' + esc(String(i.id)) +
          ', covers ' + esc(i.repository_selection) + ' repositories</span>' +
        '</div>' +
      '</div>').join('');
}

// ghAppSaveInstallation mints the github_app secret for a chosen installation.
function ghAppSaveInstallation(installationID) {
  const chosen = ghAppState.installations.find(i => String(i.id) === String(installationID));
  if (!chosen) return;
  const nameField = document.getElementById('ghAppName');
  const name = (nameField && nameField.value.trim()) ||
    ('github-' + String(chosen.account || 'app').toLowerCase().replace(/[^a-z0-9-]+/g, '-'));

  const payload = {
    app_id: Number(ghAppState.connectAppID),
    installation_id: chosen.id,
    private_key: ghAppState.connectKey,
  };
  if (ghAppState.connectBaseURL) payload.base_url = ghAppState.connectBaseURL;

  api('/api/secrets', {
    name: name,
    kind: 'github_app',
    payload: JSON.stringify(payload),
    metadata: {
      account: chosen.account,
      account_type: chosen.account_type,
      installation_id: String(chosen.id),
    },
    // Shared, not personal: an App connected by an admin is infrastructure the
    // whole hub grants from. A personal one would be invisible to every other
    // maintainer and could not be assigned to a shared project.
    personal: false,
  }).then(d => {
    if (!d || d.error) { toast((d && d.error) || 'could not store the App', 'error'); return; }
    toast('Connected ' + chosen.account, 'success');
    // The key is no longer needed anywhere in this page.
    ghAppState.connectKey = '';
    ghAppState.installations = [];
    ['ghAppKey', 'ghAppId', 'ghAppName', 'ghAppBaseUrl'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    const out = document.getElementById('ghAppInstallations');
    if (out) out.innerHTML = '';
    loadGitHubApps();
  }).catch(e => toast(String(e && e.message ? e.message : e), 'error'));
}

// loadGitHubApps lists the github_app secrets this hub holds.
window.loadGitHubApps = function() {
  if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) return Promise.resolve();
  return api('/api/secrets').then(d => {
    const secrets = (d && d.secrets) || [];
    ghAppState.apps = secrets.filter(s => s.kind === 'github_app');
    const el = document.getElementById('ghAppList');
    if (!el) return;
    if (!ghAppState.apps.length) {
      el.innerHTML = '<div class="empty-state"><p>No GitHub App connected yet.</p></div>';
      return;
    }
    el.innerHTML = ghAppState.apps.map(a => {
      const md = a.metadata || {};
      const where = md.account
        ? esc(md.account) + (md.account_type ? ' (' + esc(md.account_type) + ')' : '')
        : 'installation ' + esc(md.installation_id || '?');
      return '<div style="display:flex;align-items:center;gap:10px;padding:6px 0;' +
        'border-bottom:1px solid var(--border)">' +
        '<strong>' + esc(a.name) + '</strong>' +
        '<span style="font-size:11px;color:var(--muted)">' + where + '</span>' +
        '<span style="flex:1"></span>' +
        '<span style="font-size:11px;color:var(--muted)">' +
          esc(String(a.active_grants || 0)) + ' active grant(s)</span>' +
        '</div>';
    }).join('');
  }).catch(() => {});
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
  if (isMultiProject && selectedProjectIdx === null) {
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
      ghAppRenderAssignments();
    }).catch(() => {});
};

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
          ? '<button class="btn btn-sm btn-danger" data-gh-revoke="' + esc(a.grant_id) + '">Revoke</button>'
          : '';
        return '<tr><td>' + repos + '</td>' +
          '<td><span class="badge ' + (a.access === 'write' ? 'running' : 'complete') +
            '" style="font-size:10px">' + esc(a.access) + '</span></td>' +
          '<td>' + esc(a.secret_name) + ' <span style="font-size:10px;color:var(--muted)">' +
            esc(a.kind) + '</span></td>' +
          '<td style="font-size:11px">' + exp + '</td>' +
          '<td style="text-align:right">' + revoke + '</td></tr>';
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
          '<select id="ghAssignAccess" class="input" style="max-width:150px">' +
            '<option value="read">Read only</option>' +
            '<option value="write">Read and write</option>' +
          '</select>' +
          '<button class="btn btn-sm" id="ghAssignLoad">List repositories</button>' +
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
        '<button class="btn btn-sm btn-primary" id="ghAssignSubmit" style="margin-top:8px">' +
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

  apiMethod('POST', '/api/projects/' + ghAppProjectIdx() + '/repositories', {
    secret: sel.value,
    repos: repos,
    access: (acc && acc.value) || 'read',
  }).then(d => {
    if (!d || d.error) { toast((d && d.error) || 'could not assign', 'error'); return; }
    toast('Granted ' + repos.length + ' repositor' + (repos.length === 1 ? 'y' : 'ies'), 'success');
    loadProjectRepositories();
  }).catch(e => toast(String(e && e.message ? e.message : e), 'error'));
}

function ghAppRevoke(grantID) {
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

// One delegated listener for every control this file renders. Delegation
// rather than per-element binding because the panels are re-rendered whole on
// each load, which would otherwise strip the handlers with the markup.
document.addEventListener('click', function(ev) {
  const t = ev.target;
  if (!t || !t.closest) return;

  const install = t.closest('[data-gh-install]');
  if (install) { ghAppSaveInstallation(install.getAttribute('data-gh-install')); return; }

  const revoke = t.closest('[data-gh-revoke]');
  if (revoke) { ghAppRevoke(revoke.getAttribute('data-gh-revoke')); return; }

  if (t.closest('#ghAssignLoad')) { ghAppLoadRepos(); return; }
  if (t.closest('#ghAssignSubmit')) { ghAppSubmitAssignment(); return; }
});
