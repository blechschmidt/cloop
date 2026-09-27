// ── Suggest ──────────────────────────────────────────────────────────────────

// The panel brainstorms loose ideas or, when the user has typed a request,
// has the AI break that request into the tasks of a plan (Task 20342). Both
// arrive as the same cards. A plan's cards say which step they are and which
// steps they follow, and the server wires those dependencies as they are
// added — in whatever order, and through any the user skips (suggest.Ledger).
let currentSuggestions = [];
let suggestGen   = 0;     // generation the cards came from; echoed back on add
let suggestShown = 0;     // generation whose outcome has been announced
let suggestPlan  = false; // the cards are a plan's tasks rather than ideas
let suggestBusy  = false; // an add is in flight

window.toggleSuggestPanel = function() {
  const panel = document.getElementById('suggestPanel');
  const btn   = document.getElementById('suggestToggleBtn');
  const isHidden = panel.style.display === 'none';
  panel.style.display = isHidden ? '' : 'none';
  btn.textContent = isHidden ? 'Hide suggestions' : 'Brainstorm ideas';
};

// syncSuggestMode relabels the count for what Generate will do: with a
// request typed it is the plan's length, and left blank the AI decides it;
// without one it is how many ideas to brainstorm.
window.syncSuggestMode = function() {
  const plan = !!document.getElementById('suggestInput').value.trim();
  document.getElementById('suggestCountLabel').textContent = plan ? 'Tasks in plan:' : 'Ideas to generate:';
  document.getElementById('suggestCount').placeholder = plan ? 'auto' : '5';
};

window.runSuggest = function() {
  const path  = selectedProjectPath;
  const input = document.getElementById('suggestInput').value.trim();
  const count = Math.max(0, parseInt(document.getElementById('suggestCount').value) || 0);
  document.getElementById('suggestBtn').disabled = true;
  document.getElementById('suggestStatusLine').style.display = '';
  document.getElementById('suggestSpinner').style.display    = '';
  document.getElementById('suggestStatusText').textContent   = input
    ? 'Planning '+(count ? count+' ' : '')+'tasks with AI...'
    : 'Generating '+(count || 5)+' ideas with AI...';
  clearSuggestions();

  // Server pushes 'suggest_status' WS events on completion; no client polling.
  // A reply that lands after the user has moved to another project belongs to
  // the project it was sent from, and must not touch the panel now on screen.
  // The same goes for adds below.
  api(pUrl('/api/suggest/generate'), {count, input}).then(d => {
    if (!d.ok && path === selectedProjectPath) {
      _suggestFail('Error: '+(d.error||'failed'));
    }
  }).catch(() => { if (path === selectedProjectPath) _suggestFail('Request failed'); });
};

// applySuggestStatus is called from the WebSocket 'suggest_status' event
// handler with the latest job state. It updates the UI when the job finishes
// or errors so the client never has to poll /api/suggest/status.
function applySuggestStatus(d) {
  if (!d) return;
  const btn = document.getElementById('suggestBtn');
  if (d.running) {
    // A generation started elsewhere (another tab, or before a reload) says
    // so; one started here keeps the more specific line runSuggest wrote.
    if (!btn.disabled) document.getElementById('suggestStatusText').textContent = 'Running... (this may take a minute)';
    btn.disabled = true;
    document.getElementById('suggestStatusLine').style.display = '';
    document.getElementById('suggestSpinner').style.display    = '';
    clearSuggestions();
    return;
  }

  btn.disabled = false;
  document.getElementById('suggestSpinner').style.display = 'none';

  // A generation's outcome is announced once. The server re-sends the same
  // generation whenever one of its cards is added, here or in another tab;
  // those updates only drop what was added, so they neither toast again nor
  // bring back cards this page skipped.
  const fresh = d.gen !== suggestShown;
  suggestShown = suggestGen = d.gen || 0;

  if (d.error) {
    document.getElementById('suggestStatusText').textContent = 'Error: '+d.error;
    if (fresh) toast('Suggest failed: '+d.error, 'err');
    return;
  }

  if (!d.done) return;

  document.getElementById('suggestStatusLine').style.display = 'none';
  const pending = d.suggestions || [];
  if (!fresh) {
    const ids = new Set(pending.map(sg => sg.id));
    currentSuggestions = currentSuggestions.filter(sg => ids.has(sg.id));
    renderSuggestions();
    return;
  }
  suggestPlan = !!d.request;
  currentSuggestions = pending.slice();
  const sum = document.getElementById('suggestSummary');
  sum.textContent = d.summary || '';
  sum.style.display = d.summary ? '' : 'none';
  renderSuggestions();
  const n = currentSuggestions.length, what = suggestPlan ? 'task' : 'idea';
  toast(n ? (suggestPlan ? 'Planned ' : 'Generated ')+n+' '+what+(n===1?'':'s')+' — review below' : 'No '+what+'s proposed', n ? 'ok' : 'err');
}

function _suggestFail(msg) {
  document.getElementById('suggestBtn').disabled = false;
  document.getElementById('suggestSpinner').style.display = 'none';
  document.getElementById('suggestStatusText').textContent = msg;
  toast(msg, 'err');
}

function renderSuggestions() {
  const wrap = document.getElementById('suggestList');
  const badge = document.getElementById('suggestCountBadge');
  const n = currentSuggestions.length;
  document.getElementById('suggestAddAllBtn').style.display = n ? '' : 'none';
  document.getElementById('suggestClearBtn').style.display  = n ? '' : 'none';
  if (!n) {
    wrap.innerHTML = '';
    badge.textContent = '';
    // The summary describes cards; with none left it describes nothing.
    document.getElementById('suggestSummary').style.display = 'none';
    return;
  }
  badge.textContent = '· '+n+' '+(suggestPlan ? 'task' : 'idea')+(n===1?'':'s')+' to review';
  const cards = currentSuggestions.map((sg, i) => {
    const cat    = (sg.category || '').toLowerCase();
    const eff    = (sg.effort   || '').toUpperCase();
    const after  = (sg.depends_on || []).join(', ');
    const title  = (suggestPlan ? 'Step '+esc(sg.id)+' · ' : '')+esc(sg.title || '(untitled)');
    const desc   = esc(sg.description || '');
    const why    = esc(sg.rationale   || '');
    return ''+
      '<div class="suggest-card" data-sg-idx="'+i+'">'+
        '<div class="suggest-card-head">'+
          '<div class="suggest-card-title">'+title+'</div>'+
          '<div class="suggest-card-tags">'+
            (after ? '<span class="suggest-tag suggest-tag-dep">after '+esc(after)+'</span>' : '')+
            (cat ? '<span class="suggest-tag suggest-tag-cat">'+esc(cat)+'</span>' : '')+
            (eff ? '<span class="suggest-tag suggest-tag-eff">'+esc(eff)+'</span>' : '')+
          '</div>'+
        '</div>'+
        (desc ? '<div class="suggest-card-desc"><span class="suggest-card-label">What:</span> '+desc+'</div>' : '')+
        (why  ? '<div class="suggest-card-why"><span class="suggest-card-label">Why:</span> '+why+'</div>' : '')+
        '<div class="suggest-card-actions">'+
          '<button class="btn primary" onclick="acceptSuggestion('+i+')">Add as task</button>'+
          '<button class="btn"         onclick="rejectSuggestion('+i+')">Skip</button>'+
        '</div>'+
      '</div>';
  });
  wrap.innerHTML = cards.join('');
}

// _suggestAdd accepts proposals by ID. The server holds the generation, so it
// adds exactly what it proposed and, for a plan, what each step follows.
function _suggestAdd(sgs) {
  if (suggestBusy || !sgs.length) return;
  suggestBusy = true;
  const path = selectedProjectPath;
  api(pUrl('/api/suggest/add'), {gen: suggestGen, ids: sgs.map(sg => sg.id)}).then(d => {
    if (!d.ok) { toast(d.error||'Add failed', 'err'); return; }
    if (path !== selectedProjectPath) return;
    const ids = new Set(sgs.map(sg => sg.id));
    currentSuggestions = currentSuggestions.filter(sg => !ids.has(sg.id));
    renderSuggestions();
    // Rows appear now rather than on the state_diff the server also sends.
    try { applyStateDiff({tasks_added: d.tasks || []}); } catch(_) {}
    const n = (d.added || []).length;
    toast(sgs.length === 1 && n === 1 ? 'Added "'+sgs[0].title+'" as task' : 'Added '+n+' task'+(n===1?'':'s'), 'ok');
  }).catch(() => toast('Request failed', 'err')).finally(() => { suggestBusy = false; });
}

window.acceptSuggestion = function(idx) {
  const sg = currentSuggestions[idx];
  if (sg) _suggestAdd([sg]);
};

window.rejectSuggestion = function(idx) {
  if (!currentSuggestions[idx]) return;
  currentSuggestions.splice(idx, 1);
  renderSuggestions();
};

window.addAllSuggestions = function() {
  _suggestAdd(currentSuggestions.slice());
};

window.clearSuggestions = function() {
  currentSuggestions = [];
  renderSuggestions();
};

// resetSuggestPanel forgets the panel when the user leaves a project: its
// cards belong to that project, and accepting them under another would put
// them in the wrong plan. The next project's own job, if it has one, arrives
// on that project's stream.
function resetSuggestPanel() {
  clearSuggestions();
  suggestGen = suggestShown = 0;
  document.getElementById('suggestInput').value = '';
  document.getElementById('suggestBtn').disabled = false;
  document.getElementById('suggestStatusLine').style.display = 'none';
  syncSuggestMode();
}

// ── Decompose (AI splits one task into a plan of sub-tasks) ──────────────────

let dcTaskId   = 0;     // parent task being decomposed (0 = modal closed)
let dcSubtasks = [];    // proposed sub-tasks, each with a _keep selection flag
let dcBusy     = false; // an AI preview or apply request is in flight

window.openDecomposeModal = function(id) {
  const tasks = (appState && appState.plan && appState.plan.tasks) || [];
  const t = tasks.find(x => x.id === id);
  dcTaskId   = id;
  dcSubtasks = [];
  dcBusy     = true;
  document.getElementById('dc-title').textContent = 'Decompose Task #'+id+(t && t.title ? ' — '+t.title : '');
  document.getElementById('dc-apply-btn').style.display = 'none';
  document.getElementById('dc-count').textContent = '';
  document.getElementById('dc-body').innerHTML =
    '<div class="dc-spin"><span class="spinner"></span>'+
    '<span>Asking the AI to break this task into smaller sub-tasks… this can take a minute.</span></div>';
  openOverlay('dc-overlay', {dismiss: closeDecomposeModal});

  api(pUrl('/api/tasks/'+id+'/decompose'), {}).then(d => {
    dcBusy = false;
    if (dcTaskId !== id) return; // modal was closed or reopened for another task
    if (!d.ok) {
      document.getElementById('dc-body').innerHTML =
        '<div class="empty-state"><h3>Decompose failed</h3><p>'+esc(d.error||'unknown error')+'</p></div>';
      return;
    }
    dcSubtasks = (d.subtasks || []).map(st => Object.assign({_keep: true}, st));
    renderDecomposeList();
  }).catch(() => {
    dcBusy = false;
    if (dcTaskId !== id) return;
    document.getElementById('dc-body').innerHTML =
      '<div class="empty-state"><h3>Request failed</h3><p>Could not reach the server.</p></div>';
  });
};

window.closeDecomposeModal = function() {
  closeOverlay('dc-overlay');
  dcTaskId = 0; dcSubtasks = []; dcBusy = false;
};

function renderDecomposeList() {
  const body = document.getElementById('dc-body');
  if (!dcSubtasks.length) {
    body.innerHTML = '<div class="empty-state"><h3>No sub-tasks proposed</h3>'+
      '<p>The AI did not propose any sub-tasks for this task. Close the dialog and try again.</p></div>';
    updateDecomposeFooter();
    return;
  }
  body.innerHTML =
    '<div class="dc-hint">Review the proposed sub-tasks. Applying adds the selected ones in sequence '+
    '(each depending on the previous) and marks the parent task as <strong>skipped</strong>.</div>'+
    dcSubtasks.map((st, i) =>
      '<label class="dc-sub'+(st._keep?'':' off')+'">'+
        '<input type="checkbox" '+(st._keep?'checked':'')+' onchange="toggleDecomposeSub('+i+')">'+
        '<div style="flex:1;min-width:0">'+
          '<div class="dc-sub-title">'+(i+1)+'. '+esc(st.title||'')+'</div>'+
          (st.description ? '<div class="dc-sub-desc">'+esc(st.description)+'</div>' : '')+
          ((st.role || st.estimated_minutes) ?
            '<div class="dc-sub-meta">'+
              (st.role ? '<span>'+esc(st.role)+'</span>' : '')+
              (st.estimated_minutes ? '<span>est: '+st.estimated_minutes+'m</span>' : '')+
            '</div>' : '')+
        '</div>'+
      '</label>'
    ).join('');
  updateDecomposeFooter();
}

window.toggleDecomposeSub = function(i) {
  if (!dcSubtasks[i]) return;
  dcSubtasks[i]._keep = !dcSubtasks[i]._keep;
  renderDecomposeList();
};

function updateDecomposeFooter() {
  const kept = dcSubtasks.filter(st => st._keep).length;
  const btn = document.getElementById('dc-apply-btn');
  btn.style.display = dcSubtasks.length ? '' : 'none';
  btn.disabled = kept === 0 || dcBusy;
  btn.textContent = kept ? 'Add '+kept+' sub-task'+(kept===1?'':'s') : 'Add sub-tasks';
  document.getElementById('dc-count').textContent =
    dcSubtasks.length ? kept+'/'+dcSubtasks.length+' selected' : '';
}

window.applyDecompose = function() {
  if (dcBusy || !dcTaskId) return;
  const id = dcTaskId;
  const kept = dcSubtasks.filter(st => st._keep).map(st => ({
    title: st.title || '',
    description: st.description || '',
    role: st.role || '',
    estimated_minutes: st.estimated_minutes || 0
  }));
  if (!kept.length) return;
  dcBusy = true;
  updateDecomposeFooter();
  api(pUrl('/api/tasks/'+id+'/decompose/apply'), {subtasks: kept}).then(d => {
    dcBusy = false;
    if (!d.ok) {
      updateDecomposeFooter();
      toast(d.error||'Apply failed', 'err');
      return;
    }
    closeDecomposeModal();
    toast('Task #'+d.parent_id+' decomposed into '+(d.added||[]).length+' sub-task'+((d.added||[]).length===1?'':'s'), 'ok');
    refreshState();
  }).catch(() => {
    dcBusy = false;
    updateDecomposeFooter();
    toast('Request failed', 'err');
  });
};

