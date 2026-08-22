// ── Suggest ──────────────────────────────────────────────────────────────────

let currentSuggestions = [];

window.toggleSuggestPanel = function() {
  const panel = document.getElementById('suggestPanel');
  const btn   = document.getElementById('suggestToggleBtn');
  const isHidden = panel.style.display === 'none';
  panel.style.display = isHidden ? '' : 'none';
  btn.textContent = isHidden ? 'Hide suggestions' : 'Brainstorm ideas';
};

window.runSuggest = function() {
  const count = parseInt(document.getElementById('suggestCount').value)||5;
  document.getElementById('suggestBtn').disabled = true;
  document.getElementById('suggestStatusLine').style.display = '';
  document.getElementById('suggestSpinner').style.display    = '';
  document.getElementById('suggestStatusText').textContent   = 'Generating '+count+' ideas with AI...';
  document.getElementById('suggestList').innerHTML           = '';
  document.getElementById('suggestSummary').style.display    = 'none';
  document.getElementById('suggestAddAllBtn').style.display  = 'none';
  document.getElementById('suggestClearBtn').style.display   = 'none';

  // Server pushes 'suggest_status' WS events on completion; no client polling.
  api(pUrl('/api/suggest/generate'), {count}).then(d => {
    if (!d.ok) {
      _suggestFail('Error: '+(d.error||'failed'));
    }
  }).catch(() => _suggestFail('Request failed'));
};

// applySuggestStatus is called from the WebSocket 'suggest_status' event
// handler with the latest job state. It updates the UI when the job finishes
// or errors so the client never has to poll /api/suggest/status.
function applySuggestStatus(d) {
  if (!d) return;
  if (d.running) {
    document.getElementById('suggestBtn').disabled = true;
    document.getElementById('suggestStatusLine').style.display = '';
    document.getElementById('suggestSpinner').style.display    = '';
    document.getElementById('suggestStatusText').textContent   = 'Running... (this may take a minute)';
    return;
  }

  document.getElementById('suggestBtn').disabled = false;
  document.getElementById('suggestSpinner').style.display = 'none';

  if (d.error) {
    document.getElementById('suggestStatusText').textContent = 'Error: '+d.error;
    toast('Suggest failed: '+d.error, 'err');
    return;
  }

  if (!d.done) return;

  document.getElementById('suggestStatusLine').style.display = 'none';
  currentSuggestions = (d.suggestions || []).slice();
  if (d.summary) {
    const sum = document.getElementById('suggestSummary');
    sum.textContent = d.summary;
    sum.style.display = '';
  }
  renderSuggestions();
  if (currentSuggestions.length > 0) {
    document.getElementById('suggestAddAllBtn').style.display = '';
    document.getElementById('suggestClearBtn').style.display  = '';
    toast('Generated '+currentSuggestions.length+' ideas — review below', 'ok');
  } else {
    toast('No suggestions returned', 'err');
  }
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
  if (!currentSuggestions || currentSuggestions.length === 0) {
    wrap.innerHTML = '';
    badge.textContent = '';
    return;
  }
  badge.textContent = '· '+currentSuggestions.length+' idea'+(currentSuggestions.length===1?'':'s')+' to review';
  const cards = currentSuggestions.map((sg, i) => {
    const cat    = (sg.category || '').toLowerCase();
    const eff    = (sg.effort   || '').toUpperCase();
    const title  = esc(sg.title || '(untitled)');
    const desc   = esc(sg.description || '');
    const why    = esc(sg.rationale   || '');
    return ''+
      '<div class="suggest-card" data-sg-idx="'+i+'">'+
        '<div class="suggest-card-head">'+
          '<div class="suggest-card-title">'+title+'</div>'+
          '<div class="suggest-card-tags">'+
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

window.acceptSuggestion = function(idx) {
  const sg = currentSuggestions[idx];
  if (!sg) return;
  api(pUrl('/api/suggest/add'), {suggestions:[sg]}).then(d => {
    if (!d.ok) { toast(d.error||'Add failed', 'err'); return; }
    currentSuggestions.splice(idx, 1);
    renderSuggestions();
    if (currentSuggestions.length === 0) {
      document.getElementById('suggestAddAllBtn').style.display = 'none';
      document.getElementById('suggestClearBtn').style.display  = 'none';
    }
    refreshState();
    toast('Added "'+sg.title+'" as task', 'ok');
  }).catch(() => toast('Request failed', 'err'));
};

window.rejectSuggestion = function(idx) {
  if (!currentSuggestions[idx]) return;
  currentSuggestions.splice(idx, 1);
  renderSuggestions();
  if (currentSuggestions.length === 0) {
    document.getElementById('suggestAddAllBtn').style.display = 'none';
    document.getElementById('suggestClearBtn').style.display  = 'none';
  }
};

window.addAllSuggestions = function() {
  if (!currentSuggestions.length) return;
  const all = currentSuggestions.slice();
  api(pUrl('/api/suggest/add'), {suggestions: all}).then(d => {
    if (!d.ok) { toast(d.error||'Add failed', 'err'); return; }
    const n = (d.added || []).length;
    currentSuggestions = [];
    renderSuggestions();
    document.getElementById('suggestAddAllBtn').style.display = 'none';
    document.getElementById('suggestClearBtn').style.display  = 'none';
    refreshState();
    toast('Added '+n+' suggestion'+(n===1?'':'s')+' as tasks', 'ok');
  }).catch(() => toast('Request failed', 'err'));
};

window.clearSuggestions = function() {
  currentSuggestions = [];
  renderSuggestions();
  document.getElementById('suggestSummary').style.display   = 'none';
  document.getElementById('suggestAddAllBtn').style.display = 'none';
  document.getElementById('suggestClearBtn').style.display  = 'none';
};

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
  document.getElementById('dc-overlay').classList.add('open');

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
  document.getElementById('dc-overlay').classList.remove('open');
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

