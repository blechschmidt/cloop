// ── Keyboard shortcuts & Command Palette ─────────────────────────────────────

// Maps 1-9 to tab names in left-to-right order.
const TAB_KEYS = ['overview','tasks','kanban','timeline','kb','deps','risk-matrix','analytics','chat'];

// ── Single source of truth for all keyboard shortcuts ───────────────────────
// The help modal, the command palette hints, and the global keydown handler
// all derive from this object. Adding a new shortcut here keeps everything in
// sync — never hard-code shortcut strings elsewhere.
const KEYBOARD_SHORTCUTS = {
  Navigation: [
    { keys: ['1'], description: 'Go to Overview tab' },
    { keys: ['2'], description: 'Go to Tasks tab' },
    { keys: ['3'], description: 'Go to Kanban tab' },
    { keys: ['4'], description: 'Go to Timeline tab' },
    { keys: ['5'], description: 'Go to Knowledge Base tab' },
    { keys: ['6'], description: 'Go to Dependencies tab' },
    { keys: ['7'], description: 'Go to Risk Matrix tab' },
    { keys: ['8'], description: 'Go to Analytics tab' },
    { keys: ['9'], description: 'Go to Chat tab' },
    { keys: ['Ctrl', 'K'], description: 'Open command palette' },
    { keys: ['?'], description: 'Show this keyboard shortcut help' },
    { keys: ['Esc'], description: 'Close modal / palette / clear focus' },
  ],
  'Task Actions': [
    { keys: ['n'], description: 'New task (focus title field)' },
    { keys: ['j'], description: 'Move focus down through tasks' },
    { keys: ['k'], description: 'Move focus up through tasks' },
    { keys: ['Enter'], description: 'Edit focused task' },
    { keys: ['h'], description: 'Move focused kanban card to previous column' },
    { keys: ['l'], description: 'Move focused kanban card to next column' },
  ],
  Project: [
    { keys: ['r'], description: 'Refresh project state' },
    { keys: ['t'], description: 'Toggle dark/light theme' },
  ],
  Search: [
    { keys: ['/'], description: 'Focus search filter bar' },
  ],
};

// Helper to render a single key combo (e.g. ['Ctrl','K']) as kbd elements.
function _formatShortcutKeys(keys) {
  return keys.map((k, i) => {
    const sep = i > 0 ? '<span class="help-key-sep">+</span>' : '';
    return sep + '<kbd>' + esc(k) + '</kbd>';
  }).join('');
}

// All commands registered in the palette.
const CMD_REGISTRY = [
  { label:'Overview',        icon:'🏠', shortcut:'1', action:()=>switchTab('overview') },
  { label:'Tasks',           icon:'📋', shortcut:'2', action:()=>switchTab('tasks') },
  { label:'Kanban',          icon:'🗂', shortcut:'3', action:()=>switchTab('kanban') },
  { label:'Timeline',        icon:'📅', shortcut:'4', action:()=>switchTab('timeline') },
  { label:'Knowledge Base',  icon:'📚', shortcut:'5', action:()=>switchTab('kb') },
  { label:'Dependencies',    icon:'🔗', shortcut:'6', action:()=>switchTab('deps') },
  { label:'Risk Matrix',     icon:'⚠️', shortcut:'7', action:()=>switchTab('risk-matrix') },
  { label:'Analytics',       icon:'📊', shortcut:'8', action:()=>switchTab('analytics') },
  { label:'Chat',            icon:'💬', shortcut:'9', action:()=>switchTab('chat') },
  { label:'Assistant',       icon:'🤖', shortcut:'',  action:()=>switchTab('assistant') },
  { label:'Projects',        icon:'📁', shortcut:'',  action:()=>switchTab('projects') },
  { label:'Executors',       icon:'🖥', shortcut:'',  action:()=>switchTab('executors') },
  { label:'Settings',        icon:'⚙️', shortcut:'',  action:()=>switchTab('settings') },
  { label:'Show keyboard shortcuts', icon:'⌨️', shortcut:'?',  action:()=>openHelpModal() },
  { label:'Toggle dark/light theme', icon:'🌓', shortcut:'t',  action:()=>toggleTheme() },
  { label:'Focus search filter',     icon:'🔍', shortcut:'/',  action:()=>focusSearchFilter() },
  { label:'Brainstorm ideas',icon:'💡', shortcut:'',   action:()=>{ switchTab('tasks'); setTimeout(()=>{ const el=document.getElementById('suggestPanel'); if(el && el.style.display==='none'){ toggleSuggestPanel(); } },100); } },
  { label:'Refresh state',   icon:'🔄', shortcut:'r',  action:()=>{ api(pUrl('/api/state')).then(s=>render(s)).catch(()=>{}); toast('Refreshed','ok'); } },
  { label:'New task',        icon:'➕', shortcut:'n',  action:()=>{ switchTab('tasks'); setTimeout(()=>{ const el=document.getElementById('newTaskTitle'); if(el){el.focus();} },100); } },
  { label:'Start run',       icon:'▶️', shortcut:'',   action:()=>submitRun() },
  { label:'Stop run',        icon:'⏹', shortcut:'',   action:()=>submitStop() },
  { label:'Add task',        icon:'✏️', shortcut:'',   action:()=>{ switchTab('tasks'); setTimeout(()=>{ const el=document.getElementById('newTaskTitle'); if(el){el.focus();} },100); } },
  { label:'Run plan',        icon:'🚀', shortcut:'',   action:()=>submitRun() },
  { label:'Reset session',   icon:'🗑', shortcut:'',   action:()=>submitReset() },
];

// ── Help modal (keyboard shortcuts cheat sheet) ─────────────────────────────
let helpOpen = false;

function _renderHelpModalBody() {
  const body = document.getElementById('help-modal-body');
  if (!body) return;
  let html = '';
  for (const [category, rows] of Object.entries(KEYBOARD_SHORTCUTS)) {
    html += '<div class="help-category"><h4>' + esc(category) + '</h4>';
    for (const r of rows) {
      html += '<div class="help-row">' +
        '<span class="help-row-desc">' + esc(r.description) + '</span>' +
        '<span class="help-row-keys">' + _formatShortcutKeys(r.keys) + '</span>' +
        '</div>';
    }
    html += '</div>';
  }
  body.innerHTML = html;
}

window.openHelpModal = function() {
  if (helpOpen) return;
  helpOpen = true;
  _renderHelpModalBody();
  document.getElementById('help-backdrop').classList.add('open');
};

window.closeHelpModal = function() {
  helpOpen = false;
  document.getElementById('help-backdrop').classList.remove('open');
};

// Close help modal when clicking backdrop (not modal itself).
document.getElementById('help-backdrop').addEventListener('click', function(e) {
  if (e.target === this) closeHelpModal();
});

// Focus the unified search filter input on the current tab, or the global
// command palette as a fallback when no filter bar is visible.
function focusSearchFilter() {
  const fbar = document.getElementById('filterBar');
  const fq   = document.getElementById('filterQ');
  if (fbar && fbar.style.display !== 'none' && fq) {
    fq.focus();
    fq.select();
    return;
  }
  // Fallback: open the command palette so users can search commands.
  openCommandPalette();
}

// ── Kanban keyboard navigation state ────────────────────────────────────────
const KANBAN_COLS = ['pending','in_progress','done','failed'];
let kbKanbanIdx = -1; // index into the currently visible kanban-card list

function getKanbanCards() {
  return Array.from(document.querySelectorAll('#tab-kanban .kb-card'));
}

function kbFocusKanbanCard(idx) {
  const cards = getKanbanCards();
  if (!cards.length) { kbKanbanIdx = -1; return; }
  idx = Math.max(0, Math.min(idx, cards.length - 1));
  kbKanbanIdx = idx;
  cards.forEach((el, i) => el.classList.toggle('kb-focus', i === idx));
  cards[idx].scrollIntoView({ block: 'nearest' });
}

function kbClearKanbanFocus() {
  kbKanbanIdx = -1;
  getKanbanCards().forEach(el => el.classList.remove('kb-focus'));
}

// Move the currently focused kanban card to the previous (-1) or next (+1) column.
function kbMoveFocusedKanbanCard(direction) {
  const cards = getKanbanCards();
  if (kbKanbanIdx < 0 || kbKanbanIdx >= cards.length) return;
  const card = cards[kbKanbanIdx];
  const idStr = card.getAttribute('data-task-id');
  const id = parseInt(idStr, 10);
  if (!id) return;
  const task = appState && appState.plan && appState.plan.tasks
    ? appState.plan.tasks.find(t => t.id === id) : null;
  if (!task) return;
  const currentCol = (typeof kbColFor === 'function') ? kbColFor(task.status) : task.status;
  const ci = KANBAN_COLS.indexOf(currentCol);
  if (ci < 0) return;
  const ni = ci + direction;
  if (ni < 0 || ni >= KANBAN_COLS.length) return;
  const newStatus = KANBAN_COLS[ni];
  apiMethod('PATCH', pUrl('/api/tasks/'+id), {status: newStatus}).then(d => {
    if (d.ok) {
      toast('Task #'+id+': moved to '+newStatus.replace('_',' '), 'ok');
      refreshState();
    } else {
      toast(d.error || 'Update failed', 'err');
    }
  }).catch(() => toast('Request failed', 'err'));
}

// ── Command palette state ────────────────────────────────────────────────────
let cmdOpen = false;
let cmdSelectedIdx = 0;
let cmdFiltered = [...CMD_REGISTRY];

function openCommandPalette() {
  cmdOpen = true;
  cmdSelectedIdx = 0;
  cmdFiltered = [...CMD_REGISTRY];
  document.getElementById('cmd-backdrop').classList.add('open');
  const inp = document.getElementById('cmd-input');
  inp.value = '';
  renderCmdResults('');
  setTimeout(() => inp.focus(), 30);
}

function closeCommandPalette() {
  cmdOpen = false;
  document.getElementById('cmd-backdrop').classList.remove('open');
}

function renderCmdResults(query) {
  const q = query.trim().toLowerCase();
  cmdFiltered = q
    ? CMD_REGISTRY.filter(c => c.label.toLowerCase().includes(q))
    : [...CMD_REGISTRY];
  if (cmdSelectedIdx >= cmdFiltered.length) cmdSelectedIdx = 0;

  const container = document.getElementById('cmd-results');
  if (!cmdFiltered.length) {
    container.innerHTML = '<div class="cmd-no-results">No matching commands</div>';
    return;
  }
  container.innerHTML = cmdFiltered.map((c, i) => {
    const labelHtml = q
      ? esc(c.label).replace(new RegExp('('+escRe(q)+')', 'gi'), '<em>$1</em>')
      : esc(c.label);
    const sel = i === cmdSelectedIdx ? ' selected' : '';
    return '<div class="cmd-item'+sel+'" role="option" aria-selected="'+(i===cmdSelectedIdx)+'" data-idx="'+i+'" onclick="cmdSelect('+i+')" onmouseenter="cmdHover('+i+')">'+
      '<span class="cmd-item-icon">'+c.icon+'</span>'+
      '<span class="cmd-item-label cmd-item-match">'+labelHtml+'</span>'+
      (c.shortcut ? '<span class="cmd-item-shortcut"><kbd>'+esc(c.shortcut)+'</kbd></span>' : '')+
    '</div>';
  }).join('');
  scrollCmdItemIntoView();
}

function escRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function scrollCmdItemIntoView() {
  const container = document.getElementById('cmd-results');
  const sel = container.querySelector('.cmd-item.selected');
  if (sel) sel.scrollIntoView({ block: 'nearest' });
}

window.cmdSelect = function(idx) {
  const cmd = cmdFiltered[idx];
  if (!cmd) return;
  closeCommandPalette();
  cmd.action();
};

window.cmdHover = function(idx) {
  cmdSelectedIdx = idx;
  document.querySelectorAll('.cmd-item').forEach((el,i) => {
    el.classList.toggle('selected', i === idx);
    el.setAttribute('aria-selected', i === idx ? 'true' : 'false');
  });
};

document.getElementById('cmd-input').addEventListener('input', function() {
  renderCmdResults(this.value);
});

document.getElementById('cmd-input').addEventListener('keydown', function(e) {
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    cmdSelectedIdx = Math.min(cmdSelectedIdx + 1, cmdFiltered.length - 1);
    renderCmdResults(this.value);
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    cmdSelectedIdx = Math.max(cmdSelectedIdx - 1, 0);
    renderCmdResults(this.value);
  } else if (e.key === 'Enter') {
    e.preventDefault();
    cmdSelect(cmdSelectedIdx);
  } else if (e.key === 'Escape') {
    e.preventDefault();
    closeCommandPalette();
  }
});

// Close palette when clicking backdrop (not palette itself).
document.getElementById('cmd-backdrop').addEventListener('click', function(e) {
  if (e.target === this) closeCommandPalette();
});

// ── Task keyboard navigation state ───────────────────────────────────────────
let kbTaskIdx = -1; // index into currently visible task list items

function getTaskItems() {
  return Array.from(document.querySelectorAll('#taskListFull .task-item'));
}

function kbFocusTask(idx) {
  const items = getTaskItems();
  if (!items.length) return;
  idx = Math.max(0, Math.min(idx, items.length - 1));
  kbTaskIdx = idx;
  items.forEach((el, i) => el.classList.toggle('kb-focus', i === idx));
  items[idx].scrollIntoView({ block: 'nearest' });
}

function kbClearFocus() {
  kbTaskIdx = -1;
  getTaskItems().forEach(el => el.classList.remove('kb-focus'));
}

// ── Global keyboard shortcut handler ─────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  // Never intercept when typing in a real input/editable area.
  const tag = ((e.target && e.target.tagName) || '').toUpperCase();
  const inInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || e.target.isContentEditable;

  // Cmd/Ctrl+K — open command palette (always, even in inputs).
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault();
    if (cmdOpen) { closeCommandPalette(); } else { openCommandPalette(); }
    return;
  }

  // Escape — close any open modal / palette.
  if (e.key === 'Escape') {
    if (helpOpen) { closeHelpModal(); return; }
    if (cmdOpen) { closeCommandPalette(); return; }
    const td = document.getElementById('td-overlay');
    if (td && td.classList.contains('open')) { closeTaskDetails(); return; }
    const dc = document.getElementById('dc-overlay');
    if (dc && dc.classList.contains('open')) { closeDecomposeModal(); return; }
    const modal = document.getElementById('modal-overlay');
    if (modal && modal.classList.contains('open')) { closeModal(); return; }
    const voice = document.querySelector('.voice-modal-backdrop');
    if (voice) { voice.remove(); return; }
    kbClearFocus();
    kbClearKanbanFocus();
    return;
  }

  // All remaining shortcuts are blocked when typing in inputs.
  if (inInput) return;
  // Also block when palette / help modal is open.
  if (cmdOpen || helpOpen) return;

  // ?: open keyboard shortcuts help modal (works without modifier — shift+/ produces this key).
  if (e.key === '?' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    e.preventDefault();
    openHelpModal();
    return;
  }

  // /: focus the search filter bar (or open command palette as fallback).
  if (e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    e.preventDefault();
    focusSearchFilter();
    return;
  }

  // 1-9: switch to tab by number.
  if (e.key >= '1' && e.key <= '9' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    const idx = parseInt(e.key, 10) - 1;
    if (TAB_KEYS[idx]) { switchTab(TAB_KEYS[idx]); kbClearFocus(); kbClearKanbanFocus(); }
    return;
  }

  // r: refresh state.
  if (e.key === 'r' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    api(pUrl('/api/state')).then(s => render(s)).catch(() => {});
    toast('Refreshed', 'ok');
    return;
  }

  // t: toggle dark/light theme.
  if (e.key === 't' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    toggleTheme();
    return;
  }

  // n: new task — switch to Tasks tab and focus the add-task input.
  if (e.key === 'n' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    switchTab('tasks');
    kbClearFocus();
    setTimeout(() => { const el = document.getElementById('newTaskTitle'); if (el) el.focus(); }, 100);
    return;
  }

  // j/k: move focus through task or kanban-card list (depending on active tab).
  if ((e.key === 'j' || e.key === 'k') && !e.metaKey && !e.ctrlKey && !e.altKey) {
    if (activeTab === 'tasks') {
      e.preventDefault();
      const items = getTaskItems();
      if (!items.length) return;
      if (kbTaskIdx < 0) {
        kbFocusTask(e.key === 'j' ? 0 : items.length - 1);
      } else {
        kbFocusTask(kbTaskIdx + (e.key === 'j' ? 1 : -1));
      }
      return;
    }
    if (activeTab === 'kanban') {
      e.preventDefault();
      const cards = getKanbanCards();
      if (!cards.length) return;
      if (kbKanbanIdx < 0) {
        kbFocusKanbanCard(e.key === 'j' ? 0 : cards.length - 1);
      } else {
        kbFocusKanbanCard(kbKanbanIdx + (e.key === 'j' ? 1 : -1));
      }
      return;
    }
  }

  // h/l: move focused kanban card to previous (h) or next (l) column.
  if ((e.key === 'h' || e.key === 'l') && activeTab === 'kanban' && !e.metaKey && !e.ctrlKey && !e.altKey) {
    e.preventDefault();
    if (kbKanbanIdx < 0) {
      const cards = getKanbanCards();
      if (cards.length) kbFocusKanbanCard(0);
      return;
    }
    kbMoveFocusedKanbanCard(e.key === 'l' ? 1 : -1);
    return;
  }

  // Enter: open edit modal for the focused task.
  if (e.key === 'Enter' && activeTab === 'tasks' && kbTaskIdx >= 0) {
    e.preventDefault();
    const items = getTaskItems();
    const item = items[kbTaskIdx];
    if (item) {
      const editBtn = item.querySelector('.act.edit');
      if (editBtn) editBtn.click();
    }
    return;
  }
}, true); // use capture so we run before chat voice handler

// ── Init ─────────────────────────────────────────────────────────────────────

// On page load, probe the server. If it returns 401 show the login modal,
// otherwise detect multi-project mode and start WebSocket (SSE as fallback).
function checkAuthAndInit() {
  // First paint — runs before any project is selected, so pUrl would be
  // a no-op. The per-project state is fetched after multi-project init.
  fetch('/api/state', {headers: authHeaders()}).then(r => {
    if (r.status === 401) {
      showLoginModal();
      return;
    }
    // Also check for multi-project mode.
    fetch('/api/projects', {headers: authHeaders()}).then(pr => pr.json()).then(pd => {
      const projects = pd.projects || [];
      isMultiProject = pd.multi_project === true || projects.length > 1;
      connectWS();
      if (isMultiProject) {
        // In multi-project mode, Projects list is the landing page.
        renderProjects(projects, pd.stats || {});
        updateProjectSelector();
        switchTab('projects');
      } else {
        r.json().then(s => render(s)).catch(() => {});
        // Single-project mode: still show the "Project" scope hint for the default Overview tab.
        updateScopeHint(activeTab || 'overview');
        // Overview is the landing tab here, so its Executor card needs its
        // one non-state-diff field (Task 20160).
        loadExecutors();
      }
    }).catch(() => {
      connectWS();
      r.json().then(s => render(s)).catch(() => {});
    });
    // Initial run state arrives as a 'run_state' WebSocket event on connect
    // (see handleWS), and subsequent transitions are pushed by the watcher
    // and the run/stop handlers — no polling required.
  }).catch(() => {
    connectWS();
  });
}

// ── Theme toggle ─────────────────────────────────────────────────────────────

function _applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const icon = document.getElementById('themeToggleIcon');
  if (icon) {
    // Sun = currently dark (click to go light), Moon = currently light (click to go dark).
    icon.textContent = theme === 'light' ? '\u263D' : '\u2600';
  }
  const btn = document.getElementById('themeToggleBtn');
  if (btn) btn.setAttribute('aria-label', theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode');
}

// Sync icon with whatever the FOUC script already set.
(function() {
  const t = document.documentElement.getAttribute('data-theme') || 'dark';
  _applyTheme(t);
})();

window.toggleTheme = function() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  localStorage.setItem('cloop-theme', next);
  _applyTheme(next);
  // Re-render timeline if it's the active tab so SVG colors update.
  if (typeof activeTab !== 'undefined' && activeTab === 'timeline') {
    renderTimeline();
  }
};

checkAuthAndInit();

