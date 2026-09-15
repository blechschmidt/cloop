// ── Mobile nav helpers ─────────────────────────────────────────
window.openMobileNav = function() {
  const overlay = document.getElementById('mobileNavOverlay');
  const btn     = document.getElementById('hamburgerBtn');
  if (!overlay) return;
  if (btn) btn.setAttribute('aria-expanded', 'true');
  openOverlay(overlay, {dismiss: closeMobileNav, focus: '.mobile-nav-close'});
};

window.closeMobileNav = function() {
  const overlay = document.getElementById('mobileNavOverlay');
  const btn     = document.getElementById('hamburgerBtn');
  if (!overlay) return;
  if (btn) btn.setAttribute('aria-expanded', 'false');
  closeOverlay(overlay);
};

// Escape is handled centrally by dismissTopOverlay() in 18-shortcuts.js, which
// closes whichever dialog is in front. A second listener here would have fired
// as well, closing the nav from underneath a dialog opened over it.

// ── FAB: quick-add task on mobile ─────────────────────────────
window.fabAddTask = function() {
  // Switch to tasks tab if not there already.
  if (activeTab !== 'tasks') {
    switchTab('tasks');
  }
  // Scroll to add-task input and focus it.
  const input = document.getElementById('newTaskTitle');
  if (input) {
    input.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(() => input.focus(), 150);
  }
};

