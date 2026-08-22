// ── Mobile nav helpers ─────────────────────────────────────────
window.openMobileNav = function() {
  const overlay = document.getElementById('mobileNavOverlay');
  const btn     = document.getElementById('hamburgerBtn');
  if (!overlay) return;
  overlay.classList.add('open');
  overlay.setAttribute('aria-hidden', 'false');
  if (btn) btn.setAttribute('aria-expanded', 'true');
  // Trap focus: first close button
  const closeBtn = overlay.querySelector('.mobile-nav-close');
  if (closeBtn) setTimeout(() => closeBtn.focus(), 50);
};

window.closeMobileNav = function() {
  const overlay = document.getElementById('mobileNavOverlay');
  const btn     = document.getElementById('hamburgerBtn');
  if (!overlay) return;
  overlay.classList.remove('open');
  overlay.setAttribute('aria-hidden', 'true');
  if (btn) btn.setAttribute('aria-expanded', 'false');
};

// Close mobile nav on Escape key.
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    const overlay = document.getElementById('mobileNavOverlay');
    if (overlay && overlay.classList.contains('open')) {
      closeMobileNav();
    }
  }
});

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

