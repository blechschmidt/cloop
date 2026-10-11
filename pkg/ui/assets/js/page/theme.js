// The theme, set before the stylesheet paints anything (Task 20408): a blocking
// script in the head, since the hub's policy runs no inline script.
(function() {
  var t = null;
  try { t = localStorage.getItem('cloop-theme'); } catch (e) {}
  if (!t) t = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', t);
})();
