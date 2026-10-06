// Closes the main IIFE opened in 00-core.js. It lives in the last bundle
// fragment on purpose — numbered 99 so that a new fragment never has to
// renumber it: a fragment appended *after* the close is at global scope, where
// none of the shared helpers (api, esc, toast, relTime) are visible, so every
// call in it throws ReferenceError the first time a user opens that panel.
// That is exactly how the Sessions and Quotas panels shipped broken — the close
// had drifted to the end of 25-replay.js while two more fragments were
// appended behind it. TestDashboard_MainIIFEClosesInLastFragment pins it here.
})();
