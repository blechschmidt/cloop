// Keeping an SSO session's authority current, and getting a lapsed one back,
// without the access-token prompt (Task 20359, re-landing Tasks 20322/20330).
//
// The hub bounds how old a session's group and role claims may be when it acts
// above operator, and re-asserts them itself when it holds a refresh token —
// the first layer, which needs nothing from here. Without a refresh token it
// can only refuse. The browser can settle that, because the user is still
// signed in at the identity provider. Three layers, in the order they engage:
//
//   1. Scheduled: /api/me says when the claims need re-asserting
//      (renew_in_seconds, sent only when the hub cannot do it itself); a
//      hidden frame runs /auth/renew with prompt=none before then.
//   2. Reactive: a 403 marked renewable gets one renewal and one retry.
//   3. Visible: when the provider has to see the user — login_required, or a
//      browser blocking its cookies in a frame — a banner offers a sign-in
//      that comes back to this tab and view. A 401 skips the banner and goes
//      straight there, since there is no session left to keep.
//
// The renewal never asks /api/me to re-arm: the frame's answer carries the next
// schedule. A request to /api/me counts as the user being active, and a tab
// nobody is looking at must still idle out.
//
// Two facts, kept apart (the Task 20330 bug): `oidc` is who authenticates at
// this hub — a deployment fact, sticky once known — and `live` is whether this
// page's session is alive. One flag doing both was false exactly when a session
// lapsed, so the 401 that followed read as a token-only hub.
//
// Tunables, in milliseconds: a panel firing six refused calls must not make six
// round trips to the provider (GAP); a provider that never answers, or a
// browser that blocks the frame without a load event (TIMEOUT); how long a
// frame may rest on a document that is not ours — the provider's own page, or
// the browser's error page for a provider that refuses to be framed — before
// that reads as "needs the user", long enough for a provider that bounces
// through a page of its own (FOREIGN); setTimeout fires at once past 2^31 ms,
// so long schedules re-arm in steps (STEP); and an automatic sign-in that came
// back without a working session must not be repeated, or a hub whose cookie
// the browser refuses would bounce between here and the provider for ever
// (LOOP).
const RENEW = {GAP: 5000, TIMEOUT: 20000, FOREIGN: 4000, STEP: 600000, RETRY: 60000, LOOP: 120000};

const renewState = {
  oidc: null,
  live: false,
  timer: null,
  dueAt: 0,
  inFlight: null,
  lastAttempt: 0,
  lastOutcome: '',
  failures: 0,
  banner: '',
  redirected: false,
  booted: false,
};

function noteAuthMode(oidc) {
  if (oidc) renewState.oidc = true;
  else if (renewState.oidc === null) renewState.oidc = false;
}

// noteSessionSchedule takes an /api/me answer (from refreshPermissions).
function noteSessionSchedule(me) {
  noteAuthMode(me.oidc_enabled);
  renewState.live = !!(me.oidc_enabled && me.authenticated);
  if (!renewState.live) { clearRenewTimer(); return; }
  // A working session: whatever sign-in brought us here did its job.
  try { sessionStorage.removeItem('cloop_signin_at'); } catch (_) {}
  if (renewState.banner === 'lapsed' || me.claim_age_seconds < me.max_claim_age_seconds) hideRenewBanner();
  if (typeof me.renew_in_seconds === 'number') scheduleRenew(me.renew_in_seconds * 1000);
  else clearRenewTimer();
}

function clearRenewTimer() {
  clearTimeout(renewState.timer);
  renewState.timer = null;
  renewState.dueAt = 0;
}

function scheduleRenew(ms) {
  clearRenewTimer();
  const wait = Math.max(ms, renewState.lastAttempt + RENEW.GAP - Date.now(), 0);
  renewState.dueAt = Date.now() + wait;
  const step = () => {
    const left = renewState.dueAt - Date.now();
    if (left > 0) { renewState.timer = setTimeout(step, Math.min(left, RENEW.STEP)); return; }
    renewState.timer = null;
    // A hidden tab waits: nobody is about to act there, and the listener
    // below renews the moment somebody looks.
    if (document.visibilityState !== 'hidden') runScheduledRenew();
  };
  renewState.timer = setTimeout(step, Math.min(wait, RENEW.STEP));
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && renewState.live && renewState.dueAt &&
      Date.now() >= renewState.dueAt - 1000) runScheduledRenew();
});

function runScheduledRenew() {
  clearRenewTimer();
  renewSession().then(res => {
    if (res.outcome === 'ok') { renewState.failures = 0; afterRenewal(res); return; }
    if (res.outcome === 'throttled' || res.outcome === 'not_enabled' || renewNeedsUser(res.outcome)) return;
    // Transient — a timeout, a provider briefly unwell. Retry once, a minute
    // on, and only say so if that fails too.
    if (++renewState.failures > 1) showRenewBanner('stale');
    else scheduleRenew(RENEW.RETRY);
  });
}

// afterRenewal re-arms from the frame's own answer. Claims that changed may
// have changed the permissions too, which is worth one /api/me.
function afterRenewal(res) {
  if (res.changed) refreshPermissions();
  else if (typeof res.renew_in === 'number') scheduleRenew(res.renew_in * 1000);
  else clearRenewTimer();
}

function renewNeedsUser(outcome) {
  return outcome === 'interaction_required' || outcome === 'blocked' ||
    outcome === 'subject_mismatch' || outcome === 'no_session';
}

// renewSession runs one silent renewal, shared by every caller while it runs,
// and resolves with {outcome, renew_in, changed}. On window for the browser
// gate in renew_browser_test.go, and for an operator at the console.
function renewSession() {
  if (renewState.inFlight) return renewState.inFlight;
  if (Date.now() - renewState.lastAttempt < RENEW.GAP) {
    return Promise.resolve({outcome: 'throttled', previous: renewState.lastOutcome});
  }
  renewState.lastAttempt = Date.now();
  renewState.inFlight = runRenewFrame().then(res => {
    renewState.inFlight = null;
    renewState.lastOutcome = res.outcome;
    if (res.outcome === 'ok') { if (renewState.banner === 'stale') hideRenewBanner(); }
    else if (res.outcome === 'no_session') signInAgain(false);
    else if (renewNeedsUser(res.outcome)) showRenewBanner('stale');
    return res;
  });
  return renewState.inFlight;
}
window.renewSession = renewSession;

function runRenewFrame() {
  return new Promise(resolve => {
    const frame = document.createElement('iframe');
    frame.setAttribute('aria-hidden', 'true');
    frame.tabIndex = -1;
    frame.title = 'Renewing sign-in';
    // Off-screen rather than display:none, which not every browser loads.
    frame.style.cssText = 'position:absolute;width:0;height:0;border:0;left:-9999px';
    let rest = null;
    const finish = res => {
      clearTimeout(timer);
      clearTimeout(rest);
      window.removeEventListener('message', onMessage);
      frame.remove();
      resolve(res);
    };
    const onMessage = ev => {
      // Our frame, on our origin, or it is not evidence about our session.
      if (ev.source !== frame.contentWindow || ev.origin !== window.location.origin) return;
      const d = ev.data;
      if (d && d.type === 'cloop.oidc.renew') finish({outcome: String(d.outcome), renew_in: d.renew_in, changed: !!d.changed});
    };
    frame.addEventListener('load', () => {
      let href = null;
      try { href = frame.contentWindow.location.href; } catch (_) { /* not our origin */ }
      if (href === 'about:blank') return;
      // Our answer posts while it parses, before its load event. A frame that
      // came to rest without one is on somebody else's document, or on one of
      // ours that is not the answer (an error page).
      clearTimeout(rest);
      rest = setTimeout(() => finish({outcome: href === null ? 'blocked' : 'error'}),
        href === null ? RENEW.FOREIGN : 1000);
    });
    const timer = setTimeout(() => finish({outcome: 'timeout'}), RENEW.TIMEOUT);
    window.addEventListener('message', onMessage);
    frame.src = '/auth/renew';
    document.body.appendChild(frame);
  });
}

// renewAndRetry backs the reactive layer: one renewal, then one replay of the
// refused request. Resolves {retried, value}.
function renewAndRetry(retry) {
  return renewSession().then(res => {
    if (res.outcome === 'ok') afterRenewal(res);
    else if (!(res.outcome === 'throttled' && res.previous === 'ok')) {
      // An action was refused and the silent route did not clear it; the
      // banner's sign-in is what is left (no_session is already navigating).
      if (res.outcome !== 'throttled' && res.outcome !== 'no_session') showRenewBanner('stale');
      return {retried: false};
    }
    return retry().then(value => ({retried: true, value}));
  });
}

// handleUnauthorized decides what a 401 means here. With single sign-on there
// is no token to type: the session has lapsed and the way back is the
// provider. Every 401 an SSO hub sends says so (X-Cloop-Sign-In) — asking
// /api/me is no option, since on such a hub it needs a session too. Without the
// hint, and with OIDC never seen, this is a token-only hub and the prompt is
// right.
function handleUnauthorized(r) {
  try { if (r.headers.get('X-Cloop-Sign-In')) noteAuthMode(true); } catch (_) {}
  renewState.live = false;
  clearRenewTimer();
  if (renewState.oidc) signInAgain(false);
  else showLoginModal();
}

// signInAgain sends this tab through the identity provider and back to this
// page, where resumeView reopens the project and tab. A top-level navigation,
// so the provider's own cookie is first-party: usually two redirects and no
// prompt. Automatic calls are guarded against looping; the banner's button
// (force) is a person choosing to try anyway.
function signInAgain(force) {
  let last = 0;
  try { last = Number(sessionStorage.getItem('cloop_signin_at')) || 0; } catch (_) {}
  if (!force && (renewState.redirected || Date.now() - last < RENEW.LOOP)) { showRenewBanner('lapsed'); return; }
  renewState.redirected = true;
  try {
    sessionStorage.setItem('cloop_signin_at', String(Date.now()));
    // Before boot finishes there is no view yet, only the defaults.
    if (renewState.booted) {
      sessionStorage.setItem('cloop_resume', JSON.stringify({path: selectedProjectPath, tab: activeTab, at: Date.now()}));
    }
  } catch (_) {}
  const here = window.location.pathname + window.location.search + window.location.hash;
  window.location.assign('/auth/login?return=' + encodeURIComponent(here));
}
window.signInAgain = function() { signInAgain(true); };

// resumeView reopens what the user was looking at before signInAgain took
// them away: the project, by path (indices shift), and the tab. Boot calls it
// last, so it also marks the point from which there is a view worth keeping.
function resumeView(projects) {
  renewState.booted = true;
  let saved = null;
  try {
    saved = JSON.parse(sessionStorage.getItem('cloop_resume'));
    sessionStorage.removeItem('cloop_resume');
  } catch (_) {}
  if (!saved || Date.now() - saved.at > 900000) return;
  const i = projects ? projects.findIndex(p => p.path === saved.path) : -1;
  if (saved.path && i >= 0) openProject(i, projects[i].name);
  if (saved.tab && saved.tab !== activeTab && document.getElementById('tab-' + saved.tab)) switchTab(saved.tab);
}

function showRenewBanner(reason) {
  // A session that has ended outranks a stale one: nothing works until then.
  if (renewState.banner === 'lapsed') return;
  renewState.banner = reason;
  document.getElementById('sessionRenewText').textContent = reason === 'lapsed'
    ? 'Your sign-in has ended — sign in again to continue.'
    : 'Your sign-in needs renewing — some actions will be refused until you do.';
  document.getElementById('sessionRenewBanner').style.display = 'flex';
}

function hideRenewBanner() {
  renewState.banner = '';
  document.getElementById('sessionRenewBanner').style.display = 'none';
}
