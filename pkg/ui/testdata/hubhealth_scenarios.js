// hubhealth_scenarios.js — drives the real dashboard bundle's hub health
// indicator and its deferred Settings panel (Task 20434).
//
// The indicator's only source is GET /api/hub/health?summary=1, asked once
// /api/me has said the caller holds config.write across the hub, again when
// the hub pushes hub_health (which carries nothing) or the socket reconnects,
// and once the report it last read expires. A caller without the permission
// never asks at all. The panel renders what a check wrote as text.
//
// Run by TestDashboard_HubHealth* in hubhealth_frontend_test.go.
// Usage: node hubhealth_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const HEALTH = '/api/hub/health';
const wait = ms => new Promise(r => setTimeout(r, ms));

const ADMIN = {oidc_enabled: true, authenticated: true, role: 'admin',
  permissions: ['project.read', 'config.write'], global_permissions: ['project.read', 'config.write', 'executor.read']};
const VIEWER = {oidc_enabled: true, authenticated: true, role: 'viewer',
  permissions: ['project.read'], global_permissions: ['project.read', 'executor.read']};

const later = ms => new Date(Date.now() + ms).toISOString();
// The hub's clock is an hour behind the page's: the indicator must time the
// report's expiry by the hub's, from served_at, or it never asks again.
const HUB_SKEW = -3600000;
const hubTime = ms => new Date(Date.now() + HUB_SKEW + ms).toISOString();
const summary = (failing, expiresIn) => ({failing, counts: {pass: 3, warn: 1, fail: failing},
  checked_at: hubTime(0), served_at: hubTime(0), expires_at: hubTime(expiresIn || 600000)});

async function boot(me, answer, status) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = {multi_project: false, stats: {}, projects: [{name: 'app', path: '/srv/app', goal: 'ship', health: 'idle'}]};
  h.me = me;
  h.routes[HEALTH] = answer;
  if (status) h.routeStatus[HEALTH] = status;
  require(bundlePath);
  await globalThis.__settle(5);
  const sock = h.sockets[h.sockets.length - 1];
  sock.open();
  // /api/me is read on DOMContentLoaded, which the shim never fires; returning
  // to the project list reads it too. Both reasons land inside one debounce.
  window.clearProjectSelection();
  await settle();
  return {h, sock};
}

// settle waits out the indicator's debounce and the fetch behind it.
async function settle() {
  await wait(320);
  await globalThis.__settle(5);
}

function badge() {
  const b = document.getElementById('hubHealthBadge');
  return {shown: b.style.display !== 'none' && b.style.display !== undefined, text: String(b.textContent || ''),
    label: b.getAttribute('aria-label')};
}

const asked = h => h.requests.filter(r => String(r.url).startsWith(HEALTH)).length;
const askedFull = h => h.requests.filter(r => String(r.url) === HEALTH || String(r.url).startsWith(HEALTH + '?fresh')).length;

// The full report the panel draws, with what a hostile configuration or a
// careless check could put in it.
const MARKUP = '<img src=x onerror="window.__xss=1">';
const REPORT = {
  member: {id: 'hub-a1b2', hostname: 'hub-01.internal', port: 8081, clustered: true, leader: false},
  checked_at: new Date().toISOString(), served_at: new Date().toISOString(), expires_at: later(600000), duration_ms: 1234,
  config: {files: ['.cloop/config.yaml', '.cloop/config.ui-8081.yaml']},
  counts: {pass: 1, warn: 1, fail: 1}, failing: 1,
  findings: [
    {check: 'hubca.expiry', title: 'Hub certificate authority ' + MARKUP, severity: 'fail',
      message: 'the hub CA expires at ' + MARKUP, remediation: 'Plan the replacement ' + MARKUP,
      details: {names: ['a.example', MARKUP], nested: {k: MARKUP}},
      docs: 'https://blechschmidt.github.io/cloop/docs/operations/runbook/#doctor-gitproxy'},
    {check: 'audit.forward.lag', title: 'Audit forwarding', severity: 'warn', message: 'sink siem is 20 minutes behind',
      remediation: 'Check the sink', docs: 'javascript:window.__xss=2'},
    {check: 'policy.host_execution', title: 'Host execution policy', severity: 'pass', message: 'strict',
      docs: 'https://blechschmidt.github.io/cloop/docs/operations/runbook/#doctor-policy'},
  ],
  steps: [{id: 'policy', title: 'Host execution policy', outcome: 'finished', duration_ms: 1}],
  not_run: [{check: 'smoke', why: 'starts a workload', command: 'cloop hub doctor --smoke --port 8081'}],
};

const scenarios = {
  // An administrator's indicator: asked once at load, lit with the failing
  // count; a push that brings an all-clear report puts it out.
  async admin_indicator_follows_the_report() {
    const {h, sock} = await boot(ADMIN, summary(2));
    const first = {...badge(), asked: asked(h)};
    h.routes[HEALTH] = summary(0);
    sock.deliver('hub_health', {});
    await settle();
    return {first, after: {...badge(), asked: asked(h)}};
  },

  // A caller without config.write never asks — not at load, not on a push,
  // not on a reconnect — and never sees the indicator.
  async viewer_never_asks() {
    const {h, sock} = await boot(VIEWER, summary(3));
    sock.deliver('hub_health', {});
    await settle();
    sock.open();
    await settle();
    return {...badge(), asked: asked(h)};
  },

  // Nobody announces that a report has expired; the indicator asks again
  // once it has, by the hub's clock.
  async the_expiry_is_asked_about() {
    const {h} = await boot(ADMIN, summary(1, 1200));
    const before = {...badge(), asked: asked(h)};
    h.routes[HEALTH] = summary(4, 600000);
    for (let i = 0; i < 80 && asked(h) < 2; i++) await wait(50);
    await settle();
    return {before, after: {...badge(), asked: asked(h)}};
  },

  // A hub that cannot answer — a 500, a dropped connection — is asked again
  // a minute later rather than never; the shim's clock is not waited out, the
  // timer is read.
  async a_failed_answer_is_retried() {
    const real = globalThis.setTimeout, delays = [];
    globalThis.setTimeout = (fn, ms, ...a) => { delays.push(ms); return real(fn, ms, ...a); };
    try {
      const {h} = await boot(ADMIN, {error: 'internal error'}, 500);
      return {...badge(), asked: asked(h), retry: delays.includes(6e4)};
    } finally {
      globalThis.setTimeout = real;
    }
  },

  // A refusal re-reads /api/me, which still says the same; that must not ask
  // for the report again, or a disagreement would loop.
  async a_refusal_is_not_asked_again() {
    const {h} = await boot(ADMIN, {error: {code: 'FORBIDDEN', message: 'not permitted'}}, 403);
    await wait(1200);
    await globalThis.__settle(5);
    return {...badge(), asked: asked(h)};
  },

  // The header's indicator opens Settings → Hub health, which draws the full
  // report: grouped by severity, every value as text, a documentation link
  // only where it is one.
  async the_indicator_opens_the_panel() {
    const {h} = await boot(ADMIN, REPORT);
    const el = {dataset: {action: 'openHubHealth'}, disabled: false};
    document.dispatchEvent({type: 'click', target: {closest: sel => (sel === '[data-action]' ? el : null), dataset: {}}});
    for (let i = 0; i < 20 && !String(document.getElementById('hubHealthBody').innerHTML).includes('Failing'); i++) {
      await wait(50);
      await globalThis.__settle(3);
    }
    return {
      html: String(document.getElementById('hubHealthBody').innerHTML),
      status: String(document.getElementById('hubHealthStatus').textContent || ''),
      full: askedFull(h), xss: globalThis.__xss || null,
    };
  },
};

(async () => {
  const out = {};
  for (const [name, fn] of Object.entries(scenarios)) {
    try {
      out[name] = await fn();
    } catch (e) {
      out[name] = {error: String((e && e.stack) || e)};
    }
  }
  // The indicator's expiry timers would keep node alive for as long as the
  // reports said they last.
  process.stdout.write(JSON.stringify(out), () => process.exit(0));
})();
