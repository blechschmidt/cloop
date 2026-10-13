// approvals_badge_scenarios.js — drives the real dashboard bundle's approvals
// badge (Task 20427) through the WebSocket broadcasts that move its count.
//
// The broadcast carries a verb and an id, never the row, so the badge's only
// source of truth is GET /api/approvals/count, asked afresh on every
// secrets_update and approvals_update and once the soonest deadline passes.
// Each scenario changes what the hub would answer, delivers the frame the hub
// would send, and records what the header shows and how often it asked.
//
// Run by TestDashboard_ApprovalsBadge* in approvals_badge_frontend_test.go.
// Usage: node approvals_badge_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

const COUNT = '/api/approvals/count';
const wait = ms => new Promise(r => setTimeout(r, ms));

async function boot(count) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.projects = {multi_project: false, stats: {}, projects: [{name: 'app', path: '/srv/app', goal: 'ship', health: 'idle'}]};
  h.routes[COUNT] = count;
  require(bundlePath);
  await globalThis.__settle(5);
  const sock = h.sockets[h.sockets.length - 1];
  sock.open();
  await settle();
  return {h, sock};
}

// settle waits out the badge's debounce and the fetch behind it.
async function settle() {
  await wait(320);
  await globalThis.__settle(5);
}

function badge() {
  const b = document.getElementById('approvalsBadge');
  return {shown: b.style.display !== 'none' && b.style.display !== undefined, text: String(b.textContent || '')};
}

function asked(h) {
  return h.requests.filter(r => String(r.url).startsWith(COUNT)).length;
}

const counted = (n, extra) => Object.assign({count: n, grant_requests: n, api_tokens: 0, mine_pending: []}, extra || {});

const scenarios = {
  // An approver's badge through a request's whole life: filed, decided; filed
  // again, withdrawn; filed again, lapsed; and a token that starts waiting.
  async badge_follows_file_decide_withdraw_lapse() {
    const {h, sock} = await boot(counted(0));
    const steps = [{step: 'connect', ...badge(), asked: asked(h)}];
    const frame = async (type, data, answer, step) => {
      h.routes[COUNT] = answer;
      sock.deliver(type, data);
      await settle();
      steps.push({step, ...badge(), asked: asked(h)});
    };
    await frame('secrets_update', {event: 'request_created', id: 'req_1'}, counted(1), 'file');
    await frame('secrets_update', {event: 'request_approved', id: 'req_1'}, counted(0), 'decide');
    await frame('secrets_update', {event: 'request_created', id: 'req_2'}, counted(1), 'file again');
    await frame('secrets_update', {event: 'request_withdrawn', id: 'req_2'}, counted(0), 'withdraw');
    await frame('secrets_update', {event: 'request_created', id: 'req_3'}, counted(1), 'file a third');
    await frame('secrets_update', {event: 'request_expired', id: ''}, counted(0), 'lapse');
    await frame('approvals_update', {event: 'token_waiting', id: '0123456789abcdef'},
      {count: 1, grant_requests: 0, api_tokens: 1, mine_pending: []}, 'token waits');
    return {steps};
  },

  // A burst of broadcasts is one question, not one each.
  async a_burst_is_asked_about_once() {
    const {h, sock} = await boot(counted(0));
    const before = asked(h);
    h.routes[COUNT] = counted(3);
    for (let i = 0; i < 5; i++) sock.deliver('secrets_update', {event: 'request_created', id: 'req_' + i});
    await settle();
    return {asked: asked(h) - before, ...badge()};
  },

  // Lease and grant churn — the bulk of secrets_update — is no question at
  // all: it moves nothing the badge counts.
  async lease_churn_is_not_asked_about() {
    const {h, sock} = await boot(counted(1));
    const before = asked(h);
    for (let i = 0; i < 5; i++) sock.deliver('secrets_update', {event: 'lease_revoked', id: 'lease_' + i});
    sock.deliver('secrets_update', {event: 'grant_created', id: 'grant_1'});
    await settle();
    return {asked: asked(h) - before, ...badge()};
  },

  // Nobody announces a lapse the moment it happens; the badge asks again once
  // the soonest deadline has passed.
  async the_soonest_deadline_is_asked_about() {
    // Far enough out to still be ahead when the boot's answer arrives.
    const soon = new Date(Date.now() + 1200).toISOString();
    const {h} = await boot(counted(1, {next_deadline: soon}));
    const before = {asked: asked(h), ...badge()};
    h.routes[COUNT] = counted(0);
    await wait(2600);
    await globalThis.__settle(5);
    return {before, after: {asked: asked(h), ...badge()}};
  },

  // A decision the dashboard made is broadcast by its handler and again by
  // the notifier that records it a moment later; the requester is told once.
  async the_answer_is_said_once() {
    const {h, sock} = await boot(counted(0, {mine_pending: ['req_9']}));
    const el = document.getElementById('toast');
    h.routes[COUNT] = counted(0);
    el.textContent = '';
    sock.deliver('secrets_update', {event: 'request_approved', id: 'req_9'});
    const mine = String(el.textContent || '');
    el.textContent = '';
    sock.deliver('approvals_update', {event: 'request_approved', id: 'req_9'});
    const other = String(el.textContent || '');
    await settle();
    return {mine, other, asked: asked(h)};
  },

  // A requester is told when the broadcast names one of their own pending
  // requests as decided, and not about anybody else's.
  async the_requester_hears_the_answer() {
    const {h, sock} = await boot(counted(0, {mine_pending: ['req_9']}));
    const toast = () => String(document.getElementById('toast').textContent || '');
    document.getElementById('toast').textContent = '';
    sock.deliver('secrets_update', {event: 'request_approved', id: 'req_other'});
    await settle();
    const other = toast();
    sock.deliver('secrets_update', {event: 'request_denied', id: 'req_9'});
    await settle();
    return {other, mine: toast(), ...badge()};
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
  process.stdout.write(JSON.stringify(out));
})();
