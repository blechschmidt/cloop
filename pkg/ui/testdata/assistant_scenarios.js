// assistant_scenarios.js — drives the real dashboard bundle through how the
// plan assistant shows a request refused before its stream starts (Task 20442).
//
// The assistant's model call runs on the project's executor now, so it can be
// refused the way a run is: a sandbox with no Claude login answers 409
// harness_credential_missing, strict mode with nowhere isolating to go a 409
// naming allow_host_process. Both are JSON. The bubble used to show the raw
// body; it shows the reason, and the first opens the dialog that grants a
// credential, as every other dispatch's refusal does.
//
// Run by TestDashboard_AssistantRefusals. Each scenario returns a plain
// object; the Go side asserts on it. Printed as one JSON document.
//
// Usage: node assistant_scenarios.js <domshim.js> <bundle.js>

'use strict';

const shimPath = process.argv[2];
const bundlePath = process.argv[3];

async function boot(route, status) {
  for (const k of Object.keys(require.cache)) delete require.cache[k];
  require(shimPath);
  const h = globalThis.__harness;
  h.states = {0: {goal: 'g', status: 'idle', plan: {goal: 'g', tasks: []}}};
  h.routes['/api/chat/plan'] = route;
  h.routeStatus['/api/chat/plan'] = status;
  require(bundlePath);
  await globalThis.__settle(5);
  return h;
}

// lastBubble is the assistant's answer as the page shows it.
function lastBubble() {
  const box = document.getElementById('assistantMessages');
  const rows = (box.children || []).filter(r => String(r.className || '').indexOf('assistant') >= 0);
  const row = rows[rows.length - 1];
  if (!row) return null;
  // row → [avatar, inner]; inner → [bubble, time].
  const bubble = row.children[1].children[0];
  return {text: String(bubble.textContent || ''), error: bubble.classList.contains('error')};
}

async function ask(h) {
  // The tab is a deferred panel (Task 20456): fetched the way opening it
  // fetches it, then sent the way its Send button sends.
  const P = await window.panelAct('assistant');
  document.getElementById('assistantInput').value = 'What is next?';
  await P.submit();
  await globalThis.__settle(5);
  return {
    bubble: lastBubble(),
    toast: String(document.getElementById('toast').textContent || ''),
    posted: h.requests.filter(r => r.method === 'POST' && r.url.indexOf('/api/chat/plan') >= 0).length,
  };
}

async function main() {
  const out = {};

  // 1. No Claude login where the project runs: the reason in the bubble, and
  //    the short toast that comes with the credential dialog.
  {
    const h = await boot({error: 'No active grant gives the sandbox a Claude credential.',
      code: 'harness_credential_missing'}, 409);
    out.harness_refusal = await ask(h);
  }

  // 2. Any other refusal: its reason, not its JSON, and no credential dialog.
  {
    const h = await boot({error: 'executor: host execution is disabled by policy (executors.allow_host_process: false)',
      code: 'host_execution_denied'}, 409);
    out.policy_refusal = await ask(h);
  }

  process.stdout.write(JSON.stringify(out));
}

main().catch(e => {
  process.stdout.write(JSON.stringify({fatal: {error: String(e && e.stack || e)}}));
  process.exit(1);
});
