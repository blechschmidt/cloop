// telemetry_consent_scenarios.js — does the reporter ask before it sends?
// (Task 20311)
//
// Collection is off unless an operator switched it on, and the property that
// makes "off" mean anything is that the browser never transmits the trail in
// the first place. A page that posted and let the hub answer 404 would already
// have sent it — over the network, into whatever sits in between — on exactly
// the hub that wanted none of it.
//
// That is behaviour, not text: it is about which request is issued, in what
// order, and what is in the body. So this runs the real errboundary.js against
// the DOM shim and reads the request log back, rather than grepping the source
// for a URL.
//
// Usage: node telemetry_consent_scenarios.js <domshim.js> <errboundary.js>

'use strict';

const shimPath = process.argv[2];
const boundaryPath = process.argv[3];

// run loads a fresh shim and a fresh reporter, answers the consent probe with
// `policy` (or fails it when `status` is set), records one event, and reports
// every request the page made.
async function run(policy, status) {
  delete require.cache[require.resolve(shimPath)];
  require(shimPath);
  const h = globalThis.__harness;

  if (policy !== null) {
    h.routes['/api/telemetry/config'] = policy;
  }
  if (status) {
    h.routeStatus['/api/telemetry/config'] = status;
  }

  // The boundary guards against double installation, and require() caches, so
  // both have to be cleared for a second scenario in the same process.
  delete globalThis.__cloopErrBoundaryInstalled;
  delete require.cache[require.resolve(boundaryPath)];
  require(boundaryPath);

  // now:true is the immediate-flush path an error takes; without it the
  // reporter waits 5s for its idle timer and the scenario would prove nothing
  // about ordering.
  globalThis.cloopTelemetry.record('note', 'the-recorded-event', {now: true});
  await globalThis.__settle(12);

  // A second event, to catch a reporter that asks once and then sends anyway.
  globalThis.cloopTelemetry.record('note', 'the-second-event', {now: true});
  await globalThis.__settle(12);

  return h.requests.map(r => ({
    url: r.url,
    method: r.method,
    // Only whether the payload carried the event: the full body is noise here
    // and would make the assertion fragile against an unrelated field.
    carriesEvent: !!(r.body && String(r.body).indexOf('the-recorded-event') !== -1),
  }));
}

(async () => {
  const out = {};
  try {
    out.collecting = await run({source: 'dashboard', collect: true});
    out.refused = await run({source: 'dashboard', collect: false});
    out.probe_failed = await run({source: 'dashboard', collect: true}, 500);
    out.no_policy_route = await run(null);
  } catch (e) {
    out.error = (e && e.stack) || String(e);
  }
  process.stdout.write(JSON.stringify(out, null, 2));
})();
