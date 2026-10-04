// drive.js — drives the dashboard of a live hub through the steps of the
// device firewall and feature check (Task 20371), in headless Chrome, as an
// operator would: real clicks on the Executors panel's Firewall dialog, the
// project's Network Firewall card, the New feature dialog and the pull
// request dialog.
//
// Usage:
//   node drive.js <chrome> <base-url> <project-path> <step> [args…]
// with the hub's bearer token in CLOOP_HUB_TOKEN (an API token on an SSO hub:
// it rides on every request, the page navigation included, so no sign-in is
// needed). Steps:
//   device-fw <executor-id> <cidr,cidr…> <port,port…>  save a device rule set
//   project-fw <cidr,cidr…> <port,port…>               save a project rule set
//   feature <name> <description> <task>                create a feature, start it
//   pr <feature-slug>                                  open its pull request
//   upgrade-dialog <executor-id>                       press Upgrade, report the dialog, cancel it
//   debug                                              list the project grid
// Prints one JSON document on stdout describing what the page showed.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const [CHROME, BASE, PROJECT, STEP, ...ARGS] = process.argv.slice(2);
const TOKEN = process.env.CLOOP_HUB_TOKEN || '';
const sleep = ms => new Promise(r => setTimeout(r, ms));

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.events = [];
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) { this.events.push(msg); return; }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 30000);
      this.pending.set(id, {resolve, reject, timer});
      this.ws.send(JSON.stringify({id, method, params: params || {}}));
    });
  }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', {expression: expr, awaitPromise: true, returnByValue: true});
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-drive-'));
  // Its own process group, killed whole: helpers left behind keep writing into
  // a profile that is being deleted.
  const proc = spawn(CHROME, ['--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir,
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--window-size=1400,1000', 'about:blank'],
  {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });
  const kill = () => { try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) { /* gone */ } };
  try {
    let port = 0;
    for (let i = 0; i < 600 && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(path.join(dir, 'DevToolsActivePort'), 'utf8').split('\n');
        if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
      } catch (_) { /* not yet */ }
    }
    if (!port) throw new Error('chrome reported no debugging port: ' + stderr);
    const list = await (await fetch('http://127.0.0.1:' + port + '/json/list', {signal: AbortSignal.timeout(15000)})).json();
    const page = list.find(t => t.type === 'page');
    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      const timer = setTimeout(() => rej(new Error('cdp connect timed out')), 15000);
      ws.addEventListener('open', () => { clearTimeout(timer); res(); }, {once: true});
      ws.addEventListener('error', () => { clearTimeout(timer); rej(new Error('cdp connect failed')); }, {once: true});
    });
    return {cdp: new CDP(ws), kill, dir};
  } catch (e) {
    kill();
    throw e;
  }
}

const visible = sel => `(() => { const e = document.querySelector(${JSON.stringify(sel)});
  return !!e && e.getClientRects().length > 0; })()`;

async function waitFor(cdp, expr, what, ms = 60000) {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await cdp.eval(expr)) return;
    if (Date.now() > deadline) throw new Error('timed out waiting for ' + what);
    await sleep(100);
  }
}

// click lands a real mouse click on the element's centre, once it is laid out
// and on top.
async function click(cdp, sel) {
  let pt = null, hit = false;
  for (let i = 0; i < 200 && !hit; i++) {
    if (i) await sleep(50);
    pt = await cdp.eval(`(() => { const e = document.querySelector(${JSON.stringify(sel)});
      if (!e) return null; e.scrollIntoView({block: 'center'}); const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null; return {x: r.left + r.width / 2, y: r.top + r.height / 2}; })()`);
    if (!pt) continue;
    hit = await cdp.eval(`(() => { const e = document.elementFromPoint(${pt.x}, ${pt.y});
      const w = document.querySelector(${JSON.stringify(sel)}); return !!e && !!w && (e === w || w.contains(e)); })()`);
  }
  if (!pt || !hit) throw new Error('could not click ' + sel);
  for (const type of ['mousePressed', 'mouseReleased']) {
    await cdp.send('Input.dispatchMouseEvent', {type, x: pt.x, y: pt.y, button: 'left', clickCount: 1});
  }
}

// type replaces a field's contents the way a person does: click into it,
// select what is there, type over it.
async function type(cdp, sel, text) {
  await click(cdp, sel);
  await cdp.eval(`document.querySelector(${JSON.stringify(sel)}).select()`);
  if (text) {
    await cdp.send('Input.insertText', {text});
  } else {
    for (const t of ['keyDown', 'keyUp']) {
      await cdp.send('Input.dispatchKeyEvent', {type: t, key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8});
    }
  }
}

const text = (cdp, sel) => cdp.eval(`((document.querySelector(${JSON.stringify(sel)}) || {}).textContent || '').trim()`);
const toasts = cdp => cdp.eval(`[...document.querySelectorAll('.toast')].map(t => t.textContent.trim())`);

async function boot(cdp) {
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Network.enable');
  if (TOKEN) {
    await cdp.send('Network.setExtraHTTPHeaders', {headers: {Authorization: 'Bearer ' + TOKEN}});
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_token', ${JSON.stringify(TOKEN)}); } catch (e) {}`,
    });
  }
  await cdp.send('Page.navigate', {url: BASE + '/'});
  await waitFor(cdp, `typeof window.openNewFeatureModal === 'function' && typeof window.openProject === 'function'`,
    'the dashboard bundle');
  await waitFor(cdp, `!!window._lastProjectsData && (window._lastProjectsData.projects || []).length > 0`, 'the project list');
}

const projectIdx = (cdp, p) => cdp.eval(`(window._lastProjectsData.projects || []).findIndex(x => x.path === ${JSON.stringify(p)})`);

async function openProject(cdp, p) {
  await waitFor(cdp, `(window._lastProjectsData.projects || []).some(x => x.path === ${JSON.stringify(p)})`, p + ' in the list');
  const i = await projectIdx(cdp, p);
  const name = await cdp.eval(`window._lastProjectsData.projects[${i}].name`);
  const cut = p.indexOf('/.cloop/features/');
  if (cut > 0) {
    // A feature is reached through its project: the row in its Features panel.
    await openProject(cdp, p.slice(0, cut));
    await click(cdp, `#featuresList .feat-row[data-idx="${i}"] button[data-act="open"]`);
    await waitFor(cdp, `(document.getElementById('breadcrumbName') || {}).textContent === ${JSON.stringify(name)}`, 'the feature to open');
    return {i, name};
  }
  await cdp.eval(`window.switchTab('projects')`);
  const card = `#projList .proj-card[onclick^="openProject(${i},"]`;
  // A project whose tasks are all done is off the grid until Show completed.
  await waitFor(cdp, `!!document.querySelector('#projList .proj-card, #projList .empty-state')`, 'the project grid');
  if (!(await cdp.eval(`!!document.querySelector(${JSON.stringify(card)})`))
      && (await text(cdp, '#toggleCompletedProjectsBtn')).startsWith('Show completed')) {
    await click(cdp, '#toggleCompletedProjectsBtn');
  }
  await click(cdp, card);
  await waitFor(cdp, `(document.getElementById('breadcrumbName') || {}).textContent === ${JSON.stringify(name)}`, 'the project to open');
  return {i, name};
}

const result = {step: STEP};

async function stepDeviceFirewall(cdp, exID, cidrs, ports) {
  await cdp.eval(`window.switchTab('executors')`);
  await waitFor(cdp, `document.querySelectorAll('button[onclick^="openExecutorFirewall("]').length > 0`, 'the Executors panel');
  // The device's own card: the smallest ancestor of a Firewall button that
  // names the device (by ID or name) and holds no other card's button.
  const sel = await cdp.eval(`(() => {
    for (const b of document.querySelectorAll('button[onclick^="openExecutorFirewall("]')) {
      let c = b.parentElement;
      while (c && !c.textContent.includes(${JSON.stringify(exID)})) c = c.parentElement;
      if (c && c.querySelectorAll('button[onclick^="openExecutorFirewall("]').length === 1) {
        return 'button[onclick="' + b.getAttribute('onclick') + '"]';
      }
    }
    return null; })()`);
  if (!sel) throw new Error('no Firewall button on a card naming ' + exID);
  await click(cdp, sel);
  await waitFor(cdp, visible('#efwAllow'), 'the device firewall form');
  if (await cdp.eval(`document.getElementById('efwPub').checked`)) await click(cdp, '#efwPub');
  await type(cdp, '#efwAllow', cidrs.split(',').join('\n'));
  await type(cdp, '#efwDeny', '');
  await type(cdp, '#efwPorts', ports);
  await type(cdp, '#efwDns', '');
  result.summary_before_save = await text(cdp, '#efwSum');
  await cdp.eval(`document.getElementById('efwAllow').dataset.before = '1'`);
  await click(cdp, '#efwBody .modal-footer .btn.primary');
  await waitFor(cdp, `((document.getElementById('efwWarn') || {}).textContent || '').length > 0
    || !(document.getElementById('efwAllow') || {dataset: {before: '1'}}).dataset.before`, 'the save to answer');
  result.saved = await cdp.eval(`!(document.getElementById('efwAllow') || {dataset: {before: '1'}}).dataset.before`);
  result.refusal = await text(cdp, '#efwWarn');
  result.dialog = (await text(cdp, '#efwBody')).slice(0, 600);
  result.toasts = await toasts(cdp);
}

async function stepProjectFirewall(cdp, cidrs, ports) {
  await openProject(cdp, PROJECT);
  await waitFor(cdp, visible('#pfwAllow'), 'the Network Firewall card');
  result.governing = await text(cdp, '#pfwGov');
  await type(cdp, '#pfwAllow', cidrs.split(',').join('\n'));
  await type(cdp, '#pfwPorts', ports);
  result.summary_before_save = await text(cdp, '#pfwSum');
  // A saved rule set re-renders the form; a refused one keeps it and says why.
  await cdp.eval(`document.getElementById('pfwAllow').dataset.before = '1'`);
  await click(cdp, '#projectFirewallBody .modal-footer .btn.primary');
  await waitFor(cdp, `((document.getElementById('pfwWarn') || {}).textContent || '').length > 0
    || !(document.getElementById('pfwAllow') || {dataset: {before: '1'}}).dataset.before`, 'the save to answer');
  result.saved = await cdp.eval(`!(document.getElementById('pfwAllow') || {dataset: {before: '1'}}).dataset.before`);
  result.refusal = await text(cdp, '#pfwWarn');
  result.state = await text(cdp, '#pfwState');
  result.toasts = await toasts(cdp);
}

async function stepFeature(cdp, name, desc, task) {
  const {name: parent} = await openProject(cdp, PROJECT);
  await waitFor(cdp, visible('#newFeatureBtn'), 'the New feature button');
  await click(cdp, '#newFeatureBtn');
  await waitFor(cdp, visible('#newfeat-overlay'), 'the New feature dialog');
  await type(cdp, '#nfName', name);
  result.branch_hint = await text(cdp, '#nfSlug');
  await type(cdp, '#nfDesc', desc);
  await type(cdp, '#nfTasks', task);
  result.start_now = await cdp.eval(`document.getElementById('nfStart').checked`);
  if (!result.start_now) await click(cdp, '#nfStart');
  await click(cdp, '#nfSubmit');
  await waitFor(cdp, `((document.getElementById('breadcrumbName') || {}).textContent || '').startsWith(${JSON.stringify(parent + '/')})
    || ((document.getElementById('nfError') || {}).textContent || '').length > 0`, 'the feature to open', 120000);
  result.error = await text(cdp, '#nfError');
  result.crumb = await text(cdp, '#breadcrumbName');
  await waitFor(cdp, visible('#featureBanner'), 'the feature banner').catch(() => {});
  result.banner = (await text(cdp, '#featureBanner')).slice(0, 300);
  await sleep(3000);
  result.toasts = await toasts(cdp);
}

async function stepPR(cdp, slug) {
  const p = PROJECT + '/.cloop/features/' + slug;
  await openProject(cdp, p);
  await waitFor(cdp, visible('#featureBanner [data-act="pr"]'), 'the Open pull request button');
  await click(cdp, '#featureBanner [data-act="pr"]');
  await waitFor(cdp, visible('#featpr-overlay'), 'the pull request dialog');
  result.title = await cdp.eval(`document.getElementById('fprName').value`);
  await click(cdp, '#fprSubmit');
  await waitFor(cdp, `!(${visible('#featpr-overlay')}) || ((document.querySelector('#featpr-overlay .form-error, #fprError') || {}).textContent || '').length > 0`,
    'the pull request to open', 180000);
  result.dialog_error = await text(cdp, '#fprError');
  await sleep(2000);
  result.toasts = await toasts(cdp);
  result.banner = (await text(cdp, '#featureBanner')).slice(0, 400);
  result.pr_links = await cdp.eval(`[...document.querySelectorAll('#featureBanner a, #featuresList a')].map(a => a.href)`);
}

// stepUpgradeDialog presses Upgrade on the device's card and reports the
// dialog the dashboard opened — an alert carrying the hub's explanation when no
// release would move the device forward, or a prompt prefilled with the release
// it offers — then dismisses it, so nothing is sent.
async function stepUpgradeDialog(cdp, exID) {
  await cdp.eval(`window.switchTab('executors')`);
  await waitFor(cdp, `document.querySelectorAll('button[onclick^="upgradeExecutor("]').length > 0`, 'the Executors panel');
  const sel = await cdp.eval(`(() => {
    for (const b of document.querySelectorAll('button[onclick^="upgradeExecutor("]')) {
      let c = b.parentElement;
      while (c && !c.textContent.includes(${JSON.stringify(exID)})) c = c.parentElement;
      if (c && c.querySelectorAll('button[onclick^="upgradeExecutor("]').length === 1) {
        return 'button[onclick="' + b.getAttribute('onclick') + '"]';
      }
    }
    return null; })()`);
  if (!sel) throw new Error('no Upgrade button on a card naming ' + exID);
  cdp.events.length = 0;
  // Not awaited first: the dialog blocks the page, and the click's own answer
  // arrives only once the dialog is handled.
  const clicking = click(cdp, sel).catch(() => {});
  const deadline = Date.now() + 15000;
  let dlg = null;
  while (!dlg && Date.now() < deadline) {
    dlg = cdp.events.find(e => e.method === 'Page.javascriptDialogOpening');
    if (!dlg) await sleep(100);
  }
  if (!dlg) throw new Error('pressing Upgrade opened no dialog');
  result.dialog_type = dlg.params.type;
  result.message = dlg.params.message;
  result.default_prompt = dlg.params.defaultPrompt || '';
  await cdp.send('Page.handleJavaScriptDialog', {accept: false});
  await clicking;
}

async function main() {
  const {cdp, kill, dir} = await launchChrome();
  try {
    await boot(cdp);
    switch (STEP) {
      case 'device-fw': await stepDeviceFirewall(cdp, ARGS[0], ARGS[1], ARGS[2]); break;
      case 'project-fw': await stepProjectFirewall(cdp, ARGS[0], ARGS[1]); break;
      case 'feature': await stepFeature(cdp, ARGS[0], ARGS[1], ARGS[2]); break;
      case 'pr': await stepPR(cdp, ARGS[0]); break;
      case 'upgrade-dialog': await stepUpgradeDialog(cdp, ARGS[0]); break;
      case 'debug':
        await cdp.eval(`window.switchTab('projects')`);
        await sleep(2500);
        result.cards = await cdp.eval(`[...document.querySelectorAll('.proj-card')].map(c =>
          [c.parentElement && c.parentElement.id, c.getAttribute('onclick'), c.getClientRects().length])`);
        result.projects = await cdp.eval(`(window._lastProjectsData.projects || []).map(p => [p.name, p.path])`);
        break;
      default: throw new Error('unknown step ' + STEP);
    }
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } finally {
    kill();
    try { fs.rmSync(dir, {recursive: true, force: true}); } catch (_) { /* best effort */ }
  }
}

main().catch(err => {
  process.stdout.write(JSON.stringify({error: String(err && err.message || err), partial: result}, null, 2) + '\n');
  process.exit(1);
});
