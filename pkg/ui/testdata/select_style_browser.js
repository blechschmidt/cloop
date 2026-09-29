// select_style_browser.js — measures what the dashboard's <select> boxes look
// like and how their open picker behaves, in a real browser (Task 20355).
//
// Why a browser and not testdata/domshim.js: every fact below is computed
// style, layout or keyboard focus. The shim resolves no CSS, lays nothing out
// and has no <select> picker, so it would report every select as "styled" and
// every key as handled.
//
// The facts, gathered here and judged by select_style_browser_test.go:
//
//   * styles    — every <select> in the served page, plus the class variants
//                 that only JavaScript renders (the GitHub App panel's
//                 `.input`), in both themes: appearance, colours against the
//                 theme's own custom properties, the chevron, and the root's
//                 color-scheme, which is what themes the parts CSS cannot reach.
//   * heights   — a select beside a text input of the same family, an empty
//                 select (the Replay tab's before any task finished), and a
//                 select whose label is far wider than the box.
//   * picker    — where the browser supports appearance: base-select, the open
//                 list's own colours, and that it is really open.
//   * keyboard  — the open picker moves focus onto an <option>, so keys typed
//                 into it reach the page's global shortcut handler. Letters and
//                 digits must stay type-ahead, and Escape must close the picker
//                 without also closing the dialog behind it.
//
// Usage: node select_style_browser.js <chrome-binary> <base-url>
// Prints one JSON document on stdout.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];

// The fixture dialog: static markup, openable with no project or backend data,
// and its first field after the text inputs is a select with a change handler
// (npProvider refills npModel), so a keyboard pick can be seen to land.
const OVERLAY = 'new-project-overlay';
const SELECT_ID = 'npProvider';

const sleep = ms => new Promise(r => setTimeout(r, ms));

// WAIT_MS bounds each wait for a page condition below. It is how long to keep
// looking before reporting what is there, never a pause a healthy run sits out:
// under -race on a loaded runner a first paint takes seconds (Task 20344).
const WAIT_MS = 30000;

// ── a minimal CDP client ────────────────────────────────────────────────────

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) return;
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, {resolve, reject});
      this.ws.send(JSON.stringify({id, method, params: params || {}}));
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
    });
  }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', {
      expression: expr, awaitPromise: true, returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }

  // ── input ──
  //
  // A printable key needs `text`, or the browser treats it as a bare key press
  // with nothing typed — which would not exercise the picker's type-ahead at
  // all, and so could not show a shortcut handler stealing it.
  async key(key, code, vk, text) {
    const base = {key, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk};
    if (text) {
      await this.send('Input.dispatchKeyEvent', Object.assign({type: 'keyDown', text, unmodifiedText: text}, base));
    } else {
      await this.send('Input.dispatchKeyEvent', Object.assign({type: 'rawKeyDown'}, base));
    }
    await this.send('Input.dispatchKeyEvent', Object.assign({type: 'keyUp'}, base));
    await sleep(15);
  }
  escape() { return this.key('Escape', 'Escape', 27); }
  async clickAt(x, y) {
    const base = {x, y, button: 'left', clickCount: 1};
    await this.send('Input.dispatchMouseEvent', Object.assign({type: 'mousePressed'}, base));
    await this.send('Input.dispatchMouseEvent', Object.assign({type: 'mouseReleased'}, base));
    await sleep(15);
  }
}

async function launchChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-selectstyle-'));
  const proc = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + dir,
    // Same reasoning as testdata/overlay_browser.js: this suite runs as root on
    // the project's dev box and unprivileged in CI, and the profile is a
    // throwaway loading only a local httptest server.
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1280,900',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  // A launch that fails after the spawn must take Chrome with it, or node never
  // exits and the Go test hangs until the package timeout (Task 20340).
  try {
    const portFile = path.join(dir, 'DevToolsActivePort');
    let port = 0;
    for (let i = 0; i < 600 && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(portFile, 'utf8').split('\n');
        if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
      } catch (e) { /* not written yet */ }
    }
    if (!port) throw new Error('chrome never reported a debugging port within 30s: ' + stderr);
    return {proc, port, dir};
  } catch (e) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
    throw e;
  }
}

async function connect(port) {
  const res = await fetch('http://127.0.0.1:' + port + '/json/list', {signal: AbortSignal.timeout(15000)});
  const targets = await res.json();
  const page = targets.find(t => t.type === 'page');
  if (!page) throw new Error('no page target');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((ok, bad) => {
    setTimeout(() => bad(new Error('cdp connect timed out')), 15000).unref();
    ws.addEventListener('open', ok, {once: true});
    ws.addEventListener('error', () => bad(new Error('CDP socket failed')), {once: true});
  });
  return new CDP(ws);
}

// waitFor polls a page expression until it is truthy or WAIT_MS passes, and
// says which. It does not throw: what it waits on is also measured, and the Go
// test's assertion on that measurement explains a failure better than a
// timeout would.
async function waitFor(cdp, expr) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    try {
      if (await cdp.eval(expr)) return true;
    } catch (e) { /* navigating or not yet defined */ }
    if (Date.now() > deadline) return false;
    await sleep(50);
  }
}

// ── page-side measurements ──────────────────────────────────────────────────

// FIXTURE adds what index.html does not contain: the selects only JavaScript
// renders (32-githubapp.js builds them with class "input"), an empty select,
// one with a label far wider than its box, and a text input of each family to
// compare heights against. It sits in <main>, so it inherits what a real panel
// would.
const FIXTURE = `(() => {
  const old = document.getElementById('ssFixture');
  if (old) old.remove();
  const box = document.createElement('div');
  box.id = 'ssFixture';
  box.innerHTML =
    '<div style="display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap">' +
      '<select id="ssForm" class="form-select" style="width:200px"><option>claudecode</option></select>' +
      '<input id="ssFormInput" class="form-input" style="width:200px" value="text">' +
      '<select id="ssEmpty" class="form-select" style="width:200px"></select>' +
      '<select id="ssGh" class="input" style="max-width:150px"><option>Read only</option><option>Read and write</option></select>' +
      '<input id="ssGhInput" class="input" style="width:200px" value="text">' +
      '<select id="ssFilter" class="filter-select"><option>Any</option></select>' +
      '<select id="ssLong" class="filter-select"><option>someone-with-a-very-long-assignee-name@example.com</option></select>' +
    '</div>';
  document.querySelector('main').prepend(box);
  return true;
})()`;

// STYLES reports every select in the document against the theme's own tokens,
// resolved through a probe element so a custom property like `#0d1117` comes
// back in the same rgb() form getComputedStyle uses for the select.
const STYLES = `(() => {
  const probe = document.createElement('span');
  document.body.appendChild(probe);
  const token = name => { probe.style.color = 'var(' + name + ')'; return getComputedStyle(probe).color; };
  const tokens = {bg: token('--bg'), border: token('--border'), text: token('--text'),
                  surface: token('--surface'), accent: token('--accent'), muted: token('--muted')};
  probe.style.borderRadius = 'var(--radius)';
  tokens.radius = getComputedStyle(probe).borderTopLeftRadius;
  probe.remove();
  const bodyFont = getComputedStyle(document.body).fontFamily;
  const selects = [...document.querySelectorAll('select')].map(s => {
    const cs = getComputedStyle(s);
    return {
      id: s.id || '', cls: s.className || '', multiple: s.multiple,
      appearance: cs.appearance,
      background: cs.backgroundColor,
      background_image: cs.backgroundImage,
      border: cs.borderTopColor,
      color: cs.color,
      radius: cs.borderTopLeftRadius,
      padding_right: parseFloat(cs.paddingRight) || 0,
      font_family: cs.fontFamily,
    };
  });
  return {
    theme: document.documentElement.getAttribute('data-theme') || '',
    color_scheme: getComputedStyle(document.documentElement).colorScheme,
    body_font: bodyFont,
    tokens, selects,
  };
})()`;

const HEIGHTS = `(() => {
  const h = id => { const e = document.getElementById(id); return e ? Math.round(e.getBoundingClientRect().height * 10) / 10 : -1; };
  const long = document.getElementById('ssLong');
  const lcs = getComputedStyle(long);
  return {
    form_select: h('ssForm'), form_input: h('ssFormInput'), empty_select: h('ssEmpty'),
    gh_select: h('ssGh'), gh_input: h('ssGhInput'),
    filter_select: h('ssFilter'), long_select: h('ssLong'),
    long_width: Math.round(long.getBoundingClientRect().width),
    long_max_width: lcs.maxWidth,
  };
})()`;

// ── scenarios ───────────────────────────────────────────────────────────────

async function run(cdp) {
  const out = {};

  await cdp.eval(FIXTURE);
  out.styles = [];
  // getComputedStyle recalculates on the spot, so a theme switch needs no wait.
  for (const theme of ['dark', 'light']) {
    await cdp.eval(`document.documentElement.setAttribute('data-theme', '${theme}'), true`);
    out.styles.push(await cdp.eval(STYLES));
  }
  await cdp.eval(`document.documentElement.setAttribute('data-theme', 'dark'), true`);
  out.heights = await cdp.eval(HEIGHTS);
  await cdp.eval(`document.getElementById('ssFixture').remove(), true`);

  // Whether this browser draws the customizable picker at all. Where it does
  // not, the picker and keyboard facts below have nothing to measure: the list
  // is the platform's own popup, which no page key handler ever sees.
  out.base_select = await cdp.eval(`(() => {
    const s = document.getElementById('${SELECT_ID}');
    return {
      css_supports: !!(window.CSS && CSS.supports && CSS.supports('appearance', 'base-select')),
      applied: !!s && getComputedStyle(s).appearance === 'base-select',
    };
  })()`);
  if (!out.base_select.applied) return out;

  await cdp.eval(`window.openNewProjectModal(), true`);
  await waitFor(cdp, `window.isOverlayOpen('${OVERLAY}')`);
  const isOpen = `document.getElementById('${SELECT_ID}').matches(':open')`;
  const open = async () => {
    const pt = await cdp.eval(`(() => {
      const s = document.getElementById('${SELECT_ID}');
      s.scrollIntoView({block: 'center'});
      const b = s.getBoundingClientRect();
      return {x: Math.round(b.left + b.width / 2), y: Math.round(b.top + b.height / 2)};
    })()`);
    await cdp.clickAt(pt.x, pt.y);
    return waitFor(cdp, isOpen);
  };
  const state = () => cdp.eval(`(() => {
    const s = document.getElementById('${SELECT_ID}');
    const a = document.activeElement;
    const tab = document.querySelector('.tab-panel.active');
    return {
      open: s.matches(':open'),
      dialog_open: window.isOverlayOpen('${OVERLAY}'),
      theme: document.documentElement.getAttribute('data-theme') || '',
      tab: tab ? tab.id : '',
      active_tag: a ? a.tagName : '',
      active_in_select: !!(a && s.contains(a)) || a === s,
      value: s.value,
    };
  })()`);

  out.picker = {opened: await open()};
  if (out.picker.opened) {
    out.picker.style = await cdp.eval(`(() => {
      const s = document.getElementById('${SELECT_ID}');
      const p = getComputedStyle(s, '::picker(select)');
      const checked = s.options[s.selectedIndex];
      return {
        background: p.backgroundColor, border: p.borderTopColor, radius: p.borderTopLeftRadius,
        select_border_open: getComputedStyle(s).borderTopColor,
        checked_color: checked ? getComputedStyle(checked).color : '',
      };
    })()`);
  }

  // Keys typed into the open picker. Each is one the page binds globally:
  // `t` toggles the theme and `2` switches to the second tab. The shortcut
  // handler runs inside the key's own dispatch, so anything it did is visible
  // as soon as the key is acknowledged; there is nothing to wait for.
  const before = await state();
  await cdp.key('t', 'KeyT', 84, 't');
  await cdp.key('2', 'Digit2', 50, '2');
  const afterType = await state();
  await cdp.escape();
  await waitFor(cdp, `!${isOpen}`);
  const afterEscape = await state();
  out.keyboard = {before, after_type: afterType, after_escape: afterEscape};

  // A pick made from the keyboard still fires the select's change event, which
  // is what every onchange handler on the page hangs off.
  await cdp.eval(`(() => {
    const s = document.getElementById('${SELECT_ID}');
    s.value = '';
    window.__ssChanges = 0;
    s.addEventListener('change', () => { window.__ssChanges++; });
    return true;
  })()`);
  const reopened = await open();
  await cdp.key('ArrowDown', 'ArrowDown', 40);
  await cdp.key('Enter', 'Enter', 13, '\r');
  await waitFor(cdp, `!${isOpen} && window.__ssChanges > 0`);
  const afterPick = await state();
  out.pick = {
    reopened,
    value: afterPick.value,
    open_after: afterPick.open,
    dialog_open: afterPick.dialog_open,
    change_events: await cdp.eval(`window.__ssChanges`),
  };

  // With the picker shut and focus back on the select, Escape is the page's
  // again and closes the dialog, as it does from any other field.
  if (afterPick.open) {
    await cdp.escape();
    await waitFor(cdp, `!${isOpen}`);
  }
  await cdp.eval(`document.getElementById('${SELECT_ID}').focus(), true`);
  await cdp.escape();
  await waitFor(cdp, `!window.isOverlayOpen('${OVERLAY}')`);
  out.escape_from_closed_select = await state();
  return out;
}

(async () => {
  let chrome;
  try {
    chrome = await launchChrome();
    const cdp = await connect(chrome.port);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Page.navigate', {url: BASE});

    // Wait for the bundle to have run, not merely for the document to exist.
    let ready = false;
    for (let i = 0; i < 600 && !ready; i++) {
      await sleep(50);
      try {
        ready = await cdp.eval(
          `typeof window.openNewProjectModal === 'function' && typeof window.isOverlayOpen === 'function' && !!document.getElementById('${OVERLAY}')`);
      } catch (e) { /* navigating */ }
    }
    if (!ready) throw new Error('dashboard bundle never became ready');
    await sleep(150); // let the first render settle

    const out = await run(cdp);
    process.stdout.write(JSON.stringify(out, null, 2));
  } catch (err) {
    process.stdout.write(JSON.stringify({error: {message: String(err && err.stack || err)}}, null, 2));
    process.exitCode = 1;
  } finally {
    if (chrome) {
      try { chrome.proc.kill('SIGKILL'); } catch (e) {}
      try { fs.rmSync(chrome.dir, {recursive: true, force: true}); } catch (e) {}
    }
  }
})();
