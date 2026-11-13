// chat_fit_browser.js — the Chat and Assistant tabs at the heights screens
// really have, laid out by a real browser (Task 20492).
//
// On both tabs the page does not scroll: the messages scroll inside their list
// and the input stays at the bottom, as in every chat. The tabs used to size
// themselves as the viewport less a guess at the header, calc(100vh - 120px),
// and the guess was wrong twice over: the header is taller than 120px wherever
// its tabs wrap, and the shortcut footer is fixed over the bottom of the
// viewport. On the 1920x1200 laptop that reported it the input bar sat under
// the footer and the page grew a second scrollbar to reach it.
// testdata/domshim.js has no box model, so only an engine laying the page out
// can say where the input lands.
//
// For each viewport in the config this opens each tab over a history long
// enough to scroll and reports where the header, the messages, the input bar
// and the footer are, and what is under the input, Send and the microphone
// button. Then, at the config's "busy" viewport, it puts a presence bar and a
// banner above the chat, sends a message, grows the Assistant's box with a
// long question, and leaves for the Overview to see the page scroll there as
// before. Last, in windows too short for the controls and a few messages, it
// reports whether the list kept its minimum and the page scrolls to the input.
//
// Usage: node chat_fit_browser.js <chrome> <base-url> <config.json>
// Prints one JSON document on stdout; chat_fit_browser_test.go judges it.

'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const CONFIG = JSON.parse(fs.readFileSync(process.argv[4], 'utf8'));

const sleep = ms => new Promise(r => setTimeout(r, ms));
const q = v => JSON.stringify(v);

// How long Chrome gets to report its DevTools port, in 50 ms polls: 90 s
// (Task 20372).
const CHROME_START_POLLS = 1800;

// How long to keep looking for a condition, never a pause a healthy run sits
// out: under -race a control-plane round trip can take seconds.
const WAIT_MS = 30000;

// Chrome runs in its own process group (spawned detached), so one signal takes
// its helpers with it.
function killChrome(proc) {
  try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {
    try { proc.kill('SIGKILL'); } catch (_) { /* already gone */ }
  }
}

// closeChrome kills Chrome, waits for it to be gone (bounded, unref'd) and
// removes the profile. Best effort: cleanup never fails a run.
async function closeChrome(proc, dir) {
  killChrome(proc);
  if (proc.exitCode === null && proc.signalCode === null) {
    await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000).unref(); });
  }
  try { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 10, retryDelay: 100}); } catch (_) { /* best effort */ }
}

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
      // Cleared on the reply (Task 20372).
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 20000);
      this.pending.set(id, {
        resolve: v => { clearTimeout(timer); resolve(v); },
        reject: e => { clearTimeout(timer); reject(e); },
      });
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-chatfit-'));
  const proc = spawn(CHROME, ['--headless=new', '--remote-debugging-port=0', '--user-data-dir=' + dir,
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', 'about:blank'],
  {stdio: ['ignore', 'ignore', 'pipe'], detached: true});
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });
  // A launch that fails after the spawn must take Chrome with it, or node never
  // exits and the Go test hangs to the package timeout (Task 20340).
  try {
    let port = 0;
    for (let i = 0; i < CHROME_START_POLLS && !port; i++) {
      await sleep(50);
      if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr);
      try {
        const txt = fs.readFileSync(path.join(dir, 'DevToolsActivePort'), 'utf8').split('\n');
        if (txt[0] && txt[0].trim()) port = Number(txt[0].trim());
      } catch (e) { /* not written yet */ }
    }
    if (!port) throw new Error('chrome never reported a debugging port: ' + stderr);
    const list = await (await fetch('http://127.0.0.1:' + port + '/json/list',
      {signal: AbortSignal.timeout(15000)})).json();
    const page = list.find(t => t.type === 'page');
    if (!page) throw new Error('no page target');
    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      setTimeout(() => rej(new Error('cdp connect timed out')), 15000).unref();
      ws.addEventListener('open', res, {once: true});
      ws.addEventListener('error', () => rej(new Error('cdp connect failed')), {once: true});
    });
    return {cdp: new CDP(ws), proc, dir};
  } catch (e) {
    killChrome(proc);
    throw e;
  }
}

let cdp;

// waitFor polls expr until it is truthy; on a timeout diag, an expression for
// what the page shows instead, says why.
async function waitFor(expr, what, diag) {
  const deadline = Date.now() + WAIT_MS;
  for (;;) {
    let v = false;
    try { v = await cdp.eval(expr); } catch (e) { /* navigating */ }
    if (v) return v;
    if (Date.now() >= deadline) {
      let said = '';
      try { said = diag ? ' — the page shows: ' + await cdp.eval(diag) : ''; } catch (e) { /* gone */ }
      throw new Error('timed out waiting for ' + what + said);
    }
    await sleep(25);
  }
}

// settled resolves once the page has rendered two frames, so a
// ResizeObserver's callback has run as well.
const settled = () => cdp.eval('new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))');

// measureExpr reads a chat-shaped tab as it is on screen now. Rects are
// viewport coordinates; the *_hit fields name what a click at the middle of
// each control lands on when it is not that control — the footer, or nothing
// because it is below the bottom of the window.
const measureExpr = tab => `(() => {
  const vh = innerHeight, de = document.documentElement;
  const box = el => { if (!el) return null; const r = el.getBoundingClientRect();
    return {top: Math.round(r.top), bottom: Math.round(r.bottom), left: Math.round(r.left), right: Math.round(r.right),
      height: Math.round(r.height)}; };
  const name = el => { if (!el) return 'nothing';
    let s = el.tagName.toLowerCase(); if (el.id) s += '#' + el.id;
    if (typeof el.className === 'string' && el.className.trim()) s += '.' + el.className.trim().split(/\\s+/).join('.');
    return s; };
  const hit = el => { if (!el) return 'missing'; const r = el.getBoundingClientRect();
    const at = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    return at && (at === el || el.contains(at)) ? '' : name(at); };
  const foot = document.getElementById('kb-footer');
  const footOn = !!foot && foot.checkVisibility();
  const panel = document.getElementById(${q('tab-' + tab)});
  const pick = sel => panel && panel.querySelector(sel);
  const msgs = pick('.chat-messages'), input = pick('.chat-input'), mic = pick('.chat-mic-btn');
  const send = pick('.chat-input-bar button[data-act="submit"]');
  const rows = msgs ? msgs.querySelectorAll('.chat-bubble-row') : [];
  return {
    tab: ${q(tab)}, inner_width: innerWidth, inner_height: vh,
    page_overflow: de.scrollHeight - de.clientHeight,
    page_overflow_x: de.scrollWidth - de.clientWidth,
    scroll_y: Math.round(scrollY),
    header: box(document.querySelector('header')),
    footer: footOn ? box(foot) : null,
    chat: box(pick('.chat-layout')),
    bar: box(pick('.chat-input-bar')),
    input: box(input), send: box(send), mic: box(mic),
    input_hit: hit(input), send_hit: hit(send), mic_hit: mic ? hit(mic) : '',
    messages: msgs ? Object.assign(box(msgs), {client_height: msgs.clientHeight, scroll_height: msgs.scrollHeight,
      scroll_top: Math.round(msgs.scrollTop)}) : null,
    rows: rows.length,
    last: box(rows.length ? rows[rows.length - 1] : null),
    last_text: rows.length ? rows[rows.length - 1].textContent.replace(/\\s+/g, ' ').trim().slice(0, 80) : '',
  };
})()`;

async function setViewport(v) {
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: v.width, height: v.height, deviceScaleFactor: v.scale || 1, mobile: !!v.mobile,
  });
  await cdp.send('Emulation.resetPageScaleFactor');
  await cdp.eval('window.scrollTo(0, 0)');
  await settled();
}

// openTab shows a tab and waits for its history's last message — the panel's
// markup and code arrive on its first open (Task 20456), and every open
// redraws the history.
async function openTab(tab) {
  await cdp.eval(`window.switchTab(${q(tab)})`);
  await waitFor(`(() => { const p = document.getElementById(${q('tab-' + tab)});
    const m = p && p.querySelector('.chat-messages');
    return !!m && m.getClientRects().length > 0 && m.textContent.includes(${q(CONFIG.last_marker)}); })()`,
  'the ' + tab + ' history', `(document.getElementById(${q('tab-' + tab)}) || {}).textContent`);
  await cdp.eval('window.scrollTo(0, 0)');
  await settled();
}

// shot saves the window when CHAT_FIT_SHOTS names a directory.
async function shot(name) {
  if (!CONFIG.shots) return;
  const r = await cdp.send('Page.captureScreenshot', {format: 'png'});
  fs.writeFileSync(path.join(CONFIG.shots, name + '.png'), Buffer.from(r.data, 'base64'));
}

async function measure(tab, name) {
  await settled();
  const m = await cdp.eval(measureExpr(tab));
  m.name = name;
  await shot(name);
  return m;
}

async function main() {
  const launched = await launchChrome();
  cdp = launched.cdp;
  const out = {viewports: [], busy: null, sent: null, typing: null, overview: null, short: []};
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    // Boot picks a view once /api/projects answers, which under load is after
    // a switch made here. Its last step removes this stale marker, so the
    // marker's absence says boot is done with the tabs
    // (telemetry_panel_browser.js). The Assistant keeps its conversation in
    // the page's session; this one is as long as the Chat tab's.
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `try { sessionStorage.setItem('cloop_resume', '{"at":0}');
        sessionStorage.setItem('cloop_assistant_history', ${q(JSON.stringify(CONFIG.assistant_history))}); } catch (e) {}`,
    });
    await setViewport(CONFIG.viewports[0]);
    await cdp.send('Page.navigate', {url: BASE + '/'});
    await waitFor(`typeof window.switchTab === 'function' && typeof window.panelAct === 'function'
      && sessionStorage.getItem('cloop_resume') === null`, 'the dashboard to finish booting');

    for (const v of CONFIG.viewports) {
      await setViewport(v);
      for (const tab of ['chat', 'assistant']) {
        await openTab(tab);
        out.viewports.push(await measure(tab, tab + '-' + v.name));
      }
    }

    // Busy: whatever else the page can put above the chat — the presence bar
    // of a shared project and a hub banner — must come out of the messages,
    // not push the input off the bottom, and the newest message must stay in
    // view.
    const busy = CONFIG.viewports.find(v => v.name === CONFIG.busy);
    await setViewport(busy);
    await openTab('chat');
    await cdp.eval(`(() => {
      document.getElementById('presenceBar').innerHTML =
        '<span class="presence-label">Also here:</span><span class="presence-avatar" style="background:#8957e5">AB</span>';
      document.getElementById('hubDiskText').textContent = ${q(CONFIG.banner)};
      document.getElementById('hubDiskBanner').style.display = '';
    })()`);
    out.busy = await measure('chat', 'chat-' + busy.name + '+banners');
    await cdp.eval(`(() => {
      document.getElementById('presenceBar').innerHTML = '';
      document.getElementById('hubDiskBanner').style.display = 'none';
    })()`);

    // Sending: the reply is the newest thing in the list and on screen, and
    // the input is still there for the next message. The hub's model call is
    // answered in the page; what is measured is where the answer lands.
    await cdp.eval(`(() => {
      const real = window.fetch;
      window.fetch = function (url, opts) {
        if (String(url).indexOf('/api/chat') >= 0 && opts && opts.method === 'POST') {
          return Promise.resolve(new Response(JSON.stringify({ok: true, response: ${q(CONFIG.reply)}}),
            {status: 200, headers: {'Content-Type': 'application/json'}}));
        }
        return real.apply(this, arguments);
      };
      const i = document.getElementById('chatInput');
      i.focus();
      i.value = ${q(CONFIG.message)};
      i.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true, cancelable: true}));
    })()`);
    await waitFor(`(() => { const m = document.getElementById('chatMessages');
      return !!m && m.textContent.includes(${q(CONFIG.reply_marker)}); })()`, 'the reply to the sent message');
    out.sent = await measure('chat', 'chat-' + busy.name + '+sent');
    out.sent.input_value = await cdp.eval(`document.getElementById('chatInput').value`);

    // Typing: the Assistant's box grows with a long question, up to its cap;
    // the list gives up the room, and its newest message stays in view.
    await openTab('assistant');
    await cdp.eval(`(() => {
      const t = document.getElementById('assistantInput');
      t.focus();
      t.value = ${q(CONFIG.long_question)};
      t.dispatchEvent(new Event('input', {bubbles: true}));
    })()`);
    out.typing = await measure('assistant', 'assistant-' + busy.name + '+typing');
    await cdp.eval(`(() => { const t = document.getElementById('assistantInput');
      t.value = ''; t.dispatchEvent(new Event('input', {bubbles: true})); t.blur(); })()`);

    // Leaving: the Overview is a page again, as tall as its content at least
    // and as the window.
    await cdp.eval(`window.switchTab('overview')`);
    await settled();
    out.overview = await cdp.eval(`(() => {
      const l = document.querySelector('.layout'), de = document.documentElement;
      return {inner_height: innerHeight, layout_height: Math.round(l.getBoundingClientRect().height),
        content_height: Math.round(de.scrollHeight), page_overflow: de.scrollHeight - de.clientHeight,
        body_padding_bottom: getComputedStyle(document.body).paddingBottom,
        footer_position: getComputedStyle(document.getElementById('kb-footer')).position};
    })()`);

    // Short windows: the list keeps its minimum rather than the input being
    // squeezed out, so the page scrolls — and scrolled to its end, shows the
    // input, Send and the microphone whole and clear of the footer.
    for (const v of CONFIG.short) {
      await setViewport(v);
      await openTab('chat');
      const top = await measure('chat', 'chat-' + v.name);
      await cdp.eval('window.scrollTo(0, document.documentElement.scrollHeight)');
      const end = await measure('chat', 'chat-' + v.name + '+scrolled');
      out.short.push({top, end});
    }
    process.stdout.write(JSON.stringify(out, null, 2));
  } finally {
    await closeChrome(launched.proc, launched.dir);
  }
}

main().then(() => process.exit(0), err => {
  process.stdout.write(JSON.stringify({error: String(err && err.message || err)}, null, 2));
  process.exit(1);
});
