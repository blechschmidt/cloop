// capture.js — photograph the cloop dashboard for the documentation.
//
// Drives real headless Chromium over CDP against the throwaway hub that
// demo-hub.sh puts up. Real browser rather than a DOM shim because the output
// is an image: layout, fonts, the chart canvas and the modal backdrop all have
// to be the ones a user sees, and a shim has none of them.
//
//   node capture.js <chrome-binary> <base-url> <output-dir>
//
// Each shot is declared once, below, in SHOTS. A shot says how to get the page
// into the state worth photographing (`setup`), what to wait for, and what to
// frame — a named element, or the viewport. Adding one is adding an entry.
//
// Two decisions worth knowing about:
//
//   * deviceScaleFactor 2. The images are read on high-density displays and
//     downscaled by the site's CSS anyway; capturing at 1x and letting the
//     browser upscale is the one way to make a screenshot of text look worse
//     than the text.
//   * Element clipping, not full-page, and `maxHeight` on the tall ones. A
//     capture of a whole Settings tab is 4800 CSS pixels of stacked cards;
//     inline in a page it becomes a thumbnail with unreadable type. Framing one
//     panel, and cropping the ones that are long by nature, keeps the subject
//     roughly the size it is on screen.
'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const OUTDIR = process.argv[4];

if (!CHROME || !BASE || !OUTDIR) {
  console.error('usage: node capture.js <chrome-binary> <base-url> <output-dir>');
  process.exit(2);
}

const WIDTH = 1440;
const HEIGHT = 900;
const SCALE = 2;

const sleep = ms => new Promise(r => setTimeout(r, ms));

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
      }, 30000);
    });
  }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', {
      expression: expr, awaitPromise: true, returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(
        r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
  // waitFor polls a JS predicate until it is true, or throws.
  async waitFor(expr, what, timeoutMs = 15000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      if (await this.eval(`!!(${expr})`)) return;
      if (Date.now() > deadline) throw new Error('timed out waiting for ' + what);
      await sleep(120);
    }
  }
}

// ── the shots ───────────────────────────────────────────────────────────────
//
// `setup` runs in the page and leaves it in the state to photograph. `settle`
// is a predicate that has to become true before the shutter. `clip` names the
// element to frame; absent means the viewport.
//
// Two ways to shorten a frame that is too tall to read inline. `clipTo` cuts it
// where a named element begins — a boundary that moves with the layout, so the
// crop still lands between the same two panels after somebody adds a field.
// `maxHeight` is the blunt one, in CSS pixels, for lists with no natural end.

const SHOTS = [
  {
    file: '01-projects-overview.png',
    what: 'the Projects tab — the fleet view',
    setup: `switchTab('projects')`,
    settle: `document.querySelectorAll('#projList .proj-card').length >= 3`,
    clip: '#tab-projects',
  },
  {
    file: '02-project-overview.png',
    what: "one project's Overview — goal, stats, run options, event history",
    setup: `openProject(0, 'checkout-api'); switchTab('overview')`,
    settle: `document.getElementById('projectPanel') &&
             document.getElementById('projectPanel').style.display !== 'none' &&
             document.getElementById('stepList').children.length > 0`,
    clip: '#projectPanel',
    // Goal down to the run options, stopping where the Claude Code caps card
    // begins. On a hub with no Claude login that card is a sign-in prompt, and
    // a sign-in prompt in the middle of a page about setting up a project
    // reads as a fault rather than as the next unrelated panel. The event
    // history below it has a shot of its own.
    clipTo: '#ccLimitsSection',
  },
  {
    file: '03-tasks.png',
    what: 'the Tasks tab — the plan, and the form that adds to it',
    // Show completed: the default hides them, and a screenshot of only the
    // pending half of a plan cannot show what a finished task looks like —
    // which is most of what the Tasks tab is for.
    // The toggle's own state is module-local, so read it off the button label
    // rather than reaching for a variable the bundle does not export.
    setup: `openProject(0, 'checkout-api'); switchTab('tasks');
            await new Promise(r => setTimeout(r, 900));
            if (document.getElementById('toggleCompletedBtn').textContent.trim() === 'Show completed') {
              toggleCompletedTasks();
            }`,
    settle: `document.querySelectorAll('#taskListFull .task-item').length >= 8`,
    clip: '#tab-tasks',
  },
  {
    file: '04-task-edit.png',
    what: 'the task editor',
    setup: `openProject(0, 'checkout-api'); switchTab('tasks');
            await new Promise(r => setTimeout(r, 1200));
            openEditModal(7)`,
    settle: `document.getElementById('modal-overlay').classList.contains('open')`,
    clip: '#modal',
    teardown: `closeModal()`,
  },
  {
    file: '05-settings.png',
    what: 'Settings — the provider configuration',
    setup: `switchTab('settings')`,
    settle: `document.getElementById('tab-settings').classList.contains('active')`,
    clip: '#tab-settings',
    // The provider cards, stopping at the speech-to-text one. Everything
    // below is a different subject with its own shot or its own page.
    clipTo: '#sttKeyStatus',
  },
  {
    file: '06-executors.png',
    what: 'the Executors tab — where work is allowed to run',
    setup: `switchTab('executors');
            await new Promise(r => setTimeout(r, 1200))`,
    settle: `document.querySelectorAll('#execList > *').length >= 2`,
    clip: '#tab-executors',
  },
  {
    file: '07-new-project.png',
    what: 'the New Project dialog',
    // Filled in, and with Access opened. An empty dialog of placeholders shows
    // the fields; a filled one shows what goes in them — and Access is the
    // half of this dialog the walkthrough is actually about, so leaving it
    // folded away would hide the subject.
    setup: `switchTab('projects');
            await new Promise(r => setTimeout(r, 400));
            openNewProjectModal();
            await new Promise(r => setTimeout(r, 600));
            document.getElementById('npDir').value  = '/srv/checkout-api';
            document.getElementById('npGoal').value =
              'Ship an idempotent payment capture API with end-to-end audit coverage';
            document.getElementById('npProvider').value = 'claudecode';
            document.getElementById('npProvider').dispatchEvent(new Event('change'));
            document.getElementById('npPMMode').checked = true;
            document.getElementById('npAccessSection').open = true;
            document.activeElement && document.activeElement.blur()`,
    settle: `getComputedStyle(document.getElementById('new-project-overlay')).display !== 'none' &&
             document.getElementById('npAccessSection').open`,
    clip: '#new-project-overlay > div',
    teardown: `closeNewProjectModal()`,
  },
  {
    file: '08-executor-enroll.png',
    what: 'enrolling a remote executor — the one-time command a device runs',
    // Named, but stopped before Mint token. The screen after that one is the
    // enrollment command with a live single-use token in it, and a published
    // screenshot of a credential — however short-lived, however throwaway the
    // hub — teaches the wrong habit to everyone who copies the format.
    setup: `switchTab('executors');
            await new Promise(r => setTimeout(r, 900));
            openEnrollModal();
            await new Promise(r => setTimeout(r, 400));
            const n = document.querySelector('#enroll-overlay input');
            if (n) { n.value = 'edge-lab-02'; n.blur(); }`,
    settle: `getComputedStyle(document.getElementById('enroll-overlay')).display !== 'none'`,
    clip: '#enroll-overlay > div',
    teardown: `closeEnrollModal()`,
  },
  {
    file: '09-project-executor.png',
    what: "choosing where one project's work runs",
    setup: `openProject(0, 'checkout-api'); switchTab('overview');
            await new Promise(r => setTimeout(r, 1200));
            openExecutorPickerModal()`,
    settle: `getComputedStyle(document.getElementById('executor-picker-overlay')).display !== 'none' &&
             document.querySelectorAll('#epExecutor option').length >= 2 &&
             !/Loading/.test(document.getElementById('epExecutor').textContent)`,
    clip: '#executor-picker-overlay > div',
    teardown: `closeExecutorPickerModal()`,
  },
  {
    file: '10-settings-sso.png',
    what: 'Settings — single sign-on, the panel that turns a hub multi-user',
    setup: `switchTab('settings');
            await new Promise(r => setTimeout(r, 700));
            document.getElementById('oidcPanel').scrollIntoView({block: 'start'})`,
    settle: `document.getElementById('oidcPanel').offsetHeight > 100`,
    clip: '#oidcPanel',
    maxHeight: 1100,
  },
  {
    file: '11-event-history.png',
    what: 'the event history — every step, task transition and evolve cycle',
    setup: `openProject(0, 'checkout-api'); switchTab('overview');
            await new Promise(r => setTimeout(r, 1000));
            document.getElementById('stepList').scrollIntoView({block: 'center'})`,
    settle: `document.getElementById('stepList').children.length >= 5`,
    clip: '#stepList',
    maxHeight: 760,
  },
];

// ── driving it ──────────────────────────────────────────────────────────────

async function main() {
  fs.mkdirSync(OUTDIR, {recursive: true});
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cloop-shot-'));

  const chrome = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + profile,
    '--no-sandbox',
    '--disable-gpu',
    '--hide-scrollbars',
    '--force-device-scale-factor=' + SCALE,
    '--window-size=' + WIDTH + ',' + HEIGHT,
    // Deterministic type across machines: without this the images re-render
    // with whatever fonts the host happens to have and every regeneration is
    // a diff.
    '--font-render-hinting=none',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});

  let wsURL = '';
  chrome.stderr.on('data', d => {
    const m = /ws:\/\/[^\s]+/.exec(d.toString());
    if (m && !wsURL) wsURL = m[0];
  });

  for (let i = 0; i < 200 && !wsURL; i++) await sleep(50);
  if (!wsURL) throw new Error('chrome did not report a debugging endpoint');

  const ws = new WebSocket(wsURL);
  await new Promise((res, rej) => {
    ws.addEventListener('open', res);
    ws.addEventListener('error', () => rej(new Error('cannot attach to chrome')));
  });
  const browser = new CDP(ws);

  const {targetId} = await browser.send('Target.createTarget', {url: 'about:blank'});
  const {sessionId} = await browser.send('Target.attachToTarget', {targetId, flatten: true});

  // A flat session multiplexes over the browser socket; wrap so every call
  // carries the sessionId.
  const page = new CDP(ws);
  page.send = (method, params) => {
    const id = ++browser.id;
    return new Promise((resolve, reject) => {
      browser.pending.set(id, {resolve, reject});
      ws.send(JSON.stringify({id, sessionId, method, params: params || {}}));
      setTimeout(() => {
        if (browser.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 30000);
    });
  };

  await page.send('Page.enable');
  await page.send('Runtime.enable');
  await page.send('Emulation.setDeviceMetricsOverride', {
    width: WIDTH, height: HEIGHT, deviceScaleFactor: SCALE, mobile: false,
  });

  // Light theme. The docs site renders both themes and a dark screenshot on a
  // light page reads as a different product; light is also what a first-time
  // reader's own default most often is.
  await page.send('Page.navigate', {url: BASE});
  await page.waitFor(`document.readyState === 'complete'`, 'document load', 30000);
  await page.eval(`localStorage.setItem('cloop-theme','light')`);
  await page.send('Page.navigate', {url: BASE});
  await page.waitFor(`document.readyState === 'complete'`, 'document reload', 30000);
  await page.waitFor(`typeof window.switchTab === 'function'`, 'the dashboard bundle', 30000);
  await page.waitFor(`document.querySelectorAll('#projList .proj-card').length >= 3`,
                     'the project list', 30000);

  // The keyboard-shortcut footer is position: fixed, so it stays glued to the
  // viewport while a clip runs past it — landing as a strip of key hints
  // through the middle of any panel taller than the window. It is furniture,
  // not subject matter; take it out for the duration.
  await page.eval(`(() => {
    const css = document.createElement('style');
    css.textContent = '#kb-footer{display:none !important}';
    document.head.appendChild(css);
  })()`);
  await sleep(1500);   // first render, WebSocket catch-up

  const taken = [];
  for (const shot of SHOTS) {
    process.stdout.write('  ' + shot.file + ' … ');
    try {
      await page.eval(`(async () => { ${shot.setup} })()`);
      if (shot.settle) await page.waitFor(shot.settle, shot.file);
      await sleep(900);   // transitions, late-arriving fetches
      await page.eval(`window.scrollTo(0, 0)`);

      const params = {format: 'png', captureBeyondViewport: true};
      if (shot.clip) {
        const box = await page.eval(`(() => {
          const el = document.querySelector(${JSON.stringify(shot.clip)});
          if (!el) return null;
          const r = el.getBoundingClientRect();
          const box = {x: r.x + window.scrollX, y: r.y + window.scrollY,
                       width: r.width, height: r.height};
          const stopSel = ${JSON.stringify(shot.clipTo || '')};
          if (stopSel) {
            const stop = document.querySelector(stopSel);
            if (stop) {
              const sr = stop.getBoundingClientRect();
              const cut = sr.y + window.scrollY - box.y;
              if (cut > 40 && cut < box.height) { box.height = cut; box.cut = true; }
            }
          }
          return box;
        })()`);
        if (!box || box.width < 10 || box.height < 10) {
          throw new Error('clip target ' + shot.clip + ' is not on screen');
        }
        // A pad keeps the panel's own border and shadow inside the frame
        // instead of shaving it off at the edge.
        // Pad above and below so the panel's own border and shadow stay inside
        // the frame — except at a clipTo boundary, where padding *past* the cut
        // is what puts the first line of the next section back into the shot
        // the cut existed to remove.
        const pad = 12;
        let height = box.cut ? box.height + pad - 14 : box.height + pad * 2;
        if (shot.maxHeight && height > shot.maxHeight) height = shot.maxHeight;
        params.clip = {
          x: Math.max(0, box.x - pad),
          y: Math.max(0, box.y - pad),
          width: box.width + pad * 2,
          height,
          scale: 1,
        };
      }

      const {data} = await page.send('Page.captureScreenshot', params);
      fs.writeFileSync(path.join(OUTDIR, shot.file), Buffer.from(data, 'base64'));
      taken.push(shot.file);
      console.log('ok');

      if (shot.teardown) {
        await page.eval(`(async () => { try { ${shot.teardown} } catch (e) {} })()`);
        await sleep(400);
      }
    } catch (err) {
      console.log('FAILED: ' + err.message);
      if (shot.teardown) {
        await page.eval(`(async () => { try { ${shot.teardown} } catch (e) {} })()`)
          .catch(() => {});
      }
    }
  }

  chrome.kill('SIGKILL');
  fs.rmSync(profile, {recursive: true, force: true});

  console.log('\ncaptured ' + taken.length + '/' + SHOTS.length + ' into ' + OUTDIR);
  if (taken.length !== SHOTS.length) process.exit(1);
}

main().catch(err => { console.error(err); process.exit(1); });
