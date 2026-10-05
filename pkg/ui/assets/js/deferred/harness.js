// ── Claude credential card and dialog (Task 20379) ──────────────────────────
//
// A project whose executor isolates from the host — a container, a Pod, an
// enrolled device — runs its harness in a sandbox that gets no Claude login of
// its own, only what is granted to the project. The hub refuses to dispatch one
// that would get none (harness_credential_missing / _expiring); this file is
// the other half: a card on the Overview that says what the sandbox would sign
// in with, and a dialog that grants a credential in one step — an env secret
// the user already has, or a token pasted from `claude setup-token`.
//
// Fetched on demand rather than bundled (static.go, deferredScripts): first
// paint has no room for it. It runs outside the dashboard's IIFE, so
// loadHarnessCred in 01-overview.js hands over the few helpers it calls, and
// the only name it puts on window is the factory.
//
// The server decides everything about who may do what: which secrets are
// offered (never another person's personal secret, shared ones only to someone
// who may grant them here), whether a token may be stored, and the refusal
// text. A pasted token goes into one request body and is cleared from the
// field as soon as it is sent; nothing here keeps or logs it.
(function () {
  'use strict';

  window.cloopHarnessPanel = function (h) {
    const DAY = 86400000;
    let dialogIdx = null;
    let dialogView = null;

    function el(id) { return document.getElementById(id); }

    // The Overview card, placed after the Executor card it qualifies.
    function card() {
      let c = el('harnessCredCard');
      if (c) return c;
      const anchor = el('executorCard');
      if (!anchor || !anchor.parentNode) return null;
      c = document.createElement('div');
      c.className = 'stat-card stat-card-clickable';
      c.id = 'harnessCredCard';
      c.tabIndex = 0;
      c.setAttribute('role', 'button');
      c.style.display = 'none';
      c.innerHTML = '<div class="stat-label">Claude credential <span style="font-size:10px;opacity:.6;margin-left:4px">✎</span></div>' +
        '<div class="stat-value" style="font-size:13px;margin-top:4px"><span id="harnessCredChip"></span></div>' +
        '<div class="stat-sub" id="harnessCredSub"></div>';
      c.addEventListener('click', function () { open(h.idx()); });
      c.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(h.idx()); }
      });
      anchor.parentNode.insertBefore(c, anchor.nextSibling);
      return c;
    }

    function relative(ms) {
      if (ms < 3600000) return Math.max(1, Math.round(ms / 60000)) + ' min';
      if (ms < 2 * DAY) return Math.round(ms / 3600000) + ' h';
      return Math.round(ms / DAY) + ' d';
    }

    // tone classifies a view for the chip: green with its expiry, amber within
    // three days of it, red when there is none or it is about to lapse. text
    // is for the dialog's sentence, short for the chip, which sits in a card
    // a third of the width of a phone.
    function tone(d) {
      if (d.state === 'missing') return {color: 'var(--red)', text: 'missing', short: 'missing'};
      const exp = d.expires_at ? new Date(d.expires_at).getTime() - Date.now() : null;
      if (exp === null) return {color: 'var(--green)', text: 'never expires', short: 'no expiry'};
      const left = relative(Math.max(exp, 0));
      const color = d.state === 'expiring' ? 'var(--red)' : exp < 3 * DAY ? 'var(--yellow)' : 'var(--green)';
      return {color: color, text: 'expires in ' + left, short: left + ' left'};
    }

    function grantedBy(d) {
      const s = d.satisfied_by;
      if (!s) return '';
      return s.secret_name + (s.owner ? ' (personal)' : ' (shared)');
    }

    function renderCard(d) {
      const c = card();
      if (!c) return;
      if (!d || !d.applies) { c.style.display = 'none'; return; }
      c.style.display = '';
      const t = tone(d);
      const chip = el('harnessCredChip');
      chip.className = 'hc-chip hc-' + (d.state || 'missing');
      chip.style.cssText = 'display:inline-flex;align-items:center;gap:6px;padding:2px 9px;border-radius:999px;' +
        'font-size:12px;font-weight:600;white-space:nowrap;border:1px solid ' + t.color + ';color:' + t.color;
      chip.innerHTML = '<span aria-hidden="true">●</span>' + h.esc(t.short);
      chip.title = t.text;
      el('harnessCredSub').textContent = grantedBy(d) || 'none granted';
      c.title = d.state === 'ok'
        ? 'This project’s sandbox signs in to Claude with ' + grantedBy(d) + '. Click to grant another.'
        : (d.reason || 'This project’s sandbox has no Claude login.') + ' Click to grant one.';
    }

    function load() {
      const idx = h.idx();
      return h.api('/api/projects/' + idx + '/harness-credential').then(function (d) {
        if (h.idx() === idx) renderCard(d);
        return d;
      });
    }

    // ── The dialog ──────────────────────────────────────────────────────────
    function dialog() {
      let o = el('harness-cred-overlay');
      if (o) return o;
      o = document.createElement('div');
      o.id = 'harness-cred-overlay';
      o.setAttribute('data-overlay', 'flex');
      o.setAttribute('aria-labelledby', 'hcTitle');
      o.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center';
      o.innerHTML =
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:560px;max-width:95vw;max-height:90vh;overflow:auto">' +
          '<h2 id="hcTitle" style="font-size:15px;font-weight:600;margin-bottom:6px">Claude credential</h2>' +
          '<p id="hcIntro" style="font-size:12px;color:var(--muted);margin-bottom:12px;line-height:1.5"></p>' +
          '<div id="hcRefusal" role="alert" style="display:none;font-size:12px;padding:8px 10px;border-radius:4px;' +
            'background:rgba(248,81,73,0.12);border:1px solid var(--red);margin-bottom:12px;line-height:1.5"></div>' +
          '<div id="hcCurrent" style="font-size:12px;margin-bottom:14px;line-height:1.5"></div>' +
          '<div class="form-group" id="hcPickGroup">' +
            '<label class="form-label" for="hcSecret">Grant a secret you have</label>' +
            '<select class="form-select" id="hcSecret"></select>' +
          '</div>' +
          '<div class="form-group" id="hcPasteGroup">' +
            '<label class="form-label" for="hcToken">Or paste a token</label>' +
            '<input class="form-input" id="hcToken" type="password" autocomplete="off" spellcheck="false" ' +
              'placeholder="sk-ant-oat01-… or sk-ant-api03-…">' +
            '<div class="form-hint" id="hcPasteHint"></div>' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label" for="hcTTL">Grant for</label>' +
            '<select class="form-select" id="hcTTL"></select>' +
          '</div>' +
          '<div id="hcError" role="alert" style="font-size:12px;color:var(--red);margin-bottom:8px;display:none"></div>' +
          '<div class="modal-footer">' +
            '<button class="btn" type="button" id="hcCancel">Cancel</button>' +
            '<button class="btn primary" type="button" id="hcGrant">Grant</button>' +
          '</div>' +
        '</div>';
      document.body.appendChild(o);
      o.addEventListener('click', function (ev) { if (ev.target === o) close(); });
      o.querySelector('#hcCancel').addEventListener('click', close);
      o.querySelector('#hcGrant').addEventListener('click', submit);
      o.querySelector('#hcToken').addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter') { ev.preventDefault(); submit(); }
      });
      return o;
    }

    function close() {
      const t = el('hcToken');
      if (t) t.value = '';
      h.closeOverlay('harness-cred-overlay');
    }

    function showError(msg) {
      const e = el('hcError');
      e.textContent = msg || '';
      e.style.display = msg ? '' : 'none';
    }

    function ttlOptions(d) {
      const max = d.max_ttl_minutes || 129600;
      const def = d.default_ttl_minutes || 43200;
      const opts = [[1440, '1 day'], [10080, '7 days'], [43200, '30 days'], [129600, '90 days']]
        .filter(function (o) { return o[0] <= max; });
      return opts.map(function (o) {
        return '<option value="' + o[0] + '"' + (o[0] === def ? ' selected' : '') + '>' + o[1] + '</option>';
      }).join('');
    }

    function renderDialog(d, refusal) {
      dialogView = d;
      const ex = d.executor || {};
      el('hcIntro').textContent = (ex.id ? 'This project runs on ' + ex.id + ' (' + ex.kind + '), a sandbox' : 'This project’s sandbox') +
        ' that gets no Claude login of its own — only what is granted to ' +
        (d.grant_target && d.grant_target !== d.project ? 'its project, ' + d.grant_target : 'the project') + '.' +
        (d.personal ? ' A personal credential is used only for runs you start.' : '');

      // The cause alone: the refusal's remediation points at this dialog.
      const why = refusal ? refusal.error : (d.state !== 'ok' ? d.reason : '');
      const ref = el('hcRefusal');
      ref.textContent = why || '';
      ref.style.display = why ? '' : 'none';

      const cur = el('hcCurrent');
      if (d.satisfied_by) {
        const t = tone(d);
        cur.innerHTML = 'Now: <strong>' + h.esc(grantedBy(d)) + '</strong> · <span style="color:' + t.color + '">' +
          h.esc(t.text) + '</span>';
      } else {
        cur.textContent = d.broker_unavailable
          ? 'Nothing can be granted on this hub: ' + d.broker_unavailable + '.'
          : 'Now: no Claude credential is granted to this project.';
      }

      const cands = Array.isArray(d.candidates) ? d.candidates : [];
      const sel = el('hcSecret');
      sel.innerHTML = cands.length
        ? '<option value="">Choose a secret…</option>' + cands.map(function (c) {
            const label = c.name + ' · ' + c.keys.join(', ') + ' · ' + (c.personal ? 'personal' : 'shared') +
              (c.granted ? ' · granted' : '') + (c.complete ? '' : ' · incomplete');
            return '<option value="' + h.esc(c.id) + '"' + (c.complete ? '' : ' disabled') + '>' + h.esc(label) + '</option>';
          }).join('')
        : '<option value="">No env secret of yours holds ' + h.esc(neededText(d)) + '</option>';
      sel.disabled = !cands.length;

      el('hcPasteGroup').style.display = d.can_paste ? '' : 'none';
      el('hcPasteHint').textContent = 'From `claude setup-token` (sk-ant-oat01-…), or an Anthropic API key. ' +
        (d.personal ? 'Stored as a personal secret only you can grant.' : 'Stored as a secret on this hub.') +
        ' It is never shown again.';
      el('hcTTL').innerHTML = ttlOptions(d);
      el('hcGrant').disabled = !!d.broker_unavailable;
      showError('');
      // The dialog opened with focus on the picker; with nothing to pick it is
      // now disabled, and a disabled control drops focus to the page behind.
      // Moved only then, so a field the user already reached is left alone.
      const active = document.activeElement;
      if (!active || active.disabled || !el('harness-cred-overlay').contains(active)) {
        const first = !sel.disabled ? sel : (d.can_paste ? el('hcToken') : el('hcCancel'));
        if (first) first.focus();
      }
    }

    function neededText(d) {
      return (d.grantable || d.needed || []).map(function (set) { return set.join(' with '); }).join(' or ');
    }

    function open(idx, refusal) {
      dialogIdx = idx;
      const o = dialog();
      el('hcIntro').textContent = 'Loading…';
      el('hcRefusal').style.display = 'none';
      el('hcCurrent').textContent = '';
      el('hcSecret').innerHTML = '';
      el('hcToken').value = '';
      showError('');
      h.openOverlay(o, {dismiss: close, focus: '#hcSecret'});
      return h.api('/api/projects/' + idx + '/harness-credential').then(function (d) {
        if (dialogIdx !== idx) return;
        if (d && d.error && !d.project) { showError(d.error); return; }
        renderDialog(d, refusal);
      }).catch(function (err) { fail('load the credential', err); });
    }

    function fail(what, err) {
      // A refusal (403) or a lapsed session (401) has already been reported
      // in the hub's own words; repeating its code would replace them.
      if (err && /^(FORBIDDEN|401)$/.test(err.message)) return;
      showError((err && err.message) || 'Could not ' + what);
    }

    function submit() {
      if (!dialogView) return;
      const idx = dialogIdx;
      const tokenEl = el('hcToken');
      const token = tokenEl.value.trim();
      const secret = el('hcSecret').value;
      if (!token && !secret) { showError('Choose a secret, or paste a token.'); return; }
      const body = {ttl_minutes: parseInt(el('hcTTL').value, 10) || 0};
      if (token) body.token = token; else body.secret = secret;
      // Out of the page before the request is even answered.
      tokenEl.value = '';
      const btn = el('hcGrant');
      btn.disabled = true;
      showError('');
      h.api('/api/projects/' + idx + '/harness-credential', body).then(function (d) {
        btn.disabled = false;
        if (!d || d.error || !d.granted) { showError((d && d.error) || 'The credential was not granted'); return; }
        const g = d.granted;
        h.toast('Claude credential granted: ' + g.secret_name + ', until ' +
          new Date(g.expires_at).toLocaleDateString(), 'ok');
        if (h.idx() === idx) renderCard(d);
        close();
      }).catch(function (err) { btn.disabled = false; fail('grant the credential', err); });
    }

    return {
      load: function (opts) {
        if (opts && opts.open) return open(opts.idx === undefined || opts.idx === null ? h.idx() : opts.idx, opts.refusal);
        return load();
      },
    };
  };
})();
