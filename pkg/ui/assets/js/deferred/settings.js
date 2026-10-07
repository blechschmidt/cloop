// ── Settings tab ────────────────────────────────────────────────────────────
//
// Configuration: the default provider and each provider's model and key, the
// hub's speech-to-text key, single sign-on (Task 20308), telemetry collection
// (Task 20311), GitHub Apps (Task 20306), the USB hardware of enrolled devices
// (Task 20345), CI/CD pipeline federation (Task 20278), the display-glasses
// link (Task 20194), this hub's build, hidden projects and the reset.
//
// Fetched on the tab's first open since Task 20386 (static.go,
// deferredScripts), markup included: first paint has no room for a tab most
// sessions never open, and an admin's half of it was the bulk of the bundle's
// admin code. It was 14-settings.js, 32-oidc.js, 32-cicd.js, 33-glasses.js and
// the Settings halves of 30-telemetry.js, 32-githubapp.js and 23-executors.js.
// The build section (29-build.js) and the hidden-projects button (05-projects.js)
// stay in the bundle, which draws them elsewhere too; their markup is here and
// their inline handlers call those resident functions on window.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory.
(function () {
  'use strict';

  window.cloopSettingsPanel = function (h) {
    const {api, apiMethod, esc, toast, canGlobal, pUrl, relTime, refreshState} = h;
    // ok turns an error body into a rejection. api() resolves one — only a 401
    // and a 403 reject — so a success path that does not check reports a
    // refusal as done: Task 20386 found the Store-a-secret dialog saying
    // "Secret stored" over a 400.
    const ok = d => { if (d && d.error) throw new Error(d.error); return d; };

    // ── Settings ─────────────────────────────────────────────────────────────────

    function loadConfig() {
      api(pUrl('/api/config')).then(cfg => {
        if (cfg.error) return;
        // Provider
        const provSel = document.getElementById('cfgProvider');
        if (cfg.provider) provSel.value = cfg.provider;
        // ClaudeCode
        document.getElementById('cfgCCModel').value = cfg.claudecode?.model || '';
        // Anthropic
        document.getElementById('cfgAnthropicModel').value = cfg.anthropic?.model || '';
        document.getElementById('cfgAnthropicBase').value  = cfg.anthropic?.base_url || '';
        const antKeyEl = document.getElementById('anthropicKeyStatus');
        antKeyEl.innerHTML = cfg.anthropic?.has_key
          ? '<span class="badge complete" style="font-size:10px">key set</span>'
          : '<span class="badge unknown"  style="font-size:10px">no key</span>';
        // OpenAI
        document.getElementById('cfgOpenAIModel').value = cfg.openai?.model || '';
        document.getElementById('cfgOpenAIBase').value  = cfg.openai?.base_url || '';
        const oaiKeyEl = document.getElementById('openaiKeyStatus');
        oaiKeyEl.innerHTML = cfg.openai?.has_key
          ? '<span class="badge complete" style="font-size:10px">key set</span>'
          : '<span class="badge unknown"  style="font-size:10px">no key</span>';
        // Ollama
        document.getElementById('cfgOllamaBase').value  = cfg.ollama?.base_url || '';
        document.getElementById('cfgOllamaModel').value = cfg.ollama?.model || '';
      }).catch(() => {});
    }

    function saveConfigField(key, value) {
      if (value === undefined || value === null) return;
      api(pUrl('/api/config/set'), {key, value}).then(d => {
        if (d.ok) { toast('Saved: '+key, 'ok'); loadConfig(); }
        else toast(d.error||'Save failed', 'err');
      }).catch(() => toast('Request failed', 'err'));
    }

    function saveAnthropicCfg() {
      const key   = document.getElementById('cfgAnthropicKey').value.trim();
      const model = document.getElementById('cfgAnthropicModel').value.trim();
      const base  = document.getElementById('cfgAnthropicBase').value.trim();
      const saves = [];
      if (key)   saves.push(saveConfigField('anthropic.api_key', key));
      if (model) saves.push(saveConfigField('anthropic.model',   model));
      if (base)  saves.push(saveConfigField('anthropic.base_url', base));
      if (!saves.length) { toast('Nothing to save', 'info'); return; }
      Promise.all(saves).then(() => { document.getElementById('cfgAnthropicKey').value = ''; loadConfig(); });
    }

    function saveOpenAICfg() {
      const key   = document.getElementById('cfgOpenAIKey').value.trim();
      const model = document.getElementById('cfgOpenAIModel').value.trim();
      const base  = document.getElementById('cfgOpenAIBase').value.trim();
      const saves = [];
      if (key)   saves.push(saveConfigField('openai.api_key', key));
      if (model) saves.push(saveConfigField('openai.model',   model));
      if (base)  saves.push(saveConfigField('openai.base_url', base));
      if (!saves.length) { toast('Nothing to save', 'info'); return; }
      Promise.all(saves).then(() => { document.getElementById('cfgOpenAIKey').value = ''; loadConfig(); });
    }

    function saveOllamaCfg() {
      const base  = document.getElementById('cfgOllamaBase').value.trim();
      const model = document.getElementById('cfgOllamaModel').value.trim();
      const saves = [];
      if (base)  saves.push(saveConfigField('ollama.base_url', base));
      if (model) saves.push(saveConfigField('ollama.model',    model));
      if (!saves.length) { toast('Nothing to save', 'info'); return; }
      Promise.all(saves).then(() => loadConfig());
    }

    // ── Speech-to-text credential (Task 20250) ───────────────────────────────────
    //
    // Deliberately not pUrl(): this key is hub-wide. The dictate button and the
    // glasses call /api/transcribe with no project index, so a key filed under the
    // selected project would save, report success, and never be read by anything.
    // /api/config/stt is global-scoped for exactly that reason.

    function renderSTTSettings(d) {
      const status = document.getElementById('sttKeyStatus');
      const note   = document.getElementById('sttStatusNote');
      const clear  = document.getElementById('sttClearBtn');
      if (!status || !note || !clear) return;

      status.innerHTML = d.has_key
        ? '<span class="badge complete" style="font-size:10px">key set</span>'
        : '<span class="badge unknown"  style="font-size:10px">no key</span>';

      // Only offer to clear what we actually stored. A key arriving from
      // GROQ_API_KEY is the environment's, and a button promising to remove it
      // would do nothing and look broken.
      clear.style.display = d.stored ? '' : 'none';

      const parts = [];
      if (d.available) {
        parts.push('Dictation is enabled.');
        if (d.from_env) {
          parts.push('The key is coming from the <code>GROQ_API_KEY</code> environment variable; ' +
                     'saving one here takes precedence over it.');
        }
        if (d.endpoint) parts.push('Endpoint: <code>' + esc(d.endpoint) + '</code>');
      } else {
        parts.push('Dictation is disabled — the Dictate button stays hidden until a key is set.');
        if (d.reason) parts.push(esc(d.reason));
      }
      note.innerHTML = parts.join('<br>');
    }

    function loadSTTSettings() {
      api('/api/config/stt').then(d => {
        if (!d || d.error) return;
        renderSTTSettings(d);
      }).catch(() => {});
    }

    function saveSTTCfg() {
      const input = document.getElementById('cfgGroqKey');
      const key = input.value.trim();
      if (!key) { toast('Enter an API key first', 'info'); return; }
      apiMethod('PUT', '/api/config/stt', {groq_api_key: key}).then(d => {
        if (d && d.error) { toast(d.error, 'err'); return; }
        input.value = '';           // never leave a credential sitting in the DOM
        toast('Speech-to-text key saved', 'ok');
        renderSTTSettings(d);
        // The Tasks tab decides once at load whether to show its Dictate button,
        // so re-ask now that the answer has changed — otherwise the key works but
        // the button the user came here to enable stays hidden until a reload.
        if (window.initTaskDictation) window.initTaskDictation();
      }).catch(() => toast('Request failed', 'err'));
    }

    function clearSTTCfg() {
      if (!confirm('Remove the stored speech-to-text key? Dictation stops working until a new one is set.')) return;
      apiMethod('DELETE', '/api/config/stt').then(d => {
        if (d && d.error) { toast(d.error, 'err'); return; }
        toast('Speech-to-text key removed', 'ok');
        renderSTTSettings(d);
        if (window.initTaskDictation) window.initTaskDictation();
      }).catch(() => toast('Request failed', 'err'));
    }

    function confirmReset() {
      if (!confirm('Reset project state? This clears step history and resets status. Goal and config are preserved.')) return;
      api(pUrl('/api/reset'), {}).then(d => {
        if (d.ok) { toast('Project reset', 'ok'); refreshState(); }
        else toast(d.error||'Reset failed', 'err');
      }).catch(() => toast('Request failed', 'err'));
    }


    // The two single-field saves, which inline handlers used to spell out.
    function saveProvider() {
      return saveConfigField('provider', document.getElementById('cfgProvider').value);
    }
    function saveCCModel() {
      return saveConfigField('claudecode.model', document.getElementById('cfgCCModel').value);
    }

    // Single sign-on settings (Task 20308).
    //
    // The panel that edits ui.oidc. Three things make it different from the other
    // Settings sections, and all three come from the same property: this is the
    // block that decides who can sign in, and it is read at startup rather than
    // per request.
    //
    //  1. It refuses rather than warns. The backend validates a prospective block
    //     through the constructors the next startup will run, so a save that would
    //     stop the hub booting comes back as a 400 with the offending field named.
    //     This file's job is to put that message next to the right input.
    //
    //  2. It says when a save is not live yet. `restart_required` in the view is
    //     the answer to the one confusing thing about the feature — "I turned SSO
    //     on and nothing happened" — so it gets a banner rather than a footnote.
    //
    //  3. It never round-trips the client secret. The input is always blank on
    //     load; blank on save means "keep what is stored", and clearing needs the
    //     explicit button. So the panel cannot leak the credential into the DOM,
    //     and an operator editing the issuer cannot accidentally erase it.
    //
    // Bounds, role names and claim kinds all come from the server rather than being
    // written here, because they are already constants in pkg/config and pkg/authz.
    // A copy in this file would be the copy that goes stale, and the symptom would
    // be a form that accepts a value the next startup rejects.

    const oidcState = {
      // The last view the server sent. Role mappings are edited in place against
      // this copy, so the table is the model rather than the DOM being parsed.
      view: null,
      mappings: [],
    };

    function loadOIDCSettings() {
      // Gate the fetch as well as the panel. Without this an operator without
      // user.manage would 403 on every Settings visit, which shows up as a console
      // full of errors and a toast they can do nothing about.
      if (typeof canGlobal === 'function' && !canGlobal('user.manage')) {
        const panel = document.getElementById('oidcPanel');
        if (panel) panel.style.display = 'none';
        return Promise.resolve();
      }
      return api('/api/config/oidc').then(d => {
        if (!d || d.error) return;
        oidcState.view = d;
        oidcState.mappings = (d.role_mappings || []).map(m => Object.assign({}, m));
        renderOIDCSettings(d);
      }).catch(() => {});
    }

    function renderOIDCSettings(d) {
      const set = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.value = value;
      };
      const check = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.checked = !!value;
      };

      check('oidcEnabled', d.enabled);
      set('oidcIssuer', d.issuer || '');
      set('oidcClientId', d.client_id || '');
      set('oidcRedirectUrl', d.redirect_url || '');
      set('oidcScopes', (d.scopes || []).join(', '));
      set('oidcAdminEmails', (d.admin_emails || []).join(', '));
      set('oidcCookieSecure', d.cookie_secure || 'auto');
      check('oidcRequireIdp', d.require_idp);
      check('oidcRequireRbac', d.require_rbac);

      // The numeric fields show the effective default when unset rather than a
      // bare 0, because "0" reads as "no session lifetime" to someone who has not
      // read the config reference.
      const lim = d.limits || {};
      const num = (id, value, bound) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.value = value || (bound ? bound.default : 0);
        if (bound) {
          // A field with a disable sentinel accepts a value below its lower bound,
          // so min would reject the very thing the label tells you to type.
          el.min = bound.disable !== undefined && bound.disable !== 0 ? bound.disable : bound.lower;
          el.max = bound.upper;
        }
      };
      num('oidcSessionTtl', d.session_ttl_hours, lim.session_ttl_hours);
      num('oidcIdleTimeout', d.idle_timeout_hours, lim.idle_timeout_hours);
      num('oidcRefreshInterval', d.refresh_interval_minutes, lim.refresh_interval_minutes);
      num('oidcMaxClaimAge', d.max_claim_age_minutes, lim.max_claim_age_minutes);
      num('oidcClockSkew', d.clock_skew_seconds, lim.clock_skew_seconds);

      renderOIDCRoleOptions(d.roles || [], d.default_role || '');
      renderOIDCSecretState(d);
      renderOIDCStatus(d);
      renderOIDCRBAC(d);
      renderOIDCMappings();
    }

    // The select shows the saved value, unset included (Task 20395). It used to
    // pre-select "none" for an unset role, so saving any other field of the form
    // wrote default_role: none — which puts a role policy in force, and locked
    // out every identity without a mapping at the next restart.
    function renderOIDCRoleOptions(roles, selected) {
      const sel = document.getElementById('oidcDefaultRole');
      if (!sel) return;
      sel.innerHTML = '<option value="">unset — no default role written</option>' + roles.map(r => {
        const label = r === 'none' ? 'none — deny by default (recommended)' : r;
        return '<option value="' + esc(r) + '">' + esc(label) + '</option>';
      }).join('');
      sel.value = selected || '';
    }

    // renderOIDCRBAC says whether a role policy is in force: the hub's own
    // verdict in d.rbac (authz.Enforced, for this process and the saved block),
    // never worked out here from default_role and role_mappings.
    function renderOIDCRBAC(d) {
      const r = d.rbac || {};
      const btn = document.getElementById('oidcEnforceBtn');
      if (btn) btn.style.display = r.can_enforce ? '' : 'none';
      const note = document.getElementById('oidcRbacNote');
      if (!note) return;
      if (r.warning) {
        note.style.cssText = 'display:block;font-size:12px;padding:8px 10px;margin-bottom:8px;' +
          'border:1px solid var(--border);border-left:3px solid var(--red,#f85149);border-radius:4px';
        note.textContent = r.warning + (r.can_enforce
          ? ' Enforce deny-by-default writes default role none and keeps you and every admin email an admin.'
          : '');
      } else if (r.enforced && r.saved_enforced) {
        note.style.cssText = 'display:block;font-size:12px;color:var(--muted);margin-bottom:8px';
        note.textContent = 'RBAC is in force: a signed-in user who matches no mapping gets "' +
          (r.default_role || 'none') + '".';
      } else {
        note.style.display = 'none';
        note.textContent = '';
      }
    }

    // oidcEnforce writes deny-by-default in one step: default role none, plus an
    // admin mapping for the caller unless they already are one.
    function oidcEnforce() {
      if (!confirm('Enforce deny-by-default?\n\nAfter the next restart, a signed-in user who matches no ' +
        'role mapping gets nothing. Admin emails stay admins, and so do you.')) return;
      return apiMethod('POST', '/api/config/oidc/enforce', {}).then(d => {
        if (!d || d.error) { toast(oidcErrText(d), 'err'); return; }
        oidcState.view = d;
        oidcState.mappings = (d.role_mappings || []).map(m => Object.assign({}, m));
        renderOIDCSettings(d);
        toast('Deny-by-default saved — restart the hub to enforce it', 'ok');
      }).catch(() => toast('Request failed', 'err'));
    }

    function renderOIDCSecretState(d) {
      const state = document.getElementById('oidcSecretState');
      const clearBtn = document.getElementById('oidcClearSecretBtn');
      if (clearBtn) clearBtn.style.display = d.client_secret_source === 'file' ? '' : 'none';
      if (!state) return;
      if (d.client_secret_source === 'env') {
        // Worth saying explicitly: on this hub a value typed into the box would be
        // stored and then overridden on every load, so the box is the wrong place
        // to change it.
        state.textContent = '— supplied by CLOOP_OIDC_CLIENT_SECRET; a value typed here is ignored';
      } else if (d.client_secret_set) {
        state.textContent = '— stored';
      } else {
        // "not set" read as an unfinished form, which is how an operator ends up
        // hunting for a credential that a public-client registration does not
        // have. The field is optional: with it empty the hub authenticates the
        // code exchange with PKCE alone.
        state.textContent = '— optional; not set, so this hub signs in as a public client using PKCE';
      }
    }

    function renderOIDCStatus(d) {
      const badge = document.getElementById('oidcStatus');
      if (badge) {
        if (d.active && d.active.enabled) {
          badge.innerHTML = d.active.idp_ready
            ? '<span class="badge complete">active</span>'
            : '<span class="badge failed" title="' + esc(d.active.error || '') + '">IdP unresolved</span>';
        } else {
          badge.innerHTML = '<span class="badge unknown">off</span>';
        }
      }

      const note = document.getElementById('oidcRestartNote');
      if (!note) return;
      if (!d.restart_required) {
        note.style.display = 'none';
        note.textContent = '';
        return;
      }
      // The authenticator is built once at startup, so a saved change is inert
      // until the process restarts. Saying which direction the gap runs matters:
      // "saved on, running off" is a hub still wide open.
      const running = d.active && d.active.enabled
        ? 'currently running SSO against ' + (d.active.issuer || 'an unnamed issuer')
        : 'currently running without SSO';
      note.style.display = '';
      note.style.cssText = 'display:block;font-size:12px;padding:8px 10px;margin-bottom:12px;' +
        'border:1px solid var(--border);border-left:3px solid var(--warn,#d29922);border-radius:4px';
      note.textContent = 'Saved, but not in force yet: this hub is ' + running +
        '. Restart the hub to apply the saved configuration.';
    }

    function renderOIDCMappings() {
      const body = document.getElementById('oidcMappingsBody');
      const empty = document.getElementById('oidcMappingsEmpty');
      if (!body) return;
      if (!oidcState.mappings.length) {
        body.innerHTML = '';
        if (empty) {
          const saved = oidcState.view && oidcState.view.rbac && oidcState.view.rbac.saved_enforced;
          empty.style.display = '';
          empty.textContent = saved
            ? 'No role mappings. Every signed-in user gets the default role above; admin emails still apply.'
            : 'No role mappings.';
        }
        return;
      }
      if (empty) empty.style.display = 'none';

      const claims = (oidcState.view && oidcState.view.claims) || ['group', 'role', 'email', 'sub'];
      const roles = (oidcState.view && oidcState.view.roles) || ['none', 'viewer', 'operator', 'maintainer', 'admin'];
      const options = (values, selected) => values.map(v =>
        '<option value="' + esc(v) + '"' + (v === selected ? ' selected' : '') + '>' + esc(v) + '</option>'
      ).join('');

      // Index-addressed handlers, never interpolated values: a project name or a
      // claim value with a quote in it would otherwise break out of the attribute.
      // This is the bug class that broke per-project switching four times.
      body.innerHTML = oidcState.mappings.map((m, i) =>
        '<tr>' +
          '<td><select class="form-select" data-oidc-field="claim" data-oidc-row="' + i + '">' +
            options(claims, m.claim) + '</select></td>' +
          '<td><input class="form-input" data-oidc-field="value" data-oidc-row="' + i + '" value="' +
            esc(m.value || '') + '" placeholder="cloop-admins"></td>' +
          '<td><select class="form-select" data-oidc-field="role" data-oidc-row="' + i + '">' +
            options(roles, m.role) + '</select></td>' +
          '<td><input class="form-input" data-oidc-field="project" data-oidc-row="' + i + '" value="' +
            esc(m.project || '') + '" placeholder="all"></td>' +
          '<td><input class="form-input" data-oidc-field="executor" data-oidc-row="' + i + '" value="' +
            esc(m.executor || '') + '" placeholder="all"></td>' +
          '<td><button class="btn danger" data-oidc-remove="' + i + '">Remove</button></td>' +
        '</tr>'
      ).join('');

      body.querySelectorAll('[data-oidc-field]').forEach(el => {
        el.addEventListener('change', () => {
          const row = parseInt(el.getAttribute('data-oidc-row'), 10);
          if (!oidcState.mappings[row]) return;
          oidcState.mappings[row][el.getAttribute('data-oidc-field')] = el.value;
        });
      });
      body.querySelectorAll('[data-oidc-remove]').forEach(el => {
        el.addEventListener('click', () => {
          oidcState.mappings.splice(parseInt(el.getAttribute('data-oidc-remove'), 10), 1);
          renderOIDCMappings();
        });
      });
    }

    function oidcAddMapping() {
      oidcState.mappings.push({claim: 'group', value: '', role: 'viewer', project: '', executor: ''});
      renderOIDCMappings();
    }

    function oidcNum(id) {
      const el = document.getElementById(id);
      if (!el) return 0;
      const n = parseInt(el.value, 10);
      return isNaN(n) ? 0 : n;
    }

    function oidcList(id) {
      const el = document.getElementById(id);
      if (!el) return [];
      return el.value.split(',').map(s => s.trim()).filter(Boolean);
    }

    function saveOIDCSettings() {
      return putOIDCSettings(false);
    }

    // putOIDCSettings saves the form. The hub refuses a save that would switch
    // RBAC on, or leave single sign-on without a policy, unless it says it means
    // to (Task 20395): that refusal is asked as a question, and resent only on yes.
    function putOIDCSettings(confirmed) {
      const secretEl = document.getElementById('oidcClientSecret');
      const body = {
        enabled: !!document.getElementById('oidcEnabled').checked,
        issuer: document.getElementById('oidcIssuer').value,
        client_id: document.getElementById('oidcClientId').value,
        redirect_url: document.getElementById('oidcRedirectUrl').value,
        scopes: oidcList('oidcScopes'),
        admin_emails: oidcList('oidcAdminEmails'),
        default_role: document.getElementById('oidcDefaultRole').value,
        role_mappings: oidcState.mappings,
        session_ttl_hours: oidcNum('oidcSessionTtl'),
        idle_timeout_hours: oidcNum('oidcIdleTimeout'),
        refresh_interval_minutes: oidcNum('oidcRefreshInterval'),
        max_claim_age_minutes: oidcNum('oidcMaxClaimAge'),
        clock_skew_seconds: oidcNum('oidcClockSkew'),
        require_idp: !!document.getElementById('oidcRequireIdp').checked,
        require_rbac: !!document.getElementById('oidcRequireRbac').checked,
        cookie_secure: document.getElementById('oidcCookieSecure').value,
      };
      if (confirmed) body.confirm_rbac = true;
      // Only send the secret when one was typed. Absent means keep, which is what
      // makes every other field editable without re-entering a credential the
      // panel cannot display.
      const typed = secretEl ? secretEl.value.trim() : '';
      if (typed) body.client_secret = typed;

      return apiMethod('PUT', '/api/config/oidc', body).then(d => {
        if (oidcErrDetail(d, 'rbac_change') && !confirmed) {
          const msg = oidcErrText(d);
          if (confirm(msg.charAt(0).toUpperCase() + msg.slice(1) + '.')) return putOIDCSettings(true);
          return;
        }
        if (d && d.error) {
          oidcShowFieldError(d);
          return;
        }
        if (secretEl) secretEl.value = '';
        oidcState.view = d;
        oidcState.mappings = (d.role_mappings || []).map(m => Object.assign({}, m));
        renderOIDCSettings(d);
        toast(d.restart_required
          ? 'Saved — restart the hub to apply it'
          : 'Single sign-on settings saved', 'ok');
      }).catch(() => toast('Request failed', 'err'));
    }

    // oidcErrText pulls a human message out of either error shape the hub emits.
    //
    // jsonErr writes {"error": "..."} and apierror.WriteError writes
    // {"error": {code, message, details}}. These routes use the second, but a
    // middleware refusal on the way in — a body-size limit, a permission gate —
    // can produce the first, and "[object Object]" is a worse thing to show an
    // operator than either message.
    function oidcErrText(d) {
      if (!d || !d.error) return 'Request failed';
      if (typeof d.error === 'string') return d.error;
      return d.error.message || 'Request failed';
    }

    // oidcErrField is the input the hub blamed, if it named one.
    //
    // Reads errorDetail as well as error: parseAPIResponse now flattens an apierror
    // body to its message so ~100 render sites stop showing "[object Object]"
    // (Task 20320), and it parks the original object there precisely so the details
    // this needs survive the flattening.
    function oidcErrField(d) {
      return oidcErrDetail(d, 'field');
    }

    // oidcErrDetail reads one of the details an apierror body carries, from
    // either shape parseAPIResponse may leave it in.
    function oidcErrDetail(d, key) {
      if (!d) return '';
      var e = (d.error && typeof d.error !== 'string') ? d.error : d.errorDetail;
      return (e && e.details && e.details[key]) || '';
    }

    // oidcShowFieldError puts a refusal beside the input that caused it.
    //
    // The backend names the field in the error details precisely so this can focus
    // it: "issuer must be https" is actionable next to the issuer box and merely
    // annoying in a toast.
    function oidcShowFieldError(d) {
      const msg = oidcErrText(d);
      const note = document.getElementById('oidcStatusNote');
      if (note) {
        note.textContent = msg;
        note.style.color = 'var(--err,#f85149)';
      }
      const field = oidcErrField(d);
      const input = field ? document.getElementById(oidcFieldElementID(field)) : null;
      if (input) {
        input.focus();
        if (typeof input.scrollIntoView === 'function') {
          input.scrollIntoView({block: 'center', behavior: 'smooth'});
        }
      }
      toast(msg, 'err');
    }

    // oidcFieldElementID maps a config field name onto the input that edits it.
    function oidcFieldElementID(field) {
      const map = {
        issuer: 'oidcIssuer',
        client_id: 'oidcClientId',
        client_secret: 'oidcClientSecret',
        redirect_url: 'oidcRedirectUrl',
        cookie_secure: 'oidcCookieSecure',
        admin_emails: 'oidcAdminEmails',
        default_role: 'oidcDefaultRole',
        require_rbac: 'oidcRequireRbac',
        max_claim_age_minutes: 'oidcMaxClaimAge',
        clock_skew_seconds: 'oidcClockSkew',
      };
      return map[field] || '';
    }

    function oidcClearSecret() {
      if (!confirm('Remove the stored client secret? Sign-in will fail until a new one is set.')) return;
      apiMethod('PUT', '/api/config/oidc', {clear_client_secret: true}).then(d => {
        if (d && d.error) { toast(oidcErrText(d), 'err'); return; }
        oidcState.view = d;
        renderOIDCSettings(d);
        toast('Client secret removed', 'ok');
      }).catch(() => toast('Request failed', 'err'));
    }

    // oidcTestIssuer contacts the issuer currently in the box without saving it.
    //
    // Reachability is the one thing static validation cannot answer, and it is the
    // most common thing to get wrong — a fat-fingered tenant id is a perfectly
    // valid https URL that will fail every sign-in. Testing before saving turns
    // that from an outage into a line of red text.
    function oidcTestIssuer() {
      const note = document.getElementById('oidcTestNote');
      const issuer = document.getElementById('oidcIssuer').value.trim();
      if (note) {
        note.style.color = 'var(--muted)';
        note.textContent = 'Contacting ' + (issuer || 'the saved issuer') + '…';
      }
      api('/api/config/oidc/test', {issuer: issuer}).then(d => {
        if (!note) return;
        if (!d || (d.error && !('ok' in d))) {
          note.style.color = 'var(--err,#f85149)';
          note.textContent = oidcErrText(d);
          return;
        }
        if (d.ok) {
          note.style.color = 'var(--ok,#3fb950)';
          const keys = d.result ? d.result.signing_keys : 0;
          note.textContent = 'Reached ' + d.issuer + ' — ' + keys + ' usable signing key(s).';
          return;
        }
        note.style.color = 'var(--err,#f85149)';
        note.textContent = d.error + (d.remediation ? ' — ' + d.remediation : '');
      }).catch(() => {
        if (note) {
          note.style.color = 'var(--err,#f85149)';
          note.textContent = 'Request failed';
        }
      });
    }

    // ── collection policy (Task 20311) ──────────────────────────────────────────
    //
    // The switch that decides whether any of the above exists. Collection is off
    // unless an operator turns it on, and editing a YAML key and restarting was the
    // only way to do that — a poor place for the control of a feature whose subject
    // is what the hub records about its users.
    //
    // user.manage, which is admin-only. The markup carries data-global-perm so the
    // block is hidden for everyone else; the guard below keeps a reader without it
    // from also firing a request that can only 403.

    // An error answer resolves like any other body (api() normalises it to
    // {error}), so it is turned back into a failure here: rendered as a policy, a
    // refused save would read as collection switched off.
    function _telPolicyBody(d) {
      if (!d || d.error) throw new Error((d && d.error) || 'no answer');
      return d;
    }

    function _telPolicyNote(text) {
      const note = document.getElementById('telemetryPolicyNote');
      if (note) note.textContent = text;
    }
    const _telPolicyFailed = what => err => _telPolicyNote(what + ': ' + ((err && err.message) || err));

    function loadTelemetryPolicy() {
      if (!canGlobal('user.manage')) return Promise.resolve();
      return api('/api/config/telemetry')
        .then(_telPolicyBody)
        .then(_telRenderPolicy)
        .catch(_telPolicyFailed('Could not read the collection policy'));
    }

    function _telRenderPolicy(d) {
      const sources = Array.isArray(d.sources) ? d.sources : [];
      const enabled = !!d.enabled;
      const box = document.getElementById('telemetryPolicyEnabled');
      if (box) box.checked = enabled;

      const badge = document.getElementById('telemetryPolicyBadge');
      if (badge) {
        const on = sources.filter(s => s.collect).length;
        badge.textContent = !enabled
          ? (d.configured ? 'off' : 'off (default)')
          : (on === sources.length ? 'collecting' : 'collecting · ' + on + ' of ' + sources.length);
        badge.className = 'badge ' + (enabled ? 'running' : 'unknown');
      }

      // One checkbox per source, from the server's list: the set of front ends is a
      // Go constant, and a hardcoded pair here would be the copy that goes stale
      // the day a third one ships. Ticked from the stored selection, not from what
      // is collected now, so a narrowing reads the same while switched off.
      const host = document.getElementById('telemetryPolicySources');
      if (host) {
        host.innerHTML = sources.map(s => '<label class="tel-src"><input type="checkbox" data-tel-source="' +
          esc(s.name) + '"' + (s.selected ? ' checked' : '') + (enabled ? '' : ' disabled') + '>' +
          (s.name === 'glasses' ? 'display glasses' : esc(s.name)) + '</label>').join('');
      }

      const stored = d.stored || {};
      const chip = document.getElementById('telemetryPolicyStored');
      if (chip) {
        if (stored.error) {
          chip.textContent = 'stored: unknown (' + stored.error + ')';
        } else {
          const sess = (stored.sessions || 0) + (stored.sessions_capped ? '+' : '');
          chip.textContent = (stored.events || 0) + ' event(s) stored · ' + sess + ' session(s)' +
            (stored.oldest ? ' · oldest ' + _telTime(stored.oldest) : '');
        }
      }

      // The last clause is the one worth saying out loud: an operator switching
      // collection off for a privacy reason has not thereby deleted anything, and
      // the count above is what remains.
      _telPolicyNote((d.retention_days
        ? 'Events age out after ' + d.retention_days + ' day(s)'
        : 'Events are kept until the table fills') +
        '; the table holds at most ' + (d.max_rows || 0).toLocaleString() + ' rows' +
        '; turning collection off stops new events and deletes none — remove them with ' +
        'cloop hub telemetry prune.');
    }

    // onTelemetryPolicyToggle greys the per-source boxes while the master switch is
    // off, and ticks them all when it goes on with none ticked.
    //
    // The boxes show the stored selection, which is every front end on a hub that
    // never narrowed it, so normally they are already ticked. The fallback is not
    // cosmetic: with every box clear, ticking the master and pressing Save would
    // submit "collect, from nowhere", which is stored as off — the operator turns
    // the feature on and watches it stay off, with the form agreeing with them.
    function onTelemetryPolicyToggle() {
      const enabled = !!(document.getElementById('telemetryPolicyEnabled') || {}).checked;
      const boxes = Array.from(document.querySelectorAll('#telemetryPolicySources input[data-tel-source]'));
      const none = boxes.every(cb => !cb.checked);
      boxes.forEach(cb => {
        cb.disabled = !enabled;
        if (enabled && none) cb.checked = true;
      });
    }

    function saveTelemetryPolicy() {
      const enabled = !!(document.getElementById('telemetryPolicyEnabled') || {}).checked;
      const picked = [];
      document.querySelectorAll('#telemetryPolicySources input[data-tel-source]').forEach(cb => {
        if (cb.checked) picked.push(cb.getAttribute('data-tel-source'));
      });
      // Three cases; the middle one is the trap. An empty list sent with the master
      // on reaches the hub as "no restriction" and collects precisely what was just
      // unticked, so it is read as "no front end left to collect from", i.e. off.
      //
      // Switching the master off sends no source list at all, so a narrowing
      // survives being turned off and on again rather than silently widening.
      const body = enabled ? {enabled: picked.length > 0, sources: picked} : {enabled: false};

      const btn = document.getElementById('telemetryPolicySave');
      if (btn) btn.disabled = true;
      return apiMethod('PUT', '/api/config/telemetry', body)
        .then(_telPolicyBody)
        .then(d => {
          _telRenderPolicy(d);
          toast(d.enabled ? 'Telemetry collection on' : 'Telemetry collection off', 'ok');
        })
        .catch(_telPolicyFailed('Save failed'))
        .finally(() => { if (btn) btn.disabled = false; });
    }


    // _telTime renders a hub-side timestamp, as the Telemetry tab does.
    function _telTime(s) {
      return String(s || '').replace('T', ' ').replace(/\.\d+Z?$/, '').replace('Z', '');
    }

    // GitHub App connection (Task 20306): the Settings half. The project
    // Overview's repository assignment, the other half, stays in the bundle
    // (32-githubapp.js) because the Overview renders it on first paint.
    const ghAppState = {
      installations: [],   // discovered, awaiting a choice
      connectKey: '',      // the pasted PEM, held only until the secret is minted
      connectAppID: '',
      connectBaseURL: '',
      apps: [],            // stored github_app secrets
    };

    // ---------------------------------------------------------------------------
    // Settings: connect an App
    // ---------------------------------------------------------------------------

    // ghAppDiscover asks the hub where the pasted App is installed.
    //
    // Nothing is stored by this call. The key stays in ghAppState until the
    // operator picks an installation and the secret is minted, and is dropped
    // immediately afterwards.
    function ghAppDiscover() {
      const appID = (document.getElementById('ghAppId') || {}).value || '';
      const key = (document.getElementById('ghAppKey') || {}).value || '';
      const baseURL = (document.getElementById('ghAppBaseUrl') || {}).value || '';
      if (!appID.trim() || !key.trim()) {
        toast('App ID and private key are both required', 'error');
        return;
      }
      const out = document.getElementById('ghAppInstallations');
      if (out) out.innerHTML = '<div class="empty-state"><p>Asking GitHub…</p></div>';

      api('/api/github-app/installations', {
        app_id: appID.trim(),
        private_key: key,
        base_url: baseURL.trim(),
      }).then(d => {
        if (!d || d.error) {
          if (out) out.innerHTML = '<div style="color:var(--danger);font-size:12px">' +
            esc((d && d.error) || 'discovery failed') + '</div>';
          return;
        }
        ghAppState.installations = d.installations || [];
        ghAppState.connectKey = key;
        ghAppState.connectAppID = appID.trim();
        ghAppState.connectBaseURL = baseURL.trim();
        ghAppRenderInstallations();
      }).catch(e => {
        if (out) out.innerHTML = '<div style="color:var(--danger);font-size:12px">' +
          esc(String(e && e.message ? e.message : e)) + '</div>';
      });
    }

    function ghAppRenderInstallations() {
      const out = document.getElementById('ghAppInstallations');
      if (!out) return;
      const list = ghAppState.installations;
      if (!list.length) {
        out.innerHTML = '<div class="empty-state"><p>This App is not installed anywhere yet.</p></div>';
        return;
      }
      // "all" vs "selected" is worth showing: an operator who cannot reach a
      // repository needs to know whether to widen the installation or tick a box.
      out.innerHTML =
        '<div style="font-size:12px;color:var(--muted);margin-bottom:6px">' +
        'Choose the account whose repositories cloop should reach:</div>' +
        list.map(i =>
          '<div class="gh-install-row" style="display:flex;align-items:center;gap:10px;padding:6px 0">' +
            '<button class="btn btn-sm" data-act="ghAppSaveInstallation" data-arg="' + esc(String(i.id)) + '">Use</button>' +
            '<div><strong>' + esc(i.account) + '</strong> ' +
              '<span class="badge unknown" style="font-size:10px">' + esc(i.account_type) + '</span> ' +
              '<span style="font-size:11px;color:var(--muted)">installation ' + esc(String(i.id)) +
              ', covers ' + esc(i.repository_selection) + ' repositories</span>' +
            '</div>' +
          '</div>').join('');
    }

    // ghAppSaveInstallation mints the github_app secret for a chosen installation.
    function ghAppSaveInstallation(installationID) {
      const chosen = ghAppState.installations.find(i => String(i.id) === String(installationID));
      if (!chosen) return;
      const nameField = document.getElementById('ghAppName');
      const name = (nameField && nameField.value.trim()) ||
        ('github-' + String(chosen.account || 'app').toLowerCase().replace(/[^a-z0-9-]+/g, '-'));

      const payload = {
        app_id: Number(ghAppState.connectAppID),
        installation_id: chosen.id,
        private_key: ghAppState.connectKey,
      };
      if (ghAppState.connectBaseURL) payload.base_url = ghAppState.connectBaseURL;

      api('/api/secrets', {
        name: name,
        kind: 'github_app',
        payload: JSON.stringify(payload),
        metadata: {
          account: chosen.account,
          account_type: chosen.account_type,
          installation_id: String(chosen.id),
        },
        // Shared, not personal: an App connected by an admin is infrastructure the
        // whole hub grants from. A personal one would be invisible to every other
        // maintainer and could not be assigned to a shared project.
        personal: false,
      }).then(d => {
        if (!d || d.error) { toast((d && d.error) || 'could not store the App', 'error'); return; }
        toast('Connected ' + chosen.account, 'success');
        // The key is no longer needed anywhere in this page.
        ghAppState.connectKey = '';
        ghAppState.installations = [];
        ['ghAppKey', 'ghAppId', 'ghAppName', 'ghAppBaseUrl'].forEach(id => {
          const el = document.getElementById(id);
          if (el) el.value = '';
        });
        const out = document.getElementById('ghAppInstallations');
        if (out) out.innerHTML = '';
        loadGitHubApps();
      }).catch(e => toast(String(e && e.message ? e.message : e), 'error'));
    }

    // loadGitHubApps lists the github_app secrets this hub holds.
    function loadGitHubApps() {
      if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) return Promise.resolve();
      return api('/api/secrets').then(d => {
        const secrets = (d && d.secrets) || [];
        ghAppState.apps = secrets.filter(s => s.kind === 'github_app');
        const el = document.getElementById('ghAppList');
        if (!el) return;
        if (!ghAppState.apps.length) {
          el.innerHTML = '<div class="empty-state"><p>No GitHub App connected yet.</p></div>';
          return;
        }
        el.innerHTML = ghAppState.apps.map(a => {
          const md = a.metadata || {};
          const where = md.account
            ? esc(md.account) + (md.account_type ? ' (' + esc(md.account_type) + ')' : '')
            : 'installation ' + esc(md.installation_id || '?');
          return '<div style="display:flex;align-items:center;gap:10px;padding:6px 0;' +
            'border-bottom:1px solid var(--border)">' +
            '<strong>' + esc(a.name) + '</strong>' +
            '<span style="font-size:11px;color:var(--muted)">' + where + '</span>' +
            '<span style="flex:1"></span>' +
            '<span style="font-size:11px;color:var(--muted)">' +
              esc(String(a.active_grants || 0)) + ' active grant(s)</span>' +
            '</div>';
        }).join('');
      }).catch(() => {});
    }


    // CI/CD pipeline federation panel (Task 20278).
    //
    // Lives on the Settings tab because that is where the task asked for it and
    // because the thing it edits is a deployment-wide policy, not a per-project
    // one. Every call here is global-scope — no pUrl() — for the same reason.
    //
    // The panel has four parts, in the order an operator needs them:
    //   1. the switch, plus whether there is actually a credential to relay with
    //   2. the allowlist, which is the security-relevant part
    //   3. live sessions, so "who is spending right now" is answerable
    //   4. recent exchanges, which is where a refused pipeline is diagnosed

    const ciState = {
      settings: null,
      rules: [],
      sessions: [],
      exchanges: [],
      editing: null,   // rule id being edited, or null for "new"
    };

    // ---------------------------------------------------------------------------
    // settings
    // ---------------------------------------------------------------------------

    function ciRenderSettings(d) {
      ciState.settings = d;
      const status = document.getElementById('ciStatus');
      const note = document.getElementById('ciStatusNote');
      const snippet = document.getElementById('ciSnippet');
      if (!status || !note) return;

      status.innerHTML = d.enabled
        ? '<span class="badge complete" style="font-size:10px">enabled</span>'
        : '<span class="badge unknown" style="font-size:10px">disabled</span>';

      const parts = [];
      if (d.enabled) {
        // The order matters: a hub with federation on and nothing to relay with
        // answers every exchange with a 503, and the operator should learn that
        // here rather than from a pipeline three days later.
        if (!d.upstream_ready) {
          parts.push('<strong>No Anthropic credential to relay with.</strong> ' +
                     'Set <code>anthropic.api_key</code> above, or ' +
                     '<code>ui.ci.upstream_auth_token</code> in config.yaml — until then ' +
                     'every pipeline gets a 503.');
        } else {
          parts.push('Pipelines federate at <code>' + esc(d.base_url.replace(/\/api\/ci\/anthropic$/, '')) +
                     '/api/ci/token</code> and relay through <code>' + esc(d.base_url) + '</code>.');
          parts.push('Relaying to ' + esc(d.upstream) + '.');
        }
        parts.push('Tokens must be minted with audience <code>' + esc(d.audience) + '</code>.');
      } else {
        parts.push('CI federation is off. The exchange and relay endpoints refuse, ' +
                   'whatever rules are listed below.');
      }
      if (d.error) {
        parts.push('<span style="color:var(--danger)">Service error: ' + esc(d.error) + '</span>');
      }
      note.innerHTML = parts.join('<br>');

      const toggle = document.getElementById('ciEnabled');
      if (toggle) toggle.checked = !!d.enabled;
      const aud = document.getElementById('ciAudience');
      if (aud && document.activeElement !== aud) aud.value = d.audience || '';
      const iss = document.getElementById('ciIssuer');
      if (iss && document.activeElement !== iss) iss.value = d.issuer || '';
      const models = document.getElementById('ciDefaultModels');
      if (models && document.activeElement !== models) {
        models.value = (d.default_models || []).join(', ');
      }
      if (snippet) snippet.textContent = d.snippet || '';
    }

    function loadCISettings() {
      if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) return Promise.resolve();
      return api('/api/ci/config').then(d => {
        if (!d || d.error) return;
        ciRenderSettings(d);
      }).catch(() => {});
    }

    function saveCISettings() {
      const body = {
        enabled: !!document.getElementById('ciEnabled').checked,
        issuer: document.getElementById('ciIssuer').value.trim(),
        audience: document.getElementById('ciAudience').value.trim(),
        default_models: document.getElementById('ciDefaultModels').value
          .split(',').map(s => s.trim()).filter(Boolean),
      };
      apiMethod('PUT', '/api/ci/config', body).then(d => {
        if (d && d.error) { toast(d.error, 'err'); return; }
        toast('CI federation settings saved', 'ok');
        ciRenderSettings(d);
        loadCIRules();
        loadCISessions();
      }).catch(() => toast('Request failed', 'err'));
    }

    function copyCISnippet() {
      const el = document.getElementById('ciSnippet');
      if (!el) return;
      const text = el.textContent || '';
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
          .then(() => toast('Workflow snippet copied', 'ok'))
          .catch(() => toast('Could not copy — select the text instead', 'info'));
        return;
      }
      toast('Copy is unavailable here — select the text instead', 'info');
    }

    // ---------------------------------------------------------------------------
    // rules
    // ---------------------------------------------------------------------------

    function ciMatcherSummary(r) {
      const bits = [];
      if (r.repository) bits.push('repo ' + esc(r.repository));
      if (r.ref) bits.push('ref ' + esc(r.ref));
      if (r.workflow) bits.push('workflow ' + esc(r.workflow));
      if (r.environment) bits.push('env ' + esc(r.environment));
      if (r.actor) bits.push('actor ' + esc(r.actor));
      if (r.event_name) bits.push('on ' + esc(r.event_name));
      if (r.condition) bits.push('<code>' + esc(r.condition) + '</code>');
      return bits.length ? bits.join(' · ') : '<em>matches nothing</em>';
    }

    function ciRenderRules() {
      const body = document.getElementById('ciRulesBody');
      const empty = document.getElementById('ciRulesEmpty');
      if (!body) return;
      if (!ciState.rules.length) {
        body.innerHTML = '';
        if (empty) {
          empty.style.display = '';
          empty.textContent = 'No pipelines are allowlisted. Until one is, every ' +
            'exchange is refused even with federation enabled.';
        }
        return;
      }
      if (empty) empty.style.display = 'none';

      body.innerHTML = ciState.rules.map((r, i) => {
        const state = r.broken
          ? '<span class="badge failed" title="' + esc(r.broken) + '">not in force</span>'
          : (r.enabled ? '<span class="badge complete">enabled</span>'
                       : '<span class="badge unknown">disabled</span>');
        const live = r.live_sessions
          ? ' <span class="badge running">' + r.live_sessions + ' live</span>' : '';
        const matched = r.last_matched_at && !r.last_matched_at.startsWith('0001')
          ? relTime(r.last_matched_at) : 'never';
        return '<tr>' +
          '<td><strong>' + esc(r.name || '(unnamed)') + '</strong>' + live +
            '<div class="muted" style="font-size:11px">' + ciMatcherSummary(r) + '</div></td>' +
          '<td>' + state + '</td>' +
          '<td style="font-size:11px">' + (r.effective_models || []).map(esc).join('<br>') + '</td>' +
          '<td style="font-size:11px">' + r.effective_max_requests + ' req<br>' +
            Math.round(r.effective_ttl_seconds / 60) + ' min</td>' +
          '<td style="font-size:11px">' + esc(matched) + '</td>' +
          '<td><button class="btn btn-sm" data-ci-edit="' + i + '">Edit</button> ' +
            '<button class="btn btn-sm btn-danger" data-ci-delete="' + i + '">Delete</button></td>' +
          '</tr>';
      }).join('');

      // Listeners rather than inline onclick with interpolated data: a rule name
      // containing a quote has broken this dashboard before (Tasks 163, 20033),
      // and an index is the one thing that cannot carry a quote.
      body.querySelectorAll('[data-ci-edit]').forEach(btn => {
        btn.addEventListener('click', () => ciEditRule(+btn.getAttribute('data-ci-edit')));
      });
      body.querySelectorAll('[data-ci-delete]').forEach(btn => {
        btn.addEventListener('click', () => ciDeleteRule(+btn.getAttribute('data-ci-delete')));
      });
    }

    function loadCIRules() {
      if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) return Promise.resolve();
      return api('/api/ci/rules').then(d => {
        if (!d || d.error) return;
        ciState.rules = d.rules || [];
        ciRenderRules();
      }).catch(() => {});
    }

    function ciFormValues() {
      const val = id => (document.getElementById(id) || {value: ''}).value.trim();
      const num = id => parseInt(val(id), 10) || 0;
      return {
        name: val('ciRuleName'),
        enabled: !!(document.getElementById('ciRuleEnabled') || {}).checked,
        repository: val('ciRuleRepo'),
        ref: val('ciRuleRef'),
        workflow: val('ciRuleWorkflow'),
        environment: val('ciRuleEnv'),
        actor: val('ciRuleActor'),
        event_name: val('ciRuleEvent'),
        condition: val('ciRuleCondition'),
        models: val('ciRuleModels').split(',').map(s => s.trim()).filter(Boolean),
        max_requests: num('ciRuleMaxRequests'),
        max_output_tokens: num('ciRuleMaxOutput'),
        ttl_seconds: num('ciRuleTTL') * 60,
        project: val('ciRuleProject'),
      };
    }

    function ciSetForm(r) {
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };
      set('ciRuleName', r.name);
      set('ciRuleRepo', r.repository);
      set('ciRuleRef', r.ref);
      set('ciRuleWorkflow', r.workflow);
      set('ciRuleEnv', r.environment);
      set('ciRuleActor', r.actor);
      set('ciRuleEvent', r.event_name);
      set('ciRuleCondition', r.condition);
      set('ciRuleModels', (r.models || []).join(', '));
      set('ciRuleMaxRequests', r.max_requests || '');
      set('ciRuleMaxOutput', r.max_output_tokens || '');
      set('ciRuleTTL', r.ttl_seconds ? Math.round(r.ttl_seconds / 60) : '');
      set('ciRuleProject', r.project);
      const en = document.getElementById('ciRuleEnabled');
      if (en) en.checked = r.enabled !== false;
      const testOut = document.getElementById('ciRuleTestResult');
      if (testOut) testOut.innerHTML = '';
      const title = document.getElementById('ciRuleFormTitle');
      if (title) title.textContent = ciState.editing ? 'Edit pipeline rule' : 'Add pipeline rule';
    }

    function ciEditRule(i) {
      const r = ciState.rules[i];
      if (!r) return;
      ciState.editing = r.id;
      ciSetForm(r);
      const form = document.getElementById('ciRuleForm');
      if (form) { form.style.display = ''; form.scrollIntoView({behavior: 'smooth', block: 'nearest'}); }
    }

    function ciNewRule() {
      ciState.editing = null;
      ciSetForm({enabled: true});
      const form = document.getElementById('ciRuleForm');
      if (form) form.style.display = '';
    }

    function ciCancelRule() {
      ciState.editing = null;
      const form = document.getElementById('ciRuleForm');
      if (form) form.style.display = 'none';
    }

    function ciSaveRule() {
      const body = ciFormValues();
      const editing = ciState.editing;
      const req = editing
        ? apiMethod('PUT', '/api/ci/rules/' + encodeURIComponent(editing), body)
        : apiMethod('POST', '/api/ci/rules', body);
      req.then(d => {
        if (d && d.error) { toast(d.error, 'err'); return; }
        // An edit revokes the sessions the old text minted. Saying so is the
        // difference between a surprising 401 in a running pipeline and an
        // expected one.
        if (d && d.revoked_sessions) {
          toast('Rule saved — ' + d.revoked_sessions + ' live session(s) revoked', 'ok');
        } else {
          toast('Rule saved', 'ok');
        }
        ciCancelRule();
        loadCIRules();
        loadCISessions();
      }).catch(() => toast('Request failed', 'err'));
    }

    function ciDeleteRule(i) {
      const r = ciState.rules[i];
      if (!r) return;
      const extra = r.live_sessions
        ? '\n\n' + r.live_sessions + ' live session(s) will be revoked immediately.' : '';
      if (!confirm('Delete the rule "' + (r.name || r.id) + '"?' + extra)) return;
      apiMethod('DELETE', '/api/ci/rules/' + encodeURIComponent(r.id)).then(d => {
        if (d && d.error) { toast(d.error, 'err'); return; }
        toast('Rule deleted', 'ok');
        loadCIRules();
        loadCISessions();
      }).catch(() => toast('Request failed', 'err'));
    }

    function ciTestRule() {
      const body = ciFormValues();
      const out = document.getElementById('ciRuleTestResult');
      apiMethod('POST', '/api/ci/rules/test', body).then(d => {
        if (!out) return;
        if (d && d.error) { out.innerHTML = '<span style="color:var(--danger)">' + esc(d.error) + '</span>'; return; }
        if (!d.valid) {
          out.innerHTML = '<span style="color:var(--danger)">Will not save: ' + esc(d.error) + '</span>';
          return;
        }
        if (d.matched) {
          out.innerHTML = '<span style="color:var(--success)">Valid — admits the sample ' +
            'acme/tool pipeline (push to refs/heads/main, workflow "release", actor "dana").</span>';
          return;
        }
        out.innerHTML = '<span class="muted">Valid, but does not admit the sample pipeline' +
          (d.reason ? ': ' + esc(d.reason) : '.') +
          ' That is expected if your rule names a different repository.</span>';
      }).catch(() => { if (out) out.textContent = 'Request failed'; });
    }

    // ---------------------------------------------------------------------------
    // live sessions
    // ---------------------------------------------------------------------------

    function ciRenderSessions() {
      const body = document.getElementById('ciSessionsBody');
      const empty = document.getElementById('ciSessionsEmpty');
      if (!body) return;
      if (!ciState.sessions.length) {
        body.innerHTML = '';
        if (empty) { empty.style.display = ''; empty.textContent = 'No pipeline is federated right now.'; }
        return;
      }
      if (empty) empty.style.display = 'none';
      body.innerHTML = ciState.sessions.map((s, i) => {
        const who = s.run_url
          ? '<a href="' + esc(s.run_url) + '" target="_blank" rel="noopener">' + esc(s.repository || s.id) + '</a>'
          : esc(s.repository || s.id);
        const u = s.usage || {};
        const tokens = (u.input_tokens || 0) + (u.output_tokens || 0) +
                       (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0);
        return '<tr>' +
          '<td>' + who + '<div class="muted" style="font-size:11px">' +
            esc(s.ref || '') + ' ' + esc(s.workflow || '') + '</div></td>' +
          '<td style="font-size:11px">' + esc(s.rule_name || '') +
            (s.suspended ? ' <span class="badge" title="No hub process serves it right now; the next call from its job restores it">suspended</span>' : '') +
            '</td>' +
          '<td style="font-size:11px">' + (u.requests || 0) + ' req' +
            (u.denied ? ' <span class="badge failed">' + u.denied + ' denied</span>' : '') +
            '<br>' + tokens.toLocaleString() + ' tokens</td>' +
          '<td style="font-size:11px">' + (s.remaining_requests < 0 ? '∞' : s.remaining_requests) + ' left<br>' +
            'expires ' + esc(relTime(s.expires_at)) + '</td>' +
          '<td><button class="btn btn-sm btn-danger" data-ci-revoke="' + i + '">Revoke</button></td>' +
          '</tr>';
      }).join('');
      body.querySelectorAll('[data-ci-revoke]').forEach(btn => {
        btn.addEventListener('click', () => ciRevokeSession(+btn.getAttribute('data-ci-revoke')));
      });
    }

    function loadCISessions() {
      if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) return Promise.resolve();
      return api('/api/ci/sessions').then(d => {
        if (!d || d.error) return;
        ciState.sessions = d.sessions || [];
        ciRenderSessions();
      }).catch(() => {});
    }

    function ciRevokeSession(i) {
      const s = ciState.sessions[i];
      if (!s) return;
      if (!confirm('Revoke this session? The pipeline stops being able to relay immediately.')) return;
      apiMethod('DELETE', '/api/ci/sessions/' + encodeURIComponent(s.id)).then(d => {
        if (d && d.error) { toast(d.error, 'err'); return; }
        toast('Session revoked', 'ok');
        loadCISessions();
      }).catch(() => toast('Request failed', 'err'));
    }

    // ---------------------------------------------------------------------------
    // exchanges
    // ---------------------------------------------------------------------------

    function ciRenderExchanges() {
      const body = document.getElementById('ciExchangesBody');
      const empty = document.getElementById('ciExchangesEmpty');
      if (!body) return;
      if (!ciState.exchanges.length) {
        body.innerHTML = '';
        if (empty) { empty.style.display = ''; empty.textContent = 'No pipeline has tried to federate yet.'; }
        return;
      }
      if (empty) empty.style.display = 'none';
      body.innerHTML = ciState.exchanges.map(e => {
        const verdict = e.accepted
          ? '<span class="badge complete">accepted</span>'
          : '<span class="badge failed">' + esc(e.reason || 'refused') + '</span>';
        const who = e.repository
          ? esc(e.repository) + (e.ref ? ' <span class="muted">' + esc(e.ref) + '</span>' : '')
          : '<em>unverified token</em>';
        return '<tr>' +
          '<td style="font-size:11px">' + esc(relTime(e.at)) + '</td>' +
          '<td>' + who + '</td>' +
          '<td>' + verdict + '</td>' +
          '<td style="font-size:11px">' + esc(e.rule_name || '') + '</td>' +
          '<td style="font-size:11px">' + esc(e.detail || '') + '</td>' +
          '</tr>';
      }).join('');
    }

    function loadCIExchanges() {
      if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) return Promise.resolve();
      return api('/api/ci/exchanges').then(d => {
        if (!d || d.error) return;
        ciState.exchanges = d.exchanges || [];
        ciRenderExchanges();
      }).catch(() => {});
    }

    // loadCIPanel is the single entry point the Settings tab calls.
    function loadCIPanel() {
      if (typeof canGlobal === 'function' && !canGlobal('secret.grant')) {
        const panel = document.getElementById('ciPanel');
        if (panel) panel.style.display = 'none';
        return Promise.resolve();
      }
      return Promise.all([
        loadCISettings(),
        loadCIRules(),
        loadCISessions(),
        loadCIExchanges(),
      ]);
    }

    // loadUSBSettings lists, in the Settings tab, the USB hardware every enrolled
    // device reported (Task 20345). Expose opens that device's virtual-executor
    // dialog, where a sandbox is given the device. The index is into the same
    // /api/executors list the Executors panel renders, in the same order.
    function loadUSBSettings() {
      const el = document.getElementById('usbList');
      if (!el) return;
      api('/api/executors').then(d => {
        const rows = [];
        ((d && d.executors) || []).forEach((ex, i) => ((ex.agent_capabilities || {}).usb_devices || [])
          .filter(u => u.class !== '09').forEach(u => rows.push('<div class="exec-chips"><span class="exec-chip">'
            + esc(ex.name || ex.id) + '</span>' + esc(((u.manufacturer || '') + ' ' + (u.product || '')).trim())
            + ' <code>' + esc(u.vendor_id + ':' + u.product_id) + '</code>' + esc(u.serial ? ' serial ' + u.serial : '')
            + ' <button class="btn" style="padding:2px 8px;font-size:11px" data-act="exposeUSBDevice" data-arg="' + i + '">Expose…</button></div>')));
        el.innerHTML = rows.join('') || '<span class="form-hint">No enrolled device reported USB hardware.</span>';
      }).catch(() => { el.textContent = ''; });
    }

    function exposeUSBDevice(i) {
      window.switchTab('executors');
      window.loadExecutors().then(() => window.panelAct('execadmin', 'openExecutorVirtual', +i));
    }


    // ── Display-glasses link (Task 20194) ───────────────────────────────────────
    //
    // The panel is deliberately small: three buttons and one field, because the
    // interesting part of this feature is what the backend refuses to let the link
    // do, not what the UI does with it.
    //
    // One rule shapes every function here — the URL is returned exactly once, by
    // the mint call, and is not recoverable afterwards. So `_glassesURL` is the
    // only copy that exists, it is never written to localStorage (which would put
    // a live credential somewhere a later XSS could read at leisure), and the
    // status line after a reload can report that a link *exists* without being
    // able to show it.
    //
    // Plain paths rather than pUrl(): a link is a property of the user, not of the
    // selected project, so a ?project_idx here would imply a scope the backend
    // does not have.

    let _glassesURL = '';

    function loadGlassesLink() {
      return api('/api/glasses/link').then(d => {
        _glassesRender((d && d.link) || {});
        return d;
      }).catch(err => {
        const el = document.getElementById('glassesStatus');
        if (el) el.textContent = 'Could not read link status: ' + (err && err.message ? err.message : err);
      });
    }

    function _glassesRender(link) {
      const status = document.getElementById('glassesStatus');
      const gen    = document.getElementById('glassesGenBtn');
      const revoke = document.getElementById('glassesRevokeBtn');
      const copy   = document.getElementById('glassesCopyBtn');
      if (!status) return;

      // Only offer Copy while this page still holds the plaintext. After a reload
      // the button would have nothing to put on the clipboard, and a button that
      // silently copies an empty string is worse than one that is not there.
      if (copy) copy.style.display = _glassesURL ? '' : 'none';

      if (!link.exists) {
        status.innerHTML = 'No link yet. Generating one issues a credential that expires in 30 days.' +
          (link.per_user ? '' : ' <em>This hub has no sign-on configured, so the link belongs to the deployment rather than to an individual user.</em>');
        if (gen) gen.textContent = 'Generate link';
        if (revoke) revoke.style.display = 'none';
        return;
      }

      // Say which kind of link this is. can_add_tasks is read off the stored token,
      // so a link minted before dictation existed still reads as read-only.
      const kind = link.can_add_tasks ? 'can add tasks by voice' : 'read-only';
      const expires = link.expires_at ? new Date(link.expires_at) : null;
      const used    = link.last_used_at ? new Date(link.last_used_at) : null;
      let html = 'Active link <code>' + esc(link.prefix || '') + '</code> · ' + kind;
      if (link.owner) html += ' · for ' + esc(link.owner);
      if (expires)    html += ' · expires ' + expires.toLocaleDateString();
      html += used ? ' · last used ' + relTime(used) : ' · never used';
      html += '<br><span style="color:var(--muted)">The URL itself cannot be shown again — cloop stores only a hash. ' +
              'Generating a new link revokes this one.</span>';
      status.innerHTML = html;
      if (gen) gen.textContent = 'Regenerate link';
      if (revoke) revoke.style.display = '';
    }

    function generateGlassesLink() {
      // Confirm only when replacing: rotation silently breaks a pair of glasses
      // that is already working, and the wearer is usually not the person at the
      // dashboard.
      const existing = document.getElementById('glassesRevokeBtn');
      if (existing && existing.style.display !== 'none' &&
          !confirm('Generate a new link?\n\nThe link currently on your glasses stops working immediately.')) {
        return;
      }
      const btn = document.getElementById('glassesGenBtn');
      if (btn) { btn.disabled = true; btn.textContent = 'Generating…'; }

      const ro = document.getElementById('glassesReadOnly');
      apiMethod('POST', '/api/glasses/link', { read_only: !!(ro && ro.checked) }).then(ok).then(d => {
        _glassesURL = (d && d.url) || '';
        const box = document.getElementById('glassesUrlBox');
        const url = document.getElementById('glassesUrl');
        const warn = document.getElementById('glassesWarning');
        if (url) url.value = _glassesURL;
        if (warn) warn.textContent = (d && d.warning) || '';
        if (box) box.style.display = '';
        _glassesRender((d && d.link) || {});
        if (url) { try { url.select(); } catch (e) {} }
        toast('Link generated — copy it now', 'ok');
      }).catch(err => {
        toast('Could not generate link: ' + (err && err.message ? err.message : err), 'err');
      }).finally(() => {
        if (btn) btn.disabled = false;
        loadGlassesLink();
      });
    }

    function copyGlassesLink() {
      if (!_glassesURL) { toast('The link is only available right after generating it', 'err'); return; }
      const done = () => toast('Link copied', 'ok');
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(_glassesURL).then(done).catch(() => _glassesCopyFallback(done));
        return;
      }
      _glassesCopyFallback(done);
    }

    // execCommand('copy') is deprecated but is the only path that works without a
    // secure context, which a hub reached over plain HTTP on a LAN is not.
    function _glassesCopyFallback(done) {
      const url = document.getElementById('glassesUrl');
      if (!url) return;
      url.select();
      try { document.execCommand('copy'); done(); }
      catch (e) { toast('Copy failed — select the field and copy manually', 'err'); }
    }

    function revokeGlassesLink() {
      if (!confirm('Revoke your display-glasses link?\n\nThe app on your glasses stops working immediately.')) return;
      apiMethod('DELETE', '/api/glasses/link').then(ok).then(() => {
        _glassesURL = '';
        const box = document.getElementById('glassesUrlBox');
        if (box) box.style.display = 'none';
        toast('Link revoked', 'ok');
        loadGlassesLink();
      }).catch(err => {
        toast('Could not revoke link: ' + (err && err.message ? err.message : err), 'err');
      });
    }

    // open runs on every visit to the tab, as switchTab's list used to.
    function open() {
      loadConfig(); loadSTTSettings(); loadOIDCSettings(); loadTelemetryPolicy(); loadCIPanel();
      loadGitHubApps(); loadUSBSettings(); loadGlassesLink();
      window.loadHiddenProjects(); window.loadBuildInfo();
    }

    return h.mount({
      open, saveConfigField, saveAnthropicCfg, saveOpenAICfg, saveOllamaCfg, saveSTTCfg,
      clearSTTCfg, confirmReset, saveProvider, saveCCModel, loadOIDCSettings, oidcAddMapping,
      saveOIDCSettings, oidcClearSecret, oidcTestIssuer, oidcEnforce, loadTelemetryPolicy,
      onTelemetryPolicyToggle, saveTelemetryPolicy, ghAppDiscover, ghAppSaveInstallation,
      loadGitHubApps, loadCISettings, saveCISettings, copyCISnippet, loadCIRules, ciNewRule,
      ciCancelRule, ciSaveRule, ciTestRule, loadCISessions, loadCIExchanges, loadCIPanel,
      loadUSBSettings, exposeUSBDevice, loadGlassesLink, generateGlassesLink, copyGlassesLink,
      revokeGlassesLink
    }, 'settings', `
      <div class="section">
        <div class="section-title">Configuration</div>

        <div class="settings-section">
          <h3>Default Provider</h3>
          <div class="form-group">
            <label class="form-label">Active provider</label>
            <select class="form-select" id="cfgProvider">
              <option value="claudecode">claudecode</option>
              <option value="anthropic">anthropic</option>
              <option value="openai">openai</option>
              <option value="ollama">ollama</option>
            </select>
          </div>
          <button class="btn" data-act="saveProvider">Save Provider</button>
        </div>

        <div class="settings-section">
          <h3>ClaudeCode</h3>
          <div class="form-group">
            <label class="form-label">Model</label>
            <input class="form-input" id="cfgCCModel" placeholder="e.g. claude-opus-4-6">
          </div>
          <button class="btn settings-save" data-act="saveCCModel">Save</button>
        </div>

        <div class="settings-section">
          <h3>Anthropic <span id="anthropicKeyStatus"></span></h3>
          <div class="form-group">
            <label class="form-label">API Key (leave blank to keep existing)</label>
            <input class="form-input" id="cfgAnthropicKey" type="password" placeholder="sk-ant-...">
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Model</label>
              <input class="form-input" id="cfgAnthropicModel" placeholder="e.g. claude-opus-4-6">
            </div>
            <div class="form-group">
              <label class="form-label">Base URL (optional)</label>
              <input class="form-input" id="cfgAnthropicBase" placeholder="https://api.anthropic.com">
            </div>
          </div>
          <button class="btn settings-save" data-act="saveAnthropicCfg">Save</button>
        </div>

        <div class="settings-section">
          <h3>OpenAI <span id="openaiKeyStatus"></span></h3>
          <div class="form-group">
            <label class="form-label">API Key (leave blank to keep existing)</label>
            <input class="form-input" id="cfgOpenAIKey" type="password" placeholder="sk-...">
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Model</label>
              <input class="form-input" id="cfgOpenAIModel" placeholder="e.g. gpt-4o">
            </div>
            <div class="form-group">
              <label class="form-label">Base URL (optional)</label>
              <input class="form-input" id="cfgOpenAIBase" placeholder="https://api.openai.com/v1">
            </div>
          </div>
          <button class="btn settings-save" data-act="saveOpenAICfg">Save</button>
        </div>

        <div class="settings-section">
          <h3>Ollama</h3>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Base URL</label>
              <input class="form-input" id="cfgOllamaBase" placeholder="http://localhost:11434">
            </div>
            <div class="form-group">
              <label class="form-label">Model</label>
              <input class="form-input" id="cfgOllamaModel" placeholder="e.g. llama3.2">
            </div>
          </div>
          <button class="btn settings-save" data-act="saveOllamaCfg">Save</button>
        </div>

        <div class="settings-section">
          <h3>Speech-to-text <span id="sttKeyStatus"></span></h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">
            The key behind the <strong>Dictate</strong> button on the Tasks tab and on the display
            glasses. Transcription is hosted (Groq Whisper) — the hub never runs a speech model on
            the control-plane host. Set once here and every project can use it.
          </p>
          <div class="form-group">
            <label class="form-label" for="cfgGroqKey">Groq API key (leave blank to keep existing)</label>
            <input class="form-input" id="cfgGroqKey" type="password" autocomplete="off" placeholder="gsk_...">
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <button class="btn settings-save" data-act="saveSTTCfg">Save</button>
            <button class="btn danger" id="sttClearBtn" style="display:none" data-act="clearSTTCfg">Clear key</button>
          </div>
          <div id="sttStatusNote" style="font-size:12px;color:var(--muted);margin-top:10px"></div>
        </div>

        <div class="settings-section" id="oidcPanel" data-global-perm="user.manage" data-perm-hide>
          <h3>Single sign-on (OIDC) <span id="oidcStatus"></span></h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">
            Authenticate dashboard users against your identity provider instead of a shared token.
            With it on, every browser request needs a provider session, projects created here are
            owned by the user who created them, and roles come from the claims your IdP releases.
            The static <code>--token</code> keeps working for automation.
          </p>
          <div id="oidcRestartNote" style="display:none"></div>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:12px">
            <input type="checkbox" id="oidcEnabled">
            Require single sign-on for the dashboard
          </label>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="oidcIssuer">Issuer URL</label>
              <input class="form-input" id="oidcIssuer" autocomplete="off" placeholder="https://login.microsoftonline.com/&lt;tenant&gt;/v2.0">
            </div>
            <div class="form-group">
              <label class="form-label" for="oidcRedirectUrl">Redirect URL</label>
              <input class="form-input" id="oidcRedirectUrl" autocomplete="off" placeholder="https://cloop.example.com/auth/callback">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="oidcClientId">Client ID</label>
              <input class="form-input" id="oidcClientId" autocomplete="off" placeholder="cloop-dashboard">
            </div>
            <div class="form-group">
              <label class="form-label" for="oidcClientSecret">Client secret <span id="oidcSecretState" class="muted"></span></label>
              <input class="form-input" id="oidcClientSecret" type="password" autocomplete="off" placeholder="leave blank to keep existing">
            </div>
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
            <button class="btn" data-act="oidcTestIssuer">Test connection</button>
            <button class="btn danger" id="oidcClearSecretBtn" style="display:none" data-act="oidcClearSecret">Clear secret</button>
            <span id="oidcTestNote" style="font-size:12px;color:var(--muted)"></span>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="oidcScopes">Scopes (comma separated)</label>
              <input class="form-input" id="oidcScopes" autocomplete="off" placeholder="openid, profile, email">
            </div>
            <div class="form-group">
              <label class="form-label" for="oidcCookieSecure">Session cookie Secure flag</label>
              <select class="form-select" id="oidcCookieSecure">
                <option value="auto">auto — set when the request arrived over TLS</option>
                <option value="always">always</option>
                <option value="never">never (development only)</option>
              </select>
            </div>
          </div>

          <h4 style="margin-top:20px">Who gets in</h4>
          <p style="font-size:12px;color:var(--muted);margin-bottom:8px">
            The default role applies to a signed-in user matching no mapping below.
            <strong>none</strong> denies everything, which is the safe default. With the default role
            unset and no mappings, RBAC is off: everyone who can sign in has full access, so saving
            that asks first. A hub with no administrator cannot be administered, so at least one admin
            email or a mapping granting <code>admin</code> to the whole hub (no project or executor) is
            required before SSO can be turned on.
          </p>
          <div id="oidcRbacNote" style="display:none"></div>
          <button class="btn" id="oidcEnforceBtn" style="display:none;margin-bottom:12px" data-act="oidcEnforce">Enforce deny-by-default</button>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="oidcAdminEmails">Admin emails (comma separated)</label>
              <input class="form-input" id="oidcAdminEmails" autocomplete="off" placeholder="ops@example.com">
            </div>
            <div class="form-group">
              <label class="form-label" for="oidcDefaultRole">Default role</label>
              <select class="form-select" id="oidcDefaultRole"></select>
            </div>
          </div>
          <table class="data-table">
            <thead><tr><th>Claim</th><th>Value</th><th>Role</th><th>Project</th><th>Executor</th><th></th></tr></thead>
            <tbody id="oidcMappingsBody"></tbody>
          </table>
          <div id="oidcMappingsEmpty" class="muted" style="font-size:12px;margin:8px 0"></div>
          <button class="btn" data-act="oidcAddMapping">Add role mapping</button>

          <h4 style="margin-top:20px">Sessions</h4>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="oidcSessionTtl">Absolute lifetime (hours)</label>
              <input class="form-input" id="oidcSessionTtl" type="number" autocomplete="off">
            </div>
            <div class="form-group">
              <label class="form-label" for="oidcIdleTimeout">Idle timeout (hours)</label>
              <input class="form-input" id="oidcIdleTimeout" type="number" autocomplete="off">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="oidcRefreshInterval">Re-check with the IdP every (minutes, -1 to disable)</label>
              <input class="form-input" id="oidcRefreshInterval" type="number" autocomplete="off">
            </div>
            <div class="form-group">
              <label class="form-label" for="oidcMaxClaimAge">Max claim age for privileged actions (minutes, -1 to disable)</label>
              <input class="form-input" id="oidcMaxClaimAge" type="number" autocomplete="off">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="oidcClockSkew">Clock skew allowance (seconds, -1 for none)</label>
              <input class="form-input" id="oidcClockSkew" type="number" autocomplete="off">
            </div>
            <div class="form-group">
              <label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-top:26px">
                <input type="checkbox" id="oidcRequireIdp">
                Refuse to start if the IdP is unreachable
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-top:8px">
                <input type="checkbox" id="oidcRequireRbac">
                Refuse to start without a role policy
              </label>
            </div>
          </div>

          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px">
            <button class="btn settings-save" data-act="saveOIDCSettings">Save</button>
          </div>
          <div id="oidcStatusNote" style="font-size:12px;color:var(--muted);margin-top:10px"></div>
        </div>

        <div class="settings-section" id="telemetryPolicySection" data-global-perm="user.manage" data-perm-hide>
          <h3>Telemetry <span id="telemetryPolicyBadge" class="badge"></span></h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">
            A trail of what this hub's front ends did &mdash; gestures, views, requests, errors &mdash;
            read on the Telemetry tab. Off until switched on; each front end asks before it sends.
          </p>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px">
            <input type="checkbox" id="telemetryPolicyEnabled" data-change="onTelemetryPolicyToggle">
            Collect a diagnostic trail
          </label>
          <div id="telemetryPolicySources" style="margin:8px 0 0 24px;display:flex;gap:16px;flex-wrap:wrap"></div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px">
            <button class="btn settings-save" id="telemetryPolicySave" data-act="saveTelemetryPolicy">Save</button>
            <span id="telemetryPolicyStored" style="font-size:12px;color:var(--muted)"></span>
          </div>
          <div id="telemetryPolicyNote" style="font-size:12px;color:var(--muted);margin-top:10px"></div>
        </div>

        <div class="settings-section" id="ghAppPanel" data-global-perm="secret.grant" data-perm-hide>
          <h3>GitHub Apps</h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">
            Connect a GitHub App so projects can be granted access to specific repositories.
            cloop mints a short-lived installation token per run, scoped by GitHub itself to
            exactly the repositories and permissions granted. When a git proxy is configured the
            token stays in the hub and the sandbox only ever holds a proxy session, so the
            credential is never visible to the agent.
          </p>
          <div id="ghAppList" style="margin-bottom:14px"></div>

          <div style="padding-top:12px;border-top:1px solid var(--border)">
            <div style="font-weight:600;margin-bottom:8px">Connect an App</div>
            <div class="form-row">
              <label for="ghAppId">App ID</label>
              <input type="text" id="ghAppId" class="input" placeholder="1234567" autocomplete="off">
            </div>
            <div class="form-row">
              <label for="ghAppName">Name (optional)</label>
              <input type="text" id="ghAppName" class="input" placeholder="github-acme" autocomplete="off">
            </div>
            <div class="form-row">
              <label for="ghAppBaseUrl">API base URL (GitHub Enterprise only)</label>
              <input type="text" id="ghAppBaseUrl" class="input" placeholder="https://api.github.com" autocomplete="off">
            </div>
            <div class="form-row">
              <label for="ghAppKey">Private key (PEM)</label>
              <textarea id="ghAppKey" class="input" rows="5" spellcheck="false" autocomplete="off"
                placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;..."></textarea>
            </div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <button class="btn settings-save" data-act="ghAppDiscover">Find installations</button>
            </div>
            <div id="ghAppInstallations" style="margin-top:12px"></div>
          </div>
        </div>

        <div class="settings-section" data-global-perm="executor.manage" data-perm-hide>
          <h3>USB devices</h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Hardware attached to enrolled devices. Expose one to a sandbox through a virtual executor of its device.</p>
          <div id="usbList"></div>
        </div>

        <div class="settings-section" id="ciPanel" data-global-perm="secret.grant" data-perm-hide>
          <h3>CI/CD pipelines <span id="ciStatus"></span></h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">
            Let a GitHub Actions job run Claude Code without a long-lived API key in a repository
            secret. The job proves who it is with a short-lived OIDC token, the hub checks it against
            the allowlist below, and hands back a session that relays through this hub. The hub's
            Anthropic credential never reaches the runner, and every call it makes is metered and
            revocable from here.
          </p>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:12px">
            <input type="checkbox" id="ciEnabled">
            Accept OIDC federation from CI/CD pipelines
          </label>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="ciAudience">Token audience</label>
              <input class="form-input" id="ciAudience" placeholder="cloop">
            </div>
            <div class="form-group">
              <label class="form-label" for="ciIssuer">Issuer</label>
              <input class="form-input" id="ciIssuer" placeholder="https://token.actions.githubusercontent.com">
            </div>
          </div>
          <div class="form-group">
            <label class="form-label" for="ciDefaultModels">Default model allowlist (comma separated globs)</label>
            <input class="form-input" id="ciDefaultModels" placeholder="claude-sonnet-*, claude-haiku-*">
          </div>
          <button class="btn settings-save" data-act="saveCISettings">Save</button>
          <div id="ciStatusNote" style="font-size:12px;color:var(--muted);margin-top:10px"></div>

          <h4 style="margin-top:20px">Allowlisted pipelines</h4>
          <p style="font-size:12px;color:var(--muted);margin-bottom:8px">
            First match wins, in creation order. A rule must name a repository — either with a
            pattern whose owner is literal, or with a condition that pins
            <code>assertion.repository</code>.
          </p>
          <table class="data-table">
            <thead><tr><th>Rule</th><th>State</th><th>Models</th><th>Budget</th><th>Last match</th><th></th></tr></thead>
            <tbody id="ciRulesBody"></tbody>
          </table>
          <div id="ciRulesEmpty" class="muted" style="font-size:12px;margin:8px 0"></div>
          <button class="btn" data-act="ciNewRule">Add pipeline rule</button>

          <div id="ciRuleForm" style="display:none;margin-top:16px;padding:12px;border:1px solid var(--border);border-radius:6px">
            <h4 id="ciRuleFormTitle">Add pipeline rule</h4>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="ciRuleName">Name</label>
                <input class="form-input" id="ciRuleName" placeholder="acme/tool releases">
              </div>
              <div class="form-group">
                <label class="form-label" for="ciRuleRepo">Repository (owner must be literal)</label>
                <input class="form-input" id="ciRuleRepo" placeholder="acme/tool or acme/*">
              </div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="ciRuleRef">Ref</label>
                <input class="form-input" id="ciRuleRef" placeholder="refs/heads/main or refs/heads/**">
              </div>
              <div class="form-group">
                <label class="form-label" for="ciRuleWorkflow">Workflow</label>
                <input class="form-input" id="ciRuleWorkflow" placeholder="release, or the .yml path">
              </div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="ciRuleEnv">Environment</label>
                <input class="form-input" id="ciRuleEnv" placeholder="production">
              </div>
              <div class="form-group">
                <label class="form-label" for="ciRuleActor">Actor</label>
                <input class="form-input" id="ciRuleActor" placeholder="dana">
              </div>
              <div class="form-group">
                <label class="form-label" for="ciRuleEvent">Event</label>
                <input class="form-input" id="ciRuleEvent" placeholder="push">
              </div>
            </div>
            <div class="form-group">
              <label class="form-label" for="ciRuleCondition">Condition (CEL over the token claims)</label>
              <input class="form-input" id="ciRuleCondition" style="font-family:monospace;font-size:12px"
                     placeholder='assertion.repository == "acme/tool" &amp;&amp; assertion.ref.startsWith("refs/heads/release/")'>
              <p style="font-size:11px;color:var(--muted);margin-top:4px">
                A strict subset: literals, <code>==</code>, <code>!=</code>, <code>in</code>,
                <code>&amp;&amp;</code>, <code>||</code>, <code>!</code>, and
                <code>startsWith</code> / <code>endsWith</code> / <code>contains</code> /
                <code>matches</code>. Anything else is refused when you save, not when a
                pipeline is denied.
              </p>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="ciRuleModels">Models (blank inherits the default)</label>
                <input class="form-input" id="ciRuleModels" placeholder="claude-sonnet-*">
              </div>
              <div class="form-group">
                <label class="form-label" for="ciRuleProject">Project (optional)</label>
                <input class="form-input" id="ciRuleProject" placeholder="tool">
              </div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="ciRuleMaxRequests">Max requests</label>
                <input class="form-input" id="ciRuleMaxRequests" type="number" min="0" placeholder="500">
              </div>
              <div class="form-group">
                <label class="form-label" for="ciRuleMaxOutput">Max output tokens</label>
                <input class="form-input" id="ciRuleMaxOutput" type="number" min="0" placeholder="32000">
              </div>
              <div class="form-group">
                <label class="form-label" for="ciRuleTTL">Session TTL (minutes)</label>
                <input class="form-input" id="ciRuleTTL" type="number" min="1" placeholder="60">
              </div>
            </div>
            <label style="display:flex;align-items:center;gap:8px;font-size:12px;margin-bottom:10px">
              <input type="checkbox" id="ciRuleEnabled" checked>
              Enabled
            </label>
            <div style="display:flex;gap:8px;flex-wrap:wrap">
              <button class="btn primary" data-act="ciSaveRule">Save rule</button>
              <button class="btn" data-act="ciTestRule">Test</button>
              <button class="btn" data-act="ciCancelRule">Cancel</button>
            </div>
            <div id="ciRuleTestResult" style="font-size:12px;margin-top:10px"></div>
          </div>

          <h4 style="margin-top:20px">Live sessions</h4>
          <table class="data-table">
            <thead><tr><th>Pipeline</th><th>Rule</th><th>Spend</th><th>Remaining</th><th></th></tr></thead>
            <tbody id="ciSessionsBody"></tbody>
          </table>
          <div id="ciSessionsEmpty" class="muted" style="font-size:12px;margin:8px 0"></div>

          <h4 style="margin-top:20px">Recent exchanges</h4>
          <p style="font-size:12px;color:var(--muted);margin-bottom:8px">
            Every federation attempt, accepted or refused. This is where a pipeline reporting
            <code>403</code> is diagnosed — the refusal it sees carries no detail on purpose.
          </p>
          <table class="data-table">
            <thead><tr><th>When</th><th>Pipeline</th><th>Verdict</th><th>Rule</th><th>Detail</th></tr></thead>
            <tbody id="ciExchangesBody"></tbody>
          </table>
          <div id="ciExchangesEmpty" class="muted" style="font-size:12px;margin:8px 0"></div>

          <h4 style="margin-top:20px">Workflow snippet</h4>
          <pre id="ciSnippet" style="font-size:11px;background:var(--code-bg,#1e1e1e);color:var(--code-fg,#ddd);padding:10px;border-radius:6px;overflow:auto;max-height:300px"></pre>
          <button class="btn" data-act="copyCISnippet">Copy snippet</button>
        </div>

        <div class="settings-section">
          <h3>Display glasses</h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">
            Meta Ray-Ban Display glasses can only add an app by URL, so this link carries its own
            credential. It reaches <strong>only the glasses views</strong>: your projects, their task
            lists, and adding a task by dictation. It cannot start a run, change an existing task, or
            read secrets, settings, agent transcripts or the audit log, and it can never see more than
            your own account can. Treat the URL itself as the password — anyone holding it sees your
            projects and tasks until it expires in 30 days. Generating a new link revokes the old one.
          </p>
          <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--muted);margin-bottom:12px">
            <input type="checkbox" id="glassesReadOnly">
            Read-only — cannot add tasks by voice either
          </label>
          <div id="glassesStatus" style="font-size:13px;margin-bottom:12px;color:var(--muted)">Loading…</div>
          <div id="glassesUrlBox" style="display:none;margin-bottom:12px">
            <label class="form-label">Your link — shown once, copy it now</label>
            <input class="form-input" id="glassesUrl" readonly onclick="this.select()" style="font-family:monospace;font-size:12px">
            <p id="glassesWarning" style="font-size:12px;color:var(--warn,#e0a800);margin-top:8px"></p>
          </div>
          <button class="btn primary" id="glassesGenBtn" data-act="generateGlassesLink">Generate link</button>
          <button class="btn" id="glassesCopyBtn" data-act="copyGlassesLink" style="display:none">Copy</button>
          <button class="btn danger" id="glassesRevokeBtn" data-act="revokeGlassesLink" style="display:none">Revoke</button>
        </div>

        <div class="settings-section">
          <h3 style="display:flex;align-items:center;gap:12px">
            Build
            <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto;font-weight:400" onclick="loadBuildInfo()">&#8635; Refresh</button>
          </h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">
            Which build of cloop is serving this dashboard, and how recent it is. A deploy moves
            both the identity and the timestamps below; a deploy that silently failed moves
            neither, which is the only visible symptom of a stale deployment.
          </p>
          <div id="buildInfoBody">
            <div style="font-size:13px;color:var(--muted)">Loading...</div>
          </div>
        </div>

        <div class="settings-section">
          <h3>Hidden Projects</h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Projects you have hidden from the Projects tab. Hiding is yours alone: it changes nothing for other users, and the project keeps running. Which projects they are is behind the button &mdash; opening Settings does not put their names on screen.</p>
          <button class="btn" id="hiddenProjectsBtn" onclick="openHiddenProjectsModal()" disabled>No hidden projects</button>
        </div>

        <div class="settings-section danger-zone">
          <h3>Danger Zone</h3>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Reset clears all step history and resets the project status. The goal and config are preserved.</p>
          <button class="btn danger" data-act="confirmReset">Reset Project State</button>
        </div>
      </div>`);
  };
})();
