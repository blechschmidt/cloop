// ── Quotas panel (Task 20182) ───────────────────────────────────────────────
//
// Global and admin-only: the tab is hidden unless /api/me reports user.manage,
// and every write goes through PUT /api/quotas/{identity}, which is gated on
// the same permission server-side. Hiding the tab is a convenience — the gate
// is the route, and a tenant who forges the request gets the same 403.
//
// Editing is inline. A quota conversation is "give Alice two more projects",
// not "fill in this form", so each cell is a number input that commits on
// blur and the row shows what changed. An empty cell means "inherit from
// policy", which is different from 0 ("allowed none") — the placeholder shows
// the inherited value so the difference is visible rather than remembered.
//
// Fetched on the tab's first open since Task 20386 (static.go,
// deferredScripts), markup included: an admin-only table most sessions never
// open has no claim on first paint. It runs outside the dashboard's IIFE, so it
// is handed the helpers it calls — the formatting ones through h.quota, shared
// with the header's own-quota badge that stays in 27-quotas.js — and the only
// name it puts on window is the factory.
(function () {
  'use strict';

  window.cloopQuotasPanel = function (h) {
    const {api, apiMethod, esc, toast, pUrl, applyPermissionGating} = h;
    const q = h.quota;
    // ok turns an error body into a rejection. api() resolves one — only a 401
    // and a 403 reject — so a success path that does not check reports a
    // refusal as done: Task 20386 found the Store-a-secret dialog saying
    // "Secret stored" over a 400.
    const ok = d => { if (d && d.error) throw new Error(d.error); return d; };

    const quotaState = {
      rows: [],
      resources: [],
      enabled: false,
      notice: '',
      dirty: {},        // identity -> {resource: value|null} pending commit
      saving: false,
    };

    function _quotaCellClass(ratio) {
      if (ratio === null) return '';
      if (ratio >= 1) return 'quota-full';
      if (ratio >= 0.8) return 'quota-warn';
      return '';
    }

    function loadQuotas() {
      return api(pUrl('/api/quotas'))
        .then(d => {
          d = d || {};
          quotaState.rows = Array.isArray(d.quotas) ? d.quotas : [];
          quotaState.resources = Array.isArray(d.resources) ? d.resources : [];
          quotaState.enabled = !!d.enabled;
          quotaState.notice = d.notice || '';
          quotaState.dirty = {};
          _renderQuotas();
          return d;
        })
        .catch(err => {
          // 403 here is the expected answer for a non-admin, not a fault.
          const empty = document.getElementById('quotaEmpty');
          const table = document.getElementById('quotaTable');
          if (table) table.style.display = 'none';
          if (empty) {
            empty.style.display = '';
            const msg = (err && err.message) ? String(err.message) : String(err);
            empty.textContent = /forbidden|not permit|403/i.test(msg)
              ? 'Your role does not permit managing quotas. This panel requires the user.manage permission (admin).'
              : 'Could not load quotas: ' + msg;
          }
        });
    }

    function _renderQuotas() {
      const table  = document.getElementById('quotaTable');
      const head   = document.getElementById('quotaHead');
      const body   = document.getElementById('quotaBody');
      const empty  = document.getElementById('quotaEmpty');
      const banner = document.getElementById('quotaBanner');
      if (!table || !body || !head) return;

      if (banner) {
        if (quotaState.notice) {
          banner.style.display = '';
          banner.textContent = quotaState.notice;
        } else {
          banner.style.display = 'none';
        }
      }

      const resources = quotaState.resources.length ? quotaState.resources : Object.keys(q.labels);

      if (!quotaState.rows.length) {
        table.style.display = 'none';
        if (empty) {
          empty.style.display = '';
          empty.textContent = quotaState.enabled
            ? 'No identities yet. Quotas appear here once somebody signs in or owns a project.'
            : 'No quota policy is configured and nobody has signed in yet.';
        }
        return;
      }
      if (empty) empty.style.display = 'none';
      table.style.display = '';

      head.innerHTML =
        '<tr><th style="min-width:200px">Identity</th>' +
        resources.map(r =>
          '<th style="width:130px" title="' + esc(q.label(r)) + ' (' + esc(r) + ')">' +
            esc(q.label(r)) + '</th>').join('') +
        '<th style="width:110px"></th></tr>';

      body.innerHTML = quotaState.rows.map((row, idx) => {
        const limits  = row.limits  || {};
        const usage   = row.usage   || {};
        const sources = row.sources || {};
        const cells = resources.map(res => {
          const limit = (res in limits) ? limits[res] : null;
          const used  = usage[res] || 0;
          const ratio = q.saturation(limit, used);
          const src   = sources[res] || '';
          const title = limit === null
            ? 'Unlimited — no binding sets this resource'
            : 'Limit ' + q.fmt(res, limit) + ' from ' + (src || 'policy') +
              '; in use ' + q.fmt(res, used);
          return '<td class="quota-cell ' + _quotaCellClass(ratio) + '" title="' + esc(title) + '">' +
            '<input type="number" min="0" step="any" class="quota-input" ' +
              'data-identity-idx="' + idx + '" data-resource="' + esc(res) + '" ' +
              'value="' + (limit === null ? '' : esc(String(limit))) + '" ' +
              'placeholder="&#8734;" aria-label="' + esc(q.label(res) + ' limit for ' + row.identity) + '">' +
            '<span class="quota-used">' + esc(q.fmt(res, used)) +
              (limit === null ? '' : ' / ' + esc(q.fmt(res, limit))) + '</span>' +
          '</td>';
        }).join('');
        return '<tr>' +
          '<td class="quota-identity">' + esc(row.identity) +
            (row.overridden ? ' <span class="quota-badge" title="An admin has edited this identity">edited</span>' : '') +
          '</td>' + cells +
          '<td style="text-align:right">' +
            '<button class="btn" style="padding:3px 8px;font-size:11px" ' +
              'data-quota-save="' + idx + '" title="Save the edited limits for this identity">Save</button>' +
            (row.overridden
              ? ' <button class="btn" style="padding:3px 8px;font-size:11px" data-quota-reset="' + idx + '" ' +
                'title="Drop the override and return this identity to the configured policy">Reset</button>'
              : '') +
          '</td></tr>';
      }).join('');

      _quotaBindHandlers();
      applyPermissionGating(document.getElementById('tab-quotas'));
    }

    // Event delegation rather than inline onclick: the identity is
    // user-influenced (an IdP releases the email), and interpolating it into an
    // attribute is the exact bug that has broken this dashboard repeatedly. The
    // row index is a number and the identity is looked up from state.
    function _quotaBindHandlers() {
      const body = document.getElementById('quotaBody');
      if (!body || body._quotaBound) return;
      body._quotaBound = true;

      body.addEventListener('click', function(ev) {
        const saveBtn  = ev.target.closest('[data-quota-save]');
        const resetBtn = ev.target.closest('[data-quota-reset]');
        if (saveBtn)  { _quotaSaveRow(Number(saveBtn.getAttribute('data-quota-save'))); return; }
        if (resetBtn) { _quotaResetRow(Number(resetBtn.getAttribute('data-quota-reset'))); return; }
      });

      body.addEventListener('keydown', function(ev) {
        if (ev.key !== 'Enter') return;
        const input = ev.target.closest('.quota-input');
        if (!input) return;
        ev.preventDefault();
        _quotaSaveRow(Number(input.getAttribute('data-identity-idx')));
      });
    }

    // _quotaCollect reads one row's inputs. A blank field is null, which the API
    // reads as "clear this override" — distinct from 0, which caps at none.
    function _quotaCollect(idx) {
      const inputs = document.querySelectorAll('.quota-input[data-identity-idx="' + idx + '"]');
      const limits = {};
      let bad = null;
      inputs.forEach(input => {
        const res = input.getAttribute('data-resource');
        const raw = String(input.value || '').trim();
        if (raw === '') { limits[res] = null; return; }
        const n = Number(raw);
        if (!isFinite(n) || n < 0) { bad = q.label(res); return; }
        limits[res] = n;
      });
      return { limits, bad };
    }

    function _quotaSaveRow(idx) {
      const row = quotaState.rows[idx];
      if (!row || quotaState.saving) return;
      const collected = _quotaCollect(idx);
      if (collected.bad) {
        toast(collected.bad + ' must be a number of zero or more', 'error');
        return;
      }
      quotaState.saving = true;
      apiMethod('PUT', pUrl('/api/quotas/' + encodeURIComponent(row.identity)),
                { limits: collected.limits })
        .then(ok)
        .then(() => {
          toast('Quota updated for ' + row.identity, 'success');
          return loadQuotas();
        })
        .catch(err => toast('Could not update quota: ' + (err && err.message ? err.message : err), 'error'))
        .finally(() => { quotaState.saving = false; });
    }

    function _quotaResetRow(idx) {
      const row = quotaState.rows[idx];
      if (!row || quotaState.saving) return;
      if (!confirm('Drop the quota override for ' + row.identity + '?\n\n' +
                   'They will fall back to the limits configured in ui.quotas.')) return;
      quotaState.saving = true;
      apiMethod('DELETE', pUrl('/api/quotas/' + encodeURIComponent(row.identity)))
        .then(ok)
        .then(() => {
          toast('Override cleared for ' + row.identity, 'success');
          return loadQuotas();
        })
        .catch(err => toast('Could not clear override: ' + (err && err.message ? err.message : err), 'error'))
        .finally(() => { quotaState.saving = false; });
    }

    return h.mount({
      open: loadQuotas, loadQuotas
    }, 'quotas', `
      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          Quotas
          <span style="font-size:11px;font-weight:400;color:var(--muted)">global &mdash; admin only</span>
          <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-act="loadQuotas" title="Reload limits and live usage">&#8635; Refresh</button>
        </div>
        <p style="font-size:12px;color:var(--muted);margin-top:4px;margin-bottom:12px">
          Roles decide whether an identity may act; quotas decide how much. Each cell is the ceiling,
          with live usage below it. Leave a cell blank for <strong>unlimited</strong> &mdash; which is not
          the same as <strong>0</strong>, meaning none allowed. Edits here override the policy in
          <code>ui.quotas</code> for that one identity and are recorded in the audit trail.
          Enforcement is at admission &mdash; before a run is dispatched, a project created, or an
          executor enrolled &mdash; so a client that skips this dashboard is refused just the same.
          The same counters are exported as Prometheus gauges on <code>/metrics</code>.
        </p>

        <div id="quotaBanner" class="sec-banner" style="display:none"></div>
        <div id="quotaEmpty" class="audit-empty" style="display:none"></div>

        <div style="overflow-x:auto">
          <table class="audit-table quota-table" id="quotaTable" style="display:none">
            <thead id="quotaHead"></thead>
            <tbody id="quotaBody"></tbody>
          </table>
        </div>
      </div>`);
  };
})();
