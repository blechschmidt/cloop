// ── Approvals inbox (Task 20427) ─────────────────────────────────────────────
//
// What waits on this user — the grant requests they may decide and the API
// tokens they may approve, soonest deadline first — and what became of their
// own requests. The header badge (33-approvals.js) opens it, and so does the
// link a notification carries (/?approvals=1).
//
// Nothing is decided here. Review opens the dialog that has always decided —
// the Secrets tab's request decision, or a token's approval — which re-reads
// the item and reports whatever the hub refuses: the inbox is a way to the
// decision, not a second place to make it.
//
// The list is the hub's answer for this caller (GET /api/approvals), computed
// from the decision routes' own rules, so nothing is filtered or guessed here.
// Every string in it was typed by somebody — a justification, a token's name, a
// decision note — and goes through esc() on its way into the markup.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory.
(function () {
  'use strict';

  window.cloopApprovalsPanel = function (h) {
    const {api, esc, panel} = h;
    const {openOverlay, closeOverlay, isOverlayOpen} = window;

    function open() {
      openOverlay('approvals-overlay', {dismiss: close});
      return refresh();
    }

    function close() { closeOverlay('approvals-overlay'); }

    // refresh re-reads the inbox while it is on screen; a broadcast for a
    // closed inbox fetches nothing.
    function refresh() {
      const box = document.getElementById('approvalsList');
      if (!box || (isOverlayOpen && !isOverlayOpen('approvals-overlay'))) return Promise.resolve();
      return api('/api/approvals').then(d => render(d || {})).catch(err => {
        box.innerHTML = '<p class="deferred-note" role="alert">The approvals could not be read: ' +
          esc((err && err.message) || String(err)) + '</p>';
      });
    }

    // _left says how far off a deadline is, coarsely.
    function _left(iso) {
      const ms = Date.parse(iso) - Date.now();
      if (!iso || isNaN(ms)) return '';
      const abs = Math.abs(ms), h = Math.round(abs / 36e5);
      const span = abs >= 1728e5 ? Math.floor(abs / 864e5) + ' d ' + (Math.floor(abs / 36e5) % 24) + ' h'
        : abs >= 36e5 ? h + ' h' : Math.max(1, Math.round(abs / 6e4)) + ' min';
      return ms >= 0 ? 'in ' + span : span + ' ago';
    }

    function _when(iso) {
      if (!iso) return '';
      const d = new Date(iso);
      return isNaN(d) ? '' : d.toLocaleString();
    }

    function _clamp(s, n) {
      s = String(s ?? '');
      return s.length > n ? s.slice(0, n - 1) + '…' : s;
    }

    function _item(it) {
      const deadline = it.deadline
        ? '<span class="sec-count" title="' + esc(_when(it.deadline)) + '">' +
          (it.kind === 'api_token' ? 'expires ' : 'lapses ') + esc(_left(it.deadline)) + '</span>'
        : '<span class="sec-count">no deadline</span>';
      const id = esc(it.id);
      if (it.kind === 'api_token') {
        const t = it.token || {};
        return '<li class="apv-item" style="padding:10px 0;border-bottom:1px solid var(--border)">' +
          '<div><strong>API token</strong> ' + esc(t.name || t.prefix || it.id) +
          ' <span class="sec-chip">' + esc((t.roles || []).join(', ')) + '</span> ' + deadline + '</div>' +
          '<div class="sec-count" style="margin-top:4px">minted by ' + esc(t.created_by || 'an unknown caller') +
          (t.created_at ? ' on ' + esc(_when(t.created_at)) : '') +
          ' while no role policy was in force, so the hub refuses it until an administrator holding its roles ' +
          'approves it</div>' +
          '<div style="margin-top:6px;display:flex;gap:8px">' +
          '<button class="btn primary" data-act="review" data-arg="api_token:' + id + ':approve">Review…</button></div></li>';
      }
      const r = it.request || {};
      return '<li class="apv-item" style="padding:10px 0;border-bottom:1px solid var(--border)">' +
        '<div><strong>' + esc(r.requested_by || '') + '</strong> asks for <strong>' +
        esc(r.secret_name || r.secret_id || '') + '</strong>' +
        (r.kind ? ' <span class="sec-chip kind">' + esc(r.kind) + '</span>' : '') + ' ' + deadline + '</div>' +
        '<div class="sec-count" style="margin-top:4px">for ' + esc(r.subject || '') +
        (r.constraints ? ' · ' + esc(_clamp(r.constraints, 160)) : '') + '</div>' +
        '<div style="margin-top:4px;white-space:pre-wrap" title="' + esc(r.justification || '') + '">' +
        esc(_clamp(r.justification, 280)) + '</div>' +
        '<div style="margin-top:6px;display:flex;gap:8px">' +
        '<button class="btn primary" data-act="review" data-arg="grant_request:' + id + ':approve">Approve…</button>' +
        '<button class="btn" data-act="review" data-arg="grant_request:' + id + ':deny">Deny…</button></div></li>';
    }

    function _mine(r) {
      let state = esc(r.state || '');
      if (r.state === 'approved') state = 'approved by ' + esc(r.decided_by || '') +
        (r.grant_expires_at ? ' · grant until ' + esc(_when(r.grant_expires_at)) : '');
      else if (r.state === 'denied') state = 'denied by ' + esc(r.decided_by || '') +
        (r.decision_note ? ': ' + esc(_clamp(r.decision_note, 200)) : '');
      else if (r.state === 'pending') state = 'waiting · lapses ' + esc(_left(r.expires_at)) +
        ((r.approvers || []).length ? ' · can be approved by ' + esc(r.approvers.join('; ')) : '');
      else if (r.state === 'expired') state = 'lapsed undecided';
      return '<li style="padding:6px 0;border-bottom:1px solid var(--border)">' +
        esc(r.secret_name || r.secret_id || '') + ' for ' + esc(r.subject || '') +
        ' — <span class="sec-count">' + state + '</span></li>';
    }

    function render(d) {
      const box = document.getElementById('approvalsList');
      const mine = document.getElementById('approvalsMine');
      if (!box) return;
      const items = Array.isArray(d.items) ? d.items : [];
      box.innerHTML = items.length
        ? '<ul style="list-style:none;padding:0;margin:0">' + items.map(_item).join('') + '</ul>'
        : '<p class="deferred-note">Nothing is waiting on you.</p>';
      const own = Array.isArray(d.mine) ? d.mine : [];
      if (mine) {
        mine.innerHTML = own.length
          ? '<h3 style="font-size:13px;margin:16px 0 6px">Your requests</h3>' +
            '<ul style="list-style:none;padding:0;margin:0;font-size:12px">' + own.map(_mine).join('') + '</ul>'
          : '';
      }
    }

    // review opens the dialog that decides: arg is "kind:id:action".
    function review(arg) {
      const [kind, id, action] = String(arg || '').split(':');
      if (!id) return;
      close();
      if (window.switchTab) window.switchTab('secrets');
      return panel('secrets').then(p => kind === 'api_token'
        ? p.reviewToken(id)
        : p.reviewRequest(id, action === 'deny' ? 'deny' : 'approve'));
    }

    return h.mount({open, close, refresh, review}, null, null, `
      <div id="approvals-overlay" data-overlay="flex" data-dismiss="close" role="dialog" aria-modal="true" aria-labelledby="approvalsTitle"
           style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:640px;max-width:95vw;max-height:90vh;overflow:auto">
          <h2 id="approvalsTitle" style="font-size:15px;font-weight:600;margin-bottom:4px">Waiting on you</h2>
          <p style="font-size:12px;color:var(--muted);margin-bottom:12px">
            Access requests you may decide and API tokens you may approve, soonest deadline first. A request
            nobody decides lapses, and its requester has to ask again.
          </p>
          <div id="approvalsList"><p class="deferred-note">Loading…</p></div>
          <div id="approvalsMine"></div>
          <div class="modal-footer">
            <button class="btn" data-act="close">Close</button>
          </div>
        </div>
      </div>`);
  };
})();
