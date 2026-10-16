// ── Forwarded devices card (Task 20430) ─────────────────────────────────────
//
// The project's device settings for device forwarders: which on-prem devices
// its runs get in their sandbox, until when, and the way to add one — a
// binding for someone holding executor.manage, a request through the
// grant-request flow for a maintainer. Fetched on demand rather than bundled,
// like the Members card: first paint has no room for a card most projects
// never use. It runs outside the dashboard's IIFE, so loadProjectForwards in
// 01-overview.js hands over the helpers it calls, and the one name it puts on
// window is its factory.
//
// The server decides what the caller may do (can_bind, can_request), so the
// card offers no control the hub would refuse; its own buttons dispatch
// through data-fwd and the card's listeners, never an inline handler.
(function () {
  'use strict';

  window.cloopDevicesPanel = function (h) {
    let data = null;
    let shownIdx = null;
    let inflight = null;

    function el(id) { return document.getElementById(id); }

    function section() {
      let sec = el('fwdProjectSection');
      if (sec) return sec;
      sec = document.createElement('div');
      sec.className = 'section';
      sec.id = 'fwdProjectSection';
      sec.style.display = 'none';
      sec.innerHTML =
        '<div class="section-title">Forwarded devices</div>' +
        '<div id="fwdProjectList"></div>' +
        '<form id="fwdProjectForm" style="display:none;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px">' +
          '<select class="form-input form-select" id="fwdProjectFwd" aria-label="Forwarder" style="flex:2 1 200px;min-width:0"></select>' +
          '<input class="form-input" id="fwdProjectHours" type="number" min="1" max="2160" value="24" ' +
            'aria-label="Hours" title="Hours the binding lasts" style="flex:0 1 90px">' +
          '<input class="form-input" id="fwdProjectVX" type="text" autocomplete="off" spellcheck="false" ' +
            'placeholder="Only on virtual executor (optional)" aria-label="Virtual executor" style="flex:1 1 180px;min-width:0">' +
          '<input class="form-input" id="fwdProjectWhy" type="text" maxlength="4096" ' +
            'placeholder="Why the project needs it" aria-label="Justification" style="flex:2 1 220px;min-width:0">' +
          '<button class="btn primary" id="fwdProjectBtn" type="submit" style="padding:6px 14px">Bind</button>' +
        '</form>' +
        '<div id="fwdProjectNote" class="form-hint" style="margin-top:8px"></div>';
      const anchor = el('projectFirewallPanel') || el('featuresSection');
      const panel = el('projectPanel');
      if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(sec, anchor.nextSibling);
      else if (panel) panel.appendChild(sec);
      else return null;

      sec.querySelector('#fwdProjectForm').addEventListener('submit', function (ev) {
        ev.preventDefault();
        submit();
      });
      sec.querySelector('#fwdProjectList').addEventListener('click', function (ev) {
        const btn = ev.target && ev.target.closest ? ev.target.closest('button[data-fwd]') : null;
        if (!btn) return;
        if (btn.dataset.fwd === 'unbind') unbind(+btn.dataset.idx);
        if (btn.dataset.fwd === 'withdraw') withdraw(+btn.dataset.idx);
      });
      return sec;
    }

    function fail(what, err) {
      if (err && /^(FORBIDDEN|401)$/.test(err.message)) return;
      h.toast((err && err.message ? err.message : 'Could not ' + what), 'error');
    }

    function until(iso) {
      const ms = Date.parse(iso) - Date.now();
      if (!(ms > 0)) return 'lapsing';
      if (ms < 3600000) return 'for ' + Math.max(1, Math.round(ms / 60000)) + 'm';
      if (ms < 172800000) return 'for ' + Math.round(ms / 3600000) + 'h';
      return 'for ' + Math.round(ms / 86400000) + 'd';
    }

    function render() {
      const sec = section();
      if (!sec || !data) return;
      const binds = data.bindings || [];
      const reqs = (data.requests || []).filter(function (q) { return q.state === 'pending'; });
      const offer = (data.can_bind || data.can_request) && (data.forwarders || []).length > 0;
      sec.style.display = (binds.length || reqs.length || offer) ? '' : 'none';
      const rows = binds.map(function (b, i) {
        const used = (b.in_use && b.in_use.length) ? ' · in use' : '';
        const vx = b.virtual_executor ? ' · only on ' + h.esc(b.virtual_executor) : '';
        const btn = data.can_bind
          ? '<button class="btn" type="button" data-fwd="unbind" data-idx="' + i + '" style="padding:3px 10px">Unbind</button>' : '';
        return '<div class="feat-row"><div class="feat-main" style="cursor:default;min-width:0">' +
          '<span style="font-weight:600;overflow-wrap:anywhere">' + h.esc(b.forwarder_name || b.forwarder_id) + '</span>' +
          '<span class="feat-meta" style="overflow-wrap:anywhere">' + h.esc(b.device || b.kind) + ' · ' +
          h.esc(until(b.expires_at)) + vx + used + '</span></div>' + btn + '</div>';
      });
      reqs.forEach(function (q, i) {
        rows.push('<div class="feat-row"><div class="feat-main" style="cursor:default;min-width:0">' +
          '<span style="font-weight:600;overflow-wrap:anywhere">' + h.esc(q.secret_name || q.id) + '</span>' +
          '<span class="feat-meta">requested · waiting for an administrator</span></div>' +
          '<button class="btn" type="button" data-fwd="withdraw" data-idx="' + i + '" style="padding:3px 10px">Withdraw</button></div>');
      });
      el('fwdProjectList').innerHTML = rows.length ? rows.join('')
        : '<div class="form-hint">No on-prem device is bound to this project.</div>';
      const form = el('fwdProjectForm');
      form.style.display = offer ? 'flex' : 'none';
      if (offer) {
        el('fwdProjectFwd').innerHTML = (data.forwarders || []).map(function (f) {
          return '<option value="' + h.esc(f.id) + '">' + h.esc(f.name) + ' — ' + h.esc(f.device) +
            (f.connected ? '' : ' (offline)') + '</option>';
        }).join('');
        el('fwdProjectBtn').textContent = data.can_bind ? 'Bind' : 'Request';
        el('fwdProjectWhy').style.display = data.can_bind ? 'none' : '';
      }
      el('fwdProjectNote').textContent = data.can_bind
        ? 'Runs of this project get each bound device in their sandbox; a run whose forwarder is offline is refused.'
        : (data.can_request ? 'Binding a device takes an administrator: a request goes to the approvals inbox.' : '');
    }

    function load() {
      const idx = h.idx();
      if (inflight && shownIdx === idx) return inflight;
      shownIdx = idx;
      inflight = h.api('/api/projects/' + idx + '/forwarders').then(function (d) {
        if (shownIdx !== idx) return;
        data = d || {};
        render();
      }).catch(function () {
        const sec = el('fwdProjectSection');
        if (sec) sec.style.display = 'none';
      }).then(function () { inflight = null; });
      return inflight;
    }

    function submit() {
      if (!data) return;
      const fwd = el('fwdProjectFwd').value;
      const hours = parseFloat(el('fwdProjectHours').value || '24');
      const vx = (el('fwdProjectVX').value || '').trim();
      const btn = el('fwdProjectBtn');
      btn.disabled = true;
      let p;
      if (data.can_bind) {
        p = h.api('/api/forwarders/' + encodeURIComponent(fwd) + '/bindings',
          {project: data.project, virtual_executor: vx, ttl_minutes: Math.round(hours * 60)});
      } else {
        const why = (el('fwdProjectWhy').value || '').trim();
        if (!why) {
          btn.disabled = false;
          h.toast('Say why the project needs the device', 'error');
          el('fwdProjectWhy').focus();
          return;
        }
        p = h.api('/api/grant-requests', {source: 'forwarder', forwarder_id: fwd, project: data.project,
          virtual_executor: vx, ttl_minutes: Math.round(hours * 60), justification: why});
      }
      p.then(function (r) {
        if (r && r.error) { fail('bind the device', {message: r.error}); return; }
        h.toast(data.can_bind ? 'Device bound to this project' : 'Request sent for approval', 'success');
        el('fwdProjectWhy').value = '';
        shownIdx = null;
        return load();
      }).catch(function (err) { fail('bind the device', err); })
        .then(function () { btn.disabled = false; });
    }

    function unbind(i) {
      const b = data && (data.bindings || [])[i];
      if (!b) return;
      if (!window.confirm('Unbind ' + (b.forwarder_name || b.forwarder_id) + ' from this project? A run ' +
          'holding the device has it detached at once.')) return;
      h.apiMethod('DELETE', '/api/forwarders/bindings/' + encodeURIComponent(b.id))
        .then(function () { h.toast('Device unbound', 'success'); shownIdx = null; return load(); })
        .catch(function (err) { fail('unbind the device', err); });
    }

    function withdraw(i) {
      const reqs = ((data && data.requests) || []).filter(function (q) { return q.state === 'pending'; });
      const q = reqs[i];
      if (!q) return;
      h.api('/api/grant-requests' + '/' + encodeURIComponent(q.id) + '/withdraw', {})
        .then(function () { h.toast('Request withdrawn', 'success'); shownIdx = null; return load(); })
        .catch(function (err) { fail('withdraw the request', err); });
    }

    return {load: load};
  };
})();
