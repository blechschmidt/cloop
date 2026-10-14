// ── Task attachments (Task 20428) ────────────────────────────────────────────
//
// The files a run attached to a task — reports, charts, screenshots, exports,
// logs — listed in the task's details, with a preview for images and text and
// a download for everything. Fetched the first time a task with attachments is
// opened (static.go, deferredScripts); 12-task-crud.js draws the empty section
// and calls show() through panelAct.
//
// Bytes are never put on the page as markup. An image preview is the
// response's own bytes as a data: URL in an <img>, text is set as textContent,
// and anything else is only ever downloaded. The hub decides what may be shown
// at all: a preview asks for ?inline=1, and a file the hub will not serve
// inline comes back as a download, which this panel then does not display.
(function () {
  'use strict';

  window.cloopAttachmentsPanel = function (h) {
    // The most of a text file a preview shows: a log can be the whole
    // 32 MiB a file may be, and a <pre> that size stalls the page.
    const TEXT_PREVIEW = 200000;
    let shown = null;
    let rows = [];

    function box() { return document.getElementById('td-files'); }
    function url(id, aid, inline) {
      return h.pUrl('/api/tasks/' + id + '/attachments/' + encodeURIComponent(aid) + (inline ? '?inline=1' : ''));
    }
    function icon(t) {
      t = t || '';
      if (t.indexOf('image/') === 0) return '🖼';
      if (t === 'application/pdf') return '📕';
      if (/zip|gzip|tar/.test(t)) return '🗜';
      if (t.indexOf('text/') === 0 || /json|yaml|toml/.test(t)) return '📄';
      return '📦';
    }
    function baseName(n) { const i = (n || '').lastIndexOf('/'); return i >= 0 ? n.slice(i + 1) : (n || 'file'); }
    function find(aid) { return rows.filter(r => r.id === aid)[0]; }

    // fetchFile gets an attachment's bytes with the dashboard's credentials,
    // which a bare <img src> or <a href> cannot carry on a token-only hub. A
    // refusal goes through the dashboard's own handling — the sign-in on a
    // 401, the explanation or a quiet renewal on a 403 — and anything else
    // becomes the error the hub sent.
    function fetchFile(u) {
      return fetch(u, {credentials: 'same-origin', headers: h.authHeaders()}).then(r => r.ok ? r :
        h.parse(r, () => fetchFile(u)).then(d => {
          if (d instanceof Response) return d;
          throw new Error((d && d.error) || ('HTTP ' + r.status));
        }));
    }

    function render() {
      const sec = box();
      if (!sec) return;
      const head = '<h3>Attachments (' + rows.length + ')</h3>';
      if (!rows.length) {
        sec.innerHTML = head + '<div class="td-empty">No files are attached to this task.</div>';
        return;
      }
      sec.innerHTML = head + rows.map(r => {
        const by = r.source === 'run' ? (r.run_id ? 'run ' + r.run_id : 'run') : (r.added_by || r.source || '');
        const meta = [h.fmtBytes(r.size), r.media_type, h.relTime(new Date(r.created_at)), by].filter(Boolean).join(' · ');
        const acts = r.unavailable ? '' :
          (r.previewable ? '<button class="btn" data-act="preview" data-arg="' + h.esc(r.id) + '">Preview</button>' : '') +
          '<button class="btn" data-act="download" data-arg="' + h.esc(r.id) + '">Download</button>';
        return '<div class="td-file" data-file="' + h.esc(r.id) + '">' +
          '<div class="td-file-row">' +
            '<span class="td-file-icon" aria-hidden="true">' + icon(r.media_type) + '</span>' +
            '<span class="td-file-main"><span class="td-file-name" title="' + h.esc(r.name) + '">' + h.esc(r.name) + '</span>' +
              '<span class="td-file-meta">' + h.esc(meta) + '</span>' +
              (r.note ? '<span class="td-file-meta">' + h.esc(r.note) + '</span>' : '') +
              (r.unavailable ? '<span class="td-file-meta td-file-gone">Not on the hub: ' + h.esc(r.unavailable) + '</span>' : '') +
            '</span>' +
            '<span class="td-file-acts">' + acts +
              '<button class="btn danger" data-act="remove" data-arg="' + h.esc(r.id) + '" data-perm="task.mutate">Delete</button>' +
            '</span>' +
          '</div>' +
          '<div class="td-file-preview" hidden></div>' +
        '</div>';
      }).join('');
      h.applyPermissionGating(sec);
    }

    // show draws the attachments of task id into the details' section.
    function show(id) {
      shown = id;
      const sec = box();
      if (!sec) return;
      if (!sec.dataset.routed) {
        sec.dataset.routed = '1';
        sec.addEventListener('click', function (e) {
          const b = e.target && e.target.closest ? e.target.closest('button[data-act]') : null;
          if (!b || !{}.hasOwnProperty.call(fns, b.dataset.act) || b.dataset.act === 'show') return;
          fns[b.dataset.act](b.dataset.arg, b);
        });
      }
      return h.api(h.pUrl('/api/tasks/' + id + '/attachments')).then(d => {
        if (shown !== id) return;
        if (!d || d.error) {
          sec.innerHTML = '<h3>Attachments</h3><div class="td-empty">' + h.esc((d && d.error) || 'Could not load the attachments') + '</div>';
          return;
        }
        rows = d.attachments || [];
        render();
      }, () => {});
    }

    function preview(aid, btn) {
      const r = find(aid);
      const sec = box();
      const pane = sec && sec.querySelector('[data-file="' + aid + '"] .td-file-preview');
      if (!r || !pane) return;
      if (!pane.hidden) { pane.hidden = true; pane.textContent = ''; if (btn) btn.textContent = 'Preview'; return; }
      pane.hidden = false;
      pane.innerHTML = '<div class="td-empty">Loading…</div>';
      if (btn) btn.textContent = 'Hide';
      const id = shown;
      fetchFile(url(id, aid, true)).then(resp => {
        const type = resp.headers.get('Content-Type') || '';
        const inline = (resp.headers.get('Content-Disposition') || '').indexOf('inline') === 0;
        if (!inline) throw new Error('The hub serves this file only as a download.');
        if (type.indexOf('image/') === 0) {
          return resp.blob().then(b => new Promise((ok, no) => {
            const fr = new FileReader();
            fr.onload = () => ok(fr.result);
            fr.onerror = () => no(new Error('The image could not be read.'));
            fr.readAsDataURL(b);
          })).then(src => {
            if (shown !== id) return;
            const img = document.createElement('img');
            img.className = 'td-file-img';
            img.alt = r.name;
            img.src = src;
            pane.textContent = '';
            pane.appendChild(img);
          });
        }
        return resp.text().then(text => {
          if (shown !== id) return;
          const pre = document.createElement('pre');
          pre.className = 'td-pre';
          pre.textContent = text.length > TEXT_PREVIEW ? text.slice(0, TEXT_PREVIEW) : text;
          pane.textContent = '';
          pane.appendChild(pre);
          if (text.length > TEXT_PREVIEW) {
            const note = document.createElement('div');
            note.className = 'td-trunc-note';
            note.textContent = 'Preview cut at ' + h.fmtBytes(TEXT_PREVIEW) + '; download the file for all of it.';
            pane.appendChild(note);
          }
        });
      }).catch(err => {
        if (shown === id) pane.innerHTML = '<div class="td-empty">' + h.esc(err.message || 'Preview failed') + '</div>';
      });
    }

    // download saves the file. With a session cookie the browser fetches it
    // itself — its download manager, no copy in this page's memory; on a
    // token-only hub the request needs the token header, so the page fetches
    // the bytes and hands the browser a blob.
    function download(aid) {
      const r = find(aid);
      if (!r) return;
      const u = url(shown, aid, false);
      const save = href => {
        const a = document.createElement('a');
        a.href = href;
        a.download = baseName(r.name);
        a.rel = 'noopener';
        document.body.appendChild(a);
        a.click();
        a.remove();
      };
      if (!h.authHeaders().Authorization) { save(u); return; }
      fetchFile(u).then(resp => resp.blob()).then(b => {
        const href = URL.createObjectURL(b);
        save(href);
        setTimeout(() => URL.revokeObjectURL(href), 60000);
      }).catch(err => h.toast(err.message || 'Download failed', 'err'));
    }

    function remove(aid) {
      const r = find(aid);
      const id = shown;
      if (!r || !confirm('Delete ' + r.name + ' from task #' + id + '? The file cannot be recovered.')) return;
      h.apiMethod('DELETE', url(id, aid, false)).then(d => {
        if (d && d.error) { h.toast(d.error, 'err'); return; }
        h.toast('Deleted ' + baseName(r.name), 'ok');
        if (shown === id) show(id);
      }, () => {});
    }

    const fns = h.mount({show, preview, download, remove});
    return fns;
  };
})();
