// ── Task attachments (Task 20428) ────────────────────────────────────────────
//
// The files a run attached to a task — reports, charts, screenshots, exports,
// logs — listed in the task's details, with a preview for images and text and
// a download for everything. Fetched the first time a task's details are
// opened (static.go, deferredScripts); 12-task-crud.js draws the empty section
// and calls show() through panelAct.
//
// Input files (Task 20511) are listed above them: files a person attached for
// the task's agent, given to every attempt at the task. "Add input files…" and
// a drop on the section upload them, one POST each with the file itself as the
// body (attachments_api.go); the Add Task form calls upload() for the files
// picked with a new task.
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

    // The most a file may be, as the hub said with the list.
    let maxFile = 32 << 20;

    function render() {
      const sec = box();
      if (!sec) return;
      const inputs = rows.filter(r => r.role === 'input'), results = rows.filter(r => r.role !== 'input');
      const mayAdd = h.can('task.mutate');
      // A task with no files says nothing to someone who cannot add one.
      sec.hidden = !rows.length && !mayAdd;
      let html = '<h3>Input files (' + inputs.length + ')</h3>' +
        '<div class="td-empty">' + (inputs.length ? 'Given' : 'Files added here are given') +
        ' to the agent at the start of every attempt at this task' + (mayAdd ? '; drop files here to add them.' : '.') + '</div>' +
        list(inputs) +
        (mayAdd ? '<div class="td-file-acts" style="margin:6px 0 12px;align-items:center"><button class="btn" data-act="pick">Add input files…</button>' +
          '<span class="td-file-meta" data-up></span></div>' : '');
      if (results.length) html += '<h3>Results (' + results.length + ')</h3>' + list(results);
      sec.innerHTML = html;
      h.applyPermissionGating(sec);
    }

    function list(rs) {
      return rs.map(r => {
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
          if (!b || !{}.hasOwnProperty.call(fns, b.dataset.act) || b.dataset.act === 'show' || b.dataset.act === 'upload') return;
          fns[b.dataset.act](b.dataset.arg, b);
        });
        // Files dropped on the section are added as input files.
        sec.addEventListener('dragover', function (e) {
          if (!h.can('task.mutate') || !e.dataTransfer || [].indexOf.call(e.dataTransfer.types || [], 'Files') < 0) return;
          e.preventDefault();
          e.dataTransfer.dropEffect = 'copy';
        });
        sec.addEventListener('drop', function (e) {
          if (!h.can('task.mutate') || !e.dataTransfer || !e.dataTransfer.files.length) return;
          e.preventDefault();
          upload(shown, e.dataTransfer.files);
        });
      }
      return h.api(h.pUrl('/api/tasks/' + id + '/attachments')).then(d => {
        if (shown !== id) return;
        if (!d || d.error) {
          sec.innerHTML = '<h3>Attachments</h3><div class="td-empty">' + h.esc((d && d.error) || 'Could not load the attachments') + '</div>';
          return;
        }
        rows = d.attachments || [];
        if (d.limits && d.limits.file_bytes) maxFile = d.limits.file_bytes;
        render();
      }, () => {});
    }

    // pick asks for files to add as input files of the task on screen. One
    // hidden picker, kept in the page: a browser opens a detached one only
    // sometimes.
    let picker = null;
    function pick() {
      const id = shown;
      if (!picker) {
        picker = document.createElement('input');
        picker.type = 'file';
        picker.multiple = true;
        picker.hidden = true;
        document.body.appendChild(picker);
      }
      picker.onchange = () => {
        const files = Array.prototype.slice.call(picker.files);
        picker.value = '';
        if (files.length) upload(id, files);
      };
      picker.click();
    }

    // send posts one file as an input file of task id: the file itself is the
    // body. A refusal the dashboard handles itself — a sign-in, a renewal —
    // replays it.
    function send(id, f) {
      return fetch(h.pUrl('/api/tasks/' + id + '/attachments?name=' + encodeURIComponent(f.name)), {
        method: 'POST', credentials: 'same-origin', body: f,
        headers: Object.assign({'Content-Type': 'application/octet-stream'}, h.authHeaders()),
      }).then(r => h.parse(r, () => send(id, f)));
    }

    // upload adds files as input files of task id, one after another, and
    // says how it went. Settles once all are done; never rejects.
    function upload(id, files) {
      files = Array.prototype.slice.call(files || []);
      if (!files.length) return Promise.resolve();
      const line = () => { const sec = box(); return shown === id && sec ? sec.querySelector('[data-up]') : null; };
      let added = 0, running = false;
      return files.reduce((p, f, i) => p.then(() => {
        if (f.size > maxFile) {
          h.toast(f.name + ' is ' + h.fmtBytes(f.size) + ', over the ' + h.fmtBytes(maxFile) + ' a file may be', 'err');
          return;
        }
        const el = line();
        if (el) el.textContent = 'Uploading ' + f.name + (files.length > 1 ? ' (' + (i + 1) + ' of ' + files.length + ')' : '') + '…';
        return send(id, f).then(d => {
          if (!d || d.error) { h.toast((d && d.error) || ('Could not add ' + f.name), 'err'); return; }
          added++;
          running = running || !!d.running;
        }, () => h.toast('Could not add ' + f.name, 'err'));
      }), Promise.resolve()).then(() => {
        const el = line();
        if (el) el.textContent = '';
        if (added) {
          h.toast('Added ' + (added === 1 ? files[0].name : added + ' input files') + ' to task #' + id +
            (running ? '. The attempt running now started without ' + (added === 1 ? 'it' : 'them') + '; the next one gets ' +
              (added === 1 ? 'it' : 'them') + '.' : ''), 'ok');
        }
        if (shown === id) show(id);
      });
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

    const fns = h.mount({show, preview, download, remove, pick, upload});
    return fns;
  };
})();
