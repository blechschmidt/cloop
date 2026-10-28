// ── Chat ─────────────────────────────────────────────────────────────────────
//
// The natural-language chat that drives a project — typed, or spoken through
// the microphone button or by holding Space — with replies optionally read
// aloud. Fetched on the tab's first open since Task 20456, markup included; it
// was 16-chat.js and the voice half of 17-assistant.js.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory. open() reads the history
// afresh on every visit. The Space push-to-talk listeners are the document's,
// added when the tab is first opened and acting only while it is on screen.
(function () {
  'use strict';

  window.cloopChatPanel = function (h) {
    const {esc, toast, pUrl, authHeaders, harnessRefused, refreshState} = h;

    let chatTtsEnabled = false;
    let chatVoiceMediaRecorder = null;
    let chatVoiceChunks = [];
    let chatVoiceRecording = false;
    let chatVoiceBlob = null;
    let spaceVoiceActive = false;

    // Restore TTS preference; the markup below draws the box checked to match.
    chatTtsEnabled = localStorage.getItem('cloop_chat_tts') === 'true';

    function toggleTTS() {
      const enabled = chatTtsEnabled = !!this.checked;
      localStorage.setItem('cloop_chat_tts', enabled ? 'true' : 'false');
      if (!enabled && window.speechSynthesis) window.speechSynthesis.cancel();
    }

    function speakText(text) {
      if (!chatTtsEnabled || !window.speechSynthesis) return;
      window.speechSynthesis.cancel();
      const utt = new SpeechSynthesisUtterance(text);
      utt.rate = 1.05;
      window.speechSynthesis.speak(utt);
    }

    function chatFmtTime(ts) {
      const d = ts ? new Date(ts) : new Date();
      return d.toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});
    }

    function appendChatBubble(role, content, opts) {
      const box = document.getElementById('chatMessages');
      if (!box) return;
      const welcome = box.querySelector('.chat-welcome');
      if (welcome) welcome.remove();

      const row = document.createElement('div');
      row.className = 'chat-bubble-row ' + role;
      const initials = role === 'user' ? 'U' : 'AI';
      const action   = (opts && opts.action) ? opts.action : '';
      const ts       = (opts && opts.ts)     ? opts.ts     : null;
      const isError  = opts && opts.error;

      row.innerHTML =
        '<div class="chat-avatar ' + role + '">' + initials + '</div>' +
        '<div>' +
          '<div class="chat-bubble ' + role + (isError ? ' error' : '') + '">' +
            esc(content) +
            (action ? '<br><span class="chat-bubble-action">$ cloop ' + esc(action) + '</span>' : '') +
          '</div>' +
          '<div class="chat-bubble-time">' + chatFmtTime(ts) + '</div>' +
        '</div>';

      box.appendChild(row);
      box.scrollTop = box.scrollHeight;
      return row;
    }

    function showChatThinking() {
      const box = document.getElementById('chatMessages');
      if (!box) return null;
      const el = document.createElement('div');
      el.className = 'chat-thinking';
      el.id = 'chatThinking';
      el.innerHTML = '<span class="spinner"></span> Thinking...';
      box.appendChild(el);
      box.scrollTop = box.scrollHeight;
      return el;
    }

    function removeChatThinking() {
      const el = document.getElementById('chatThinking');
      if (el) el.remove();
    }

    async function submitChat() {
      const input = document.getElementById('chatInput');
      if (!input) return;
      const msg = input.value.trim();
      if (!msg) return;
      input.value = '';

      appendChatBubble('user', msg, {ts: new Date()});
      showChatThinking();

      try {
        const resp = await fetch(pUrl('/api/chat'), {
          method: 'POST',
          headers: Object.assign({'Content-Type': 'application/json'}, authHeaders()),
          body: JSON.stringify({message: msg}),
        });
        if (resp.status === 401) { h.unauthorized(resp); removeChatThinking(); return; }
        const data = await resp.json();
        removeChatThinking();
        harnessRefused(data);
        const content = data.response || (data.ok ? 'Done.' : (data.error || 'Error'));
        appendChatBubble('assistant', content, {ts: new Date(), error: !data.ok, action: data.action});
        if (data.ok) speakText(content);
        if (data.ok) refreshState();
      } catch(err) {
        removeChatThinking();
        appendChatBubble('assistant', 'Request failed: ' + err.message, {ts: new Date(), error: true});
      }
    }

    function clearChatHistory() {
      const box = document.getElementById('chatMessages');
      if (!box) return;
      box.innerHTML =
        '<div class="chat-welcome">' +
        '<div class="chat-welcome-icon">&#x1F4AC;</div>' +
        '<div class="chat-welcome-title">Chat with cloop</div>' +
        '<div class="chat-welcome-text">Type a natural language command to control your project.<br>' +
        'Examples: <em>"add a task to fix the login bug"</em>, <em>"start the run"</em>, <em>"show me task 3"</em>, <em>"pause"</em></div>' +
        '</div>';
    }

    function loadChatHistory() {
      fetch(pUrl('/api/chat/history'), {headers: authHeaders()}).then(r => r.json()).then(history => {
        if (!history || !history.length) return;
        const box = document.getElementById('chatMessages');
        if (!box) return;
        box.innerHTML = '';
        history.forEach(m => appendChatBubble(m.role, m.content, {ts: m.timestamp, action: m.action}));
      }).catch(() => {});
    }

    // ── Chat voice ────────────────────────────────────────────────────────────────

    async function toggleChatVoice() {
      if (chatVoiceRecording) { stopChatVoice(); return; }
      await startChatVoice();
    }

    async function startChatVoice() {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({audio: true});
        chatVoiceChunks = []; chatVoiceBlob = null;
        const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
          ? 'audio/webm;codecs=opus'
          : (MediaRecorder.isTypeSupported('audio/ogg') ? 'audio/ogg' : '');
        chatVoiceMediaRecorder = new MediaRecorder(stream, mimeType ? {mimeType} : {});
        chatVoiceMediaRecorder.ondataavailable = e => { if (e.data.size > 0) chatVoiceChunks.push(e.data); };
        chatVoiceMediaRecorder.onstop = () => {
          stream.getTracks().forEach(t => t.stop());
          const ext = (chatVoiceMediaRecorder.mimeType || '').includes('ogg') ? 'ogg' : 'webm';
          chatVoiceBlob = new Blob(chatVoiceChunks, {type: chatVoiceMediaRecorder.mimeType || 'audio/webm'});
          chatVoiceBlob._ext = ext;
          chatVoiceRecording = false;
          document.getElementById('chatMicBtn').classList.remove('recording');
          document.getElementById('chatVoiceBar').style.display = 'none';
          sendChatVoice();
        };
        chatVoiceMediaRecorder.start(200);
        chatVoiceRecording = true;
        document.getElementById('chatMicBtn').classList.add('recording');
        document.getElementById('chatVoiceBar').style.display = 'flex';
      } catch(err) {
        toast('Microphone error: ' + err.message, 'err');
      }
    }

    function stopChatVoice() {
      if (chatVoiceMediaRecorder && chatVoiceMediaRecorder.state !== 'inactive') chatVoiceMediaRecorder.stop();
    }

    function cancelChatVoice() {
      if (chatVoiceMediaRecorder && chatVoiceMediaRecorder.state !== 'inactive') chatVoiceMediaRecorder.stop();
      chatVoiceBlob = null;
      chatVoiceRecording = false;
      document.getElementById('chatMicBtn').classList.remove('recording');
      document.getElementById('chatVoiceBar').style.display = 'none';
    }

    async function sendChatVoice() {
      if (!chatVoiceBlob) return;
      appendChatBubble('user', '&#x1F3A4; Voice message (transcribing\u2026)', {ts: new Date()});
      showChatThinking();

      const ext = chatVoiceBlob._ext || 'webm';
      const formData = new FormData();
      formData.append('audio', chatVoiceBlob, 'recording.' + ext);
      formData.append('execute', 'true');

      try {
        const headers = authHeaders();
        delete headers['Content-Type'];
        const resp = await fetch('/api/voice', {method: 'POST', headers, body: formData});
        if (resp.status === 401) { h.unauthorized(resp); removeChatThinking(); return; }
        const data = await resp.json();
        removeChatThinking();

        // Update the placeholder bubble with actual transcription.
        const msgBox = document.getElementById('chatMessages');
        if (msgBox) {
          const userBubbles = msgBox.querySelectorAll('.chat-bubble-row.user');
          if (userBubbles.length > 0) {
            const lastBubble = userBubbles[userBubbles.length - 1].querySelector('.chat-bubble');
            const lines = (data.output || '').split('\n');
            const tVal  = lines.find(l => l.trim().startsWith('"') && l.trim().endsWith('"'));
            const tText = tVal ? tVal.trim().replace(/^"|"$/g, '') : '&#x1F3A4; (voice command)';
            if (lastBubble) lastBubble.textContent = '\uD83C\uDFA4 ' + (tVal ? tVal.trim().replace(/^"|"$/g, '') : '(voice command)');
          }
        }

        const content = data.output || (data.ok ? 'Done.' : (data.error || 'Error'));
        appendChatBubble('assistant', content, {ts: new Date(), error: !data.ok});
        if (data.ok) speakText(content);
        if (data.ok) refreshState();
        chatVoiceBlob = null;
      } catch(err) {
        removeChatThinking();
        appendChatBubble('assistant', 'Voice request failed: ' + err.message, {ts: new Date(), error: true});
      }
    }

    // ── Space push-to-talk (Chat tab only) ───────────────────────────────────────

    document.addEventListener('keydown', async function(e) {
      if (h.tab() !== 'chat') return;
      if (e.code !== 'Space') return;
      const tag = ((e.target && e.target.tagName) || '').toUpperCase();
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'BUTTON') return;
      if (spaceVoiceActive || chatVoiceRecording) return;
      e.preventDefault();
      spaceVoiceActive = true;
      await startChatVoice();
    });

    document.addEventListener('keyup', function(e) {
      if (e.code !== 'Space') return;
      if (!spaceVoiceActive) return;
      spaceVoiceActive = false;
      if (chatVoiceRecording) stopChatVoice();
    });

    return h.mount({open: loadChatHistory, toggleTTS, clear: clearChatHistory, toggleVoice: toggleChatVoice, submit: submitChat, stopVoice: stopChatVoice, cancelVoice: cancelChatVoice}, 'chat', `
    <div class="chat-layout">
      <div class="chat-header">
        <span class="section-title" style="margin:0">AI Chat</span>
        <span class="chat-hint">Type a command or question — or hold <kbd>Space</kbd> to talk</span>
        <div style="display:flex;gap:6px;align-items:center;margin-left:auto">
          <label class="chat-tts-label" title="Read responses aloud">
            <input type="checkbox" id="chatTtsToggle" data-change="toggleTTS"${chatTtsEnabled ? ' checked' : ''}> TTS
          </label>
          <button class="btn" style="padding:4px 10px;font-size:12px" data-act="clear">Clear</button>
        </div>
      </div>
      <div class="chat-messages" id="chatMessages">
        <div class="chat-welcome">
          <div class="chat-welcome-icon">💬</div>
          <div class="chat-welcome-title">Chat with cloop</div>
          <div class="chat-welcome-text">Type a natural language command to control your project.<br>
          Examples: <em>"add a task to fix the login bug"</em>, <em>"start the run"</em>, <em>"show me task 3"</em>, <em>"pause"</em></div>
        </div>
      </div>
      <div class="chat-input-bar">
        <button class="btn mic chat-mic-btn" id="chatMicBtn" data-act="toggleVoice" title="Hold Space or click to record voice command">
          <svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14"><path d="M5 3a3 3 0 0 1 6 0v5a3 3 0 0 1-6 0V3z"/><path d="M3.5 6.5A.5.5 0 0 1 4 7v1a4 4 0 0 0 8 0V7a.5.5 0 0 1 1 0v1a5 5 0 0 1-4.5 4.975V15h2.5a.5.5 0 0 1 0 1h-6a.5.5 0 0 1 0-1H7.5v-2.025A5 5 0 0 1 3 8V7a.5.5 0 0 1 .5-.5z"/></svg>
        </button>
        <input class="form-input chat-input" id="chatInput" placeholder="Ask anything or give a command..."
               data-enter="submit">
        <button class="btn primary" data-act="submit" style="flex-shrink:0">
          <svg viewBox="0 0 16 16" fill="currentColor" width="13" height="13"><path d="M15.854.146a.5.5 0 0 1 .11.54l-5.819 14.547a.75.75 0 0 1-1.329.124l-3.178-4.995L.643 7.184a.75.75 0 0 1 .124-1.33L15.314.037a.5.5 0 0 1 .54.11z"/></svg>
          Send
        </button>
      </div>
      <div class="chat-voice-bar" id="chatVoiceBar" style="display:none">
        <span class="chat-voice-indicator">
          <span class="live-dot connected" style="width:6px;height:6px"></span>
          Recording...
        </span>
        <button class="btn danger" style="padding:4px 10px;font-size:12px" data-act="stopVoice">Stop &amp; Send</button>
        <button class="btn" style="padding:4px 10px;font-size:12px" data-act="cancelVoice">Cancel</button>
      </div>
    </div>
    `);
  };
})();
