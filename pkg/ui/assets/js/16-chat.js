// ── Chat ─────────────────────────────────────────────────────────────────────

let chatTtsEnabled = false;
let chatVoiceMediaRecorder = null;
let chatVoiceChunks = [];
let chatVoiceRecording = false;
let chatVoiceBlob = null;
let spaceVoiceActive = false;

// Restore TTS preference.
(function() {
  const saved = localStorage.getItem('cloop_chat_tts');
  if (saved === 'true') {
    chatTtsEnabled = true;
    const el = document.getElementById('chatTtsToggle');
    if (el) el.checked = true;
  }
})();

window.toggleTTS = function(enabled) {
  chatTtsEnabled = enabled;
  localStorage.setItem('cloop_chat_tts', enabled ? 'true' : 'false');
  if (!enabled && window.speechSynthesis) window.speechSynthesis.cancel();
};

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

window.submitChat = async function() {
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
    if (resp.status === 401) { showLoginModal(); removeChatThinking(); return; }
    const data = await resp.json();
    removeChatThinking();
    const content = data.response || (data.ok ? 'Done.' : (data.error || 'Error'));
    appendChatBubble('assistant', content, {ts: new Date(), error: !data.ok, action: data.action});
    if (data.ok) speakText(content);
    if (data.ok) refreshState();
  } catch(err) {
    removeChatThinking();
    appendChatBubble('assistant', 'Request failed: ' + err.message, {ts: new Date(), error: true});
  }
};

window.clearChatHistory = function() {
  const box = document.getElementById('chatMessages');
  if (!box) return;
  box.innerHTML =
    '<div class="chat-welcome">' +
    '<div class="chat-welcome-icon">&#x1F4AC;</div>' +
    '<div class="chat-welcome-title">Chat with cloop</div>' +
    '<div class="chat-welcome-text">Type a natural language command to control your project.<br>' +
    'Examples: <em>"add a task to fix the login bug"</em>, <em>"start the run"</em>, <em>"show me task 3"</em>, <em>"pause"</em></div>' +
    '</div>';
};

function loadChatHistory() {
  fetch(pUrl('/api/chat/history'), {headers: authHeaders()}).then(r => r.json()).then(history => {
    if (!history || !history.length) return;
    const box = document.getElementById('chatMessages');
    if (!box) return;
    box.innerHTML = '';
    history.forEach(m => appendChatBubble(m.role, m.content, {ts: m.timestamp, action: m.action}));
  }).catch(() => {});
}

