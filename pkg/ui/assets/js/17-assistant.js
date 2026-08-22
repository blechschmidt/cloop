// ── Plan Assistant tab ────────────────────────────────────────────────────────

const ASSISTANT_STORAGE_KEY = 'cloop_assistant_history';
let assistantHistory = []; // [{role, content}]
let assistantStreaming = false;

function loadAssistantHistory() {
  try {
    const raw = sessionStorage.getItem(ASSISTANT_STORAGE_KEY);
    if (raw) {
      assistantHistory = JSON.parse(raw) || [];
    }
  } catch(e) {
    assistantHistory = [];
  }
  const box = document.getElementById('assistantMessages');
  if (!box) return;
  box.innerHTML = '';
  if (assistantHistory.length === 0) {
    box.innerHTML = '<div class="chat-welcome" id="assistantWelcome">' +
      '<div class="chat-welcome-icon">&#129302;</div>' +
      '<div class="chat-welcome-title">Plan-Aware Assistant</div>' +
      '<div class="chat-welcome-text">I have full knowledge of your plan — tasks, statuses, priorities, and annotations.<br>' +
      'Ask me anything about your project or click a suggested question above.</div>' +
      '</div>';
    return;
  }
  assistantHistory.forEach(m => appendAssistantBubble(m.role, m.content, false));
}

function saveAssistantHistory() {
  try {
    sessionStorage.setItem(ASSISTANT_STORAGE_KEY, JSON.stringify(assistantHistory));
  } catch(e) {}
}

function appendAssistantBubble(role, content, streaming) {
  const box = document.getElementById('assistantMessages');
  if (!box) return null;
  const welcome = box.querySelector('.chat-welcome');
  if (welcome) welcome.remove();

  const row = document.createElement('div');
  row.className = 'chat-bubble-row ' + role;
  const initials = role === 'user' ? 'U' : 'AI';

  const bubbleDiv = document.createElement('div');
  bubbleDiv.className = 'chat-bubble ' + role;
  bubbleDiv.textContent = content;
  if (streaming) {
    const cursor = document.createElement('span');
    cursor.className = 'assistant-streaming-cursor';
    cursor.id = 'assistantCursor';
    bubbleDiv.appendChild(cursor);
  }

  const timeDiv = document.createElement('div');
  timeDiv.className = 'chat-bubble-time';
  timeDiv.textContent = chatFmtTime(new Date());

  const avatarDiv = document.createElement('div');
  avatarDiv.className = 'chat-avatar ' + role;
  avatarDiv.textContent = initials;

  const inner = document.createElement('div');
  inner.appendChild(bubbleDiv);
  inner.appendChild(timeDiv);

  row.appendChild(avatarDiv);
  row.appendChild(inner);
  box.appendChild(row);
  box.scrollTop = box.scrollHeight;
  return { row, bubbleDiv };
}

window.assistantChipAsk = function(question) {
  const inp = document.getElementById('assistantInput');
  if (inp) inp.value = question;
  submitAssistantChat();
};

function autoGrowTextarea(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}

window.submitAssistantChat = async function() {
  if (assistantStreaming) return;
  const input = document.getElementById('assistantInput');
  if (!input) return;
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  input.style.height = 'auto';

  // Add user bubble.
  appendAssistantBubble('user', msg, false);
  assistantHistory.push({role: 'user', content: msg});

  // Show streaming assistant bubble.
  const result = appendAssistantBubble('assistant', '', true);
  if (!result) return;
  const { bubbleDiv } = result;
  let accumulated = '';

  assistantStreaming = true;
  const box = document.getElementById('assistantMessages');

  try {
    const body = JSON.stringify({
      message: msg,
      history: assistantHistory.slice(0, -1), // exclude the user message just added
    });
    const resp = await fetch(pUrl('/api/chat/plan'), {
      method: 'POST',
      headers: Object.assign({'Content-Type': 'application/json'}, authHeaders()),
      body,
    });
    if (resp.status === 401) { showLoginModal(); return; }
    if (!resp.ok || !resp.body) {
      const errText = await resp.text().catch(() => 'Request failed');
      bubbleDiv.textContent = errText;
      bubbleDiv.classList.add('error');
      assistantStreaming = false;
      return;
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep incomplete line

      let eventType = '';
      for (const line of lines) {
        if (line.startsWith('event: ')) {
          eventType = line.slice(7).trim();
        } else if (line.startsWith('data: ')) {
          const raw = line.slice(6).trim();
          if (eventType === 'token') {
            try {
              const d = JSON.parse(raw);
              accumulated += (d.token || '');
              // Update bubble text while keeping cursor.
              const cursor = document.getElementById('assistantCursor');
              bubbleDiv.textContent = accumulated;
              if (cursor) bubbleDiv.appendChild(cursor);
              if (box) box.scrollTop = box.scrollHeight;
            } catch(e) {}
          } else if (eventType === 'error') {
            try {
              const d = JSON.parse(raw);
              accumulated = d.error || 'Error';
              bubbleDiv.textContent = accumulated;
              bubbleDiv.classList.add('error');
            } catch(e) {}
          } else if (eventType === 'done') {
            // Remove cursor.
            const cursor = document.getElementById('assistantCursor');
            if (cursor) cursor.remove();
          }
          eventType = '';
        }
      }
    }
  } catch(err) {
    const cursor = document.getElementById('assistantCursor');
    if (cursor) cursor.remove();
    accumulated = 'Request failed: ' + err.message;
    bubbleDiv.textContent = accumulated;
    bubbleDiv.classList.add('error');
  }

  // Remove blinking cursor if still present.
  const cursor = document.getElementById('assistantCursor');
  if (cursor) cursor.remove();

  assistantStreaming = false;

  if (accumulated && !bubbleDiv.classList.contains('error')) {
    assistantHistory.push({role: 'assistant', content: accumulated});
    saveAssistantHistory();
  }
};

window.clearAssistantPanel = function() {
  assistantHistory = [];
  saveAssistantHistory();
  const box = document.getElementById('assistantMessages');
  if (!box) return;
  box.innerHTML = '<div class="chat-welcome" id="assistantWelcome">' +
    '<div class="chat-welcome-icon">&#129302;</div>' +
    '<div class="chat-welcome-title">Plan-Aware Assistant</div>' +
    '<div class="chat-welcome-text">I have full knowledge of your plan — tasks, statuses, priorities, and annotations.<br>' +
    'Ask me anything about your project or click a suggested question above.</div>' +
    '</div>';
};

// ── Chat voice ────────────────────────────────────────────────────────────────

window.toggleChatVoice = async function() {
  if (chatVoiceRecording) { stopChatVoice(); return; }
  await startChatVoice();
};

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

window.stopChatVoice = function() {
  if (chatVoiceMediaRecorder && chatVoiceMediaRecorder.state !== 'inactive') chatVoiceMediaRecorder.stop();
};

window.cancelChatVoice = function() {
  if (chatVoiceMediaRecorder && chatVoiceMediaRecorder.state !== 'inactive') chatVoiceMediaRecorder.stop();
  chatVoiceBlob = null;
  chatVoiceRecording = false;
  document.getElementById('chatMicBtn').classList.remove('recording');
  document.getElementById('chatVoiceBar').style.display = 'none';
};

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
    if (resp.status === 401) { showLoginModal(); removeChatThinking(); return; }
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
  if (activeTab !== 'chat') return;
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

