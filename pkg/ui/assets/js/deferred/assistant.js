// ── Plan Assistant tab ────────────────────────────────────────────────────────
//
// Questions about the plan answered by a model that sees every task, streamed
// in as it writes; the conversation is kept for the tab's session. Fetched on
// the tab's first open since Task 20456, markup included; it was the first
// half of 17-assistant.js.
//
// It runs outside the dashboard's IIFE, so it is handed the helpers it calls,
// and the only name it puts on window is the factory. open() redraws the
// conversation on every visit.
(function () {
  'use strict';

  window.cloopAssistantPanel = function (h) {
    const {toast, pUrl, authHeaders, harnessRefused} = h;

    // The chat tab's time format, for the bubbles both draw.
    const chatFmtTime = ts => (ts ? new Date(ts) : new Date()).toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});


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

    function chipAsk(question) {
      const inp = document.getElementById('assistantInput');
      if (inp) inp.value = question;
      submitAssistantChat();
    }

    function autoGrowTextarea(el) {
      el.style.height = 'auto';
      el.style.height = Math.min(el.scrollHeight, 120) + 'px';
    }
    // On input rather than the keydown it used to share with Enter, which ran
    // before the keystroke reached the box and named a function the bundle never
    // exposed, so every key in it threw.
    function autoGrow() { autoGrowTextarea(this); }

    async function submitAssistantChat() {
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
        if (resp.status === 401) { h.unauthorized(resp); return; }
        if (!resp.ok || !resp.body) {
          // A refusal is JSON. The model call runs on the project's executor
          // (Task 20442), so one with no Claude login opens the dialog that
          // grants one.
          const errText = await resp.text().catch(() => 'Request failed');
          let d = null;
          try { d = JSON.parse(errText); } catch (e) {}
          bubbleDiv.textContent = (d && d.error) || errText;
          bubbleDiv.classList.add('error');
          assistantStreaming = false;
          harnessRefused(d);
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
    }

    function clearAssistantPanel() {
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
    }

    return h.mount({open: loadAssistantHistory, clear: clearAssistantPanel, ask: chipAsk, grow: autoGrow, submit: submitAssistantChat}, 'assistant', `
    <div class="chat-layout">
      <div class="chat-header">
        <span class="section-title" style="margin:0">&#129302; Plan Assistant</span>
        <span class="chat-hint">Ask questions about your plan — the AI has full task context</span>
        <button class="btn" style="padding:4px 10px;font-size:12px;margin-left:auto" data-act="clear">Clear</button>
      </div>
      <div class="assistant-chips" id="assistantChips">
        <span class="chip-label">Try asking:</span>
        <button class="assist-chip" data-act="ask" data-arg="What tasks are blocked?">What tasks are blocked?</button>
        <button class="assist-chip" data-act="ask" data-arg="What should I work on next?">What should I work on next?</button>
        <button class="assist-chip" data-act="ask" data-arg="Summarise progress for stakeholders">Summarise progress for stakeholders</button>
        <button class="assist-chip" data-act="ask" data-arg="Which tasks are overdue or at risk?">Which tasks are overdue or at risk?</button>
        <button class="assist-chip" data-act="ask" data-arg="Give me a risk assessment of the current plan">Risk assessment</button>
      </div>
      <div class="chat-messages" id="assistantMessages">
        <div class="chat-welcome" id="assistantWelcome">
          <div class="chat-welcome-icon">&#129302;</div>
          <div class="chat-welcome-title">Plan-Aware Assistant</div>
          <div class="chat-welcome-text">I have full knowledge of your plan — tasks, statuses, priorities, and annotations.<br>
          Ask me anything about your project or click a suggested question above.</div>
        </div>
      </div>
      <div class="chat-input-bar">
        <textarea class="form-input chat-input assistant-textarea" id="assistantInput"
                  rows="1" placeholder="Ask about your plan..."
                  data-enter="submit" data-input="grow"></textarea>
        <button class="btn primary" data-act="submit" style="flex-shrink:0">
          <svg viewBox="0 0 16 16" fill="currentColor" width="13" height="13"><path d="M15.854.146a.5.5 0 0 1 .11.54l-5.819 14.547a.75.75 0 0 1-1.329.124l-3.178-4.995L.643 7.184a.75.75 0 0 1 .124-1.33L15.314.037a.5.5 0 0 1 .54.11z"/></svg>
          Send
        </button>
      </div>
    </div>
    `);
  };
})();
