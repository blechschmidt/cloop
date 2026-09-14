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

window.saveConfigField = function(key, value) {
  if (value === undefined || value === null) return;
  api(pUrl('/api/config/set'), {key, value}).then(d => {
    if (d.ok) { toast('Saved: '+key, 'ok'); loadConfig(); }
    else toast(d.error||'Save failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

window.saveAnthropicCfg = function() {
  const key   = document.getElementById('cfgAnthropicKey').value.trim();
  const model = document.getElementById('cfgAnthropicModel').value.trim();
  const base  = document.getElementById('cfgAnthropicBase').value.trim();
  const saves = [];
  if (key)   saves.push(saveConfigField('anthropic.api_key', key));
  if (model) saves.push(saveConfigField('anthropic.model',   model));
  if (base)  saves.push(saveConfigField('anthropic.base_url', base));
  if (!saves.length) { toast('Nothing to save', 'info'); return; }
  Promise.all(saves).then(() => { document.getElementById('cfgAnthropicKey').value = ''; loadConfig(); });
};

window.saveOpenAICfg = function() {
  const key   = document.getElementById('cfgOpenAIKey').value.trim();
  const model = document.getElementById('cfgOpenAIModel').value.trim();
  const base  = document.getElementById('cfgOpenAIBase').value.trim();
  const saves = [];
  if (key)   saves.push(saveConfigField('openai.api_key', key));
  if (model) saves.push(saveConfigField('openai.model',   model));
  if (base)  saves.push(saveConfigField('openai.base_url', base));
  if (!saves.length) { toast('Nothing to save', 'info'); return; }
  Promise.all(saves).then(() => { document.getElementById('cfgOpenAIKey').value = ''; loadConfig(); });
};

window.saveOllamaCfg = function() {
  const base  = document.getElementById('cfgOllamaBase').value.trim();
  const model = document.getElementById('cfgOllamaModel').value.trim();
  const saves = [];
  if (base)  saves.push(saveConfigField('ollama.base_url', base));
  if (model) saves.push(saveConfigField('ollama.model',    model));
  if (!saves.length) { toast('Nothing to save', 'info'); return; }
  Promise.all(saves).then(() => loadConfig());
};

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

window.saveSTTCfg = function() {
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
};

window.clearSTTCfg = function() {
  if (!confirm('Remove the stored speech-to-text key? Dictation stops working until a new one is set.')) return;
  apiMethod('DELETE', '/api/config/stt').then(d => {
    if (d && d.error) { toast(d.error, 'err'); return; }
    toast('Speech-to-text key removed', 'ok');
    renderSTTSettings(d);
    if (window.initTaskDictation) window.initTaskDictation();
  }).catch(() => toast('Request failed', 'err'));
};

window.confirmReset = function() {
  if (!confirm('Reset project state? This clears step history and resets status. Goal and config are preserved.')) return;
  api(pUrl('/api/reset'), {}).then(d => {
    if (d.ok) { toast('Project reset', 'ok'); refreshState(); }
    else toast(d.error||'Reset failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

