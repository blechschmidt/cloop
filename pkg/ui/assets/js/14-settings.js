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

window.confirmReset = function() {
  if (!confirm('Reset project state? This clears step history and resets status. Goal and config are preserved.')) return;
  api(pUrl('/api/reset'), {}).then(d => {
    if (d.ok) { toast('Project reset', 'ok'); refreshState(); }
    else toast(d.error||'Reset failed', 'err');
  }).catch(() => toast('Request failed', 'err'));
};

