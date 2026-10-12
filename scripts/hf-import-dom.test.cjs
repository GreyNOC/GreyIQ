'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.resolve(__dirname, '..', 'public', 'app.js'), 'utf8');

function functionSource(start, end) {
  const first = source.indexOf(start);
  const last = source.indexOf(end, first);
  assert.ok(first >= 0 && last > first, `${start} should be present`);
  return source.slice(first, last);
}

test('saved loopback model starts its runtime once when the renderer loads', async () => {
  const loopback = vm.runInNewContext(
    `${functionSource('function isLoopbackOllamaUrl(', 'async function importHuggingFaceModel(')}\nisLoopbackOllamaUrl`,
    { URL },
  );
  const loadSource = functionSource('async function loadCoderConfig(', 'els.brainProvider?.addEventListener(');
  async function exercise(config) {
    let starts = 0;
    let refreshes = 0;
    const els = { brainForm: {}, brainStatus: { textContent: '' }, brainOllamaModel: {}, brainSave: {} };
    const context = {
      coderConfig: null, savedLocalRuntimeBootAttempted: false, els,
      isLoopbackOllamaUrl: loopback,
      renderBrainForm() {}, renderAgentBar() {}, pollModelPull() {},
      refreshModelStatus() { refreshes += 1; },
      apiFetch: async (url) => url === '/api/coder' ? config : { active: false },
      window: { greyiqDesktop: { ensureOllama: async () => { starts += 1; return { ok: true }; } } },
    };
    const load = vm.runInNewContext(`${loadSource}\nloadCoderConfig`, context);
    await load();
    await load();
    return { starts, refreshes, status: els.brainStatus.textContent };
  }
  const local = await exercise({ enabled: true, provider: 'local',
    local: { model: 'hf.co/acme/Code-GGUF:Q4_K_M', base_url: '' } });
  assert.equal(local.starts, 1);
  assert.equal(local.refreshes, 1);
  assert.match(local.status, /runtime ready/i);
  const remote = await exercise({ enabled: true, provider: 'local',
    local: { model: 'hf.co/acme/Code-GGUF:Q4_K_M', base_url: 'https://models.example/v1' } });
  assert.equal(remote.starts, 0);
});

test('late runtime startup does not replace a newer model setup result', async () => {
  const loopback = vm.runInNewContext(
    `${functionSource('function isLoopbackOllamaUrl(', 'async function importHuggingFaceModel(')}\nisLoopbackOllamaUrl`,
    { URL },
  );
  const loadSource = functionSource('async function loadCoderConfig(', 'els.brainProvider?.addEventListener(');
  let resolveRuntime;
  const runtime = new Promise((resolve) => { resolveRuntime = resolve; });
  const els = { brainForm: {}, brainStatus: { textContent: '' }, brainOllamaModel: {}, brainSave: {} };
  const context = {
    coderConfig: null, savedLocalRuntimeBootAttempted: false, els,
    isLoopbackOllamaUrl: loopback,
    renderBrainForm() {}, renderAgentBar() {}, pollModelPull() {}, refreshModelStatus() {},
    apiFetch: async (url) => url === '/api/coder'
      ? { enabled: true, provider: 'local', local: { model: 'hf.co/acme/Code-GGUF', base_url: '' } }
      : { active: false },
    window: { greyiqDesktop: { ensureOllama: () => runtime } },
  };
  const load = vm.runInNewContext(`${loadSource}\nloadCoderConfig`, context);
  await load();
  els.brainStatus.textContent = 'Model setup completed.';
  resolveRuntime({ ok: true });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(els.brainStatus.textContent, 'Model setup completed.');
});

test('Hugging Face import starts setup without a premature model selection', async () => {
  const importSource = functionSource('async function importHuggingFaceModel(', 'els.brainHfImport?.addEventListener(');
  const calls = [];
  let polled = null;
  const els = {
    brainHfReference: { value: 'https://huggingface.co/acme/Code-GGUF:Q4_K_M' },
    brainHfStatus: { textContent: '' }, brainHfImport: { disabled: false },
  };
  const context = {
    els, modelPullTimer: null, modelSetupStarting: false, service: { available: true },
    refreshServiceStatus: async () => true,
    window: { greyiqDesktop: { ensureOllama: async () => ({ ok: true }) } },
    apiFetch: async (url, options) => {
      calls.push({ url, options });
      return { ok: true, active: true, model: 'hf.co/acme/Code-GGUF:Q4_K_M' };
    },
    pollModelPull(options) { polled = options; },
  };
  const importModel = vm.runInNewContext(`${importSource}\nimportHuggingFaceModel`, context);
  await importModel();
  assert.deepEqual(calls.map((call) => call.url), ['/api/coder/huggingface/import']);
  assert.equal(JSON.parse(calls[0].options.body).reference, els.brainHfReference.value);
  assert.equal(polled.statusEl, els.brainHfStatus);
  assert.equal(polled.button, els.brainHfImport);
  assert.equal(els.brainHfImport.disabled, true, 'selection awaits the readiness status');
});

test('model setup status selects only when chat and tool readiness passed', async () => {
  const pollSource = functionSource('function pollModelPull(', 'async function setupSelectedOllamaModel(');
  async function exercise(status) {
    let loads = 0;
    const els = {
      brainModelStatus: { textContent: '' }, brainOllamaModel: { disabled: true, value: 'previous-model' },
      brainSave: { disabled: true }, brainStatus: { textContent: '' },
      brainHfStatus: { textContent: '' }, brainHfImport: { disabled: true },
    };
    const context = {
      els, modelPullTimer: null, coderConfig: { local: { model: 'previous-model' } },
      apiFetch: async (url) => {
        assert.equal(url, '/api/coder/pull');
        return status;
      },
      loadCoderConfig: async () => { loads += 1; },
      refreshModelStatus() {}, setInterval: () => 1, clearInterval() {},
    };
    const poll = vm.runInNewContext(`${pollSource}\npollModelPull`, context);
    poll({ statusEl: els.brainHfStatus, button: els.brainHfImport });
    await new Promise((resolve) => setImmediate(resolve));
    return { loads, els };
  }
  const selected = await exercise({ done: true, selected: true, model: 'hf.co/acme/Code-GGUF' });
  assert.equal(selected.loads, 1);
  assert.match(selected.els.brainHfStatus.textContent, /ready for chat and agent tools/);
  const chatOnly = await exercise({ done: true, chat_only: true, selected: false,
    model: 'hf.co/acme/Code-GGUF', error: 'No structured tool call.' });
  assert.equal(chatOnly.loads, 0);
  assert.match(chatOnly.els.brainStatus.textContent, /previous brain is still active/);
  const shardedProgress = await exercise({ active: true, done: false,
    model: 'hf.co/acme/Code-GGUF', percent: 41, status: 'downloading GGUF part 2 of 4' });
  assert.match(shardedProgress.els.brainHfStatus.textContent, /41% downloading GGUF part 2 of 4/);
  assert.equal(shardedProgress.els.brainHfImport.disabled, true);
  assert.equal(shardedProgress.loads, 0);
  for (const error of [
    'Not enough free disk space for this GGUF model. Free space and retry.',
    'This GGUF model architecture is unsupported by the local Ollama runtime. Choose a compatible model.',
  ]) {
    const failed = await exercise({ done: true, selected: false,
      model: 'hf.co/acme/Code-GGUF', error });
    assert.equal(failed.loads, 0, 'a failed import must not load or select the new brain');
    assert.equal(failed.els.brainOllamaModel.value, 'previous-model');
    assert.equal(failed.els.brainHfImport.disabled, false, 'retry must be available');
    assert.match(failed.els.brainHfStatus.textContent, /Your brain setting is unchanged\./);
    assert.ok(failed.els.brainHfStatus.textContent.includes(error));
  }
});
