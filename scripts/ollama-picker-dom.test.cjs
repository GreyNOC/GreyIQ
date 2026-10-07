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

function node(tagName) {
  return {
    tagName, children: [], value: '', textContent: '',
    append(...children) { this.children.push(...children); },
    replaceChildren() { this.children = []; },
    addEventListener() {},
    setAttribute() {},
    get firstChild() { return this.children[0]; },
  };
}

test('free local picker combines installed and live catalog entries without cloud stubs', () => {
  const picker = node('select');
  const context = {
    els: { brainOllamaModel: picker },
    document: { createElement: node },
    coderConfig: { local: { model: 'qwen2.5:14b' } },
    ollamaCatalog: { installed: ['qwen2.5:14b', 'kimi-k3:cloud'], loading: false,
      models: [{ name: 'qwen3', sizes: ['4b', '8b'], description: 'Local coding model' }] },
  };
  const render = vm.runInNewContext(
    `${functionSource('function renderOllamaOptions(', 'async function refreshOllamaCatalog(')}\nrenderOllamaOptions`, context);
  render();
  const options = picker.children.flatMap((child) => child.tagName === 'optgroup' ? child.children : [child]);
  assert.deepEqual(options.map((option) => option.value), ['', 'qwen2.5:14b', 'qwen3']);
  assert.equal(picker.value, 'qwen2.5:14b');
  assert.match(options.at(-1).textContent, /4b, 8b/);
});

test('saved model casing resolves to the installed Ollama name', () => {
  const picker = node('select');
  const context = {
    els: { brainOllamaModel: picker }, document: { createElement: node },
    coderConfig: { local: { model: 'hf.co/Example/Repo:Q4' } },
    ollamaCatalog: { installed: ['hf.co/example/repo:q4'], loading: false, models: [] },
  };
  const render = vm.runInNewContext(
    `${functionSource('function renderOllamaOptions(', 'async function refreshOllamaCatalog(')}\nrenderOllamaOptions`, context);
  render();
  assert.equal(picker.value, 'hf.co/example/repo:q4');
});

test('a partial or failed live catalog is labeled explicitly', async () => {
  const catalog = { models: [], installed: [], loaded: false, loading: false, requestId: 0 };
  const els = {
    brainOllamaModel: {}, brainCatalogRefresh: { disabled: false },
    brainCatalogStatus: { textContent: '' },
  };
  let response = { ok: true, partial: true, warning: 'Page 3 timed out.',
    models: [{ name: 'qwen3' }] };
  const context = {
    ollamaCatalog: catalog, els, renderOllamaOptions() {},
    apiFetch: async () => response,
  };
  const refresh = vm.runInNewContext(
    `${functionSource('async function refreshOllamaCatalog(', 'async function loadCoderConfig(')}\nrefreshOllamaCatalog`, context);
  await refresh();
  assert.match(els.brainCatalogStatus.textContent, /Partial list: Page 3 timed out/);
  response = { ok: false, error: 'Ollama is unreachable', models: [] };
  await refresh();
  assert.match(els.brainCatalogStatus.textContent, /catalog unavailable: Ollama is unreachable/i);
  assert.equal(catalog.models.length, 0);
});

test('choosing a model starts runtime and readiness-checked setup without saving it early', async () => {
  const calls = [];
  let runtimeStarts = 0;
  let polls = 0;
  const els = {
    brainOllamaModel: { value: 'qwen3', disabled: false },
    brainBaseUrl: { value: '' }, brainModelStatus: { textContent: '' },
    brainSave: { disabled: false },
  };
  const context = {
    els, service: { available: true }, modelPullTimer: null, modelSetupStarting: false,
    refreshServiceStatus: async () => true,
    isLoopbackOllamaUrl: () => true,
    window: { greyiqDesktop: { ensureOllama: async () => { runtimeStarts += 1; return { ok: true }; } } },
    apiFetch: async (url, options) => {
      calls.push({ url, options });
      return { ok: true, active: true, model: 'qwen3' };
    },
    pollModelPull() { polls += 1; context.modelPullTimer = 1; },
  };
  const setup = vm.runInNewContext(
    `${functionSource('async function setupSelectedOllamaModel(', 'els.brainOllamaModel?.addEventListener(')}\nsetupSelectedOllamaModel`, context);
  await setup();
  assert.equal(runtimeStarts, 1);
  assert.deepEqual(calls.map((call) => call.url), ['/api/coder/setup']);
  assert.deepEqual(JSON.parse(calls[0].options.body), { model: 'qwen3', base_url: '' });
  assert.equal(polls, 1);
  assert.equal(els.brainOllamaModel.disabled, true);
});

test('a second selection cannot race a pending service check', async () => {
  let resolveService;
  const serviceCheck = new Promise((resolve) => { resolveService = resolve; });
  const calls = [];
  const els = {
    brainOllamaModel: { value: 'qwen3', disabled: false }, brainBaseUrl: { value: '' },
    brainModelStatus: { textContent: '' }, brainSave: { disabled: false },
  };
  const context = {
    els, service: { available: false }, modelPullTimer: null, modelSetupStarting: false,
    refreshServiceStatus: () => serviceCheck,
    isLoopbackOllamaUrl: () => true,
    window: {},
    apiFetch: async (url, options) => { calls.push({ url, options }); return { ok: true }; },
    pollModelPull() {},
  };
  const setup = vm.runInNewContext(
    `${functionSource('async function setupSelectedOllamaModel(', 'els.brainOllamaModel?.addEventListener(')}\nsetupSelectedOllamaModel`, context);
  const first = setup();
  els.brainOllamaModel.value = 'gemma4';
  const second = setup();
  resolveService(true);
  await Promise.all([first, second]);
  assert.equal(calls.length, 1);
  assert.equal(JSON.parse(calls[0].options.body).model, 'qwen3');
});

test('an edited server URL is used for installed models and cannot remove on the old host', async () => {
  const calls = [];
  let rendered;
  const els = {
    brainModelStatus: { textContent: '' }, brainBaseUrl: { value: 'https://models.example/v1' },
    brainProvider: { value: 'local' },
  };
  const context = {
    els, service: { available: true }, modelStatusRequestId: 0,
    coderConfig: { local: { model: 'qwen3', base_url: '' } },
    ollamaCatalog: { installed: [], installedBaseUrl: null },
    refreshServiceStatus: async () => true,
    renderOllamaOptions() {},
    renderModelList(...args) { rendered = args; },
    apiFetch: async (url) => {
      calls.push(url);
      return { ok: true, installed: ['qwen3', 'kimi-k3:cloud'], configured: 'qwen3', present: true };
    },
    encodeURIComponent,
  };
  const refresh = vm.runInNewContext(
    `${functionSource('async function refreshModelStatus(', 'els.brainBaseUrl?.addEventListener(')}\nrefreshModelStatus`, context);
  await refresh();
  assert.deepEqual(calls, ['/api/coder/models?base_url=https%3A%2F%2Fmodels.example%2Fv1']);
  assert.deepEqual(Array.from(rendered[0]), ['qwen3']);
  assert.equal(rendered[2], false);
  assert.match(els.brainModelStatus.textContent, /1 installed local models/);
});

test('Remove is disabled while the displayed server differs from the saved server', () => {
  const list = node('div');
  const context = { els: { brainModelList: list }, document: { createElement: node } };
  const render = vm.runInNewContext(
    `${functionSource('function renderModelList(', 'async function deleteModel(')}\nrenderModelList`, context);
  render(['qwen3'], '', false);
  const remove = list.children[0].children[1].children[0];
  assert.equal(remove.disabled, true);
});

test('Remove is disabled for the active local brain', () => {
  const list = node('div');
  const context = { els: { brainModelList: list }, document: { createElement: node } };
  const render = vm.runInNewContext(
    `${functionSource('function renderModelList(', 'async function deleteModel(')}\nrenderModelList`, context);
  render(['qwen3:latest'], 'qwen3', true);
  const remove = list.children[0].children[1].children[0];
  assert.equal(remove.disabled, true);
  assert.match(remove.title, /Select another model/);
});
