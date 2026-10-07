'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function loadMain({ responding, external = false, accessKey = '', modelsDir = '', listenLog = true }) {
  const handlers = new Map();
  const requests = [];
  const children = [];
  const windows = [];
  const userData = path.join(process.cwd(), '.test-greyiq-userdata');
  const fakeHttp = {
    request(options, callback) {
      const request = new EventEmitter();
      request.end = (body) => {
        requests.push({ options, body: JSON.parse(body) });
        setImmediate(() => {
          const response = new EventEmitter();
          response.statusCode = 200;
          response.resume = () => {};
          callback(response);
          response.emit('end');
        });
      };
      request.destroy = (error) => request.emit('error', error);
      return request;
    },
  };
  const fakeApp = {
    isPackaged: true,
    getPath: () => userData,
    whenReady: () => new Promise(() => {}),
    on: () => {},
  };
  const fakeFs = {
    ...fs,
    existsSync: (target) => target === '/fake/ollama' || fs.existsSync(target),
    mkdirSync: () => {},
    realpathSync: (target) => path.resolve(target),
  };
  const fakeProcess = {
    platform: process.platform,
    arch: process.arch,
    env: {
      ...(accessKey ? { GREYIQ_ACCESS_KEY: accessKey } : {}),
      ...(modelsDir ? { OLLAMA_MODELS: modelsDir } : {}),
    },
    resourcesPath: '/fake/resources',
    stdout: { write: () => {} },
    stderr: { write: () => {} },
  };
  const fakeSpawn = (_binary, _args, options) => {
    const child = new EventEmitter();
    child.spawnOptions = options;
    child.pid = 12345;
    child.exitCode = null;
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    children.push(child);
    setImmediate(() => {
      child.emit('spawn');
      if (listenLog) child.stderr.emit('data', 'msg="Listening on 127.0.0.1:11434 (version 0.35.0)"');
    });
    return child;
  };
  class FakeBrowserWindow extends EventEmitter {
    constructor(options) {
      super();
      this.options = options;
      this.loadedUrls = [];
      this.destroyed = false;
      this.maximized = false;
      this.webContents = new EventEmitter();
      this.webContents.sent = [];
      this.webContents.send = (...args) => this.webContents.sent.push(args);
      this.webContents.setWindowOpenHandler = () => {};
      this.webContents.session = { setPermissionRequestHandler: () => {} };
      windows.push(this);
    }
    isDestroyed() { return this.destroyed; }
    isMaximized() { return this.maximized; }
    minimize() { this.minimized = true; }
    maximize() { this.maximized = true; this.emit('maximize'); }
    unmaximize() { this.maximized = false; this.emit('unmaximize'); }
    close() { this.closed = true; }
    loadURL(url) { this.loadedUrls.push(url); }
  }
  const requireMock = (name) => {
    if (name === 'electron') return {
      app: fakeApp, BrowserWindow: FakeBrowserWindow, Menu: { setApplicationMenu: () => {} }, shell: {}, dialog: {},
      ipcMain: { handle: (channel, handler) => handlers.set(channel, handler) },
    };
    if (name === 'node:http') return fakeHttp;
    if (name === 'node:fs') return fakeFs;
    if (name === 'node:child_process') return { spawn: fakeSpawn };
    if (name === './health.cjs') return { probeHealth: async () => true };
    if (name === './ollama-runtime.cjs') return {
      ollamaAssets: () => ({}),
      selectOllamaBinary: async () => ({ binary: '/fake/ollama', external }),
      extractArchive: async () => {},
    };
    if (name === './runtime-path.cjs') return {
      resolveRuntimeDir: () => '/fake/runtime',
      migrateLegacyRuntime: () => false,
    };
    return require(name);
  };
  const filename = path.join(__dirname, 'main.cjs');
  const source = fs.readFileSync(filename, 'utf8');
  const exposed = '\nmodule.exports = { registerIpcHandlers, createWindow, loadingHtml, errorHtml, backendStoppedHtml, '
    + 'setResponding: (fn) => { ollamaResponding = fn; }, '
    + 'setResolveRuntime: (fn) => { resolveOllamaRuntime = fn; }, '
    + 'setBackendReady: (value) => { backendReady = value; } };';
  const sandbox = {
    module: { exports: {} }, require: requireMock, __dirname, process: fakeProcess,
    Buffer, URL, setTimeout, clearTimeout,
  };
  vm.runInNewContext(source + exposed, sandbox, { filename });
  sandbox.module.exports.setResponding(responding);
  sandbox.module.exports.setResolveRuntime(async () => '/fake/ollama');
  sandbox.module.exports.registerIpcHandlers();
  return {
    ensureOllama: handlers.get('greyiq:ensure-ollama'),
    setBackendReady: sandbox.module.exports.setBackendReady,
    createWindow: sandbox.module.exports.createWindow,
    loadingHtml: sandbox.module.exports.loadingHtml,
    errorHtml: sandbox.module.exports.errorHtml,
    backendStoppedHtml: sandbox.module.exports.backendStoppedHtml,
    handlers, requests, children, windows, userData,
  };
}

test('an already-running Ollama gives the backend an unknown model store', async () => {
  const app = loadMain({ responding: async () => true });
  const result = await app.ensureOllama();
  assert.equal(result.ok, true);
  assert.equal(result.runtime, 'system');
  assert.equal(app.children.length, 0);
  assert.equal(app.requests.length, 1);
  assert.equal(app.requests[0].body.models_dir, null);
  assert.equal(app.requests[0].options.path, '/api/internal/ollama-model-store');
  assert.ok(app.requests[0].options.headers['X-GreyIQ-Internal-Model-Store-Token']);
});

test('a bundled Ollama hands off its actual store before ensure returns, then clears on exit', async () => {
  let calls = 0;
  const app = loadMain({ responding: async () => ++calls > 1 });
  const result = await app.ensureOllama();
  assert.equal(result.ok, true);
  assert.equal(app.requests.length, 1);
  assert.equal(app.requests[0].body.models_dir, path.resolve(app.userData, 'ollama-models'));
  app.setBackendReady(true);
  const child = app.children[0];
  child.exitCode = 0;
  child.emit('exit', 0);
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(app.requests.length, 2);
  assert.equal(app.requests[1].body.models_dir, null);
});

test('an external Ollama binary never claims GreyIQ model storage', async () => {
  let calls = 0;
  const app = loadMain({ responding: async () => ++calls > 1, external: true });
  const result = await app.ensureOllama();
  assert.equal(result.ok, true);
  assert.equal(result.runtime, 'system');
  assert.equal(app.children[0].spawnOptions.env.OLLAMA_MODELS, undefined);
  assert.equal(app.requests[0].body.models_dir, null);
});

test('a launched external Ollama with explicit model storage hands off its proven path', async () => {
  let calls = 0;
  const modelsDir = path.join(process.cwd(), 'temporary', '..', 'operator-model-store');
  const app = loadMain({ responding: async () => ++calls > 1, external: true, modelsDir });
  const result = await app.ensureOllama();
  const expected = path.resolve(modelsDir);
  assert.equal(result.ok, true);
  assert.equal(result.runtime, 'system');
  assert.equal(app.children[0].spawnOptions.env.OLLAMA_MODELS, expected);
  assert.equal(app.requests[0].body.models_dir, expected);
  app.setBackendReady(true);
  const child = app.children[0];
  child.exitCode = 0;
  child.emit('exit', 0);
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(app.requests[1].body.models_dir, null);
});

test('a pre-existing Ollama remains unknown despite explicit local model storage', async () => {
  const app = loadMain({
    responding: async () => true,
    external: true,
    modelsDir: path.join(process.cwd(), 'operator-model-store'),
  });
  const result = await app.ensureOllama();
  assert.equal(result.ok, true);
  assert.equal(app.children.length, 0);
  assert.equal(app.requests[0].body.models_dir, null);
});

test('bundled Ollama and backend use the requested model store', async () => {
  let calls = 0;
  const modelsDir = path.join(process.cwd(), 'alternate-model-store');
  const app = loadMain({ responding: async () => ++calls > 1, modelsDir });
  const result = await app.ensureOllama();
  assert.equal(result.ok, true);
  assert.equal(app.children[0].spawnOptions.env.OLLAMA_MODELS, path.resolve(modelsDir));
  assert.equal(app.requests[0].body.models_dir, path.resolve(modelsDir));
});

test('internal update includes configured backend access key', async () => {
  const app = loadMain({ responding: async () => true, accessKey: 'operator-key' });
  await app.ensureOllama();
  const authorization = app.requests[0].options.headers.Authorization;
  assert.equal(authorization, `Basic ${Buffer.from(':operator-key').toString('base64')}`);
});

test('a server that wins the Ollama port race is never assigned the bundled model store', async () => {
  let checks = 0;
  let app;
  app = loadMain({
    listenLog: false,
    responding: async () => {
      checks += 1;
      if (checks === 1) return false;
      if (checks === 2) {
        setImmediate(() => {
          const child = app.children[0];
          child.exitCode = 1;
          child.emit('exit', 1);
        });
      }
      return true;
    },
  });
  const result = await app.ensureOllama();
  assert.equal(result.ok, true);
  assert.equal(result.runtime, 'system');
  assert.equal(app.requests[0].body.models_dir, null);
});

test('a port-race winner is not assigned an external child’s configured store', async () => {
  let checks = 0;
  let app;
  app = loadMain({
    external: true,
    modelsDir: path.join(process.cwd(), 'operator-model-store'),
    listenLog: false,
    responding: async () => {
      checks += 1;
      if (checks === 1) return false;
      if (checks === 2) {
        setImmediate(() => {
          const child = app.children[0];
          child.exitCode = 1;
          child.emit('exit', 1);
        });
      }
      return true;
    },
  });
  const result = await app.ensureOllama();
  assert.equal(result.ok, true);
  assert.equal(app.requests[0].body.models_dir, null);
});

test('frameless app and all local fallback pages retain window controls', () => {
  const app = loadMain({ responding: async () => true });
  app.createWindow();
  const window = app.windows[0];
  assert.equal(window.options.frame, false);
  assert.equal(window.options.webPreferences.contextIsolation, true);
  assert.equal(window.options.webPreferences.sandbox, true);
  assert.equal(window.loadedUrls.length, 1);
  for (const page of [window.loadedUrls[0], app.errorHtml(), app.backendStoppedHtml(1, null)]) {
    const html = decodeURIComponent(page.split(',').slice(1).join(','));
    for (const action of ['minimize', 'maximize', 'close']) {
      assert.ok(html.includes(`data-window-control="${action}"`), `${action} missing on fallback page`);
    }
    assert.ok(html.includes("default-src 'none'"));
  }
});

test('window IPC acts only on the owned live window and reports maximize state', async () => {
  const app = loadMain({ responding: async () => true });
  app.createWindow();
  const window = app.windows[0];
  const owned = { sender: window.webContents };
  const foreign = { sender: {} };
  const minimize = app.handlers.get('greyiq:window-minimize');
  const toggle = app.handlers.get('greyiq:window-toggle-maximize');
  const state = app.handlers.get('greyiq:window-is-maximized');
  const close = app.handlers.get('greyiq:window-close');
  assert.equal(minimize(foreign), false);
  assert.equal(toggle(foreign), false);
  assert.equal(close(foreign), false);
  assert.equal(window.minimized, undefined);
  assert.equal(minimize(owned), true);
  assert.equal(window.minimized, true);
  assert.equal(state(owned), false);
  assert.equal(toggle(owned), true);
  assert.equal(state(owned), true);
  assert.equal(toggle(owned), false);
  assert.deepEqual(window.webContents.sent.map((item) => item[1]), [true, false]);
  assert.equal(close(owned), true);
  assert.equal(window.closed, true);
  window.destroyed = true;
  assert.equal(minimize(owned), false);
});

test('preload reveals and binds titlebar controls without page scripts', async () => {
  const calls = [];
  const ipcRenderer = new EventEmitter();
  ipcRenderer.invoke = async (channel) => {
    calls.push(channel);
    return channel === 'greyiq:window-toggle-maximize';
  };
  const classSet = () => {
    const values = new Set();
    return {
      values,
      add: (value) => values.add(value),
      toggle: (value, active) => active ? values.add(value) : values.delete(value),
    };
  };
  const buttons = Object.fromEntries(['minimize', 'maximize', 'close'].map((action) => {
    const listeners = new Map();
    const button = {
      action, listeners, classList: classSet(),
      getAttribute: () => action,
      setAttribute(name, value) { this[name] = value; },
      addEventListener: (name, callback) => listeners.set(name, callback),
    };
    return [action, button];
  }));
  const titlebar = {
    hidden: true,
    querySelector: () => buttons.maximize,
    querySelectorAll: () => Object.values(buttons),
  };
  const document = {
    readyState: 'loading',
    body: { classList: classSet() },
    querySelector: () => titlebar,
  };
  const windowListeners = new Map();
  const window = { addEventListener: (name, callback) => windowListeners.set(name, callback) };
  const exposed = {};
  const preloadSource = fs.readFileSync(path.join(__dirname, 'preload.cjs'), 'utf8');
  vm.runInNewContext(preloadSource, {
    require: (name) => name === 'electron'
      ? { contextBridge: { exposeInMainWorld: (name, api) => { exposed[name] = api; } }, ipcRenderer }
      : require(name),
    process: { platform: 'win32' }, document, window,
  });
  assert.equal(typeof exposed.greyiqDesktop.ensureOllama, 'function');
  assert.equal(titlebar.hidden, true);
  windowListeners.get('DOMContentLoaded')();
  assert.equal(titlebar.hidden, false);
  assert.ok(document.body.classList.values.has('desktop-window'));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(buttons.maximize['aria-label'], 'Maximize GreyIQ');
  for (const button of Object.values(buttons)) button.listeners.get('click')();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(calls, [
    'greyiq:window-is-maximized',
    'greyiq:window-minimize',
    'greyiq:window-toggle-maximize',
    'greyiq:window-close',
  ]);
  assert.equal(buttons.maximize['aria-label'], 'Restore GreyIQ');
});
