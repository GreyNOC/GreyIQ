'use strict';

const { app, BrowserWindow, shell } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const { spawn } = require('node:child_process');

const APP_NAME = 'GreyIQ';
const HOST = '127.0.0.1';
const DEFAULT_PORT = parseInt(process.env.GREYIQ_PORT || '8766', 10);
const STARTUP_TIMEOUT_MS = 60_000;
const HEALTH_POLL_MS = 400;
const PROJECT_ROOT = app.isPackaged ? path.join(process.resourcesPath, 'app') : path.resolve(__dirname, '..');
// The PyInstaller-frozen backend is shipped as an extraResource at
// <resources>/backend/greyiq-backend(.exe). Present only in packaged builds.
const BACKEND_RESOURCE_DIR = app.isPackaged ? path.join(process.resourcesPath, 'backend') : null;
const RUNTIME_DIR = path.join(app.getPath('userData'), 'runtime');

let mainWindow = null;
let backendProcess = null;
let backendPort = DEFAULT_PORT;
let backendReady = false;
let startupError = '';
let quitting = false;

function parseUrl(rawUrl) {
  try {
    return new URL(rawUrl);
  } catch (_) {
    return null;
  }
}

function isAllowedExternalUrl(rawUrl) {
  const parsed = parseUrl(rawUrl);
  return Boolean(parsed && (parsed.protocol === 'https:' || parsed.protocol === 'http:' || parsed.protocol === 'mailto:'));
}

function isTrustedBackendUrl(rawUrl) {
  const parsed = parseUrl(rawUrl);
  if (!parsed) return false;
  if (!backendReady && parsed.protocol === 'data:') return true;
  return parsed.protocol === 'http:' && parsed.hostname === HOST && Number(parsed.port) === backendPort;
}

function isPortFree(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.once('listening', () => server.close(() => resolve(true)));
    try {
      server.listen(port, HOST);
    } catch (_) {
      resolve(false);
    }
  });
}

async function findFreePort(start) {
  for (let port = start; port < start + 80; port += 1) {
    // eslint-disable-next-line no-await-in-loop
    if (await isPortFree(port)) return port;
  }
  throw new Error(`No free port found near ${start}`);
}

function resolvePython() {
  if (process.env.GREYIQ_PYTHON && fs.existsSync(process.env.GREYIQ_PYTHON)) {
    return { exe: process.env.GREYIQ_PYTHON, args: ['-m', 'backend.greyiq_api'] };
  }

  const candidates = process.platform === 'win32'
    ? [
        path.join(PROJECT_ROOT, '.venv', 'Scripts', 'python.exe'),
        path.join(PROJECT_ROOT, 'venv', 'Scripts', 'python.exe'),
      ]
    : [
        path.join(PROJECT_ROOT, '.venv', 'bin', 'python'),
        path.join(PROJECT_ROOT, 'venv', 'bin', 'python'),
      ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return { exe: candidate, args: ['-m', 'backend.greyiq_api'] };
  }

  if (process.platform === 'win32') return { exe: 'py', args: ['-3', '-m', 'backend.greyiq_api'] };
  return { exe: 'python3', args: ['-m', 'backend.greyiq_api'] };
}

function resolveBackendCommand() {
  // Prefer the self-contained frozen backend in packaged builds; fall back to a
  // local Python interpreter for `electron .` development runs.
  if (app.isPackaged && BACKEND_RESOURCE_DIR) {
    const exeName = process.platform === 'win32' ? 'greyiq-backend.exe' : 'greyiq-backend';
    const frozen = path.join(BACKEND_RESOURCE_DIR, exeName);
    if (fs.existsSync(frozen)) {
      return { exe: frozen, args: [], cwd: BACKEND_RESOURCE_DIR };
    }
  }
  const py = resolvePython();
  return { exe: py.exe, args: py.args, cwd: PROJECT_ROOT };
}

function probeHealth(port) {
  return new Promise((resolve) => {
    const req = http.get(
      {
        host: HOST,
        port,
        path: '/api/health',
        timeout: 2000,
      },
      (res) => {
        res.resume();
        resolve(res.statusCode >= 200 && res.statusCode < 500);
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitForBackend(port) {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    // eslint-disable-next-line no-await-in-loop
    if (await probeHealth(port)) return true;
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, HEALTH_POLL_MS));
  }
  return false;
}

async function startBackend() {
  backendPort = await findFreePort(DEFAULT_PORT);
  const command = resolveBackendCommand();
  const env = {
    ...process.env,
    GREYIQ_HOST: HOST,
    GREYIQ_PORT: String(backendPort),
    GREYIQ_RUNTIME_DIR: process.env.GREYIQ_RUNTIME_DIR || RUNTIME_DIR,
    PYTHONUTF8: '1',
  };

  backendProcess = spawn(command.exe, command.args, {
    cwd: command.cwd || PROJECT_ROOT,
    env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  backendProcess.stdout.on('data', (chunk) => process.stdout.write(`[GreyIQ] ${chunk}`));
  backendProcess.stderr.on('data', (chunk) => process.stderr.write(`[GreyIQ] ${chunk}`));
  backendProcess.on('exit', (code, signal) => {
    if (!quitting && !backendReady) {
      startupError = `Backend exited before ready (code=${code} signal=${signal})`;
    }
  });

  backendReady = await waitForBackend(backendPort);
  if (!backendReady && !startupError) {
    startupError = 'Backend did not become ready in time.';
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 980,
    minHeight: 680,
    title: APP_NAME,
    backgroundColor: '#f6f7f4',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isAllowedExternalUrl(url)) {
      void shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!isTrustedBackendUrl(url)) {
      event.preventDefault();
    }
  });

  mainWindow.webContents.session.setPermissionRequestHandler((_webContents, _permission, callback) => {
    callback(false);
  });

  if (backendReady) {
    mainWindow.loadURL(`http://${HOST}:${backendPort}/`);
  } else {
    mainWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(`
      <body style="font-family:system-ui;margin:32px;background:#f6f7f4;color:#1d2430">
        <h1>GreyIQ backend did not start</h1>
        <p>${startupError || 'Unknown startup error.'}</p>
      </body>
    `)}`);
  }
}

async function boot() {
  await startBackend();
  createWindow();
}

app.whenReady().then(boot);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  quitting = true;
  if (backendProcess && !backendProcess.killed) {
    backendProcess.kill();
  }
});
