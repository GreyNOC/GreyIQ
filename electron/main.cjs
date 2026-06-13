'use strict';

const { app, BrowserWindow, shell, ipcMain, dialog } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const { spawn } = require('node:child_process');

const APP_NAME = 'GreyIQ';
const HOST = '127.0.0.1';
const DEFAULT_PORT = parseInt(process.env.GREYIQ_PORT || '8766', 10);
// The frozen backend's first launch is slow: the portable build unpacks ~1 GB to
// a temp dir and torch/model import is cold (measured ~200 s on a fresh run, less
// on later launches once the unpack is cached). Wait well past that before giving
// up so a working backend is never killed by an impatient timeout.
const STARTUP_TIMEOUT_MS = parseInt(process.env.GREYIQ_STARTUP_TIMEOUT_MS || '360000', 10);
const HEALTH_POLL_MS = 500;
const PROJECT_ROOT = app.isPackaged ? path.join(process.resourcesPath, 'app') : path.resolve(__dirname, '..');
// The PyInstaller-frozen backend is shipped as an extraResource at
// <resources>/backend/greyiq-backend(.exe). Present only in packaged builds.
const BACKEND_RESOURCE_DIR = app.isPackaged ? path.join(process.resourcesPath, 'backend') : null;
const RUNTIME_DIR = path.join(app.getPath('userData'), 'runtime');

let mainWindow = null;
let backendProcess = null;
let backendPort = DEFAULT_PORT;
let backendReady = false;
let backendExited = false;
let startupError = '';
let quitting = false;
let logStream = null;

function backendLogPath() {
  try {
    return path.join(app.getPath('userData'), 'backend.log');
  } catch (_) {
    return '';
  }
}

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
    // If the backend process died, stop waiting immediately instead of burning
    // the whole timeout — the error page should appear right away.
    if (backendExited) return false;
    // eslint-disable-next-line no-await-in-loop
    if (await probeHealth(port)) return true;
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, HEALTH_POLL_MS));
  }
  return false;
}

function teeBackendOutput(chunk) {
  process.stdout.write(`[GreyIQ] ${chunk}`);
  if (logStream) {
    try {
      logStream.write(chunk);
    } catch (_) {
      // Logging is best-effort; never let it crash startup.
    }
  }
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

  // Mirror backend output to a log file so failures are diagnosable even though
  // a packaged GUI app has no attached console.
  try {
    logStream = fs.createWriteStream(backendLogPath(), { flags: 'a' });
    logStream.write(`\n===== GreyIQ backend start ${new Date().toISOString()} (${command.exe}) =====\n`);
  } catch (_) {
    logStream = null;
  }

  backendProcess = spawn(command.exe, command.args, {
    cwd: command.cwd || PROJECT_ROOT,
    env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  backendProcess.on('error', (err) => {
    backendExited = true;
    if (!startupError) startupError = `Failed to launch backend: ${err.message}`;
  });
  backendProcess.stdout.on('data', teeBackendOutput);
  backendProcess.stderr.on('data', teeBackendOutput);
  backendProcess.on('exit', (code, signal) => {
    backendExited = true;
    if (!quitting && !backendReady) {
      startupError = `Backend exited before ready (code=${code} signal=${signal}). See ${backendLogPath()}`;
    }
  });

  backendReady = await waitForBackend(backendPort);
  if (!backendReady && !startupError) {
    startupError = `Backend did not become ready within ${Math.round(STARTUP_TIMEOUT_MS / 1000)}s.`;
  }
}

function loadingHtml() {
  return `data:text/html;charset=utf-8,${encodeURIComponent(`
    <body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#f6f7f4;color:#1d2430">
      <div style="text-align:center;max-width:440px;padding:24px">
        <div style="width:42px;height:42px;border:4px solid #d6dad0;border-top-color:#3b7a57;border-radius:50%;margin:0 auto 22px;animation:spin 1s linear infinite"></div>
        <h1 style="font-size:20px;font-weight:500;margin:0 0 10px">Starting GreyIQ…</h1>
        <p style="color:#5f6b5a;font-size:14px;line-height:1.65;margin:0">The local AI engine is warming up. The first launch can take a few minutes while it unpacks and loads the model — later launches are much faster. This window will open automatically when it's ready.</p>
      </div>
      <style>@keyframes spin{to{transform:rotate(360deg)}}</style>
    </body>`)}`;
}

function errorHtml() {
  return `data:text/html;charset=utf-8,${encodeURIComponent(`
    <body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:32px;background:#f6f7f4;color:#1d2430">
      <h1 style="font-size:20px;font-weight:500">GreyIQ backend did not start</h1>
      <p style="color:#5f6b5a;line-height:1.6">${startupError || 'Unknown startup error.'}</p>
      <p style="color:#5f6b5a;line-height:1.6">The first launch is the slowest. Try closing and reopening GreyIQ — the engine unpacks once and starts faster afterwards. A log is at:<br><code>${backendLogPath()}</code></p>
    </body>`)}`;
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

  // Show a loading screen immediately so the user sees the app is alive while the
  // backend warms up, rather than nothing at all for the duration of startup.
  mainWindow.loadURL(loadingHtml());
}

function showApp() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (backendReady) {
    mainWindow.loadURL(`http://${HOST}:${backendPort}/`);
  } else {
    mainWindow.loadURL(errorHtml());
  }
}

function registerIpcHandlers() {
  // Native folder picker for "Add a local folder" in the training panel.
  ipcMain.handle('greyiq:pick-folder', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Choose a folder to add to GreyIQ training data',
      properties: ['openDirectory'],
    });
    if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
      return null;
    }
    return result.filePaths[0];
  });
}

async function boot() {
  registerIpcHandlers();
  createWindow();
  await startBackend();
  showApp();
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
  if (logStream) {
    try {
      logStream.end();
    } catch (_) {
      // ignore
    }
  }
});
