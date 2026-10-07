'use strict';

const { app, BrowserWindow, shell, ipcMain, dialog } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { probeHealth } = require('./health.cjs');
const { ollamaAssets, selectOllamaBinary, extractArchive } = require('./ollama-runtime.cjs');
const { resolveRuntimeDir, migrateLegacyRuntime } = require('./runtime-path.cjs');

const APP_NAME = 'GreyIQ';
const HOST = '127.0.0.1';
const DEFAULT_PORT = parseInt(process.env.GREYIQ_PORT || '8766', 10);
// The frozen backend's first launch pays a one-time unpack of the portable archive
// to a temp dir (~250 MB since PyTorch was dropped from the bundle); later launches
// reuse the cached unpack and the API now answers /api/health in ~1 s (torch + pandas
// are no longer on the boot path). The timeout stays generous so a slow first unpack
// on a cold disk is never killed by an impatient timeout.
const STARTUP_TIMEOUT_MS = parseInt(process.env.GREYIQ_STARTUP_TIMEOUT_MS || '180000', 10);
const HEALTH_POLL_MS = 500;
const PROJECT_ROOT = app.isPackaged ? path.join(process.resourcesPath, 'app') : path.resolve(__dirname, '..');
// The PyInstaller-frozen backend is shipped as an extraResource at
// <resources>/backend/greyiq-backend(.exe). Present only in packaged builds.
const BACKEND_RESOURCE_DIR = app.isPackaged ? path.join(process.resourcesPath, 'backend') : null;
const RUNTIME_DIR = resolveRuntimeDir({
  platform: process.platform,
  packaged: app.isPackaged,
  userDataDir: app.getPath('userData'),
  projectRoot: PROJECT_ROOT,
});
// Ollama runtime (zero-setup LOCAL brain). It is NO LONGER bundled — it was ~1.4 GB
// (86% of the old portable) and the bug-hunting engine + the Claude/OpenAI brains
// never use it. It is downloaded ON DEMAND to a writable userData dir the first time
// the operator actually selects the local model, so the default app stays small/fast.
// Keep ARM64's cache separate from older amd64 downloads in the same profile.
const OLLAMA_BASE_DIR = path.join(app.getPath('userData'),
  process.platform === 'linux' && process.arch === 'arm64' ? 'ollama-arm64' : 'ollama');
const OLLAMA_BIN = process.platform === 'win32'
  ? path.join(OLLAMA_BASE_DIR, 'ollama.exe')
  : path.join(OLLAMA_BASE_DIR, 'bin', 'ollama');
const OLLAMA_PORT = 11434;
const OLLAMA_ASSETS = ollamaAssets(process.platform, process.arch);
// AMD GPUs need Ollama's ROCm runner (a separate ~1 GB package); fetched once on
// first run when an AMD GPU is detected on a supported architecture.

// extraResources can drop the executable bit on non-Windows; restore it
// best-effort before we spawn a bundled binary.
function ensureExecutable(filePath) {
  if (process.platform === 'win32' || !filePath) return;
  try {
    fs.chmodSync(filePath, 0o755);
  } catch (_) {
    // best-effort; the file may already be executable or owned read-only.
  }
}

function existingFile(filePath) {
  if (!filePath) return false;
  try {
    return fs.statSync(filePath).isFile();
  } catch (_) {
    return false;
  }
}

function newestMatchingFile(dirPath, pattern) {
  try {
    return fs.readdirSync(dirPath)
      .filter((name) => pattern.test(name))
      .map((name) => path.join(dirPath, name))
      .filter(existingFile)
      .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0] || '';
  } catch (_) {
    return '';
  }
}

// TACNOC remains its own sandboxed Electron application and engine. GreyIQ only
// discovers and starts that trusted companion; no renderer-controlled path or
// command-line argument crosses IPC. An explicit environment override supports
// custom installs, while the remaining candidates cover bundled, installed, and
// local-development layouts.
function tacnocCommandFrom(candidate) {
  if (!candidate) return null;
  const target = path.resolve(candidate);
  if (existingFile(target)) return { exe: target, args: [], cwd: path.dirname(target) };

  try {
    if (!fs.statSync(target).isDirectory()) return null;
  } catch (_) {
    return null;
  }

  if (process.platform === 'darwin' && target.toLowerCase().endsWith('.app')) {
    return { exe: '/usr/bin/open', args: [target], cwd: path.dirname(target) };
  }

  const packaged = process.platform === 'win32'
    ? [
        path.join(target, 'TACNOC.exe'),
        path.join(target, 'dist', 'win-unpacked', 'TACNOC.exe'),
      ]
    : [
        path.join(target, 'TACNOC'),
        path.join(target, 'dist', 'TACNOC'),
      ];
  for (const executable of packaged) {
    if (existingFile(executable)) return { exe: executable, args: [], cwd: path.dirname(executable) };
  }

  const artifact = process.platform === 'win32'
    ? newestMatchingFile(path.join(target, 'dist'), /^TACNOC-.*-Portable-.*\.exe$/i)
    : newestMatchingFile(path.join(target, 'dist'), /^TACNOC-.*\.AppImage$/i);
  if (artifact) return { exe: artifact, args: [], cwd: path.dirname(artifact) };

  // A built development checkout can run through its own Electron binary. Requiring
  // both the compiled main entry and package identity avoids treating an arbitrary
  // directory as an Electron application.
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(target, 'package.json'), 'utf8'));
    const electron = process.platform === 'win32'
      ? path.join(target, 'node_modules', 'electron', 'dist', 'electron.exe')
      : path.join(target, 'node_modules', 'electron', 'dist', 'electron');
    if (pkg.name === 'greynoc-tacnoc'
        && existingFile(path.join(target, 'out', 'main', 'index.js'))
        && existingFile(electron)) {
      return { exe: electron, args: [target], cwd: target };
    }
  } catch (_) {
    // Not a TACNOC source checkout.
  }
  return null;
}

function resolveTacnocCommand() {
  const candidates = [];
  if (process.env.GREYIQ_TACNOC_PATH) candidates.push(process.env.GREYIQ_TACNOC_PATH);
  if (app.isPackaged) candidates.push(path.join(process.resourcesPath, 'tacnoc'));

  if (process.platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || '';
    if (localAppData) {
      candidates.push(path.join(localAppData, 'Programs', 'TACNOC', 'TACNOC.exe'));
      candidates.push(path.join(localAppData, 'Programs', 'greynoc-tacnoc', 'TACNOC.exe'));
    }
    candidates.push(path.join(path.dirname(process.execPath), 'TACNOC.exe'));
  } else if (process.platform === 'darwin') {
    candidates.push('/Applications/TACNOC.app');
  } else {
    candidates.push('/opt/TACNOC/TACNOC');
    candidates.push('/usr/local/bin/tacnoc');
  }

  // GreyNOC's normal local-development checkout name. app.getPath('desktop') is
  // user-relative, so this works without hard-coding an account name or drive.
  candidates.push(path.join(app.getPath('desktop'), 'GreyNOC Belcher'));

  for (const candidate of [...new Set(candidates.filter(Boolean))]) {
    const command = tacnocCommandFrom(candidate);
    if (command) return command;
  }
  return null;
}

function launchTacnoc() {
  const command = resolveTacnocCommand();
  if (!command) {
    return Promise.resolve({
      ok: false,
      error: 'TACNOC was not found. Install TACNOC or set GREYIQ_TACNOC_PATH to its executable or project folder.',
    });
  }
  if (process.platform !== 'win32' && command.exe !== '/usr/bin/open') ensureExecutable(command.exe);

  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(command.exe, command.args, {
        cwd: command.cwd,
        detached: true,
        stdio: 'ignore',
        windowsHide: false,
      });
    } catch (err) {
      resolve({ ok: false, error: `TACNOC could not be opened: ${err.message}` });
      return;
    }
    child.once('error', (err) => resolve({ ok: false, error: `TACNOC could not be opened: ${err.message}` }));
    child.once('spawn', () => {
      child.unref();
      resolve({ ok: true });
    });
  });
}

let mainWindow = null;
let backendProcess = null;
let ollamaProcess = null;
let ollamaStartPromise = null;
let backendPort = DEFAULT_PORT;
let backendReady = false;
let backendExited = false;
let startupError = '';
let quitting = false;
let logStream = null;
let logBytes = 0;  // bytes written to the current backend.log since it was (re)opened; drives mid-session rolling
const LOG_MAX_BYTES = 5 * 1024 * 1024;

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
    // Packaged build but the frozen backend is GONE (a broken install or antivirus
    // quarantine). Do NOT fall back to a dev Python path — an end-user machine has no
    // Python and no source tree, so that produces a misleading "python failed" error.
    // Signal a specific, actionable failure instead.
    return { missing: true, exeName };
  }
  const py = resolvePython();
  return { exe: py.exe, args: py.args, cwd: PROJECT_ROOT };
}

async function waitForBackend(port, launchId) {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    // If the backend process died, stop waiting immediately instead of burning
    // the whole timeout — the error page should appear right away.
    if (backendExited) return false;
    // eslint-disable-next-line no-await-in-loop
    if (await probeHealth(HOST, port, launchId)) return true;
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, HEALTH_POLL_MS));
  }
  return false;
}

// Roll the live log mid-session once it crosses the cap. The spawn-time roll only
// fires once per launch, so a long-lived, chatty session would otherwise append to
// backend.log without bound (hundreds of MB). Mirror the spawn-time roll here.
function rollBackendLog() {
  const logPath = backendLogPath();
  if (!logPath) return;
  try {
    if (logStream) { try { logStream.end(); } catch (_) { /* ignore */ } }
    try { fs.rmSync(`${logPath}.1`, { force: true }); } catch (_) { /* no prior backup */ }
    try { fs.renameSync(logPath, `${logPath}.1`); } catch (_) { /* best-effort roll */ }
    logStream = fs.createWriteStream(logPath, { flags: 'a' });
    logBytes = 0;
  } catch (_) {
    logStream = null;
  }
}

function teeBackendOutput(chunk) {
  process.stdout.write(`[GreyIQ] ${chunk}`);
  if (logStream) {
    try {
      logStream.write(chunk);
      // chunk is a Buffer on stdio pipes, so .length is the byte count.
      logBytes += chunk.length;
      if (logBytes > LOG_MAX_BYTES) rollBackendLog();
    } catch (_) {
      // Logging is best-effort; never let it crash startup.
    }
  }
}

async function startBackend() {
  backendPort = await findFreePort(DEFAULT_PORT);
  const command = resolveBackendCommand();
  if (command.missing) {
    backendExited = true;
    startupError = `GreyIQ's backend component (${command.exeName}) is missing from this install. `
      + `Reinstall GreyIQ, and check whether antivirus quarantined a file.`;
    return;  // nothing to spawn or wait for — showApp() will render the error page
  }
  if (app.isPackaged) ensureExecutable(command.exe);
  const launchId = crypto.randomBytes(32).toString('hex');
  const env = {
    ...process.env,
    GREYIQ_HOST: HOST,
    GREYIQ_PORT: String(backendPort),
    GREYIQ_LAUNCH_ID: launchId,
    GREYIQ_RUNTIME_DIR: process.env.GREYIQ_RUNTIME_DIR || RUNTIME_DIR,
    PYTHONUTF8: '1',
  };

  // Mirror backend output to a log file so failures are diagnosable even though
  // a packaged GUI app has no attached console. Bound its growth: an append-only log with no cap
  // inflates to hundreds of MB over months of launches / chatty engine sessions and can exhaust a
  // small disk. Roll to a single .1 backup once it passes the cap, then keep appending to a fresh file.
  try {
    const logPath = backendLogPath();
    try {
      if (fs.statSync(logPath).size > LOG_MAX_BYTES) {
        try { fs.rmSync(`${logPath}.1`, { force: true }); } catch (_) { /* no prior backup */ }
        try { fs.renameSync(logPath, `${logPath}.1`); } catch (_) { /* best-effort roll */ }
      }
    } catch (_) { /* no existing log yet */ }
    logStream = fs.createWriteStream(logPath, { flags: 'a' });
    // Seed the running byte counter with the size already on disk (flags:'a' appends),
    // so mid-session rolling accounts for pre-existing content, not just this session's writes.
    try { logBytes = fs.statSync(logPath).size; } catch (_) { logBytes = 0; }
    const startBanner = `\n===== GreyIQ backend start ${new Date().toISOString()} (${command.exe}) =====\n`;
    logStream.write(startBanner);
    logBytes += Buffer.byteLength(startBanner);
  } catch (_) {
    logStream = null;
  }

  backendProcess = spawn(command.exe, command.args, {
    cwd: command.cwd || PROJECT_ROOT,
    env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    // POSIX: make the child a process-group leader so killTree's process.kill(-pid)
    // actually signals its grandchildren (model runners). Windows uses taskkill /T.
    detached: process.platform !== 'win32',
  });

  backendProcess.on('error', (err) => {
    backendExited = true;
    if (!startupError) startupError = `Failed to launch backend: ${err.message}`;
  });
  backendProcess.stdout.on('data', teeBackendOutput);
  backendProcess.stderr.on('data', teeBackendOutput);
  backendProcess.on('exit', (code, signal) => {
    backendExited = true;
    if (quitting) return;
    if (!backendReady) {
      startupError = `Backend exited before ready (code=${code} signal=${signal}). See ${backendLogPath()}`;
    } else {
      // The engine died AFTER the UI had loaded — every apiFetch now fails silently.
      // Mark it not-ready (so the data: stopped-page is a trusted navigation again) and
      // replace the now-dead UI with a clear "engine stopped, restart" page instead of
      // leaving a frozen-looking app.
      backendReady = false;
      showBackendStoppedPage(code, signal);
    }
  });

  backendReady = await waitForBackend(backendPort, launchId);
  if (!backendReady && !startupError) {
    startupError = `Backend did not become ready within ${Math.round(STARTUP_TIMEOUT_MS / 1000)}s.`;
  }
}

function escapeSystemPageHtml(value) {
  return String(value == null ? '' : value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const SYSTEM_PAGE_HEAD = `
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
  <meta name="color-scheme" content="dark">
`;

function loadingHtml() {
  return `data:text/html;charset=utf-8,${encodeURIComponent(`
    <!doctype html>${SYSTEM_PAGE_HEAD}
    <body style="font-family:'IBM Plex Sans',system-ui,-apple-system,Segoe UI,sans-serif;margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0e14;color:#edf1f6">
      <div style="text-align:center;max-width:440px;padding:24px">
        <div style="font:600 11px 'Cascadia Mono',Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;color:#7e8b9c;margin-bottom:18px">GreyNOC / Operations</div>
        <div style="width:36px;height:36px;border:3px solid #1e2633;border-top-color:#5b8cff;border-radius:50%;margin:0 auto 22px;animation:spin 1s linear infinite"></div>
        <h1 style="font-size:20px;font-weight:700;margin:0 0 10px">Starting GreyIQ…</h1>
        <p style="color:#a8b3c2;font-size:14px;line-height:1.65;margin:0">The local engine is starting. First launch setup takes longer; later launches are faster. This window opens automatically when it is ready.</p>
      </div>
      <style>@keyframes spin{to{transform:rotate(360deg)}}</style>
    </body>`)}`;
}

function errorHtml() {
  const detail = escapeSystemPageHtml(startupError || 'Unknown startup error.');
  const logPath = escapeSystemPageHtml(backendLogPath());
  return `data:text/html;charset=utf-8,${encodeURIComponent(`
    <!doctype html>${SYSTEM_PAGE_HEAD}
    <body style="font-family:'IBM Plex Sans',system-ui,-apple-system,Segoe UI,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0e14;color:#edf1f6">
      <main style="width:min(620px,calc(100% - 48px));padding:28px;border:1px solid #1e2633;border-radius:6px;background:#10151d">
        <div style="font:600 11px 'Cascadia Mono',Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;color:#f0506e">Engine unavailable</div>
        <h1 style="font-size:20px;font-weight:700;margin:10px 0">GreyIQ did not start</h1>
        <p style="color:#a8b3c2;line-height:1.6">${detail}</p>
        <p style="color:#a8b3c2;line-height:1.6">Close and reopen GreyIQ. If the problem continues, review the local log:<br><code style="color:#7aa2ff">${logPath}</code></p>
      </main>
    </body>`)}`;
}

function backendStoppedHtml(code, signal) {
  const exitDetail = escapeSystemPageHtml(`code=${code} signal=${signal}`);
  const logPath = escapeSystemPageHtml(backendLogPath());
  return `data:text/html;charset=utf-8,${encodeURIComponent(`
    <!doctype html>${SYSTEM_PAGE_HEAD}
    <body style="font-family:'IBM Plex Sans',system-ui,-apple-system,Segoe UI,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0e14;color:#edf1f6">
      <main style="width:min(620px,calc(100% - 48px));padding:28px;border:1px solid #1e2633;border-radius:6px;background:#10151d">
        <div style="font:600 11px 'Cascadia Mono',Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;color:#f0506e">Engine stopped</div>
        <h1 style="font-size:20px;font-weight:700;margin:10px 0">GreyIQ lost its local engine</h1>
        <p style="color:#a8b3c2;line-height:1.6">The engine exited unexpectedly (${exitDetail}). Your saved programs, scopes, and reports remain safe on disk.</p>
        <p style="color:#a8b3c2;line-height:1.6">Close and reopen GreyIQ to continue. Local log:<br><code style="color:#7aa2ff">${logPath}</code></p>
      </main>
    </body>`)}`;
}

function showBackendStoppedPage(code, signal) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  try { void mainWindow.loadURL(backendStoppedHtml(code, signal)); } catch (_) { /* window may be tearing down */ }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 980,
    minHeight: 680,
    title: APP_NAME,
    backgroundColor: '#0a0e14',
    // GreyNOC owl app icon for the window, taskbar/dock, and dev runs. On packaged
    // Windows the taskbar uses the icon embedded in the exe (build/icon.ico via
    // electron-builder); setting it here also covers `electron .` dev runs and Linux,
    // where the window icon comes from this file rather than the executable.
    icon: path.join(__dirname, process.platform === 'win32' ? 'icon.ico' : 'icon.png'),
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

  // If the renderer crashes (OOM, GPU fault) after the app loaded, reload the UI from the
  // still-running backend rather than leaving a blank window. If the backend is already
  // gone, its own exit handler shows the stopped page.
  mainWindow.webContents.on('render-process-gone', (_event, details) => {
    if (quitting || (details && details.reason === 'clean-exit')) return;
    if (backendReady && !backendExited) {
      try { void mainWindow.loadURL(`http://${HOST}:${backendPort}/`); } catch (_) { /* tearing down */ }
    }
  });

  // Deny every permission EXCEPT 'notifications' -- the completion/submission alerts
  // (public/app.js's ckNotify) call the standard Web Notification API, which Electron
  // maps straight to a native OS notification with no custom bridge needed. Without
  // this allow-list entry, Notification.requestPermission() silently resolves to
  // 'denied' in the packaged app even though the same code works fine in a plain
  // browser tab during dev.
  mainWindow.webContents.session.setPermissionRequestHandler((_webContents, permission, callback) => {
    callback(permission === 'notifications');
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

function ollamaResponding() {
  return new Promise((resolve) => {
    const req = http.get(
      { host: '127.0.0.1', port: OLLAMA_PORT, path: '/api/tags', timeout: 1500 },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200 && String(res.headers['content-type'] || '').includes('application/json'));
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

// ---- GPU acceleration for the bundled local model (Ollama) ----
// NVIDIA (CUDA) ships in the bundled runtime and Ollama auto-detects it. AMD
// (ROCm) is fetched on first run. Everything here is best-effort: any failure
// falls back to the bundled runtime so the app never breaks over GPU setup.
let detectedGpu = 'unknown';         // 'nvidia' | 'amd' | 'other' | 'unknown'
let activeOllamaRuntime = 'bundled'; // 'bundled' | 'rocm' | 'system'
let lastOllamaError = '';
let gpuVendorCache = null;

function logGpu(message) {
  process.stdout.write(`[GPU] ${message}\n`);
}

function detectGpuVendor() {
  return new Promise((resolve) => {
    try {
      if (process.platform === 'linux') {
        let vendors = '';
        try {
          for (const entry of fs.readdirSync('/sys/class/drm')) {
            if (!/^card\d+$/.test(entry)) continue;
            try {
              vendors += fs.readFileSync(path.join('/sys/class/drm', entry, 'device', 'vendor'), 'utf8');
            } catch (_) { /* card without a vendor file */ }
          }
        } catch (_) { /* no DRM info available */ }
        if (/0x10de/i.test(vendors)) return resolve('nvidia'); // prefer NVIDIA (CUDA bundled)
        if (/0x1002/i.test(vendors)) return resolve('amd');
        return resolve('other');
      }
      if (process.platform === 'win32') {
        const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', '(Get-CimInstance Win32_VideoController).Name'], { windowsHide: true });
        let out = '';
        ps.stdout.on('data', (chunk) => { out += chunk; });
        ps.on('error', () => resolve('other'));
        ps.on('exit', () => {
          if (/NVIDIA|GeForce|RTX|Quadro/i.test(out)) return resolve('nvidia');
          if (/AMD|Radeon/i.test(out)) return resolve('amd');
          resolve('other');
        });
        return;
      }
      resolve('other');
    } catch (_) {
      resolve('other');
    }
  });
}

async function gpuVendor() {
  if (gpuVendorCache === null) gpuVendorCache = await detectGpuVendor();
  return gpuVendorCache;
}

function downloadFile(url, dest, redirects = 5) {
  return new Promise((resolve, reject) => {
    // This archive is executed after extraction. A release redirect must never
    // downgrade its transport to HTTP.
    if (parseUrl(url)?.protocol !== 'https:') {
      reject(new Error('runtime download requires HTTPS'));
      return;
    }
    const req = https.get(url, { timeout: 60000 }, (res) => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400 && res.headers.location) {
        res.resume();
        if (redirects <= 0) { reject(new Error('too many redirects')); return; }
        resolve(downloadFile(new URL(res.headers.location, url).toString(), dest, redirects - 1));
        return;
      }
      if (status !== 200) { res.resume(); reject(new Error(`HTTP ${status}`)); return; }
      const out = fs.createWriteStream(dest);
      res.pipe(out);
      out.on('finish', () => out.close(() => resolve(dest)));
      out.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('download timed out')); });
  });
}

async function ensureBaseOllama() {
  // Provision (once) the base Ollama runtime to a writable userData dir, downloading
  // it on demand (it is no longer bundled). Only ever called when the user wants the local
  // model — never at boot — so the default app never pays for it.
  if (!app.isPackaged) return null;  // dev: use a system-installed ollama if present
  if (!OLLAMA_ASSETS) {
    throw new Error(`Automatic Ollama download is unavailable for ${process.platform}/${process.arch}. Install Ollama and set GREYIQ_OLLAMA_PATH.`);
  }
  if (fs.existsSync(OLLAMA_BIN)) return OLLAMA_BIN;
  logGpu('Local model selected — downloading the Ollama runtime (one-time ~1 GB)…');
  const archive = path.join(app.getPath('userData'), process.platform === 'win32' ? 'ollama-base.zip' : 'ollama-base.tar.zst');
  try {
    fs.mkdirSync(OLLAMA_BASE_DIR, { recursive: true });
    await downloadFile(OLLAMA_ASSETS.base, archive);
    await extractArchive(archive, OLLAMA_BASE_DIR);
    fs.rmSync(archive, { force: true });
    if (!fs.existsSync(OLLAMA_BIN)) throw new Error('Ollama binary missing after extraction');
    ensureExecutable(OLLAMA_BIN);
    logGpu('Ollama runtime ready.');
    return OLLAMA_BIN;
  } catch (err) {
    logGpu(`Ollama provisioning failed (${err.message}).`);
    try { fs.rmSync(archive, { force: true }); } catch (_) { /* ignore */ }
    try { fs.rmSync(OLLAMA_BASE_DIR, { recursive: true, force: true }); } catch (_) { /* ignore */ }
    throw err;
  }
}

async function ensureRocmRuntime() {
  // Provision (once) and return the path to a ROCm-capable ollama binary, or null.
  // Needs the base runtime first (it's overlaid onto a copy of it).
  if (!OLLAMA_ASSETS?.rocm) return null;
  if (!fs.existsSync(OLLAMA_BIN)) return null;
  const rocmDir = path.join(app.getPath('userData'), 'ollama-rocm');
  const rocmBin = process.platform === 'win32'
    ? path.join(rocmDir, 'ollama.exe')
    : path.join(rocmDir, 'bin', 'ollama');
  const sentinel = path.join(rocmDir, '.rocm-ready');
  if (fs.existsSync(sentinel) && fs.existsSync(rocmBin)) return rocmBin;

  logGpu('AMD GPU detected — provisioning Ollama ROCm runtime (one-time ~1 GB download)…');
  const archive = path.join(app.getPath('userData'), process.platform === 'win32' ? 'ollama-rocm.zip' : 'ollama-rocm.tar.zst');
  try {
    fs.rmSync(rocmDir, { recursive: true, force: true });
    fs.mkdirSync(rocmDir, { recursive: true });
    // Writable copy of the base runtime (binary + CPU runner), minus the CUDA
    // libs an AMD box won't use; the ROCm overlay is extracted on top next.
    fs.cpSync(OLLAMA_BASE_DIR, rocmDir, {
      recursive: true,
      filter: (src) => !/[\\/]lib[\\/]ollama[\\/]cuda/i.test(src),
    });
    await downloadFile(OLLAMA_ASSETS.rocm, archive);
    await extractArchive(archive, rocmDir);
    fs.rmSync(archive, { force: true });
    if (!fs.existsSync(rocmBin)) throw new Error('ROCm runtime binary missing after extraction');
    ensureExecutable(rocmBin);
    fs.writeFileSync(sentinel, new Date().toISOString());
    logGpu('Ollama ROCm runtime ready.');
    return rocmBin;
  } catch (err) {
    logGpu(`ROCm provisioning failed (${err.message}); falling back to the bundled runtime.`);
    try { fs.rmSync(archive, { force: true }); } catch (_) { /* ignore */ }
    return null;
  }
}

async function resolveOllamaRuntime() {
  try {
    detectedGpu = await gpuVendor();
    logGpu(`GPU vendor: ${detectedGpu}`);
    if (detectedGpu === 'amd' && OLLAMA_ASSETS?.rocm) {
      const rocmBin = await ensureRocmRuntime();
      if (rocmBin && fs.existsSync(rocmBin)) {
        activeOllamaRuntime = 'rocm';
        return rocmBin;
      }
    }
  } catch (err) {
    logGpu(`GPU runtime resolution failed (${err.message}); using base runtime.`);
  }
  activeOllamaRuntime = 'bundled';
  return OLLAMA_BIN;
}

async function startOllama() {
  if (ollamaStartPromise) return ollamaStartPromise;
  ollamaStartPromise = startOllamaOnce();
  try {
    return await ollamaStartPromise;
  } finally {
    ollamaStartPromise = null;
  }
}

async function startOllamaOnce() {
  // On-demand local brain: provision the Ollama runtime (downloaded on first use),
  // then start it — unless a system Ollama is already serving on the port. Triggered
  // by the renderer when the user selects the local model, NEVER at boot.
  lastOllamaError = '';
  if (await ollamaResponding()) return true;
  // A Linux install can supply Ollama through PATH or an explicit override, even
  // when GreyIQ itself is packaged. Use that installation's model directory too.
  const selected = await selectOllamaBinary({
    platform: process.platform,
    packaged: app.isPackaged,
    ensureBase: ensureBaseOllama,
  });
  const baseBin = selected.binary;
  if (!baseBin || (app.isPackaged && !selected.external && !fs.existsSync(baseBin))) {
    lastOllamaError = 'Ollama runtime was not found. Install Ollama or set GREYIQ_OLLAMA_PATH.';
    return false;
  }
  // Pick a GPU-capable runtime (NVIDIA works on the base runner; AMD ROCm is fetched
  // once). A system install manages its own GPU runners.
  const ollamaBin = app.isPackaged && !selected.external ? ((await resolveOllamaRuntime()) || baseBin) : baseBin;
  if (selected.external) activeOllamaRuntime = 'system';
  if (app.isPackaged && !selected.external) ensureExecutable(ollamaBin);
  const modelsDir = path.join(app.getPath('userData'), 'ollama-models');
  const ollamaEnv = { ...process.env, OLLAMA_HOST: `127.0.0.1:${OLLAMA_PORT}` };
  if (app.isPackaged && !selected.external) {
    fs.mkdirSync(modelsDir, { recursive: true });
    ollamaEnv.OLLAMA_MODELS = modelsDir;
  }
  try {
    ollamaProcess = spawn(ollamaBin, ['serve'], {
      env: ollamaEnv,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      // POSIX group leader so killTree reaps Ollama's model-runner grandchildren.
      detached: process.platform !== 'win32',
    });
    ollamaProcess.stdout.on('data', (chunk) => process.stdout.write(`[Ollama] ${chunk}`));
    ollamaProcess.stderr.on('data', (chunk) => process.stdout.write(`[Ollama] ${chunk}`));
    let exited = false;
    ollamaProcess.once('exit', () => { exited = true; });
    const spawned = await new Promise((resolve) => {
      ollamaProcess.once('spawn', () => resolve(true));
      ollamaProcess.once('error', (err) => {
        lastOllamaError = `Ollama could not start (${err.message}). Check GREYIQ_OLLAMA_PATH or install Ollama.`;
        process.stderr.write(`[Ollama] failed to start: ${err.message}\n`);
        resolve(false);
      });
    });
    if (!spawned || exited || ollamaProcess.exitCode !== null) {
      if (!lastOllamaError) lastOllamaError = 'Ollama exited before it was ready. Check the Ollama logs.';
      return false;
    }
    const deadline = Date.now() + 30000;
    while (!exited && Date.now() < deadline) {
      // eslint-disable-next-line no-await-in-loop
      if (await ollamaResponding()) return true;
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    killTree(ollamaProcess);
    lastOllamaError = 'Ollama did not answer on 127.0.0.1:11434 within 30 seconds. Check the Ollama logs.';
    return false;
  } catch (err) {
    lastOllamaError = `Ollama could not start (${err.message}).`;
    process.stderr.write(`[Ollama] spawn error: ${err.message}\n`);
    return false;
  }
}

function registerIpcHandlers() {
  // Provision + start the on-demand Ollama runtime (the renderer calls this when the
  // user selects the local model). Downloads ~1 GB on first use; later launches reuse it.
  ipcMain.handle('greyiq:ensure-ollama', async () => {
    try {
      const ok = await startOllama();
      return { ok: Boolean(ok), runtime: activeOllamaRuntime, ...(ok ? {} : { error: lastOllamaError }) };
    } catch (err) {
      return { ok: false, error: String(err && err.message || err) };
    }
  });

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

  // Report local-model GPU acceleration status so the UI can confirm it works.
  ipcMain.handle('greyiq:gpu-info', async () => {
    const vendor = await gpuVendor();
    const accelerated = vendor === 'nvidia' || (vendor === 'amd' && activeOllamaRuntime === 'rocm');
    return { vendor, runtime: activeOllamaRuntime, accelerated };
  });

  // Open the companion TACNOC app in its own hardened Electron process. Keeping
  // the engines separate preserves TACNOC's contextBridge and secret-store boundary.
  ipcMain.handle('greyiq:launch-tacnoc', async () => launchTacnoc());
}

async function boot() {
  registerIpcHandlers();
  // Ollama is NOT started at boot — it's downloaded + started on demand (greyiq:
  // ensure-ollama) only when the operator selects the local model, so the default
  // app stays small and fast. If a system Ollama is already serving, the backend
  // uses it directly.
  createWindow();
  // Always swap to the app (or the error page) even if startup throws — otherwise an
  // unhandled rejection leaves the window stuck on the loading spinner forever.
  try {
    if (process.platform === 'linux' && app.isPackaged && !process.env.GREYIQ_RUNTIME_DIR) {
      const migrated = migrateLegacyRuntime({
        legacyDir: path.join(app.getPath('userData'), 'runtime'),
        targetDir: RUNTIME_DIR,
      });
      if (migrated) process.stdout.write(`[GreyIQ] Copied previous runtime data to ${RUNTIME_DIR}.\n`);
    }
    await startBackend();
  } catch (err) {
    if (!startupError) startupError = `Startup failed: ${err && err.message ? err.message : err}`;
  } finally {
    showApp();
  }
}

app.whenReady().then(boot).catch((err) => {
  if (!startupError) startupError = `Startup failed: ${err && err.message ? err.message : err}`;
  try { showApp(); } catch (_) { /* nothing more we can do */ }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// Kill the whole process tree, not just the direct child — the backend and Ollama
// spawn their own children (model runners), which would otherwise be orphaned and
// keep holding ports/memory after the app quits.
function killTree(proc) {
  if (!proc || proc.killed || proc.pid == null) return;
  try {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(proc.pid), '/T', '/F'], { windowsHide: true });
    } else {
      try { process.kill(-proc.pid); } catch (_) { proc.kill(); }
    }
  } catch (_) { /* best-effort during shutdown */ }
}

app.on('before-quit', () => {
  quitting = true;
  killTree(backendProcess);
  killTree(ollamaProcess);
  if (logStream) {
    try {
      logStream.end();
    } catch (_) {
      // ignore
    }
  }
});
