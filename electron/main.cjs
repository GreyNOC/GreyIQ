'use strict';

const { app, BrowserWindow, shell, ipcMain, dialog } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
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
// Bundled Ollama runtime (zero-setup local brain). Present only in packaged
// builds. The Windows zip puts ollama.exe at the root; the Linux tarball puts
// the binary under bin/ (with its libs alongside under lib/).
const OLLAMA_RES_DIR = app.isPackaged ? path.join(process.resourcesPath, 'ollama') : null;
const BUNDLED_OLLAMA = OLLAMA_RES_DIR
  ? (process.platform === 'win32'
      ? path.join(OLLAMA_RES_DIR, 'ollama.exe')
      : path.join(OLLAMA_RES_DIR, 'bin', 'ollama'))
  : null;
const OLLAMA_PORT = 11434;
// NVIDIA (CUDA) is included in the bundled Ollama runtime. AMD GPUs need Ollama's
// ROCm runner, which ships as a separate ~1 GB package — too big to bundle under
// GitHub's 2 GiB asset cap — so we fetch it once on first run when an AMD GPU is
// detected and overlay it onto a writable copy of the bundled runtime.
const OLLAMA_ROCM_URL = process.platform === 'win32'
  ? 'https://github.com/ollama/ollama/releases/latest/download/ollama-windows-amd64-rocm.zip'
  : 'https://github.com/ollama/ollama/releases/latest/download/ollama-linux-amd64-rocm.tar.zst';

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

let mainWindow = null;
let backendProcess = null;
let ollamaProcess = null;
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
  if (app.isPackaged) ensureExecutable(command.exe);
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

function ollamaResponding() {
  return new Promise((resolve) => {
    const req = http.get(
      { host: '127.0.0.1', port: OLLAMA_PORT, path: '/api/tags', timeout: 1500 },
      (res) => {
        res.resume();
        resolve(true);
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
let activeOllamaRuntime = 'bundled'; // 'bundled' | 'rocm'
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
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.get(url, { timeout: 60000 }, (res) => {
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

function extractArchive(archivePath, destDir) {
  return new Promise((resolve, reject) => {
    // Linux ships a .tar.zst (tar --zstd); Windows ships a .zip (bundled bsdtar reads zip).
    const args = process.platform === 'win32'
      ? ['-xf', archivePath, '-C', destDir]
      : ['--zstd', '-xf', archivePath, '-C', destDir];
    const child = spawn('tar', args, { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
    let err = '';
    child.stderr.on('data', (chunk) => { err += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`tar exit ${code}: ${String(err).slice(0, 200)}`))));
  });
}

async function ensureRocmRuntime() {
  // Provision (once) and return the path to a ROCm-capable ollama binary, or null.
  if (!OLLAMA_RES_DIR) return null;
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
    // Writable copy of the bundled runtime (binary + CPU runner), minus the CUDA
    // libs an AMD box won't use; the ROCm overlay is extracted on top next.
    fs.cpSync(OLLAMA_RES_DIR, rocmDir, {
      recursive: true,
      filter: (src) => !/[\\/]lib[\\/]ollama[\\/]cuda/i.test(src),
    });
    await downloadFile(OLLAMA_ROCM_URL, archive);
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
    if (detectedGpu === 'amd') {
      const rocmBin = await ensureRocmRuntime();
      if (rocmBin && fs.existsSync(rocmBin)) {
        activeOllamaRuntime = 'rocm';
        return rocmBin;
      }
    }
  } catch (err) {
    logGpu(`GPU runtime resolution failed (${err.message}); using bundled runtime.`);
  }
  activeOllamaRuntime = 'bundled';
  return BUNDLED_OLLAMA;
}

async function startBundledOllama() {
  // Zero-setup local brain: start the bundled Ollama, unless a system Ollama is
  // already serving on the port (then we just use that). No-op in dev (no bundle).
  if (!BUNDLED_OLLAMA || !fs.existsSync(BUNDLED_OLLAMA)) return;
  if (await ollamaResponding()) return;
  // Pick a GPU-capable runtime (NVIDIA is bundled; AMD is fetched once), always
  // falling back to the bundled binary.
  const ollamaBin = (await resolveOllamaRuntime()) || BUNDLED_OLLAMA;
  ensureExecutable(ollamaBin);
  const modelsDir = path.join(app.getPath('userData'), 'ollama-models');
  try {
    fs.mkdirSync(modelsDir, { recursive: true });
  } catch (_) {
    // ignore
  }
  try {
    ollamaProcess = spawn(ollamaBin, ['serve'], {
      env: { ...process.env, OLLAMA_HOST: `127.0.0.1:${OLLAMA_PORT}`, OLLAMA_MODELS: modelsDir },
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    ollamaProcess.stdout.on('data', (chunk) => process.stdout.write(`[Ollama] ${chunk}`));
    ollamaProcess.stderr.on('data', (chunk) => process.stdout.write(`[Ollama] ${chunk}`));
    ollamaProcess.on('error', (err) => process.stderr.write(`[Ollama] failed to start: ${err.message}\n`));
  } catch (err) {
    process.stderr.write(`[Ollama] spawn error: ${err.message}\n`);
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

  // Report local-model GPU acceleration status so the UI can confirm it works.
  ipcMain.handle('greyiq:gpu-info', async () => {
    const vendor = await gpuVendor();
    const accelerated = vendor === 'nvidia' || (vendor === 'amd' && activeOllamaRuntime === 'rocm');
    return { vendor, runtime: activeOllamaRuntime, accelerated };
  });
}

async function boot() {
  registerIpcHandlers();
  // Warm up the bundled local runtime in the background (don't block the window).
  void startBundledOllama();
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
  if (ollamaProcess && !ollamaProcess.killed) {
    ollamaProcess.kill();
  }
  if (logStream) {
    try {
      logStream.end();
    } catch (_) {
      // ignore
    }
  }
});
