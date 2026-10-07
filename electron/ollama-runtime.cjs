'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const RELEASE_ROOT = 'https://github.com/ollama/ollama/releases/latest/download';

function ollamaAssets(platform, arch) {
  if (platform === 'win32' && arch === 'x64') {
    return {
      base: `${RELEASE_ROOT}/ollama-windows-amd64.zip`,
      rocm: `${RELEASE_ROOT}/ollama-windows-amd64-rocm.zip`,
    };
  }
  if (platform === 'linux' && (arch === 'x64' || arch === 'arm64')) {
    const releaseArch = arch === 'x64' ? 'amd64' : 'arm64';
    return {
      base: `${RELEASE_ROOT}/ollama-linux-${releaseArch}.tar.zst`,
      // Ollama publishes a Linux ROCm overlay for amd64, but not arm64.
      rocm: arch === 'x64' ? `${RELEASE_ROOT}/ollama-linux-amd64-rocm.tar.zst` : null,
    };
  }
  return null;
}

function findLinuxOllama(env = process.env, fileSystem = fs) {
  const override = (env.GREYIQ_OLLAMA_PATH || '').trim();
  if (override) return override;
  for (const dir of (env.PATH || '').split(path.delimiter)) {
    if (!dir) continue; // An empty PATH element would search the working directory.
    const candidate = path.join(dir, 'ollama');
    try {
      if (fileSystem.statSync(candidate).isFile()) {
        fileSystem.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      }
    } catch (_) {
      // Keep looking for another executable on PATH.
    }
  }
  return null;
}

async function selectOllamaBinary({ platform, packaged, ensureBase, env = process.env, fileSystem = fs }) {
  // Packaged macOS installs have no GreyIQ-managed archive. Use an operator
  // override or an executable on PATH just as packaged Linux does.
  const external = (platform === 'linux' || platform === 'darwin')
    ? (findLinuxOllama(env, fileSystem) || (!packaged ? 'ollama' : null))
    : (!packaged ? (env.GREYIQ_OLLAMA_PATH || 'ollama') : null);
  if (external) return { binary: external, external: true };
  return { binary: await ensureBase(), external: false };
}

function extractArchive(archivePath, destDir, options = {}) {
  const platform = options.platform || process.platform;
  const spawnProcess = options.spawnProcess || spawn;
  return new Promise((resolve, reject) => {
    const args = platform === 'win32'
      ? ['-xf', archivePath, '-C', destDir]
      : ['--zstd', '-xf', archivePath, '-C', destDir];
    let child;
    try {
      child = spawnProcess('tar', args, { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
    } catch (err) {
      reject(extractionError(platform, `could not start tar: ${err.message}`));
      return;
    }
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', (err) => reject(extractionError(platform, `could not start tar: ${err.message}`)));
    child.once('exit', (code) => {
      if (code === 0) resolve();
      else reject(extractionError(platform, `tar exited ${code}: ${stderr.trim().slice(0, 300) || 'no details'}`));
    });
  });
}

function extractionError(platform, detail) {
  const remedy = platform === 'linux'
    ? ' Install tar and zstd (on Debian: sudo apt install tar zstd), then retry the download.'
    : '';
  return new Error(`Ollama archive extraction failed: ${detail}.${remedy}`);
}

module.exports = { ollamaAssets, findLinuxOllama, selectOllamaBinary, extractArchive };
