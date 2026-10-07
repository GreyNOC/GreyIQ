'use strict';

const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const { randomUUID } = require('node:crypto');

// The frozen Linux CLI and API use this XDG data path when no runtime override
// is set. Packaged Electron must pass the same path to its backend so the CLI
// dashboard and desktop show one portfolio, ledger, and report history.
function resolveRuntimeDir({ platform, packaged, userDataDir, projectRoot, env = process.env, homeDir = os.homedir() }) {
  if (env.GREYIQ_RUNTIME_DIR) return env.GREYIQ_RUNTIME_DIR;
  if (platform === 'linux' && !packaged) return path.posix.join(projectRoot, 'runtime');
  if (platform === 'linux' && packaged) {
    const xdgHome = env.XDG_DATA_HOME;
    const dataHome = xdgHome && path.posix.isAbsolute(xdgHome)
      ? xdgHome
      : path.posix.join(homeDir, '.local', 'share');
    return path.posix.join(dataHome, 'greyiq', 'runtime');
  }
  return path.join(userDataDir, 'runtime');
}

// Previous AppImages kept backend data under Electron's userData directory.
// Copy to a temporary sibling, then promote it only if the XDG destination is
// still absent. Retain the original directory as a recoverable backup.
function migrateLegacyRuntime({ legacyDir, targetDir, fileSystem = fs }) {
  if (path.resolve(legacyDir) === path.resolve(targetDir)
      || fileSystem.existsSync(targetDir)
      || !fileSystem.existsSync(legacyDir)) return false;

  const parent = path.dirname(targetDir);
  const staging = path.join(parent, `.greyiq-runtime-migrate-${process.pid}-${randomUUID()}`);
  try {
    if (!fileSystem.lstatSync(legacyDir).isDirectory()) {
      throw new Error('the previous runtime path is not a directory');
    }
    fileSystem.mkdirSync(parent, { recursive: true, mode: 0o700 });
    fileSystem.cpSync(legacyDir, staging, {
      recursive: true,
      force: false,
      errorOnExist: true,
      preserveTimestamps: true,
      dereference: false,
    });
    if (fileSystem.existsSync(targetDir)) return false;
    fileSystem.renameSync(staging, targetDir);
    return true;
  } catch (err) {
    throw new Error(`Could not copy previous GreyIQ data to ${targetDir}: ${err.message}. Original data remains at ${legacyDir}.`, { cause: err });
  } finally {
    try { fileSystem.rmSync(staging, { recursive: true, force: true }); } catch (_) { /* best-effort cleanup */ }
  }
}

module.exports = { resolveRuntimeDir, migrateLegacyRuntime };
