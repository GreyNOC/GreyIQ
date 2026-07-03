const { existsSync, readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { pathToFileURL } = require("node:url");
const { spawnSync } = require("node:child_process");

const configs = ["ecosystem.config.cjs", "ecosystem.config.js", "ecosystem.config.mjs"].filter(existsSync);

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

// The backend version string (stamped into every delivered bug-bounty report + /api/health) MUST
// equal package.json. Guard against the two drifting — a stale backend version misrepresents the
// build to a triager, which is exactly what happened (0.49.0 shipped as 0.70.0).
function checkVersionParity() {
  const pkg = JSON.parse(readFileSync(resolve("package.json"), "utf8")).version;
  const src = readFileSync(resolve("backend/_version.py"), "utf8");
  const m = src.match(/VERSION\s*=\s*["']([^"']+)["']/);
  if (!m) {
    fail("backend/_version.py: could not find VERSION = \"…\"");
    return;
  }
  if (m[1] !== pkg) {
    fail(`version drift: backend/_version.py is "${m[1]}" but package.json is "${pkg}" — bump both in the Release commit.`);
  }
}

async function loadConfig(file) {
  const absolute = resolve(file);
  if (file.endsWith(".cjs")) {
    return require(absolute);
  }
  const module = await import(pathToFileURL(absolute));
  return module.default || module;
}

function validateConfig(file, config) {
  if (!config || !Array.isArray(config.apps) || config.apps.length === 0) {
    fail(`${file}: expected a non-empty apps array`);
    return;
  }
  for (const app of config.apps) {
    if (!app || typeof app !== "object") {
      fail(`${file}: app entry must be an object`);
      continue;
    }
    if (!app.name || !app.script) {
      fail(`${file}: each app must include name and script`);
    }
    const env = app.env || {};
    for (const key of ["HOST", "GREYIQ_HOST"]) {
      if (env[key] === "0.0.0.0") {
        fail(`${file}: ${app.name} uses 0.0.0.0; keep deployment defaults on 127.0.0.1`);
      }
    }
  }
}

async function main() {
  checkVersionParity();
  for (const file of configs) {
    const syntax = spawnSync(process.execPath, ["--check", file], { stdio: "inherit" });
    if (syntax.status !== 0) {
      process.exit(syntax.status || 1);
    }
    validateConfig(file, await loadConfig(file));
  }
}

main().catch((error) => {
  fail(error && error.stack ? error.stack : String(error));
});
