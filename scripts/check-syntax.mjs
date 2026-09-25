#!/usr/bin/env node
// Parse every JavaScript file this repo ships, DERIVED from the tree rather than hand-listed.
//
// `check:js` used to be four `node --check` calls written out by hand:
//
//     node --check server.mjs && node --check public/app.js
//       && node --check electron/main.cjs && node --check electron/preload.cjs
//
// which had already drifted. `ecosystem.config.cjs` (the PM2 process definition) and
// `scripts/check-devops.cjs` (the version-drift gate the same `npm run check` invokes) were both
// absent, so a syntax error in either shipped green — and in check-devops.cjs's case it would have
// taken the gate that is supposed to catch it down with it. The same hand-listing bug that
// gn_cli.py's CLI_COMMANDS fixed by deriving, fixed the same way.
//
// Failures are collected, not thrown on first hit: one run should name every broken file.

import { execFileSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

// Vendored, generated, or build output — none of it is ours to parse.
const SKIP_DIRS = new Set([
  "node_modules", ".git", "runtime", "release", "dist", "build",
  ".venv-build", ".claude", "__pycache__",
]);
const EXTENSIONS = [".js", ".mjs", ".cjs"];
const ROOT = process.cwd();

function collect(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) collect(full, out);
    } else if (entry.isFile() && EXTENSIONS.some((ext) => entry.name.endsWith(ext))) {
      out.push(full);
    }
  }
  return out;
}

const files = collect(ROOT).sort();
if (files.length === 0) {
  // An empty sweep is a broken gate, not a clean repo: it would pass forever.
  console.error("check-syntax: found no JavaScript files to check — the walk is broken.");
  process.exit(1);
}

const failures = [];
for (const file of files) {
  try {
    execFileSync(process.execPath, ["--check", file], { stdio: ["ignore", "ignore", "pipe"] });
  } catch (error) {
    const detail = (error.stderr ? error.stderr.toString() : String(error)).trim();
    failures.push(`${relative(ROOT, file).split(sep).join("/")}\n${detail}`);
  }
}

if (failures.length) {
  console.error(`check-syntax: ${failures.length} of ${files.length} JavaScript file(s) failed to parse:\n`);
  for (const failure of failures) console.error(`${failure}\n`);
  process.exit(1);
}

console.log(`check-syntax: ${files.length} JavaScript file(s) parse clean.`);
