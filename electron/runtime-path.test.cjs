'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { resolveRuntimeDir, migrateLegacyRuntime } = require('./runtime-path.cjs');

const options = {
  platform: 'linux',
  packaged: true,
  userDataDir: '/home/operator/.config/GreyIQ',
  projectRoot: '/home/operator/checkout/GreyIQ',
  homeDir: '/home/operator',
};

test('packaged Linux desktop shares the frozen CLI XDG runtime', () => {
  assert.equal(resolveRuntimeDir({ ...options, env: { XDG_DATA_HOME: '/mnt/operator-data' } }),
    '/mnt/operator-data/greyiq/runtime');
  assert.equal(resolveRuntimeDir({ ...options, env: {} }),
    '/home/operator/.local/share/greyiq/runtime');
  assert.equal(resolveRuntimeDir({ ...options, env: { XDG_DATA_HOME: 'relative-data' } }),
    '/home/operator/.local/share/greyiq/runtime');
});

test('explicit runtime override wins and non-Linux/default behavior is preserved', () => {
  const override = '/srv/greyiq/operator-runtime';
  assert.equal(resolveRuntimeDir({ ...options, env: { GREYIQ_RUNTIME_DIR: override } }), override);
  assert.equal(resolveRuntimeDir({ ...options, packaged: false, env: {} }),
    '/home/operator/checkout/GreyIQ/runtime');
  assert.equal(resolveRuntimeDir({ ...options, platform: 'win32', env: {} }),
    path.join(options.userDataDir, 'runtime'));
});

test('legacy runtime is copied once without deleting or overwriting data', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'greyiq-runtime-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const legacyDir = path.join(root, 'config', 'GreyIQ', 'runtime');
  const targetDir = path.join(root, 'data', 'greyiq', 'runtime');
  fs.mkdirSync(legacyDir, { recursive: true });
  fs.writeFileSync(path.join(legacyDir, 'portfolio.json'), '{"programs":{"older":{}}}');

  assert.equal(migrateLegacyRuntime({ legacyDir, targetDir }), true);
  assert.equal(fs.readFileSync(path.join(targetDir, 'portfolio.json'), 'utf8'), '{"programs":{"older":{}}}');
  assert.equal(fs.readFileSync(path.join(legacyDir, 'portfolio.json'), 'utf8'), '{"programs":{"older":{}}}');

  fs.writeFileSync(path.join(targetDir, 'portfolio.json'), '{"programs":{"newer":{}}}');
  assert.equal(migrateLegacyRuntime({ legacyDir, targetDir }), false);
  assert.equal(fs.readFileSync(path.join(targetDir, 'portfolio.json'), 'utf8'), '{"programs":{"newer":{}}}');
});

test('migration failure explains recovery and keeps previous data intact', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'greyiq-runtime-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const legacyDir = path.join(root, 'config', 'GreyIQ', 'runtime');
  const blockedParent = path.join(root, 'blocked-parent');
  const targetDir = path.join(blockedParent, 'runtime');
  fs.mkdirSync(legacyDir, { recursive: true });
  fs.writeFileSync(path.join(legacyDir, 'portfolio.json'), '{"programs":{"older":{}}}');
  fs.writeFileSync(blockedParent, 'not a directory');

  assert.throws(() => migrateLegacyRuntime({ legacyDir, targetDir }),
    (err) => err.message.includes('Could not copy previous GreyIQ data')
      && err.message.includes(legacyDir));
  assert.equal(fs.readFileSync(path.join(legacyDir, 'portfolio.json'), 'utf8'), '{"programs":{"older":{}}}');
});
