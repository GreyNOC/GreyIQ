'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const path = require('node:path');
const test = require('node:test');
const {
  ollamaAssets,
  findLinuxOllama,
  selectOllamaBinary,
  extractArchive,
} = require('./ollama-runtime.cjs');

test('selects official Linux archives for each supported architecture', () => {
  const amd64 = ollamaAssets('linux', 'x64');
  const arm64 = ollamaAssets('linux', 'arm64');
  assert.match(amd64.base, /ollama-linux-amd64\.tar\.zst$/);
  assert.match(amd64.rocm, /ollama-linux-amd64-rocm\.tar\.zst$/);
  assert.match(arm64.base, /ollama-linux-arm64\.tar\.zst$/);
  assert.equal(arm64.rocm, null);
  assert.equal(ollamaAssets('linux', 'riscv64'), null);
});

test('packaged Linux honors GREYIQ_OLLAMA_PATH without provisioning', async () => {
  let provisions = 0;
  const selected = await selectOllamaBinary({
    platform: 'linux',
    packaged: true,
    env: { GREYIQ_OLLAMA_PATH: '/opt/ollama/bin/ollama', PATH: '' },
    ensureBase: async () => { provisions += 1; return '/downloaded/ollama'; },
  });
  assert.deepEqual(selected, { binary: '/opt/ollama/bin/ollama', external: true });
  assert.equal(provisions, 0);
});

test('packaged Linux uses an executable on PATH before provisioning', async () => {
  const command = path.join('/usr/bin', 'ollama');
  const fakeFs = {
    statSync(candidate) {
      if (candidate !== command) throw new Error('missing');
      return { isFile: () => true };
    },
    accessSync(candidate) { assert.equal(candidate, command); },
  };
  let provisions = 0;
  const selected = await selectOllamaBinary({
    platform: 'linux',
    packaged: true,
    env: { PATH: ['/missing', '/usr/bin'].join(path.delimiter) },
    fileSystem: fakeFs,
    ensureBase: async () => { provisions += 1; return '/downloaded/ollama'; },
  });
  assert.deepEqual(selected, { binary: command, external: true });
  assert.equal(provisions, 0);
  assert.equal(findLinuxOllama({ PATH: '/missing' }, fakeFs), null);
});

test('packaged Linux provisions only when no system binary is available', async () => {
  let provisions = 0;
  const selected = await selectOllamaBinary({
    platform: 'linux',
    packaged: true,
    env: { PATH: '' },
    ensureBase: async () => { provisions += 1; return '/downloaded/ollama'; },
  });
  assert.deepEqual(selected, { binary: '/downloaded/ollama', external: false });
  assert.equal(provisions, 1);
});

test('Linux tar/zstd failures explain the dependency and retry action', async () => {
  let args;
  const spawnProcess = (command, commandArgs) => {
    assert.equal(command, 'tar');
    args = commandArgs;
    const child = new EventEmitter();
    child.stderr = new EventEmitter();
    queueMicrotask(() => {
      child.stderr.emit('data', Buffer.from('tar: zstd: Cannot exec: No such file or directory'));
      child.emit('exit', 2);
    });
    return child;
  };
  await assert.rejects(
    extractArchive('/tmp/ollama.tar.zst', '/tmp/ollama', { platform: 'linux', spawnProcess }),
    /Install tar and zstd \(on Debian: sudo apt install tar zstd\), then retry the download/,
  );
  assert.deepEqual(args, ['--zstd', '-xf', '/tmp/ollama.tar.zst', '-C', '/tmp/ollama']);
});

test('missing tar reports an actionable Linux extraction error', async () => {
  const spawnProcess = () => {
    const child = new EventEmitter();
    child.stderr = new EventEmitter();
    queueMicrotask(() => child.emit('error', new Error('spawn tar ENOENT')));
    return child;
  };
  await assert.rejects(
    extractArchive('/tmp/ollama.tar.zst', '/tmp/ollama', { platform: 'linux', spawnProcess }),
    /could not start tar: spawn tar ENOENT.*sudo apt install tar zstd/,
  );
});
