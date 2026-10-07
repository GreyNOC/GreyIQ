'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');
const { probeHealth } = require('./health.cjs');

async function withServer(respond, check) {
  const server = http.createServer((req, res) => {
    assert.equal(req.url, '/api/health');
    respond(res);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    return await check(server.address().port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('accepts the GreyIQ health contract', async () => {
  await withServer((res) => {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end('{"status":"ok","launchId":"current-launch"}');
  }, async (port) => assert.equal(await probeHealth('127.0.0.1', port, 'current-launch'), true));
});

test('rejects missing, wrong, and unconfigured launch IDs', async () => {
  for (const [body, expectedLaunchId] of [
    ['{"status":"ok"}', 'current-launch'],
    ['{"status":"ok","launchId":"old-launch"}', 'current-launch'],
    ['{"status":"ok","launchId":"current-launch"}', undefined],
  ]) {
    // eslint-disable-next-line no-await-in-loop
    await withServer((res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(body);
    }, async (port) => assert.equal(await probeHealth('127.0.0.1', port, expectedLaunchId), false));
  }
});

test('rejects wrong status, non-JSON, and malformed health bodies', async () => {
  const cases = [
    [404, 'application/json', '{"status":"ok","launchId":"current-launch"}'],
    [200, 'text/html', '{"status":"ok","launchId":"current-launch"}'],
    [200, 'application/json', '{"status":"starting","launchId":"current-launch"}'],
    [200, 'application/json', '{bad json}'],
  ];
  for (const [status, contentType, body] of cases) {
    // eslint-disable-next-line no-await-in-loop
    await withServer((res) => {
      res.writeHead(status, { 'Content-Type': contentType });
      res.end(body);
    }, async (port) => assert.equal(await probeHealth('127.0.0.1', port, 'current-launch'), false));
  }
});

test('rejects an oversized health body', async () => {
  await withServer((res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', launchId: 'current-launch', padding: 'x'.repeat(2048) }));
  }, async (port) => assert.equal(await probeHealth('127.0.0.1', port, 'current-launch'), false));
});
