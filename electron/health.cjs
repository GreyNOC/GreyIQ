'use strict';

const http = require('node:http');

// A free loopback port can be claimed by another process between allocation and
// backend launch. The child receives a random launch ID through its environment;
// the probe never sends it to the server that may have claimed the port.
function probeHealth(host, port, expectedLaunchId, timeoutMs = 2000) {
  if (typeof expectedLaunchId !== 'string' || !expectedLaunchId) return Promise.resolve(false);
  return new Promise((resolve) => {
    const req = http.get({ host, port, path: '/api/health', timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200 || !String(res.headers['content-type'] || '').includes('application/json')) {
        res.resume();
        resolve(false);
        return;
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        body += chunk;
        if (body.length > 1024) {
          req.destroy();
          resolve(false);
        }
      });
      res.on('end', () => {
        try {
          const health = JSON.parse(body);
          resolve(health?.status === 'ok' && health.launchId === expectedLaunchId);
        } catch (_) {
          resolve(false);
        }
      });
      res.on('error', () => resolve(false));
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

module.exports = { probeHealth };
