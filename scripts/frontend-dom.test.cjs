'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

test('renderer bootstrap selectors exist in the shipped HTML', () => {
  const root = path.resolve(__dirname, '..');
  const html = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');
  const source = fs.readFileSync(path.join(root, 'public', 'app.js'), 'utf8');
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]));
  const maps = [
    source.slice(source.indexOf('const els = {'), source.indexOf('class AccelerationBackend')),
    source.slice(source.indexOf('const ck = {'), source.indexOf('let ckOpPoll')),
  ];
  for (const map of maps) {
    const selectors = [...map.matchAll(/document\.querySelector\("#([^"]+)"\)/g)].map((match) => match[1]);
    assert.ok(selectors.length > 50, 'bootstrap selector map should be found');
    for (const id of selectors) assert.ok(ids.has(id), `#${id} is missing from public/index.html`);
  }
});
