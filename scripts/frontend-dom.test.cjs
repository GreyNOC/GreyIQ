'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

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

test('structured-scope row retains its HackerOne asset id only for the original identifier', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '..', 'public', 'app.js'), 'utf8');
  const start = source.indexOf('function ckScopeRowEl(entry) {');
  const end = source.indexOf('// Mirrors the backend', start);
  assert.ok(start >= 0 && end > start, 'scope row serializer should be found');
  const cel = () => ({
    children: [],
    append(...nodes) { this.children.push(...nodes); },
    addEventListener() {},
  });
  const makeRow = vm.runInNewContext(`${source.slice(start, end)}\nckScopeRowEl`, { cel });
  const row = makeRow({
    identifier: 'https://app.example.test', id: 'asset-123',
    eligible_for_submission: false,
  });
  assert.equal(row._ckGet().id, 'asset-123');
  assert.equal(row._ckGet().eligible_for_submission, false);
  row.children[0].value = 'https://other.example.test';
  assert.equal(row._ckGet().id, '', 'renaming the asset must clear stale report routing');
});

test('platform API browse, preview, and Save keep an imported program paused', async () => {
  const source = fs.readFileSync(path.resolve(__dirname, '..', 'public', 'app.js'), 'utf8');
  const formStart = source.indexOf('function ckProgramSetupForm(prefill) {');
  const formEnd = source.indexOf('\nlet ckProgramRenderGen', formStart);
  const browseStart = source.indexOf('function ckWizardIdentifyPlatformApi(nav) {');
  const browseEnd = source.indexOf('\n// Shape a YesWeHack import response', browseStart);
  assert.ok(formStart >= 0 && formEnd > formStart && browseStart >= 0 && browseEnd > browseStart);

  // The renderer is plain browser JS with no DOM package dependency. Exercise the
  // real click/submit handlers in a small DOM double, not source-text assertions.
  function element(tag, className = '', content = '') {
    const node = {
      tag, className: className || '', textContent: String(content ?? ''), children: [],
      value: '', disabled: false, hidden: false, checked: false, listeners: {},
      classList: { add() {}, remove() {} },
      append(...children) {
        this.children.push(...children);
        if (this.tag === 'select' && this.children.length === children.length && children[0]) {
          this.value = children[0].value;
        }
      },
      replaceChildren(...children) { this.children = [...children]; },
      addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); },
      querySelector(selector) { return find(this, (child) => child.tag === selector); },
      remove() {},
      focus() {},
      async dispatch(name) {
        const event = { preventDefault() {}, key: '' };
        for (const fn of this.listeners[name] || []) await fn(event);
      },
      click() { return this.dispatch('click'); },
    };
    return node;
  }
  function find(root, match) {
    for (const child of root.children || []) {
      if (match(child)) return child;
      const nested = find(child, match);
      if (nested) return nested;
    }
    return null;
  }
  function field(label, _type, value = '') {
    const wrap = element('label');
    const caption = element('span', '', label);
    const input = element('input'); input.value = value || '';
    wrap.append(caption, input);
    return { wrap, input };
  }
  const calls = [];
  let launched = 0;
  const context = {
    cel: element,
    ckField: field,
    ckTextareaField: field,
    ckToggle: (_label, checked) => { const wrap = element('label'); const input = element('input'); input.checked = checked; wrap.append(input); return { wrap, input }; },
    ckScopeTable: (rows) => { const table = element('div'); let current = rows || []; table.ckCollect = () => current; table.ckReplace = (next) => { current = next; }; return table; },
    ckTargetImport: () => element('div'),
    ckRepositoryUrlsFromScope: () => [],
    ckParseRepositoryUrls: () => [],
    ckMergeScopeRows: (left, right) => ({ rows: [...left, ...right], truncated: false }),
    CK_PLATFORMS: [
      { id: 'hackerone', name: 'HackerOne' }, { id: 'yeswehack', name: 'YesWeHack' },
      { id: 'bugcrowd', name: 'Bugcrowd' }, { id: 'intigriti', name: 'Intigriti' },
    ],
    CK_MAX_SCOPE_ENTRIES: 500,
    ckProgEdit: null,
    ckFlow: { view: 'wizard', prefill: null },
    ck: { activeProgram: { value: '' } },
    ckProgReset() { context.ckFlow = { view: 'list', prefill: null }; },
    ckRenderProgram() {},
    ckRefreshProgramsEverywhere: async () => {},
    ckApplyActiveProgram() { launched += 1; },
    ckStatus() {}, ckFocusLaunchStep() {},
    document: { querySelector() { return null; } },
    setTimeout,
    apiFetch: async (url, options = {}) => {
      calls.push({ url, options });
      if (url === '/api/platforms/credentials') return { ok: true, platforms: { bugcrowd: { has_token: true } } };
      if (url === '/api/platforms/programs') return { ok: true, programs: [
        { id: 'program-uuid', handle: 'example', name: 'Example', status: 'open' },
      ] };
      if (url === '/api/platforms/preview' && JSON.parse(options.body).program_id === 'missing') {
        return { ok: false, error: 'Program unavailable' };
      }
      if (url === '/api/platforms/preview') return {
        ok: true, platform: 'bugcrowd', program_id: 'program-uuid', handle: 'example',
        program_name: 'Example', structured_scope: [{ identifier: 'https://example.test', eligible_for_submission: true }],
        source_url: 'https://api.bugcrowd.com/programs/program-uuid', fetched_at: '2026-10-06T00:00:00Z',
        status: 'open', scope_complete: false, warnings: ['Review exclusions'],
      };
      if (url === '/api/operator/programs') return { ok: true, program: { id: 'saved-program' } };
      throw new Error(`Unexpected API call: ${url}`);
    },
  };
  const { wizard, setupForm } = vm.runInNewContext(
    `${source.slice(formStart, formEnd)}\n${source.slice(browseStart, browseEnd)}\n` +
    '({ wizard: ckWizardIdentifyPlatformApi, setupForm: ckProgramSetupForm })', context,
  );

  const nav = element('div');
  const wizardBox = wizard(nav);
  const platform = find(wizardBox, (node) => node.tag === 'select');
  platform.value = 'bugcrowd';
  await platform.dispatch('change');
  const continueButton = find(nav, (node) => node.textContent === 'Review and save →');
  assert.equal(continueButton.disabled, true);
  const programIdLabel = find(wizardBox, (node) => node.tag === 'label'
    && node.children.some((child) => child.tag === 'span' && child.textContent === 'Program ID or handle'));
  programIdLabel.querySelector('input').value = 'missing';
  await find(wizardBox, (node) => node.textContent === 'Preview selected program').click();
  assert.equal(continueButton.disabled, true, 'a failed preview cannot unlock Save');
  await find(wizardBox, (node) => node.textContent === 'Browse programs').click();
  const row = find(wizardBox, (node) => node.textContent.startsWith('Example — example'));
  assert.ok(row, 'the API result should be selectable');
  await row.click();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(continueButton.disabled, false, 'Save remains locked until preview succeeds');
  assert.deepEqual(JSON.parse(calls.find((call) => call.url === '/api/platforms/programs').options.body),
    { platform: 'bugcrowd', query: '', limit: 100 });
  assert.deepEqual(JSON.parse(calls.filter((call) => call.url === '/api/platforms/preview').at(-1).options.body),
    { platform: 'bugcrowd', program_id: 'program-uuid' });
  await continueButton.click();
  assert.equal(context.ckFlow.view, 'form');
  assert.equal(context.ckFlow.prefill.intake_source.provider_id, 'program-uuid');
  assert.equal(calls.some((call) => call.url === '/api/operator/programs'), false,
    'browsing and preview must never persist a program');

  const form = setupForm(context.ckFlow.prefill);
  await form.dispatch('submit');
  const save = calls.find((call) => call.url === '/api/operator/programs');
  assert.ok(save, 'Save should submit the reviewed program');
  const payload = JSON.parse(save.options.body);
  assert.equal(payload.name, 'Example');
  assert.equal(payload.platform, 'bugcrowd');
  assert.equal(payload.intake_source.provider_id, 'program-uuid');
  assert.equal(payload.structured_scope[0].identifier, 'https://example.test');
  for (const flag of ['enabled', 'active', 'live', 'deep']) assert.equal(payload[flag], false, flag);
  assert.equal(launched, 0, 'an imported program must not auto-launch after Save');
});
