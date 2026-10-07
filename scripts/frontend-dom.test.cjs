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

test('verified replay joins only the old default training selection once', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '..', 'public', 'app.js'), 'utf8');
  const constants = source.slice(source.indexOf('const TRAINING_SOURCE_REVISION'),
    source.indexOf('const DEFAULT_TRAIN_SETTINGS'));
  const helpers = source.slice(source.indexOf('function normalizeSelectedTrainingSources'),
    source.indexOf('function trainingSourceName'));
  const { migrateSelectedTrainingSources, revision } = vm.runInNewContext(
    `${constants}\n${helpers}\n({ migrateSelectedTrainingSources, revision: TRAINING_SOURCE_REVISION })`
  );
  const oldDefault = ['src_starter_knowledge', 'src_bug_bounty',
    'src_personal_choices', 'src_preferred_examples'];
  assert.deepEqual(Array.from(migrateSelectedTrainingSources(oldDefault, 0)),
    [...oldDefault, 'src_verified_replay']);
  assert.deepEqual(Array.from(migrateSelectedTrainingSources(['src_bug_bounty'], 0)),
    ['src_bug_bounty'], 'custom selections must stay unchanged');
  assert.deepEqual(Array.from(migrateSelectedTrainingSources(oldDefault, revision)), oldDefault,
    'removing verified replay after migration must be respected');
});

test('structured-scope row retains its HackerOne asset id only for the original identifier', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '..', 'public', 'app.js'), 'utf8');
  const start = source.indexOf('function ckScopeRowEl(entry, onOperatorChange) {');
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
      if (url === '/api/platforms/credentials') return { ok: true, platforms: { intigriti: { has_token: true } } };
      if (url === '/api/platforms/programs') return { ok: true, programs: [
        { id: 'program-uuid', handle: 'example', name: 'Example', status: 'open' },
      ] };
      if (url === '/api/platforms/preview' && JSON.parse(options.body).program_id === 'missing') {
        return { ok: false, error: 'Program unavailable' };
      }
      if (url === '/api/platforms/preview') return {
        ok: true, platform: 'intigriti', program_id: 'program-uuid', handle: 'example',
        program_name: 'Example', structured_scope: [{ identifier: 'https://example.test', eligible_for_submission: true }],
        source_url: 'https://api.intigriti.com/external/researcher/v1/programs/program-uuid', fetched_at: '2026-10-06T00:00:00Z',
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
  assert.equal(platform.children.some((option) => option.value === 'bugcrowd'), false,
    'the browse flow must not offer the Bugcrowd organization API to researchers');
  platform.value = 'intigriti';
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
    { platform: 'intigriti', query: '', limit: 100 });
  assert.deepEqual(JSON.parse(calls.filter((call) => call.url === '/api/platforms/preview').at(-1).options.body),
    { platform: 'intigriti', program_id: 'program-uuid' });
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
  assert.equal(payload.platform, 'intigriti');
  assert.equal(payload.intake_source.provider_id, 'program-uuid');
  assert.equal(payload.structured_scope[0].identifier, 'https://example.test');
  for (const flag of ['enabled', 'active', 'live', 'deep']) assert.equal(payload[flag], false, flag);
  assert.equal(launched, 0, 'an imported program must not auto-launch after Save');
});

test('lead cards show hypothesis controls as text and hide them after confirmation', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '..', 'public', 'app.js'), 'utf8');
  const celStart = source.indexOf('function cel(tag, className, text) {');
  const celEnd = source.indexOf('// Client-side mirror', celStart);
  const renderStart = source.indexOf('function ckRenderLeadQueue(panel, res) {');
  const renderEnd = source.indexOf('async function ckGenerateEngagementReport', renderStart);
  assert.ok(celStart >= 0 && celEnd > celStart && renderStart >= 0 && renderEnd > renderStart);

  function element(tag) {
    return {
      tag, className: '', children: [], ownText: '',
      set textContent(value) { this.ownText = String(value); this.children = []; },
      get textContent() { return this.ownText + this.children.map((child) => child.textContent).join(''); },
      set innerHTML(_) { throw new Error('lead data must never be interpreted as HTML'); },
      append(...children) { this.children.push(...children); },
      addEventListener() {},
    };
  }
  const document = {
    createElement: element,
    createTextNode: (value) => ({ tag: '#text', textContent: String(value) }),
  };
  const render = vm.runInNewContext(
    `${source.slice(celStart, celEnd)}\n${source.slice(renderStart, renderEnd)}\nckRenderLeadQueue`,
    { document, ckDownloadText() {} },
  );
  const marker = '<img src=x onerror=alert(1)>';
  const planned = {
    id: 'L1', title: 'Potential issue', status: 'candidate', proof_obligation: 'Capture a response',
    predicted_positive_signal: `Different response ${marker}`,
    negative_control: `Same request against owned control ${marker}`,
    falsifier_stop_condition: `Both responses match ${marker}`,
  };
  const panel = element('div');
  render(panel, { lead_count: 2, report: { hunts: [{ leads: [
    planned, { ...planned, id: 'L2', status: 'confirmed' },
  ] }] } });

  const cards = panel.children.filter((child) => child.className === 'ck-lead');
  assert.equal(cards.length, 2);
  for (const label of ['Expected signal: ', 'Negative control: ', 'Stop if: ']) {
    assert.ok(cards[0].textContent.includes(label), `${label} should be visible`);
    assert.ok(!cards[1].textContent.includes(label), `${label} should not be shown on confirmed leads`);
  }
  assert.equal(cards[0].textContent.match(/<img/g).length, 3);
  const tags = [];
  function visit(node) { tags.push(node.tag); for (const child of node.children || []) visit(child); }
  visit(panel);
  assert.ok(!tags.includes('img'), 'HTML-looking lead values remain text nodes');
});

function programIntakeHarness(apiResponse) {
  const source = fs.readFileSync(path.resolve(__dirname, '..', 'public', 'app.js'), 'utf8');
  const slice = (start, end) => {
    const a = source.indexOf(start);
    const b = source.indexOf(end, a);
    assert.ok(a >= 0 && b > a, `${start} should be found before ${end}`);
    return source.slice(a, b);
  };
  function find(root, match) {
    if (match(root)) return root;
    for (const child of root.children || []) {
      const result = find(child, match);
      if (result) return result;
    }
    return null;
  }
  function element(tag, className = '', content = '') {
    return {
      tag, className: className || '', ownText: String(content ?? ''), children: [],
      parent: null, value: '', checked: false, disabled: false, hidden: false, listeners: {},
      classList: { add() {}, remove() {} },
      get textContent() { return this.ownText + this.children.map((child) => child.textContent).join(''); },
      set textContent(value) { this.ownText = String(value); this.children = []; },
      append(...children) {
        for (const child of children) { child.parent = this; this.children.push(child); }
        if (this.tag === 'select' && this.children.length === children.length && children[0]) {
          this.value = children[0].value;
        }
      },
      replaceChildren(...children) { this.children = []; this.append(...children); },
      querySelector(selector) { return find(this, (child) => selector[0] === '.'
        ? child.className.split(' ').includes(selector.slice(1)) : child.tag === selector); },
      querySelectorAll(selector) {
        const rows = [];
        const visit = (node) => {
          for (const child of node.children || []) {
            if (child.className.split(' ').includes(selector.slice(1))) rows.push(child);
            visit(child);
          }
        };
        visit(this);
        return rows;
      },
      remove() { if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this); },
      addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); },
      async dispatch(name) {
        const event = { preventDefault() {}, key: '' };
        for (const fn of this.listeners[name] || []) await fn(event);
      },
      click() { return this.dispatch('click'); },
      focus() {}, scrollIntoView() {}, setAttribute() {},
    };
  }
  function field(label, _type, value = '') {
    const wrap = element('label');
    const input = element('input'); input.value = value || '';
    wrap.append(element('span', '', label), input);
    return { wrap, input };
  }
  const calls = [];
  let launched = 0;
  const context = {
    cel: element, ckField: field, ckTextareaField: field,
    ckToggle: (_label, checked) => {
      const wrap = element('label'); const input = element('input'); input.checked = checked;
      wrap.append(input); return { wrap, input };
    },
    ckTargetImport: () => element('div'), ckRepositoryUrlsFromScope: () => [],
    ckParseRepositoryUrls: () => [],
    CK_PLATFORMS: [{ id: 'hackerone', name: 'HackerOne' }, { id: 'yeswehack', name: 'YesWeHack' }],
    ckProgEdit: null, ckFlow: { view: 'wizard', prefill: null },
    ckState: { h1: { has_token: true } }, ck: { activeProgram: { value: '' }, views: {} },
    ckFetchCreds: async () => {}, ckSetView() {}, ckRenderProgram() {},
    ckProgReset() { context.ckFlow = { view: 'list', prefill: null }; },
    ckRefreshProgramsEverywhere: async () => {},
    ckApplyActiveProgram() { launched += 1; }, ckStatus() {}, ckFocusLaunchStep() {},
    document: { querySelector() { return null; } }, setTimeout,
    apiFetch: async (url, options = {}) => {
      calls.push({ url, options });
      if (url === '/api/operator/programs') return { ok: true, program: { id: 'saved' } };
      if (url === '/api/hackerone/import-scope' || url === '/api/yeswehack/import-scope') {
        return typeof apiResponse === 'function' ? apiResponse(url) : apiResponse;
      }
      throw new Error(`Unexpected API call: ${url}`);
    },
  };
  const code = [
    slice('function ckScopeRowEl(entry', '// Mirrors the backend\'s cap'),
    slice('const CK_MAX_SCOPE_ENTRIES = 500;', 'function ckProgramWithCandidateHosts'),
    slice('function ckProgramSetupForm(prefill) {', '\nlet ckProgramRenderGen'),
    slice('function ckWizardIdentifyH1(nav) {', '// The YesWeHack path'),
    slice('function ckWizardIdentifyYWH(nav) {', 'function ckWizardIdentifyPlatformApi'),
    slice('function ckYwhPrefill(res, slug) {', 'function ckWizardIdentifyManual'),
    '({ setupForm: ckProgramSetupForm, h1Wizard: ckWizardIdentifyH1, ywhWizard: ckWizardIdentifyYWH, mergeFetched: ckMergeFetchedScopeRows })',
  ].join('\n');
  const actions = vm.runInNewContext(code, context);
  return { ...actions, context, calls, element, find, launched: () => launched };
}

test('legacy HackerOne and YesWeHack wizard imports carry bounded provenance and save paused', async () => {
  for (const [platform, endpoint, response] of [
    ['hackerone', '/api/hackerone/import-scope', { ok: true, handle: 'acme', program_name: 'Acme',
      structured_scope: [{ identifier: 'app.acme.test', eligible_for_submission: true }],
      warnings: Array(12).fill('review '.repeat(50)) }],
    ['yeswehack', '/api/yeswehack/import-scope', { ok: true, slug: 'acme', program_name: 'Acme',
      structured_scope: [{ identifier: 'app.acme.test', eligible_for_submission: true }],
      warnings: Array(12).fill('review '.repeat(50)) }],
  ]) {
    const h = programIntakeHarness(response);
    const nav = h.element('div');
    const box = platform === 'hackerone' ? h.h1Wizard(nav) : h.ywhWizard(nav);
    const input = h.find(box, (node) => node.tag === 'label' && node.children[0]?.textContent.includes('handle'))?.querySelector('input')
      || h.find(box, (node) => node.tag === 'label' && node.children[0]?.textContent.includes('Program slug'))?.querySelector('input');
    assert.ok(input, `${platform} identifier input exists`);
    input.value = 'acme';
    await h.find(box, (node) => node.tag === 'button' && node.textContent === 'Fetch scope').click();
    assert.equal(h.calls[0].url, endpoint);
    await h.find(nav, (node) => node.tag === 'button' && node.textContent === 'Continue →').click();
    const source = h.context.ckFlow.prefill.intake_source;
    assert.equal(source.platform, platform);
    assert.equal(source.provider_id, 'acme');
    assert.equal(source.scope_complete, false);
    assert.match(source.source_url, /^https:\/\/api\./);
    assert.ok(source.fetched_at);
    assert.ok(source.warnings.length <= 8 && source.warnings.every((warning) => warning.length <= 240));
    const form = h.setupForm(h.context.ckFlow.prefill);
    await form.dispatch('submit');
    const save = h.calls.find((call) => call.url === '/api/operator/programs');
    assert.ok(save, `${platform} form saves`);
    const payload = JSON.parse(save.options.body);
    assert.equal(payload.intake_source.provider_id, 'acme');
    for (const flag of ['enabled', 'active', 'live', 'deep']) assert.equal(payload[flag], false, flag);
    assert.equal(h.launched(), 0, 'an imported program must not auto-launch');
  }
});

test('legacy import fallback records a failed fetch and still saves paused', async () => {
  for (const platform of ['hackerone', 'yeswehack']) {
    const h = programIntakeHarness({ ok: false, error: 'Program unavailable' });
    const nav = h.element('div');
    const box = platform === 'hackerone' ? h.h1Wizard(nav) : h.ywhWizard(nav);
    const input = h.find(box, (node) => node.tag === 'label' && node.children[0]?.textContent.includes('handle'))?.querySelector('input')
      || h.find(box, (node) => node.tag === 'label' && node.children[0]?.textContent.includes('Program slug'))?.querySelector('input');
    input.value = 'acme';
    await h.find(box, (node) => node.tag === 'button' && node.textContent === 'Fetch scope').click();
    await h.find(nav, (node) => node.tag === 'button' && node.textContent === 'Continue anyway →').click();
    const source = h.context.ckFlow.prefill.intake_source;
    assert.equal(source.status, 'fetch_failed');
    assert.equal(source.scope_complete, false);
    assert.equal(source.fetched_at, '');
    assert.equal(source.source_url, '');
    const form = h.setupForm(h.context.ckFlow.prefill);
    await form.dispatch('submit');
    const payload = JSON.parse(h.calls.find((call) => call.url === '/api/operator/programs').options.body);
    for (const flag of ['enabled', 'active', 'live', 'deep']) assert.equal(payload[flag], false, flag);
  }
});

test('re-fetch retains saved exclusions at the cap and never requests their removal', async () => {
  const existing = [
    ...Array.from({ length: 499 }, (_, i) => ({ identifier: `old${i}.example.test`, eligible_for_submission: true })),
    { identifier: 'blocked.example.test', eligible_for_submission: false, instruction: 'Manual exclusion' },
  ];
  const fetched = [
    ...Array.from({ length: 499 }, (_, i) => ({ identifier: `new${i}.example.test`, eligible_for_submission: true })),
    { identifier: 'blocked.example.test', eligible_for_submission: true },
  ];
  const h = programIntakeHarness({ ok: true, handle: 'acme', program_name: 'Acme', structured_scope: fetched });
  h.context.ckProgEdit = { id: 'saved', name: 'Acme', platform: 'hackerone', platform_handle: 'acme',
    structured_scope: existing, enabled: true, active: true, live: true, deep: true };
  const form = h.setupForm(null);
  await h.find(form, (node) => node.tag === 'button' && node.textContent === 'Fetch scope from HackerOne').click();
  const table = h.find(form, (node) => node.className === 'ck-scope-table');
  const rows = table.ckCollect();
  assert.equal(rows.length, 500);
  assert.deepEqual(rows.find((row) => row.identifier === 'blocked.example.test')?.eligible_for_submission, false);
  assert.equal(rows.find((row) => row.identifier === 'blocked.example.test')?.instruction, 'Manual exclusion');
  await form.dispatch('submit');
  const payload = JSON.parse(h.calls.find((call) => call.url === '/api/operator/programs').options.body);
  assert.equal(payload.enabled, false, 're-fetch pauses an active program');
  assert.equal(payload.remove_out_of_scope_hosts, undefined, 'automatic re-fetch has no removal intent');
  assert.equal(payload.intake_source.platform, 'hackerone');
});

test('explicit excluded-row changes request removal; an over-cap exclusion fetch blocks Save', async () => {
  for (const action of ['remove', 'toggle']) {
    const h = programIntakeHarness({ ok: true, handle: 'acme', structured_scope: [] });
    h.context.ckProgEdit = { id: 'saved', name: 'Acme', platform: 'hackerone',
      structured_scope: [{ identifier: 'https://blocked.example.test', eligible_for_submission: false }], enabled: false };
    const form = h.setupForm(null);
    const table = h.find(form, (node) => node.className === 'ck-scope-table');
    const row = table.querySelector('.ck-scope-body').children[0];
    if (action === 'remove') await h.find(row, (node) => node.tag === 'button' && node.title === 'Remove row').click();
    else {
      const checkbox = h.find(row, (node) => node.tag === 'input' && node.type === 'checkbox');
      checkbox.checked = true;
      await checkbox.dispatch('change');
    }
    await form.dispatch('submit');
    const payload = JSON.parse(h.calls.find((call) => call.url === '/api/operator/programs').options.body);
    assert.deepEqual(payload.remove_out_of_scope_hosts, ['https://blocked.example.test']);
  }

  const existing = Array.from({ length: 500 }, (_, i) => ({
    identifier: `blocked${i}.example.test`, eligible_for_submission: false,
  }));
  const h = programIntakeHarness({ ok: true, handle: 'acme', structured_scope: [
    { identifier: 'new-blocked.example.test', eligible_for_submission: false },
  ] });
  h.context.ckProgEdit = { id: 'saved', name: 'Acme', platform: 'hackerone', platform_handle: 'acme',
    structured_scope: existing, enabled: true };
  const form = h.setupForm(null);
  await h.find(form, (node) => node.tag === 'button' && node.textContent === 'Fetch scope from HackerOne').click();
  const table = h.find(form, (node) => node.className === 'ck-scope-table');
  assert.equal(table.ckCollect().length, 500, 'blocked merge leaves the original rows intact');
  await form.dispatch('submit');
  assert.equal(h.calls.some((call) => call.url === '/api/operator/programs'), false, 'Save is blocked');
});

test('Operator scope editor sends literal free text and permits an explicit clear', async () => {
  const source = fs.readFileSync(path.resolve(__dirname, '..', 'public', 'app.js'), 'utf8');
  const start = source.indexOf('function ckProgramForm() {');
  const end = source.indexOf('\nfunction ckToggle(', start);
  assert.ok(start >= 0 && end > start, 'Operator program form should be found');

  function element(tag, textContent = '') {
    return {
      tag, textContent, children: [], value: '', checked: false, listeners: {},
      classList: { add() {}, remove() {} },
      append(...children) { this.children.push(...children); },
      addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); },
      async dispatch(name) {
        for (const fn of this.listeners[name] || []) await fn({ preventDefault() {}, submitter: null });
      },
    };
  }
  function find(root, match) {
    if (match(root)) return root;
    for (const child of root.children || []) {
      const found = find(child, match);
      if (found) return found;
    }
    return null;
  }
  function field(label, tag, value = '') {
    const wrap = element('label');
    const input = element(tag); input.value = value;
    wrap.append(element('span', label), input);
    return { wrap, input };
  }
  const payloads = [];
  const typedScope = '  https://app.example.test/only?mode=1\n  operator note  ';
  const editing = { id: 'saved', name: 'Acme', scope_text: 'app.example.test', active: true,
    repository_urls: [], seed_targets: [], platform: 'manual', enabled: true };
  const context = {
    ckOpEdit: editing,
    cel: (_tag, _className, text = '') => element(_tag, text),
    ckField: (label, _type, value) => field(label, 'input', value),
    ckTextareaField: (label) => field(label, 'textarea'),
    ckToggle: (_label, checked) => {
      const wrap = element('label'); const input = element('input'); input.checked = checked;
      wrap.append(input); return { wrap, input };
    },
    ckTargetImport: () => element('div'),
    ckParseRepositoryUrls: () => [],
    ckRefreshProgramsEverywhere: async () => {},
    ckRenderOperator: () => {},
    apiFetch: async (_url, options) => {
      payloads.push(JSON.parse(options.body)); return { ok: true };
    },
  };
  const makeForm = vm.runInNewContext(`${source.slice(start, end)}\nckProgramForm`, context);
  const form = makeForm();
  const scope = find(form, (node) => node.tag === 'label'
    && node.children.some((child) => child.textContent === 'Scope (hosts/wildcards — the active gate)'));
  assert.equal(scope.children[1].tag, 'textarea');
  assert.equal(scope.children[1].value, editing.scope_text, 'the saved scope renders without normalization');
  scope.children[1].value = typedScope;
  await form.dispatch('submit');
  assert.equal(payloads[0].scope_text, typedScope, 'save preserves leading/trailing whitespace and newline');

  context.ckOpEdit = { ...editing, scope_text: typedScope };
  const unchangedForm = makeForm();
  const unchangedScope = find(unchangedForm, (node) => node.tag === 'label'
    && node.children.some((child) => child.textContent === 'Scope (hosts/wildcards — the active gate)'));
  assert.equal(unchangedScope.children[1].value, typedScope);
  await unchangedForm.dispatch('submit');
  assert.equal(payloads[1].scope_text, undefined, 'schedule-only edit must not mark derived text manual');

  context.ckOpEdit = { ...editing, scope_text: typedScope };
  const clearForm = makeForm();
  const clearScope = find(clearForm, (node) => node.tag === 'label'
    && node.children.some((child) => child.textContent === 'Scope (hosts/wildcards — the active gate)'));
  clearScope.children[1].value = '';
  await clearForm.dispatch('submit');
  assert.equal(payloads[2].scope_text, '', 'clearing an existing scope is sent explicitly');
});
