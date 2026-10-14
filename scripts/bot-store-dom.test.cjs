'use strict';

// Behaviour of the app's half of the shared bot store (public/app.js). The store itself is pinned
// by backend/test_gn_bots.py, and the routes by backend/test_bot_store_api.py; what is left is what
// only the browser does — merging the registry's record with this viewer's own colour and fit,
// re-keying everything when a handover changes a bot's id, and telling the truth about a field that
// can be unset. Each of these failed once while this was being built:
//
//   * `Number(null)` is 0 and `Number.isFinite(0)` is true, so a bot whose temperature is the
//     provider's default read back as a temperature of ZERO — the editor showed 0.00 for it, and
//     the next keystroke anywhere in the panel would have saved that as the operator's choice.
//   * the selection was read after the store's answer had already replaced it, so a browser that
//     had Forge live came back on tinygpt.
//
// Same slice-and-run-in-a-vm pattern as frontend-dom.test.cjs: no browser, no backend.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const SOURCE = fs.readFileSync(path.resolve(__dirname, '..', 'public', 'app.js'), 'utf8');

function slice(fromMarker, toMarker) {
  const start = SOURCE.indexOf(fromMarker);
  const end = SOURCE.indexOf(toMarker, start);
  assert.ok(start >= 0 && end > start, `${fromMarker} .. ${toMarker} is gone from app.js`);
  return SOURCE.slice(start, end);
}

const STORE_CLIENT = slice('// ---- the shared bot store', 'function activeChat()');
const EDITOR = slice('function updateBotFromEditor(event)', 'els.botEditor.addEventListener');

// Everything the slices reach for that lives elsewhere in app.js. Stubs, so a test failure is
// about the bot store rather than about the rest of the app.
function harness(overrides = {}) {
  const calls = [];
  const context = {
    state: {
      bots: [], activeBotId: '', botPresentation: {}, botFit: {}, chats: {}, memories: {},
      botsMigration: null, pendingBotMigration: null, pendingBotSelection: '',
    },
    service: { available: true },
    COLORS: ['#ff6633', '#8ec7d8', '#4bb377'],
    DEFAULT_SAMPLING_TEMPERATURE: 0.32,
    DEFAULT_BOT_ID: 'tinygpt',
    normalizeWeights: (weights) => (Array.isArray(weights) ? weights.slice() : []),
    serializableBot: (bot) => ({ id: bot.id, name: bot.name, temperature: bot.temperature,
      persona: bot.persona, style: bot.style, corpus: bot.corpus || [] }),
    refreshServiceStatus: async () => context.service.available,
    apiFetch: async (route, options) => {
      calls.push({ route, body: options && options.body ? JSON.parse(options.body) : null });
      return (overrides.responses && overrides.responses[route]) || { ok: true, bots: [] };
    },
    render: () => {},
    saveState: () => {},
    queueCoreSync: () => {},
    trainBot: () => {},
    window: { setTimeout: () => 0, clearTimeout: () => {} },
    calls,
    ...overrides.context,
  };
  const exported = '({ botStore, botView, applyBotStore, refreshBots, botWrite, selectBot, '
    + 'migrateBotsOnce, activeBot, storedTemperature, samplingTemperature, queueBotSave, '
    + 'presentationFor, colorForBot })';
  return { context, calls, api: vm.runInNewContext(`${STORE_CLIENT}\n${exported}`, context) };
}

// --- a temperature that is not set is not a temperature of zero --------------------------------
test('an unset temperature reads as unset, not as zero', () => {
  const { api } = harness();
  for (const value of [null, undefined, '']) {
    assert.equal(api.storedTemperature({ temperature: value }), null,
      `${String(value)} must read as "the provider's default", not as 0`);
  }
  assert.equal(api.storedTemperature({ temperature: 0 }), 0, 'an explicit zero is a real value');
  assert.equal(api.storedTemperature({ temperature: '0.65' }), 0.65);
  assert.equal(api.storedTemperature({ temperature: 'warm' }), null);
  // The browser's own paths still need a number, and it is the one the API model declares.
  assert.equal(api.samplingTemperature({ temperature: null }), 0.32);
  assert.equal(api.samplingTemperature({ temperature: 0 }), 0);
});

test('typing a name does not turn the provider default into a number the operator never chose', () => {
  const sent = [];
  const node = (value = '') => ({ value, disabled: false, id: '' });
  const els = {
    botName: node('Recon'), botPersona: node('terse'), botStyle: node('direct'),
    botTemperature: node('0.3'), botProvider: node('tinygpt'), botModel: node(''),
  };
  els.botProvider.disabled = true;
  els.botModel.disabled = true;
  const context = {
    els,
    activeBot: () => context.bot,
    bot: { id: 'recon', temperature: null },
    storedTemperature: (bot) => (bot.temperature === null || bot.temperature === undefined
      || bot.temperature === '' ? null : Number(bot.temperature)),
    queueBotSave: (fields) => sent.push(fields),
    trainBot: () => {}, queueCoreSync: () => {}, render: () => {},
  };
  const run = vm.runInNewContext(`${EDITOR}\n({ updateBotFromEditor })`, context);

  run.updateBotFromEditor({ target: { id: 'botName' } });
  assert.ok(!('temperature' in sent[0]), 'a keystroke in the name field must not write a temperature');

  // Moving the slider is the operator choosing one, so it goes.
  run.updateBotFromEditor({ target: { id: 'botTemperature' } });
  assert.equal(sent[1].temperature, 0.3);

  // And a bot that ALREADY has one is left alone too, because the slider snaps to its own step:
  // a 0.46 set from the CLI became 0.45 the first time anything else in the panel was typed.
  context.bot = { id: 'recon', temperature: 0.46 };
  els.botTemperature.value = '0.45';
  run.updateBotFromEditor({ target: { id: 'botPersona' } });
  assert.ok(!('temperature' in sent[2]), 'typing elsewhere must not re-quantize a stored value');
});

// --- the record is the store's; the colour and the fit are this browser's ----------------------
test('a bot view is the store record plus this viewer own two fields', () => {
  const { api, context } = harness();
  context.state.botFit = { recon: { weights: [0.5], trainedAt: 1234 } };
  context.state.botPresentation = { recon: { color: '#abcdef' } };
  const view = api.botView({ id: 'recon', name: 'Recon', provider: 'local',
    lessons: ['cite the endpoint'] }, 0);
  assert.equal(view.provider, 'local');
  // `corpus` is the store's `lessons` under the name the browser's ranker already reads.
  assert.deepEqual(view.corpus, ['cite the endpoint']);
  assert.equal(view.color, '#abcdef');
  assert.deepEqual(view.weights, [0.5]);
  assert.equal(view.trainedAt, 1234);
});

test('a bot the CLI made gets a colour here and keeps it', () => {
  const { api, context } = harness();
  const first = api.colorForBot('shellmade', 1);
  assert.equal(first, '#8ec7d8');
  context.state.bots = [];
  assert.equal(api.colorForBot('shellmade', 2), first, 'the colour must not move between renders');
});

test('the live bot is the store answer, never a local guess', () => {
  const { api, context } = harness();
  context.state.activeBotId = 'whatever-this-browser-thought';
  api.applyBotStore({ bots: [{ id: 'tinygpt' }, { id: 'shellmade' }], active_id: 'shellmade' });
  assert.equal(context.state.activeBotId, 'shellmade');
  assert.equal(api.botStore.loaded, true);
});

test('an answer with no bots keeps the roster rather than blanking it', () => {
  // gn_bots.load synthesizes the built-ins even for a broken store, so an empty list is not a
  // store listing — and an operator looking at the panel should not watch it empty itself.
  const { api, context } = harness();
  context.state.bots = [{ id: 'recon' }];
  api.applyBotStore({ bots: [] });
  assert.deepEqual(context.state.bots.map((bot) => bot.id), ['recon']);
  assert.match(api.botStore.lastError, /no bots/);
});

test('the store own complaint is carried, not swallowed', () => {
  const { api } = harness();
  api.applyBotStore({ bots: [{ id: 'tinygpt' }], active_id: 'tinygpt',
    error: 'bots.json: ghost: provider \'ollama\' is not one of ...' });
  assert.match(api.botStore.error, /ghost/);
});

test('a bot with no store record claims neither readiness nor where it runs', () => {
  // The cached roster shown while the service is down carries neither fact, and those two are the
  // ones this panel most has to be right about.
  const READINESS = slice('function renderBotReadiness(bot)', 'const activeChatPolls');
  const node = { textContent: '', classList: { add() { node.added = true; }, toggle() {} } };
  const run = vm.runInNewContext(`${READINESS}
({ renderBotReadiness })`,
    { els: { botReadiness: node } });
  run.renderBotReadiness({ id: 'astra', name: 'Astra' });
  assert.match(node.textContent, /Start the local GreyIQ service/);
  assert.ok(!/Stays on this machine/.test(node.textContent));
  assert.ok(!/undefined/.test(node.textContent));
  // And a real record still reads normally.
  run.renderBotReadiness({ id: 'recon', readiness: 'ready', key_state: 'not needed' });
  assert.match(node.textContent, /^Ready\. Stays on this machine\./);
});

test('with no store the editor takes no edits it could not keep', () => {
  const FREEZE = slice('function freezeBotEditor()', 'function setSelectValue(');
  const control = () => ({ disabled: false, title: '' });
  const els = { botName: control(), botPersona: control(), botStyle: control(),
    botTemperature: control(), botProvider: control(), botModel: control(),
    newBotButton: control(), cloneBotButton: control(), deleteBotButton: control() };
  const { api } = harness();
  api.botStore.loaded = false;
  const run = vm.runInNewContext(`${FREEZE}
({ freezeBotEditor })`,
    { els, botStore: api.botStore });
  run.freezeBotEditor();
  for (const [name, node] of Object.entries(els)) {
    assert.equal(node.disabled, true, `${name} must not accept an edit that cannot be saved`);
    assert.match(node.title, /local GreyIQ service/);
  }
});

// --- writes go to the store, or they do not happen ---------------------------------------------
test('a write with no service refuses in a sentence instead of keeping a second copy', async () => {
  const { api, context, calls } = harness();
  context.service.available = false;
  context.refreshServiceStatus = async () => false;
  const result = await api.botWrite('/api/bots', { name: 'Ghost' }, { verb: 'make a bot' });
  assert.equal(result, null);
  assert.equal(calls.length, 0, 'nothing may be posted');
  assert.match(api.botStore.lastError, /local GreyIQ service/);
});

test('a store that keeps failing is not re-asked on every status poll', async () => {
  // The poll runs every couple of seconds and a store that will not load is still a service that
  // is UP, so without a backoff this re-asks forever and fills the operator's own log with it.
  const { api, context, calls } = harness();
  context.apiFetch = async (route) => { calls.push({ route }); throw new Error('503 registry'); };
  assert.equal(await api.refreshBots({ render: false }), false);
  assert.equal(calls.length, 1);
  assert.equal(await api.refreshBots({ render: false, auto: true }), false);
  assert.equal(calls.length, 1, 'an automatic retry must wait');
  // An explicit refresh (the operator did something) is never held back.
  await api.refreshBots({ render: false });
  assert.equal(calls.length, 2);
});

test('selecting a bot posts to the one writer of the setting', async () => {
  const { api, context, calls } = harness({
    responses: { '/api/bots/active': { bots: [{ id: 'shellmade' }], active_id: 'shellmade' } },
  });
  context.state.activeBotId = 'tinygpt';
  await api.selectBot('shellmade');
  assert.deepEqual(calls.map((call) => call.route), ['/api/bots/active']);
  assert.deepEqual(calls[0].body, { bot: 'shellmade' });
  assert.equal(context.state.activeBotId, 'shellmade');
});

test('a refused selection snaps back to the bot that is actually live', async () => {
  const { api, context } = harness();
  context.apiFetch = async () => { throw new Error('422 not in the store'); };
  context.state.activeBotId = 'tinygpt';
  await api.selectBot('ghost');
  assert.equal(context.state.activeBotId, 'tinygpt');
});

test('a pending edit goes to the bot it was typed into, not the one clicked next', async () => {
  // The debounce used to read state.activeBotId when it FIRED, so typing a persona and clicking
  // another bot inside the window wrote your words onto whichever bot you clicked.
  const timers = [];
  const { api, context, calls } = harness({
    context: { window: { setTimeout: (fn) => { timers.push(fn); return timers.length; },
      clearTimeout: () => {} } },
    responses: { '/api/bots/active': { bots: [{ id: 'other' }], active_id: 'other' },
      '/api/bots/update': { bots: [{ id: 'recon' }], active_id: 'recon' } },
  });
  context.state.activeBotId = 'recon';
  api.queueBotSave({ persona: 'typed into recon' });
  await api.selectBot('other');
  const update = calls.find((call) => call.route === '/api/bots/update');
  assert.ok(update, 'the edit must be sent before the switch, not dropped');
  assert.equal(update.body.bot, 'recon');
  assert.equal(update.body.fields.persona, 'typed into recon');
  // And the switch still happened.
  assert.ok(calls.some((call) => call.route === '/api/bots/active'));
});

// --- the handover ------------------------------------------------------------------------------
function migrationHarness() {
  const migrated = [
    { from: 'astra', id: 'astra', status: 'created' },
    { from: 'Forge', id: 'forge', status: 'created' },
    { from: 'bot-6f1c0b7e-6b0a-4d6c-9a1a-2f2b6c7d8e9f', id: 'bot-6f1c0b7e-6b0a-4d6c-9a1a-2f2b',
      status: 'created' },
  ];
  const harnessed = harness({
    responses: {
      '/api/bots/migrate': {
        bots: [{ id: 'astra' }, { id: 'forge' }, { id: 'bot-6f1c0b7e-6b0a-4d6c-9a1a-2f2b' }],
        active_id: 'tinygpt', configured: 'tinygpt', created: 3, migrated,
      },
      '/api/bots/active': { bots: [{ id: 'forge' }], active_id: 'forge' },
    },
  });
  harnessed.api.botStore.loaded = true;
  Object.assign(harnessed.context.state, {
    pendingBotMigration: [{ id: 'astra' }, { id: 'Forge' },
      { id: 'bot-6f1c0b7e-6b0a-4d6c-9a1a-2f2b6c7d8e9f' }],
    pendingBotSelection: 'Forge',
    chats: { Forge: [{ text: 'forge remembers this' }] },
    memories: { Forge: [{ text: 'always name the file' }] },
    botPresentation: { Forge: { color: '#4bb377' } },
    botFit: { astra: { weights: [0.2], trainedAt: 9 } },
  });
  return harnessed;
}

test('a handover re-keys everything this browser keeps per bot', async () => {
  const { api, context } = migrationHarness();
  await api.migrateBotsOnce();
  const { state } = context;
  assert.deepEqual(Object.keys(state.chats), ['forge'], 'chat history must follow the new id');
  assert.equal(state.chats.forge[0].text, 'forge remembers this');
  assert.deepEqual(Object.keys(state.memories), ['forge']);
  assert.equal(state.botPresentation.forge.color, '#4bb377', 'the colour follows too');
  assert.deepEqual(state.botFit.astra.weights, [0.2], 'an id that did not change is left alone');
  assert.equal(state.botsMigration.created, 3);
  assert.deepEqual(state.botsMigration.refused, []);
});

test('the bot this browser had selected stays selected', async () => {
  const { api, calls } = migrationHarness();
  await api.migrateBotsOnce();
  const routes = calls.map((call) => call.route);
  assert.ok(routes.includes('/api/bots/active'), 'the selection must come across');
  assert.deepEqual(calls[routes.indexOf('/api/bots/active')].body, { bot: 'forge' });
});

test('a selection already made in the shell is not overruled by a browser arriving late', async () => {
  const { api, context, calls } = migrationHarness();
  context.state.pendingBotSelection = 'Forge';
  // The operator has already run `gn bot use shellmade`.
  const response = { bots: [{ id: 'forge' }], active_id: 'shellmade', configured: 'shellmade',
    created: 3, migrated: [{ from: 'Forge', id: 'forge', status: 'created' }] };
  context.apiFetch = async (route, options) => {
    calls.push({ route, body: options && options.body ? JSON.parse(options.body) : null });
    return route === '/api/bots/migrate' ? response : { bots: [], active_id: 'shellmade' };
  };
  await api.migrateBotsOnce();
  assert.ok(!calls.some((call) => call.route === '/api/bots/active'),
    'the shell chose a live bot; a handover must not take it away');
});

test('a bot the store already had is not re-selected by the handover', async () => {
  const { api, context, calls } = migrationHarness();
  context.state.pendingBotSelection = 'astra';
  context.apiFetch = async (route, options) => {
    calls.push({ route, body: options && options.body ? JSON.parse(options.body) : null });
    return route === '/api/bots/migrate'
      ? { bots: [{ id: 'astra' }], active_id: 'tinygpt', configured: 'tinygpt', created: 0,
          migrated: [{ from: 'astra', id: 'astra', status: 'exists' }] }
      : { bots: [], active_id: 'tinygpt' };
  };
  await api.migrateBotsOnce();
  assert.ok(!calls.some((call) => call.route === '/api/bots/active'),
    'an id that was already in the store is somebody else bot; it must not become live');
});

test('a failed handover stays pending instead of being lost', async () => {
  const { api, context } = migrationHarness();
  context.apiFetch = async () => { throw new Error('service went away'); };
  await api.migrateBotsOnce();
  assert.equal(context.state.pendingBotMigration.length, 3, 'it must be retried on the next load');
  assert.equal(context.state.botsMigration, null, 'and no marker may claim it happened');
});

test('a handover runs once', async () => {
  const { api, context, calls } = migrationHarness();
  await api.migrateBotsOnce();
  const after = calls.length;
  await api.migrateBotsOnce();
  assert.equal(calls.length, after, 'the second call must do nothing at all');
  assert.equal(context.state.pendingBotMigration, null);
});

test('a bot the store refused is named rather than swallowed', async () => {
  const { api, context } = migrationHarness();
  context.apiFetch = async () => ({
    bots: [{ id: 'astra' }], active_id: 'tinygpt', configured: 'tinygpt', created: 1,
    migrated: [{ from: 'astra', id: 'astra', status: 'created' },
      { from: '!!!', id: '', status: 'refused', note: "'!!!' cannot be a bot id" }],
  });
  await api.migrateBotsOnce();
  assert.equal(context.state.botsMigration.refused.length, 1);
  assert.match(api.botStore.lastError, /could not be added to the store/);
});
