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
    renderBots: () => {},
    els: { botEditor: null },
    document: { activeElement: null },
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

test('the panel shows the store own sentence for what making a bot live means', () => {
  // gn_bots.what_it_does is "one sentence, both doors" -- it exists because the CLI and the studio
  // each had their own copy and one of them was false. Clicking a bot in the roster IS `gn bot use`,
  // so the app must print that sentence rather than compose an equivalent.
  const READINESS = slice('function renderBotReadiness(bot)', 'const activeChatPolls');
  const node = { textContent: '', classList: { add() {}, toggle() {} } };
  const state = { activeBotId: 'recon' };
  const run = vm.runInNewContext(`${READINESS}
({ renderBotReadiness })`,
    { els: { botReadiness: node }, state, botStore: { loaded: true },
      BLOCKING_READINESS: ['needs a key', 'needs a model'] });
  const sentence = 'it answers chat and plans the hunt';
  run.renderBotReadiness({ id: 'recon', readiness: 'ready', key_state: 'not needed',
    what_it_does: sentence });
  assert.match(node.textContent, new RegExp(`^Live: ${sentence}\.`));
  run.renderBotReadiness({ id: 'other', readiness: 'ready', key_state: 'not needed',
    what_it_does: sentence });
  assert.match(node.textContent, new RegExp(`^When live: ${sentence}\.`));
  // An inert clone gets the store's wording too, not a sentence written in the browser.
  const inert = 'it answers here from the offline pack; it is an inert clone, so it never runs';
  run.renderBotReadiness({ id: 'stranger', inert: true, readiness: 'inert', what_it_does: inert });
  assert.ok(node.textContent.includes(inert));
  assert.ok(!/cannot become a brain/.test(node.textContent),
    'that explanation belongs on the disabled control, not restated here');
});

test('a posture is not reported as a failure', () => {
  // gn_bots.readiness returns `off`, `edits only` and `inert` for bots that work exactly as
  // designed. Calling those "Not ready" told the operator a working bot was broken, and said it
  // on the same line as the sentence that had just described what the bot does.
  const READINESS = slice('function renderBotReadiness(bot)', 'const activeChatPolls');
  const node = { textContent: '', classList: { add() {}, toggle(_c, on) { node.warn = on; } } };
  const run = vm.runInNewContext(`${READINESS}
({ renderBotReadiness })`,
    { els: { botReadiness: node }, state: { activeBotId: '' }, botStore: { loaded: true },
      BLOCKING_READINESS: ['needs a key', 'needs a model'] });

  for (const posture of ['off', 'edits only', 'inert']) {
    run.renderBotReadiness({ id: 'x', readiness: posture, what_it_does: 'something the store says',
      provider: posture === 'off' ? 'off' : 'offline' });
    assert.ok(!/Not ready/.test(node.textContent), `"${posture}" is a posture, not a failure`);
    assert.equal(node.warn, false, `"${posture}" must not be flagged as a problem`);
  }
  // The two that really do block still say so, and still colour the line.
  for (const blocked of ['needs a key', 'needs a model']) {
    run.renderBotReadiness({ id: 'x', readiness: blocked, provider: 'anthropic',
      what_it_does: 'it answers' });
    assert.match(node.textContent, new RegExp(`Not ready: ${blocked}\.`));
    assert.equal(node.warn, true);
  }
  // And `off` is not reassured about the network: nothing is asked of it.
  run.renderBotReadiness({ id: 'x', readiness: 'off', provider: 'off', what_it_does: 'nothing' });
  assert.ok(!/Stays on this machine/.test(node.textContent));
});

test('a bot with no store record claims neither readiness nor where it runs', () => {
  // A DEFAULT_BOTS-shaped record: the browser that has never reached the service. (Its sibling
  // above covers the harder case -- a cache from a session that DID reach it.)
  const READINESS = slice('function renderBotReadiness(bot)', 'const activeChatPolls');
  const node = { textContent: '', classList: { add() { node.added = true; }, toggle() {} } };
  const store = { loaded: true };
  const run = vm.runInNewContext(`${READINESS}
({ renderBotReadiness })`,
    { els: { botReadiness: node }, state: { activeBotId: '' }, botStore: store,
      BLOCKING_READINESS: ['needs a key', 'needs a model'] });
  run.renderBotReadiness({ id: 'astra', name: 'Astra' });
  assert.match(node.textContent, /Start the local GreyIQ service/);
  assert.ok(!/Stays on this machine/.test(node.textContent));
  assert.ok(!/undefined/.test(node.textContent));
  // And a real record still reads normally.
  run.renderBotReadiness({ id: 'recon', readiness: 'ready', key_state: 'not needed' });
  assert.match(node.textContent, /^Ready\. Stays on this machine\./);
});

function availabilityHarness() {
  const AVAIL = slice('function applyEditorAvailability(bot)', 'function setSelectValue(');
  const control = () => ({ disabled: false, title: '' });
  const els = { botName: control(), botPersona: control(), botStyle: control(),
    botTemperature: control(), botProvider: control(), botModel: control(),
    newBotButton: control(), cloneBotButton: control(), deleteBotButton: control() };
  const { api } = harness();
  const state = { bots: [{ id: 'a' }, { id: 'b' }] };
  const run = vm.runInNewContext(
    `${AVAIL}
({ applyEditorAvailability })`,
    { els, state, botStore: api.botStore,
      FROZEN_EDITOR_TITLE: 'The bot store is served by the local GreyIQ service — start it to edit bots.' });
  return { els, api, run };
}

test('with no store the editor takes no edits it could not keep', () => {
  const { els, api, run } = availabilityHarness();
  api.botStore.loaded = false;
  run.applyEditorAvailability({ id: 'recon', provider: 'local' });
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
  api.botStore.loaded = true;
  context.state.activeBotId = 'tinygpt';
  await api.selectBot('shellmade');
  assert.deepEqual(calls.map((call) => call.route), ['/api/bots/active']);
  assert.deepEqual(calls[0].body, { bot: 'shellmade' });
  assert.equal(context.state.activeBotId, 'shellmade');
});

test('clicking the roster before the store has answered posts nothing', async () => {
  // The rows stay clickable while the editor is frozen, and the id under them is this browser's
  // cache -- before the handover, a pre-registry id the store has never heard of. Clicking one
  // posted it, painted a 422, and bumped the write counter, which discarded the boot read.
  const { api, context, calls } = harness();
  api.botStore.loaded = false;
  context.state.activeBotId = 'tinygpt';
  await api.selectBot('astra');
  assert.equal(calls.length, 0, 'nothing may be posted before the store has answered');
  assert.equal(context.state.activeBotId, 'tinygpt');
  assert.match(api.botStore.lastError, /local GreyIQ service/);
});

test('a refused selection snaps back to the bot that is actually live', async () => {
  const { api, context } = harness();
  context.apiFetch = async () => { throw new Error('422 not in the store'); };
  api.botStore.loaded = true;
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
  api.botStore.loaded = true;
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

test('the editor comes back when the store does', () => {
  // This only ever SET disabled, and three controls were enabled elsewhere. One render with the
  // service down -- opening the app before the backend is up -- left Name/Persona/Style/Variation
  // and both buttons permanently dead, with the tooltip explaining why cleared on the next render.
  const { els, api, run } = availabilityHarness();
  const runnable = { id: 'recon', provider: 'local' };

  api.botStore.loaded = false;
  run.applyEditorAvailability(runnable);
  assert.equal(els.botName.disabled, true);

  api.botStore.loaded = true;
  run.applyEditorAvailability(runnable);
  for (const [name, node] of Object.entries(els)) {
    assert.equal(node.disabled, false, `${name} must be editable once the store answers`);
    assert.equal(node.title, '', `${name} must not keep the "service is down" tooltip`);
  }
});

test('a control disabled for its own reason says which reason, and recovers', () => {
  // Every control is assigned on every call from (bot, store) alone, so the panel cannot depend
  // on what ran before it.
  const { els, api, run } = availabilityHarness();
  api.botStore.loaded = true;

  run.applyEditorAvailability({ id: 'tinygpt', provider: 'tinygpt', builtin: true });
  assert.equal(els.botModel.disabled, true);
  assert.match(els.botModel.title, /takes no model name/);
  assert.equal(els.deleteBotButton.disabled, true);
  assert.match(els.deleteBotButton.title, /ships with GreyIQ/);
  assert.equal(els.botName.disabled, false);

  run.applyEditorAvailability({ id: 'stranger', provider: 'off', inert: true });
  assert.equal(els.botProvider.disabled, true);
  assert.match(els.botProvider.title, /inert by design/);

  // ...and an ordinary bot clears all of it, with no residue from the two above.
  run.applyEditorAvailability({ id: 'recon', provider: 'anthropic' });
  for (const [name, node] of Object.entries(els)) {
    assert.equal(node.disabled, false, `${name} kept a rule that no longer applies`);
    assert.equal(node.title, '', `${name} kept a stale reason`);
  }
});

test('a cached roster claims nothing about readiness or the network', () => {
  // The gate was `!bot.readiness`, but saveState persisted the backend-computed fields, so a cache
  // written by an earlier session carried one -- and the panel said "Ready. Key configured. Stays
  // on this machine." with no backend running at all.
  const READINESS = slice('function renderBotReadiness(bot)', 'const activeChatPolls');
  const SUMMARY = slice('function botRowSummary(bot)', 'function renderBotStoreNote()');
  const node = { textContent: '', classList: { add() {}, toggle() {} } };
  const { api } = harness();
  api.botStore.loaded = false;
  const context = { els: { botReadiness: node }, state: { activeBotId: 'recon' },
    botStore: api.botStore, BLOCKING_READINESS: ['needs a key', 'needs a model'] };
  const run = vm.runInNewContext(`${READINESS}
${SUMMARY}
({ renderBotReadiness, botRowSummary })`,
    context);

  // Exactly what localStorage would have handed back before saveState stopped writing these.
  const stale = { id: 'recon', readiness: 'ready', key_state: 'configured', off_machine: true,
    endpoint: 'https://api.anthropic.com', describe: 'anthropic - claude-opus-5',
    what_it_does: 'it answers chat and plans the hunt' };
  run.renderBotReadiness(stale);
  assert.match(node.textContent, /Start the local GreyIQ service/);
  for (const claim of ['Ready.', 'Key configured', 'Stays on this machine', 'off this machine']) {
    assert.ok(!node.textContent.includes(claim), `claimed "${claim}" with no store behind it`);
  }
  // The roster row keeps what the record IS and drops what only a live check could know.
  assert.equal(run.botRowSummary({ ...stale, readiness: 'needs a key' }), 'anthropic - claude-opus-5');

  api.botStore.loaded = true;
  assert.equal(run.botRowSummary({ ...stale, readiness: 'needs a key' }),
    'anthropic - claude-opus-5 [needs a key] ->net');
});

test('the fields only the backend can compute are never persisted', () => {
  const SAVE = slice('function saveState() {', '// Per-session token');
  let saved = null;
  const state = { theme: 'dark', chats: {}, bots: [
    { id: 'recon', name: 'Recon', readiness: 'ready', key_state: 'configured',
      off_machine: true, endpoint: 'https://api.anthropic.com', describe: 'anthropic - x' },
  ] };
  vm.runInNewContext(`${SAVE}
saveState();`, {
    state, STORE_KEY: 'test',
    localStorage: { setItem(_key, value) { saved = JSON.parse(value); } },
  });
  for (const field of ['readiness', 'key_state', 'off_machine', 'endpoint']) {
    assert.ok(!(field in saved.bots[0]), `${field} must not reach localStorage`);
  }
  assert.equal(saved.bots[0].describe, 'anthropic - x', 'what the record IS still caches');
});

test('an edit the store refuses leaves the screen as well as the disk', () => {
  // updateBotFromEditor applies the typing to the cache so the panel stays responsive. On a
  // refusal that optimistic value used to stay -- shown in the roster, the chat byline and the
  // editor, and persisted -- while the error under the roster said the write had failed.
  const { api, context } = harness();
  api.applyBotStore({ bots: [{ id: 'recon', name: 'Recon' }], active_id: 'recon' });
  assert.equal(context.state.bots[0].name, 'Recon');
  Object.assign(context.state.bots[0], { name: 'Burned' });   // what the editor does as you type
  context.apiFetch = async () => { throw new Error("422: 'recon' is not a bot in the store."); };
  return api.botWrite('/api/bots/update', { bot: 'recon', fields: { name: 'Burned' } })
    .then(() => {
      assert.equal(context.state.bots[0].name, 'Recon', 'the refused name must not survive');
      assert.match(api.botStore.lastError, /not a bot in the store/);
    });
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
      // Every route answers with the whole store (_bots_response), not just the bot it touched.
      '/api/bots/active': {
        bots: [{ id: 'astra' }, { id: 'forge' }, { id: 'bot-6f1c0b7e-6b0a-4d6c-9a1a-2f2b' }],
        active_id: 'forge', configured: 'forge',
      },
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

test('a handover carries data onto an id the store already holds, never over it', async () => {
  // The `delete store[from]` used to be unconditional, so whenever the destination key already
  // existed the source's data was thrown away. For colours the destination ALWAYS exists, because
  // the listing that arrived moments earlier assigns every id a palette colour.
  const { api, context } = migrationHarness();
  Object.assign(context.state, {
    chats: { Forge: [{ text: 'from the browser' }], forge: [{ text: 'already here' }] },
    memories: { Forge: [{ text: 'browser memory' }], forge: [{ text: 'shell memory' }] },
    botPresentation: { Forge: { color: '#4bb377' }, forge: { color: '#8ec7d8', auto: true } },
    botFit: { Forge: { weights: [0.9], trainedAt: 7 }, forge: { weights: [], trainedAt: 0 } },
  });
  await api.migrateBotsOnce();
  const { state } = context;
  // Joined rather than deepEqual'd: `.map()` on an array built inside the vm returns a vm-realm
  // array, which assert's deep comparison will not match against one from this realm.
  assert.equal(state.chats.forge.map((m) => m.text).join('|'), 'from the browser|already here',
    'both sides are the operator own turns; both survive');
  assert.equal(state.memories.forge.map((m) => m.text).join('|'), 'browser memory|shell memory');
  assert.equal(state.botPresentation.forge.color, '#4bb377',
    'a colour the operator picked beats one assigned from the palette');
  assert.equal(state.botFit.forge.trainedAt, 7, 'the side that was actually fitted wins');
  assert.ok(!('Forge' in state.chats), 'and nothing is left stranded under the old id');
});

test('a colour the operator chose is never overwritten by a handover', async () => {
  const { api, context } = migrationHarness();
  context.state.botPresentation = {
    Forge: { color: '#4bb377' },
    forge: { color: '#d9a441', auto: false },   // chosen in this browser, for the shell's bot
  };
  await api.migrateBotsOnce();
  assert.equal(context.state.botPresentation.forge.color, '#d9a441');
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

test('a failed handover keeps the selection it was going to restore', async () => {
  // pendingBotSelection was cleared before the POST and only the bot LIST was restored on failure,
  // so a handover that timed out lost the bot the operator had live -- and the retry could not
  // re-derive it, because applyBotStore had already overwritten state.activeBotId.
  const { api, context } = migrationHarness();
  context.apiFetch = async () => { throw new Error('service went away'); };
  await api.migrateBotsOnce();
  assert.equal(context.state.pendingBotSelection, 'Forge');
  assert.equal(context.state.pendingBotMigration.length, 3);
});

test('an answer that is not a store listing does not mark the handover done', async () => {
  // A 200 that applyBotStore would refuse two lines later used to still write the marker, which
  // permanently records a handover that never happened.
  for (const bad of [{ ok: true }, { bots: [], migrated: [] }, { bots: [{ id: 'astra' }] }]) {
    const { api, context } = migrationHarness();
    context.apiFetch = async () => bad;
    await api.migrateBotsOnce();
    assert.equal(context.state.botsMigration, null, `marked done on ${JSON.stringify(bad)}`);
    assert.equal(context.state.pendingBotMigration.length, 3, 'and it must be retried');
  }
});

test('data for a bot the shell deleted is cleared on the next full read, not before it', async () => {
  const { api, context } = harness({
    responses: { '/api/bots': { bots: [{ id: 'tinygpt' }], active_id: 'tinygpt' } },
  });
  Object.assign(context.state, {
    chats: { tinygpt: [{ text: 'keep' }], gone: [{ text: 'orphan' }] },
    botPresentation: { gone: { color: '#fff' } },
    // A handover is still pending, so this read must NOT prune: on the first load of a
    // pre-registry browser the listing is the built-ins and this browser's own bots are exactly
    // the ids missing from it.
    pendingBotMigration: [{ id: 'gone' }],
  });
  await api.refreshBots({ render: false });
  assert.ok('gone' in context.state.chats, 'pruned data the handover was about to re-key');

  context.state.pendingBotMigration = null;
  await api.refreshBots({ render: false });
  assert.ok(!('gone' in context.state.chats), 'a bot the store no longer has leaves nothing behind');
  assert.ok(!('gone' in context.state.botPresentation));
  assert.ok('tinygpt' in context.state.chats, 'and a bot that is still there keeps its history');
});

test('a store the backend could not fully read deletes nothing', async () => {
  // gn_bots.load answers an unparseable bots.json with the six built-ins, and a file holding an
  // entry it refuses with that entry left out -- and never overwrites either, so the operator's
  // bots come back once the file is fixed. Pruning against such a listing turned a recoverable
  // file problem into permanent, silent loss of their chat history.
  for (const degraded of [
    { label: 'unparseable', listing: { bots: [{ id: 'tinygpt' }], active_id: 'tinygpt',
        readable: false, error: 'bots.json is not valid JSON (Expecting value)' } },
    { label: 'one entry refused', listing: { bots: [{ id: 'tinygpt' }], active_id: 'tinygpt',
        readable: true, error: "bots.json: ghost: provider 'ollama' is not one of ..." } },
  ]) {
    const { api, context } = harness({ responses: { '/api/bots': degraded.listing } });
    Object.assign(context.state, { chats: { recon: [{ text: 'keep me' }] },
      memories: { recon: [{ text: 'and me' }] }, botPresentation: { recon: { color: '#fff' } } });
    await api.refreshBots({ render: false });
    assert.ok('recon' in context.state.chats, `${degraded.label}: chat history was deleted`);
    assert.ok('recon' in context.state.memories, `${degraded.label}: memories were deleted`);
    assert.equal(api.botStore.healthy, false);
  }
});

test('a healthy listing is what decides a bot is gone', async () => {
  const healthy = (ids) => ({ bots: ids.map((id) => ({ id })), active_id: ids[0],
    readable: true, error: '' });
  const { api, context } = harness({ responses: { '/api/bots': healthy(['tinygpt', 'recon']) } });
  Object.assign(context.state, { chats: { recon: [{ text: 'keep me' }], stray: [{ text: 'orphan' }] } });

  await api.refreshBots({ render: false });
  assert.ok('recon' in context.state.chats, 'a bot still in the store keeps its history');
  assert.ok(!('stray' in context.state.chats), 'an id the store vouches it does not have goes');

  context.apiFetch = async () => healthy(['tinygpt']);
  await api.refreshBots({ render: false });
  assert.ok(!('recon' in context.state.chats), 'a bot the shell removed takes its data with it');
});

test('a revalidation read that started before a click cannot undo it', async () => {
  // Nothing stopped a write starting while a read was in flight, and applyBotStore applied
  // whichever landed last -- so the roster highlight and the "Live:" line snapped back to the
  // previous bot for up to 30s while the store said otherwise.
  let releaseRead;
  const readLanded = new Promise((resolve) => { releaseRead = resolve; });
  const { api, context } = harness();
  context.apiFetch = async (route, options) => {
    if (route === '/api/bots') {
      await readLanded;
      return { bots: [{ id: 'tinygpt' }, { id: 'recon' }], active_id: 'tinygpt', readable: true };
    }
    return { bots: [{ id: 'tinygpt' }, { id: 'recon' }], active_id: 'recon', readable: true,
      ...(options ? {} : {}) };
  };
  // The store has answered once already, which is the only state a click is accepted in.
  api.applyBotStore({ bots: [{ id: 'tinygpt' }, { id: 'recon' }], active_id: 'tinygpt', readable: true });
  const read = api.refreshBots({ render: false, auto: true });   // starts, does not resolve yet
  await api.selectBot('recon');                                   // the operator clicks
  assert.equal(context.state.activeBotId, 'recon');
  releaseRead();
  await read;
  assert.equal(context.state.activeBotId, 'recon',
    'the older read must not put the previous bot back');
});

test('a failed handover survives a reload', () => {
  // The pending list was DERIVED at load from the saved bots and never persisted. After the first
  // successful read state.bots is the store's records and saveState writes those -- so a failed
  // handover followed by a reload derived an empty pending list from a cache that no longer held
  // the browser's own bots. One service hiccup during the one-shot handover, and they were gone.
  const SAVE = slice('function saveState() {', '// Per-session token');
  const LOAD = slice('function loadState() {', 'function migrateDefaultBots(');
  let saved = null;
  const legacy = [{ id: 'astra', name: 'Astra', corpus: [] }, { id: 'Forge', name: 'Forge', corpus: [] }];
  // The state a browser is in right after a failed handover: the cache is the store's roster
  // (every record names a provider), and the browser's own bots exist only in the pending list.
  const state = { theme: 'dark', chats: {},
    bots: [{ id: 'tinygpt', provider: 'tinygpt' }, { id: 'local', provider: 'local' }],
    activeBotId: 'tinygpt', botsMigration: null,
    pendingBotMigration: legacy, pendingBotSelection: 'Forge' };
  vm.runInNewContext(`${SAVE}
saveState();`, { state, STORE_KEY: 'test',
    localStorage: { setItem(_k, v) { saved = JSON.parse(v); } } });
  assert.equal(saved.pendingBotMigration.length, 2, 'the pending list must be written');

  const reloaded = vm.runInNewContext(`${LOAD}
loadState()`, {
    STORE_KEY: 'test', localStorage: { getItem: () => JSON.stringify(saved) },
    DEFAULT_BOTS: [{ id: 'astra', name: 'Astra' }], BOT_DEFAULT_REVISION: 2,
    TRAINING_SOURCE_REVISION: 1, DEFAULT_SELECTED_TRAINING_SOURCES: [],
    DEFAULT_TRAIN_SETTINGS: {}, structuredClone: (x) => JSON.parse(JSON.stringify(x)),
    migrateDefaultBots: (bots) => bots, normalizeWeights: (w) => w || [],
    migrateSelectedTrainingSources: () => [], harvestedPresentation: () => ({}),
    harvestedFit: () => ({}),
  });
  assert.equal(reloaded.pendingBotMigration.length, 2, 'the browser own bots must still be pending');
  assert.equal(reloaded.pendingBotMigration[1].id, 'Forge');
  assert.equal(reloaded.pendingBotSelection, 'Forge', 'and so must the selection');
});

test('a capped handover keeps the unread tail pending and records no marker', async () => {
  // The route reads MIGRATE_LIMIT entries per call. The cap row used to say "run it again", which
  // the operator had no way to do: the marker landed and the tail was gone for good.
  const pending = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
  const { api, context, calls } = harness({
    responses: {
      '/api/bots/migrate': { bots: [{ id: 'a' }, { id: 'b' }], active_id: 'tinygpt',
        configured: 'tinygpt', created: 2, read: 2,
        migrated: [{ from: 'a', id: 'a', status: 'created' }, { from: 'b', id: 'b', status: 'created' },
          { from: '', id: '', status: 'deferred', note: '1 more bot(s) were not read' }] },
    },
  });
  api.botStore.loaded = true;
  Object.assign(context.state, { pendingBotMigration: pending, pendingBotSelection: 'c' });
  await api.migrateBotsOnce();
  assert.deepEqual(context.state.pendingBotMigration.map((b) => b.id).join(','), 'c',
    'the unread tail must stay pending');
  assert.equal(context.state.pendingBotSelection, 'c', 'a selection in the tail stays with it');
  assert.equal(context.state.botsMigration, null, 'no marker until the last of them lands');
  // The next read sends the rest, and only then is the handover recorded.
  context.apiFetch = async (route, options) => {
    calls.push({ route, body: options && options.body ? JSON.parse(options.body) : null });
    return route === '/api/bots/migrate'
      ? { bots: [{ id: 'a' }, { id: 'b' }, { id: 'c' }], active_id: 'tinygpt', configured: 'tinygpt',
          created: 1, read: 1, migrated: [{ from: 'c', id: 'c', status: 'created' }] }
      : { bots: [{ id: 'a' }, { id: 'b' }, { id: 'c' }], active_id: 'c' };
  };
  await api.migrateBotsOnce();
  const second = calls.filter((c) => c.route === '/api/bots/migrate').pop();
  assert.deepEqual(second.body.bots.map((b) => b.id), ['c'], 'only the tail is sent');
  assert.equal(context.state.pendingBotMigration, null);
  assert.ok(context.state.botsMigration, 'recorded once everything has landed');
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
