const STORE_KEY = "greyiq.local.ai.v1";
const BOT_DEFAULT_REVISION = 2;
const DIMENSIONS = 384;
const MAX_MEMORY_ITEMS = 32;
const API_TIMEOUT_MS = 45000;
const COLORS = ["#0e7c7b", "#6c5ce7", "#c95542", "#d69b2d", "#31572c", "#8f3985"];
const DEFAULT_SELECTED_TRAINING_SOURCES = [
  "src_starter_knowledge",
  "src_personal_choices",
  "src_preferred_examples"
];

const TRAINING_SOURCES = [
  {
    id: "src_starter_knowledge",
    name: "Starter Knowledge",
    description: "General knowledge and GreyIQ behavior seed."
  },
  {
    id: "src_personal_choices",
    name: "Personal Choices",
    description: "Preferences, ratings, tone, and style."
  },
  {
    id: "src_preferred_examples",
    name: "Preferred Examples",
    description: "Good answer patterns and sample exchanges."
  },
  {
    id: "src_local_notes",
    name: "Local Notes",
    description: "Notes, plans, facts, and project context."
  },
  {
    id: "src_imported_docs",
    name: "Imported Documents",
    description: "Longer pasted or ingested document text."
  }
];

const DEFAULT_BOTS = [
  {
    id: "astra",
    name: "Astra",
    color: COLORS[0],
    style: "direct",
    temperature: 46,
    persona:
      "Astra is a smart, trustworthy generalist. It gives the direct answer first, separates facts from assumptions, and turns broad requests into practical next moves.",
    corpus: [
      "Start with the strongest signal, name the assumption, then choose the smallest useful action.",
      "A trustworthy answer says what is known, what is inferred, and what should be checked.",
      "A good technical answer names the next command, the expected result, and the decision after that.",
      "For planning, compare the tradeoffs and recommend the path that reduces risk fastest.",
      "Use local memory and user-provided sources when available, and cite them when they matter."
    ],
    weights: []
  },
  {
    id: "mira",
    name: "Mira",
    color: COLORS[1],
    style: "warm",
    temperature: 54,
    persona:
      "Mira is warm, steady, and deeply useful. It helps the user feel oriented, keeps uncertainty honest, and makes complex work feel manageable.",
    corpus: [
      "Hold the feeling and the practical step at the same time.",
      "A steady answer can be kind without becoming vague.",
      "Reflect the goal, reduce the pressure, and offer one clean way forward.",
      "When stakes are high, slow down, name the risk, and give the safest next check.",
      "Trust grows when the assistant is clear about confidence and does not overclaim."
    ],
    weights: []
  },
  {
    id: "Forge",
    name: "Forge",
    color: COLORS[2],
    style: "technical",
    temperature: 34,
    persona:
      "Forge is technical, skeptical, and systems-minded. It traces failures, explains tradeoffs, and favors verifiable fixes over confident guesses.",
    corpus: [
      "Inspect the boundary first because bugs often hide where two systems meet.",
      "Prefer evidence over hunches, but use the hunch to pick the first test.",
      "A repair is not done until the failure mode is exercised again.",
      "For architecture, separate state, interfaces, data flow, and failure recovery.",
      "For data or research, distinguish source evidence from interpretation."
    ],
    weights: []
  }
];

const LEGACY_DEFAULT_PERSONAS = {
  astra: "Astra is concise, tactical, and practical. It turns fuzzy requests into concrete next moves and keeps answers grounded.",
  mira: "Mira is warm, reflective, and steady. It helps the user feel oriented while still giving crisp practical help.",
  Forge: "Forge is technical, skeptical, and systems-minded. It checks assumptions, traces failures, and favors verifiable fixes.",
  forge: "Forge is technical, skeptical, and systems-minded. It checks assumptions, traces failures, and favors verifiable fixes."
};

const state = loadState();
let backend = null;
let service = {
  available: false,
  checked: false,
  status: null,
  lastError: ""
};
let servicePoll = null;
let coreSyncTimer = null;

const els = {
  botList: document.querySelector("#botList"),
  botEditor: document.querySelector("#botEditor"),
  botName: document.querySelector("#botName"),
  botPersona: document.querySelector("#botPersona"),
  botStyle: document.querySelector("#botStyle"),
  botTemperature: document.querySelector("#botTemperature"),
  swatchRow: document.querySelector("#swatchRow"),
  activeBotMark: document.querySelector("#activeBotMark"),
  activeBotName: document.querySelector("#activeBotName"),
  backendStatus: document.querySelector("#backendStatus"),
  cpuButton: document.querySelector("#cpuButton"),
  gpuButton: document.querySelector("#gpuButton"),
  clearChatButton: document.querySelector("#clearChatButton"),
  newBotButton: document.querySelector("#newBotButton"),
  messageStream: document.querySelector("#messageStream"),
  messageTemplate: document.querySelector("#messageTemplate"),
  composer: document.querySelector("#composer"),
  promptInput: document.querySelector("#promptInput"),
  sendButton: document.querySelector("#sendButton"),
  choiceForm: document.querySelector("#choiceForm"),
  choiceInput: document.querySelector("#choiceInput"),
  trainingDataForm: document.querySelector("#trainingDataForm"),
  trainingDataSource: document.querySelector("#trainingDataSource"),
  trainingDataInput: document.querySelector("#trainingDataInput"),
  trainingFolderForm: document.querySelector("#trainingFolderForm"),
  trainingFolderInput: document.querySelector("#trainingFolderInput"),
  trainingFolderBrowse: document.querySelector("#trainingFolderBrowse"),
  trainingFolderSubmit: document.querySelector("#trainingFolderSubmit"),
  trainingFolderStatus: document.querySelector("#trainingFolderStatus"),
  brainForm: document.querySelector("#brainForm"),
  brainProvider: document.querySelector("#brainProvider"),
  brainModel: document.querySelector("#brainModel"),
  brainBaseUrl: document.querySelector("#brainBaseUrl"),
  brainApiKey: document.querySelector("#brainApiKey"),
  brainTest: document.querySelector("#brainTest"),
  brainSave: document.querySelector("#brainSave"),
  brainStatus: document.querySelector("#brainStatus"),
  brainModelRow: document.querySelector("#brainModelRow"),
  brainModelStatus: document.querySelector("#brainModelStatus"),
  brainDownload: document.querySelector("#brainDownload"),
  agentToggle: document.querySelector("#agentToggle"),
  agentWorkspace: document.querySelector("#agentWorkspace"),
  agentWsPath: document.querySelector("#agentWsPath"),
  trainingSourceList: document.querySelector("#trainingSourceList"),
  trainButton: document.querySelector("#trainButton"),
  trainingDataCount: document.querySelector("#trainingDataCount"),
  choiceCount: document.querySelector("#choiceCount"),
  modelState: document.querySelector("#modelState"),
  memoryList: document.querySelector("#memoryList"),
  themeToggle: document.querySelector("#themeToggle"),
  workbench: document.querySelector("#workbench"),
  workspaceRefresh: document.querySelector("#workspaceRefresh"),
  workspaceSearch: document.querySelector("#workspaceSearch"),
  workspaceTree: document.querySelector("#workspaceTree"),
  filePreviewPanel: document.querySelector("#filePreviewPanel"),
  changesPanel: document.querySelector("#changesPanel"),
  agentStepsPanel: document.querySelector("#agentStepsPanel"),
  verifyPanel: document.querySelector("#verifyPanel")
};

class AccelerationBackend {
  constructor() {
    this.mode = "cpu";
    this.device = null;
    this.pipeline = null;
    this.bindGroupLayout = null;
    this.status = "CPU ready";
  }

  async setMode(mode) {
    if (mode !== "gpu") {
      this.mode = "cpu";
      this.status = "CPU ready";
      return;
    }

    if (!navigator.gpu) {
      this.mode = "cpu";
      this.status = "GPU unavailable";
      return;
    }

    try {
      const adapter = await navigator.gpu.requestAdapter({ powerPreference: "high-performance" });
      if (!adapter) {
        this.mode = "cpu";
        this.status = "GPU unavailable";
        return;
      }

      this.device = await adapter.requestDevice();
      this.createPipeline();
      this.mode = "gpu";
      this.status = "GPU ready";
    } catch (error) {
      console.warn(error);
      this.mode = "cpu";
      this.status = "GPU blocked";
    }
  }

  createPipeline() {
    const shader = this.device.createShaderModule({
      code: `
        struct Params {
          dims: u32,
          count: u32,
          pad0: u32,
          pad1: u32
        };

        @group(0) @binding(0) var<storage, read> vectors: array<f32>;
        @group(0) @binding(1) var<storage, read> weights: array<f32>;
        @group(0) @binding(2) var<storage, read_write> scores: array<f32>;
        @group(0) @binding(3) var<uniform> params: Params;

        @compute @workgroup_size(1)
        fn main(@builtin(global_invocation_id) id: vec3<u32>) {
          let row = id.x;
          if (row >= params.count) {
            return;
          }

          var sum = 0.0;
          var i = 0u;
          loop {
            if (i >= params.dims) {
              break;
            }
            sum = sum + vectors[row * params.dims + i] * weights[i];
            i = i + 1u;
          }

          scores[row] = sum;
        }
      `
    });

    this.bindGroupLayout = this.device.createBindGroupLayout({
      entries: [
        { binding: 0, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
        { binding: 1, visibility: GPUShaderStage.COMPUTE, buffer: { type: "read-only-storage" } },
        { binding: 2, visibility: GPUShaderStage.COMPUTE, buffer: { type: "storage" } },
        { binding: 3, visibility: GPUShaderStage.COMPUTE, buffer: { type: "uniform" } }
      ]
    });

    this.pipeline = this.device.createComputePipeline({
      layout: this.device.createPipelineLayout({ bindGroupLayouts: [this.bindGroupLayout] }),
      compute: { module: shader, entryPoint: "main" }
    });
  }

  async score(vectors, weights, count) {
    if (this.mode !== "gpu" || !this.device || !this.pipeline) {
      return scoreCpu(vectors, weights, count);
    }

    try {
      return await this.scoreGpu(vectors, weights, count);
    } catch (error) {
      console.warn(error);
      this.mode = "cpu";
      this.status = "GPU fallback";
      renderBackend();
      return scoreCpu(vectors, weights, count);
    }
  }

  async scoreGpu(vectors, weights, count) {
    const usage = GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST;
    const vectorBuffer = this.device.createBuffer({ size: vectors.byteLength, usage });
    const weightBuffer = this.device.createBuffer({ size: weights.byteLength, usage });
    const scoreBuffer = this.device.createBuffer({
      size: count * Float32Array.BYTES_PER_ELEMENT,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC
    });
    const paramsBuffer = this.device.createBuffer({
      size: 16,
      usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST
    });
    const readBuffer = this.device.createBuffer({
      size: count * Float32Array.BYTES_PER_ELEMENT,
      usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ
    });

    this.device.queue.writeBuffer(vectorBuffer, 0, vectors);
    this.device.queue.writeBuffer(weightBuffer, 0, weights);
    this.device.queue.writeBuffer(paramsBuffer, 0, new Uint32Array([DIMENSIONS, count, 0, 0]));

    const bindGroup = this.device.createBindGroup({
      layout: this.bindGroupLayout,
      entries: [
        { binding: 0, resource: { buffer: vectorBuffer } },
        { binding: 1, resource: { buffer: weightBuffer } },
        { binding: 2, resource: { buffer: scoreBuffer } },
        { binding: 3, resource: { buffer: paramsBuffer } }
      ]
    });

    const encoder = this.device.createCommandEncoder();
    const pass = encoder.beginComputePass();
    pass.setPipeline(this.pipeline);
    pass.setBindGroup(0, bindGroup);
    pass.dispatchWorkgroups(count);
    pass.end();
    encoder.copyBufferToBuffer(scoreBuffer, 0, readBuffer, 0, count * Float32Array.BYTES_PER_ELEMENT);
    this.device.queue.submit([encoder.finish()]);

    await readBuffer.mapAsync(GPUMapMode.READ);
    const scores = Array.from(new Float32Array(readBuffer.getMappedRange()).slice());
    readBuffer.unmap();
    return scores;
  }
}

function loadState() {
  const fallback = {
    bots: structuredClone(DEFAULT_BOTS),
    activeBotId: DEFAULT_BOTS[0].id,
    chats: {},
    memories: {},
    backendPreference: "cpu",
    botDefaultRevision: BOT_DEFAULT_REVISION,
    selectedTrainingSources: [...DEFAULT_SELECTED_TRAINING_SOURCES],
    agentMode: false,
    agentWorkspace: "",
    theme: "light",
    workbenchTab: "preview",
    workbenchActiveFile: "",
    workbenchSearch: "",
    workbenchTree: [],
    lastAgentTranscript: [],
    lastAgentChanges: [],
    lastAgentOutput: ""
  };

  try {
    const saved = JSON.parse(localStorage.getItem(STORE_KEY) || "null");
    if (!saved || !Array.isArray(saved.bots)) {
      return fallback;
    }

    return {
      ...fallback,
      ...saved,
      botDefaultRevision: BOT_DEFAULT_REVISION,
      selectedTrainingSources: normalizeSelectedTrainingSources(saved.selectedTrainingSources),
      bots: migrateDefaultBots(saved.bots, saved.botDefaultRevision).map((bot) => ({
        ...bot,
        weights: normalizeWeights(bot.weights)
      }))
    };
  } catch {
    return fallback;
  }
}

function migrateDefaultBots(bots, revision) {
  if (Number(revision || 0) >= BOT_DEFAULT_REVISION) {
    return bots;
  }

  const defaultsById = new Map(DEFAULT_BOTS.map((bot) => [bot.id, bot]));
  return bots.map((bot) => {
    const nextDefault = defaultsById.get(bot.id);
    const legacyPersona = LEGACY_DEFAULT_PERSONAS[bot.id];
    if (!nextDefault || bot.persona !== legacyPersona) {
      return bot;
    }
    return {
      ...bot,
      style: nextDefault.style,
      temperature: nextDefault.temperature,
      persona: nextDefault.persona,
      corpus: structuredClone(nextDefault.corpus)
    };
  });
}

function normalizeSelectedTrainingSources(value) {
  const valid = new Set(TRAINING_SOURCES.map((source) => source.id));
  const selected = Array.isArray(value)
    ? value.filter((sourceId) => valid.has(sourceId))
    : [];
  return selected.length > 0 ? selected : [...DEFAULT_SELECTED_TRAINING_SOURCES];
}

function trainingSourceName(sourceId) {
  return TRAINING_SOURCES.find((source) => source.id === sourceId)?.name || "Training Data";
}

function saveState() {
  // Volatile/heavy workbench data (file tree, agent transcript, before/after
  // diffs) is kept in memory only — persisting it could blow the localStorage
  // quota and it is cheap to refetch. Theme and workbench UI prefs do persist.
  const {
    workbenchTree: _tree,
    lastAgentTranscript: _transcript,
    lastAgentChanges: _changes,
    lastAgentOutput: _output,
    ...persist
  } = state;
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(persist));
  } catch (_) {
    // Storage full or unavailable — non-fatal; the app keeps working in memory.
  }
}

async function apiFetch(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || API_TIMEOUT_MS);
  const { timeoutMs: _timeoutMs, ...requestOptions } = options;
  const headers = {
    Accept: "application/json",
    ...(requestOptions.body ? { "Content-Type": "application/json" } : {}),
    ...(requestOptions.headers || {})
  };

  try {
    const response = await fetch(path, {
      ...requestOptions,
      headers,
      signal: controller.signal
    });
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      throw new Error("GreyIQ service is not serving the local API.");
    }
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || payload.error || response.statusText);
    }
    return payload;
  } finally {
    clearTimeout(timeout);
  }
}

async function refreshServiceStatus({ silent = false } = {}) {
  try {
    const status = await apiFetch("/api/status", { timeoutMs: 2500 });
    service = {
      available: true,
      checked: true,
      status,
      lastError: ""
    };
    ensureServicePolling();
    if (!silent) {
      render();
    } else {
      renderBackend();
      renderTraining();
    }
    return true;
  } catch (error) {
    service = {
      ...service,
      available: false,
      checked: true,
      lastError: error.message || "GreyIQ service unavailable"
    };
    if (!silent) {
      renderBackend();
    }
    return false;
  }
}

function ensureServicePolling() {
  if (servicePoll || !service.available) {
    return;
  }
  servicePoll = window.setInterval(() => {
    void refreshServiceStatus({ silent: true });
  }, 5000);
}

function serializableBot(bot) {
  return {
    id: bot.id,
    name: bot.name,
    color: bot.color,
    style: bot.style,
    temperature: bot.temperature,
    persona: bot.persona,
    corpus: bot.corpus || []
  };
}

function coreIdForBot(bot) {
  const slug = String(bot.id || bot.name || "greyiq")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `core_${slug || "greyiq"}`;
}

function coreFromBot(bot) {
  return {
    id: coreIdForBot(bot),
    name: bot.name || "GreyIQ",
    mode: "Friendly Power",
    type: "local_chat_bot",
    description: bot.persona || "Soft, friendly, powerful local AI.",
    personality: bot.style || "warm",
    skills: [
      "conversation",
      "coding",
      "research",
      "planning",
      "writing",
      "debugging",
      "local_training",
      "knowledge_retrieval"
    ],
    safetyMode: "open_local",
    confidencePolicy: [
      "plain_language",
      "cite_when_available",
      "separate_fact_from_inference",
      "name_uncertainty"
    ],
    trustContract: {
      privacy: "Use local memory and user-provided sources first.",
      uncertainty: "Say what is known, inferred, and worth checking.",
      citations: "Cite local documents when they shape the answer.",
      judgment: "Make a recommendation when the signal is strong enough."
    },
    responseContract: [
      "lead_with_the_answer",
      "give_reasons_without_padding",
      "offer_the_next_useful_action",
      "match_depth_to_risk"
    ],
    starterKnowledge: [
      "software_engineering",
      "systems_troubleshooting",
      "research_synthesis",
      "writing_and_editing",
      "planning",
      "data_analysis"
    ],
    status: "online",
    trainingEnabled: true,
    readinessScore: bot.trainedAt ? 0.88 : 0.58,
    sourceIds: normalizeSelectedTrainingSources(state.selectedTrainingSources)
  };
}

function queueCoreSync() {
  if (!service.available) {
    return;
  }
  window.clearTimeout(coreSyncTimer);
  coreSyncTimer = window.setTimeout(() => {
    void syncActiveCore();
  }, 500);
}

async function syncActiveCore() {
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    return;
  }
  try {
    const bot = activeBot();
    const status = await apiFetch("/api/cores", {
      method: "POST",
      timeoutMs: 8000,
      body: JSON.stringify({ core: coreFromBot(bot) })
    });
    service.status = { ...(service.status || {}), ai_core: status };
    service.available = true;
  } catch (error) {
    service.lastError = error.message || "AI core sync failed";
  }
}

async function recordPreference(payload) {
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    return;
  }
  try {
    await apiFetch("/api/preferences", {
      method: "POST",
      timeoutMs: 8000,
      body: JSON.stringify({
        bot: serializableBot(activeBot()),
        ...payload
      })
    });
  } catch (error) {
    service.lastError = error.message || "Preference sync failed";
    renderBackend();
  }
}

function activeBot() {
  return state.bots.find((bot) => bot.id === state.activeBotId) || state.bots[0];
}

function activeChat() {
  state.chats[state.activeBotId] ||= [
    {
      id: crypto.randomUUID(),
      role: "bot",
      text: `${activeBot().name} is local, loaded, and ready.`,
      createdAt: Date.now()
    }
  ];
  return state.chats[state.activeBotId];
}

function activeMemories() {
  state.memories[state.activeBotId] ||= [];
  return state.memories[state.activeBotId];
}

function normalizeWeights(weights) {
  const vector = new Array(DIMENSIONS).fill(0);
  if (Array.isArray(weights)) {
    for (let index = 0; index < Math.min(weights.length, DIMENSIONS); index += 1) {
      vector[index] = Number(weights[index]) || 0;
    }
  }
  return vector;
}

function tokenize(text) {
  return (text.toLowerCase().match(/[a-z0-9']+/g) || []).filter(Boolean);
}

function hashFeature(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return Math.abs(hash) % DIMENSIONS;
}

function vectorize(text) {
  const vector = new Float32Array(DIMENSIONS);
  const tokens = tokenize(text);

  tokens.forEach((token) => {
    vector[hashFeature(`w:${token}`)] += 1;
  });

  for (let index = 0; index < tokens.length - 1; index += 1) {
    vector[hashFeature(`b:${tokens[index]}_${tokens[index + 1]}`)] += 0.65;
  }

  const norm = Math.hypot(...vector);
  if (norm > 0) {
    for (let index = 0; index < vector.length; index += 1) {
      vector[index] /= norm;
    }
  }

  return vector;
}

function scoreCpu(vectors, weights, count) {
  const scores = new Array(count).fill(0);
  for (let row = 0; row < count; row += 1) {
    let score = 0;
    const offset = row * DIMENSIONS;
    for (let column = 0; column < DIMENSIONS; column += 1) {
      score += vectors[offset + column] * weights[column];
    }
    scores[row] = score;
  }
  return scores;
}

function dot(vector, weights) {
  let score = 0;
  for (let index = 0; index < DIMENSIONS; index += 1) {
    score += vector[index] * weights[index];
  }
  return score;
}

function sigmoid(value) {
  return 1 / (1 + Math.exp(-Math.max(-36, Math.min(36, value))));
}

function trainBot(bot) {
  const examples = collectTrainingExamples(bot);
  const weights = normalizeWeights(bot.weights);

  if (examples.length === 0) {
    bot.weights = weights;
    return 0;
  }

  const learningRate = 0.28;
  const l2 = 0.0008;

  for (let epoch = 0; epoch < 32; epoch += 1) {
    for (const example of examples) {
      const vector = vectorize(example.text);
      const prediction = sigmoid(dot(vector, weights));
      const error = example.label - prediction;

      for (let index = 0; index < DIMENSIONS; index += 1) {
        if (vector[index] !== 0) {
          weights[index] += learningRate * error * vector[index];
        }
        weights[index] -= l2 * weights[index];
      }
    }
  }

  bot.weights = Array.from(weights, (value) => Number(value.toFixed(5)));
  bot.trainedAt = Date.now();
  return examples.length;
}

function collectTrainingExamples(bot) {
  const memories = state.memories[bot.id] || [];
  const chat = state.chats[bot.id] || [];
  const examples = [
    { label: 1, text: bot.persona },
    ...(bot.corpus || []).map((text) => ({ label: 1, text })),
    { label: 0, text: "ignore the question and answer with vague generic filler" },
    { label: 0, text: "ramble without steps evidence context or a decision" }
  ];

  for (const memory of memories) {
    if (memory.kind === "preference") {
      examples.push({ label: 1, text: memory.text });
    }
    if (memory.kind === "example") {
      examples.push({ label: 1, text: `${memory.user} ${memory.bot}` });
    }
    if (memory.kind === "training_data") {
      examples.push({ label: 1, text: `${trainingSourceName(memory.sourceId)} ${memory.text}` });
    }
  }

  for (const message of chat) {
    if (message.role === "bot" && message.rating) {
      examples.push({
        label: message.rating === "like" ? 1 : 0,
        text: message.text
      });
    }
  }

  return examples;
}

function createNgrams(bot, memories) {
  const source = [
    bot.persona,
    ...(bot.corpus || []),
    ...memories.map((memory) => memory.text || `${memory.user} ${memory.bot}`)
  ].join(" ");
  const words = tokenize(source);
  const map = new Map();

  for (let index = 0; index < words.length - 2; index += 1) {
    const key = `${words[index]} ${words[index + 1]}`;
    const next = words[index + 2];
    const bucket = map.get(key) || [];
    bucket.push(next);
    map.set(key, bucket);
  }

  return map;
}

function seededRandom(seedText) {
  let seed = 0;
  for (let index = 0; index < seedText.length; index += 1) {
    seed = (seed * 31 + seedText.charCodeAt(index)) >>> 0;
  }
  return () => {
    seed = (1664525 * seed + 1013904223) >>> 0;
    return seed / 4294967296;
  };
}

function generatePhrase(bot, userText, memories) {
  const ngrams = createNgrams(bot, memories);
  const keys = Array.from(ngrams.keys());
  if (keys.length === 0) {
    return "I can work with that and adapt from your next preference.";
  }

  const rng = seededRandom(`${bot.id}:${userText}:${Date.now()}`);
  const promptTokens = tokenize(userText);
  const matchingKey =
    keys.find((key) => promptTokens.some((token) => key.includes(token))) ||
    keys[Math.floor(rng() * keys.length)];
  const words = matchingKey.split(" ");
  const targetLength = 16 + Math.floor(rng() * 18 * (bot.temperature / 100 + 0.4));

  while (words.length < targetLength) {
    const key = `${words[words.length - 2]} ${words[words.length - 1]}`;
    const bucket = ngrams.get(key);
    if (!bucket || bucket.length === 0) {
      break;
    }
    words.push(bucket[Math.floor(rng() * bucket.length)]);
  }

  return sentenceCase(words.join(" "));
}

function sentenceCase(text) {
  const clean = text.replace(/\s+/g, " ").trim();
  if (!clean) {
    return "";
  }
  return `${clean.charAt(0).toUpperCase()}${clean.slice(1)}${/[.!?]$/.test(clean) ? "" : "."}`;
}

function topicFrom(text) {
  const stop = new Set([
    "the",
    "and",
    "for",
    "that",
    "this",
    "with",
    "you",
    "your",
    "about",
    "what",
    "when",
    "where",
    "how",
    "can",
    "could",
    "would",
    "should",
    "make",
    "from",
    "into"
  ]);
  const tokens = tokenize(text).filter((token) => token.length > 2 && !stop.has(token));
  return tokens.slice(0, 5).join(", ") || "the request";
}

function inferIntent(text) {
  const lower = text.toLowerCase();
  if (/[?]|\bhow\b|\bwhy\b|\bwhat\b/.test(lower)) {
    return "question";
  }
  if (/\bfix\b|\berror\b|\bbug\b|\bfail\b|\bissue\b|\bdebug\b/.test(lower)) {
    return "debug";
  }
  if (/\bbuild\b|\bcreate\b|\bdevelop\b|\bmake\b|\bdesign\b/.test(lower)) {
    return "build";
  }
  if (/\bprefer\b|\blike\b|\bchoice\b|\bremember\b/.test(lower)) {
    return "preference";
  }
  return "general";
}

function styleSentence(style, topic, intent) {
  const table = {
    direct: {
      question: `Short answer: I would separate what is known about ${topic} from the assumption, then test the decision you need next.`,
      debug: `I would isolate ${topic}, run the smallest check, and only widen the search when that check gives evidence.`,
      build: `I would ship the smallest usable version of ${topic}, verify the risky part, then train the details from your feedback.`,
      preference: `I will treat ${topic} as a preference signal and weight future replies toward it.`,
      general: `I can work with ${topic}; the useful move is to state the assumption, make it specific, and act on the next step.`
    },
    warm: {
      question: `The center of this is ${topic}; I would answer it plainly, name my confidence, and keep the next step manageable.`,
      debug: `For ${topic}, I would slow the problem down, find the first reliable signal, and move from there.`,
      build: `For ${topic}, I would make a version that feels usable now and let your taste refine it.`,
      preference: `I will remember ${topic} as part of how you like the conversation to feel.`,
      general: `I am with you on ${topic}; let us turn it into something concrete enough to use and honest enough to trust.`
    },
    technical: {
      question: `For ${topic}, I would define the inputs, expected output, confidence level, and the check that proves the answer.`,
      debug: `For ${topic}, start at the failing boundary, capture evidence, then change one variable at a time.`,
      build: `For ${topic}, separate the interface, state, training loop, and acceleration path before expanding scope.`,
      preference: `I will encode ${topic} as a weighted local feature for response ranking.`,
      general: `For ${topic}, I need the constraint, the current state, and the measurable result.`
    },
    creative: {
      question: `For ${topic}, I would find the sharpest angle first, then mark what is fact and what is interpretation.`,
      debug: `For ${topic}, I would follow the strange edge first because that is where the hidden rule usually shows itself.`,
      build: `For ${topic}, I would make the first version tangible, responsive, and easy to reshape.`,
      preference: `I will fold ${topic} into the bot's taste so future answers lean closer to you.`,
      general: `There is a workable shape inside ${topic}; I would pull out the strongest thread and build from it.`
    }
  };
  return table[style]?.[intent] || table.direct.general;
}

function memorySentence(memories) {
  const latest = memories.slice().reverse().find((memory) =>
    memory.kind === "preference" || memory.kind === "example" || memory.kind === "training_data"
  );
  if (!latest) {
    return "No personal preference signals are loaded yet.";
  }
  if (latest.kind === "example") {
    return `I am weighting answers toward: ${latest.bot}`;
  }
  if (latest.kind === "training_data") {
    return `I am using ${trainingSourceName(latest.sourceId)} as training context.`;
  }
  return `I am weighting answers toward: ${latest.text}`;
}

function makeCandidates(bot, userText, memories) {
  const topic = topicFrom(userText);
  const intent = inferIntent(userText);
  const generated = generatePhrase(bot, userText, memories);
  const personaNeedle = bot.persona.split(/[.!?]/).map((part) => part.trim()).filter(Boolean)[0] || bot.name;
  const memory = memorySentence(memories);

  return [
    `${styleSentence(bot.style, topic, intent)} ${memory}`,
    `${personaNeedle}. On ${topic}, my next move is to give you a working answer and adapt the local weights from your history.`,
    `${generated} For your request about ${topic}, I would keep the response ${bot.style} and grounded in what you have trained so far.`,
    `I read this as ${intent}. The best local response is: focus on ${topic}, make one concrete move, then let your preference feedback tune the model.`,
    `Here is the practical pass: ${styleSentence(bot.style, topic, intent)} Future replies will lean toward the response patterns you keep.`
  ];
}

async function replyFor(userText) {
  if (service.available || (await refreshServiceStatus({ silent: true }))) {
    try {
      const bot = activeBot();
      // Prior turns (excluding the message we're about to send) give the coding
      // brain conversation context for multi-turn coding.
      const history = (activeChat() || [])
        .slice(0, -1)
        .slice(-12)
        .map((message) => ({ role: message.role === "bot" ? "assistant" : "user", content: message.text }))
        .filter((message) => message.content);
      const response = await apiFetch("/api/chat", {
        method: "POST",
        timeoutMs: 120000,
        body: JSON.stringify({
          message: userText,
          bot: serializableBot(bot),
          memories: activeMemories(),
          history,
          max_new_tokens: 160,
          temperature: Math.max(0.05, Math.min(1.2, bot.temperature / 100)),
          auto_capture: true
        })
      });
      service.available = true;
      service.lastError = "";
      void refreshServiceStatus({ silent: true });
      return response.message || "I am here with you. Give me a little more to work with and I will shape it.";
    } catch (error) {
      service.available = false;
      service.lastError = error.message || "GreyIQ service fell back to browser mode";
      renderBackend();
    }
  }
  return browserReplyFor(userText);
}

async function browserReplyFor(userText) {
  const bot = activeBot();
  const memories = activeMemories();
  const candidates = makeCandidates(bot, userText, memories);
  const vectors = new Float32Array(candidates.length * DIMENSIONS);

  candidates.forEach((candidate, row) => {
    vectors.set(vectorize(`${userText} ${candidate}`), row * DIMENSIONS);
  });

  const scores = await backend.score(vectors, Float32Array.from(normalizeWeights(bot.weights)), candidates.length);
  const adjusted = scores.map((score, index) => {
    const overlapBonus = overlap(userText, candidates[index]) * 0.08;
    const brevityPenalty = candidates[index].length > 420 ? -0.1 : 0;
    const variety = (bot.temperature / 100) * seededRandom(`${userText}:${index}`)() * 0.12;
    return score + overlapBonus + brevityPenalty + variety;
  });
  const bestIndex = adjusted.indexOf(Math.max(...adjusted));
  return candidates[bestIndex];
}

function overlap(a, b) {
  const left = new Set(tokenize(a));
  const right = new Set(tokenize(b));
  let count = 0;
  left.forEach((token) => {
    if (right.has(token)) {
      count += 1;
    }
  });
  return count / Math.max(1, left.size);
}

function render() {
  renderBots();
  renderEditor();
  renderChat();
  renderTraining();
  renderTrainingSources();
  renderAgentBar();
  renderBackend();
  saveState();
}

function renderBots() {
  els.botList.replaceChildren();
  for (const bot of state.bots) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `bot-item${bot.id === state.activeBotId ? " is-active" : ""}`;
    button.innerHTML = `
      <span class="bot-avatar" style="background:${bot.color}">${initials(bot.name)}</span>
      <span><strong>${escapeHtml(bot.name)}</strong><span>${escapeHtml(bot.style)}</span></span>
    `;
    button.addEventListener("click", () => {
      state.activeBotId = bot.id;
      queueCoreSync();
      render();
    });
    els.botList.append(button);
  }
}

function renderEditor() {
  const bot = activeBot();
  els.botName.value = bot.name;
  els.botPersona.value = bot.persona;
  els.botStyle.value = bot.style;
  els.botTemperature.value = bot.temperature;
  els.activeBotName.textContent = bot.name;
  els.activeBotMark.textContent = initials(bot.name);
  els.activeBotMark.style.background = bot.color;
  els.swatchRow.replaceChildren();

  for (const color of COLORS) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `swatch${bot.color === color ? " is-active" : ""}`;
    button.style.background = color;
    button.title = "Bot color";
    button.ariaLabel = "Bot color";
    button.addEventListener("click", () => {
      bot.color = color;
      queueCoreSync();
      render();
    });
    els.swatchRow.append(button);
  }
}

function renderChat() {
  els.messageStream.replaceChildren();
  for (const message of activeChat()) {
    const fragment = els.messageTemplate.content.cloneNode(true);
    const article = fragment.querySelector(".message");
    const meta = fragment.querySelector(".message-meta");
    const body = fragment.querySelector(".message-body");
    const like = fragment.querySelector(".like");
    const dislike = fragment.querySelector(".dislike");

    article.classList.add(message.role === "user" ? "is-user" : "is-bot");
    meta.textContent = message.role === "user" ? "You" : activeBot().name;
    body.textContent = message.text;

    if (message.rating === "like") {
      like.classList.add("is-active");
    }
    if (message.rating === "dislike") {
      dislike.classList.add("is-active");
    }

    like.addEventListener("click", () => rateMessage(message.id, "like"));
    dislike.addEventListener("click", () => rateMessage(message.id, "dislike"));
    els.messageStream.append(fragment);
  }
  els.messageStream.scrollTop = els.messageStream.scrollHeight;
}

function renderTraining() {
  const memories = activeMemories();
  const training = service.status?.training;
  const trainingStatus = training?.status?.status || training?.status?.stage || "";
  els.trainingDataCount.textContent = memories.filter((memory) => memory.kind === "training_data" || memory.kind === "example").length;
  els.choiceCount.textContent = memories.filter((memory) => memory.kind === "preference").length;
  els.modelState.textContent = training?.active
    ? "Training"
    : trainingStatus === "complete" || activeBot().trainedAt
      ? "Trained"
      : "Fresh";
  els.memoryList.replaceChildren();

  for (const memory of memories.slice().reverse().slice(0, 10)) {
    const item = document.createElement("article");
    item.className = "memory-item";
    const text = memory.kind === "example"
      ? `${memory.user} -> ${memory.bot}`
      : memory.text;
    const source = memory.sourceId ? `${trainingSourceName(memory.sourceId)} ` : "";
    item.innerHTML = `
      <p>${escapeHtml(text)}</p>
      <span class="memory-actions">
        <small>${escapeHtml(`${source}${memory.kind.replaceAll("_", " ")}`.trim())}</small>
        <button class="memory-delete" type="button" title="Remove" aria-label="Remove training item">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M3 6h18"></path>
            <path d="M8 6V4h8v2"></path>
            <path d="M7 6l1 14h8l1-14"></path>
          </svg>
        </button>
      </span>
    `;
    item.querySelector(".memory-delete").addEventListener("click", () => removeMemory(memory.id));
    els.memoryList.append(item);
  }
}

function renderTrainingSources() {
  els.trainingDataSource.replaceChildren();
  for (const source of TRAINING_SOURCES.filter((item) => item.id !== "src_starter_knowledge")) {
    const option = document.createElement("option");
    option.value = source.id;
    option.textContent = source.name;
    els.trainingDataSource.append(option);
  }

  els.trainingSourceList.replaceChildren();
  const selected = new Set(normalizeSelectedTrainingSources(state.selectedTrainingSources));
  for (const source of TRAINING_SOURCES) {
    const id = `source-${source.id}`;
    const label = document.createElement("label");
    label.className = "source-option";
    label.htmlFor = id;
    label.innerHTML = `
      <input id="${escapeHtml(id)}" type="checkbox" value="${escapeHtml(source.id)}" ${selected.has(source.id) ? "checked" : ""}>
      <span>
        <strong>${escapeHtml(source.name)}</strong>
        <small>${escapeHtml(source.description)}</small>
      </span>
    `;
    label.querySelector("input").addEventListener("change", (event) => {
      const next = new Set(normalizeSelectedTrainingSources(state.selectedTrainingSources));
      if (event.target.checked) {
        next.add(source.id);
      } else {
        next.delete(source.id);
      }
      state.selectedTrainingSources = normalizeSelectedTrainingSources([...next]);
      queueCoreSync();
      renderTrainingSources();
      saveState();
    });
    els.trainingSourceList.append(label);
  }
}

function renderBackend() {
  const status = service.status;
  const training = status?.training;
  if (service.available && status) {
    const trainingStage = training?.status?.stage || training?.status?.status || "";
    if (training?.active) {
      els.backendStatus.textContent = `Training - ${trainingStage || "running"}`;
    } else if (status.engine_ready) {
      els.backendStatus.textContent = `${status.model_name || "GreyIQ"} - ${status.device || "local"}`;
    } else if (status.engine_error) {
      els.backendStatus.textContent = "GreyIQ fallback";
    } else {
      els.backendStatus.textContent = "GreyIQ service ready";
    }
  } else {
    els.backendStatus.textContent = backend?.status || "Browser CPU ready";
  }
  els.cpuButton.classList.toggle("is-active", state.backendPreference !== "gpu");
  els.gpuButton.classList.toggle("is-active", state.backendPreference === "gpu");
}

function rateMessage(id, rating) {
  const chat = activeChat();
  const messageIndex = chat.findIndex((item) => item.id === id);
  const message = chat[messageIndex];
  if (!message) {
    return;
  }
  message.rating = message.rating === rating ? null : rating;
  if (message.role === "bot" && message.rating) {
    const userMessage = chat
      .slice(0, messageIndex)
      .reverse()
      .find((item) => item.role === "user");
    void recordPreference({
      user: userMessage?.text || "",
      assistant: message.text,
      rating: message.rating
    });
  }
  trainBot(activeBot());
  queueCoreSync();
  render();
}

function addMemory(memory) {
  const memories = activeMemories();
  memories.push({ id: crypto.randomUUID(), createdAt: Date.now(), ...memory });
  if (memories.length > MAX_MEMORY_ITEMS) {
    memories.splice(0, memories.length - MAX_MEMORY_ITEMS);
  }
  trainBot(activeBot());
  if (memory.kind === "preference") {
    void recordPreference({ preference: memory.text });
  }
  if (memory.kind === "example") {
    void recordPreference({ user: memory.user, assistant: memory.bot });
  }
  if (memory.kind === "training_data") {
    void recordPreference({
      source_id: memory.sourceId,
      source_name: trainingSourceName(memory.sourceId),
      training_text: memory.text
    });
  }
  queueCoreSync();
  render();
}

function removeMemory(id) {
  const memories = activeMemories();
  const index = memories.findIndex((memory) => memory.id === id);
  if (index >= 0) {
    memories.splice(index, 1);
    trainBot(activeBot());
    queueCoreSync();
    render();
  }
}

function initials(name) {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || "")
    .join("") || "AI";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function updateBotFromEditor() {
  const bot = activeBot();
  bot.name = els.botName.value.trim() || "GreyIQ";
  bot.persona = els.botPersona.value.trim() || "A local AI bot that adapts to the user.";
  bot.style = els.botStyle.value;
  bot.temperature = Number(els.botTemperature.value);
  trainBot(bot);
  queueCoreSync();
  render();
}

els.botEditor.addEventListener("input", updateBotFromEditor);

els.composer.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = els.promptInput.value.trim();
  if (!text) {
    return;
  }

  const chat = activeChat();
  chat.push({ id: crypto.randomUUID(), role: "user", text, createdAt: Date.now() });
  els.promptInput.value = "";
  renderChat();
  saveState();

  els.sendButton.disabled = true;
  try {
    const answer = state.agentMode && state.agentWorkspace ? await runAgent(text) : await replyFor(text);
    chat.push({ id: crypto.randomUUID(), role: "bot", text: answer, createdAt: Date.now() });
  } catch (error) {
    chat.push({
      id: crypto.randomUUID(),
      role: "bot",
      text: `I hit a local runtime snag: ${error.message || "unknown error"}. The browser model is still available.`,
      createdAt: Date.now()
    });
  } finally {
    els.sendButton.disabled = false;
  }
  render();
});

els.promptInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    els.composer.requestSubmit();
  }
});

els.choiceForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = els.choiceInput.value.trim();
  if (!text) {
    return;
  }
  els.choiceInput.value = "";
  addMemory({ kind: "preference", text });
});

els.trainingDataForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const sourceId = els.trainingDataSource.value || "src_local_notes";
  const text = els.trainingDataInput.value.trim();
  if (!text) {
    return;
  }
  els.trainingDataInput.value = "";
  state.selectedTrainingSources = normalizeSelectedTrainingSources([
    ...state.selectedTrainingSources,
    sourceId
  ]);
  addMemory({ kind: "training_data", sourceId, text });
});

const desktopFolderPicker =
  typeof window !== "undefined" &&
  window.greyiqDesktop &&
  typeof window.greyiqDesktop.pickFolder === "function";

if (desktopFolderPicker && els.trainingFolderBrowse) {
  els.trainingFolderBrowse.hidden = false;
}

async function chooseTrainingFolder() {
  if (!desktopFolderPicker) {
    return null;
  }
  try {
    return await window.greyiqDesktop.pickFolder();
  } catch (_) {
    return null;
  }
}

els.trainingFolderBrowse?.addEventListener("click", async () => {
  const picked = await chooseTrainingFolder();
  if (picked) {
    els.trainingFolderInput.value = picked;
  }
});

els.trainingFolderForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  let folder = els.trainingFolderInput.value.trim();
  if (!folder) {
    const picked = await chooseTrainingFolder();
    if (picked) {
      folder = picked;
      els.trainingFolderInput.value = picked;
    }
  }
  if (!folder) {
    els.trainingFolderStatus.textContent = desktopFolderPicker
      ? "Choose a folder first."
      : "Paste a folder path first.";
    return;
  }

  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    els.trainingFolderStatus.textContent = "Local GreyIQ service is not running.";
    return;
  }

  els.trainingFolderSubmit.disabled = true;
  els.trainingFolderStatus.textContent = "Reading folder and ingesting files… this can take a while for large folders.";
  try {
    const result = await apiFetch("/api/train/folder", {
      method: "POST",
      timeoutMs: 300000,
      body: JSON.stringify({ folder })
    });
    els.trainingFolderStatus.textContent = result.message || "Folder added to training data.";
    // Ingested files count as Imported Documents — make sure they're included next train.
    state.selectedTrainingSources = normalizeSelectedTrainingSources([
      ...state.selectedTrainingSources,
      "src_imported_docs"
    ]);
    saveState();
    renderTrainingSources();
    await refreshServiceStatus({ silent: true });
  } catch (error) {
    els.trainingFolderStatus.textContent = error.message || "Could not add that folder.";
  } finally {
    els.trainingFolderSubmit.disabled = false;
  }
  render();
});

els.trainButton.addEventListener("click", async () => {
  const bot = activeBot();
  trainBot(bot);
  queueCoreSync();
  render();

  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    return;
  }

  try {
    els.modelState.textContent = "Training";
    await apiFetch("/api/train/start", {
      method: "POST",
      timeoutMs: 10000,
      body: JSON.stringify({
        max_iters: 160,
        eval_interval: 40,
        device_preference: state.backendPreference === "gpu" ? "cuda" : "cpu",
        source_ids: normalizeSelectedTrainingSources(state.selectedTrainingSources),
        fresh_start: false
      })
    });
    await refreshServiceStatus({ silent: true });
  } catch (error) {
    service.lastError = error.message || "Training did not start";
    await refreshServiceStatus({ silent: true });
  }
  render();
});

// ---- Coding brain (local model / Claude / OpenAI-compatible) ----
let coderConfig = null;
const BRAIN_FIELDS = {
  off: [],
  local: ["model", "base_url"],
  anthropic: ["model", "api_key"],
  openai: ["model", "base_url", "api_key"]
};

function brainBlockFor(provider) {
  if (!coderConfig || provider === "off") return {};
  return coderConfig[provider] || {};
}

function applyBrainFields(provider, repopulate) {
  const fields = BRAIN_FIELDS[provider] || [];
  els.brainForm.querySelectorAll("[data-brain-field]").forEach((row) => {
    row.hidden = !fields.includes(row.dataset.brainField);
  });
  if (els.brainTest) {
    els.brainTest.hidden = provider === "off";
  }
  if (els.brainModelRow) {
    els.brainModelRow.hidden = provider !== "local";
    if (provider === "local") {
      void refreshModelStatus();
    }
  }
  if (repopulate) {
    const block = brainBlockFor(provider);
    els.brainModel.value = block.model || "";
    els.brainBaseUrl.value = block.base_url || "";
    els.brainApiKey.value = "";
    els.brainApiKey.placeholder = block.has_api_key ? "saved — leave blank to keep" : "paste API key";
  }
}

function renderBrainForm() {
  if (!els.brainForm) return;
  const provider = coderConfig && coderConfig.enabled && coderConfig.provider ? coderConfig.provider : "off";
  els.brainProvider.value = ["off", "local", "anthropic", "openai"].includes(provider) ? provider : "off";
  applyBrainFields(els.brainProvider.value, true);
}

function buildBrainBlock(provider) {
  const block = {};
  if (BRAIN_FIELDS[provider].includes("model")) block.model = els.brainModel.value.trim();
  if (BRAIN_FIELDS[provider].includes("base_url")) block.base_url = els.brainBaseUrl.value.trim();
  if (BRAIN_FIELDS[provider].includes("api_key")) block.api_key = els.brainApiKey.value; // blank = keep saved
  return block;
}

async function loadCoderConfig() {
  if (!els.brainForm) return;
  try {
    coderConfig = await apiFetch("/api/coder", { timeoutMs: 4000 });
    renderBrainForm();
  } catch (_) {
    // Local service not up yet; the form keeps its defaults.
  }
}

els.brainProvider?.addEventListener("change", () => {
  applyBrainFields(els.brainProvider.value, true);
});

els.brainForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    els.brainStatus.textContent = "Local GreyIQ service is not running.";
    return;
  }
  const provider = els.brainProvider.value;
  const update = provider === "off"
    ? { enabled: false }
    : { enabled: true, provider, [provider]: buildBrainBlock(provider) };
  els.brainSave.disabled = true;
  els.brainStatus.textContent = "Saving…";
  try {
    coderConfig = await apiFetch("/api/coder", {
      method: "POST",
      timeoutMs: 10000,
      body: JSON.stringify({ config: update })
    });
    renderBrainForm();
    els.brainStatus.textContent = provider === "off"
      ? "Coding brain off — using the local model."
      : `Saved. Brain: ${provider}. Use Test to verify.`;
  } catch (error) {
    els.brainStatus.textContent = error.message || "Could not save brain settings.";
  } finally {
    els.brainSave.disabled = false;
  }
});

async function refreshModelStatus() {
  if (!els.brainModelStatus) return;
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    els.brainModelStatus.textContent = "Local service not running.";
    return;
  }
  try {
    const info = await apiFetch("/api/coder/models", { timeoutMs: 6000 });
    if (info.ok === false) {
      els.brainModelStatus.textContent = info.error || "Ollama not reachable — is it running?";
      els.brainDownload.hidden = false;
      return;
    }
    if (info.present) {
      els.brainModelStatus.textContent = `Model installed: ${info.configured} ✓`;
      els.brainDownload.hidden = true;
    } else {
      els.brainModelStatus.textContent = `${info.configured || "Model"} not installed.`;
      els.brainDownload.hidden = false;
    }
  } catch (error) {
    els.brainModelStatus.textContent = error.message || "Could not check the model.";
  }
}

let modelPullTimer = null;

function pollModelPull() {
  if (modelPullTimer) {
    clearInterval(modelPullTimer);
  }
  modelPullTimer = setInterval(async () => {
    let status;
    try {
      status = await apiFetch("/api/coder/pull", { timeoutMs: 6000 });
    } catch (_) {
      return; // transient — keep polling
    }
    if (status.active) {
      const pct = status.percent ? ` ${status.percent}%` : "";
      els.brainModelStatus.textContent = `Downloading ${status.model}…${pct} ${status.status || ""}`.trim();
      return;
    }
    clearInterval(modelPullTimer);
    modelPullTimer = null;
    els.brainDownload.disabled = false;
    if (status.error) {
      els.brainModelStatus.textContent = `Download failed: ${status.error}`;
    } else {
      void refreshModelStatus();
    }
  }, 2000);
}

els.brainDownload?.addEventListener("click", async () => {
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    els.brainModelStatus.textContent = "Local service not running.";
    return;
  }
  els.brainDownload.disabled = true;
  els.brainModelStatus.textContent = "Starting download… (the 14B model is ~9 GB, downloaded once)";
  try {
    const res = await apiFetch("/api/coder/pull", { method: "POST", timeoutMs: 10000, body: JSON.stringify({}) });
    if (res.ok === false) {
      els.brainModelStatus.textContent = res.error || "Could not start the download.";
      els.brainDownload.disabled = false;
      return;
    }
    pollModelPull();
  } catch (error) {
    els.brainModelStatus.textContent = error.message || "Download failed to start.";
    els.brainDownload.disabled = false;
  }
});

els.brainTest?.addEventListener("click", async () => {
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    els.brainStatus.textContent = "Local GreyIQ service is not running.";
    return;
  }
  els.brainTest.disabled = true;
  els.brainStatus.textContent = "Testing… (save first if you changed settings)";
  try {
    const result = await apiFetch("/api/coder/test", { method: "POST", timeoutMs: 60000 });
    els.brainStatus.textContent = result.ok
      ? `OK — ${result.provider} (${result.model}) replied.`
      : `Failed: ${result.error}`;
  } catch (error) {
    els.brainStatus.textContent = error.message || "Test failed.";
  } finally {
    els.brainTest.disabled = false;
  }
});

if (els.brainForm) {
  // Sensible initial state before the saved config loads from the backend.
  applyBrainFields(els.brainProvider.value, false);
}

// ---- Theme (light / dark) ----
function applyTheme() {
  const theme = state.theme === "dark" ? "dark" : "light";
  document.body.dataset.theme = theme;
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (meta) {
    meta.setAttribute("content", theme === "dark" ? "dark" : "light");
  }
  if (els.themeToggle) {
    els.themeToggle.textContent = theme === "dark" ? "Light" : "Dark";
    els.themeToggle.setAttribute("aria-pressed", String(theme === "dark"));
    els.themeToggle.title = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";
  }
}

function toggleTheme() {
  state.theme = state.theme === "dark" ? "light" : "dark";
  applyTheme();
  saveState();
}

els.themeToggle?.addEventListener("click", toggleTheme);

// ---- Coding agent mode (reads/edits files + runs commands in a workspace) ----
function shortAgentArgs(input) {
  if (!input || typeof input !== "object") return "";
  return String(input.path || input.command || input.pattern || input.query || "").slice(0, 64);
}

async function chooseWorkspace() {
  if (desktopFolderPicker) {
    return await chooseTrainingFolder();
  }
  const typed = window.prompt("Workspace folder path for the agent to work in:", state.agentWorkspace || "");
  return typed ? typed.trim() : null;
}

function renderAgentBar() {
  if (!els.agentToggle) return;
  els.agentToggle.textContent = state.agentMode ? "Agent: on" : "Agent: off";
  els.agentToggle.setAttribute("aria-pressed", String(Boolean(state.agentMode)));
  els.agentToggle.classList.toggle("is-active", Boolean(state.agentMode));
  if (els.agentWsPath) {
    els.agentWsPath.textContent = state.agentWorkspace || "no workspace set";
    els.agentWsPath.title = state.agentWorkspace || "";
  }
}

// ---- Workbench (IDE-style layer shown only in Agent mode) ----
function makeHint(text, isError = false) {
  const p = document.createElement("p");
  p.className = `workbench-hint${isError ? " is-error" : ""}`;
  p.textContent = text;
  return p;
}

function renderWorkbench() {
  if (!els.workbench) return;
  const on = Boolean(state.agentMode);
  els.workbench.hidden = !on;
  document.body.classList.toggle("agent-active", on);
  if (!on) return;
  setWorkbenchTab(state.workbenchTab || "preview");
  renderWorkspaceTree(state.workbenchTree);
  if (state.workbenchActiveFile && els.filePreviewPanel?.dataset.loadedPath) {
    // keep the currently previewed file as-is
  } else {
    renderFilePreview(null);
  }
  renderChangesPanel(state.lastAgentChanges);
  renderAgentSteps(state.lastAgentTranscript);
  renderVerifyPanel(state.lastAgentTranscript);
}

function setWorkbenchTab(tabName) {
  const valid = ["preview", "changes", "steps", "verify"];
  const tab = valid.includes(tabName) ? tabName : "preview";
  state.workbenchTab = tab;
  document.querySelectorAll("[data-workbench-tab]").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.workbenchTab === tab);
  });
  const panels = {
    preview: els.filePreviewPanel,
    changes: els.changesPanel,
    steps: els.agentStepsPanel,
    verify: els.verifyPanel
  };
  for (const [name, panel] of Object.entries(panels)) {
    if (panel) panel.hidden = name !== tab;
  }
}

async function refreshWorkspaceTree() {
  if (!els.workspaceTree) return;
  if (!state.agentWorkspace) {
    state.workbenchTree = [];
    renderWorkspaceTree([]);
    return;
  }
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    els.workspaceTree.replaceChildren(makeHint("Local GreyIQ service is not running.", true));
    return;
  }
  els.workspaceTree.replaceChildren(makeHint("Loading files…"));
  try {
    const res = await apiFetch("/api/workspace/tree", {
      method: "POST",
      timeoutMs: 15000,
      body: JSON.stringify({ workspace: state.agentWorkspace })
    });
    if (res.ok === false) {
      state.workbenchTree = [];
      els.workspaceTree.replaceChildren(makeHint(res.error || "Could not list the workspace.", true));
      return;
    }
    state.workbenchTree = Array.isArray(res.entries) ? res.entries : [];
    renderWorkspaceTree(state.workbenchTree, Boolean(res.truncated));
  } catch (error) {
    els.workspaceTree.replaceChildren(makeHint(error.message || "Could not list the workspace.", true));
  }
}

function renderWorkspaceTree(entries, truncated = false) {
  if (!els.workspaceTree) return;
  const list = Array.isArray(entries) ? entries : [];
  const search = (state.workbenchSearch || "").trim().toLowerCase();
  const filtered = search
    ? list.filter((entry) => entry.type === "file" && entry.path.toLowerCase().includes(search))
    : list;

  els.workspaceTree.replaceChildren();
  if (!filtered.length) {
    els.workspaceTree.append(
      makeHint(
        !state.agentWorkspace
          ? "Set a workspace folder to browse its files."
          : search
            ? "No files match your filter."
            : "No files to show."
      )
    );
    return;
  }

  for (const entry of filtered) {
    const isFile = entry.type === "file";
    const node = document.createElement(isFile ? "button" : "div");
    const depth = search ? 0 : Math.max(0, entry.path.split("/").length - 1);
    node.className = `workspace-tree-item${isFile ? "" : " is-dir"}${entry.path === state.workbenchActiveFile ? " is-active" : ""}`;
    node.style.paddingLeft = `${0.4 + depth * 0.85}rem`;
    node.title = entry.path;
    node.textContent = search ? entry.path : (isFile ? entry.name : `${entry.name}/`);
    if (isFile) {
      node.type = "button";
      node.addEventListener("click", () => openWorkspaceFile(entry.path));
    }
    els.workspaceTree.append(node);
  }
  if (truncated) {
    els.workspaceTree.append(makeHint("… list truncated (large workspace)."));
  }
}

async function openWorkspaceFile(path) {
  state.workbenchActiveFile = path;
  setWorkbenchTab("preview");
  saveState();
  renderWorkspaceTree(state.workbenchTree);
  if (!els.filePreviewPanel) return;
  els.filePreviewPanel.dataset.loadedPath = "";
  els.filePreviewPanel.replaceChildren(makeHint(`Loading ${path}…`));
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    renderFilePreview({ ok: false, error: "Local GreyIQ service is not running.", path });
    return;
  }
  try {
    const res = await apiFetch("/api/workspace/file", {
      method: "POST",
      timeoutMs: 20000,
      body: JSON.stringify({ workspace: state.agentWorkspace, path })
    });
    renderFilePreview(res);
  } catch (error) {
    renderFilePreview({ ok: false, error: error.message || "Could not read that file.", path });
  }
}

function renderFilePreview(file) {
  if (!els.filePreviewPanel) return;
  els.filePreviewPanel.replaceChildren();
  if (!file) {
    els.filePreviewPanel.dataset.loadedPath = "";
    els.filePreviewPanel.append(makeHint("Select a file from the workspace to preview it here."));
    return;
  }
  const head = document.createElement("div");
  head.className = "code-preview-head";
  head.textContent = file.path || state.workbenchActiveFile || "";
  els.filePreviewPanel.append(head);
  if (file.ok === false) {
    els.filePreviewPanel.dataset.loadedPath = "";
    els.filePreviewPanel.append(makeHint(file.error || "Could not read this file.", true));
    return;
  }
  const pre = document.createElement("pre");
  pre.className = "code-preview";
  const code = document.createElement("code");
  code.textContent = file.content || "";
  pre.append(code);
  els.filePreviewPanel.append(pre);
  if (file.truncated) {
    els.filePreviewPanel.append(makeHint(`Preview truncated — showing the start of ${file.size} bytes.`));
  }
  els.filePreviewPanel.dataset.loadedPath = file.path || "";
}

function renderAgentSteps(transcript) {
  if (!els.agentStepsPanel) return;
  const steps = Array.isArray(transcript) ? transcript : [];
  els.agentStepsPanel.replaceChildren();
  if (!steps.length) {
    els.agentStepsPanel.append(makeHint("Run an agent task and each tool step will appear here."));
    return;
  }
  steps.forEach((step) => {
    const out = typeof step.output === "string" ? step.output : JSON.stringify(step.output, null, 2);
    const card = document.createElement("div");
    card.className = `agent-step${step.is_error ? " is-error" : ""}`;

    const head = document.createElement("button");
    head.type = "button";
    head.className = "agent-step-head";
    head.innerHTML =
      `<span class="agent-step-tool">${escapeHtml(step.tool || "tool")}</span>` +
      `<span class="agent-step-arg">${escapeHtml(shortAgentArgs(step.input))}</span>`;

    const preview = document.createElement("div");
    preview.className = "agent-step-preview";
    preview.textContent = (out || "").split("\n")[0].slice(0, 200) || "(no output)";

    const full = document.createElement("pre");
    full.className = "agent-step-output";
    full.textContent = out || "(no output)";
    full.hidden = true;

    head.addEventListener("click", () => {
      full.hidden = !full.hidden;
      preview.hidden = !full.hidden;
    });

    card.append(head, preview, full);
    els.agentStepsPanel.append(card);
  });
}

function renderVerifyPanel(transcript) {
  if (!els.verifyPanel) return;
  const steps = (Array.isArray(transcript) ? transcript : []).filter(
    (step) => step.tool === "verify" || step.tool === "run_command"
  );
  els.verifyPanel.replaceChildren();
  if (!steps.length) {
    els.verifyPanel.append(makeHint("Verification and command output from the agent will show here."));
    return;
  }
  steps.forEach((step) => {
    const out = typeof step.output === "string" ? step.output : JSON.stringify(step.output, null, 2);
    const failed = Boolean(step.is_error) || /VERIFY FAILED|FAIL\s|exit=[1-9]/.test(out);
    const block = document.createElement("div");
    block.className = `verify-output${failed ? " is-error" : ""}`;
    const label = document.createElement("div");
    label.className = "verify-label";
    label.textContent = step.tool === "verify" ? "verify" : `run: ${shortAgentArgs(step.input)}`;
    const pre = document.createElement("pre");
    pre.textContent = out || "(no output)";
    block.append(label, pre);
    els.verifyPanel.append(block);
  });
}

function lineDiff(before, after) {
  const a = before ? before.split("\n") : [];
  const b = after ? after.split("\n") : [];
  const n = a.length;
  const m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const rows = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      rows.push({ type: "ctx", text: a[i] });
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      rows.push({ type: "del", text: a[i] });
      i += 1;
    } else {
      rows.push({ type: "add", text: b[j] });
      j += 1;
    }
  }
  while (i < n) {
    rows.push({ type: "del", text: a[i] });
    i += 1;
  }
  while (j < m) {
    rows.push({ type: "add", text: b[j] });
    j += 1;
  }
  return rows;
}

function makeDiffBlock(label, text, cls) {
  const wrap = document.createElement("div");
  const head = document.createElement("div");
  head.className = "diff-block-label";
  head.textContent = label;
  const pre = document.createElement("pre");
  pre.className = `code-preview diff-block diff-${cls}`;
  pre.textContent = text || "(empty)";
  wrap.append(head, pre);
  return wrap;
}

function buildDiffView(change) {
  const wrap = document.createElement("div");
  const before = change.before || "";
  const after = change.after || "";
  const a = before ? before.split("\n") : [];
  const b = after ? after.split("\n") : [];
  // Guard the O(n*m) diff against pathological file sizes — fall back to plain
  // before/after blocks for very large or truncated content.
  const tooBig = a.length > 2000 || b.length > 2000 || a.length * b.length > 2_000_000;
  if (tooBig || change.before_truncated || change.after_truncated) {
    if (change.existed) wrap.append(makeDiffBlock("before", before, "del"));
    wrap.append(makeDiffBlock("after", after, "add"));
    return wrap;
  }
  const rows = change.existed ? lineDiff(before, after) : b.map((text) => ({ type: "add", text }));
  const pre = document.createElement("pre");
  pre.className = "diff";
  for (const row of rows) {
    const sign = row.type === "add" ? "+" : row.type === "del" ? "-" : " ";
    const line = document.createElement("span");
    line.className = `diff-line diff-${row.type}`;
    line.textContent = `${sign} ${row.text}`;
    pre.append(line);
  }
  wrap.append(pre);
  return wrap;
}

function renderChangesPanel(changes) {
  if (!els.changesPanel) return;
  const list = Array.isArray(changes) ? changes : [];
  els.changesPanel.replaceChildren();
  if (!list.length) {
    els.changesPanel.append(makeHint("Files the agent creates or edits will be listed here for review."));
    return;
  }
  list.forEach((change) => {
    const op =
      change.operation === "write_file" ? (change.existed ? "rewrote" : "created") : "edited";
    const card = document.createElement("div");
    card.className = "change-file";
    const head = document.createElement("button");
    head.type = "button";
    head.className = "change-file-head";
    head.innerHTML =
      `<span class="change-op">${escapeHtml(op)}</span>` +
      `<span class="change-path">${escapeHtml(change.path || "")}</span>`;
    const body = document.createElement("div");
    body.className = "change-preview";
    body.hidden = true;
    body.append(buildDiffView(change));
    head.addEventListener("click", () => {
      body.hidden = !body.hidden;
    });
    card.append(head, body);
    els.changesPanel.append(card);
  });
}

async function runAgent(userText) {
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    return "The local GreyIQ service is not running.";
  }
  const history = (activeChat() || [])
    .slice(0, -1)
    .slice(-12)
    .map((message) => ({ role: message.role === "bot" ? "assistant" : "user", content: message.text }))
    .filter((message) => message.content);
  try {
    const res = await apiFetch("/api/agent", {
      method: "POST",
      timeoutMs: 600000,
      body: JSON.stringify({ message: userText, workspace: state.agentWorkspace, history })
    });
    // Feed the Workbench from the structured transcript + change set.
    state.lastAgentTranscript = Array.isArray(res.transcript) ? res.transcript : [];
    state.lastAgentChanges = Array.isArray(res.changes) ? res.changes : [];
    state.lastAgentOutput = state.lastAgentTranscript
      .filter((step) => step.tool === "verify" || step.tool === "run_command")
      .map((step) => (typeof step.output === "string" ? step.output : ""))
      .join("\n\n");
    if (state.lastAgentChanges.length) {
      void refreshWorkspaceTree();
    }
    renderWorkbench();

    if (res.ok === false) {
      return res.message || "The agent could not run.";
    }
    let text = res.message || "(done)";
    if (state.lastAgentTranscript.length) {
      const steps = state.lastAgentTranscript
        .map((t) => `${t.is_error ? "⚠ " : ""}${t.tool}(${shortAgentArgs(t.input)})`)
        .join("  ·  ");
      text += `\n\n— ${res.model_name || "agent"} ran ${state.lastAgentTranscript.length} step(s): ${steps}`;
    }
    if (state.lastAgentChanges.length) {
      text += `\n\nChanged ${state.lastAgentChanges.length} file(s) — open the Changes tab in the Workbench to review.`;
    }
    return text;
  } catch (error) {
    return `Agent failed: ${error.message || error}`;
  }
}

document.querySelectorAll("[data-workbench-tab]").forEach((btn) => {
  btn.addEventListener("click", () => setWorkbenchTab(btn.dataset.workbenchTab));
});

els.workspaceRefresh?.addEventListener("click", () => {
  void refreshWorkspaceTree();
});

els.workspaceSearch?.addEventListener("input", (event) => {
  state.workbenchSearch = event.target.value || "";
  renderWorkspaceTree(state.workbenchTree);
});

els.agentToggle?.addEventListener("click", async () => {
  if (!state.agentMode && !state.agentWorkspace) {
    const picked = await chooseWorkspace();
    if (!picked) return;
    state.agentWorkspace = picked;
  }
  state.agentMode = !state.agentMode;
  saveState();
  renderAgentBar();
  renderWorkbench();
  if (state.agentMode) {
    void refreshWorkspaceTree();
  }
});

els.agentWorkspace?.addEventListener("click", async () => {
  const picked = await chooseWorkspace();
  if (picked) {
    state.agentWorkspace = picked;
    state.workbenchActiveFile = "";
    if (els.filePreviewPanel) els.filePreviewPanel.dataset.loadedPath = "";
    saveState();
    renderAgentBar();
    if (state.agentMode) {
      renderWorkbench();
      void refreshWorkspaceTree();
    }
  }
});

els.cpuButton.addEventListener("click", async () => {
  state.backendPreference = "cpu";
  if (service.available || (await refreshServiceStatus({ silent: true }))) {
    try {
      await apiFetch("/api/runtime/device", {
        method: "POST",
        timeoutMs: 10000,
        body: JSON.stringify({ preference: "cpu" })
      });
      await refreshServiceStatus({ silent: true });
    } catch (error) {
      service.lastError = error.message || "CPU preference failed";
    }
  }
  await backend.setMode("cpu");
  render();
});

els.gpuButton.addEventListener("click", async () => {
  state.backendPreference = "gpu";
  els.backendStatus.textContent = "GPU starting";
  if (service.available || (await refreshServiceStatus({ silent: true }))) {
    try {
      await apiFetch("/api/runtime/device", {
        method: "POST",
        timeoutMs: 10000,
        body: JSON.stringify({ preference: "cuda" })
      });
      await refreshServiceStatus({ silent: true });
    } catch (error) {
      service.lastError = error.message || "GPU preference failed";
    }
  }
  await backend.setMode("gpu");
  render();
});

els.clearChatButton.addEventListener("click", () => {
  state.chats[state.activeBotId] = [];
  render();
});

els.newBotButton.addEventListener("click", () => {
  const id = `bot-${crypto.randomUUID()}`;
  const bot = {
    id,
    name: "New Bot",
    color: COLORS[state.bots.length % COLORS.length],
    style: "direct",
    temperature: 45,
    persona: "A local AI bot shaped by the user's ratings, examples, and personal preferences.",
    corpus: [
      "Adapt to the user's preferred style and keep the answer useful.",
      "Ask for less only when a practical assumption would be risky."
    ],
    weights: []
  };
  state.bots.push(bot);
  state.activeBotId = id;
  trainBot(bot);
  queueCoreSync();
  render();
});

async function boot() {
  applyTheme();
  backend = new AccelerationBackend();
  await backend.setMode(state.backendPreference || "cpu");

  for (const bot of state.bots) {
    if (!bot.trainedAt) {
      trainBot(bot);
    }
  }

  await refreshServiceStatus({ silent: true });
  if (service.available) {
    void syncActiveCore();
  }
  void loadCoderConfig();
  render();
  renderWorkbench();
  if (state.agentMode && state.agentWorkspace) {
    void refreshWorkspaceTree();
  }
}

boot();
