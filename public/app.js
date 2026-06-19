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

const STARTER_TASKS = [
  {
    label: "Review project",
    prompt: "Review this project. Start by scanning the repo structure, identify the main components, then summarize risks, missing tests, and the safest next improvements.",
    agent: true
  },
  {
    label: "Explain repo",
    prompt: "Explain this repo in plain language: what it does, how it is organized, the main entry points, and how to run or test it.",
    agent: true
  },
  {
    label: "Fix failing tests",
    prompt: "Find and fix the failing tests. Inspect the test/build commands first, make the smallest safe change, then run verification and explain what changed.",
    agent: true
  },
  {
    label: "Find security risks",
    prompt: "Review the project for security risks. Focus on secrets, command execution, file access, network exposure, dependency risk, and unsafe auth or scan behavior.",
    agent: true
  },
  {
    label: "Create README",
    prompt: "Create or improve the README for this project with purpose, setup, run commands, test commands, features, and safety notes.",
    agent: true
  },
  {
    label: "Package for release",
    prompt: "Prepare a release plan for this project. Check package/build settings, list required verification, and identify any blockers before packaging.",
    agent: true
  },
  {
    label: "Issue / PR plan",
    prompt: "Create an issue and PR plan for this work: scope, files likely to change, test plan, risks, and review checklist.",
    agent: false
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
  repoIngestForm: document.querySelector("#repoIngestForm"),
  repoSourcesInput: document.querySelector("#repoSourcesInput"),
  repoIngestButton: document.querySelector("#repoIngestButton"),
  repoIngestStatus: document.querySelector("#repoIngestStatus"),
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
  modelStatusIndicator: document.querySelector("#modelStatusIndicator"),
  agentToggle: document.querySelector("#agentToggle"),
  agentWorkspace: document.querySelector("#agentWorkspace"),
  agentWsPath: document.querySelector("#agentWsPath"),
  trainingSourceList: document.querySelector("#trainingSourceList"),
  trainButton: document.querySelector("#trainButton"),
  trainingDataCount: document.querySelector("#trainingDataCount"),
  choiceCount: document.querySelector("#choiceCount"),
  modelState: document.querySelector("#modelState"),
  memoryList: document.querySelector("#memoryList"),
  projectBriefList: document.querySelector("#projectBriefList"),
  themeToggle: document.querySelector("#themeToggle"),
  appShell: document.querySelector(".app-shell"),
  workbench: document.querySelector("#workbench"),
  workbenchDivider: document.querySelector("#workbenchDivider"),
  workbenchMaximize: document.querySelector("#workbenchMaximize"),
  workbenchTablist: document.querySelector(".workbench-tablist"),
  workspaceRefresh: document.querySelector("#workspaceRefresh"),
  workspaceSearch: document.querySelector("#workspaceSearch"),
  workspaceTree: document.querySelector("#workspaceTree"),
  filePreviewPanel: document.querySelector("#filePreviewPanel"),
  changesPanel: document.querySelector("#changesPanel"),
  agentStepsPanel: document.querySelector("#agentStepsPanel"),
  verifyPanel: document.querySelector("#verifyPanel"),
  agentRunFlow: document.querySelector("#agentRunFlow"),
  bountyForm: document.querySelector("#bountyForm"),
  bountyProfile: document.querySelector("#bountyProfile"),
  bountyProfileHint: document.querySelector("#bountyProfileHint"),
  bountyClass: document.querySelector("#bountyClass"),
  bountyTarget: document.querySelector("#bountyTarget"),
  bountyScope: document.querySelector("#bountyScope"),
  bountyOutput: document.querySelector("#bountyOutput"),
  bountyOutputBrowse: document.querySelector("#bountyOutputBrowse"),
  bountyAuthorized: document.querySelector("#bountyAuthorized"),
  bountyPerFinding: document.querySelector("#bountyPerFinding"),
  bountyRunLive: document.querySelector("#bountyRunLive"),
  bountyRun: document.querySelector("#bountyRun"),
  bountyStatus: document.querySelector("#bountyStatus"),
  bountyReport: document.querySelector("#bountyReport"),
  bountyReportActions: document.querySelector("#bountyReportActions"),
  bountyCopyReport: document.querySelector("#bountyCopyReport"),
  redteamForm: document.querySelector("#redteamForm"),
  redteamBehavioral: document.querySelector("#redteamBehavioral"),
  redteamAuthorized: document.querySelector("#redteamAuthorized"),
  redteamRun: document.querySelector("#redteamRun"),
  redteamStatus: document.querySelector("#redteamStatus"),
  redteamReport: document.querySelector("#redteamReport"),
  redteamReportActions: document.querySelector("#redteamReportActions"),
  redteamCopyReport: document.querySelector("#redteamCopyReport"),
  toolkitForm: document.querySelector("#toolkitForm"),
  toolkitCategory: document.querySelector("#toolkitCategory"),
  toolkitClass: document.querySelector("#toolkitClass"),
  toolkitSearch: document.querySelector("#toolkitSearch"),
  toolkitStatus: document.querySelector("#toolkitStatus"),
  toolkitList: document.querySelector("#toolkitList")
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
    theme: "dark",
    workbenchTab: "preview",
    workbenchActiveFile: "",
    workbenchSearch: "",
    workbenchTree: [],
    workbenchViewedFiles: [],
    workbenchHeight: null,
    workbenchDocked: false,
    workbenchWrap: false,
    rollbackStatus: "",
    lastAgentSummary: "",
    lastAgentTranscript: [],
    lastAgentChanges: [],
    bountyProfile: "full-sweep",
    bountyClass: "",
    bountyScope: "",
    bountyOutput: "",
    bountyPerFinding: false,
    bountyRunLive: false,
    redteamBehavioral: false
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

function normalizeReplyPayload(payload, userText) {
  const diagnostics = payload?.diagnostics || {};
  return {
    text: payload?.message || "I am here with you. Give me a little more to work with and I will shape it.",
    citations: Array.isArray(payload?.citations) ? payload.citations : [],
    diagnostics: {
      used_fallback: Boolean(payload?.used_fallback || diagnostics.used_fallback),
      captured_for_training: Boolean(payload?.captured_for_training || diagnostics.captured_for_training),
      intent: diagnostics.intent || inferIntent(userText),
      mode: diagnostics.mode || "default",
      strategy: diagnostics.strategy || "local_engine",
      confidence: Number(payload?.confidence ?? diagnostics.confidence ?? 0),
      retrieval_count: Number(diagnostics.retrieval_count || 0),
      memory_count: Number(diagnostics.memory_count || 0),
      note_count: Number(diagnostics.note_count || 0),
      citation_count: Number(diagnostics.citation_count || payload?.citations?.length || 0),
      engine_ready: Boolean(diagnostics.engine_ready),
      device: diagnostics.device || payload?.device || "local"
    },
    modelName: payload?.model_name || "GreyIQ",
    device: payload?.device || diagnostics.device || "local"
  };
}

function normalizeAnswerForChat(answer, userText, strategy = "local_engine") {
  if (answer && typeof answer === "object" && "text" in answer) {
    return answer;
  }
  return {
    text: String(answer || "I am here with you. Give me a little more to work with and I will shape it."),
    citations: [],
    diagnostics: {
      used_fallback: false,
      captured_for_training: false,
      intent: inferIntent(userText),
      mode: strategy === "coding_agent" ? "agent" : "default",
      strategy,
      confidence: 0,
      retrieval_count: 0,
      memory_count: 0,
      note_count: 0,
      citation_count: 0,
      engine_ready: Boolean(service.available),
      device: service.status?.device || backend?.mode || "local"
    },
    modelName: strategy === "coding_agent" ? "coding-agent" : "GreyIQ",
    device: service.status?.device || backend?.mode || "local"
  };
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
      return normalizeReplyPayload(response, userText);
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
  const bestScore = adjusted[bestIndex] || 0;
  const confidence = Math.max(0.18, Math.min(0.74, 0.42 + bestScore * 0.18));
  return {
    text: candidates[bestIndex],
    citations: [],
    diagnostics: {
      used_fallback: true,
      captured_for_training: false,
      intent: inferIntent(userText),
      mode: "browser",
      strategy: "browser_ranker",
      confidence,
      retrieval_count: 0,
      memory_count: memories.length,
      note_count: 0,
      citation_count: 0,
      engine_ready: false,
      device: backend?.mode || "cpu"
    },
    modelName: "browser-ranker",
    device: backend?.mode || "cpu"
  };
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

function labelFromIdentifier(value) {
  return String(value || "")
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .trim();
}

function formatConfidence(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) {
    return "";
  }
  return `${Math.round(Math.max(0, Math.min(1, number)) * 100)}% confidence`;
}

function appendEvidenceChip(row, text) {
  if (!text) {
    return;
  }
  const chip = document.createElement("span");
  chip.className = "evidence-chip";
  chip.textContent = text;
  row.append(chip);
}

function renderMessageEvidence(article, message) {
  if (message.role !== "bot") {
    return;
  }

  const diagnostics = message.diagnostics || {};
  const citations = Array.isArray(message.citations) ? message.citations : [];
  const confidence = formatConfidence(diagnostics.confidence);
  const hasEvidence =
    confidence ||
    message.modelName ||
    diagnostics.strategy ||
    diagnostics.used_fallback ||
    citations.length > 0;

  if (!hasEvidence) {
    return;
  }

  const evidence = document.createElement("div");
  evidence.className = "message-evidence";
  const chips = document.createElement("div");
  chips.className = "evidence-chips";

  appendEvidenceChip(chips, diagnostics.used_fallback ? "Fallback" : "Local engine");
  appendEvidenceChip(chips, message.modelName || diagnostics.device);
  appendEvidenceChip(chips, labelFromIdentifier(diagnostics.strategy));
  appendEvidenceChip(chips, confidence);
  if (citations.length > 0) {
    appendEvidenceChip(chips, `${citations.length} source${citations.length === 1 ? "" : "s"}`);
  }

  evidence.append(chips);

  if (citations.length > 0) {
    const details = document.createElement("details");
    details.className = "source-list";
    const summary = document.createElement("summary");
    summary.textContent = "Sources";
    details.append(summary);

    for (const citation of citations.slice(0, 3)) {
      const item = document.createElement("article");
      item.className = "source-hit";
      const heading = document.createElement("strong");
      heading.textContent = citation.source || citation.source_id || "Local source";
      const score = document.createElement("small");
      const scoreValue = Number(citation.score || 0);
      score.textContent = Number.isFinite(scoreValue) && scoreValue > 0 ? `${Math.round(scoreValue * 100)}% match` : "";
      const excerpt = document.createElement("p");
      excerpt.textContent = citation.excerpt || "";
      item.append(heading, score, excerpt);
      details.append(item);
    }

    evidence.append(details);
  }

  const ratingBar = article.querySelector(".rating-bar");
  article.insertBefore(evidence, ratingBar);
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

function applyStarterTask(task) {
  if (!task || !els.promptInput) return;
  els.promptInput.value = task.prompt;
  els.promptInput.focus();
  els.promptInput.setSelectionRange(els.promptInput.value.length, els.promptInput.value.length);
  if (task.agent && state.agentWorkspace) {
    state.agentMode = true;
    state.workbenchDocked = true;
    renderAgentBar();
    renderWorkbench();
    void refreshWorkspaceTree();
  } else if (task.agent && els.agentWsPath) {
    els.agentWsPath.textContent = "Choose a workspace to run this with Agent mode";
  }
}

function renderStarterHome() {
  const home = document.createElement("section");
  home.className = "starter-home";
  const title = document.createElement("div");
  title.className = "starter-title";
  title.innerHTML = `
    <p class="eyebrow">GreyIQ Workbench</p>
    <h2>What should we work on?</h2>
    <p>Start with a prompt, or pick a task card. Repo-aware cards use Agent mode when a workspace is available.</p>
  `;
  const grid = document.createElement("div");
  grid.className = "starter-grid";
  STARTER_TASKS.forEach((task) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "starter-card";
    button.innerHTML = `
      <strong>${escapeHtml(task.label)}</strong>
      <span>${task.agent ? "Agent workspace" : "Chat plan"}</span>
    `;
    button.addEventListener("click", () => applyStarterTask(task));
    grid.append(button);
  });
  home.append(title, grid);
  els.messageStream.append(home);
}

function renderChat() {
  els.messageStream.replaceChildren();
  const chat = activeChat();
  if (!chat.length) {
    renderStarterHome();
    return;
  }
  for (const message of chat) {
    const fragment = els.messageTemplate.content.cloneNode(true);
    const article = fragment.querySelector(".message");
    const meta = fragment.querySelector(".message-meta");
    const body = fragment.querySelector(".message-body");
    const like = fragment.querySelector(".like");
    const dislike = fragment.querySelector(".dislike");

    article.classList.add(message.role === "user" ? "is-user" : "is-bot");
    meta.textContent = message.role === "user" ? "You" : activeBot().name;
    body.textContent = message.text;
    renderMessageEvidence(article, message);

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
  renderProjectBrief(memories, trainingStatus);
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
    const rawAnswer = state.agentMode && state.agentWorkspace ? await runAgent(text) : await replyFor(text);
    const answer = normalizeAnswerForChat(
      rawAnswer,
      text,
      state.agentMode && state.agentWorkspace ? "coding_agent" : "local_engine"
    );
    chat.push({
      id: crypto.randomUUID(),
      role: "bot",
      text: answer.text,
      citations: answer.citations,
      diagnostics: answer.diagnostics,
      modelName: answer.modelName,
      device: answer.device,
      createdAt: Date.now()
    });
  } catch (error) {
    chat.push({
      id: crypto.randomUUID(),
      role: "bot",
      text: `I hit a local runtime snag: ${error.message || "unknown error"}. The browser model is still available.`,
      citations: [],
      diagnostics: {
        used_fallback: true,
        strategy: "ui_exception",
        confidence: 0.12,
        intent: inferIntent(text),
        mode: "browser"
      },
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

els.repoIngestForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const sources = els.repoSourcesInput.value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (sources.length === 0) {
    els.repoIngestStatus.textContent = "Add at least one repo path or URL.";
    return;
  }
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    els.repoIngestStatus.textContent = "Start the GreyIQ backend before ingesting repositories.";
    return;
  }

  els.repoIngestButton.disabled = true;
  els.repoIngestStatus.textContent = "Ingesting repositories...";
  try {
    const payload = await apiFetch("/api/repos/ingest", {
      method: "POST",
      timeoutMs: 240000,
      body: JSON.stringify({
        sources,
        max_total_chars: 4000000,
        max_files_per_repo: 900
      })
    });
    const summary = payload.summary || {};
    state.selectedTrainingSources = normalizeSelectedTrainingSources([
      ...state.selectedTrainingSources,
      "src_imported_docs"
    ]);
    addMemory({
      kind: "training_data",
      sourceId: "src_imported_docs",
      text: `Repository ingest: ${summary.ingested || 0} repo(s), ${summary.files_added || 0} file(s), ${summary.characters_added || 0} characters.`
    });
    els.repoIngestStatus.textContent = `Ingested ${summary.ingested || 0} repo(s), ${summary.files_added || 0} file(s).`;
    await refreshServiceStatus({ silent: true });
  } catch (error) {
    els.repoIngestStatus.textContent = error.message || "Repository ingest failed.";
  } finally {
    els.repoIngestButton.disabled = false;
    renderTrainingSources();
    renderBackend();
    saveState();
  }
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
  els.trainingFolderStatus.textContent = "Reading folder and ingesting files... this can take a while for large folders.";
  try {
    const result = await apiFetch("/api/train/folder", {
      method: "POST",
      timeoutMs: 300000,
      body: JSON.stringify({ folder })
    });
    els.trainingFolderStatus.textContent = result.message || "Folder added to training data.";
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
  updateModelStatusIndicator();
}

function updateModelStatusIndicator(text, stateName = "ready") {
  if (!els.modelStatusIndicator) return;
  const provider = els.brainProvider?.value || "off";
  let label = text;
  let tone = stateName;
  if (!label) {
    if (provider === "off") {
      label = "Local only / cloud disabled";
      tone = "local";
    } else if (provider === "local") {
      label = "Local model ready";
      tone = "ready";
    } else {
      label = `${labelFromIdentifier(provider)} model selected`;
      tone = "cloud";
    }
  }
  els.modelStatusIndicator.dataset.state = tone;
  const textEl = els.modelStatusIndicator.querySelector("span:last-child");
  if (textEl) textEl.textContent = label;
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
  updateModelStatusIndicator();
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
    updateModelStatusIndicator();
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
    updateModelStatusIndicator("Model needs setup", "setup");
    return;
  }
  try {
    const info = await apiFetch("/api/coder/models", { timeoutMs: 6000 });
    if (info.ok === false) {
      els.brainModelStatus.textContent = info.error || "Ollama not reachable — is it running?";
      els.brainDownload.hidden = false;
      updateModelStatusIndicator("Model needs setup", "setup");
      return;
    }
    if (info.present) {
      els.brainModelStatus.textContent = `Model installed: ${info.configured} ✓`;
      els.brainDownload.hidden = true;
      updateModelStatusIndicator("Local model ready", "ready");
    } else {
      els.brainModelStatus.textContent = `${info.configured || "Model"} not installed.`;
      els.brainDownload.hidden = false;
      updateModelStatusIndicator("Model needs setup", "setup");
    }
  } catch (error) {
    els.brainModelStatus.textContent = error.message || "Could not check the model.";
    updateModelStatusIndicator("Model needs setup", "setup");
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
      updateModelStatusIndicator("Downloading model", "downloading");
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
  updateModelStatusIndicator("Downloading model", "downloading");
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

const WORKBENCH_TABS = ["preview", "changes", "steps", "verify"];

function applyWorkbenchSize() {
  if (!els.appShell) return;
  const docked = Boolean(state.workbenchDocked);
  // Docked = workbench fills the left, chat docks to the right at ~1/3 (CSS).
  els.appShell.classList.toggle("wb-docked", docked);
  if (!docked) {
    const height = (typeof state.workbenchHeight === "number" && state.workbenchHeight > 0)
      ? state.workbenchHeight
      : Math.round(window.innerHeight * 0.44);
    els.appShell.style.setProperty("--workbench-h", `${height}px`);
    if (els.workbenchDivider) {
      // Expose the splitter's value/bounds so screen readers announce resizing.
      els.workbenchDivider.setAttribute("aria-valuemin", String(8 * 16));
      els.workbenchDivider.setAttribute("aria-valuemax", String(Math.round(window.innerHeight * 0.88)));
      els.workbenchDivider.setAttribute("aria-valuenow", String(height));
    }
  }
  if (els.workbenchMaximize) {
    els.workbenchMaximize.setAttribute("aria-pressed", String(docked));
    els.workbenchMaximize.textContent = docked ? "⤡" : "⤢";
    const label = docked ? "Restore split (chat below)" : "Dock workbench (chat to the right)";
    els.workbenchMaximize.title = label;
    els.workbenchMaximize.setAttribute("aria-label", label);
  }
}

function renderWorkbench() {
  if (!els.workbench) return;
  const on = Boolean(state.agentMode);
  els.workbench.hidden = !on;
  els.appShell?.classList.toggle("is-agent", on);
  document.body.classList.toggle("agent-active", on);
  if (!on) return;
  applyWorkbenchSize();
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
  renderAgentRunFlow();
}

function setWorkbenchTab(tabName, focusTab = false) {
  const tab = WORKBENCH_TABS.includes(tabName) ? tabName : "preview";
  state.workbenchTab = tab;
  document.querySelectorAll("[data-workbench-tab]").forEach((btn) => {
    const active = btn.dataset.workbenchTab === tab;
    btn.classList.toggle("is-active", active);
    btn.setAttribute("aria-selected", String(active));
    btn.tabIndex = active ? 0 : -1;
    if (active && focusTab) btn.focus();
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

// Folders the user has expanded (collapsed by default so a deep repo stays
// readable). Persists across re-renders for the session.
const expandedDirs = new Set();

function isSecurityRelatedPath(path) {
  return /(^|\/)(\.env|secrets?|auth|security|crypto|token|keys?|permissions?|bughunter|trust)(\/|\.|$)/i.test(path || "");
}

function fileMarker(entry) {
  const path = entry.path || "";
  const viewed = Array.isArray(state.workbenchViewedFiles) && state.workbenchViewedFiles.includes(path);
  const change = (Array.isArray(state.lastAgentChanges) ? state.lastAgentChanges : []).find((item) => item.path === path);
  if (change) {
    if (change.operation === "write_file" && !change.existed) return { label: "created", cls: "created" };
    return { label: "changed", cls: "changed" };
  }
  if (isSecurityRelatedPath(path)) return { label: "risky", cls: "risky" };
  if (viewed) return { label: "viewed", cls: "viewed" };
  return null;
}

function makeTreeButton(entry, depth, isDir, fullPath) {
  const node = document.createElement("button");
  node.type = "button";
  const isActive = !isDir && entry.path === state.workbenchActiveFile;
  node.className = `workspace-tree-item${isDir ? " is-dir" : ""}${isActive ? " is-active" : ""}`;
  node.style.paddingLeft = `${0.4 + depth * 0.8}rem`;
  node.title = entry.path;
  node.setAttribute("role", "treeitem");
  node.setAttribute("aria-level", String(depth + 1));

  const icon = document.createElement("span");
  icon.className = "tree-icon";
  icon.setAttribute("aria-hidden", "true");
  const label = document.createElement("span");
  label.className = "tree-label";
  label.textContent = fullPath ? entry.path : entry.name;
  const markerInfo = !isDir ? fileMarker(entry) : null;
  const marker = document.createElement("span");
  if (markerInfo) {
    marker.className = `tree-marker is-${markerInfo.cls}`;
    marker.textContent = markerInfo.label;
  }

  if (isDir) {
    const open = expandedDirs.has(entry.path);
    node.setAttribute("aria-expanded", String(open));
    icon.textContent = open ? "▾" : "▸";
    node.addEventListener("click", () => {
      if (expandedDirs.has(entry.path)) expandedDirs.delete(entry.path);
      else expandedDirs.add(entry.path);
      renderWorkspaceTree(state.workbenchTree);
      [...els.workspaceTree.querySelectorAll(".workspace-tree-item")]
        .find((el) => el.title === entry.path)
        ?.focus();
    });
  } else {
    icon.textContent = ""; // spacer keeps file labels aligned under the chevrons
    if (isActive) node.setAttribute("aria-current", "true");
    node.addEventListener("click", () => openWorkspaceFile(entry.path));
  }
  node.append(icon, label);
  if (markerInfo) node.append(marker);
  return node;
}

function renderWorkspaceTree(entries, truncated = false) {
  if (!els.workspaceTree) return;
  const list = Array.isArray(entries) ? entries : [];
  const search = (state.workbenchSearch || "").trim().toLowerCase();
  els.workspaceTree.replaceChildren();

  if (!list.length) {
    els.workspaceTree.append(
      makeHint(state.agentWorkspace ? "No files to show." : "Set a workspace folder to browse its files.")
    );
    return;
  }

  // Search: flat list of matching files (full path), ignoring the tree structure.
  if (search) {
    const matches = list.filter((entry) => entry.type === "file" && entry.path.toLowerCase().includes(search));
    if (!matches.length) {
      els.workspaceTree.append(makeHint("No files match your filter."));
      return;
    }
    matches.forEach((entry, index) => {
      const node = makeTreeButton(entry, 0, false, true);
      node.tabIndex = index === 0 ? 0 : -1;
      els.workspaceTree.append(node);
    });
    return;
  }

  // Collapsible tree: group the flat list by parent, render only expanded branches.
  const byParent = new Map();
  for (const entry of list) {
    const slash = entry.path.lastIndexOf("/");
    const parent = slash >= 0 ? entry.path.slice(0, slash) : "";
    if (!byParent.has(parent)) byParent.set(parent, []);
    byParent.get(parent).push(entry);
  }
  const rows = [];
  const walk = (parent, depth) => {
    for (const entry of byParent.get(parent) || []) {
      const isDir = entry.type === "dir";
      rows.push({ entry, depth, isDir });
      if (isDir && expandedDirs.has(entry.path)) walk(entry.path, depth + 1);
    }
  };
  walk("", 0);

  if (!rows.length) {
    els.workspaceTree.append(makeHint("No files to show."));
    return;
  }
  const activeIdx = rows.findIndex((row) => row.entry.path === state.workbenchActiveFile);
  const tabStop = activeIdx >= 0 ? activeIdx : 0;
  rows.forEach((row, index) => {
    const node = makeTreeButton(row.entry, row.depth, row.isDir, false);
    node.tabIndex = index === tabStop ? 0 : -1;
    els.workspaceTree.append(node);
  });
  if (truncated) {
    els.workspaceTree.append(makeHint("… list truncated (large workspace)."));
  }
}

async function openWorkspaceFile(path) {
  state.workbenchActiveFile = path;
  const viewed = Array.isArray(state.workbenchViewedFiles) ? state.workbenchViewedFiles : [];
  state.workbenchViewedFiles = [path, ...viewed.filter((item) => item !== path)].slice(0, 80);
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

// ---- Lightweight, safe syntax highlighting (no external library) ----
const HL_KEYWORDS = {
  js: new Set(
    ("const let var function return if else for while do switch case break continue new class extends " +
      "super this typeof instanceof in of try catch finally throw async await yield import export from " +
      "default null undefined true false void delete static get set").split(" ")
  ),
  py: new Set(
    ("def return if elif else for while break continue class import from as try except finally raise with " +
      "lambda yield global nonlocal pass assert del in is not and or None True False async await print self").split(" ")
  ),
  shell: new Set("if then else elif fi for while do done case esac function in return export local set echo".split(" ")),
  config: new Set("true false null yes no on off".split(" "))
};
// Languages we colorize; anything else renders as plain (escaped) text.
const HL_LANGS = new Set(["js", "py", "shell", "config", "json", "css"]);

function langFromPath(path) {
  const ext = String(path || "").split(".").pop().toLowerCase();
  if (["js", "mjs", "cjs", "jsx", "ts", "tsx"].includes(ext)) return "js";
  if (ext === "json") return "json";
  if (ext === "py") return "py";
  if (["css", "scss", "less", "sass"].includes(ext)) return "css";
  if (["sh", "bash", "zsh", "ps1", "bat", "cmd"].includes(ext)) return "shell";
  if (["yml", "yaml", "toml", "ini", "cfg", "conf", "properties", "env"].includes(ext)) return "config";
  return "";
}

function highlightCode(text, lang) {
  if (!HL_LANGS.has(lang)) return escapeHtml(text);
  const kw = HL_KEYWORDS[lang];
  const rules = [];
  if (lang === "js" || lang === "css") rules.push(["comment", /\/\*[\s\S]*?\*\/|\/\/[^\n]*/y]);
  else if (lang === "py" || lang === "shell" || lang === "config") rules.push(["comment", /#[^\n]*/y]);
  rules.push(["string", /"(?:\\.|[^"\\\n])*"?|'(?:\\.|[^'\\\n])*'?|`(?:\\.|[^`\\])*`?/y]);
  rules.push(["number", /\b\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?\b/y]);
  rules.push(["ident", /[A-Za-z_$][\w$]*/y]);
  rules.push(["space", /\s+/y]);
  rules.push(["other", /[^]/y]);

  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    let consumed = false;
    for (const [type, re] of rules) {
      re.lastIndex = i;
      const m = re.exec(text);
      if (!m || m.index !== i || m[0].length === 0) continue;
      const chunk = m[0];
      let cls = "";
      if (type === "comment") cls = "tok-comment";
      else if (type === "string") {
        cls = "tok-string";
        if (lang === "json") {
          let j = i + chunk.length;
          while (j < n && (text[j] === " " || text[j] === "\t")) j += 1;
          if (text[j] === ":") cls = "tok-key";
        }
      } else if (type === "number") cls = "tok-number";
      else if (type === "ident") {
        if (kw && kw.has(chunk)) cls = "tok-keyword";
        else {
          let j = i + chunk.length;
          while (j < n && text[j] === " ") j += 1;
          if (text[j] === "(") cls = "tok-func";
        }
      }
      const safe = escapeHtml(chunk);
      out += cls ? `<span class="${cls}">${safe}</span>` : safe;
      i += chunk.length;
      consumed = true;
      break;
    }
    if (!consumed) {
      out += escapeHtml(text[i]);
      i += 1;
    }
  }
  return out;
}

function renderFilePreview(file) {
  if (!els.filePreviewPanel) return;
  els.filePreviewPanel.replaceChildren();
  if (!file) {
    els.filePreviewPanel.dataset.loadedPath = "";
    els.filePreviewPanel.append(makeHint("Select a file from the workspace to preview it here."));
    return;
  }

  const bar = document.createElement("div");
  bar.className = "code-toolbar";
  const pathEl = document.createElement("span");
  pathEl.className = "code-path";
  pathEl.textContent = file.path || state.workbenchActiveFile || "";
  bar.append(pathEl);

  if (file.ok === false) {
    els.filePreviewPanel.dataset.loadedPath = "";
    els.filePreviewPanel.append(bar, makeHint(file.error || "Could not read this file.", true));
    return;
  }

  const wrapBtn = document.createElement("button");
  wrapBtn.type = "button";
  wrapBtn.className = "code-wrap-toggle";
  const setWrapLabel = () => {
    wrapBtn.textContent = state.workbenchWrap ? "Wrap: on" : "Wrap: off";
    wrapBtn.setAttribute("aria-pressed", String(Boolean(state.workbenchWrap)));
  };
  setWrapLabel();
  const trustInfo = file.trust && typeof file.trust === "object" ? file.trust : null;
  if (trustInfo) {
    const trustBadge = document.createElement("span");
    trustBadge.className = `trust-badge trust-${trustInfo.level || "caution"}`;
    trustBadge.textContent = trustInfo.label || "Review content";
    const patterns = Array.isArray(trustInfo.patterns) && trustInfo.patterns.length
      ? ` Patterns: ${trustInfo.patterns.join(", ")}.`
      : "";
    trustBadge.title = `${trustInfo.summary || "Treat workspace content as data."}${patterns}`;
    bar.append(trustBadge);
  }
  bar.append(wrapBtn);
  els.filePreviewPanel.append(bar);

  const content = file.content || "";
  const lines = content.split("\n");
  const view = document.createElement("div");
  view.className = `code-view${state.workbenchWrap ? " is-wrap" : ""}`;

  const gutter = document.createElement("pre");
  gutter.className = "code-gutter";
  gutter.setAttribute("aria-hidden", "true");
  gutter.textContent = lines.map((_, index) => index + 1).join("\n");

  const body = document.createElement("pre");
  body.className = "code-body";
  const code = document.createElement("code");
  const lang = langFromPath(file.path || "");
  // Guard the highlighter against pathological files (keeps the UI responsive).
  const tooBig = lines.length > 2500 || content.length > 100000;
  if (tooBig || !lang) {
    code.textContent = content;
  } else {
    code.innerHTML = highlightCode(content, lang);
  }
  body.append(code);
  view.append(gutter, body);
  els.filePreviewPanel.append(view);

  if (file.truncated) {
    els.filePreviewPanel.append(makeHint(`Preview truncated — showing the start of ${file.size} bytes.`));
  }

  wrapBtn.addEventListener("click", () => {
    state.workbenchWrap = !state.workbenchWrap;
    saveState();
    view.classList.toggle("is-wrap", state.workbenchWrap);
    setWrapLabel();
  });

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
    head.setAttribute("aria-expanded", "false");
    head.setAttribute(
      "aria-label",
      `${step.tool || "tool"} ${shortAgentArgs(step.input)} — ${step.is_error ? "error" : "ok"}; show output`
    );
    head.innerHTML =
      `<span class="agent-step-status" aria-hidden="true">${step.is_error ? "✕" : "✓"}</span>` +
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
      head.setAttribute("aria-expanded", String(!full.hidden));
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
    const status = document.createElement("span");
    status.className = "verify-status";
    status.setAttribute("aria-hidden", "true");
    status.textContent = failed ? "✕" : "✓";
    // Status word for screen readers (the glyph is decorative + color isn't enough).
    const srStatus = document.createElement("span");
    srStatus.className = "visually-hidden";
    srStatus.textContent = failed ? "failed: " : "passed: ";
    const labelText = document.createElement("span");
    labelText.textContent = step.tool === "verify" ? "verify" : `run: ${shortAgentArgs(step.input)}`;
    label.append(status, srStatus, labelText);
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
  const actions = document.createElement("div");
  actions.className = "change-actions";
  const status = document.createElement("span");
  status.className = `change-rollback-status${state.rollbackStatus?.startsWith("Could not") ? " is-error" : ""}`;
  status.textContent = state.rollbackStatus || "Review the saved before/after snapshot before undoing.";
  const undo = document.createElement("button");
  undo.type = "button";
  undo.className = "change-rollback";
  undo.textContent = "Undo last run";
  undo.addEventListener("click", () => {
    void rollbackLastAgentRun(undo);
  });
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "change-rollback";
  copy.textContent = "Copy summary";
  copy.disabled = !state.lastAgentSummary;
  copy.addEventListener("click", () => copyAgentSummary(copy));
  actions.append(status, copy, undo);
  els.changesPanel.append(actions);
  list.forEach((change) => {
    const op =
      change.operation === "write_file" ? (change.existed ? "rewrote" : "created") : "edited";
    const card = document.createElement("div");
    card.className = "change-file";
    const head = document.createElement("button");
    head.type = "button";
    head.className = "change-file-head";
    head.setAttribute("aria-expanded", "false");
    head.setAttribute("aria-label", `${op} ${change.path || ""} — show diff`);
    head.innerHTML =
      `<span class="change-op">${escapeHtml(op)}</span>` +
      `<span class="change-path">${escapeHtml(change.path || "")}</span>`;
    const body = document.createElement("div");
    body.className = "change-preview";
    body.hidden = true;
    body.append(buildDiffView(change));
    head.addEventListener("click", () => {
      body.hidden = !body.hidden;
      head.setAttribute("aria-expanded", String(!body.hidden));
    });
    card.append(head, body);
    els.changesPanel.append(card);
  });
}

async function copyAgentSummary(button) {
  const changes = Array.isArray(state.lastAgentChanges) ? state.lastAgentChanges : [];
  const verify = verificationSummary(state.lastAgentTranscript);
  const risk = changeRiskSummary(changes);
  const summary = [
    state.lastAgentSummary || "No agent summary available.",
    "",
    `Files changed: ${changes.length}`,
    `Verification: ${verify.label}`,
    `Risk level: ${risk.label}`,
    changes.length ? `Changed files: ${changes.map((change) => change.path).join(", ")}` : ""
  ].filter(Boolean).join("\n");
  try {
    await navigator.clipboard.writeText(summary);
    if (button) {
      const old = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => {
        button.textContent = old;
      }, 1400);
    }
  } catch (_) {
    window.prompt("Copy agent summary:", summary);
  }
}

function verificationSummary(transcript) {
  const steps = (Array.isArray(transcript) ? transcript : []).filter(
    (step) => step.tool === "verify" || step.tool === "run_command"
  );
  if (!steps.length) return { label: "verification not run", failed: false, count: 0 };
  const failed = steps.some((step) => {
    const out = typeof step.output === "string" ? step.output : JSON.stringify(step.output || "");
    return Boolean(step.is_error) || /VERIFY FAILED|FAIL\s|exit=[1-9]/.test(out);
  });
  return {
    label: failed ? `${steps.length} verification step(s), review needed` : `${steps.length} verification step(s) passed`,
    failed,
    count: steps.length
  };
}

function changeRiskSummary(changes) {
  const list = Array.isArray(changes) ? changes : [];
  const risky = list.some((change) => isSecurityRelatedPath(change.path || ""));
  if (risky) return { label: "Elevated", tone: "warn" };
  if (list.length > 3) return { label: "Medium", tone: "mid" };
  return { label: list.length ? "Low" : "None", tone: "ok" };
}

function runFlowStep(label, detail, stateName) {
  const item = document.createElement("article");
  item.className = `run-flow-step is-${stateName}`;
  item.innerHTML = `<strong>${escapeHtml(label)}</strong><span>${escapeHtml(detail)}</span>`;
  return item;
}

function renderAgentRunFlow() {
  if (!els.agentRunFlow) return;
  const transcript = Array.isArray(state.lastAgentTranscript) ? state.lastAgentTranscript : [];
  const changes = Array.isArray(state.lastAgentChanges) ? state.lastAgentChanges : [];
  const verify = verificationSummary(transcript);
  const risk = changeRiskSummary(changes);
  const hasRun = transcript.length || changes.length || state.lastAgentSummary;
  els.agentRunFlow.replaceChildren();
  els.agentRunFlow.append(
    runFlowStep("Plan", hasRun ? `${transcript.length || 1} agent step(s)` : "Waiting for an Agent task", hasRun ? "done" : "idle"),
    runFlowStep("Change", changes.length ? `${changes.length} file(s) changed` : "No file changes", changes.length ? "done" : "idle"),
    runFlowStep("Verify", verify.label, verify.failed ? "warn" : verify.count ? "done" : "idle"),
    runFlowStep("Explain", state.lastAgentSummary ? "Summary available" : "No explanation yet", state.lastAgentSummary ? "done" : "idle")
  );

  const trust = document.createElement("div");
  trust.className = `run-flow-trust is-${risk.tone}`;
  trust.innerHTML = `
    <span>Risk: ${escapeHtml(risk.label)}</span>
    <span>Files: ${changes.length}</span>
    <span>${escapeHtml(verify.label)}</span>
  `;
  const actions = document.createElement("div");
  actions.className = "run-flow-actions";
  const openDiff = document.createElement("button");
  openDiff.type = "button";
  openDiff.textContent = "Open diff";
  openDiff.disabled = !changes.length;
  openDiff.addEventListener("click", () => setWorkbenchTab("changes", true));
  const copy = document.createElement("button");
  copy.type = "button";
  copy.textContent = "Copy summary";
  copy.disabled = !state.lastAgentSummary;
  copy.addEventListener("click", () => copyAgentSummary(copy));
  actions.append(openDiff, copy);
  els.agentRunFlow.append(trust, actions);
}

async function rollbackLastAgentRun(button) {
  const changes = Array.isArray(state.lastAgentChanges) ? state.lastAgentChanges : [];
  if (!changes.length) return;
  if (!state.agentWorkspace) {
    state.rollbackStatus = "Could not undo: no workspace is selected.";
    renderChangesPanel(changes);
    return;
  }
  const confirmed = window.confirm(
    "Undo the last agent run in this workspace? Files changed after the run will not be overwritten."
  );
  if (!confirmed) return;
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    state.rollbackStatus = "Could not undo: local GreyIQ service is not running.";
    renderChangesPanel(changes);
    return;
  }
  if (button) button.disabled = true;
  state.rollbackStatus = "Undoing last run...";
  renderChangesPanel(changes);
  try {
    const res = await apiFetch("/api/workspace/rollback", {
      method: "POST",
      timeoutMs: 60000,
      body: JSON.stringify({ workspace: state.agentWorkspace, changes })
    });
    if (res.ok === false) {
      const detail = Array.isArray(res.errors) && res.errors.length ? ` ${res.errors.join(" ")}` : "";
      state.rollbackStatus = `Could not undo every file.${detail}`;
    } else {
      const restored = Array.isArray(res.restored) ? res.restored.length : 0;
      const deleted = Array.isArray(res.deleted) ? res.deleted.length : 0;
      state.rollbackStatus = `Undone: restored ${restored}, deleted ${deleted}.`;
      state.lastAgentChanges = [];
      state.lastAgentTranscript = [];
      state.lastAgentSummary = "";
      state.workbenchActiveFile = "";
      if (els.filePreviewPanel) els.filePreviewPanel.dataset.loadedPath = "";
      void refreshWorkspaceTree();
    }
  } catch (error) {
    state.rollbackStatus = `Could not undo: ${error.message || error}`;
  } finally {
    renderWorkbench();
  }
}

function briefItem(label, value) {
  const item = document.createElement("article");
  item.className = "brief-item";
  const heading = document.createElement("strong");
  heading.textContent = label;
  const body = document.createElement("span");
  body.textContent = value;
  item.append(heading, body);
  return item;
}

function renderProjectBrief(memories, trainingStatus) {
  if (!els.projectBriefList) return;
  const changed = Array.isArray(state.lastAgentChanges) ? state.lastAgentChanges.length : 0;
  const verified = verificationSummary(state.lastAgentTranscript);
  const notes = memories.filter((memory) => memory.kind === "preference" || memory.kind === "training_data").length;
  els.projectBriefList.replaceChildren(
    briefItem("Purpose", "Local-first GreyIQ chat, coding agent, Workbench, memory, rollback, verification, and BugHunter."),
    briefItem("Tech stack", "Static browser UI, Node/Electron shell, Python API/runtime, local model support."),
    briefItem("Run commands", "npm run start, npm run backend, npm run desktop, npm run check."),
    briefItem("Key files", "public/app.js, public/styles.css, backend/agent.py, backend/workspace.py, backend/greyiq_api.py."),
    briefItem("User notes", notes ? `${notes} saved preference/source item(s).` : "No project notes saved yet."),
    briefItem("Last scan", changed ? `${changed} file(s) changed; ${verified.label}.` : (trainingStatus || "No agent run yet."))
  );
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
    state.lastAgentSummary = res.message || "";
    state.rollbackStatus = "";
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

// Tab keyboard navigation (WAI-ARIA tabs pattern).
els.workbenchTablist?.addEventListener("keydown", (event) => {
  const idx = WORKBENCH_TABS.indexOf(state.workbenchTab);
  let next = -1;
  if (event.key === "ArrowRight") next = (idx + 1) % WORKBENCH_TABS.length;
  else if (event.key === "ArrowLeft") next = (idx - 1 + WORKBENCH_TABS.length) % WORKBENCH_TABS.length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = WORKBENCH_TABS.length - 1;
  else return;
  event.preventDefault();
  setWorkbenchTab(WORKBENCH_TABS[next], true);
});

// File-tree roving focus (arrow keys move the single tab stop).
els.workspaceTree?.addEventListener("keydown", (event) => {
  const items = [...els.workspaceTree.querySelectorAll(".workspace-tree-item")];
  if (!items.length) return;
  let idx = items.indexOf(document.activeElement);
  if (idx < 0) idx = 0;
  if (event.key === "ArrowDown") idx = Math.min(items.length - 1, idx + 1);
  else if (event.key === "ArrowUp") idx = Math.max(0, idx - 1);
  else if (event.key === "Home") idx = 0;
  else if (event.key === "End") idx = items.length - 1;
  else return;
  event.preventDefault();
  items.forEach((item, k) => {
    item.tabIndex = k === idx ? 0 : -1;
  });
  items[idx].focus();
});

// Resizable chat <-> workbench split (drag the divider, or arrow keys).
function setWorkbenchHeightPx(px) {
  const min = 8 * 16;
  const max = Math.round(window.innerHeight * 0.88);
  state.workbenchHeight = Math.max(min, Math.min(max, Math.round(px)));
  state.workbenchDocked = false;
  applyWorkbenchSize();
}

if (els.workbenchDivider) {
  let dragging = false;
  // Slide the workbench (almost) to the top → snap into docked mode (chat right).
  const dockThreshold = () => window.innerHeight * 0.9;
  const stop = (event) => {
    if (!dragging) return;
    dragging = false;
    document.body.classList.remove("is-resizing");
    els.workbenchDivider.releasePointerCapture?.(event.pointerId);
    saveState();
  };
  const onMove = (event) => {
    if (!dragging) return;
    const height = window.innerHeight - event.clientY;
    if (height >= dockThreshold()) {
      state.workbenchDocked = true;
      applyWorkbenchSize();
      saveState();
      stop(event); // end the drag; the divider hides in docked mode
      els.workbenchMaximize?.focus(); // keep keyboard focus on a visible control
      return;
    }
    setWorkbenchHeightPx(height);
  };
  els.workbenchDivider.addEventListener("pointerdown", (event) => {
    dragging = true;
    document.body.classList.add("is-resizing");
    els.workbenchDivider.setPointerCapture?.(event.pointerId);
    event.preventDefault();
  });
  els.workbenchDivider.addEventListener("pointermove", onMove);
  els.workbenchDivider.addEventListener("pointerup", stop);
  els.workbenchDivider.addEventListener("pointercancel", stop);
  els.workbenchDivider.addEventListener("keydown", (event) => {
    const current =
      (typeof state.workbenchHeight === "number" && state.workbenchHeight) ||
      Math.round(window.innerHeight * 0.44);
    if (event.key === "ArrowUp") setWorkbenchHeightPx(current + 24);
    else if (event.key === "ArrowDown") setWorkbenchHeightPx(current - 24);
    else if (event.key === "Home") {
      state.workbenchDocked = true; // slide all the way up → dock chat to the right
      applyWorkbenchSize();
      els.workbenchMaximize?.focus(); // divider hides when docked; keep focus visible
    } else if (event.key === "End") {
      setWorkbenchHeightPx(8 * 16);
    } else {
      return;
    }
    event.preventDefault();
    saveState();
  });
}

els.workbenchMaximize?.addEventListener("click", () => {
  state.workbenchDocked = !state.workbenchDocked;
  applyWorkbenchSize();
  saveState();
});

window.addEventListener("resize", () => {
  if (state.agentMode) applyWorkbenchSize();
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

// ---- Bug bounty hunt (scan a target → report with attack plans) ----
let bountyProfilesData = [];

async function loadBountyProfiles() {
  if (!els.bountyProfile) return;
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) return;
  let info;
  try {
    info = await apiFetch("/api/bounty/types", { timeoutMs: 6000 });
  } catch (_) {
    return;
  }
  if (!info || info.ok === false) return;
  bountyProfilesData = Array.isArray(info.profiles) ? info.profiles : [];
  els.bountyProfile.replaceChildren();
  for (const profile of bountyProfilesData) {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = profile.name;
    els.bountyProfile.append(option);
  }
  if (bountyProfilesData.some((p) => p.id === state.bountyProfile)) {
    els.bountyProfile.value = state.bountyProfile;
  } else if (bountyProfilesData.length) {
    state.bountyProfile = bountyProfilesData[0].id;
  }
  if (els.bountyClass) {
    const classes = Array.isArray(info.classes) ? info.classes : [];
    els.bountyClass.replaceChildren();
    const any = document.createElement("option");
    any.value = "";
    any.textContent = "Any class found";
    els.bountyClass.append(any);
    for (const cls of classes) {
      const option = document.createElement("option");
      option.value = cls.id;
      option.textContent = cls.name;
      els.bountyClass.append(option);
    }
    els.bountyClass.value = state.bountyClass || "";
  }
  if (els.bountyScope) els.bountyScope.value = state.bountyScope || "";
  if (els.bountyOutput) els.bountyOutput.value = state.bountyOutput || "";
  if (els.bountyPerFinding) els.bountyPerFinding.checked = Boolean(state.bountyPerFinding);
  if (els.bountyRunLive) els.bountyRunLive.checked = Boolean(state.bountyRunLive);
  updateBountyHint();
}

function updateBountyHint() {
  if (!els.bountyProfileHint) return;
  const profile = bountyProfilesData.find((p) => p.id === els.bountyProfile?.value);
  if (!profile) {
    els.bountyProfileHint.textContent = "";
    return;
  }
  const names = new Map(Array.from(els.bountyClass?.options || []).map((option) => [option.value, option.textContent]));
  const focus = Array.isArray(profile.classes)
    ? profile.classes.map((id) => names.get(id) || id).filter(Boolean).slice(0, 6)
    : [];
  els.bountyProfileHint.textContent = focus.length
    ? `${profile.description} Focuses: ${focus.join(", ")}.`
    : profile.description;
}

els.bountyProfile?.addEventListener("change", () => {
  state.bountyProfile = els.bountyProfile.value;
  saveState();
  updateBountyHint();
});

els.bountyClass?.addEventListener("change", () => {
  state.bountyClass = els.bountyClass.value;
  saveState();
});

if (desktopFolderPicker && els.bountyOutputBrowse) {
  els.bountyOutputBrowse.hidden = false;
}

els.bountyOutputBrowse?.addEventListener("click", async () => {
  const picked = await chooseTrainingFolder();
  if (picked) {
    els.bountyOutput.value = picked;
    state.bountyOutput = picked;
    saveState();
  }
});

els.bountyForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = (els.bountyTarget?.value || "").trim();
  if (!target) {
    els.bountyStatus.textContent = "Enter a target URL or folder/repo path.";
    return;
  }
  if (!els.bountyAuthorized?.checked) {
    els.bountyStatus.textContent = "Confirm you're authorized to test this target (tick the box).";
    return;
  }
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    els.bountyStatus.textContent = "Local GreyIQ service is not running.";
    return;
  }
  state.bountyProfile = els.bountyProfile.value;
  state.bountyClass = els.bountyClass.value;
  state.bountyScope = (els.bountyScope?.value || "").trim();
  state.bountyOutput = (els.bountyOutput?.value || "").trim();
  state.bountyPerFinding = Boolean(els.bountyPerFinding?.checked);
  state.bountyRunLive = Boolean(els.bountyRunLive?.checked);
  saveState();
  els.bountyRun.disabled = true;
  els.bountyStatus.textContent = state.bountyRunLive
    ? "Hunting... running scanners, live browser pass, and writing the report (this can take a minute)."
    : "Hunting... running scanners and writing the report (this can take a minute).";
  if (els.bountyReport) els.bountyReport.hidden = true;
  if (els.bountyReportActions) els.bountyReportActions.hidden = true;
  try {
    const res = await apiFetch("/api/bounty/scan", {
      method: "POST",
      timeoutMs: 600000,
      body: JSON.stringify({
        target,
        profile: state.bountyProfile,
        vuln_class: state.bountyClass || null,
        scope: state.bountyScope,
        output_dir: state.bountyOutput || null,
        authorized: true,
        run_live: state.bountyRunLive,
        per_finding: state.bountyPerFinding
      })
    });
    if (res.ok === false) {
      els.bountyStatus.textContent = res.error || "The hunt could not run.";
    } else {
      const counts = res.severity_counts || {};
      const sev = `${counts.critical || 0}C / ${counts.high || 0}H / ${counts.medium || 0}M`;
      const brain = res.used_brain ? ` · analysis by ${res.brain_model}` : " · deterministic (no brain configured)";
      const warn = Array.isArray(res.scan_errors) && res.scan_errors.length
        ? `⚠ ${res.scan_errors.length} scanner(s) failed — results are partial. `
        : "";
      const perFiles = Array.isArray(res.per_finding_paths) && res.per_finding_paths.length
        ? ` + ${res.per_finding_paths.length} per-finding file(s)`
        : "";
      els.bountyStatus.textContent =
        `${warn}Done — risk ${String(res.risk).toUpperCase()}, ${res.finding_count} finding(s) [${sev}]${brain}. Report saved to: ${res.report_path}${perFiles}`;
      lastBountyReportMarkdown = res.report_markdown || "";
      if (els.bountyReport && lastBountyReportMarkdown) {
        els.bountyReport.textContent = lastBountyReportMarkdown;
        els.bountyReport.hidden = false;
        if (els.bountyReportActions) els.bountyReportActions.hidden = false;
      }
    }
  } catch (error) {
    els.bountyStatus.textContent = error.message || "The hunt failed.";
  } finally {
    els.bountyRun.disabled = false;
  }
});

let lastBountyReportMarkdown = "";

els.bountyCopyReport?.addEventListener("click", async () => {
  if (!lastBountyReportMarkdown) return;
  try {
    await navigator.clipboard.writeText(lastBountyReportMarkdown);
    els.bountyCopyReport.textContent = "Copied ✓";
    setTimeout(() => {
      if (els.bountyCopyReport) els.bountyCopyReport.textContent = "Copy report";
    }, 1500);
  } catch (_) {
    // Clipboard blocked — select the text so the user can copy manually.
    const range = document.createRange();
    range.selectNodeContents(els.bountyReport);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
});

// ---- Agent security red-team (test GreyIQ's own agent) ----
let lastRedteamReportMarkdown = "";

if (els.redteamBehavioral) {
  els.redteamBehavioral.checked = Boolean(state.redteamBehavioral);
}

els.redteamForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!els.redteamAuthorized?.checked) {
    els.redteamStatus.textContent = "Tick the box to red-team your GreyIQ agent.";
    return;
  }
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    els.redteamStatus.textContent = "Local GreyIQ service is not running.";
    return;
  }
  state.redteamBehavioral = Boolean(els.redteamBehavioral?.checked);
  saveState();
  els.redteamRun.disabled = true;
  els.redteamStatus.textContent = state.redteamBehavioral
    ? "Red-teaming… running sandbox + behavioral probes (the behavioral ones use your brain)."
    : "Red-teaming… running sandbox + policy probes.";
  if (els.redteamReport) els.redteamReport.hidden = true;
  if (els.redteamReportActions) els.redteamReportActions.hidden = true;
  try {
    const res = await apiFetch("/api/agent/redteam", {
      method: "POST",
      timeoutMs: 600000,
      body: JSON.stringify({ authorized: true, include_behavioral: state.redteamBehavioral })
    });
    if (res.ok === false) {
      els.redteamStatus.textContent = res.error || "The security test could not run.";
    } else {
      const c = res.counts || {};
      const detail = `${c.secure || 0} secure, ${c.vulnerable || 0} vulnerable, ${c.review || 0} review, ${c.error || 0} error`;
      els.redteamStatus.textContent =
        `Posture: ${String(res.posture).toUpperCase()} — ${res.probe_count} probe(s) (${detail}). Report saved to: ${res.report_path}`;
      lastRedteamReportMarkdown = res.report_markdown || "";
      if (els.redteamReport && lastRedteamReportMarkdown) {
        els.redteamReport.textContent = lastRedteamReportMarkdown;
        els.redteamReport.hidden = false;
        if (els.redteamReportActions) els.redteamReportActions.hidden = false;
      }
    }
  } catch (error) {
    els.redteamStatus.textContent = error.message || "The security test failed.";
  } finally {
    els.redteamRun.disabled = false;
  }
});

els.redteamCopyReport?.addEventListener("click", async () => {
  if (!lastRedteamReportMarkdown) return;
  try {
    await navigator.clipboard.writeText(lastRedteamReportMarkdown);
    els.redteamCopyReport.textContent = "Copied ✓";
    setTimeout(() => {
      if (els.redteamCopyReport) els.redteamCopyReport.textContent = "Copy report";
    }, 1500);
  } catch (_) {
    const range = document.createRange();
    range.selectNodeContents(els.redteamReport);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
});

// ---- Pentest toolkit (curated catalog from awesome-pentest, mapped to bug classes) ----
let toolkitData = { tools: [], categories: [], vuln_classes: {} };

function toolkitBadge(text, cls) {
  const span = document.createElement("span");
  span.className = cls;
  span.textContent = text;
  return span;
}

function renderToolkit() {
  if (!els.toolkitList) return;
  const cat = els.toolkitCategory?.value || "";
  const cls = els.toolkitClass?.value || "";
  const q = (els.toolkitSearch?.value || "").trim().toLowerCase();
  const names = toolkitData.vuln_classes || {};
  const items = toolkitData.tools.filter((tool) => {
    if (cat && tool.category !== cat) return false;
    if (cls && !(tool.maps_to || []).includes(cls)) return false;
    if (q) {
      const hay = `${tool.name} ${tool.description} ${(tool.tags || []).join(" ")}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  if (els.toolkitStatus) {
    els.toolkitStatus.textContent = `${items.length} of ${toolkitData.tools.length} tools`;
  }
  els.toolkitList.replaceChildren();
  for (const tool of items) {
    const card = document.createElement("div");
    card.className = "toolkit-item";
    const head = document.createElement("div");
    head.className = "toolkit-item-head";
    const link = document.createElement("a");
    link.className = "toolkit-name";
    link.href = tool.url || "#";
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = tool.name || "(unnamed)";
    head.append(link);
    if (tool.kind) head.append(toolkitBadge(tool.kind, "toolkit-kind"));
    card.append(head);
    if (tool.description) {
      const desc = document.createElement("p");
      desc.className = "toolkit-desc";
      desc.textContent = tool.description;
      card.append(desc);
    }
    const meta = document.createElement("div");
    meta.className = "toolkit-tags";
    for (const m of tool.maps_to || []) meta.append(toolkitBadge(names[m] || m, "toolkit-class"));
    if (Array.isArray(tool.platforms) && tool.platforms.length) {
      meta.append(toolkitBadge(tool.platforms.join(" · "), "toolkit-plat"));
    }
    if (meta.childNodes.length) card.append(meta);
    els.toolkitList.append(card);
  }
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "folder-status";
    empty.textContent = "No tools match these filters.";
    els.toolkitList.append(empty);
  }
}

async function loadToolkit() {
  if (!els.toolkitForm) return;
  let data;
  try {
    data = await apiFetch("/api/toolkit", { timeoutMs: 6000 });
  } catch (_) {
    return; // local service not up yet; the panel stays empty
  }
  if (!data || data.ok === false) return;
  toolkitData = {
    tools: Array.isArray(data.tools) ? data.tools : [],
    categories: Array.isArray(data.categories) ? data.categories : [],
    vuln_classes: data.vuln_classes || {}
  };
  if (els.toolkitCategory) {
    els.toolkitCategory.replaceChildren();
    const any = document.createElement("option");
    any.value = "";
    any.textContent = `All categories (${toolkitData.tools.length})`;
    els.toolkitCategory.append(any);
    for (const c of toolkitData.categories) {
      const option = document.createElement("option");
      option.value = c.id;
      option.textContent = c.label;
      els.toolkitCategory.append(option);
    }
  }
  if (els.toolkitClass) {
    const present = new Set();
    for (const tool of toolkitData.tools) for (const m of tool.maps_to || []) present.add(m);
    els.toolkitClass.replaceChildren();
    const any = document.createElement("option");
    any.value = "";
    any.textContent = "Any bug class";
    els.toolkitClass.append(any);
    for (const id of Array.from(present).sort()) {
      const option = document.createElement("option");
      option.value = id;
      option.textContent = toolkitData.vuln_classes[id] || id;
      els.toolkitClass.append(option);
    }
  }
  renderToolkit();
}

els.toolkitCategory?.addEventListener("change", renderToolkit);
els.toolkitClass?.addEventListener("change", renderToolkit);
els.toolkitSearch?.addEventListener("input", renderToolkit);

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
  void loadBountyProfiles();
  void loadToolkit();
  render();
  renderWorkbench();
  if (state.agentMode && state.agentWorkspace) {
    void refreshWorkspaceTree();
  }
}

boot();
