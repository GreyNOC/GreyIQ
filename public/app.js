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
      "Astra is a generalist. It gives the direct answer first, separates facts from assumptions, and turns broad requests into practical next moves.",
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
      "Mira is warm and steady. It helps the user feel oriented, keeps uncertainty honest, and makes complex work feel manageable.",
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
  deleteBotButton: document.querySelector("#deleteBotButton"),
  messageStream: document.querySelector("#messageStream"),
  messageTemplate: document.querySelector("#messageTemplate"),
  composer: document.querySelector("#composer"),
  promptInput: document.querySelector("#promptInput"),
  sendButton: document.querySelector("#sendButton"),
  templateBar: document.querySelector("#templateBar"),
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
  brainModelList: document.querySelector("#brainModelList"),
  agentToggle: document.querySelector("#agentToggle"),
  agentWorkspace: document.querySelector("#agentWorkspace"),
  agentWsPath: document.querySelector("#agentWsPath"),
  agentCmdPolicy: document.querySelector("#agentCmdPolicy"),
  trainingSourceList: document.querySelector("#trainingSourceList"),
  trainButton: document.querySelector("#trainButton"),
  trainingDataCount: document.querySelector("#trainingDataCount"),
  choiceCount: document.querySelector("#choiceCount"),
  modelState: document.querySelector("#modelState"),
  memoryList: document.querySelector("#memoryList"),
  themeToggle: document.querySelector("#themeToggle"),
  appShell: document.querySelector(".app-shell"),
  workbench: document.querySelector("#workbench"),
  workbenchDivider: document.querySelector("#workbenchDivider"),
  workbenchMaximize: document.querySelector("#workbenchMaximize"),
  workbenchTablist: document.querySelector(".workbench-tablist"),
  workspaceRefresh: document.querySelector("#workspaceRefresh"),
  workspaceSearch: document.querySelector("#workspaceSearch"),
  workspaceTree: document.querySelector("#workspaceTree"),
  projectPanel: document.querySelector("#projectPanel"),
  workflowPanel: document.querySelector("#workflowPanel"),
  filePreviewPanel: document.querySelector("#filePreviewPanel"),
  changesPanel: document.querySelector("#changesPanel"),
  agentStepsPanel: document.querySelector("#agentStepsPanel"),
  verifyPanel: document.querySelector("#verifyPanel"),
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
  bountyActive: document.querySelector("#bountyActive"),
  bountyRun: document.querySelector("#bountyRun"),
  bountyStatus: document.querySelector("#bountyStatus"),
  bountyNextSteps: document.querySelector("#bountyNextSteps"),
  bountyReport: document.querySelector("#bountyReport"),
  bountyReportActions: document.querySelector("#bountyReportActions"),
  bountyCopyReport: document.querySelector("#bountyCopyReport"),
  bountyToggleReport: document.querySelector("#bountyToggleReport"),
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
  toolkitList: document.querySelector("#toolkitList"),
  panelModes: document.querySelector(".panel-modes"),
  panelModeButtons: [...document.querySelectorAll(".panel-mode-btn")],
  panelModePanels: [...document.querySelectorAll(".panel-mode")],
  panelModeEyebrow: document.querySelector("#panelModeEyebrow"),
  panelModeTitle: document.querySelector("#panelModeTitle")
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
    themeChosen: false,
    workbenchTab: "project",
    workbenchActiveFile: "",
    workbenchSearch: "",
    workbenchTree: [],
    workbenchHeight: null,
    workbenchDocked: false,
    workbenchWrap: false,
    lastAgentTranscript: [],
    lastAgentChanges: [],
    lastAgentPlan: [],
    lastAgentExplain: "",
    lastAgentFlaggedReads: [],
    bountyProfile: "full-sweep",
    bountyClass: "",
    bountyScope: "",
    bountyOutput: "",
    bountyPerFinding: false,
    bountyActive: false,
    redteamBehavioral: false,
    panelMode: "brain",
    appMode: "hunt",
    ckRunType: "hunt",
    ckTarget: "",
    ckScope: "",
    ckProgram: "",
    ckActive: false,
    ckTimeBased: false,
    ckLive: false,
    ckAuthCookie: "",
    ckAuthHeaders: ""
  };

  try {
    const saved = JSON.parse(localStorage.getItem(STORE_KEY) || "null");
    // An empty bots array is as invalid as a missing one — the app assumes at least
    // one bot (activeBot()/render paths index into it), so fall back to defaults.
    if (!saved || !Array.isArray(saved.bots) || saved.bots.length === 0) {
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
    lastAgentPlan: _plan,
    lastAgentExplain: _explain,
    lastAgentFlaggedReads: _flagged,
    agentSnapshot: _snapshot,
    projectMemory: _projectMemory,
    ...persist
  } = state;
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(persist));
  } catch (_) {
    // Storage full or unavailable — non-fatal; the app keeps working in memory.
  }
}

// Per-session token the backend injected into the page (CSP-safe <meta>); echoed
// on every /api/* call so the backend knows the request is from its own app and
// not another local process. Absent in the static browser fallback (no backend).
const SESSION_TOKEN = (() => {
  const meta = document.querySelector('meta[name="greyiq-session"]');
  const value = meta ? meta.content : "";
  return value && value !== "__GREYIQ_SESSION_TOKEN__" ? value : "";
})();

async function apiFetch(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || API_TIMEOUT_MS);
  const { timeoutMs: _timeoutMs, ...requestOptions } = options;
  const headers = {
    Accept: "application/json",
    ...(SESSION_TOKEN ? { "X-GreyIQ-Token": SESSION_TOKEN } : {}),
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
      // A non-ok response can carry a JSON body that ISN'T an object (literal null, an
      // array, a bare string from a proxy/error page) -- dereferencing .detail on that
      // throws an opaque "Cannot read properties of null" that hides the real HTTP
      // status behind a confusing client-side error instead of surfacing it.
      const safe = payload && typeof payload === "object" ? payload : {};
      throw new Error(safe.detail || safe.error || response.statusText);
    }
    return payload;
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeReplyPayload(payload, userText) {
  const diagnostics = payload?.diagnostics || {};
  return {
    text: payload?.message || "Give me a little more to work with and I will respond.",
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
    text: String(answer || "Give me a little more to work with and I will respond."),
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
    if (typeof ckSyncService === "function") ckSyncService();
    // If the cockpit profiles failed to load at boot (late backend), fill them now.
    if (ck && ck.profile && !ck.profile.options.length) void ckPopulateProfiles();
    // If the backend only just became reachable, fill any Security-panel selectors
    // that bailed empty at boot (the lazy poll is how a late backend gets noticed).
    if (state.panelMode === "security") ensureSecurityData();
    if (!silent) {
      render();
    } else {
      renderBackend();
      // Only rebuild the training/memory panel when something it shows actually
      // changed — a no-op poll must not wipe the user's focus/scroll there.
      if (trainingSignature() !== lastTrainingSignature) {
        renderTraining();
      }
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
    mode: "Friendly Direct",
    type: "local_chat_bot",
    description: bot.persona || "Local AI that learns your preferences.",
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
      text: `${activeBot().name} is loaded and running locally.`,
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
    // Build via DOM, not innerHTML: bot.color comes from localStorage and was
    // interpolated raw into a style="" attribute — a tampered value could break out
    // and inject markup. Setting it through the CSSOM (style.background) makes the
    // browser reject anything that isn't a valid color.
    const avatar = document.createElement("span");
    avatar.className = "bot-avatar";
    avatar.style.background = String(bot.color || "");
    avatar.textContent = initials(bot.name);
    const meta = document.createElement("span");
    const strong = document.createElement("strong");
    strong.textContent = bot.name;
    const sub = document.createElement("span");
    sub.textContent = bot.style;
    meta.append(strong, sub);
    button.replaceChildren(avatar, meta);
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
  if (els.deleteBotButton) els.deleteBotButton.disabled = state.bots.length <= 1;
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

let lastTrainingSignature = "";

// A compact signature of everything renderTraining() actually reflects. The 5s
// status poll uses it to skip rebuilding the memory list when nothing changed —
// otherwise replaceChildren() every tick destroys focus/scroll in that panel.
function trainingSignature() {
  const t = service.status?.training || {};
  const memories = activeMemories();
  return JSON.stringify([
    Boolean(t.active), Boolean(t.paused),
    t.status?.status || t.status?.stage || "",
    t.last_error || "", t.finished_at || "",
    memories.length, Boolean(activeBot()?.trainedAt), state.activeBotId,
  ]);
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
  lastTrainingSignature = trainingSignature();
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
  // A transient "thinking" bubble appended straight to the stream (NOT persisted chat
  // state), so a multi-second reply — or a multi-minute Agent-mode run — never looks
  // frozen. Removed in finally the instant the reply (or error) lands.
  const pending = document.createElement("article");
  pending.className = "message is-bot is-pending";
  const pMeta = document.createElement("div"); pMeta.className = "message-meta"; pMeta.textContent = activeBot().name;
  const pBody = document.createElement("div"); pBody.className = "message-body";
  const dots = document.createElement("span"); dots.className = "typing-dots";
  dots.append(document.createElement("span"), document.createElement("span"), document.createElement("span"));
  pBody.append(dots);
  pending.append(pMeta, pBody);
  els.messageStream.append(pending);
  els.messageStream.scrollTop = els.messageStream.scrollHeight;
  try {
    // scan/bughunt commands always go to the chat endpoint so BugHunter's scanner
    // runs — even in Agent mode, where the agent endpoint wouldn't detect them.
    const isScanCommand = /^\s*\/?(?:scan|bughunt)\b[:\s]/i.test(text);
    const useAgent = Boolean(state.agentMode && state.agentWorkspace) && !isScanCommand;
    const rawAnswer = useAgent ? await runAgent(text) : await replyFor(text);
    const answer = normalizeAnswerForChat(
      rawAnswer,
      text,
      useAgent ? "coding_agent" : "local_engine"
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
      text: `Local runtime error: ${error.message || "unknown error"}. The browser model is still available.`,
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
    pending.remove();  // drop the thinking bubble no matter how the reply resolved
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
  if (els.brainModelList) els.brainModelList.hidden = provider !== "local";
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
    renderAgentBar(); // refresh the command-policy trust label now the config is known
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
    // The local (Ollama) runtime is downloaded on first use to keep the app small —
    // provision + start it now that the user picked the local model.
    if (provider === "local" && window.greyiqDesktop && typeof window.greyiqDesktop.ensureOllama === "function") {
      els.brainStatus.textContent = "Saved. Preparing the local model runtime (first time downloads ~1 GB)…";
      window.greyiqDesktop.ensureOllama().then((res) => {
        els.brainStatus.textContent = res && res.ok
          ? "Local model runtime ready. Use Test to verify."
          : "Saved, but the local runtime could not start — install Ollama, or use the Claude/OpenAI brain.";
      }).catch(() => {});
    }
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
      renderModelList([], "");
      return;
    }
    if (info.present) {
      els.brainModelStatus.textContent = `Model installed: ${info.configured} ✓`;
      els.brainDownload.hidden = true;
    } else {
      els.brainModelStatus.textContent = `${info.configured || "Model"} not installed.`;
      els.brainDownload.hidden = false;
    }
    renderModelList(info.installed, info.configured);
  } catch (error) {
    els.brainModelStatus.textContent = error.message || "Could not check the model.";
  }
}

// List the installed local models, each with a Remove button.
function renderModelList(installed, configured) {
  if (!els.brainModelList) return;
  els.brainModelList.replaceChildren();
  const models = Array.isArray(installed) ? installed : [];
  for (const name of models) {
    const row = document.createElement("div");
    row.className = "model-row";
    const label = document.createElement("span");
    label.className = "model-name";
    const inUse = name === configured || name === `${configured}:latest`;
    label.textContent = inUse ? `${name} (in use)` : name;
    const del = document.createElement("button");
    del.type = "button";
    del.className = "text-button danger";
    del.textContent = "Remove";
    del.addEventListener("click", () => deleteModel(name, del));
    row.append(label, del);
    els.brainModelList.append(row);
  }
}

async function deleteModel(name, btn) {
  if (!window.confirm(`Delete the local model "${name}"? This frees its disk space; you can re-download it later.`)) return;
  if (btn) { btn.disabled = true; btn.textContent = "Removing…"; }
  try {
    const res = await apiFetch("/api/coder/delete", { method: "POST", timeoutMs: 60000, body: JSON.stringify({ model: name }) });
    if (res.ok === false) {
      els.brainModelStatus.textContent = res.error || "Could not delete the model.";
      if (btn) { btn.disabled = false; btn.textContent = "Remove"; }
      return;
    }
    void refreshModelStatus();
  } catch (error) {
    els.brainModelStatus.textContent = error.message || "Delete failed.";
    if (btn) { btn.disabled = false; btn.textContent = "Remove"; }
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
  // Default to dark; honor the user's explicit choice once they've toggled.
  const theme = state.themeChosen ? (state.theme === "dark" ? "dark" : "light") : "dark";
  state.theme = theme;
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
  const ckTheme = document.querySelector("#ckTheme");
  if (ckTheme) ckTheme.textContent = theme === "dark" ? "Light" : "Dark";
}

function toggleTheme() {
  state.themeChosen = true;
  state.theme = state.theme === "dark" ? "light" : "dark";
  applyTheme();
  saveState();
}

els.themeToggle?.addEventListener("click", toggleTheme);

// ---- Right-panel mode menu (Brain / Train / Security) ----
// One surface at a time. Each mode owns a slice of the old "everything" panel, so
// the user picks an intent and only its controls show. Mirrors the WAI-ARIA tabs
// pattern (the workbench tablist uses the same approach).
const PANEL_MODES = ["brain", "train", "security"];
const PANEL_MODE_LABELS = {
  brain: { eyebrow: "Setup", title: "Coding Brain" },
  train: { eyebrow: "Local model", title: "Training" },
  security: { eyebrow: "Offense", title: "Security" }
};

function setPanelMode(mode, focusTab = false) {
  if (!PANEL_MODES.includes(mode)) mode = "brain";
  state.panelMode = mode;
  for (const button of els.panelModeButtons) {
    const active = button.dataset.panelMode === mode;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
    if (active && focusTab) button.focus();
  }
  for (const panel of els.panelModePanels) {
    panel.hidden = panel.dataset.mode !== mode;
  }
  const label = PANEL_MODE_LABELS[mode];
  if (els.panelModeEyebrow) els.panelModeEyebrow.textContent = label.eyebrow;
  if (els.panelModeTitle) els.panelModeTitle.textContent = label.title;
  saveState();
  // The Security panel's selectors (bounty type, focus class, toolkit) load lazily
  // and self-gate on the local service. (Re)load them whenever the panel is shown
  // and they're still empty — otherwise a backend that comes up after boot leaves
  // the dropdowns blank with no retry.
  if (mode === "security") ensureSecurityData();
}

// Populate the Security panel's selectors if they haven't loaded yet. Idempotent
// and cheap: both loaders self-gate on service availability and no-op when already
// populated, so this is safe to call on every panel show and service-up transition.
function ensureSecurityData() {
  if (els.bountyProfile && !bountyProfilesData.length) void loadBountyProfiles();
  if (els.toolkitForm && !toolkitData.tools.length) void loadToolkit();
}

for (const button of els.panelModeButtons) {
  button.addEventListener("click", () => setPanelMode(button.dataset.panelMode));
}

// Arrow-key navigation across the mode menu (WAI-ARIA tabs pattern).
els.panelModes?.addEventListener("keydown", (event) => {
  const idx = PANEL_MODES.indexOf(state.panelMode);
  let next = -1;
  if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (idx + 1) % PANEL_MODES.length;
  else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (idx - 1 + PANEL_MODES.length) % PANEL_MODES.length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = PANEL_MODES.length - 1;
  else return;
  event.preventDefault();
  setPanelMode(PANEL_MODES[next], true);
});

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
  if (els.agentCmdPolicy) {
    // Trust label for tool actions: is run_command gated behind approval?
    const allow = Boolean(coderConfig && coderConfig.agent && coderConfig.agent.allow_commands);
    els.agentCmdPolicy.hidden = !state.agentMode;
    els.agentCmdPolicy.textContent = allow ? "⚠ commands: enabled" : "commands: approval required";
    els.agentCmdPolicy.className = `agent-cmd-policy${allow ? " is-on" : ""}`;
    els.agentCmdPolicy.title = allow
      ? "run_command is ON — the agent can run shell commands in this workspace."
      : "run_command is OFF — the agent cannot run shell commands (enable it in the agent config to allow).";
  }
}

// ---- Task templates (starter workflows that prefill the composer) ----
// Each chip drops a vetted prompt into the input — it does NOT auto-send, so the
// user can tweak it first. `needsAgent` templates flip Agent mode on (the agent
// can then read/edit files); `scan` ones run BugHunter's code scanner instead.
const TASK_TEMPLATES = [
  {
    id: "review",
    label: "Review project",
    hint: "Read the code and report back — no file changes",
    needsAgent: true,
    prompt:
      "Review this project. Read the key files first, then give a concise assessment: " +
      "what it does, how it's structured, code quality and risks, and the top 3 " +
      "improvements you'd make. Don't change any files — just report."
  },
  {
    id: "explain",
    label: "Explain repo",
    hint: "A beginner-friendly tour of the codebase",
    needsAgent: true,
    prompt:
      "Explain this repo like I'm brand new to it: the big picture, the main parts and " +
      "how they fit together, the key files to start reading, and how control and data " +
      "flow. Keep it beginner-friendly and don't change any files."
  },
  {
    id: "readme",
    label: "Create README",
    hint: "Generate or update README.md, then verify it",
    needsAgent: true,
    prompt:
      "Read this project and write a clear README.md: what it is, how to install and " +
      "run it, the main features, and the project layout. Create or update README.md, " +
      "then verify it."
  },
  {
    id: "tests",
    label: "Fix failing tests",
    hint: "Diagnose and fix failing tests, then verify",
    needsAgent: true,
    prompt:
      "Find and fix the failing tests in this project. Run the test suite to see what's " +
      "failing, fix the root cause (don't change the test unless the test itself is " +
      "wrong), and verify the tests pass. If running commands isn't enabled, tell me " +
      "exactly what to run."
  },
  {
    id: "security",
    label: "Find security risks",
    hint: "Run BugHunter's code scanner on your workspace",
    scan: true
  },
  {
    id: "release",
    label: "Package for release",
    hint: "Steps to produce a release build",
    needsAgent: true,
    prompt:
      "Help me package this app for release: review the build and release setup, give me " +
      "the exact step-by-step to produce a release build, and flag anything missing or " +
      "risky. Don't change files unless I confirm."
  },
  {
    id: "plan",
    label: "Issue / PR plan",
    hint: "Draft a GitHub issue + step-by-step PR plan",
    needsAgent: true,
    prompt:
      "Turn my request into a concrete plan: a GitHub issue (title, problem, acceptance " +
      "criteria) and a step-by-step PR plan (files to change, in order, plus tests). If I " +
      "haven't told you what the change is yet, ask me first."
  }
];

function renderTemplateBar() {
  if (!els.templateBar) return;
  els.templateBar.replaceChildren();
  const label = document.createElement("span");
  label.className = "template-bar-label";
  label.textContent = "Templates";
  els.templateBar.append(label);
  for (const template of TASK_TEMPLATES) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "template-chip";
    chip.textContent = template.label;
    chip.title = template.hint || template.label;
    chip.addEventListener("click", () => void applyTemplate(template));
    els.templateBar.append(chip);
  }
}

function fillComposer(text) {
  els.promptInput.value = text;
  els.promptInput.focus();
  // If there's a fill-in-the-blank placeholder, select it so the user types over it.
  const placeholder = "<path to your project>";
  const at = text.indexOf(placeholder);
  if (at >= 0) {
    els.promptInput.setSelectionRange(at, at + placeholder.length);
  } else {
    els.promptInput.setSelectionRange(text.length, text.length);
  }
  els.promptInput.scrollIntoView({ block: "nearest" });
}

// Turn Agent mode ON (vs. the toggle, which flips it). Picks a workspace first if
// none is set. Returns false if the user cancels the workspace picker.
async function ensureAgentMode() {
  if (state.agentMode) return true;
  if (!state.agentWorkspace) {
    const picked = await chooseWorkspace();
    if (!picked) return false;
    state.agentWorkspace = picked;
  }
  state.agentMode = true;
  saveState();
  renderAgentBar();
  renderWorkbench();
  void refreshWorkspaceTree();
  return true;
}

async function applyTemplate(template) {
  if (template.scan) {
    let workspace = (state.agentWorkspace || "").trim();
    if (!workspace) {
      const picked = await chooseWorkspace();
      if (picked) {
        workspace = picked.trim();
        state.agentWorkspace = workspace;
        saveState();
        renderAgentBar();
      }
    }
    fillComposer(workspace ? `scan code ${workspace}` : "scan code <path to your project>");
    return;
  }
  if (template.needsAgent) {
    // Best-effort: if the user cancels the workspace picker we still prefill, so
    // they can run it as a plain chat or set a workspace and resend.
    await ensureAgentMode();
  }
  fillComposer(template.prompt);
}

// ---- Workbench (IDE-style layer shown only in Agent mode) ----
function makeHint(text, isError = false) {
  const p = document.createElement("p");
  p.className = `workbench-hint${isError ? " is-error" : ""}`;
  p.textContent = text;
  return p;
}

const WORKBENCH_TABS = ["project", "workflow", "preview", "changes", "steps", "verify"];

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
  setWorkbenchTab(state.workbenchTab || "project");
  renderWorkspaceTree(state.workbenchTree);
  if (state.workbenchActiveFile && els.filePreviewPanel?.dataset.loadedPath) {
    // keep the currently previewed file as-is
  } else {
    renderFilePreview(null);
  }
  renderChangesPanel(state.lastAgentChanges);
  renderAgentSteps(state.lastAgentTranscript);
  renderVerifyPanel(state.lastAgentTranscript);
  renderWorkflowPanel();
  renderProjectPanel();
  // Fetch rollback availability + project memory once per session so they survive a
  // reload (both live server-side). `undefined` = not yet checked this workspace.
  if (state.agentWorkspace && state.agentSnapshot === undefined) {
    state.agentSnapshot = null;
    void refreshSnapshotState();
  }
  if (state.agentWorkspace && state.projectMemory === undefined) {
    state.projectMemory = null;
    void refreshProjectMemory();
  }
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
    project: els.projectPanel,
    workflow: els.workflowPanel,
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
  bar.append(wrapBtn);
  if (file.trust && file.trust.label) {
    const badge = document.createElement("span");
    badge.className = `trust-badge is-${file.trust.level || "clean"}`;
    badge.textContent = file.trust.label;
    bar.append(badge);
  }
  els.filePreviewPanel.append(bar);

  // Trust warning: list the prompt-injection signals when the file isn't clean.
  if (file.trust && file.trust.level && file.trust.level !== "clean" && (file.trust.signals || []).length) {
    const warn = document.createElement("details");
    warn.className = `trust-warning is-${file.trust.level}`;
    warn.open = file.trust.level === "risk";
    const summary = document.createElement("summary");
    summary.textContent =
      file.trust.level === "risk"
        ? "⚠ This file contains text that reads like instructions to an AI — the agent treats it as data, not commands."
        : "This file has content worth reviewing before trusting it.";
    warn.append(summary);
    const ul = document.createElement("ul");
    file.trust.signals.forEach((sig) => {
      const li = document.createElement("li");
      const label = document.createElement("strong");
      label.textContent = sig.label || sig.id || "signal";
      li.append(label);
      if (sig.excerpt) {
        const code = document.createElement("code");
        code.textContent = sig.excerpt;
        li.append(document.createTextNode(": "), code);
      }
      ul.append(li);
    });
    warn.append(ul);
    els.filePreviewPanel.append(warn);
  }

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

// ---- Workflow tab: Plan -> Change -> Verify -> Explain (the guided trust loop) ----
function makeWorkflowStage(title, glyph, statusClass) {
  const stage = document.createElement("section");
  stage.className = "workflow-stage";
  const head = document.createElement("div");
  head.className = "workflow-stage-head";
  const badge = document.createElement("span");
  badge.className = `workflow-stage-num${statusClass ? " " + statusClass : ""}`;
  badge.textContent = glyph;
  badge.setAttribute("aria-hidden", "true");
  const heading = document.createElement("span");
  heading.className = "workflow-stage-title";
  heading.textContent = title;
  head.append(badge, heading);
  const body = document.createElement("div");
  body.className = "workflow-stage-body";
  stage.append(head, body);
  els.workflowPanel.append(stage);
  return body;
}

function renderWorkflowPanel() {
  if (!els.workflowPanel) return;
  els.workflowPanel.replaceChildren();

  const transcript = Array.isArray(state.lastAgentTranscript) ? state.lastAgentTranscript : [];
  const changes = Array.isArray(state.lastAgentChanges) ? state.lastAgentChanges : [];
  const plan = Array.isArray(state.lastAgentPlan) ? state.lastAgentPlan : [];
  const explain = state.lastAgentExplain || "";

  const intro = document.createElement("p");
  intro.className = "workflow-intro";
  intro.textContent = "Plan → Change → Verify → Explain";
  els.workflowPanel.append(intro);

  if (!(transcript.length || changes.length || plan.length || explain)) {
    els.workflowPanel.append(
      makeHint("Run an agent task and its Plan → Change → Verify → Explain will appear here.")
    );
    return;
  }

  // 1) Plan
  const planBody = makeWorkflowStage("Plan", "1");
  if (plan.length) {
    const ol = document.createElement("ol");
    ol.className = "workflow-plan";
    plan.forEach((step) => {
      const li = document.createElement("li");
      li.textContent = step;
      ol.append(li);
    });
    planBody.append(ol);
  } else {
    planBody.append(makeHint("No plan was captured for this run."));
  }

  // 2) Change
  const changeBody = makeWorkflowStage("Change", "2");
  if (changes.length) {
    const list = document.createElement("ul");
    list.className = "workflow-changes";
    changes.forEach((change) => {
      const op =
        change.operation === "write_file" ? (change.existed ? "rewrote" : "created") : "edited";
      const li = document.createElement("li");
      li.innerHTML =
        `<span class="change-op">${escapeHtml(op)}</span> ` +
        `<span class="change-path">${escapeHtml(change.path || "")}</span>`;
      list.append(li);
    });
    changeBody.append(list);
    const open = document.createElement("button");
    open.type = "button";
    open.className = "workflow-link";
    open.textContent = "Open diffs in Changes →";
    open.addEventListener("click", () => setWorkbenchTab("changes", true));
    changeBody.append(open);
  } else {
    changeBody.append(makeHint("No files were changed."));
  }

  // 3) Verify
  const verifySteps = transcript.filter((s) => s.tool === "verify" || s.tool === "run_command");
  const anyFail = verifySteps.some(
    (s) => s.is_error || /VERIFY FAILED|FAIL\s|exit=[1-9]/.test(String(s.output || ""))
  );
  const verified = verifySteps.length > 0 && !anyFail;
  const verifyBody = makeWorkflowStage(
    "Verify",
    verifySteps.length ? (verified ? "✓" : "✕") : "3",
    verifySteps.length ? (verified ? "is-ok" : "is-error") : ""
  );
  if (!verifySteps.length) {
    verifyBody.append(makeHint("Nothing was verified this run."));
  } else {
    const summary = document.createElement("p");
    summary.textContent = verified
      ? `Verification passed (${verifySteps.length} check${verifySteps.length > 1 ? "s" : ""}).`
      : "Verification reported a problem.";
    verifyBody.append(summary);
    const open = document.createElement("button");
    open.type = "button";
    open.className = "workflow-link";
    open.textContent = "Open Verify output →";
    open.addEventListener("click", () => setWorkbenchTab("verify", true));
    verifyBody.append(open);
  }

  // 4) Explain
  const explainBody = makeWorkflowStage("Explain", "4");
  const summary = document.createElement("p");
  summary.className = "workflow-explain";
  summary.textContent = explain || "(no summary)";
  explainBody.append(summary);

  // Trust check: files the agent read this run that looked like prompt injection.
  const flagged = Array.isArray(state.lastAgentFlaggedReads) ? state.lastAgentFlaggedReads : [];
  if (flagged.length) {
    const risky = flagged.filter((f) => f.level === "risk").length;
    const note = document.createElement("div");
    note.className = `workflow-security${risky ? " is-risk" : ""}`;
    const heading = document.createElement("strong");
    heading.textContent = "⚠ Trust check";
    const body = document.createElement("p");
    body.textContent =
      `The agent read ${flagged.length} flagged file(s)` +
      (risky ? ` (${risky} prompt-injection risk)` : "") +
      ` — their contents were treated as untrusted data, not instructions: ` +
      flagged.map((f) => f.path).join(", ") +
      ".";
    note.append(heading, body);
    els.workflowPanel.append(note);
  }

  // Rollback footer — one-click undo of the whole run.
  if (state.agentSnapshot && state.agentSnapshot.available) {
    const footer = document.createElement("div");
    footer.className = "workflow-rollback";
    const count = Number(state.agentSnapshot.count || 0);
    const undo = document.createElement("button");
    undo.type = "button";
    undo.className = "workflow-undo";
    undo.textContent = `Undo last agent run${count ? ` (${count} file${count > 1 ? "s" : ""})` : ""}`;
    undo.addEventListener("click", () => void undoLastAgentRun());
    const note = document.createElement("p");
    note.className = "workflow-rollback-note";
    note.textContent = "Restores files to their state before the last run.";
    footer.append(undo, note);
    els.workflowPanel.append(footer);
  }
}

async function refreshSnapshotState() {
  if (!state.agentWorkspace) {
    state.agentSnapshot = { available: false, count: 0 };
    return;
  }
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    return;
  }
  try {
    const res = await apiFetch("/api/agent/snapshot", {
      method: "POST",
      body: JSON.stringify({ workspace: state.agentWorkspace })
    });
    state.agentSnapshot = {
      available: Boolean(res && res.available),
      count: Number((res && res.count) || 0)
    };
  } catch (_) {
    state.agentSnapshot = { available: false, count: 0 };
  }
  if (state.agentMode) renderWorkflowPanel();
}

async function undoLastAgentRun() {
  if (!state.agentWorkspace) return;
  const count = Number(state.agentSnapshot?.count || 0);
  const message = count
    ? `Undo the last agent run? This restores ${count} file${count > 1 ? "s" : ""} to their state before the run, discarding changes since.`
    : "Undo the last agent run? This restores files to their state before the run.";
  if (!window.confirm(message)) return;
  try {
    const res = await apiFetch("/api/agent/undo", {
      method: "POST",
      body: JSON.stringify({ workspace: state.agentWorkspace })
    });
    if (!res || res.ok === false) {
      window.alert((res && res.error) || "Undo failed.");
      return;
    }
    state.agentSnapshot = { available: false, count: 0 };
    state.lastAgentChanges = [];
    const restored = (res.restored || []).length;
    const deleted = (res.deleted || []).length;
    activeChat().push({
      id: crypto.randomUUID(),
      role: "bot",
      text:
        `Rolled back the last agent run — restored ${restored} file(s)` +
        (deleted ? `, deleted ${deleted} created file(s)` : "") +
        ".",
      createdAt: Date.now()
    });
    renderChat();
    saveState();
    void refreshWorkspaceTree();
    renderChangesPanel(state.lastAgentChanges);
    renderWorkflowPanel();
  } catch (error) {
    window.alert(`Undo failed: ${error.message || error}`);
  }
}

// ---- Project tab: source cards of what GreyIQ knows about this workspace ----
const PROJECT_CATEGORIES = [
  { key: "purpose", label: "Purpose" },
  { key: "stack", label: "Tech stack" },
  { key: "run", label: "Run commands" },
  { key: "files", label: "Key files" },
  { key: "preferences", label: "Preferences" },
  { key: "constraints", label: "Constraints" },
  { key: "tasks", label: "Open tasks" }
];

function renderProjectPanel() {
  if (!els.projectPanel) return;
  els.projectPanel.replaceChildren();
  const mem = state.projectMemory || {};
  const facts = Array.isArray(mem.facts) ? mem.facts : [];

  const head = document.createElement("div");
  head.className = "project-head";
  const intro = document.createElement("p");
  intro.className = "project-intro";
  intro.textContent = "What GreyIQ knows about this project";
  const scanBtn = document.createElement("button");
  scanBtn.type = "button";
  scanBtn.className = "project-scan";
  scanBtn.disabled = Boolean(mem.scanning);
  scanBtn.textContent = mem.scanning ? "Scanning…" : facts.length ? "Re-scan" : "Scan project";
  scanBtn.addEventListener("click", () => void scanProject());
  head.append(intro, scanBtn);
  els.projectPanel.append(head);

  if (!facts.length) {
    els.projectPanel.append(
      makeHint(
        mem.scanning
          ? "Scanning the workspace…"
          : "No project memory yet. Click “Scan project” to derive the purpose, tech stack, run commands, and key files — or add your own notes below."
      )
    );
  } else {
    PROJECT_CATEGORIES.forEach(({ key, label }) => {
      const items = facts.filter((fact) => fact.category === key);
      if (!items.length) return;
      const card = document.createElement("section");
      card.className = "project-card";
      const cardHead = document.createElement("div");
      cardHead.className = "project-card-head";
      cardHead.textContent = label;
      card.append(cardHead);
      const ul = document.createElement("ul");
      ul.className = "project-facts";
      items.forEach((fact) => {
        const li = document.createElement("li");
        li.className = "project-fact";
        const text = document.createElement("span");
        text.className = "project-fact-text";
        text.textContent = fact.text;
        const tag = document.createElement("span");
        tag.className = `project-fact-src is-${fact.source === "auto" ? "auto" : "user"}`;
        tag.textContent = fact.source === "auto" ? "auto" : "you";
        const del = document.createElement("button");
        del.type = "button";
        del.className = "project-fact-del";
        del.title = "Remove this fact";
        del.setAttribute("aria-label", `Remove: ${fact.text}`);
        del.textContent = "✕";
        del.addEventListener("click", () => void removeProjectFact(fact.id));
        li.append(text, tag, del);
        ul.append(li);
      });
      card.append(ul);
      els.projectPanel.append(card);
    });
  }

  const addForm = document.createElement("form");
  addForm.className = "project-add";
  const select = document.createElement("select");
  select.className = "project-add-cat";
  select.setAttribute("aria-label", "Category");
  PROJECT_CATEGORIES.forEach(({ key, label }) => {
    const option = document.createElement("option");
    option.value = key;
    option.textContent = label;
    select.append(option);
  });
  select.value = "constraints";
  const input = document.createElement("input");
  input.type = "text";
  input.className = "project-add-text";
  input.placeholder = "Add a note GreyIQ should remember…";
  input.setAttribute("aria-label", "New project note");
  const addBtn = document.createElement("button");
  addBtn.type = "submit";
  addBtn.className = "project-add-btn";
  addBtn.textContent = "Add";
  addForm.append(select, input, addBtn);
  addForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    void addProjectFact(select.value, text);
  });
  els.projectPanel.append(addForm);

  if (mem.updatedAt) {
    const when = new Date(mem.updatedAt);
    if (!Number.isNaN(when.getTime())) {
      const upd = document.createElement("p");
      upd.className = "project-updated";
      upd.textContent = `Updated ${when.toLocaleString()}`;
      els.projectPanel.append(upd);
    }
  }
}

async function refreshProjectMemory() {
  if (!state.agentWorkspace) {
    state.projectMemory = { facts: [] };
    return;
  }
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) return;
  try {
    const res = await apiFetch("/api/project/memory", {
      method: "POST",
      body: JSON.stringify({ workspace: state.agentWorkspace })
    });
    state.projectMemory = {
      facts: Array.isArray(res.facts) ? res.facts : [],
      updatedAt: res.updated_at || null
    };
  } catch (_) {
    state.projectMemory = { facts: [] };
  }
  if (state.agentMode) renderProjectPanel();
}

async function scanProject() {
  if (!state.agentWorkspace) return;
  state.projectMemory = { ...(state.projectMemory || {}), scanning: true };
  renderProjectPanel();
  try {
    const res = await apiFetch("/api/project/scan", {
      method: "POST",
      timeoutMs: 120000,
      body: JSON.stringify({ workspace: state.agentWorkspace })
    });
    if (res && res.ok !== false) {
      state.projectMemory = {
        facts: Array.isArray(res.facts) ? res.facts : [],
        updatedAt: res.updated_at || null
      };
    } else {
      state.projectMemory = { ...(state.projectMemory || {}), scanning: false };
      window.alert((res && res.error) || "Scan failed.");
    }
  } catch (error) {
    state.projectMemory = { ...(state.projectMemory || {}), scanning: false };
    window.alert(`Scan failed: ${error.message || error}`);
  }
  renderProjectPanel();
}

async function saveProjectMemory(facts) {
  state.projectMemory = { ...(state.projectMemory || {}), facts, scanning: false };
  renderProjectPanel();
  if (!state.agentWorkspace) return;
  try {
    const res = await apiFetch("/api/project/memory/save", {
      method: "POST",
      body: JSON.stringify({ workspace: state.agentWorkspace, facts })
    });
    if (res && Array.isArray(res.facts)) {
      state.projectMemory = { facts: res.facts, updatedAt: res.updated_at || null };
      renderProjectPanel();
    }
  } catch (_) {
    // Kept in memory; non-fatal if the save round-trip fails.
  }
}

function addProjectFact(category, text) {
  const facts = [...((state.projectMemory && state.projectMemory.facts) || [])];
  facts.push({ id: crypto.randomUUID(), category, text, source: "user" });
  return saveProjectMemory(facts);
}

function removeProjectFact(id) {
  const facts = ((state.projectMemory && state.projectMemory.facts) || []).filter((fact) => fact.id !== id);
  return saveProjectMemory(facts);
}

const agentSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function runAgent(userText) {
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) {
    return "The local GreyIQ service is not running.";
  }
  const history = (activeChat() || [])
    .slice(0, -1)
    .slice(-12)
    .map((message) => ({ role: message.role === "bot" ? "assistant" : "user", content: message.text }))
    .filter((message) => message.content);

  // Prefer the streamed run so the Workbench shows tool-by-tool progress live;
  // fall back to the one-shot endpoint if streaming isn't available (older backend).
  let started = null;
  try {
    started = await apiFetch("/api/agent/stream", {
      method: "POST",
      timeoutMs: 20000,
      body: JSON.stringify({ message: userText, workspace: state.agentWorkspace, history })
    });
  } catch (_) {
    started = null;
  }
  if (!started || started.ok === false || !started.request_id) {
    return runAgentSync(userText, history);
  }

  // Reset the live view and surface the Agent Steps tab while the run streams in.
  state.lastAgentTranscript = [];
  state.lastAgentPlan = [];
  state.workbenchTab = "steps";
  renderWorkbench();

  const requestId = started.request_id;
  let cursor = 0;
  let failures = 0;
  const deadline = Date.now() + 600000; // 10-minute ceiling
  while (Date.now() < deadline) {
    let ev;
    try {
      ev = await apiFetch("/api/agent/events", {
        method: "POST",
        timeoutMs: 30000,
        body: JSON.stringify({ request_id: requestId, cursor })
      });
      failures = 0;
    } catch (error) {
      // The run continues server-side; tolerate a few transient poll failures.
      if (++failures > 5) return `Agent failed: ${error.message || error}`;
      await agentSleep(800);
      continue;
    }
    if (ev.ok === false) {
      return ev.error ? `Agent failed: ${ev.error}` : "The agent run was lost.";
    }
    cursor = typeof ev.cursor === "number" ? ev.cursor : cursor;
    let changed = false;
    for (const event of ev.events || []) {
      if (event.type === "plan") {
        state.lastAgentPlan = Array.isArray(event.plan) ? event.plan : [];
      } else if (event.type === "step" && event.entry) {
        state.lastAgentTranscript.push(event.entry);
      }
      changed = true;
    }
    if (changed) renderWorkbench();
    if (ev.done) return applyAgentResult(ev.result || {});
    await agentSleep(600);
  }
  return "The agent run timed out.";
}

async function runAgentSync(userText, history) {
  try {
    const res = await apiFetch("/api/agent", {
      method: "POST",
      timeoutMs: 600000,
      body: JSON.stringify({ message: userText, workspace: state.agentWorkspace, history })
    });
    return applyAgentResult(res);
  } catch (error) {
    return `Agent failed: ${error.message || error}`;
  }
}

// Apply a finished agent result to the Workbench and return the chat summary.
// Shared by the streamed and one-shot paths so a run ends identically either way.
function applyAgentResult(res) {
  state.lastAgentTranscript = Array.isArray(res.transcript) ? res.transcript : state.lastAgentTranscript;
  state.lastAgentChanges = Array.isArray(res.changes) ? res.changes : [];
  state.lastAgentPlan = Array.isArray(res.plan) ? res.plan : state.lastAgentPlan;
  state.lastAgentExplain = res.message || "";
  state.lastAgentFlaggedReads = Array.isArray(res.flagged_reads) ? res.flagged_reads : [];
  state.lastAgentCompleted = res.ok !== false ? Boolean(res.completed) : null;
  state.lastAgentOutstanding = Array.isArray(res.outstanding) ? res.outstanding : [];
  state.agentSnapshot = {
    available: Boolean(res.snapshot_available),
    count: Number(res.snapshot_count || 0)
  };
  // Surface the guided Plan → Change → Verify → Explain view after a run.
  state.workbenchTab = "workflow";
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
  // Honest completion status: only claim "done" when the run finished cleanly and
  // its changes verified. Otherwise name what's left so a re-run is productive.
  if (state.lastAgentCompleted === true) {
    text += `\n\n✓ Completed${res.verified ? " and verified" : ""}.`;
  } else if (state.lastAgentCompleted === false) {
    const reasons = state.lastAgentOutstanding.length
      ? "\n  - " + state.lastAgentOutstanding.join("\n  - ")
      : "";
    text += `\n\n⚠ Not fully complete:${reasons}`;
  }
  return text;
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
    state.agentSnapshot = undefined; // re-check rollback availability for the new workspace
    state.projectMemory = undefined; // re-load project memory for the new workspace
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

els.deleteBotButton?.addEventListener("click", () => {
  if (state.bots.length <= 1) return; // always keep at least one personality
  const bot = activeBot();
  if (!window.confirm(`Delete "${bot.name}"? This removes its chat history and learned memory on this device.`)) return;
  const removedId = bot.id;
  state.bots = state.bots.filter((b) => b.id !== removedId);
  delete state.chats[removedId];
  delete state.memories[removedId];
  state.activeBotId = state.bots[0].id;
  // Best-effort: drop the matching AI core on the backend too (ignore failures).
  if (service.available) {
    void apiFetch("/api/cores/delete", {
      method: "POST",
      timeoutMs: 8000,
      body: JSON.stringify({ core_id: coreIdForBot(bot) })
    }).catch(() => {});
  }
  saveState();
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
  if (els.bountyActive) els.bountyActive.checked = Boolean(state.bountyActive);
  updateBountyHint();
}

function updateBountyHint() {
  if (!els.bountyProfileHint) return;
  const profile = bountyProfilesData.find((p) => p.id === els.bountyProfile?.value);
  els.bountyProfileHint.textContent = profile ? profile.description : "";
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
  state.bountyActive = Boolean(els.bountyActive?.checked);
  saveState();
  els.bountyRun.disabled = true;
  els.bountyStatus.textContent = "Hunting… running scanners and writing the report (this can take a minute).";
  if (els.bountyReport) els.bountyReport.hidden = true;
  if (els.bountyNextSteps) {
    els.bountyNextSteps.hidden = true;
    els.bountyNextSteps.replaceChildren();
  }
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
        per_finding: state.bountyPerFinding,
        active: state.bountyActive
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
      const verified = Array.isArray(res.active_verified_classes) ? res.active_verified_classes : [];
      const activeNote = verified.length
        ? ` · ✓ actively confirmed: ${verified.join(", ")}`
        : (state.bountyActive && res.active_authorization && res.active_authorization.in_scope === false
          ? " · active verification skipped (host not in scope)"
          : "");
      els.bountyStatus.textContent =
        `${warn}Done — risk ${String(res.risk).toUpperCase()}, ${res.finding_count} finding(s) [${sev}]${brain}${activeNote}. Report saved to: ${res.report_path}${perFiles}`;
      lastBountyReportMarkdown = res.report_markdown || "";
      renderBountyNextSteps(res.next_steps, res.coverage);
      if (els.bountyReport && lastBountyReportMarkdown) {
        els.bountyReport.textContent = lastBountyReportMarkdown;
        els.bountyReport.hidden = true; // next-steps lead; full report is opt-in
        if (els.bountyToggleReport) {
          els.bountyToggleReport.hidden = false;
          els.bountyToggleReport.textContent = "Show full report";
          els.bountyToggleReport.setAttribute("aria-expanded", "false");
        }
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

// Render the structured, ordered operator action plan returned by a hunt. DOM-built
// (no innerHTML) so brain-authored step text can never inject markup.
function renderBountyNextSteps(steps, coverage) {
  const host = els.bountyNextSteps;
  if (!host) return;
  host.replaceChildren();
  const list = Array.isArray(steps) ? steps : [];
  if (!list.length) {
    host.hidden = true;
    return;
  }

  const title = document.createElement("h4");
  title.className = "next-steps-title";
  title.textContent = "Next steps";
  host.append(title);

  const intro = document.createElement("p");
  intro.className = "next-steps-intro";
  intro.textContent =
    "Ordered by impact, highest first. Each step lists the action and the tool to use.";
  host.append(intro);

  let currentPhase = null;
  let phaseItems = null;
  for (const step of list) {
    const phase = String(step.phase || "");
    if (phase !== currentPhase) {
      const phaseEl = document.createElement("div");
      phaseEl.className = "next-steps-phase";
      phaseEl.textContent = phase;
      host.append(phaseEl);
      phaseItems = document.createElement("div");
      phaseItems.className = "next-steps-items";
      host.append(phaseItems);
      currentPhase = phase;
    }
    const priority = String(step.priority || "").toLowerCase();
    const row = document.createElement("div");
    row.className = `next-step prio-${priority}`;

    const num = document.createElement("span");
    num.className = "next-step-num";
    num.textContent = String(step.order ?? "");
    row.append(num);

    const body = document.createElement("div");
    body.className = "next-step-body";
    const head = document.createElement("div");
    head.className = "next-step-head";
    const tag = String(step.priority || "").toUpperCase();
    if (tag) {
      const badge = document.createElement("span");
      badge.className = "next-step-tag";
      badge.textContent = tag;
      head.append(badge);
    }
    const action = document.createElement("span");
    action.className = "next-step-action";
    action.textContent = String(step.action || "");
    head.append(action);
    body.append(head);

    if (step.detail) {
      const detail = document.createElement("p");
      detail.className = "next-step-detail";
      detail.textContent = String(step.detail);
      body.append(detail);
    }
    const meta = [];
    if (step.ref) meta.push(`finding ${step.ref}`);
    if (step.tool) meta.push(`tool: ${step.tool}`);
    if (meta.length) {
      const metaEl = document.createElement("p");
      metaEl.className = "next-step-meta";
      metaEl.textContent = meta.join(" · ");
      body.append(metaEl);
    }
    row.append(body);
    phaseItems.append(row);
  }

  const cov = coverage || {};
  const covered = Array.isArray(cov.covered) ? cov.covered : [];
  const gaps = Array.isArray(cov.gaps) ? cov.gaps : [];
  if (covered.length || gaps.length) {
    const wrap = document.createElement("div");
    wrap.className = "next-steps-coverage";
    if (covered.length) wrap.append(coverageBlock("Covered by this run", covered, "covered"));
    if (gaps.length) wrap.append(coverageBlock("Not covered — blind spots", gaps, "gaps"));
    host.append(wrap);
  }
  host.hidden = false;
}

function coverageBlock(title, items, kind) {
  const block = document.createElement("div");
  block.className = `coverage-block coverage-${kind}`;
  const heading = document.createElement("div");
  heading.className = "coverage-title";
  heading.textContent = title;
  block.append(heading);
  const ul = document.createElement("ul");
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = String(item);
    ul.append(li);
  }
  block.append(ul);
  return block;
}

els.bountyToggleReport?.addEventListener("click", () => {
  if (!els.bountyReport) return;
  const show = els.bountyReport.hidden;
  els.bountyReport.hidden = !show;
  els.bountyToggleReport.textContent = show ? "Hide full report" : "Show full report";
  els.bountyToggleReport.setAttribute("aria-expanded", show ? "true" : "false");
});

els.bountyCopyReport?.addEventListener("click", async () => {
  if (!lastBountyReportMarkdown) return;
  try {
    await navigator.clipboard.writeText(lastBountyReportMarkdown);
    els.bountyCopyReport.textContent = "Copied ✓";
    setTimeout(() => {
      if (els.bountyCopyReport) els.bountyCopyReport.textContent = "Copy report";
    }, 1500);
  } catch (_) {
    // Clipboard blocked — select the text so the user can copy manually. The report
    // is hidden by default now (next-steps lead), and you can't select a hidden
    // element, so reveal it first and sync the toggle.
    if (els.bountyReport && els.bountyReport.hidden) {
      els.bountyReport.hidden = false;
      if (els.bountyToggleReport) {
        els.bountyToggleReport.textContent = "Hide full report";
        els.bountyToggleReport.setAttribute("aria-expanded", "true");
      }
    }
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

// Show local-model (Ollama) GPU acceleration status — desktop builds only.
async function renderGpuAccel() {
  const el = document.querySelector("#brainAccel");
  if (!el || !window.greyiqDesktop || typeof window.greyiqDesktop.gpuInfo !== "function") return;
  try {
    const info = await window.greyiqDesktop.gpuInfo();
    if (!info) return;
    if (info.accelerated) {
      const how = info.runtime === "rocm" ? "ROCm" : "CUDA";
      const vendor = info.vendor === "amd" ? "AMD" : "NVIDIA";
      el.textContent = `Local model GPU: ${vendor} (${how}) ✓`;
    } else if (info.vendor === "amd") {
      el.textContent = "Local model GPU: AMD detected — setting up ROCm (first run)…";
    } else {
      el.textContent = "Local model: CPU (no supported GPU detected)";
    }
  } catch (_) {
    // browser / non-desktop: no GPU info available
  }
}

// ===================== BUG-BOUNTY COCKPIT =====================
// A bug-bounty-only surface that is the app's default. It consumes the bounty
// engine over the API (scan / campaign / learn / stats) and renders a findings
// board, a per-finding proof pane, a recon surface map, a submission queue, and a
// learning dashboard. Every dynamic node is built with createElement + textContent
// (never innerHTML) because finding/proof text is scanner- and brain-derived.

const ck = {
  root: document.querySelector("#cockpit"),
  service: document.querySelector("#ckService"),
  theme: document.querySelector("#ckTheme"),
  studio: document.querySelector("#ckStudio"),
  huntReturn: document.querySelector("#huntReturn"),
  nav: document.querySelector("#ckNav"),
  navButtons: [...document.querySelectorAll(".ck-nav-btn")],
  launch: document.querySelector("#ckLaunch"),
  segHunt: document.querySelector("#ckRunHunt"),
  segCampaign: document.querySelector("#ckRunCampaign"),
  segPortfolio: document.querySelector("#ckRunPortfolio"),
  portfolioList: document.querySelector("#ckPortfolioPrograms"),
  portfolioAll: document.querySelector("#ckPortfolioAll"),
  portfolioCount: document.querySelector("#ckPortfolioCount"),
  activeProgram: document.querySelector("#ckActiveProgram"),
  spanScopeWrap: document.querySelector("#ckSpanScopeWrap"),
  spanScope: document.querySelector("#ckSpanScope"),
  spanScopeCount: document.querySelector("#ckSpanScopeCount"),
  target: document.querySelector("#ckTarget"),
  scope: document.querySelector("#ckScope"),
  profile: document.querySelector("#ckProfile"),
  klass: document.querySelector("#ckClass"),
  program: document.querySelector("#ckProgram"),
  maxPages: document.querySelector("#ckMaxPages"),
  profileHint: document.querySelector("#ckProfileHint"),
  active: document.querySelector("#ckActive"),
  timeBased: document.querySelector("#ckTimeBased"),
  deep: document.querySelector("#ckDeep"),
  live: document.querySelector("#ckLive"),
  authFold: document.querySelector("#ckAuthFold"),
  authCookie: document.querySelector("#ckAuthCookie"),
  authHeaders: document.querySelector("#ckAuthHeaders"),
  authorized: document.querySelector("#ckAuthorized"),
  run: document.querySelector("#ckRun"),
  status: document.querySelector("#ckStatus"),
  views: {
    program: document.querySelector("#ckViewProgram"),
    campaign: document.querySelector("#ckViewCampaign"),
    findings: document.querySelector("#ckViewFindings"),
    surface: document.querySelector("#ckViewSurface"),
    submissions: document.querySelector("#ckViewSubmissions"),
    idor: document.querySelector("#ckViewIdor"),
    learn: document.querySelector("#ckViewLearn"),
    operator: document.querySelector("#ckViewOperator")
  },
  detail: document.querySelector("#ckDetail"),
  body: document.querySelector(".ck-body")
};

let ckOpPoll = null;        // operator event-poll timer
let ckOpEventCount = 0;     // events already rendered
let ckOpEdit = null;        // the program being edited in the form (null = adding a new one)
let ckLivePoll = null;      // scan/campaign live-progress poll timer
let ckLiveEventCount = 0;   // live-progress lines already rendered

const ckState = {
  result: null,          // last hunt/campaign response
  runId: "",             // server run id — keys canonical submission packages
  findings: [],          // normalized finding rows
  surface: null,         // recon { urls, sources, notes }
  selectedUid: "",
  filter: "all",         // all | confirmed | critical | high | medium | low
  sort: { key: "rank", dir: 1 },
  view: "program",
  h1: null,              // { team_handle, api_username, has_token } — never the token
  platform: "hackerone", // report format for Copy/Download (server re-shapes per platform)
  triage: {},            // ref -> "submitted" | "drafted" (client-side worklist marks)
  reportFocus: null,     // a finding pinned open as a Full report on the Submissions page (from a drawer's "View full report")
  sub: { query: "", sev: "all", proof: "all", sort: "severity" }  // Submissions page search / filter / sort
};

// Report formats — mirrors backend report_formats.PLATFORMS (HackerOne first).
const CK_PLATFORMS = [
  { id: "hackerone", name: "HackerOne" },
  { id: "yeswehack", name: "YesWeHack" },
  { id: "bugcrowd", name: "Bugcrowd" },
  { id: "intigriti", name: "Intigriti" }
];

const CK_SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function cel(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = String(text);
  return node;
}

function setAppMode(mode) {
  state.appMode = mode === "studio" ? "studio" : "hunt";
  document.body.dataset.appMode = state.appMode;
  saveState();
  if (state.appMode === "hunt") ckSyncService();
}

function ckSyncService() {
  if (!ck.service) return;
  const up = Boolean(service.available);
  ck.service.textContent = up ? "engine ready" : "engine offline";
  ck.service.classList.toggle("is-up", up);
  ck.service.classList.toggle("is-down", !up);
}

function ckSetView(view) {
  ckState.view = view;
  for (const btn of ck.navButtons) btn.classList.toggle("is-active", btn.dataset.ckView === view);
  for (const [name, node] of Object.entries(ck.views)) node.hidden = name !== view;
  if (view === "program") void ckRenderProgram();
  if (view === "campaign") ckRenderCampaign();
  if (view === "findings") ckRenderFindings();
  if (view === "learn") void ckRenderLearn();
  if (view === "surface") ckRenderSurface();
  if (view === "submissions") ckRenderSubmissions();
  if (view === "idor") ckRenderIdor();
  if (view === "operator") void ckRenderOperator();
  // Operator events only poll while its tab is open.
  if (view !== "operator" && ckOpPoll) { clearInterval(ckOpPoll); ckOpPoll = null; }
}

function ckSetRunType(type) {
  state.ckRunType = ["campaign", "portfolio"].includes(type) ? type : "hunt";
  saveState();
  ck.segHunt?.classList.toggle("is-active", state.ckRunType === "hunt");
  ck.segCampaign?.classList.toggle("is-active", state.ckRunType === "campaign");
  ck.segPortfolio?.classList.toggle("is-active", state.ckRunType === "portfolio");
  for (const node of document.querySelectorAll("[data-ck-when]")) {
    node.hidden = node.dataset.ckWhen !== state.ckRunType;
  }
  if (ck.run) ck.run.textContent = state.ckRunType === "campaign" ? "Run campaign" : (state.ckRunType === "portfolio" ? "Run portfolio hunt" : "Run hunt");
  ckUpdateSpanScopeToggle();
  if (state.ckRunType === "portfolio") ckRenderPortfolioPicker();
}

// The Portfolio-mode program multi-select: a checkbox per saved program (marking which have
// no huntable targets), plus a select-all. Populated from the shared programs cache.
function ckRenderPortfolioPicker() {
  const host = ck.portfolioList;
  if (!host) return;
  const prev = new Set([...host.querySelectorAll("input[type=checkbox]:checked")].map((c) => c.value));
  host.replaceChildren();
  const progs = ckProgramsCache || [];
  if (!progs.length) {
    host.append(cel("p", "ck-hint", ckProgramsReachable
      ? "No saved programs yet — add one in the Program tab (import a HackerOne scope or add seed targets)."
      : "Engine unreachable — can't load your programs."));
    if (ck.portfolioCount) ck.portfolioCount.textContent = "";
    return;
  }
  for (const p of progs) {
    const n = (p.seed_targets || []).length || (p.structured_scope || []).filter((s) => s && s.eligible_for_submission !== false).length;
    const row = cel("label", "ck-portfolio-row");
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.value = p.id; cb.checked = prev.has(p.id);
    cb.disabled = !n;
    cb.addEventListener("change", ckUpdatePortfolioCount);
    row.append(cb);
    const txt = cel("span", null, p.name || p.id);
    if (!n) txt.append(cel("em", "ck-portfolio-empty", " — no huntable targets"));
    else txt.append(cel("span", "ck-tag", ` ${n} target${n === 1 ? "" : "s"}`));
    row.append(txt);
    host.append(row);
  }
  ckUpdatePortfolioCount();
}

function ckUpdatePortfolioCount() {
  if (!ck.portfolioCount) return;
  const n = ck.portfolioList ? ck.portfolioList.querySelectorAll("input[type=checkbox]:checked").length : 0;
  ck.portfolioCount.textContent = n ? `(${n} selected)` : "";
}

async function ckPopulateProfiles() {
  if (!ck.profile) return;
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) return;
  let info;
  try { info = await apiFetch("/api/bounty/types", { timeoutMs: 6000 }); } catch (_) { return; }
  if (!info || info.ok === false) return;
  const profiles = Array.isArray(info.profiles) ? info.profiles : [];
  ck.profile.replaceChildren();
  for (const p of profiles) {
    const o = cel("option", null, p.name);
    o.value = p.id;
    o.dataset.desc = p.description || "";
    ck.profile.append(o);
  }
  if (profiles.some((p) => p.id === state.bountyProfile)) ck.profile.value = state.bountyProfile;
  const classes = Array.isArray(info.classes) ? info.classes : [];
  if (ck.klass) {
    ck.klass.replaceChildren();
    const any = cel("option", null, "Any class found"); any.value = "";
    ck.klass.append(any);
    for (const c of classes) { const o = cel("option", null, c.name); o.value = c.id; ck.klass.append(o); }
  }
  ckUpdateProfileHint();
}

function ckUpdateProfileHint() {
  if (!ck.profileHint || !ck.profile) return;
  const opt = ck.profile.selectedOptions[0];
  ck.profileHint.textContent = opt ? (opt.dataset.desc || "") : "";
}

function ckNormalizeFindings(res) {
  // Build uniform rows from either a /scan response (full structured data) or a
  // /campaign response (consolidated rows + per-ref proof/cvss maps).
  const findings = Array.isArray(res.findings) ? res.findings : [];
  const proofMap = res.proof_of_impact || {};
  const cvssMap = res.cvss || {};
  const plans = res.attack_plans || {};
  return findings.map((f, i) => {
    const ref = String(f.ref || `F${i + 1}`);
    const proof = (proofMap[ref] && proofMap[ref].status) || f.proof_status || "missing";
    const cvss = cvssMap[ref] || f.cvss || null;
    return {
      ref,
      runId: String(res.run_id || ""),   // the run this finding belongs to (submit/copy/screenshot use THIS, not the latest)
      dedupKey: String(f.dedup_key || ""),  // exact ledger key (campaign findings) so delete targets THIS finding precisely
      rank: f.rank || i + 1,
      title: String(f.title || "Finding"),
      severity: String(f.severity || "info").toLowerCase(),
      className: String(f.class_name || f.class_id || "—"),
      class_id: String(f.class_id || f.class_name || ""),   // stable identity for the cross-app status overlay
      rule_id: String(f.rule_id || ""),
      cwe: String(f.cwe || ""),
      location: String(f.location || f.file_path || f.source_url || ""),
      proof: String(proof).toLowerCase(),
      cvssScore: cvss && (cvss.base_score ?? cvss.score) != null ? Number(cvss.base_score ?? cvss.score) : null,
      cvss,
      plan: plans[ref] || null,
      proofObj: proofMap[ref] || null,
      description: String(f.description || ""),
      remediation: String(f.remediation || ""),
      snippet: String(f.snippet || ""),
      sourceUrl: String(f.source_url || ""),
      matched_value: String(f.matched_value || (f.proof_evidence && f.proof_evidence.matched_value) || ""),
      proofEvidence: f.proof_evidence || f.proofEvidence || null,
      apiKeyAccessProof: f.credential_access_artifact || null,
      apiKeyAccessText: ""
    };
  });
}

function ckProofBadge(status) {
  const s = ["confirmed", "candidate", "missing"].includes(status) ? status : "missing";
  const label = s === "confirmed" ? "Confirmed" : s === "candidate" ? "Candidate" : "Missing";
  return cel("span", `ck-proof ${s}`, label);
}

// --- Cross-app finding-status overlay ---------------------------------------------
// A finding's status (proof + pipeline stage) is shown in many places — the campaign
// dashboard, the Findings board + detail drawer, the Submissions queue + history, and the
// persistent ledger. When an action changes it (Create proof of impact → confirmed; Submit
// → submitted), that change must show EVERYWHERE the same finding appears. This overlay is
// the one shared source of truth, keyed by a stable finding identity (the same
// class|rule|normalized-location the ledger dedups on), resolved by every view — and it's
// persisted so a confirm/submit survives a reload.
const ckStatusOverlay = (() => {
  try { return JSON.parse(localStorage.getItem("greyiq-ck-status") || "{}") || {}; } catch (_) { return {}; }
})();

function ckFindingKey(f) {
  if (!f) return "";
  const cls = String(f.class_id || f.className || f.cls || f.class_name || "").toLowerCase().trim();
  const rule = String(f.rule_id || f.rule || "").toLowerCase().trim();
  const loc = String(f.location || f.source_url || f.sourceUrl || f.target || "").replace(/\d+/g, "N").trim();
  const key = `${cls}|${rule}|${loc}`;
  return key === "||" ? "" : key;
}

// A stable per-ROW identity for selection/highlight. ref is NOT unique across ckState.findings
// (standalone confirm tools reuse "F1", so a hunt "F1" and a confirmed "F1" of a different
// class coexist), so resolving a clicked row by ref alone opens/acts on the wrong finding.
// This mirrors the compound identity ckDeleteFinding already uses.
function ckFindingUid(f) {
  if (!f) return "";
  return [f.ref || "", f.className || "", f.class_id || "", f.location || ""].join("|");
}

function ckSaveStatusOverlay() {
  try { localStorage.setItem("greyiq-ck-status", JSON.stringify(ckStatusOverlay)); } catch (_) { /* private mode / quota */ }
}

// Effective proof/stage = the overlay (if any) over the finding's own value.
function ckEffectiveProof(f, fallback) {
  const o = ckStatusOverlay[ckFindingKey(f)];
  return String((o && o.proof) || fallback || f.proof || f.proof_status || "missing").toLowerCase();
}
function ckEffectiveStage(f) {
  const o = ckStatusOverlay[ckFindingKey(f)];
  return String((o && o.stage) || f.stage || "");
}

// Record a status change and reflect it across every finding view immediately.
function ckMarkStatus(f, patch) {
  const key = ckFindingKey(f);
  if (!key) return;
  ckStatusOverlay[key] = { ...(ckStatusOverlay[key] || {}), ...patch };
  ckSaveStatusOverlay();
  if (patch.proof && f && typeof f === "object") f.proof = patch.proof;  // keep the in-hand object consistent too
  ckSyncFindingViews();
}

// True when an active-prover result's class matches this finding (so a re-probe that
// confirms a DIFFERENT class at the same URL never falsely flips THIS finding to confirmed).
function ckProofMatchesFinding(activeFindings, f) {
  const cls = String(f.class_id || f.cls || f.className || "").toLowerCase();
  if (!cls) return false;
  return (activeFindings || []).some((r) => {
    if (r.status !== "confirmed") return false;
    const hint = String(r.class_hint || "").toLowerCase();
    return hint && (hint === cls || cls.includes(hint) || hint.includes(cls));
  });
}

// Re-render whichever finding views are live so a status change shows at once.
function ckSyncFindingViews() {
  if (ckState.view === "findings") {
    ckRenderFindings();
    if (ckState.selectedUid) {
      const sel = ckState.findings.find((x) => ckFindingUid(x) === ckState.selectedUid);
      if (sel && !ck.detail?.hidden) ckRenderDetail(sel);
    }
  } else if (ckState.view === "submissions") {
    ckRenderSubmissions();
  } else if (ckState.view === "campaign") {
    ckRenderCampaign();
  }
  ckBadgeCount("submissions", ckState.findings.filter((f) => {
    const p = ckEffectiveProof(f);
    return p === "confirmed" || p === "candidate";
  }).length);
}

// Worst severity present, in the SAME risk-word scheme campaign._campaign_risk uses
// (critical/high/moderate/low/clean), so a fresh client-side badge means the same thing
// the server-computed one does.
const _RISK_FROM_SEVERITY = [["critical", "critical"], ["high", "high"], ["medium", "moderate"]];
function ckDeriveRisk(findings) {
  const present = new Set(findings.map((f) => String(f.severity || "").toLowerCase()));
  for (const [sev, label] of _RISK_FROM_SEVERITY) if (present.has(sev)) return label;
  return findings.length ? "low" : "clean";
}

function ckRenderFindings() {
  const host = ck.views.findings;
  host.replaceChildren();
  const res = ckState.result;
  // A standalone confirm tool (IDOR/BFLA/takeover/CVE/…) can populate ckState.findings
  // WITHOUT ever running a hunt (res stays null) — show the board whenever there's
  // anything to show, not only after a hunt specifically.
  if (!res && !ckState.findings.length) {
    const empty = cel("div", "ck-empty");
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM21 21l-4.3-4.3");
    svg.append(p);
    empty.append(svg, cel("h2", null, "Run a hunt to begin"), cel("p", null,
      "Enter an authorized target and scope on the left, then run a single hunt or a full campaign. Findings land here with a proof-status column; click any row for the captured proof and a submission draft."));
    host.append(empty);
    return;
  }

  // Summary strip. The headline numbers (risk/severity-counts/finding-count) are derived
  // FRESH from ckState.findings — not the (possibly stale) hunt result: a standalone
  // confirm tool run AFTER a hunt replaces/extends ckState.findings without touching
  // ckState.result, so trusting res's cached counts here would show a strip that
  // describes a different set of findings than the rows below it.
  const strip = cel("div", "ck-summary");
  const risk = ckDeriveRisk(ckState.findings);
  if (risk) strip.append(ckPill(`risk-${risk}`, "Risk", risk.toUpperCase()));
  const counts = {};
  for (const f of ckState.findings) { const s = String(f.severity || "").toLowerCase(); counts[s] = (counts[s] || 0) + 1; }
  const dots = cel("span", "ck-sevdots");
  for (const [k, cls] of [["critical", "c"], ["high", "h"], ["medium", "m"], ["low", "l"], ["info", "i"]]) {
    if (counts[k]) dots.append(cel("span", `ck-sevdot ${cls}`, `${counts[k]}${k[0].toUpperCase()}`));
  }
  if (dots.childNodes.length) { const wrap = ckPill("", "Findings", String(ckState.findings.length)); wrap.append(dots); strip.append(wrap); }
  else strip.append(ckPill("", "Findings", String(ckState.findings.length)));
  const confirmed = ckState.findings.filter((f) => f.proof === "confirmed").length;
  if (confirmed) strip.append(ckPill("is-armed", "Confirmed", String(confirmed)));
  // Active-verification authorization chip — genuinely hunt-specific (no standalone tool
  // produces it), so it's fine to source from res and simply absent without one.
  const auth = res ? res.active_authorization : null;
  if (auth) {
    if (auth.in_scope && (res.active_verified_classes || []).length) {
      strip.append(ckPill("is-armed", "Active", `armed · ${(res.active_verified_classes || []).join(", ")}`));
    } else if (auth.in_scope === false && auth.skipped_reason) {
      strip.append(ckPill("is-disarmed", "Active", "disarmed (passive only)"));
    }
  }
  if (res && res.scanners_run) strip.append(ckPill("", "Scanners", (res.scanners_run || []).join(", ") || "none"));
  host.append(strip);

  // Filter chips.
  const filters = cel("div", "ck-filters");
  const chipDefs = [["all", "All"], ["confirmed", "Confirmed"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]];
  for (const [key, label] of chipDefs) {
    const chip = cel("button", "ck-chip", label);
    chip.type = "button";
    chip.classList.toggle("is-active", ckState.filter === key);
    chip.addEventListener("click", () => { ckState.filter = key; ckRenderFindings(); });
    filters.append(chip);
  }
  host.append(filters);

  // Filter + sort rows.
  let rows = ckState.findings.slice();
  if (ckState.filter === "confirmed") rows = rows.filter((f) => ckEffectiveProof(f) === "confirmed");
  else if (ckState.filter !== "all") rows = rows.filter((f) => f.severity === ckState.filter);
  const { key, dir } = ckState.sort;
  rows.sort((a, b) => {
    let av, bv;
    if (key === "severity") { av = CK_SEV_RANK[a.severity] || 0; bv = CK_SEV_RANK[b.severity] || 0; }
    else if (key === "proof") { const r = { confirmed: 3, candidate: 2, missing: 1 }; av = r[ckEffectiveProof(a)] || 0; bv = r[ckEffectiveProof(b)] || 0; }
    else if (key === "cvss") { av = a.cvssScore || 0; bv = b.cvssScore || 0; }
    else { av = a.rank; bv = b.rank; }
    return (av < bv ? -1 : av > bv ? 1 : 0) * dir;
  });

  if (!rows.length) {
    host.append(cel("p", "ck-hint", ckState.findings.length ? "No findings match this filter." : "No findings surfaced. See the per-target report for the manual checklist."));
    return;
  }

  const table = cel("table", "ck-table");
  const thead = cel("thead");
  const htr = cel("tr");
  for (const [label, sortKey] of [["Sev", "severity"], ["Class", null], ["Proof", "proof"], ["Finding", null], ["Where", null], ["CVSS", "cvss"]]) {
    const th = cel("th", null, label);
    if (sortKey) {
      // dir=-1 sorts DESCENDING (the default on first click — critical/high first); the
      // glyph must match the conventional meaning (▼ descending, ▲ ascending), not invert it.
      const arrow = cel("span", "ck-sort", ckState.sort.key === sortKey ? (ckState.sort.dir < 0 ? " ▼" : " ▲") : " ⇅");
      th.append(arrow);
      th.addEventListener("click", () => {
        if (ckState.sort.key === sortKey) ckState.sort.dir *= -1;
        else ckState.sort = { key: sortKey, dir: -1 };
        ckRenderFindings();
      });
    } else { th.style.cursor = "default"; }
    htr.append(th);
  }
  thead.append(htr);
  table.append(thead);

  const tbody = cel("tbody");
  for (const f of rows) {
    const tr = cel("tr", `ck-row sev-${f.severity}`);
    if (ckFindingUid(f) === ckState.selectedUid) tr.classList.add("is-selected");
    tr.append(td(cel("span", `ck-sev sev-${f.severity}`, f.severity.toUpperCase())));
    const cls = cel("span", null, f.className);
    const clsTd = td(cls);
    if (f.cwe) clsTd.append(cel("span", "ck-tag", f.cwe));
    tr.append(clsTd);
    const proofTd = td(ckProofBadge(ckEffectiveProof(f)));
    if (ckEffectiveStage(f) === "submitted") proofTd.append(document.createTextNode(" "), cel("span", "ck-tag", "submitted"));
    tr.append(proofTd);
    tr.append(td(cel("span", "ck-ftitle", f.title)));
    tr.append(td(cel("span", "ck-floc", f.location || "—")));
    tr.append(td(f.cvssScore != null ? cel("span", "ck-cvss", f.cvssScore.toFixed(1)) : cel("span", "ck-cvss", "—")));
    tr.addEventListener("click", () => ckSelectFinding(f));
    tbody.append(tr);
  }
  table.append(tbody);
  host.append(table);

  function td(child) { const cell = cel("td"); cell.append(child); return cell; }
}

function ckPill(cls, label, value) {
  const pill = cel("span", `ck-pill ${cls}`.trim());
  pill.append(cel("span", null, label + ": "));
  pill.append(cel("strong", null, value));
  return pill;
}

function ckSelectFinding(f) {
  if (!f) return;
  // Bind to the exact finding object the row holds (and key selection on its compound uid),
  // never re-resolve by ref — ref collides across rows, which mis-targeted Delete/Submit.
  ckState.selectedUid = ckFindingUid(f);
  for (const row of document.querySelectorAll(".ck-row")) row.classList.remove("is-selected");
  ckRenderDetail(f);
  ck.body?.classList.add("has-detail");
  ck.detail.hidden = false;
  // Re-mark the selected row (cheap re-render of the board keeps it in sync).
  ckRenderFindings();
}

function ckCloseDetail() {
  ckState.selectedUid = "";
  ck.detail.hidden = true;
  ck.body?.classList.remove("has-detail");
  ckRenderFindings();
}

function ckRenderDetail(f) {
  const host = ck.detail;
  host.replaceChildren();
  const head = cel("div", "ck-detail-head");
  head.append(cel("h3", null, f.title));
  const close = cel("button", "ck-detail-close", "✕");
  close.type = "button";
  close.setAttribute("aria-label", "Close finding detail");
  close.addEventListener("click", ckCloseDetail);
  head.append(close);
  host.append(head);

  // Badges row.
  const badges = cel("div", "ck-summary");
  badges.append(cel("span", `ck-sev sev-${f.severity}`, f.severity.toUpperCase()));
  badges.append(ckProofBadge(ckEffectiveProof(f)));
  if (ckEffectiveStage(f) === "submitted" || ckState.triage[f.ref] === "submitted") badges.append(cel("span", "ck-tag", "submitted"));
  if (f.cwe) badges.append(cel("span", "ck-tag", f.cwe));
  host.append(badges);

  const meta = cel("dl", "ck-meta-grid");
  const addMeta = (k, v) => { if (v) { meta.append(cel("dt", null, k)); meta.append(cel("dd", null, v)); } };
  addMeta("Class", f.className);
  addMeta("Location", f.location);
  if (f.cvss && f.cvss.vector) addMeta("CVSS", `${f.cvss.vector}${f.cvssScore != null ? ` (${f.cvssScore.toFixed(1)})` : ""}`);
  else if (f.cvssScore != null) addMeta("CVSS", f.cvssScore.toFixed(1));
  host.append(meta);

  if (f.description) { host.append(cel("h4", null, "Description")); host.append(cel("p", null, f.description)); }

  const plan = f.plan || {};
  const steps = Array.isArray(plan.steps) ? plan.steps : [];
  if (steps.length) {
    host.append(cel("h4", null, "Steps to reproduce"));
    const ol = cel("ol", "ck-steps");
    for (const s of steps) ol.append(cel("li", null, s));
    host.append(ol);
  }
  const pocArtifact = ckProofOfConceptArtifact(f);
  host.append(cel("h4", null, "Proof of concept"));
  host.append(cel("pre", null, pocArtifact || "No runnable PoC artifact is captured yet. Attach an authorized request, command, saved HTML PoC, or working screenshot before submission."));

  // Proof of impact block.
  const po = f.proofObj || (plan.proof_of_impact && typeof plan.proof_of_impact === "object" ? plan.proof_of_impact : null);
  if (po) {
    host.append(cel("h4", null, "Proof of impact"));
    const pm = cel("dl", "ck-meta-grid");
    const add = (k, v) => { if (v) { pm.append(cel("dt", null, k)); pm.append(cel("dd", null, v)); } };
    add("Status", (po.status || "").replace(/^./, (c) => c.toUpperCase()));
    add("Observed", po.observed_result);
    add("Control", po.control_result);
    add("Evidence", po.evidence);
    if (pm.childNodes.length) host.append(pm);
    if (po.status !== "confirmed" && po.proof_obligation) {
      const ob = cel("div", "ck-obligation");
      ob.append(cel("strong", null, "To confirm: "));
      ob.append(document.createTextNode(po.proof_obligation));
      host.append(ob);
    }
  }
  host.append(cel("h4", null, "Proof of exploitability"));
  host.append(cel("pre", null, ckBuildProofOfExploitabilityText(f)));
  if (plan.impact) { host.append(cel("h4", null, "Impact")); host.append(cel("p", null, plan.impact)); }
  if (f.remediation) { host.append(cel("h4", null, "Remediation")); host.append(cel("p", null, f.remediation)); }

  // Actions.
  const actions = cel("div", "ck-actions");
  const fullBtn = cel("button", "ck-btn primary", "View full report →");
  fullBtn.type = "button";
  fullBtn.title = "Open the full submission report (proof of impact, screenshots, everything to submit) on the Submissions page";
  fullBtn.addEventListener("click", () => ckViewFullReport(f));
  actions.append(fullBtn);
  const copyBtn = cel("button", "ck-btn", "Copy submission report");
  copyBtn.type = "button";
  copyBtn.addEventListener("click", async () => {
    copyBtn.disabled = true; copyBtn.textContent = "Preparing…";  // the server package can take up to 20s
    try {
      const pkg = await ckSubmissionMarkdown(f);
      const ok = await ckCopy(pkg.text);
      copyBtn.textContent = ok ? (pkg.canonical ? "Copied ✓" : "Copied (offline)") : "Copy failed";
    } finally { copyBtn.disabled = false; setTimeout(() => { copyBtn.textContent = "Copy submission report"; }, 1600); }
  });
  actions.append(copyBtn);
  const dlBtn = cel("button", "ck-btn", "Download .md");
  dlBtn.type = "button";
  dlBtn.addEventListener("click", async () => {
    dlBtn.disabled = true; dlBtn.textContent = "Preparing…";
    try {
      const pkg = await ckSubmissionMarkdown(f);
      ckDownloadText(`${f.ref}-${ckSlug(f.title)}.md`, pkg.text);
    } finally { dlBtn.disabled = false; dlBtn.textContent = "Download .md"; }
  });
  actions.append(dlBtn);

  // Capture a proof screenshot of this finding's PoC URL (opt-in, Playwright-backed,
  // scope-gated). The image is NOT auto-redacted — review before submitting.
  const shotBtn = cel("button", "ck-btn", "Capture screenshot");
  shotBtn.type = "button";
  const shotWrap = cel("div", "ck-shot");
  shotBtn.addEventListener("click", () => ckCaptureScreenshot(f, shotBtn, shotWrap));
  actions.append(shotBtn);

  const keyWrap = cel("div", "ck-research");
  if (ckCanTestApiKeyAccess(f)) {
    const keyBtn = cel("button", "ck-btn", f.apiKeyAccessText ? "Re-test API key" : "Test API key access");
    keyBtn.type = "button";
    keyBtn.title = "Send one read-only request to the key's own issuer, record what the API key can access, and include it in the PoC bundle";
    keyBtn.addEventListener("click", () => ckTestApiKeyAccess(f, keyBtn, keyWrap));
    actions.append(keyBtn);
  }

  // Research this lead with the configured brain (or a deterministic dossier).
  const researchBtn = cel("button", "ck-btn", "Research this lead");
  researchBtn.type = "button";
  const researchWrap = cel("div", "ck-research");
  researchBtn.addEventListener("click", () => ckResearchLead(f, researchBtn, researchWrap));
  actions.append(researchBtn);

  // Delete this finding — removes it from the board AND permanently suppresses it, so no
  // future hunt/campaign surfaces it again (a false positive or accepted-risk you never
  // want to see re-reported). Destructive; confirmed first.
  const delBtn = cel("button", "ck-btn ck-btn-danger", "Delete finding");
  delBtn.type = "button";
  delBtn.title = "Remove this finding and never surface it again in future hunts";
  delBtn.addEventListener("click", () => ckDeleteFinding(f, delBtn));
  actions.append(delBtn);

  host.append(actions);
  host.append(shotWrap);
  host.append(keyWrap);
  host.append(researchWrap);
}

// Delete a board finding: permanently suppress it (server records its stable dedup key) so
// no future hunt or campaign surfaces it again, then drop it from the in-memory board and
// close the drawer. The server derives the key from class_id/rule_id/location — the same
// fields the engine keys on — so the deletion sticks across runs, targets, and programs.
async function ckDeleteFinding(f, btn) {
  if (!window.confirm(
    `Delete "${f.title}"?\n\nIt's removed from this board and will never be surfaced again in future hunts or campaigns. `
    + `Use this for a false positive or an accepted risk you don't want re-reported.`)) return;
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = "Deleting…";
  let res;
  try {
    res = await apiFetch("/api/bounty/finding/dismiss", {
      method: "POST", timeoutMs: 15000,
      body: JSON.stringify({
        dedup_key: f.dedupKey || "",
        class_id: f.class_id || "", rule_id: f.rule_id || "",
        location: f.location || f.sourceUrl || "", title: f.title || "",
      }),
    });
  } catch (err) {
    btn.disabled = false; btn.textContent = old;
    window.alert(err.message || "Could not delete the finding.");
    return;
  }
  if (!res || res.ok === false) {
    btn.disabled = false; btn.textContent = old;
    window.alert((res && res.error) || "Could not delete the finding.");
    return;
  }
  // Drop THIS finding only, then refresh counts + drawer. ref is NOT unique across
  // ckState.findings — standalone confirm tools reuse "F1", so a hunt finding and a
  // separately-confirmed finding can share a ref. Match the same identity the insert-dedup
  // uses (ref + className) plus class_id/location; filtering by ref alone would also silently
  // remove unrelated rows that happen to share the ref.
  ckState.findings = ckState.findings.filter((x) =>
    !(x.ref === f.ref && x.className === f.className
      && (x.class_id || "") === (f.class_id || "") && (x.location || "") === (f.location || "")));
  ckCloseDetail();
  ckRenderFindings();
  ckBadgeCount("findings", ckState.findings.length);
  ckBadgeCount("submissions", ckState.findings.filter((x) => x.proof === "confirmed" || x.proof === "candidate").length);
}

async function ckResearchLead(f, btn, wrap) {
  if (!(f.runId || ckState.runId)) {
    wrap.replaceChildren(cel("p", "ck-status is-error", "Run a hunt first — research attaches to a cached finding."));
    return;
  }
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Researching…";
  wrap.replaceChildren();
  try {
    const res = await apiFetch("/api/bounty/research", {
      method: "POST", timeoutMs: 120000, body: JSON.stringify({ run_id: f.runId || ckState.runId, ref: f.ref })
    });
    if (res && res.ok) {
      btn.textContent = "Re-research lead";
      const src = res.used_brain ? `Researched by ${res.model || "your model"}` : "Deterministic dossier — plug in Claude/ChatGPT/local for deeper research";
      wrap.append(cel("p", "ck-hint", src + (res.path ? " · saved + included in the bundle" : "")));
      const pre = cel("pre", "ck-research-md");
      pre.textContent = res.markdown || "";   // textContent — safe, no markup injection
      pre.style.whiteSpace = "pre-wrap";
      pre.style.maxHeight = "340px";
      pre.style.overflow = "auto";
      wrap.append(pre);
    } else {
      btn.textContent = label;
      wrap.append(cel("p", "ck-status is-error", (res && res.error) || "Research failed."));
    }
  } catch (err) {
    btn.textContent = label;
    wrap.append(cel("p", "ck-status is-error", err.message || "Research failed."));
  } finally {
    btn.disabled = false;
  }
}

function ckCanTestApiKeyAccess(f) {
  if (!(f && (f.runId || ckState.runId) && f.ref)) return false;
  const cls = String(f.class_id || f.className || "").toLowerCase();
  const rule = String(f.rule_id || "").toLowerCase();
  return cls === "secrets" && [
    "secret.google-api-key",
    "secret.github-pat",
    "secret.slack-bot-token",
    "secret.openai-key",
    "secret.anthropic-key",
    "secret.stripe-key",
  ].includes(rule);
}

async function ckTestApiKeyAccess(f, btn, wrap) {
  if (!ckCanTestApiKeyAccess(f)) {
    if (wrap) wrap.replaceChildren(cel("p", "ck-status is-error", "This source finding is not a supported API-key type."));
    return;
  }
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Testing key...";
  if (wrap) { wrap.hidden = false; wrap.replaceChildren(); }
  try {
    const res = await apiFetch("/api/bounty/credential-test", {
      method: "POST", timeoutMs: 30000,
      body: JSON.stringify({ run_id: f.runId || ckState.runId, ref: f.ref, authorized: true }),
    });
    if (!res || res.ok === false) {
      if (wrap) wrap.append(cel("p", "ck-status is-error", (res && res.error) || "API-key test failed."));
      btn.textContent = old;
      return;
    }
    f.apiKeyAccessProof = res.proof || null;
    f.apiKeyAccessText = res.artifact_text || "";
    f.apiKeyAccessPath = res.path || "";
    f.apiKeyAccessJsonPath = res.json_path || "";
    if (res.live === true) {
      f.proof = "confirmed";
      if (ckFindingKey(f)) {
        ckStatusOverlay[ckFindingKey(f)] = { ...(ckStatusOverlay[ckFindingKey(f)] || {}), proof: "confirmed" };
        ckSaveStatusOverlay();
      }
    }
    btn.textContent = "Re-test API key";
    if (wrap) {
      const p = res.proof || {};
      wrap.append(cel("p", "ck-hint", `Saved API-key access proof${res.path ? ": " + res.path : ""}. It is included in the PoC zip and engagement bundle.`));
      const pre = cel("pre", "ck-research-md");
      pre.textContent = res.artifact_text || [
        `Status: ${res.status || ""}`,
        p.access_summary ? `Accessible with key: ${p.access_summary}` : "",
        p.api_response ? `API response:\n${p.api_response}` : "",
      ].filter(Boolean).join("\n\n");
      pre.style.whiteSpace = "pre-wrap";
      pre.style.maxHeight = "340px";
      pre.style.overflow = "auto";
      wrap.append(pre);
    }
  } catch (err) {
    btn.textContent = old;
    if (wrap) wrap.append(cel("p", "ck-status is-error", err.message || "API-key test failed."));
  } finally {
    btn.disabled = false;
  }
}

async function ckCaptureScreenshot(f, btn, wrap, onShots) {
  // Capture needs a URL (used directly when the run isn't cached) OR a cached run to resolve one.
  if (!(f.location || f.sourceUrl || f.source_url || f.target || f.runId || ckState.runId)) {
    wrap.replaceChildren(cel("p", "ck-status is-error", "No URL to screenshot for this finding."));
    return;
  }
  btn.disabled = true;
  btn.textContent = "Capturing…";
  wrap.replaceChildren();
  try {
    const res = await apiFetch("/api/bounty/screenshot", {
      method: "POST", timeoutMs: 60000,
      // Carry the finding's OWN url/title/evidence so capture works even when the run is no
      // longer cached (a history finding) — no re-hunt. Send the cockpit's current Scope box
      // too; the server unions it with the run + live program scope and still fails closed.
      body: JSON.stringify({
        run_id: f.runId || ckState.runId, ref: f.ref || "",
        url: f.location || f.sourceUrl || f.source_url || f.target || "",
        title: f.title || "", location: f.location || f.source_url || "",
        matched_value: f.matched_value || f.snippet || (f.proofObj && (f.proofObj.evidence || f.proofObj.observed_result)) || "",
        scope: (ck.scope?.value || "").trim(),
      })
    });
    if (res && res.ok) {
      btn.textContent = "Re-capture screenshot";
      // The plain-text request/response/source proof, for the report's Copy / POC zip.
      if (res.source_text) f.sourceText = res.source_text;
      const shots = Array.isArray(res.shots) && res.shots.length ? res.shots
        : (res.data_url ? [{ data_url: res.data_url, kind: "evidence" }] : []);
      // When the caller owns persistent rendering (the full-report panel, which re-renders on
      // its own async report fetch), hand it the shots to stash + re-render — appending into a
      // wrap that a later re-render detaches would silently drop the just-captured images.
      if (onShots) { onShots(shots, res); return; }
      if (res.warning) wrap.append(cel("p", "ck-status is-error", res.warning));
      const kindLabel = { "source": "Response source (PoC)", "rendered": "Rendered page", "evidence": "Rendered page", "full-page": "Full page" };
      for (const shot of shots) {
        if (shot && shot.data_url) ckAppendScreenshot(wrap, shot.data_url, f.title || f.ref, kindLabel[shot.kind] || shot.kind || "");
      }
      wrap.append(cel("p", "ck-hint", `Saved locally${res.path ? ": " + res.path : ""}. Now embedded in this finding's Copy report / Download .md.`));
    } else {
      btn.textContent = "Capture screenshot";
      wrap.append(cel("p", "ck-status is-error", (res && res.error) || "Capture failed."));
      if (res && res.install) wrap.append(cel("p", "ck-hint", res.install));
    }
  } catch (err) {
    btn.textContent = "Capture screenshot";
    wrap.append(cel("p", "ck-status is-error", err.message || "Capture failed."));
  } finally {
    btn.disabled = false;
  }
}

// Language tag for a fenced PoC so a reviewer (and HackerOne's automated report check)
// recognizes it as code — a bare ``` fence around an HTML PoC gets flagged as "missing PoC
// code". Mirrors report.py _poc_lang.
function ckPocLang(poc) {
  const t = String(poc || "").replace(/^\s+/, "").toLowerCase();
  if (t.startsWith("<!doctype") || t.startsWith("<html") || t.startsWith("<meta") || t.startsWith("<body") || t.indexOf("<script") !== -1) return "html";
  return "";
}

function ckProofStatusLabel(status) {
  const s = String(status || "missing").toLowerCase();
  if (s === "confirmed") return "Confirmed";
  if (s === "candidate") return "Candidate / unverified";
  return s.replace(/^./, (c) => c.toUpperCase()) || "Missing";
}

function ckCapturedRequestResponseText(focus, includeReadData) {
  const pe = (focus && focus.proofEvidence) || {};
  const L = [];
  if (pe.request_line) {
    L.push(String(pe.request_line));
    if (pe.request_header) L.push(String(pe.request_header));
    L.push("");
  }
  if (pe.response_status) L.push(String(pe.response_status));
  if (pe.response_header) L.push(String(pe.response_header));
  if (pe.set_cookie) L.push(String(pe.set_cookie));
  if (pe.matched_value) L.push(String(pe.matched_value));
  if (includeReadData && pe.read_data) {
    if (L.length) L.push("");
    L.push("Exploit output / response body excerpt:");
    L.push(String(pe.read_data));
  }
  return L.join("\n").trim();
}

function ckProofOfConceptArtifact(focus) {
  const plan = (focus && focus.plan) || {};
  if (plan.poc) return String(plan.poc).trim();
  return ckCapturedRequestResponseText(focus, false);
}

function ckScreenshotProofNames(focus) {
  const out = [];
  if (focus && focus.screenshot && focus.screenshot.data_url) out.push("captured proof screenshot");
  for (const s of ((focus && focus.shots) || [])) {
    if (!s || !s.data_url) continue;
    const base = s.path ? String(s.path).replace(/\\/g, "/").split("/").pop() : "";
    out.push(base || String(s.kind || "screenshot"));
  }
  return out;
}

function ckBuildProofOfExploitabilityText(focus) {
  const plan = (focus && focus.plan) || {};
  const po = (focus && focus.proofObj) || {};
  const shots = ckScreenshotProofNames(focus);
  const chunks = [];
  let hasText = false;
  if (plan.poc) { chunks.push("Proof of concept used:\n" + String(plan.poc).trim()); hasText = true; }
  const req = ckCapturedRequestResponseText(focus, true);
  if (req) { chunks.push("Captured exploit request/response:\n" + req); hasText = true; }
  const observed = [];
  if (po.method) observed.push("Method: " + po.method);
  if (po.observed_result) observed.push("Observed result: " + po.observed_result);
  if (po.control_result) observed.push("Negative control: " + po.control_result);
  if (po.evidence) observed.push("Evidence: " + po.evidence);
  if (observed.length) { chunks.push("Observed exploit behavior:\n" + observed.join("\n")); hasText = true; }
  if (focus && (focus.apiKeyAccessText || focus.apiKeyAccessProof)) {
    chunks.push("API key access proof:\n" + (focus.apiKeyAccessText || JSON.stringify(focus.apiKeyAccessProof, null, 2)));
    hasText = true;
  }
  if (shots.length) chunks.push("Working exploit screenshot(s): " + shots.join(", "));
  const status = chunks.length ? ckProofStatusLabel((po && po.status) || (focus && focus.proof)) : "Missing";
  if (!chunks.length) {
    const obligation = po && po.proof_obligation ? "\n- Capture required: " + po.proof_obligation : "";
    return "- Status: Missing - no exploit proof artifact is attached yet." + obligation + "\n- Accepted artifact: a redacted request/response text proof or a screenshot showing the exploit working.";
  }
  const kinds = [];
  if (hasText) kinds.push("text");
  if (shots.length) kinds.push("screenshot");
  return "- Status: " + status + "\n- Exploit proof artifact: " + (kinds.join(" and ") || "captured artifact") + ".\n\n" + chunks.join("\n\n");
}

function ckBuildSubmissionDraft(f) {
  const lines = [];
  const sev = f.severity.replace(/^./, (c) => c.toUpperCase());
  lines.push(`# [${sev}] ${f.title}`, "");
  lines.push(`**Target / location:** ${f.location || "(see report)"}`);
  lines.push(`**Class:** ${f.className}${f.cwe ? ` (${f.cwe})` : ""}`);
  if (f.cvss && f.cvss.vector) lines.push(`**CVSS v3.1:** ${f.cvss.vector}${f.cvssScore != null ? ` — ${f.cvssScore.toFixed(1)}` : ""}`);
  lines.push(`**Proof status:** ${f.proof}`, "");
  if (f.description) lines.push("## Summary", f.description, "");
  const plan = f.plan || {};
  if (Array.isArray(plan.steps) && plan.steps.length) {
    lines.push("## Steps to reproduce");
    plan.steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
    lines.push("");
  }
  const poc = ckProofOfConceptArtifact(f);
  lines.push("## Proof of concept");
  if (poc) lines.push("```" + ckPocLang(poc), poc, "```", "");
  else lines.push("_No runnable PoC artifact is captured yet. Attach an authorized request, command, saved HTML PoC, or working screenshot before submission._", "");
  const po = f.proofObj || null;
  if (po) {
    lines.push("## Proof of impact");
    if (po.observed_result) lines.push(`- Observed: ${po.observed_result}`);
    if (po.control_result) lines.push(`- Control: ${po.control_result}`);
    if (po.evidence) lines.push(`- Evidence: ${po.evidence}`);
    if (po.status !== "confirmed" && po.proof_obligation) lines.push(`- To confirm: ${po.proof_obligation}`);
    lines.push("");
  }
  lines.push("## Proof of exploitability", ckBuildProofOfExploitabilityText(f), "");
  if (plan.impact) lines.push("## Impact", plan.impact, "");
  if (f.remediation) lines.push("## Remediation", f.remediation, "");
  lines.push("---", "_Drafted by GreyIQ BugHunter. Verify the proof obligation before you submit._");
  return lines.join("\n");
}

async function ckCopy(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch (_) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.append(ta); ta.select();
      const ok = document.execCommand("copy"); ta.remove(); return ok;
    } catch (_e) { return false; }
  }
}

// Fetch the CANONICAL server-built submission package (build_submission) for a
// finding. Falls back to the client draft only when the server package is
// unavailable (e.g. the run was evicted) so offline still works.
async function ckSubmissionMarkdown(f) {
  const rid = f.runId || ckState.runId;   // the finding's OWN run, not whatever ran last
  if (rid) {
    try {
      const res = await apiFetch("/api/bounty/submission", {
        method: "POST", timeoutMs: 20000,
        body: JSON.stringify({ run_id: rid, ref: f.ref, platform: ckState.platform || "hackerone" })
      });
      if (res.ok && res.package && res.package.vulnerability_information) {
        return { text: res.package.vulnerability_information, canonical: true, package: res.package };
      }
    } catch (_) { /* fall through to the offline draft */ }
  }
  return { text: ckBuildSubmissionDraft(f), canonical: false, package: null };
}

function ckSlug(s) { return String(s || "finding").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "finding"; }

function ckDownloadText(filename, text, mime) {
  const blob = new Blob([text], { type: mime || "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function ckFetchCreds() {
  try {
    const res = await apiFetch("/api/bounty/hackerone/creds", { timeoutMs: 6000 });
    ckState.h1 = res && res.ok ? res : null;
  } catch (_) { ckState.h1 = null; }
  return ckState.h1;
}

function ckCanSubmit(f) {
  return ckEffectiveProof(f) === "confirmed" && ckState.h1 && ckState.h1.has_token && ckState.h1.team_handle;
}

async function ckSubmitFinding(f, btn, statusEl) {
  if (!ckCanSubmit(f)) return;
  const handle = ckState.h1.team_handle;
  if (!window.confirm(`File "${f.title}" to the HackerOne team "${handle}"?\n\nThis sends a real report to the live program. Only do this for an in-scope, authorized, CONFIRMED finding.`)) return;
  btn.disabled = true;
  btn.textContent = "Submitting…";
  try {
    const res = await apiFetch("/api/bounty/submit", {
      method: "POST", timeoutMs: 60000,
      body: JSON.stringify({ run_id: f.runId || ckState.runId, ref: f.ref, confirm: true, platform: "hackerone" })
    });
    if (res.ok) {
      ckState.triage[f.ref] = "submitted";
      btn.replaceWith(ckReportLink(res.url, res.report_id));
      if (statusEl) statusEl.textContent = "";
      // Reflect the submitted stage across every view (dashboard, board, history) + persist it.
      ckMarkStatus(f, { stage: "submitted" });
    } else {
      btn.disabled = false; btn.textContent = "Submit to HackerOne";
      if (statusEl) { statusEl.textContent = res.error || "Submit refused."; statusEl.classList.add("is-error"); }
    }
  } catch (err) {
    btn.disabled = false; btn.textContent = "Submit to HackerOne";
    if (statusEl) { statusEl.textContent = err.message || "Submit failed."; statusEl.classList.add("is-error"); }
  }
}

function ckReportLink(url, reportId) {
  const wrap = cel("span", "ck-report-link-group");
  const link = cel("a", "ck-btn", url ? `Submitted ✓ (#${reportId || ""})` : "Submitted ✓");
  if (url) { link.href = url; link.target = "_blank"; link.rel = "noopener noreferrer"; }
  wrap.append(link);
  if (reportId) {
    const checkBtn = cel("button", "ck-btn", "Check status"); checkBtn.type = "button";
    const statusSpan = cel("span", "ck-floc", "");
    checkBtn.addEventListener("click", async () => {
      const label = checkBtn.textContent; checkBtn.disabled = true; checkBtn.textContent = "Checking…";
      try {
        const res = await apiFetch("/api/hackerone/report-status", { method: "POST", body: JSON.stringify({ report_id: String(reportId) }) });
        statusSpan.textContent = (res && res.ok) ? ` — ${res.state || "unknown"}` : ` — ${(res && res.error) || "could not check status"}`;
      } catch (err) {
        statusSpan.textContent = ` — ${err.message || "check failed"}`;
      } finally {
        checkBtn.disabled = false; checkBtn.textContent = label;
      }
    });
    wrap.append(checkBtn, statusSpan);
  }
  return wrap;
}

function ckTakeoverForm() {
  const wrap = cel("div", "ck-creds");
  const head = cel("div", "ck-creds-head");
  head.append(cel("strong", null, "Subdomain takeover"));
  wrap.append(head);
  wrap.append(cel("p", "ck-hint", "Enumerate subdomains of an in-scope apex and confirm dangling-service takeovers (GitHub Pages, S3, Heroku, Fastly, Shopify, …). GET-only, scope-bound — no resource is ever claimed."));
  const form = cel("form", "ck-learn-form");
  const target = ckField("Apex / host (e.g. example.com)", "text", "");
  const scope = ckField("Scope (apex / wildcard)", "text", state.ckScope || "");
  form.append(target.wrap, scope.wrap);
  const run = cel("button", "ck-btn primary", "Scan for takeovers");
  run.type = "submit";
  form.append(run);
  const note = cel("p", "ck-status"); note.style.flexBasis = "100%";
  const out = cel("div", "ck-research");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!target.input.value.trim()) { note.classList.add("is-error"); note.textContent = "Enter an apex/host to enumerate."; return; }
    const label = run.textContent;
    run.disabled = true; run.textContent = "Scanning…";
    note.classList.remove("is-error"); note.textContent = ""; out.replaceChildren();
    try {
      const res = await apiFetch("/api/bounty/takeover", {
        method: "POST", timeoutMs: 120000,
        body: JSON.stringify({ target: target.input.value.trim(), scope: scope.input.value.trim(), platform: ckState.platform || "hackerone" })
      });
      if (!res || res.ok === false) {
        note.classList.add("is-error"); note.textContent = (res && res.error) || "Scan failed.";
      } else {
        note.textContent = `Resolved ${res.resolved_count} in-scope host(s) · ${res.count} takeover(s) confirmed.`;
        if (res.count > 0) {
          ckState.runId = res.run_id || ckState.runId;
          for (const f of (res.findings || [])) out.append(cel("p", "ck-ftitle", "✅ " + f.title));
          // Additive merge (like every other standalone confirm tool) — never wipe an existing
          // hunt/campaign board. Namespaced refs (TK*) avoid colliding with a hunt's F-numbers.
          const tkRows = (res.findings || []).map((f, i) => ({
            ref: f.ref || `TK${i + 1}`, title: f.title, severity: f.severity || "high", proof: "confirmed",
            className: "Subdomain takeover", cwe: "CWE-350 / CWE-284", runId: res.run_id || ckState.runId, plan: {}, cvss: {},
            proofObj: { status: "confirmed" }, description: "", location: f.location || f.host || f.source_url || ""
          }));
          const tkKeys = new Set(tkRows.map(ckFindingUid));
          ckState.findings = (ckState.findings || []).filter((x) => !tkKeys.has(ckFindingUid(x))).concat(tkRows);
          ckBadgeCount("submissions", ckState.findings.length);
          if (res.report) {
            const pre = cel("pre", "ck-research-md");
            pre.textContent = res.report;
            pre.style.whiteSpace = "pre-wrap"; pre.style.maxHeight = "320px"; pre.style.overflow = "auto";
            out.append(pre);
          }
          out.append(cel("p", "ck-hint", "Added to Submissions — Copy report / Download / Submit there."));
        }
      }
    } catch (err) {
      note.classList.add("is-error"); note.textContent = err.message || "Scan failed.";
    } finally {
      run.disabled = false; run.textContent = label;
    }
  });
  form.append(note); wrap.append(form); wrap.append(out);
  return wrap;
}

function ckCveForm() {
  const wrap = cel("div", "ck-creds");
  const head = cel("div", "ck-creds-head");
  head.append(cel("strong", null, "Known-CVE components"));
  wrap.append(head);
  wrap.append(cel("p", "ck-hint", "Fingerprint a page's front-end libraries (jQuery, Lodash, Bootstrap, Moment, AngularJS, Handlebars, DOMPurify) and flag outdated versions with known CVEs. These are version-fingerprint candidates — confirm exploitability before submitting. GET-only, scope-bound."));
  const form = cel("form", "ck-learn-form");
  const target = ckField("URL / host (e.g. https://app.example.com)", "text", "");
  const scope = ckField("Scope (host / wildcard)", "text", state.ckScope || "");
  form.append(target.wrap, scope.wrap);
  const run = cel("button", "ck-btn primary", "Scan components");
  run.type = "submit";
  form.append(run);
  const note = cel("p", "ck-status"); note.style.flexBasis = "100%";
  const out = cel("div", "ck-research");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!target.input.value.trim()) { note.classList.add("is-error"); note.textContent = "Enter a URL/host to scan."; return; }
    const label = run.textContent;
    run.disabled = true; run.textContent = "Scanning…";
    note.classList.remove("is-error"); note.textContent = ""; out.replaceChildren();
    try {
      const res = await apiFetch("/api/bounty/cve", {
        method: "POST", timeoutMs: 120000,
        body: JSON.stringify({ target: target.input.value.trim(), scope: scope.input.value.trim(), platform: ckState.platform || "hackerone" })
      });
      if (!res || res.ok === false) {
        note.classList.add("is-error"); note.textContent = (res && res.error) || "Scan failed.";
      } else {
        note.textContent = `${(res.components || []).length} component(s) fingerprinted · ${res.count} outdated with known CVEs.`;
        if (res.count > 0) {
          ckState.runId = res.run_id || ckState.runId;
          for (const f of (res.findings || [])) out.append(cel("p", "ck-ftitle", "⚠ " + f.title));
          // Additive merge — never discard an existing hunt/campaign board (see takeover above).
          const cveRows = (res.findings || []).map((f, i) => ({
            ref: f.ref || `CVE${i + 1}`, title: f.title, severity: f.severity || "medium", proof: "candidate",
            className: "Vulnerable / outdated component", cwe: "", runId: res.run_id || ckState.runId, plan: {}, cvss: {},
            proofObj: { status: "candidate" }, description: "", location: f.location || f.host || f.source_url || ""
          }));
          const cveKeys = new Set(cveRows.map(ckFindingUid));
          ckState.findings = (ckState.findings || []).filter((x) => !cveKeys.has(ckFindingUid(x))).concat(cveRows);
          ckBadgeCount("submissions", ckState.findings.length);
          if (res.report) {
            const pre = cel("pre", "ck-research-md");
            pre.textContent = res.report;
            pre.style.whiteSpace = "pre-wrap"; pre.style.maxHeight = "320px"; pre.style.overflow = "auto";
            out.append(pre);
          }
          out.append(cel("p", "ck-hint", "Added to Submissions as candidates — Copy report / Download work; Submit stays gated until you confirm exploitability."));
        }
      }
    } catch (err) {
      note.classList.add("is-error"); note.textContent = err.message || "Scan failed.";
    } finally {
      run.disabled = false; run.textContent = label;
    }
  });
  form.append(note); wrap.append(form); wrap.append(out);
  return wrap;
}

function ckRenderSurface() {
  const host = ck.views.surface;
  host.replaceChildren();
  host.append(ckWalkthrough("surface"));
  host.append(ckTakeoverForm());
  host.append(ckCveForm());
  const s = ckState.surface;
  if (!s || !(s.urls || []).length) {
    host.append(cel("p", "ck-hint", "Run a full campaign to map the target's surface (discovered URLs, robots/sitemap/security.txt sources)."));
    return;
  }
  host.append(cel("h2", "ck-section-title", `Surface — ${s.urls.length} in-scope URL(s)`));
  const srcs = s.sources || {};
  if (Object.keys(srcs).length) {
    const p = cel("p", "ck-hint", "Sources: " + Object.entries(srcs).map(([k, v]) => `${k} ${v}`).join(" · "));
    host.append(p);
  }
  for (const note of (s.notes || [])) host.append(cel("p", "ck-hint", note));
  const ul = cel("ul", "ck-list");
  for (const u of s.urls) { const li = cel("li"); li.append(cel("span", "ck-floc", u)); ul.append(li); }
  host.append(ul);
}

function ckTextareaField(label, placeholder) {
  const w = cel("label");
  w.append(cel("span", null, label));
  const ta = cel("textarea");
  ta.rows = 2; ta.autocomplete = "off";
  if (placeholder) ta.placeholder = placeholder;
  w.append(ta);
  return { wrap: w, input: ta };
}

// --- Reusable collapsible "walkthrough" for the cockpit's dense panels ------------
// One declarative spec per panel (keyed below). Each renders a <details> the user can
// fold; the open/closed choice persists per key so a panel a user closes stays closed.
// Pure copy grounded in what each panel actually does — it never changes behaviour.
//   spec = { summary, intro?, defaultOpen?, sections: [{ h4?, ordered?, list }], safety? }
//   a list item is a string, or a ["Bold lead. ", "rest of the sentence"] tuple.
const CK_WALKTHROUGHS = {
  "program": {
    summary: "Program setup — walkthrough",
    intro: "Set up the program you're authorized to test ONCE here, then reuse it everywhere: the launch rail's Program picker fills in Target/Scope, and the same list backs the Operator's autonomous scheduling. This is step one of Program → Hunt → Reports.",
    sections: [
      { h4: "Get the scope in", list: [
        ["Fetch from HackerOne. ", "Enter the program's HackerOne team handle and click Fetch — pulls the program's structured scope via HackerOne's own API, using the API username/token you already saved in Submissions. Many programs restrict this to invited researchers, so a 403/404 here is common, not a bug."],
        ["Import a CSV or paste. ", "No API access? Export or copy the program's scope table from its HackerOne page and paste/upload it — GreyIQ recognizes the real column names (identifier, asset type, eligible for submission/bounty, instruction, max severity) and keeps every column."],
        ["Or just type it. ", "Add scope rows by hand with “+ Add scope row” — an identifier is the only required field."],
      ] },
      { h4: "Review before you hunt", list: [
        "Untick “In scope” on any row you don't want probed — it becomes an exclusion, never an expansion.",
        "A program with no in-scope rows (and no hand-typed Scope) can never go active — the same fail-closed gate the launch rail and Operator use.",
      ] },
      { h4: "Then", ordered: true, list: [
        ["Save the program. ", "It appears in the launch rail's Program picker and the Operator tab."],
        ["Pick it before you hunt. ", "Selecting it in the launch rail fills in Target/Scope — still hand-editable after."],
        ["Set up SSRF/OOB testing (optional). ", "Confirm the program's policy allows out-of-band testing, then jump straight to the Access-control tab's collaborator panel with scope pre-filled."],
      ] },
    ],
    safety: "Only the HackerOne API fetch reaches a non-target host (api.hackerone.com, read-only, only on this explicit click). CSV/paste import is local parsing — nothing is added to scope, and nothing is probed, until you click Save.",
  },
  "ssrf-setup": {
    summary: "Program-specific SSRF/OOB setup — walkthrough",
    defaultOpen: false,
    intro: "Blind SSRF (and blind XXE) are confirmed with an out-of-band collaborator: GreyIQ injects a callback URL into a candidate parameter and watches for the target calling home. The detection itself lives in the Access-control tab's OOB panel — this is the checklist for setting it up per program.",
    sections: [
      { h4: "Before you start", list: [
        ["Confirm the policy allows it. ", "Some programs explicitly forbid interacting with third-party/out-of-network services during testing. Check the program's policy, then tick “This program's policy allows out-of-band / collaborator testing” in its Program-setup form."],
        ["Set up a collaborator once. ", "The Access-control tab's OOB panel needs a collaborator base URL + secret (one-time, global setup) — see its own walkthrough there."],
      ] },
      { h4: "Where to look for SSRF sinks", list: [
        "Webhook / callback URL fields (integrations, notifications).",
        "“Import from URL” / “fetch a file from a link” features (avatars, attachments, feed importers).",
        "Image or link proxies / thumbnail generators.",
        "PDF or screenshot export / “render this URL” tools.",
        "Any parameter that already looks like a URL (redirect, next, return_to, source).",
      ] },
      { h4: "Run it", ordered: true, list: [
        ["Jump over with scope filled in. ", "Use “Set up SSRF/OOB →” on a saved program's row — it carries the program's scope into the Access-control tab's Scope box."],
        ["Mint + probe. ", "In the OOB panel, mint a callback URL, then run the blind-SSRF probe against a candidate endpoint — GreyIQ injects the callback into likely params and polls for a hit."],
      ] },
    ],
    safety: "GET-only against in-scope hosts, with a same-run negative control before anything is marked confirmed. The proof is the out-of-band interaction, never target data.",
  },
  "access-control": {
    summary: "How access-control testing works — walkthrough",
    intro: "These checks prove broken access control with a real differential — never by showing another user's data. Each is GET-only and scope-bound (fail-closed): a host you don't name in Scope is skipped. Work them in this order. (Looking for the blind-SSRF/OOB collaborator panel? Open the “Program-specific SSRF/OOB setup” walkthrough below, or use “Set up SSRF/OOB →” on a program row in the Program tab.)",
    sections: [
      { h4: "Before you start", list: [
        "Two authorized test accounts you control on the SAME host (e.g. a high- and a low-privilege login).",
        "Each account's session: its Cookie, plus any Authorization / extra header it needs.",
        "The target host named in the Scope box of each panel — and written authorization to test it.",
      ] },
      { h4: "The flow", ordered: true, list: [
        ["Scope. ", "Put the target host in the Scope box on each panel — it is the fail-closed gate; an unnamed host is refused."],
        ["Discover — “IDOR discovery — single-session id probe”. ", "Paste one authenticated object URL with a numeric id + that account's session. GreyIQ mutates the id and flags a neighbouring DISTINCT object as a candidate."],
        ["Confirm cross-tenant — “Access control — IDOR / BOLA”. ", "Give account A's object URL + session and account B's OWN object URL + session. Confirmed means B's session read A's object — the proof is the differential, not the data."],
        ["Function-level — “Access control — BFLA”. ", "Give an admin-only endpoint + your high-privilege session and your low-privilege session. Confirmed when the low-privilege session reaches it; an anonymous control proves the endpoint is actually gated."],
        ["Submit. ", "Confirmed findings (and the discovery probe's candidate) land in the Submissions tab — copy, download, or file them there. A borderline dual-session IDOR / BFLA result is reported inline with its differential, not added to Submissions."],
      ] },
    ],
    safety: "Safety: only your own test accounts, only an in-scope host you are authorized to test. GreyIQ never displays or stores another user's data — a confirmed result is an identity/length differential.",
  },
  "hunt": {
    summary: "How a hunt works — walkthrough",
    defaultOpen: false,  // the primary, frequently-used form — start collapsed
    intro: "GreyIQ hunts an authorized target, proves what it can with benign checks, and drafts a submission. A single hunt scans one target; a full campaign also maps the surface and works each confirmed lead. Default runs are passive — active probing only fires when you opt in AND name the host in Scope.",
    sections: [
      { h4: "Set the target", list: [
        "Program (optional) — pick a program you set up in the Program tab and it fills in Target/Scope below; still hand-editable after.",
        "Target — the authorized URL (or local repo path) to hunt.",
        "Scope — name the host(s) you're allowed to probe; this is the fail-closed gate for every active check (an unnamed host stays passive-only).",
        "Profile / Focus class — bias the hunt toward a program's payouts or a single bug class (single hunt only).",
        ["Hunt this program's entire scope (Full campaign only). ", "Appears once you pick a program with more than one derivable target — runs one full campaign per in-scope target (from seed targets, or every eligible row in the program's structured scope) and merges them into one findings board, instead of just the single Target box."],
      ] },
      { h4: "Choose how hard it probes", list: [
        ["Test for proof of impact (active). ", "Fires one benign crafted request per check to turn a lead into a Confirmed proof. Off = passive only."],
        ["Deep SQLi probe. ", "Adds a single bounded, time-based SLEEP check — opt-in, in-scope only."],
        ["Dynamic browser pass (Playwright). ", "Renders the page in a real browser to catch client-side surface."],
        ["Deep auto-work. ", "On a campaign, implies proof of impact + the time-based SQLi probe, then auto-captures a proof screenshot and writes a research dossier for each confirmed lead (needs the host in Scope)."],
      ] },
      { h4: "Run it", ordered: true, list: [
        ["Authorize. ", "Tick “I'm authorized to test this target (in scope)” — no hunt runs until you do, and active checks need it too."],
        ["Behind a login? ", "Open “Scan behind a login” and paste a session Cookie / headers so the hunt sees authenticated pages."],
        ["Run. ", "Findings land in the Findings board with a proof-status column; click any row for the captured proof and a submission draft."],
      ] },
    ],
    safety: "Authorized testing only. Active probes are benign and idempotent, and fire only at a host you named in Scope after you tick the authorization box.",
  },
  "operator": {
    summary: "How the autonomous operator works — walkthrough",
    intro: "The operator works a PORTFOLIO of programs unattended: for each enabled program it runs the full loop on a schedule — recon → hunt → prove → dedup → report. It only files findings when you've armed auto-submit, and the kill switch stops it instantly. (Programs are shared with the Program tab — add/import scope there, tune automation here; both edit the same record.)",
    sections: [
      { h4: "Add a program", list: [
        "Name + Scope — the hosts/wildcards you're authorized to test (the fail-closed gate; active and deep modes need a non-empty scope).",
        "Seed targets — the URLs/hosts to hunt each cycle (each within scope).",
        "Cadence + daily cap — how often it re-runs, and the most it may auto-submit per day.",
        "HackerOne handle — required only if you want auto-submit.",
      ] },
      { h4: "Pick how hard it works each program", list: [
        ["Active. ", "Capture proof of impact with benign crafted probes."],
        ["Deep auto-work. ", "Adds time-based SQLi plus an auto proof-screenshot + research dossier per confirmed lead — needs the host in Scope."],
        ["Auto-submit. ", "FILE confirmed, non-duplicate findings automatically — per-program opt-in, needs a handle, capped per day. Default off (review-only)."],
      ] },
      { h4: "Run it", ordered: true, list: [
        ["Arm (optional). ", "Tick “Arm auto-submit” only if you want hands-off filing — every other gate still applies."],
        ["Start. ", "It runs due programs sequentially; watch the Activity log and the Money pipeline funnel fill in."],
        ["Kill switch. ", "Stop immediately at any time — it halts after the current step."],
      ] },
    ],
    safety: "Auto-submit is triple-gated (armed + per-program opt-in + confirmed & non-duplicate + daily cap) and defaults to review-only. Starting confirms you're authorized to test every enabled program's scope.",
  },
  "surface": {
    summary: "What the Surface tab does — walkthrough",
    intro: "Map and pick apart a target's external surface. Two opt-in tools sit on top of the discovered-URL map; both are GET-only and scope-bound.",
    sections: [
      { h4: "Tools", list: [
        ["Subdomain takeover. ", "Enumerate subdomains of an in-scope apex and confirm dangling-service takeovers (GitHub Pages, S3, Heroku, Fastly, …). No resource is ever claimed."],
        ["Outdated components (CVE). ", "Fingerprint a page's front-end libraries and flag versions with known CVEs — confirm exploitability before submitting."],
      ] },
      { h4: "Surface map", list: [
        "Run a full campaign to populate the discovered-URL list (with its robots / sitemap / security.txt sources).",
        "Use those URLs as seed targets for a focused hunt or the access-control checks.",
      ] },
    ],
    safety: "Both tools are GET-only and only ever act on a host you name in Scope.",
  },
};

function ckWalkthrough(key) {
  const spec = CK_WALKTHROUGHS[key];
  if (!spec) return cel("span");  // unknown key — render nothing (defensive)
  const storeKey = "greyiq.walkthrough." + key;
  const box = cel("details", "ck-walkthrough");
  const stored = localStorage.getItem(storeKey);
  box.open = stored === null ? (spec.defaultOpen !== false) : stored !== "0";  // honour the user's choice once set
  box.addEventListener("toggle", () => {
    try { localStorage.setItem(storeKey, box.open ? "1" : "0"); } catch (_) {}
  });
  box.append(cel("summary", null, spec.summary));
  if (spec.intro) box.append(cel("p", "ck-hint", spec.intro));
  for (const sec of spec.sections || []) {
    if (sec.h4) box.append(cel("h4", null, sec.h4));
    const listEl = cel(sec.ordered ? "ol" : "ul", "ck-steps");
    for (const item of sec.list || []) {
      const li = cel("li");
      if (Array.isArray(item)) { li.append(cel("strong", null, item[0])); li.append(document.createTextNode(item[1])); }
      else li.append(document.createTextNode(item));
      listEl.append(li);
    }
    box.append(listEl);
  }
  if (spec.safety) box.append(cel("p", "ck-hint", spec.safety));
  return box;
}

// --- Program setup — the front door. One program record (name, HackerOne handle,
// structured scope, SSRF/OOB notes) feeds the launch rail's Program picker AND the
// Operator tab's autonomous scheduling — both read/write the same /api/operator/programs
// list, so a program created in either tab shows up in both. -----------------------------
let ckProgEdit = null;   // the program being edited here (null = adding a new one)
let ckProgramsCache = []; // last-fetched program list, shared with the launch-rail picker

let ckProgramsReachable = true;  // false after the last fetch FAILED (engine down) — so an
                                 // empty list is never mislabeled "no programs yet".
async function ckFetchProgramsList() {
  try {
    const data = await apiFetch("/api/operator/programs");
    ckProgramsCache = data.programs || [];
    ckProgramsReachable = true;
  } catch (_) { ckProgramsCache = []; ckProgramsReachable = false; }
  return ckProgramsCache;
}

// Programs can be created/edited/enabled/disabled/deleted from EITHER the Program tab
// or the Operator tab (both read/write the same /api/operator/programs list) -- call
// this after ANY of those mutations, from EITHER tab, so the launch rail's picker never
// goes stale just because the change happened to come from the other tab.
async function ckRefreshProgramsEverywhere() {
  await ckFetchProgramsList();
  ckPopulateActiveProgramSelect();
}

// Delete a program and CASCADE the deletion across the whole app: remove it from the portfolio
// and every view, clear it as the active program, drop its in-memory findings, and delete its
// ledger findings — HIGH/CRITICAL findings are KEPT in the History "Archived" subcategory, the
// rest are purged. Confirms once, returns true on success so the caller can re-render its view.
async function ckDeleteProgram(programId, programName) {
  if (!window.confirm(
    `Delete program "${programName || programId}"?\n\n`
    + `Its findings are deleted too — High/Critical findings are KEPT in History (Archived), `
    + `everything else is permanently removed.`)) return false;
  let res;
  try {
    res = await apiFetch("/api/operator/programs/delete", { method: "POST", body: JSON.stringify({ id: programId }) });
  } catch (err) {
    window.alert(err.message || "Could not delete the program — the engine may be unreachable, so it may still exist.");
    return false;
  }
  if (res && res.ok === false) { window.alert(res.error || "Could not delete the program."); return false; }
  // Register the deletion everywhere so no stale reference survives.
  if (state.ckActiveProgramId === programId) { state.ckActiveProgramId = ""; saveState(); }
  ckState._history = null;   // force the Submissions/History view to reload (findings gone + Archived populated)
  if (Array.isArray(ckState.findings)) {
    ckState.findings = ckState.findings.filter((f) => String(f.program || "") !== String(programId));
  }
  await ckRefreshProgramsEverywhere();
  const kept = (res && res.archived) || 0, purged = (res && res.purged) || 0;
  if (kept || purged) {
    window.alert(`Program deleted. Kept ${kept} High/Critical finding(s) in History → Archived; removed ${purged} other finding(s).`);
  }
  return true;
}

function ckPopulateActiveProgramSelect() {
  if (!ck.activeProgram) return;
  const current = ck.activeProgram.value;
  ck.activeProgram.replaceChildren();
  const none = cel("option", null, "— pick a saved program —"); none.value = "";
  ck.activeProgram.append(none);
  for (const p of ckProgramsCache) {
    const o = cel("option", null, p.name || p.id); o.value = p.id;
    ck.activeProgram.append(o);
  }
  const restore = state.ckActiveProgramId || current;
  if (restore && [...ck.activeProgram.options].some((o) => o.value === restore)) ck.activeProgram.value = restore;
  // Keep the Portfolio multi-select in sync with the same programs cache.
  if (state.ckRunType === "portfolio") ckRenderPortfolioPicker();
}

// Fills Target/Scope from a saved program — still hand-editable after. Only runs on an
// explicit picker change, never silently on boot (that would clobber a hand-edited
// Target/Scope with stale program data on every reload).
function ckApplyActiveProgram(id) {
  state.ckActiveProgramId = id;
  saveState();
  const prog = ckProgramsCache.find((p) => p.id === id);
  if (!prog) { ckUpdateSpanScopeToggle({ resetDefault: true }); return; }
  if (ck.target && prog.seed_targets && prog.seed_targets.length) ck.target.value = prog.seed_targets[0];
  if (ck.scope && prog.scope_text) ck.scope.value = prog.scope_text;
  if (ck.program) ck.program.value = prog.platform_handle || "";
  state.ckTarget = ck.target ? ck.target.value : state.ckTarget;
  state.ckScope = ck.scope ? ck.scope.value : state.ckScope;
  state.ckProgram = ck.program ? ck.program.value : state.ckProgram;
  saveState();
  ckUpdateSpanScopeToggle({ resetDefault: true });
}

// "Span this program's whole scope" -- client-side ESTIMATE of the target list the
// server's campaign.program_campaign_targets would derive (seed_targets, else eligible
// structured_scope entries, wildcard-stripped). Approximate on purpose -- only used for
// a UI count hint; the server always does the authoritative derivation when a campaign
// actually runs, so an estimate mismatch here can never widen what gets hunted.
function ckEstimateSpanTargets(prog) {
  if (!prog) return [];
  const seeds = (prog.seed_targets || []).map((t) => String(t || "").trim()).filter(Boolean);
  if (seeds.length) return [...new Set(seeds)];
  const out = [];
  const seen = new Set();
  for (const entry of prog.structured_scope || []) {
    if (!entry || entry.eligible_for_submission === false) continue;
    const id = String(entry.identifier || "").trim().replace(/^\*\.?/, "").toLowerCase();
    if (id && id.includes(".") && !seen.has(id)) { seen.add(id); out.push(id); }
  }
  return out;
}

function ckUpdateSpanScopeToggle(opts) {
  if (!ck.spanScopeWrap) return;
  const isCampaign = state.ckRunType === "campaign";
  const prog = state.ckActiveProgramId ? ckProgramsCache.find((p) => p.id === state.ckActiveProgramId) : null;
  const n = prog ? ckEstimateSpanTargets(prog).length : 0;
  const show = isCampaign && Boolean(prog) && n > 0;
  ck.spanScopeWrap.hidden = !show;
  if (ck.spanScopeCount) ck.spanScopeCount.textContent = show ? `(${n} target${n === 1 ? "" : "s"})` : "";
  if (!show && ck.spanScope) ck.spanScope.checked = false;
  // Default ON only at the moment a NEW program is picked (opts.resetDefault), and only
  // when there's actually more than one target to span -- never fight a user who
  // explicitly unchecked it afterward on an unrelated re-render (e.g. switching tabs).
  if (show && ck.spanScope && opts && opts.resetDefault) ck.spanScope.checked = n > 1;
  ckUpdateAuthorizedLabel();
}

function ckUpdateAuthorizedLabel() {
  if (!ck.authorized) return;
  const label = ck.authorized.closest("label")?.querySelector("strong");
  if (!label) return;
  const spanning = state.ckRunType === "campaign" && ck.spanScope && !ck.spanScopeWrap?.hidden && ck.spanScope.checked;
  label.textContent = spanning
    ? "I'm authorized to test every in-scope asset in this program (in scope)."
    : "I'm authorized to test this target (in scope).";
}

function ckScopeRowEl(entry) {
  const row = cel("div", "ck-scope-row");
  const id = cel("input"); id.type = "text"; id.placeholder = "*.example.com"; id.value = entry.identifier || "";
  const type = cel("input"); type.type = "text"; type.placeholder = "URL"; type.value = entry.asset_type || "";
  const sub = cel("label", "ck-scope-check");
  const subInput = cel("input"); subInput.type = "checkbox"; subInput.checked = entry.eligible_for_submission !== false;
  sub.append(subInput, cel("span", null, "In scope"));
  const bounty = cel("label", "ck-scope-check");
  const bountyInput = cel("input"); bountyInput.type = "checkbox"; bountyInput.checked = Boolean(entry.eligible_for_bounty);
  bounty.append(bountyInput, cel("span", null, "Bounty"));
  const sev = cel("input"); sev.type = "text"; sev.placeholder = "max severity"; sev.value = entry.max_severity || "";
  const note = cel("input"); note.type = "text"; note.placeholder = "instruction (optional)"; note.value = entry.instruction || "";
  const rm = cel("button", "ck-btn ck-scope-rm", "✕"); rm.type = "button"; rm.title = "Remove row";
  rm.addEventListener("click", () => row.remove());
  row.append(id, type, sub, bounty, sev, note, rm);
  row._ckGet = () => ({
    identifier: id.value.trim(), asset_type: type.value.trim(),
    eligible_for_submission: subInput.checked, eligible_for_bounty: bountyInput.checked,
    max_severity: sev.value.trim(), instruction: note.value.trim(),
  });
  return row;
}

// Mirrors the backend's cap (greyiq_api.ProgramUpsertRequest.structured_scope max_length,
// portfolio._MAX_SCOPE_ENTRIES) so the client truncates gracefully with a visible note
// instead of the whole "Save program" request hard-failing with a generic 422.
const CK_MAX_SCOPE_ENTRIES = 500;

// Dedupe-by-identifier merge of `incoming` rows into `existing`, capped at
// CK_MAX_SCOPE_ENTRIES. Returns { rows, truncated } — used by both the CSV/paste importer
// and the HackerOne fetch button so neither can silently grow the table past what a save
// can actually accept.
function ckMergeScopeRows(existing, incoming) {
  const seen = new Set(existing.map((e) => e.identifier.toLowerCase()));
  const merged = existing.slice();
  let truncated = false;
  for (const r of incoming) {
    if (merged.length >= CK_MAX_SCOPE_ENTRIES) { truncated = true; break; }
    const key = r.identifier.toLowerCase();
    if (!seen.has(key)) { seen.add(key); merged.push(r); }
  }
  return { rows: merged, truncated };
}

function ckScopeTable(initialRows) {
  const wrap = cel("div", "ck-scope-table");
  const header = cel("div", "ck-scope-row ck-scope-head");
  for (const label of ["Identifier", "Asset type", "", "", "Max severity", "Instruction", ""]) header.append(cel("span", null, label));
  wrap.append(header);
  const body = cel("div", "ck-scope-body");
  for (const entry of (initialRows || [])) body.append(ckScopeRowEl(entry));
  wrap.append(body);
  const addRow = cel("button", "ck-btn", "+ Add scope row"); addRow.type = "button";
  addRow.addEventListener("click", () => body.append(ckScopeRowEl({})));
  wrap.append(addRow);
  wrap.ckCollect = () => [...body.querySelectorAll(".ck-scope-row")].map((r) => r._ckGet()).filter((e) => e.identifier);
  wrap.ckReplace = (rows) => { body.replaceChildren(); for (const e of rows) body.append(ckScopeRowEl(e)); };
  return wrap;
}

function ckProgramSetupRow(p) {
  const li = cel("li"); li.style.flexWrap = "wrap";
  const left = cel("div"); left.style.flex = "1";
  left.append(cel("span", "ck-ftitle", p.name || p.id));
  if (p.platform_handle) left.append(document.createTextNode(" "), cel("span", "ck-tag", `HackerOne: ${p.platform_handle}`));
  if (p.oob_allowed) left.append(document.createTextNode(" "), cel("span", "ck-tag", "OOB allowed"));
  if (p.disclose_automation) left.append(document.createTextNode(" "), cel("span", "ck-tag", "Discloses tool use"));
  const stats = p.h1_program_stats || {};
  if (stats.offers_bounties) left.append(document.createTextNode(" "), cel("span", "ck-tag", "Offers bounties"));
  if (stats.fast_payments) left.append(document.createTextNode(" "), cel("span", "ck-tag", "Fast payments"));
  if (stats.gold_standard_safe_harbor) left.append(document.createTextNode(" "), cel("span", "ck-tag", "Gold Standard Safe Harbor"));
  if (stats.open_scope) left.append(document.createTextNode(" "), cel("span", "ck-tag", "Open scope"));
  const n = (p.structured_scope || []).length;
  left.append(cel("div", "ck-floc", `${p.scope_text || "(no scope)"} · ${n} structured scope entr${n === 1 ? "y" : "ies"}`));
  if (stats.number_of_valid_reports_for_user > 0) {
    const earned = stats.bounty_earned_for_user ? ` · $${stats.bounty_earned_for_user} earned` : "";
    left.append(cel("div", "ck-floc", `Your track record: ${stats.number_of_valid_reports_for_user} valid report${stats.number_of_valid_reports_for_user === 1 ? "" : "s"}${earned}`));
  }
  li.append(left);

  const acts = cel("div", "ck-actions"); acts.style.margin = "0";
  const edit = cel("button", "ck-btn", "Edit"); edit.type = "button";
  edit.addEventListener("click", () => {
    ckProgEdit = p;
    void ckRenderProgram();
    setTimeout(() => {
      const f = document.querySelector(".ck-prog-setup-form");
      if (f) { f.scrollIntoView({ behavior: "smooth", block: "center" }); const inp = f.querySelector("input"); if (inp) inp.focus(); }
    }, 60);
  });
  const ssrf = cel("button", "ck-btn", "Set up SSRF/OOB →"); ssrf.type = "button";
  ssrf.title = "Jump to the Access-control tab's OOB panel with this program's scope pre-filled";
  ssrf.addEventListener("click", () => {
    if (!p.oob_allowed && !window.confirm(
      `"${p.name || p.id}" isn't marked as allowing out-of-band/collaborator testing (edit the program and tick that if its policy allows it). Continue to SSRF/OOB setup anyway?`
    )) return;
    // Route through the same apply/select-sync path the picker itself uses, so the
    // always-visible launch-rail Program picker never disagrees with what this shortcut
    // just set Target/Scope to.
    ckApplyActiveProgram(p.id);
    if (ck.activeProgram) ck.activeProgram.value = p.id;
    ckSetView("idor");
  });
  const del = cel("button", "ck-btn", "Delete"); del.type = "button";
  del.addEventListener("click", async () => {
    if (await ckDeleteProgram(p.id, p.name)) void ckRenderProgram();
  });
  acts.append(edit, ssrf, del);
  li.append(acts);
  return li;
}

function ckProgramSetupForm() {
  const editing = ckProgEdit;
  const form = cel("form", "ck-prog-setup-form");
  const name = ckField("Program name", "text", editing ? (editing.name || "") : "");
  const handle = ckField("HackerOne team handle", "text", editing ? (editing.platform_handle || "") : "");
  form.append(name.wrap, handle.wrap);

  // Program-level signals fetched alongside the scope (offers_bounties, fast_payments,
  // etc.) — carried here so a Save persists them even though the form has no dedicated
  // fields for them; re-fetching overwrites this with fresher data.
  let fetchedProgramStats = editing ? (editing.h1_program_stats || {}) : {};

  const fetchBar = cel("div", "ck-import-row");
  const fetchBtn = cel("button", "ck-btn", "Fetch scope from HackerOne"); fetchBtn.type = "button";
  const hacktivityBtn = cel("button", "ck-btn", "Recent hacktivity"); hacktivityBtn.type = "button";
  fetchBar.append(fetchBtn, hacktivityBtn);
  const fetchNote = cel("p", "ck-status");
  form.append(fetchBar, fetchNote);
  const hacktivityPanel = cel("div", "ck-hacktivity-panel"); hacktivityPanel.hidden = true;
  form.append(hacktivityPanel);

  hacktivityBtn.addEventListener("click", async () => {
    const h = handle.input.value.trim();
    if (!h) { fetchNote.className = "ck-status is-error"; fetchNote.textContent = "Enter a HackerOne team handle first."; return; }
    const label = hacktivityBtn.textContent; hacktivityBtn.disabled = true; hacktivityBtn.textContent = "Loading…";
    hacktivityPanel.hidden = false; hacktivityPanel.replaceChildren(cel("p", "ck-status", "Loading recent hacktivity…"));
    try {
      const res = await apiFetch("/api/hackerone/hacktivity", { method: "POST", timeoutMs: 30000, body: JSON.stringify({ team_handle: h }) });
      hacktivityPanel.replaceChildren();
      if (!res || res.ok === false) {
        hacktivityPanel.append(cel("p", "ck-status is-error", (res && res.error) || "Could not fetch hacktivity."));
        return;
      }
      const items = res.items || [];
      if (!items.length) { hacktivityPanel.append(cel("p", "ck-status", "No disclosed hacktivity found for this program.")); return; }
      const table = cel("div", "ck-scope-table");
      const head = cel("div", "ck-scope-row ck-scope-head");
      for (const label of ["Severity", "CWE", "Bounty", "Disclosed", "Title"]) head.append(cel("span", null, label));
      table.append(head);
      const body = cel("div", "ck-scope-body");
      for (const item of items) {
        const row = cel("div", "ck-scope-row");
        row.append(
          cel("span", null, item.severity_rating || "—"),
          cel("span", null, item.cwe || "—"),
          cel("span", null, item.total_awarded_amount != null ? `$${item.total_awarded_amount}` : "—"),
          cel("span", null, (item.disclosed_at || "").slice(0, 10) || "—"),
          cel("span", null, item.title || ""),
        );
        body.append(row);
      }
      table.append(body);
      hacktivityPanel.append(cel("p", "ck-floc", `${items.length} recent disclosed report${items.length === 1 ? "" : "s"} for "${h}" — what's actually getting paid here.`), table);
    } catch (err) {
      hacktivityPanel.replaceChildren(cel("p", "ck-status is-error", err.message || "Fetch failed."));
    } finally {
      hacktivityBtn.disabled = false; hacktivityBtn.textContent = label;
    }
  });

  form.append(cel("h4", null, "Structured scope"));
  const scopeTable = ckScopeTable(editing ? (editing.structured_scope || []) : []);
  form.append(scopeTable);

  fetchBtn.addEventListener("click", async () => {
    const h = handle.input.value.trim();
    if (!h) { fetchNote.className = "ck-status is-error"; fetchNote.textContent = "Enter a HackerOne team handle first."; return; }
    const label = fetchBtn.textContent; fetchBtn.disabled = true; fetchBtn.textContent = "Fetching…";
    fetchNote.className = "ck-status"; fetchNote.textContent = "";
    try {
      const res = await apiFetch("/api/hackerone/import-scope", { method: "POST", timeoutMs: 30000, body: JSON.stringify({ handle: h }) });
      if (!res || res.ok === false) {
        fetchNote.className = "ck-status is-error";
        fetchNote.textContent = (res && res.error) || "Could not fetch scope.";
        return;
      }
      fetchedProgramStats = res.program_stats || {};
      const entries = res.structured_scope || [];
      let mergeNote = "";
      if (entries.length) {
        // Merge (dedupe by identifier, fetched rows win on a match) rather than replace —
        // a fetch must never silently discard hand-typed or CSV-merged rows already in
        // the table.
        const { rows: merged, truncated } = ckMergeScopeRows(
          scopeTable.ckCollect().filter((e) => !entries.some((f) => f.identifier.toLowerCase() === e.identifier.toLowerCase())),
          entries
        );
        scopeTable.ckReplace(merged);
        if (truncated) mergeNote = ` Capped at ${CK_MAX_SCOPE_ENTRIES} scope entries — some existing rows were dropped.`;
      }
      fetchNote.className = "ck-status";
      fetchNote.textContent = `Fetched ${entries.length} scope entr${entries.length === 1 ? "y" : "ies"} for "${res.program_name}".`
        + ((res.warnings || []).length ? " " + res.warnings.join(" ") : "") + mergeNote;
    } catch (err) {
      fetchNote.className = "ck-status is-error"; fetchNote.textContent = err.message || "Fetch failed.";
    } finally {
      fetchBtn.disabled = false; fetchBtn.textContent = label;
    }
  });

  // CSV/paste import merges into the same table (dedupes by identifier) rather than
  // replacing it, so it composes with a HackerOne fetch or hand-typed rows.
  const importNote = cel("p", "ck-status");
  form.append(ckTargetImport(null, null, (rows) => {
    const { rows: merged, truncated } = ckMergeScopeRows(scopeTable.ckCollect(), rows);
    scopeTable.ckReplace(merged);
    importNote.textContent = truncated ? `Capped at ${CK_MAX_SCOPE_ENTRIES} scope entries — some imported rows were dropped.` : "";
  }));
  form.append(importNote);

  const toggles = cel("div", "ck-toggles");
  const oobAllowed = ckToggle("This program's policy allows out-of-band / collaborator testing (SSRF, blind XXE)", editing ? Boolean(editing.oob_allowed) : false);
  toggles.append(oobAllowed.wrap);
  const discloseAutomation = ckToggle("This program's terms require disclosing automated-tool assistance — add a disclosure line to submitted reports", editing ? Boolean(editing.disclose_automation) : false);
  toggles.append(discloseAutomation.wrap);
  form.append(toggles);

  const notes = ckTextareaField("Notes (policy excerpt, reward table, anything worth remembering)", "");
  notes.input.value = editing ? (editing.notes || "") : "";
  notes.input.rows = 3;
  form.append(notes.wrap);

  // --- Hunting requirements: research-account access + a program-mandated user-agent tag ---
  const acc = (editing && editing.account_access) || {};
  const accWrap = cel("div", "ck-subsection");
  accWrap.append(cel("h4", "ck-subhead", "Account access & hunting requirements"));
  accWrap.append(cel("p", "ck-hint", "Give the engine your authorized research account so it hunts logged-in, and any user-agent tag the program requires. Credentials are stored locally and sent only to this program's own login page — the password and session cookie are never shown again after saving."));
  const accEmail = ckField("Research-account email (e.g. your program-assigned alias)", "text", acc.email || "");
  const accPassword = ckField("Password (the engine logs in with this each run)", "password", "");
  if (acc.password_set) accPassword.input.placeholder = "•••••••• saved — leave blank to keep";
  const accLoginUrl = ckField("Login URL (where the engine submits the login)", "text", acc.login_url || "");
  const accRegisterUrl = ckField("Self-register URL (for your reference — register manually first)", "text", acc.register_url || "");
  const accCookie = ckTextareaField("Session cookie — optional fallback if auto-login can't drive the form (CAPTCHA/SSO)", "");
  if (acc.cookie_set) accCookie.input.placeholder = "•••• saved session cookie — leave blank to keep";
  accCookie.input.rows = 2;
  const uaSuffix = ckField('Required user-agent suffix (appended to every request, e.g. " -BugBounty-acme-31337 ")', "text", (editing && editing.user_agent_suffix) || "");
  accWrap.append(accEmail.wrap, accPassword.wrap, accLoginUrl.wrap, accRegisterUrl.wrap, accCookie.wrap, uaSuffix.wrap);
  form.append(accWrap);

  const submit = cel("button", "ck-btn primary", editing ? "Update program" : "Save program");
  submit.type = "submit";
  form.append(submit);
  if (editing) {
    const cancel = cel("button", "ck-btn", "Cancel"); cancel.type = "button";
    cancel.addEventListener("click", () => { ckProgEdit = null; void ckRenderProgram(); });
    form.append(cancel);
  }
  const saveNote = cel("p", "ck-status");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const structuredScope = scopeTable.ckCollect();
    if (!name.input.value.trim()) { saveNote.className = "ck-status is-error"; saveNote.textContent = "Program name is required."; return; }
    const payload = {
      name: name.input.value.trim(),
      platform: handle.input.value.trim() ? "hackerone" : "manual",
      platform_handle: handle.input.value.trim(),
      structured_scope: structuredScope,
      oob_allowed: oobAllowed.input.checked,
      disclose_automation: discloseAutomation.input.checked,
      h1_program_stats: fetchedProgramStats,
      notes: notes.input.value,
      // A blank password/cookie means "keep the saved one" (the server merge-preserves them, since
      // they're read back redacted); email/URLs/suffix are sent verbatim so clearing them takes effect.
      account_access: {
        email: accEmail.input.value.trim(),
        password: accPassword.input.value,
        login_url: accLoginUrl.input.value.trim(),
        register_url: accRegisterUrl.input.value.trim(),
        cookie: accCookie.input.value.trim(),
      },
      user_agent_suffix: uaSuffix.input.value,
      // This form owns the structured-scope table, so a save here should always re-derive
      // scope_text/in_scope_hosts/out_of_scope_hosts from whatever the table currently
      // holds — never echo back a stale value from before this edit. The server no-ops
      // this when structured_scope is empty, so it can't blank out a scope set some other
      // way (e.g. hand-typed via the Operator tab).
      resync_scope: true,
    };
    if (editing) {
      payload.id = editing.id;
      // Fields this form doesn't expose (seed targets, automation toggles) are simply
      // omitted — the server preserves the existing stored value for anything not present
      // in the request instead of resetting it to that field's bare default.
      payload.enabled = editing.enabled;
    }
    submit.disabled = true;  // no double upsert on a slow save
    try {
      await apiFetch("/api/operator/programs", { method: "POST", body: JSON.stringify(payload) });
      ckProgEdit = null;
      saveNote.classList.remove("is-error"); saveNote.textContent = "Saved.";
      await ckRefreshProgramsEverywhere();
      void ckRenderProgram();
    } catch (err) { saveNote.textContent = err.message || "Could not save."; saveNote.classList.add("is-error"); }
    finally { submit.disabled = false; }
  });
  form.append(saveNote);
  return form;
}

let ckProgramRenderGen = 0;  // guards against overlapping renders (Edit + Delete fired in quick succession) clobbering each other out of order

async function ckRenderProgram() {
  const myGen = ++ckProgramRenderGen;
  const host = ck.views.program;
  const programs = await ckFetchProgramsList();
  if (myGen !== ckProgramRenderGen) return;   // a newer call started while this one awaited — it owns the render now, not us
  ckPopulateActiveProgramSelect();

  host.replaceChildren();
  host.append(cel("h2", "ck-section-title", "Program setup"));
  host.append(cel("p", "ck-hint",
    "Set up the program you're authorized to test: its scope, and (optionally) its HackerOne handle. This feeds the Program picker on the launch rail and the Operator's autonomous scheduling — one program, everywhere."));
  host.append(ckWalkthrough("program"));

  host.append(cel("h3", "ck-section-title", `Programs (${programs.length})`));
  if (!programs.length && !ckProgramsReachable) {
    host.append(cel("p", "ck-status is-error", "Couldn't reach the local engine — your programs weren't loaded. This does NOT mean they're gone; retry once the engine is back."));
    const retry = cel("button", "ck-btn", "Retry");
    retry.type = "button";
    retry.addEventListener("click", () => void ckRenderProgram());
    host.append(retry);
  } else if (!programs.length) {
    host.append(cel("p", "ck-hint", "No programs yet — add one below, or fetch/import a scope to get started."));
  } else {
    const list = cel("ul", "ck-list");
    for (const p of programs) list.append(ckProgramSetupRow(p));
    host.append(list);
  }

  host.append(cel("h3", "ck-section-title", ckProgEdit ? `Edit program — ${ckProgEdit.name || ckProgEdit.id}` : "Add a program"));
  host.append(ckProgramSetupForm());
}

// --- Guided first-run wizard — drives the REAL cockpit (real ckSetView navigation, real
// controls), it doesn't simulate a separate flow. Auto-shown once on a clean install (no
// saved programs, no HackerOne creds); always reachable again via the topbar "Guide me"
// button. Persisted dismissal is local-only (localStorage), not a server call. ------------
const CK_WIZARD_STEPS = [
  { title: "Welcome to GreyIQ", body: "Authorized testing only — your own assets, an authorized engagement, or a bug-bounty program you're enrolled in. Every active probe is scope-bound and fails closed: a host you don't name in Scope is never touched. This tour walks Program → Hunt → Reports." },
  { title: "Optional: connect a coding brain", body: "GreyIQ's scanners, proofs, and reports all work fully offline with no model. To get sharper reproduction steps, richer write-ups, and the chat/agent features, connect a brain — the built-in local model (a one-time ~1 GB download), or your own Claude or OpenAI API key. Set it in the Studio (chat) side under model settings; you can do this any time." },
  { title: "1. Add your first program", body: "Give it a name (and its HackerOne handle if it has one). Then pull in real scope: “Fetch scope from HackerOne” (uses the API creds you save in Submissions), or import/paste a CSV, or add rows by hand.", view: "program" },
  { title: "2. Review the scope", body: "Check the structured-scope table — untick “In scope” on anything you don't want probed (that's an exclusion, never an expansion). Click Save program when it looks right.", view: "program" },
  { title: "3. SSRF/OOB setup (optional)", body: "If the program's policy allows out-of-band/collaborator testing, tick that on its form, then use “Set up SSRF/OOB →” on the program row to land here with scope pre-filled. Skip this step if you don't need it.", view: "idor" },
  { title: "4. Run your first hunt", body: "Back in the launch rail: pick your program (fills in Target/Scope), tick “I'm authorized to test this target”, and click Run hunt. Start with a Single hunt before a full campaign.", view: "program", focusSelector: "#ckActiveProgram" },
  { title: "5. Read the results", body: "Findings land here with a proof-status column — Confirmed means GreyIQ actually proved it with a benign probe, not just flagged a pattern. Click any row for the evidence.", view: "findings" },
  { title: "6. Generate a report", body: "Confirmed findings show up in Submissions — copy the Markdown, download it, or (once you've saved HackerOne API creds) submit it directly. Nothing is ever auto-filed without you arming it.", view: "submissions" },
];

function ckDismissWizard() {
  document.querySelector(".ck-wizard")?.remove();
  try { localStorage.setItem("greyiq.wizard.dismissed", "1"); } catch (_) {}
  ckRenderGuideButton();
}

function ckShowWizard(stepIndex) {
  document.querySelector(".ck-wizard")?.remove();
  const i = Math.max(0, Math.min(stepIndex || 0, CK_WIZARD_STEPS.length - 1));
  const step = CK_WIZARD_STEPS[i];
  if (step.view) ckSetView(step.view);
  if (step.focusSelector) {
    setTimeout(() => {
      const el = document.querySelector(step.focusSelector);
      if (el) { el.scrollIntoView({ behavior: "smooth", block: "center" }); el.focus?.(); }
    }, 80);
  }

  const overlay = cel("div", "ck-wizard");
  const card = cel("div", "ck-wizard-card");
  card.append(cel("p", "ck-wizard-step", `Step ${i + 1} of ${CK_WIZARD_STEPS.length}`));
  card.append(cel("h3", null, step.title));
  card.append(cel("p", "ck-hint", step.body));
  const acts = cel("div", "ck-wizard-acts");
  const skip = cel("button", "ck-btn", "Skip tour"); skip.type = "button";
  skip.addEventListener("click", () => ckDismissWizard());
  acts.append(skip);
  if (i > 0) {
    const back = cel("button", "ck-btn", "Back"); back.type = "button";
    back.addEventListener("click", () => ckShowWizard(i - 1));
    acts.append(back);
  }
  const isLast = i === CK_WIZARD_STEPS.length - 1;
  const next = cel("button", "ck-btn primary", isLast ? "Done" : "Next"); next.type = "button";
  next.addEventListener("click", () => { if (isLast) ckDismissWizard(); else ckShowWizard(i + 1); });
  acts.append(next);
  card.append(acts);
  overlay.append(card);
  document.body.append(overlay);
}

function ckRenderGuideButton() {
  if (document.querySelector("#ckGuideBtn")) return;
  const actions = document.querySelector(".ck-topbar-actions");
  if (!actions) return;
  const btn = cel("button", "ck-ghost", "🧭 Guide me"); btn.type = "button"; btn.id = "ckGuideBtn";
  btn.title = "Replay the guided setup tour";
  btn.addEventListener("click", () => ckShowWizard(0));
  actions.prepend(btn);
}

function ckMaybeShowWizard() {
  ckRenderGuideButton();
  let dismissed = false;
  try { dismissed = localStorage.getItem("greyiq.wizard.dismissed") === "1"; } catch (_) {}
  const hasProgram = ckProgramsCache.length > 0;
  const hasCreds = Boolean(ckState.h1 && (ckState.h1.has_token || ckState.h1.api_username));
  if (dismissed || hasProgram || hasCreds) return;
  ckShowWizard(0);
}

// Access control (IDOR/BOLA) — dual-session cross-tenant read confirm. The operator
// supplies their two authorized test accounts; the server proves B can read A's object.
function ckRenderIdor() {
  const host = ck.views.idor;
  host.replaceChildren();
  host.append(cel("h2", "ck-section-title", "Access control — IDOR / BOLA"));
  host.append(cel("p", "ck-hint",
    "Confirm a cross-tenant read with your TWO authorized test accounts. Give account A's object URL + session and account B's OWN object URL + session on the same host. GET-only, scope-bound — another user's data is never shown or stored; the proof is the differential."));
  host.append(ckWalkthrough("access-control"));

  const form = cel("form", "ck-learn-form");
  const urlA = ckField("Account A — object URL", "text", "");
  const urlB = ckField("Account B — its OWN object URL (same host, a DIFFERENT object)", "text", "");
  const aCookie = ckField("Account A — Cookie", "text", "");
  const aHdr = ckTextareaField("Account A — extra headers (one 'Name: value' per line, optional)", "Authorization: Bearer ...");
  const bCookie = ckField("Account B — Cookie", "text", "");
  const bHdr = ckTextareaField("Account B — extra headers (optional)", "");
  const scope = ckField("Scope (name the host to allow testing)", "text", state.ckScope || "");
  form.append(urlA.wrap, urlB.wrap, aCookie.wrap, aHdr.wrap, bCookie.wrap, bHdr.wrap, scope.wrap);

  const run = cel("button", "ck-btn primary", "Confirm IDOR");
  run.type = "submit";
  form.append(run);
  const note = cel("p", "ck-status"); note.style.flexBasis = "100%";
  const out = cel("div", "ck-research");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!urlA.input.value.trim() || !urlB.input.value.trim()) {
      note.classList.add("is-error"); note.textContent = "Both object URLs are required."; return;
    }
    const label = run.textContent;
    run.disabled = true; run.textContent = "Testing…";
    note.classList.remove("is-error"); note.textContent = ""; out.replaceChildren();
    const lines = (v) => v.split("\n").map((s) => s.trim()).filter(Boolean);
    try {
      const res = await apiFetch("/api/bounty/idor", {
        method: "POST", timeoutMs: 60000, body: JSON.stringify({
          url_a: urlA.input.value.trim(), url_b: urlB.input.value.trim(),
          a_cookie: aCookie.input.value.trim(), a_headers: lines(aHdr.input.value),
          b_cookie: bCookie.input.value.trim(), b_headers: lines(bHdr.input.value),
          scope: scope.input.value.trim(), platform: ckState.platform || "hackerone"
        })
      });
      if (!res || res.ok === false) {
        note.classList.add("is-error"); note.textContent = (res && res.error) || "Could not run the check.";
      } else if (res.status === "confirmed") {
        out.append(cel("p", "ck-ftitle", "✅ IDOR / broken access control CONFIRMED"));
        out.append(cel("p", "ck-hint", "Added to Submissions — Copy report / Download / Submit it there."));
        ckState.runId = res.run_id || ckState.runId;
        const row = { runId: res.run_id || ckState.runId, ref: res.ref || "F1", title: res.title || "IDOR / broken access control",
                      severity: res.severity || "high", proof: "confirmed",
                      className: "Broken access control (IDOR/BOLA)", cwe: "CWE-639 / CWE-284",
                      plan: {}, cvss: {}, proofObj: { status: "confirmed" }, description: "" };
        ckState.findings = (ckState.findings || []).filter((f) => !(f.ref === row.ref && f.className === row.className)).concat(row);
        ckBadgeCount("submissions", ckState.findings.filter((f) => f.proof === "confirmed" || f.proof === "candidate").length);
        const pre = cel("pre", "ck-research-md");
        pre.textContent = res.report || "";
        pre.style.whiteSpace = "pre-wrap"; pre.style.maxHeight = "360px"; pre.style.overflow = "auto";
        out.append(pre);
      } else {
        note.textContent = `Not confirmed (${res.status}). ${res.reason || ""}`;
        if (res.detail) out.append(cel("p", "ck-hint", "Differential: " + JSON.stringify(res.detail)));
      }
    } catch (err) {
      note.classList.add("is-error"); note.textContent = err.message || "Check failed.";
    } finally {
      run.disabled = false; run.textContent = label;
    }
  });
  form.append(note);
  host.append(form);
  host.append(out);
  host.append(ckIdorProbeForm());
  host.append(ckBflaForm());
  host.append(ckStoredXssForm());
  host.append(ckWalkthrough("ssrf-setup"));
  host.append(ckOobPanel());
}

function ckStoredXssForm() {
  const wrap = cel("div");
  wrap.append(cel("h3", "ck-section-title", "Stored XSS — persistence confirm"));
  wrap.append(cel("p", "ck-hint",
    "Confirm stored XSS: GreyIQ mints a unique marker payload — submit it into the target field yourself (default, GET-only), then give the view URL to check if it rendered unescaped. Tick “Send automatically” to have GreyIQ POST the payload into the field (its only non-GET egress)."));
  const form = cel("form", "ck-learn-form");
  const viewUrl = ckField("View URL (where the content renders)", "text", "");
  const injectUrl = ckField("Inject URL (form endpoint — auto-send only)", "text", "");
  const field = ckField("Field name (auto-send only)", "text", "");
  const cookie = ckField("Session Cookie (optional)", "text", "");
  const marker = ckField("Marker (to re-check after a manual submit — optional)", "text", "");
  const scope = ckField("Scope (name the host)", "text", state.ckScope || "");
  form.append(viewUrl.wrap, injectUrl.wrap, field.wrap, cookie.wrap, marker.wrap, scope.wrap);
  const sendWrap = cel("label", "ck-hint"); sendWrap.style.flexBasis = "100%";
  const sendBox = cel("input"); sendBox.type = "checkbox"; sendBox.style.marginRight = "6px";
  sendWrap.append(sendBox, document.createTextNode("Send the payload automatically (POST into the field — the only non-GET egress)"));
  form.append(sendWrap);
  const run = cel("button", "ck-btn", "Confirm stored XSS"); run.type = "submit"; form.append(run);
  const note = cel("p", "ck-status"); note.style.flexBasis = "100%";
  const out = cel("div", "ck-research");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!viewUrl.input.value.trim()) { note.classList.add("is-error"); note.textContent = "The view URL is required."; return; }
    const label = run.textContent; run.disabled = true; run.textContent = sendBox.checked ? "Sending…" : "Checking…";
    note.classList.remove("is-error"); note.textContent = ""; out.replaceChildren();
    try {
      const res = await apiFetch("/api/bounty/stored-xss", {
        method: "POST", timeoutMs: 60000, body: JSON.stringify({
          view_url: viewUrl.input.value.trim(), inject_url: injectUrl.input.value.trim(), field: field.input.value.trim(),
          cookie: cookie.input.value.trim(), marker: marker.input.value.trim(), send: sendBox.checked,
          scope: scope.input.value.trim(), platform: ckState.platform || "hackerone"
        })
      });
      if (!res || res.ok === false) {
        note.classList.add("is-error"); note.textContent = (res && res.error) || "Check failed.";
      } else if (res.status === "confirmed") {
        out.append(cel("p", "ck-ftitle", "✅ Stored XSS CONFIRMED"));
        ckState.runId = res.run_id || ckState.runId;
        const row = { runId: res.run_id || ckState.runId, ref: res.ref || "F1", title: res.title || "Stored XSS", severity: res.severity || "high",
                      proof: "confirmed", className: "Stored / persistent XSS", cwe: "CWE-79",
                      plan: {}, cvss: {}, proofObj: { status: "confirmed" }, description: "" };
        ckState.findings = (ckState.findings || []).filter((f) => !(f.ref === row.ref && f.className === row.className)).concat(row);
        ckBadgeCount("submissions", ckState.findings.filter((f) => f.proof === "confirmed" || f.proof === "candidate").length);
        const pre = cel("pre", "ck-research-md"); pre.textContent = res.report || ""; pre.style.whiteSpace = "pre-wrap"; pre.style.maxHeight = "300px"; pre.style.overflow = "auto"; out.append(pre);
      } else if (res.status === "ready") {
        if (res.marker) marker.input.value = res.marker;
        out.append(cel("p", "ck-hint", `Submit one of these into the target field, then click Confirm again (marker ${res.marker}):`));
        const pl = res.payloads || {};
        for (const k of Object.keys(pl)) { out.append(cel("p", "ck-ftitle", k)); const pre = cel("pre", "ck-research-md"); pre.textContent = pl[k]; pre.style.whiteSpace = "pre-wrap"; pre.style.maxHeight = "120px"; pre.style.overflow = "auto"; out.append(pre); }
      } else {
        note.textContent = `Not confirmed (${res.status}). ${res.reason || res.error || ""}`;
      }
    } catch (err) { note.classList.add("is-error"); note.textContent = err.message || "Check failed."; }
    finally { run.disabled = false; run.textContent = label; }
  });
  form.append(note); wrap.append(form); wrap.append(out);
  return wrap;
}

function ckIdorProbeForm() {
  const wrap = cel("div");
  wrap.append(cel("h3", "ck-section-title", "IDOR discovery — single-session id probe"));
  wrap.append(cel("p", "ck-hint",
    "Give ONE authenticated object URL with a numeric id (path or query) + your session. The probe mutates the id and flags a neighbouring DISTINCT object as a candidate — then confirm cross-tenant with the dual-session check above. GET-only, scope-bound."));
  const form = cel("form", "ck-learn-form");
  const url = ckField("Object URL with a numeric id (e.g. https://app/api/order/1001)", "text", "");
  const cookie = ckField("Your session — Cookie", "text", "");
  const scope = ckField("Scope (name the host)", "text", state.ckScope || "");
  form.append(url.wrap, cookie.wrap, scope.wrap);
  const run = cel("button", "ck-btn", "Probe ids"); run.type = "submit"; form.append(run);
  const note = cel("p", "ck-status"); note.style.flexBasis = "100%";
  const out = cel("div", "ck-research");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!url.input.value.trim()) { note.classList.add("is-error"); note.textContent = "Enter an object URL with a numeric id."; return; }
    const label = run.textContent; run.disabled = true; run.textContent = "Probing…";
    note.classList.remove("is-error"); note.textContent = ""; out.replaceChildren();
    try {
      const res = await apiFetch("/api/bounty/idor-probe", {
        method: "POST", timeoutMs: 60000, body: JSON.stringify({
          url: url.input.value.trim(), cookie: cookie.input.value.trim(),
          scope: scope.input.value.trim(), platform: ckState.platform || "hackerone"
        })
      });
      if (!res || res.ok === false) {
        note.classList.add("is-error"); note.textContent = (res && res.error) || "Probe failed.";
      } else if (res.status === "candidate" && res.run_id) {
        out.append(cel("p", "ck-ftitle", "⚠ Possible IDOR (candidate) — confirm cross-tenant with two accounts above"));
        ckState.runId = res.run_id || ckState.runId;
        const row = { runId: res.run_id || ckState.runId, ref: res.ref || "F1", title: res.title || "Possible IDOR (single-session probe)",
                      severity: res.severity || "medium", proof: "candidate",
                      className: "Broken access control (IDOR/BOLA)", cwe: "CWE-639 / CWE-284",
                      plan: {}, cvss: {}, proofObj: { status: "candidate" }, description: "" };
        ckState.findings = (ckState.findings || []).filter((f) => !(f.ref === row.ref && f.className === row.className)).concat(row);
        ckBadgeCount("submissions", ckState.findings.filter((f) => f.proof === "confirmed" || f.proof === "candidate").length);
        const pre = cel("pre", "ck-research-md"); pre.textContent = res.report || ""; pre.style.whiteSpace = "pre-wrap"; pre.style.maxHeight = "300px"; pre.style.overflow = "auto"; out.append(pre);
      } else {
        note.textContent = `No IDOR signal (${res.status}). ${res.reason || ""}`;
      }
    } catch (err) { note.classList.add("is-error"); note.textContent = err.message || "Probe failed."; }
    finally { run.disabled = false; run.textContent = label; }
  });
  form.append(note); wrap.append(form); wrap.append(out);
  return wrap;
}

function ckBflaForm() {
  const wrap = cel("div");
  wrap.append(cel("h2", "ck-section-title", "Access control — BFLA (function-level)"));
  wrap.append(cel("p", "ck-hint",
    "Confirm broken function-level authorization: an admin-only endpoint reachable by a LOW-privilege account. Give the privileged URL + your high-privilege session and your low-privilege session. GET-only, scope-bound — an anonymous control proves the endpoint is gated; the privileged body is never shown."));
  const form = cel("form", "ck-learn-form");
  const url = ckField("Privileged endpoint URL (e.g. https://app/admin/users)", "text", "");
  const adminCookie = ckField("High-privilege account — Cookie", "text", "");
  const adminHdr = ckTextareaField("High-privilege — extra headers (optional)", "Authorization: Bearer ...");
  const userCookie = ckField("Low-privilege account — Cookie", "text", "");
  const userHdr = ckTextareaField("Low-privilege — extra headers (optional)", "");
  const scope = ckField("Scope (name the host to allow testing)", "text", state.ckScope || "");
  form.append(url.wrap, adminCookie.wrap, adminHdr.wrap, userCookie.wrap, userHdr.wrap, scope.wrap);
  const run = cel("button", "ck-btn primary", "Confirm BFLA"); run.type = "submit"; form.append(run);
  const note = cel("p", "ck-status"); note.style.flexBasis = "100%";
  const out = cel("div", "ck-research");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!url.input.value.trim()) { note.classList.add("is-error"); note.textContent = "The privileged endpoint URL is required."; return; }
    const label = run.textContent; run.disabled = true; run.textContent = "Testing…";
    note.classList.remove("is-error"); note.textContent = ""; out.replaceChildren();
    const lines = (v) => v.split("\n").map((s) => s.trim()).filter(Boolean);
    try {
      const res = await apiFetch("/api/bounty/bfla", {
        method: "POST", timeoutMs: 60000, body: JSON.stringify({
          priv_url: url.input.value.trim(),
          admin_cookie: adminCookie.input.value.trim(), admin_headers: lines(adminHdr.input.value),
          user_cookie: userCookie.input.value.trim(), user_headers: lines(userHdr.input.value),
          scope: scope.input.value.trim(), platform: ckState.platform || "hackerone"
        })
      });
      if (!res || res.ok === false) {
        note.classList.add("is-error"); note.textContent = (res && res.error) || "Could not run the check.";
      } else if (res.status === "confirmed") {
        out.append(cel("p", "ck-ftitle", "✅ BFLA / broken function-level authorization CONFIRMED"));
        out.append(cel("p", "ck-hint", "Added to Submissions — Copy report / Download / Submit it there."));
        ckState.runId = res.run_id || ckState.runId;
        const row = { runId: res.run_id || ckState.runId, ref: res.ref || "F1", title: res.title || "Broken function-level authorization",
                      severity: res.severity || "high", proof: "confirmed",
                      className: "Broken function-level authorization (BFLA)", cwe: "CWE-862 / CWE-285",
                      plan: {}, cvss: {}, proofObj: { status: "confirmed" }, description: "" };
        ckState.findings = (ckState.findings || []).filter((f) => !(f.ref === row.ref && f.className === row.className)).concat(row);
        ckBadgeCount("submissions", ckState.findings.filter((f) => f.proof === "confirmed" || f.proof === "candidate").length);
        const pre = cel("pre", "ck-research-md"); pre.textContent = res.report || ""; pre.style.whiteSpace = "pre-wrap"; pre.style.maxHeight = "360px"; pre.style.overflow = "auto"; out.append(pre);
      } else {
        note.textContent = `Not confirmed (${res.status}). ${res.reason || ""}`;
        if (res.detail) out.append(cel("p", "ck-hint", "Differential: " + JSON.stringify(res.detail)));
      }
    } catch (err) { note.classList.add("is-error"); note.textContent = err.message || "Check failed."; }
    finally { run.disabled = false; run.textContent = label; }
  });
  form.append(note); wrap.append(form); wrap.append(out);
  return wrap;
}

// Out-of-band (OOB) collaborator — config + mint + blind-SSRF confirm. Uses your own
// collaborator (e.g. the greynoc-chat /oob endpoint on your phone). The secret is
// write-only (only its presence is returned).
function ckOobPanel() {
  const wrap = cel("div");
  wrap.append(cel("h2", "ck-section-title", "Out-of-band (OOB) — blind SSRF"));
  wrap.append(cel("p", "ck-hint", "Confirm blind bugs with your own collaborator: the probe injects a unique callback URL and polls the collaborator for a hit. Configure your collaborator (e.g. your phone's tunnel), then auto-confirm blind SSRF, or mint a URL to paste into a manual XXE / blind-XSS payload."));

  const cfg = cel("div", "ck-creds");
  const head = cel("div", "ck-creds-head"); head.append(cel("strong", null, "Collaborator"));
  const tag = cel("span", "ck-tag", "…"); head.append(tag); cfg.append(head);
  const form = cel("form", "ck-learn-form");
  const url = ckField("Collaborator base URL (e.g. https://chat.example)", "text", "");
  const secret = ckField("OOB secret", "password", "");
  secret.input.placeholder = "paste secret";
  form.append(url.wrap, secret.wrap);
  const save = cel("button", "ck-btn primary", "Save"); save.type = "submit"; form.append(save);
  const note = cel("p", "ck-status"); note.style.flexBasis = "100%";
  apiFetch("/api/oob/config", { timeoutMs: 6000 }).then((s) => {
    if (s && s.ok) {
      url.input.value = s.collaborator_url || "";
      tag.textContent = (s.has_secret && s.collaborator_url) ? "configured" : "not configured";
      secret.input.placeholder = s.has_secret ? "•••••• (saved — blank keeps it)" : "paste secret";
    }
  }).catch(() => {});
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const s = await apiFetch("/api/oob/config", { method: "POST", body: JSON.stringify({ collaborator_url: url.input.value.trim(), secret: secret.input.value }) });
      tag.textContent = (s && s.has_secret && s.collaborator_url) ? "configured" : "not configured";
      note.classList.remove("is-error"); note.textContent = "Saved."; secret.input.value = "";
    } catch (err) { note.classList.add("is-error"); note.textContent = err.message || "Could not save."; }
  });
  form.append(note); cfg.append(form); wrap.append(cfg);

  const mintBar = cel("div", "ck-actions");
  const mintBtn = cel("button", "ck-btn", "Mint callback URL"); mintBtn.type = "button";
  const mintOut = cel("p", "ck-hint"); mintOut.style.flexBasis = "100%";
  mintBtn.addEventListener("click", async () => {
    try {
      const m = await apiFetch("/api/oob/mint", { method: "POST", body: "{}" });
      mintOut.textContent = (m && m.ok) ? `Paste into a payload: ${m.callback_url}  (token ${m.token})` : ((m && m.error) || "Configure the collaborator first.");
    } catch (err) { mintOut.textContent = err.message || "Mint failed."; }
  });
  mintBar.append(mintBtn); wrap.append(mintBar); wrap.append(mintOut);

  const sform = cel("form", "ck-learn-form");
  const turl = ckField("Target URL (with a server-side-fetch parameter)", "text", "");
  const tscope = ckField("Scope (name the host)", "text", state.ckScope || "");
  sform.append(turl.wrap, tscope.wrap);
  const run = cel("button", "ck-btn primary", "Confirm blind SSRF"); run.type = "submit"; sform.append(run);
  const snote = cel("p", "ck-status"); snote.style.flexBasis = "100%";
  const sout = cel("div", "ck-research");
  sform.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!turl.input.value.trim()) { snote.classList.add("is-error"); snote.textContent = "Enter a target URL."; return; }
    const label = run.textContent; run.disabled = true; run.textContent = "Probing…";
    snote.classList.remove("is-error"); snote.textContent = ""; sout.replaceChildren();
    try {
      const res = await apiFetch("/api/bounty/oob-ssrf", { method: "POST", timeoutMs: 90000, body: JSON.stringify({ url: turl.input.value.trim(), scope: tscope.input.value.trim(), platform: ckState.platform || "hackerone" }) });
      if (!res || res.ok === false) {
        snote.classList.add("is-error"); snote.textContent = (res && res.error) || "Probe failed.";
      } else if (res.status === "confirmed") {
        sout.append(cel("p", "ck-ftitle", `✅ Blind SSRF CONFIRMED via '${res.param}'`));
        ckState.runId = res.run_id || ckState.runId;
        const row = { runId: res.run_id || ckState.runId, ref: res.ref || "F1", title: res.title || "Blind SSRF",
                      severity: res.severity || "high", proof: "confirmed", className: "Server-side request forgery (SSRF)",
                      cwe: "CWE-918", plan: {}, cvss: {}, proofObj: { status: "confirmed" }, description: "" };
        ckState.findings = (ckState.findings || []).filter((f) => !(f.ref === row.ref && f.className === row.className)).concat(row);
        ckBadgeCount("submissions", ckState.findings.filter((f) => f.proof === "confirmed" || f.proof === "candidate").length);
        if (res.report) { const pre = cel("pre", "ck-research-md"); pre.textContent = res.report; pre.style.whiteSpace = "pre-wrap"; pre.style.maxHeight = "320px"; pre.style.overflow = "auto"; sout.append(pre); }
        sout.append(cel("p", "ck-hint", "Added to Submissions."));
      } else {
        snote.textContent = `No out-of-band callback observed (${res.status}). ${res.reason || ""}`;
      }
    } catch (err) { snote.classList.add("is-error"); snote.textContent = err.message || "Probe failed."; }
    finally { run.disabled = false; run.textContent = label; }
  });
  wrap.append(sform); wrap.append(snote); wrap.append(sout);

  // --- Blind XXE over OOB ---
  wrap.append(cel("h2", "ck-section-title", "Out-of-band (OOB) — blind XXE"));
  wrap.append(cel("p", "ck-hint", "Confirm blind XXE. By default GreyIQ hands you ready payload variants to deliver to an XML endpoint yourself (GET-only stays intact), then re-poll the token to confirm. Tick “Send automatically” to have GreyIQ POST the benign payload itself — its only non-GET request."));
  const xform = cel("form", "ck-learn-form");
  const xurl = ckField("XML endpoint URL", "text", "");
  const xscope = ckField("Scope (name the host)", "text", state.ckScope || "");
  const xtoken = ckField("Token (to re-poll after manual delivery — optional)", "text", "");
  xform.append(xurl.wrap, xscope.wrap, xtoken.wrap);
  const sendWrap = cel("label", "ck-hint"); sendWrap.style.flexBasis = "100%";
  const sendBox = cel("input"); sendBox.type = "checkbox"; sendBox.style.marginRight = "6px";
  sendWrap.append(sendBox, document.createTextNode("Send the payload automatically (POST — the only non-GET egress)"));
  xform.append(sendWrap);
  const xrun = cel("button", "ck-btn primary", "Confirm blind XXE"); xrun.type = "submit"; xform.append(xrun);
  const xnote = cel("p", "ck-status"); xnote.style.flexBasis = "100%";
  const xout = cel("div", "ck-research");
  xform.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!xurl.input.value.trim()) { xnote.classList.add("is-error"); xnote.textContent = "Enter the XML endpoint URL."; return; }
    const label = xrun.textContent; xrun.disabled = true; xrun.textContent = sendBox.checked ? "Sending…" : "Polling…";
    xnote.classList.remove("is-error"); xnote.textContent = ""; xout.replaceChildren();
    try {
      const res = await apiFetch("/api/bounty/oob-xxe", { method: "POST", timeoutMs: 90000, body: JSON.stringify({ url: xurl.input.value.trim(), scope: xscope.input.value.trim(), platform: ckState.platform || "hackerone", send: sendBox.checked, token: xtoken.input.value.trim() }) });
      if (!res || res.ok === false) {
        xnote.classList.add("is-error"); xnote.textContent = (res && res.error) || "Probe failed.";
      } else if (res.status === "confirmed" || res.status === "candidate") {
        xout.append(cel("p", "ck-ftitle", res.status === "confirmed" ? "✅ Blind XXE CONFIRMED" : "⚠ Blind XXE candidate (verify the callback source)"));
        ckState.runId = res.run_id || ckState.runId;
        const row = { runId: res.run_id || ckState.runId, ref: res.ref || "F1", title: res.title || "Blind XXE",
                      severity: res.severity || "high", proof: res.status, className: "XML External Entity (XXE)",
                      cwe: "CWE-611", plan: {}, cvss: {}, proofObj: { status: res.status }, description: "" };
        ckState.findings = (ckState.findings || []).filter((f) => !(f.ref === row.ref && f.className === row.className)).concat(row);
        ckBadgeCount("submissions", ckState.findings.filter((f) => f.proof === "confirmed" || f.proof === "candidate").length);
        if (res.report) { const pre = cel("pre", "ck-research-md"); pre.textContent = res.report; pre.style.whiteSpace = "pre-wrap"; pre.style.maxHeight = "320px"; pre.style.overflow = "auto"; xout.append(pre); }
        xout.append(cel("p", "ck-hint", "Added to Submissions."));
      } else if (res.status === "ready") {
        if (res.token) xtoken.input.value = res.token;
        xout.append(cel("p", "ck-hint", `Deliver one of these payloads to the XML endpoint, then click Confirm again to poll token ${res.token}:`));
        const pl = res.payloads || {};
        for (const k of Object.keys(pl)) {
          xout.append(cel("p", "ck-ftitle", k));
          const pre = cel("pre", "ck-research-md"); pre.textContent = pl[k]; pre.style.whiteSpace = "pre-wrap"; pre.style.maxHeight = "180px"; pre.style.overflow = "auto"; xout.append(pre);
        }
      } else {
        xnote.textContent = `No out-of-band callback (${res.status}). ${res.reason || res.error || ""}`;
      }
    } catch (err) { xnote.classList.add("is-error"); xnote.textContent = err.message || "Probe failed."; }
    finally { xrun.disabled = false; xrun.textContent = label; }
  });
  wrap.append(xform); wrap.append(xnote); wrap.append(xout);
  return wrap;
}

// --- "View full report" — the drawers (Findings board + live Campaign) pin a finding open
// on the Submissions page, where its full submission report lives (proof of impact,
// screenshot, everything needed to submit). ---

// Normalize either finding shape (board finding OR campaign-snapshot finding) into one the
// Submissions Full-report panel + report/submit helpers understand, enriching from the board
// findings by stable key so a campaign finding still gets its run/ref (needed to submit).
function ckNormalizeForReport(f, extra) {
  extra = extra || {};
  const focus = {
    ref: f.ref || "",
    runId: f.runId || extra.runId || ckState.runId || "",
    title: f.title || "Finding",
    severity: String(f.severity || "info").toLowerCase(),
    className: f.className || f.class_name || f.cls || f.class_id || "",
    class_id: f.class_id || "",
    rule_id: f.rule_id || f.rule || "",
    cwe: f.cwe || "",
    location: f.location || f.sourceUrl || f.source_url || f.target || "",
    target: f.target || f.location || f.source_url || "",
    cvss: f.cvss || null,
    cvssScore: (f.cvssScore != null ? f.cvssScore : (f.cvss && (f.cvss.base_score ?? f.cvss.score))) ?? null,
    plan: f.plan || null,
    description: f.description || "",
    remediation: f.remediation || "",
    snippet: f.snippet || "",
    matched_value: f.matched_value || (f.proof_evidence && f.proof_evidence.matched_value) || "",
    proofEvidence: f.proof_evidence || f.proofEvidence || null,  // captured request/response + read_data
    // proofObj precedence: an explicit manual re-verify wins, then the finding's OWN active proof
    // captured during the campaign (proof_detail — observed-vs-control differential), so a campaign-
    // confirmed finding's full report renders CONFIRMED without needing a manual re-verify.
    proofObj: f.proofObj || extra.proofObj || (f.proof_detail && typeof f.proof_detail === "object" && f.proof_detail.status ? f.proof_detail : null),
    proof: ckEffectiveProof(f, f.proof_status),
    dedupKey: f.dedupKey || f.dedup_key || "",
    screenshot: extra.screenshot || null,
    apiKeyAccessProof: f.apiKeyAccessProof || f.credential_access_artifact || null,
    apiKeyAccessText: f.apiKeyAccessText || "",
    apiKeyAccessPath: f.apiKeyAccessPath || "",
    apiKeyAccessJsonPath: f.apiKeyAccessJsonPath || "",
    _md: null,   // cached full-report markdown (so a Submissions re-render doesn't refetch)
  };
  if (!focus.ref) {
    const m = ckState.findings.find((x) => ckFindingKey(x) === ckFindingKey(focus));
    if (m) {
      focus.ref = m.ref || "";
      focus.runId = focus.runId || m.runId || "";
      focus.plan = focus.plan || m.plan || null;
      focus.proofObj = focus.proofObj || m.proofObj || null;
      focus.proofEvidence = focus.proofEvidence || m.proof_evidence || m.proofEvidence || null;
      focus.apiKeyAccessProof = focus.apiKeyAccessProof || m.apiKeyAccessProof || null;
      focus.apiKeyAccessText = focus.apiKeyAccessText || m.apiKeyAccessText || "";
      focus.apiKeyAccessPath = focus.apiKeyAccessPath || m.apiKeyAccessPath || "";
      focus.apiKeyAccessJsonPath = focus.apiKeyAccessJsonPath || m.apiKeyAccessJsonPath || "";
      focus.cvss = focus.cvss || m.cvss || null;
      if (focus.cvssScore == null) focus.cvssScore = m.cvssScore ?? null;
      focus.description = focus.description || m.description || "";
    }
  }
  return focus;
}

function ckViewFullReport(f, extra) {
  ckState.reportFocus = ckNormalizeForReport(f, extra);
  ckSetView("submissions");
  // The panel pins to the top of the Submissions page; when opened from a history row deep in
  // the list, bring it into view so the operator lands on the report they asked for.
  const panel = document.querySelector(".ck-fullreport");
  if (panel && panel.scrollIntoView) panel.scrollIntoView({ block: "start" });
}

// The canonical full report for a focused finding. Prefer the run package (build_submission)
// when we have run+ref (board findings); otherwise the general finding→report builder
// (campaign findings, ledger records); offline draft as the last resort.
async function ckFullReportMarkdown(focus) {
  if (focus.runId && focus.ref) {
    try {
      const res = await apiFetch("/api/bounty/submission", {
        method: "POST", timeoutMs: 20000,
        body: JSON.stringify({ run_id: focus.runId, ref: focus.ref, platform: ckState.platform || "hackerone" }),
      });
      if (res && res.ok && res.package && res.package.vulnerability_information) {
        return { text: res.package.vulnerability_information, canonical: true, package: res.package };
      }
    } catch (_) { /* fall through */ }
  }
  try {
    const res = await apiFetch("/api/bounty/finding/report", {
      method: "POST", timeoutMs: 30000,
      body: JSON.stringify({
        title: focus.title, severity: focus.severity, class_name: focus.className, class_id: focus.class_id,
        location: focus.location, cwe: focus.cwe, rule_id: focus.rule_id, target: focus.target || focus.location,
        scope: (ck.scope && ck.scope.value) || state.ckScope || ckCampaign.scope || "",
        platform: ckState.platform || "hackerone", proof: focus.proofObj || null,
        poc: (focus.plan && focus.plan.poc) || "",   // fold the PoC outline into the on-demand report
        // Carry the engine's captured request/response so the report shows the concrete headers
        // (e.g. CORS ACAO/ACAC) and builds the class-specific reproduction from the real evidence.
        proof_evidence: focus.proofEvidence || null,
      }),
    });
    if (res && res.ok && res.package && res.package.vulnerability_information) {
      return { text: res.package.vulnerability_information, canonical: true, package: res.package };
    }
  } catch (_) { /* fall through */ }
  return { text: ckBuildSubmissionDraft(focus), canonical: false, package: null };
}

function ckFullReportPanel(focus) {
  const wrap = cel("div", "ck-creds ck-fullreport");
  const head = cel("div", "ck-creds-head");
  head.append(cel("strong", null, "Full report"));
  head.append(ckProofBadge(ckEffectiveProof(focus)));
  const back = cel("button", "ck-btn", "✕ Close");
  back.type = "button";
  back.title = "Close this report";
  back.style.marginLeft = "auto";
  back.addEventListener("click", () => { ckState.reportFocus = null; ckRenderSubmissions(); });
  head.append(back);
  wrap.append(head);

  wrap.append(cel("h3", "ck-ftitle", focus.title));
  const badges = cel("div", "ck-summary");
  badges.append(cel("span", `ck-sev sev-${focus.severity}`, focus.severity.toUpperCase()));
  badges.append(ckProofBadge(ckEffectiveProof(focus)));
  if (ckEffectiveStage(focus) === "submitted") badges.append(cel("span", "ck-tag", "submitted"));
  if (focus.cwe) badges.append(cel("span", "ck-tag", focus.cwe));
  wrap.append(badges);

  const meta = cel("dl", "ck-meta-grid");
  const add = (k, v) => { if (v) { meta.append(cel("dt", null, k)); meta.append(cel("dd", null, String(v))); } };
  add("Class", focus.className);
  add("Location", focus.location);
  if (focus.target && focus.target !== focus.location) add("Target", focus.target);
  if (focus.cvss && focus.cvss.vector) add("CVSS", `${focus.cvss.vector}${focus.cvssScore != null ? ` (${Number(focus.cvssScore).toFixed(1)})` : ""}`);
  else if (focus.cvssScore != null) add("CVSS", Number(focus.cvssScore).toFixed(1));
  wrap.append(meta);

  const po = focus.proofObj;
  if (po && (po.observed_result || po.control_result || po.evidence || po.proof_obligation)) {
    wrap.append(cel("h4", null, "Proof of impact"));
    const pm = cel("dl", "ck-meta-grid");
    const a2 = (k, v) => { if (v) { pm.append(cel("dt", null, k)); pm.append(cel("dd", null, String(v))); } };
    a2("Status", (po.status || "").replace(/^./, (c) => c.toUpperCase()));
    a2("Observed", po.observed_result);
    a2("Control", po.control_result);
    a2("Evidence", po.evidence);
    if (pm.childNodes.length) wrap.append(pm);
    if (po.status !== "confirmed" && po.proof_obligation) {
      const ob = cel("div", "ck-obligation");
      ob.append(cel("strong", null, "To confirm: "), document.createTextNode(po.proof_obligation));
      wrap.append(ob);
    }
  }

  // Proof of concept — the plan's PoC outline, shown in this view AND folded into the
  // downloaded/copied report (ckFullReportMarkdown passes it through).
  const pocText = ckProofOfConceptArtifact(focus);
  wrap.append(cel("h4", null, "Proof of concept"));
  wrap.append(cel("pre", "ck-poc", pocText || "No runnable PoC artifact is captured yet. Attach an authorized request, command, saved HTML PoC, or working screenshot before submission."));
  wrap.append(cel("h4", null, "Proof of exploitability"));
  wrap.append(cel("pre", "ck-poc", ckBuildProofOfExploitabilityText(focus)));
  if (focus.apiKeyAccessText || focus.apiKeyAccessProof) {
    wrap.append(cel("h4", null, "API key access proof"));
    const pre = cel("pre", "ck-poc", focus.apiKeyAccessText || JSON.stringify(focus.apiKeyAccessProof, null, 2));
    wrap.append(pre);
  }

  // Screenshots: a campaign-prove shot arrives on focus.screenshot; captures done here are
  // stashed on focus.shots so they SURVIVE the panel's own async report-fetch re-render (which
  // rebuilds this whole node). Each image renders with its own Download button.
  const shotWrap = cel("div", "ck-shot");
  const _shotKindLabel = { "source": "Response source (PoC)", "rendered": "Rendered page", "evidence": "Rendered page", "full-page": "Full page" };
  if (focus.screenshot && focus.screenshot.data_url) ckAppendScreenshot(shotWrap, focus.screenshot.data_url, focus.title, "Evidence");
  for (const shot of (focus.shots || [])) {
    if (shot && shot.data_url) ckAppendScreenshot(shotWrap, shot.data_url, focus.title, _shotKindLabel[shot.kind] || shot.kind || "");
  }
  if (focus.shots && focus.shots.length) shotWrap.append(cel("p", "ck-hint", "Saved locally. Review before attaching — screenshots are not auto-redacted."));

  // Report actions are laid out as a workflow, not a flat button pile: a single hero
  // "Prepare full report" that chains the whole pipeline, then the same steps broken out
  // into three ordered stages (Prove → Package → Submit) so the operator keeps full control
  // and every piece stays individually available.
  const actions = cel("div", "ck-report-actions");
  const statusEl = cel("p", "ck-status"); statusEl.style.flexBasis = "100%";
  const resultEl = cel("div", "ck-cd-rv-result"); resultEl.style.flexBasis = "100%"; resultEl.hidden = true;

  // A labeled stage group: a short label column + a wrapping row of its buttons.
  const stage = (label) => {
    const el = cel("div", "ck-stage");
    el.append(cel("div", "ck-stage-label", label));
    const row = cel("div", "ck-stage-row");
    el.append(row);
    return { el, row };
  };

  // ---- Hero: one click runs prove → screenshot → build so the report comes back "done and
  // ready". It only chains steps the operator could run by hand below, so nothing is hidden. ----
  const hero = cel("div", "ck-hero");
  const prepBtn = cel("button", "ck-btn primary ck-hero-btn", "⚡ Prepare full report");
  prepBtn.type = "button";
  prepBtn.title = "One click: prove impact (if not already confirmed), capture a screenshot, and assemble the complete report";
  prepBtn.addEventListener("click", () => ckPrepareFullReport(focus, prepBtn, statusEl, shotWrap));
  hero.append(prepBtn, cel("span", "ck-hero-note", ckReadinessNote(focus)));
  actions.append(hero);

  // ---- Stage 1 · Prove — the two active steps that CHANGE the finding's state. ----
  const s1 = stage("1 · Prove");
  // Actively re-probe this finding's URL in scope and capture the live request/response
  // differential + a screenshot. A candidate is promoted to Confirmed; a Confirmed finding
  // still benefits from a freshly-captured, submittable artifact.
  const proveBtn = cel("button", "ck-btn", ckEffectiveProof(focus) === "confirmed" ? "Get proof of impact" : "Create proof of impact");
  proveBtn.type = "button";
  proveBtn.title = "Actively re-probe this finding in scope and capture the live proof-of-impact artifact (request/response differential + screenshot)";
  proveBtn.addEventListener("click", () => ckCreateProofOfImpact(focus, proveBtn, statusEl, resultEl));
  const hasShots = (focus.shots && focus.shots.length) || (focus.screenshot && focus.screenshot.data_url);
  const shotBtn = cel("button", "ck-btn", hasShots ? "Re-capture screenshot" : "Capture screenshot");
  shotBtn.type = "button";
  shotBtn.title = "Capture annotated + full-page proof screenshots of this finding's page";
  shotBtn.addEventListener("click", () => ckCaptureScreenshot(focus, shotBtn, shotWrap, (shots) => {
    // Persist on the focus so the shots survive a panel re-render, then repaint.
    focus.shots = shots;
    focus._prepMsg = "";  // a fresh manual capture invalidates the last "prepare" caption
    if (ckState.reportFocus === focus && ckState.view === "submissions") ckRenderSubmissions();
  }));
  s1.row.append(proveBtn, shotBtn);
  if (ckCanTestApiKeyAccess(focus)) {
    const keyBtn = cel("button", "ck-btn", focus.apiKeyAccessText ? "Re-test API key access" : "Test API key access");
    keyBtn.type = "button";
    keyBtn.title = "Send one read-only request to the API key's own issuer and save the returned access proof into the PoC bundle";
    keyBtn.addEventListener("click", async () => {
      await ckTestApiKeyAccess(focus, keyBtn, resultEl);
      const m = ckState.findings.find((x) => ckFindingKey(x) === ckFindingKey(focus));
      if (m) {
        m.apiKeyAccessProof = focus.apiKeyAccessProof;
        m.apiKeyAccessText = focus.apiKeyAccessText;
        m.apiKeyAccessPath = focus.apiKeyAccessPath;
        m.apiKeyAccessJsonPath = focus.apiKeyAccessJsonPath;
      }
      focus._md = null;
      if (ckState.reportFocus === focus && ckState.view === "submissions") ckRenderSubmissions();
    });
    s1.row.append(keyBtn);
  }
  actions.append(s1.el);

  // ---- Stage 2 · Package — every export of the finished report, each still separate. ----
  const s2 = stage("2 · Package");
  const copyBtn = cel("button", "ck-btn primary", "Copy report");
  copyBtn.type = "button";
  copyBtn.title = "Copy the full submission report (Markdown) to the clipboard";
  copyBtn.addEventListener("click", async () => {
    copyBtn.disabled = true; copyBtn.textContent = "Preparing…";
    try {
      const pkg = await ckFullReportMarkdown(focus);
      const ok = await ckCopy(pkg.text);
      copyBtn.textContent = ok ? (pkg.canonical ? "Copied ✓" : "Copied (offline)") : "Failed";
    } finally { copyBtn.disabled = false; setTimeout(() => { copyBtn.textContent = "Copy report"; }, 1600); }
  });
  const dlBtn = cel("button", "ck-btn", "Download .md");
  dlBtn.type = "button";
  dlBtn.title = "Download the full report as a Markdown file";
  dlBtn.addEventListener("click", async () => {
    dlBtn.disabled = true; dlBtn.textContent = "Preparing…";
    try { const pkg = await ckFullReportMarkdown(focus); ckDownloadText(`${ckSlug(focus.title)}.md`, pkg.text); }
    finally { dlBtn.disabled = false; dlBtn.textContent = "Download .md"; }
  });
  // Copy JUST the proof of impact + steps + captured responses/data as plain text, to paste
  // straight into a submission's "Proof of impact" field.
  const poiBtn = cel("button", "ck-btn", "Copy proof of impact");
  poiBtn.type = "button";
  poiBtn.title = "Copy just the proof of impact, steps to reproduce, and the captured request/response + sensitive data as plain text";
  poiBtn.addEventListener("click", async () => {
    const ok = await ckCopy(ckBuildProofOfImpactText(focus));
    poiBtn.textContent = ok ? "Copied ✓" : "Copy failed";
    setTimeout(() => { poiBtn.textContent = "Copy proof of impact"; }, 1600);
  });
  const zipBtn = cel("button", "ck-btn", "Download bundle (.zip)");
  zipBtn.type = "button";
  zipBtn.title = "One zip: the report, a PoC/evidence summary, a runnable PoC page, every captured screenshot, and the finding JSON";
  zipBtn.addEventListener("click", () => ckDownloadPocZip(focus, zipBtn));
  s2.row.append(copyBtn, dlBtn, poiBtn, zipBtn);
  actions.append(s2.el);

  // ---- Stage 3 · Submit — terminal step, with an inline reason when it's gated. ----
  const s3 = stage("3 · Submit");
  if (ckEffectiveStage(focus) === "submitted") {
    s3.row.append(ckReportLink("", ""));
  } else {
    const submitBtn = cel("button", "ck-btn primary", "Submit to HackerOne");
    submitBtn.type = "button";
    const can = ckCanSubmit(focus);
    submitBtn.disabled = !can;
    submitBtn.title = can ? "File this confirmed finding to your HackerOne program" : "Blocked — see the reason next to this button";
    submitBtn.addEventListener("click", () => ckSubmitFinding(focus, submitBtn, statusEl));
    s3.row.append(submitBtn);
    if (!can) s3.row.append(cel("p", "ck-gate-note", ckSubmitGateReason(focus)));
  }
  actions.append(s3.el);

  wrap.append(actions, statusEl, shotWrap, resultEl);

  // The full report markdown itself (cached on the focus so a search-keystroke re-render of
  // this page doesn't refetch it).
  const preview = cel("div", "ck-report-preview");
  if (focus._md != null) {
    ckRenderReportPreview(preview, "Submission report", focus._md, `${ckSlug(focus.title)}.md`);
  } else {
    preview.append(cel("p", "ck-hint", "Building the full report…"));
    // Fetch once (a re-render mid-flight — e.g. a search keystroke — must not spawn another),
    // then re-render the page so the cached markdown paints into the live DOM, not a node this
    // render captured that a later re-render already detached.
    if (!focus._mdLoading) {
      focus._mdLoading = true;
      void (async () => {
        const pkg = await ckFullReportMarkdown(focus);
        focus._md = pkg.text;
        focus._mdLoading = false;
        if (ckState.reportFocus === focus && ckState.view === "submissions") {
          // Preserve the search box's focus/caret: this async re-render can land mid-typing
          // (the fetch runs while the operator searches), and replaceChildren() would otherwise
          // steal focus for one keystroke.
          const active = document.activeElement;
          const onSearch = active && active.id === "ckSubSearch";
          const caret = onSearch ? active.selectionStart : null;
          ckRenderSubmissions();
          if (onSearch) {
            const again = document.getElementById("ckSubSearch");
            if (again) { again.focus(); try { again.setSelectionRange(caret, caret); } catch (_) { /* type=search */ } }
          }
        }
      })();
    }
  }
  wrap.append(preview);
  return wrap;
}

// The one-line caption under the hero "Prepare full report" button: the last prepare outcome
// if there is one, otherwise what the pipeline still has to gather to make this submit-ready.
function ckReadinessNote(f) {
  if (f._prepMsg) return f._prepMsg;
  const proof = ckEffectiveProof(f);
  const hasShot = (f.shots && f.shots.length) || (f.screenshot && f.screenshot.data_url);
  if (proof === "confirmed" && hasShot) return "Confirmed with a screenshot attached — ready to package and submit.";
  const missing = [];
  if (proof !== "confirmed") missing.push("proof of impact");
  if (!hasShot) missing.push("a screenshot");
  return `One click runs prove → screenshot → build. Still missing: ${missing.join(" + ")}.`;
}

// Why Submit is gated, in plain terms, shown inline next to the disabled button — mirrors
// exactly the conditions ckCanSubmit checks so the reason is never out of sync with the gate.
function ckSubmitGateReason(f) {
  if (ckEffectiveProof(f) !== "confirmed")
    return "Blocked — impact isn’t confirmed. Run “Prepare full report” or “Create proof of impact” first; only a Confirmed finding can be filed.";
  if (!(ckState.h1 && ckState.h1.has_token))
    return "Blocked — add your HackerOne API token in the credentials bar below.";
  if (!(ckState.h1 && ckState.h1.team_handle))
    return "Blocked — set your HackerOne team handle in the credentials bar below.";
  if (!f.ref)
    return "Blocked — open this finding from the Findings board after the campaign to file it.";
  return "Blocked.";
}

// One-click pipeline behind "Prepare full report": prove (only when not already confirmed, to
// avoid needless live traffic) → capture a screenshot (only if none yet) → build the full report
// markdown. Drives a single status line and stashes everything on the finding, then re-renders so
// the panel paints the finished, submit-ready state. Every step here is ALSO an individual button,
// so this only chains what the operator could do by hand — no hidden behavior.
async function ckPrepareFullReport(f, btn, statusEl, shotWrap) {
  const old = btn.textContent;
  btn.disabled = true;
  f._prepMsg = "";
  const step = (msg) => { statusEl.className = "ck-status"; statusEl.textContent = msg; };
  try {
    // 1 · Prove — only when not already confirmed.
    if (ckEffectiveProof(f) !== "confirmed") {
      const url = String(f.location || f.sourceUrl || "").trim();
      if (url) {
        btn.textContent = "Proving…";
        step(`Step 1 of 3 — actively probing ${url} in scope…`);
        let scope = state.ckScope || "";
        try { const h = new URL(url).hostname; if (h && !scope.split(/\s+/).includes(h)) scope = `${scope} ${h}`.trim(); } catch (_) { /* non-URL location */ }
        try {
          const res = await apiFetch("/api/bounty/finding/prove", {
            method: "POST", timeoutMs: 120000,
            // run_id + ref so the engine persists the captured proof onto this cached run —
            // otherwise step 3 below rebuilds the canonical report and it still reads "candidate".
            body: JSON.stringify({ url, scope, program_id: state.ckActiveProgramId || null,
              run_id: f.runId || "", ref: f.ref || "", authorized: true, screenshot: true }),
          });
          if (res && res.ok !== false) {
            if ((res.confirmed || 0) && ckProofMatchesFinding(res.findings, f)) {
              const best = (res.findings || []).find((x) => x.status === "confirmed");
              if (best) {
                f.proofObj = { status: "confirmed", method: best.method || "", observed_result: best.observed || "",
                               control_result: best.control || "", evidence: best.evidence || "", affected_asset: best.affected_asset || "" };
              }
              ckMarkStatus(f, { proof: "confirmed" });
            }
            const shot = res.screenshot;
            if (shot && shot.ok && shot.data_url) f.shots = (f.shots || []).concat([{ data_url: shot.data_url, kind: "evidence" }]);
          }
        } catch (_) { /* keep going — we still build the report from what we have */ }
      }
    }
    // 2 · Screenshot — only if we still have none (prove with screenshot:true may already have one).
    const hasShot = (f.shots && f.shots.length) || (f.screenshot && f.screenshot.data_url);
    if (!hasShot && (f.location || f.sourceUrl || f.source_url || f.target || f.runId || ckState.runId)) {
      btn.textContent = "Capturing…";
      step("Step 2 of 3 — capturing a proof screenshot…");
      try {
        const res = await apiFetch("/api/bounty/screenshot", {
          method: "POST", timeoutMs: 60000,
          body: JSON.stringify({
            run_id: f.runId || ckState.runId, ref: f.ref || "",
            url: f.location || f.sourceUrl || f.source_url || f.target || "",
            title: f.title || "", location: f.location || f.source_url || "",
            matched_value: f.matched_value || f.snippet || (f.proofObj && (f.proofObj.evidence || f.proofObj.observed_result)) || "",
            scope: (ck.scope?.value || "").trim(),
          }),
        });
        if (res && res.ok) {
          if (res.source_text) f.sourceText = res.source_text;
          const shots = Array.isArray(res.shots) && res.shots.length ? res.shots
            : (res.data_url ? [{ data_url: res.data_url, kind: "evidence" }] : []);
          if (shots.length) f.shots = (f.shots || []).concat(shots);
        }
      } catch (_) { /* keep going — we still build the report */ }
    }
    // 3 · Build the report markdown (cached on the finding so the preview paints without a refetch).
    btn.textContent = "Assembling…";
    step("Step 3 of 3 — assembling the full report…");
    try { const pkg = await ckFullReportMarkdown(f); f._md = pkg.text; } catch (_) { /* the preview block will retry */ }
    f._prepMsg = ckEffectiveProof(f) === "confirmed"
      ? "Full report ready — confirmed, screenshot attached, report built. Package or submit below."
      : "Report built, but impact isn’t confirmed — Submit stays gated. Re-run “Create proof of impact” to confirm it.";
  } finally {
    btn.disabled = false; btn.textContent = old;
    if (ckState.reportFocus === f && ckState.view === "submissions") ckRenderSubmissions();
  }
}

// --- Search / filter / sort for the Submissions page (current-run queue + history). ---
function ckSubMatch(f, opts) {
  const q = String(opts.query || "").toLowerCase().trim();
  if (q) {
    const hay = [
      f.title, f.location || f.source_url || f.sourceUrl || f.target,
      f.className || f.class_name || f.cls || f.class_id, f.cwe, f.program,
    ].map((x) => String(x || "").toLowerCase()).join(" ");
    if (!hay.includes(q)) return false;
  }
  if (opts.sev !== "all" && String(f.severity || "info").toLowerCase() !== opts.sev) return false;
  if (opts.proof !== "all") {
    const p = ckEffectiveProof(f, f.proof_status);
    if (opts.proof === "missing") { if (p === "confirmed" || p === "candidate") return false; }
    else if (p !== opts.proof) return false;
  }
  return true;
}

function ckSubSort(list, sort) {
  const arr = list.slice();
  if (sort === "title") arr.sort((a, b) => String(a.title || "").localeCompare(String(b.title || "")));
  else if (sort === "severity") arr.sort((a, b) =>
    (CK_SEV_RANK[String(b.severity || "info").toLowerCase()] ?? 0) - (CK_SEV_RANK[String(a.severity || "info").toLowerCase()] ?? 0));
  // "recent" keeps the incoming order (server returns newest-first; the run queue is rank order).
  return arr;
}

function ckSubControlsBar() {
  const opts = ckState.sub;
  const wrap = cel("div", "ck-creds ck-sub-controls");
  const head = cel("div", "ck-creds-head");
  head.append(cel("strong", null, "Search · filter · sort"));
  wrap.append(head);

  const row = cel("div", "ck-sub-controls-row");

  const searchLab = cel("label", "ck-sub-search");
  searchLab.append(cel("span", null, "Search"));
  const search = cel("input");
  search.type = "search"; search.id = "ckSubSearch"; search.value = opts.query;
  search.placeholder = "title, URL, class, CWE…"; search.autocomplete = "off";
  search.addEventListener("input", () => {
    const pos = search.selectionStart;
    opts.query = search.value;
    ckRenderSubmissions();
    const again = document.getElementById("ckSubSearch");
    if (again) { again.focus(); try { again.setSelectionRange(pos, pos); } catch (_) { /* type=search quirk */ } }
  });
  searchLab.append(search);
  row.append(searchLab);

  const mkSelect = (label, value, choices, onset) => {
    const lab = cel("label");
    lab.append(cel("span", null, label));
    const sel = cel("select");
    for (const [val, text] of choices) {
      const opt = cel("option", null, text); opt.value = val;
      if (val === value) opt.selected = true;
      sel.append(opt);
    }
    sel.addEventListener("change", () => { onset(sel.value); ckRenderSubmissions(); });
    lab.append(sel);
    return lab;
  };

  row.append(mkSelect("Severity", opts.sev, [
    ["all", "All severities"], ["critical", "Critical"], ["high", "High"],
    ["medium", "Medium"], ["low", "Low"], ["info", "Info"],
  ], (v) => { opts.sev = v; }));
  row.append(mkSelect("Proof", opts.proof, [
    ["all", "Any proof"], ["confirmed", "Confirmed"], ["candidate", "Candidate"], ["missing", "Unproven"],
  ], (v) => { opts.proof = v; }));
  row.append(mkSelect("Sort", opts.sort, [
    ["severity", "Severity"], ["title", "Title (A–Z)"], ["recent", "Most recent"],
  ], (v) => { opts.sort = v; }));

  const active = opts.query || opts.sev !== "all" || opts.proof !== "all" || opts.sort !== "severity";
  if (active) {
    const clear = cel("button", "ck-btn", "Clear");
    clear.type = "button";
    clear.addEventListener("click", () => { ckState.sub = { query: "", sev: "all", proof: "all", sort: "severity" }; ckRenderSubmissions(); });
    row.append(clear);
  }
  wrap.append(row);
  return wrap;
}

function ckRenderSubmissions() {
  const host = ck.views.submissions;
  host.replaceChildren();

  // A finding pinned open from a drawer's "View full report" lives at the top of this page,
  // with everything needed to submit: proof of impact, screenshot, the full report, submit.
  if (ckState.reportFocus) host.append(ckFullReportPanel(ckState.reportFocus));

  host.append(ckCredsBar());
  host.append(ckHackeroneActivityPanel());
  host.append(ckFormatBar());
  host.append(ckReportsExportBar());
  host.append(ckSubControlsBar());
  const opts = ckState.sub;

  // --- This run: findings from the most recent hunt/campaign (in-memory). ---
  const reportable = ckState.findings.filter((f) => ["confirmed", "candidate"].includes(ckEffectiveProof(f)));
  let ready = reportable.filter((f) => ckSubMatch(f, opts));
  if (opts.sort === "severity") {
    // Default: confirmed-first, then by severity rank.
    ready = ready.slice().sort((a, b) =>
      ((ckEffectiveProof(a) === "confirmed" ? 0 : 1) - (ckEffectiveProof(b) === "confirmed" ? 0 : 1))
      || ((CK_SEV_RANK[String(b.severity || "info").toLowerCase()] ?? 0) - (CK_SEV_RANK[String(a.severity || "info").toLowerCase()] ?? 0)));
  } else {
    ready = ckSubSort(ready, opts.sort);
  }
  host.append(cel("h2", "ck-section-title",
    `This run — ${ready.length}${ready.length !== reportable.length ? ` of ${reportable.length}` : ""} reportable`));
  if (!reportable.length) {
    host.append(cel("p", "ck-hint", "Confirmed and candidate findings from the current run land here. Create proof of impact to confirm a candidate — only a Confirmed finding can be filed to HackerOne. Past runs are in “All findings” below."));
  } else if (!ready.length) {
    host.append(cel("p", "ck-hint", "No current-run findings match your search / filter."));
  } else {
    const ul = cel("ul", "ck-list");
    for (const f of ready) ul.append(ckSubmissionRow(f));
    host.append(ul);
  }

  // --- All findings: durable history across every run + program (persistent ledger). ---
  host.append(ckHistorySection());
}

// One row in the current-run submission queue: title + proof, Copy/Download report, Create
// proof of impact (candidates), and Submit (confirmed).
function ckSubmissionRow(f) {
  const li = cel("li");
  li.style.flexWrap = "wrap";

  const left = cel("div");
  left.style.flex = "1";
  left.append(cel("span", "ck-ftitle", f.title), document.createTextNode(" "));
  left.append(ckProofBadge(ckEffectiveProof(f)));
  const submitted = ckEffectiveStage(f) === "submitted" || ckState.triage[f.ref] === "submitted";
  if (submitted) left.append(document.createTextNode(" "), cel("span", "ck-tag", "submitted"));
  li.append(left);

  const acts = cel("div", "ck-actions");
  acts.style.margin = "0";
  const statusEl = cel("p", "ck-status");
  statusEl.style.flexBasis = "100%";
  const resultEl = cel("div", "ck-cd-rv-result");
  resultEl.style.flexBasis = "100%";
  resultEl.hidden = true;

  const viewBtn = cel("button", "ck-btn", "View full report");
  viewBtn.type = "button";
  viewBtn.title = "Open the full report (proof of impact, screenshot, submit) at the top of this page";
  viewBtn.addEventListener("click", () => ckViewFullReport(f));
  acts.append(viewBtn);

  const copyBtn = cel("button", "ck-btn", "Copy report");
  copyBtn.type = "button";
  copyBtn.addEventListener("click", async () => {
    copyBtn.disabled = true; copyBtn.textContent = "Preparing…";
    try {
      const pkg = await ckSubmissionMarkdown(f);
      const ok = await ckCopy(pkg.text);
      copyBtn.textContent = ok ? (pkg.canonical ? "Copied ✓" : "Copied (offline)") : "Failed";
    } finally { copyBtn.disabled = false; setTimeout(() => { copyBtn.textContent = "Copy report"; }, 1600); }
  });
  acts.append(copyBtn);

  const dlBtn = cel("button", "ck-btn", "Download .md");
  dlBtn.type = "button";
  dlBtn.addEventListener("click", async () => {
    dlBtn.disabled = true; dlBtn.textContent = "Preparing…";
    try {
      const pkg = await ckSubmissionMarkdown(f);
      ckDownloadText(`${f.ref}-${ckSlug(f.title)}.md`, pkg.text);
    } finally { dlBtn.disabled = false; dlBtn.textContent = "Download .md"; }
  });
  acts.append(dlBtn);

  // Candidates can be actively proven right here (a separate track, scope-gated).
  if (ckEffectiveProof(f) === "candidate") {
    const proveBtn = cel("button", "ck-btn", "Create proof of impact");
    proveBtn.type = "button";
    proveBtn.addEventListener("click", () => ckCreateProofOfImpact(f, proveBtn, statusEl, resultEl));
    acts.append(proveBtn);
  }

  if (submitted) {
    acts.append(ckReportLink("", ""));
  } else {
    const submitBtn = cel("button", "ck-btn primary", "Submit to HackerOne");
    submitBtn.type = "button";
    const can = ckCanSubmit(f);
    submitBtn.disabled = !can;
    submitBtn.title = can ? "File this confirmed finding to your HackerOne program"
      : (ckEffectiveProof(f) !== "confirmed" ? "Create proof of impact first — only a Confirmed finding can be filed."
        : "Add your HackerOne team handle + API token below.");
    submitBtn.addEventListener("click", () => ckSubmitFinding(f, submitBtn, statusEl));
    acts.append(submitBtn);
  }

  li.append(acts, statusEl, resultEl);
  return li;
}

// Report-format selector — the platform the Copy report / Download .md output is shaped
// for. The server (report_formats) re-frames the SAME finding + the SAME gathered
// evidence per platform; this only picks which framing to export.
function ckFormatBar() {
  const wrap = cel("div", "ck-creds");
  const head = cel("div", "ck-creds-head");
  head.append(cel("strong", null, "Report format"));
  const cur = CK_PLATFORMS.find((p) => p.id === ckState.platform) || CK_PLATFORMS[0];
  head.append(cel("span", "ck-tag", cur.name));
  wrap.append(head);

  const form = cel("div", "ck-learn-form");
  const lab = cel("label");
  lab.append(cel("span", null, "Platform"));
  const sel = cel("select");
  for (const p of CK_PLATFORMS) {
    const opt = cel("option", null, p.name);
    opt.value = p.id;
    if (p.id === ckState.platform) opt.selected = true;
    sel.append(opt);
  }
  sel.addEventListener("change", () => {
    ckState.platform = sel.value || "hackerone";
    ckRenderSubmissions();
  });
  lab.append(sel);
  form.append(lab);
  wrap.append(form);

  wrap.append(cel("p", "ck-hint",
    `Copy report / Download .md produce a ${cur.name}-shaped report with the gathered evidence included. `
    + "The one-click API submit files to HackerOne only."));
  return wrap;
}

// Engagement bundle — one click to download the whole run (reports, per-platform
// packages, evidence, screenshots, research dossiers, JSON) as a .zip.
function ckBundleBar() {
  const wrap = cel("div", "ck-creds");
  const head = cel("div", "ck-creds-head");
  head.append(cel("strong", null, "Engagement bundle"));
  wrap.append(head);
  const btn = cel("button", "ck-btn primary", "Download everything (.zip)");
  btn.type = "button";
  const note = cel("p", "ck-hint", "Reports, per-platform submission packages, captured evidence, screenshots, and research — zipped to submit from.");
  btn.addEventListener("click", () => ckDownloadBundle(btn, note));
  wrap.append(btn);
  wrap.append(note);
  return wrap;
}

async function ckDownloadBundle(btn, note) {
  if (!ckState.runId) { note.textContent = "Run a hunt or campaign first — the bundle packages a finished run."; return; }
  const label = btn.textContent;
  btn.disabled = true; btn.textContent = "Bundling…";
  try {
    const res = await apiFetch("/api/bounty/bundle", {
      method: "POST", timeoutMs: 120000, body: JSON.stringify({ run_id: ckState.runId })
    });
    if (res && res.ok) {
      const skipped = (res.skipped || []).length ? ` (${res.skipped.length} skipped)` : "";
      if (res.inline && res.download_b64) {
        ckDownloadBase64(res.filename || "greyiq-engagement.zip", res.download_b64, "application/zip");
        note.textContent = `Downloaded ${res.file_count} file(s)${skipped}.`;
      } else {
        note.textContent = `Bundle written to ${res.path} (${Math.round((res.zip_bytes || 0) / 1024)} KB)${skipped} — too large to download inline; open it from that path.`;
      }
    } else {
      note.textContent = (res && res.error) || "Could not build the bundle.";
    }
  } catch (err) {
    note.textContent = err.message || "Bundle failed.";
  } finally {
    btn.disabled = false; btn.textContent = label;
  }
}

function ckDownloadBase64(filename, b64, mime) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  const blob = new Blob([arr], { type: mime || "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// The file extension for a screenshot data: URI (jpeg -> jpg), defaulting to png.
function ckShotExt(dataUrl) {
  const m = /^data:image\/([a-z0-9.+-]+)/i.exec(String(dataUrl || ""));
  const t = (m ? m[1] : "png").toLowerCase().replace(/[^a-z0-9]/g, "");
  return t === "jpeg" ? "jpg" : (t || "png");
}

// Save a data: URI (a captured screenshot) to a real file. Returns false on a malformed URI.
function ckDownloadDataUrl(dataUrl, filename) {
  const m = /^data:([^;,]*)(;base64)?,([\s\S]*)$/.exec(String(dataUrl || ""));
  if (!m) return false;
  // Both branches can throw on a malformed payload (atob on non-base64, decodeURIComponent on
  // a bad %-escape). Honor the documented false-return contract so the caller's "Download
  // failed" fallback fires instead of an uncaught exception escaping the click handler.
  try {
    if (m[2]) ckDownloadBase64(filename, m[3], m[1] || "application/octet-stream");
    else ckDownloadText(filename, decodeURIComponent(m[3]), m[1] || "text/plain");
    return true;
  } catch (_) { return false; }
}

// Render a captured screenshot into `wrap` with a "Download screenshot" button beside it, so
// the operator can save just the image (for an attachment) without the whole report. Shared by
// the capture flow, the full-report panel, and the prove/re-probe result.
// --- Minimal in-browser ZIP writer (store method; a CDN lib is blocked by CSP). Produces a
// standard .zip a POC bundle downloads at one click, with no server round-trip so it works for
// any finding including a history one. ---
function ckCrc32(bytes) {
  let c, crc = 0xFFFFFFFF;
  if (!ckCrc32._t) {
    const t = ckCrc32._t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) { c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; }
  }
  for (let i = 0; i < bytes.length; i++) crc = (crc >>> 8) ^ ckCrc32._t[(crc ^ bytes[i]) & 0xFF];
  return (crc ^ 0xFFFFFFFF) >>> 0;
}
function ckZip(files) {
  // files: [{name, data: Uint8Array}] -> Blob
  const enc = new TextEncoder();
  const chunks = []; const central = []; let offset = 0;
  const u16 = (n) => [n & 0xFF, (n >>> 8) & 0xFF];
  const u32 = (n) => [n & 0xFF, (n >>> 8) & 0xFF, (n >>> 16) & 0xFF, (n >>> 24) & 0xFF];
  for (const f of files) {
    const name = enc.encode(f.name); const data = f.data; const crc = ckCrc32(data);
    const local = new Uint8Array([].concat(u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0), u32(crc), u32(data.length), u32(data.length), u16(name.length), u16(0)));
    chunks.push(local, name, data);
    central.push({ header: new Uint8Array([].concat(u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0), u32(crc), u32(data.length), u32(data.length), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset))), name });
    offset += local.length + name.length + data.length;
  }
  const centralStart = offset; let centralSize = 0;
  for (const c of central) { chunks.push(c.header, c.name); centralSize += c.header.length + c.name.length; }
  chunks.push(new Uint8Array([].concat(u32(0x06054b50), u16(0), u16(0), u16(central.length), u16(central.length), u32(centralSize), u32(centralStart), u16(0))));
  return new Blob(chunks, { type: "application/zip" });
}
function ckDataUrlBytes(dataUrl) {
  const m = /^data:[^;,]*;base64,([\s\S]*)$/.exec(String(dataUrl || ""));
  if (!m) return null;
  try {
    const bin = atob(m[1]); const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  } catch (_) { return null; }
}

// A human-readable PoC + evidence summary for the zip (self-contained even if report.md omits
// a section). Built from the finding the panel already holds — no extra fetch.
function ckBuildPocSummary(focus) {
  const L = [];
  const sev = String(focus.severity || "info").replace(/^./, (c) => c.toUpperCase());
  L.push(`# Proof of concept — ${focus.title}`, "");
  L.push(`- **Severity:** ${sev}`);
  if (focus.className) L.push(`- **Class:** ${focus.className}${focus.cwe ? ` (${focus.cwe})` : ""}`);
  if (focus.location) L.push(`- **Location:** ${focus.location}`);
  if (focus.cvss && focus.cvss.vector) L.push(`- **CVSS:** ${focus.cvss.vector}${focus.cvssScore != null ? ` (${Number(focus.cvssScore).toFixed(1)})` : ""}`);
  L.push("");
  const plan = focus.plan || {};
  if (Array.isArray(plan.steps) && plan.steps.length) { L.push("## Steps to reproduce"); plan.steps.forEach((s, i) => L.push(`${i + 1}. ${s}`)); L.push(""); }
  const poc = ckProofOfConceptArtifact(focus);
  L.push("## Proof of concept");
  if (poc) L.push("```", poc, "```", "");
  else L.push("_No runnable PoC artifact is captured yet. Attach an authorized request, command, saved HTML PoC, or working screenshot before submission._", "");
  const po = focus.proofObj;
  if (po && (po.observed_result || po.control_result || po.evidence || po.proof_obligation)) {
    L.push("## Proof of impact");
    if (po.status) L.push(`- **Status:** ${String(po.status).replace(/^./, (c) => c.toUpperCase())}`);
    if (po.observed_result) L.push(`- **Observed:** ${po.observed_result}`);
    if (po.control_result) L.push(`- **Control:** ${po.control_result}`);
    if (po.evidence) L.push(`- **Evidence:** ${po.evidence}`);
    if (po.status !== "confirmed" && po.proof_obligation) L.push(`- **To confirm:** ${po.proof_obligation}`);
    L.push("");
  }
  L.push("## Proof of exploitability", ckBuildProofOfExploitabilityText(focus), "");
  L.push("## Screenshots", "See the `screenshots/` folder — the `*-source.png` shot shows the served response/source that proves the finding.", "");
  L.push("---", "_Screenshots are NOT auto-redacted — review before sharing._");
  return L.join("\n");
}

// A self-contained, class-aware PoC web page for the zip. For a browser-exploitable class it
// carries a REAL, one-click demonstration (nothing runs until the operator clicks) — most
// importantly a CORS PoC that fetches the target with credentials and shows the authenticated
// response read cross-origin, the exact "working PoC" a triager asks for. Everything is escaped;
// the target URL is embedded as a JSON string literal so it can't break out of the script.
function ckBuildPocHtml(focus) {
  const esc = escapeHtml;
  const j = (s) => JSON.stringify(String(s == null ? "" : s));
  const cls = String(focus.class_id || "").toLowerCase();
  const url = String(focus.location || focus.target || "");
  const plan = focus.plan || {};
  const po = focus.proofObj || {};

  let note = "", runnable = "";
  if (cls === "cors") {
    note = "Host this file on ANY origin you control (NOT the target). Open it in a browser that is logged in to the target, then click Run. If the target's authenticated response body appears below, a foreign origin read it — that is the exploit HackerOne wants demonstrated.";
    runnable = [
      '<div class="run"><button id="gx-run" type="button" class="btn">▶ Run PoC — read the target cross-origin</button>',
      '<pre id="gx-out" class="out">Served from this page’s origin. Click Run to fetch the target with credentials.</pre></div>',
      '<script>(function(){var TARGET=' + j(url) + ';var b=document.getElementById("gx-run"),o=document.getElementById("gx-out");',
      'b.addEventListener("click",function(){o.textContent="Fetching "+TARGET+" with credentials from origin "+location.origin+" …";',
      'fetch(TARGET,{credentials:"include",mode:"cors"}).then(function(r){return r.text().then(function(t){return {s:r.status,t:t};});})',
      '.then(function(x){o.textContent="PROVED — "+location.origin+" read the authenticated response cross-origin.\\nHTTP "+x.s+" — "+x.t.length+" bytes of sensitive data:\\n\\n"+x.t.slice(0,6000);})',
      '.catch(function(e){o.textContent="No cross-origin read (the browser blocked it): "+e;});});})();</script>',
    ].join("");
  } else if (cls === "csrf") {
    note = "Opened from a foreign origin with the victim's session, this cross-site POST performs the action with no anti-CSRF token. Add the state-changing parameters the action needs, then submit.";
    runnable = '<form class="run" action="' + esc(url) + '" method="POST" target="_blank"><input name="example" value="change-me"><button type="submit" class="btn">▶ Submit cross-site request</button></form>';
  } else if (cls === "redirect" || cls === "xss") {
    note = cls === "xss"
      ? "Open the URL — for a reflected XSS the marker payload executes in the target's page. (Stored XSS: view the page where it was stored.)"
      : "Follow the link — if the browser lands on the external host, the open redirect is confirmed.";
    runnable = '<div class="run"><a class="btn" href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">▶ Open the crafted URL</a></div>';
  } else {
    note = "This class has no safe one-click browser PoC. Reproduce with the request below and capture the response — the Response source screenshot already shows the served proof.";
    const repro = String(po.evidence || (Array.isArray(plan.steps) && plan.steps[0]) || plan.poc || ("GET " + url));
    runnable = '<pre class="out">' + esc(repro) + '</pre>';
  }

  const section = (h, inner) => inner ? `<section><h2>${esc(h)}</h2>${inner}</section>` : "";
  const stepsHtml = (Array.isArray(plan.steps) && plan.steps.length)
    ? section("Steps to reproduce", "<ol>" + plan.steps.map((s) => `<li>${esc(s)}</li>`).join("") + "</ol>") : "";
  const pocArtifact = ckProofOfConceptArtifact(focus);
  const pocHtml = section("Proof of concept", pocArtifact
    ? `<pre>${esc(pocArtifact)}</pre>`
    : "<p class=\"note\">No runnable PoC artifact is captured yet. Attach an authorized request, command, saved HTML PoC, or working screenshot before submission.</p>");
  let poiHtml = "";
  if (po.observed_result || po.control_result || po.evidence || po.proof_obligation) {
    const row = (k, v) => v ? `<div><b>${esc(k)}:</b> ${esc(String(v))}</div>` : "";
    poiHtml = section("Proof of impact", row("Status", po.status) + row("Observed", po.observed_result)
      + row("Control", po.control_result) + row("Evidence", po.evidence)
      + (po.status !== "confirmed" ? row("To confirm", po.proof_obligation) : ""));
  }
  const shots = [];
  if (focus.screenshot && focus.screenshot.data_url) shots.push(focus.screenshot);
  for (const s of (focus.shots || [])) if (s && s.data_url) shots.push(s);
  const shotsHtml = shots.length ? section("Screenshots",
    shots.map((s) => `<figure><figcaption>${esc(s.kind || "screenshot")}</figcaption><img src="${s.data_url}" alt="proof screenshot"></figure>`).join("")) : "";
  const exploitHtml = section("Proof of exploitability", `<pre>${esc(ckBuildProofOfExploitabilityText(focus))}</pre>`);

  const cvss = focus.cvss && focus.cvss.vector
    ? `${esc(focus.cvss.vector)}${focus.cvssScore != null ? ` (${Number(focus.cvssScore).toFixed(1)})` : ""}` : "";
  return [
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
    `<title>PoC — ${esc(focus.title)}</title><style>`,
    "body{margin:0;font:14px/1.55 system-ui,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e6edf3}",
    "h1{font-size:18px;margin:16px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#8aa0c6;margin:0 0 8px}",
    "section{padding:12px 16px;border-top:1px solid #1e2a44}.meta{margin:0 16px 6px;color:#b6c2da}",
    "code,pre{font-family:ui-monospace,Consolas,monospace}pre{white-space:pre-wrap;word-break:break-word;background:#111a2e;border:1px solid #1e2a44;border-radius:8px;padding:10px}",
    ".warn{background:#3a2a08;color:#ffd98a;padding:10px 16px;border-bottom:2px solid #f0a500;font-size:13px}",
    ".btn{display:inline-block;background:#f0a500;color:#111;border:0;border-radius:8px;padding:9px 14px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none}",
    ".out{margin-top:10px;min-height:2em}.note{color:#b6c2da;margin:0 0 10px}.sev{background:#7a1020;color:#fff;border-radius:5px;padding:1px 7px;font-weight:700;font-size:12px}",
    "figure{margin:0 0 12px}figcaption{color:#8aa0c6;font-size:12px;margin-bottom:4px}img{max-width:100%;border:1px solid #1e2a44;border-radius:8px}",
    "footer{padding:14px 16px;color:#7a88a6;font-size:12px}</style></head><body>",
    '<div class="warn">⚠ Authorized security testing only — run this against a target you are permitted to test. Nothing executes until you click Run.</div>',
    `<h1>${esc(focus.title)}</h1>`,
    `<div class="meta"><span class="sev">${esc(String(focus.severity || "info").toUpperCase())}</span> ${esc(focus.className || "")}${focus.cwe ? " · " + esc(focus.cwe) : ""}</div>`,
    `<div class="meta">Target: <code>${esc(url)}</code></div>`,
    cvss ? `<div class="meta">CVSS: <code>${cvss}</code></div>` : "",
    section("Live proof of concept", (note ? `<p class="note">${esc(note)}</p>` : "") + runnable),
    stepsHtml, pocHtml, poiHtml, exploitHtml, shotsHtml,
    "<footer>Generated by GreyIQ BugHunter. Screenshots and responses are NOT auto-redacted — review before sharing.</footer>",
    "</body></html>",
  ].join("");
}

// A plain-text Proof of impact + steps to reproduce + the captured request/response and the actual
// sensitive data — for the operator to paste straight into their submission. Used by the "Copy
// proof of impact" button AND the steps-and-evidence.txt in the zip.
function ckBuildProofOfImpactText(focus) {
  const L = [];
  const rule = (c) => c.repeat(60);
  L.push(`PROOF OF IMPACT — ${focus.title}`, rule("="), "");
  L.push(`Severity:  ${String(focus.severity || "info").toUpperCase()}`);
  if (focus.className) L.push(`Class:     ${focus.className}${focus.cwe ? ` (${focus.cwe})` : ""}`);
  if (focus.location) L.push(`Location:  ${focus.location}`);
  if (focus.cvss && focus.cvss.vector) L.push(`CVSS:      ${focus.cvss.vector}${focus.cvssScore != null ? ` (${Number(focus.cvssScore).toFixed(1)})` : ""}`);
  L.push("");
  const plan = focus.plan || {};
  if (Array.isArray(plan.steps) && plan.steps.length) {
    L.push("STEPS TO REPRODUCE", rule("-"));
    plan.steps.forEach((s, i) => L.push(`${i + 1}. ${s}`));
    L.push("");
  }
  const poc = ckProofOfConceptArtifact(focus);
  L.push("PROOF OF CONCEPT", rule("-"));
  if (poc) L.push(poc, "");
  else L.push("No runnable PoC artifact is captured yet. Attach an authorized request, command, saved HTML PoC, or working screenshot before submission.", "");
  if (focus.apiKeyAccessText || focus.apiKeyAccessProof) {
    L.push("API KEY ACCESS TEST", rule("-"));
    if (focus.apiKeyAccessText) L.push(String(focus.apiKeyAccessText));
    else L.push(JSON.stringify(focus.apiKeyAccessProof, null, 2));
    L.push("");
  }
  const po = focus.proofObj || {};
  if (po.status || po.observed_result || po.control_result || po.evidence || po.proof_obligation) {
    L.push("PROOF OF IMPACT", rule("-"));
    if (po.status) L.push(`Status:     ${String(po.status).replace(/^./, (c) => c.toUpperCase())}`);
    if (po.method) L.push(`Method:     ${po.method}`);
    if (po.affected_asset) L.push(`Affected:   ${po.affected_asset}`);
    if (po.observed_result) L.push(`Observed:   ${po.observed_result}`);
    if (po.control_result) L.push(`Control:    ${po.control_result}`);
    if (po.evidence) L.push(`Evidence:   ${po.evidence}`);
    if (po.status !== "confirmed" && po.proof_obligation) L.push(`To confirm: ${po.proof_obligation}`);
    L.push("");
  }
  L.push("PROOF OF EXPLOITABILITY", rule("-"), ckBuildProofOfExploitabilityText(focus), "");
  const pe = focus.proofEvidence || {};
  if (pe.request_line || pe.request_header || pe.response_status || pe.matched_value) {
    L.push("CAPTURED REQUEST / RESPONSE", rule("-"));
    if (pe.request_line) L.push(`Request:   ${pe.request_line}`);
    if (pe.request_header) L.push(`Header:    ${pe.request_header}`);
    if (pe.response_status) L.push(`Response:  ${pe.response_status}`);
    if (pe.matched_value) L.push(`Matched:   ${pe.matched_value}`);
    L.push("");
  }
  // Only claim an actual data READ when we captured a real response body (read_data). A bare
  // matched header/banner (matched_value/snippet) is NOT sensitive data read — labeling it so
  // overstates impact and gets reports rejected; show it under a neutral heading instead.
  if (pe.read_data) {
    L.push("SENSITIVE DATA READ (cross-origin / authenticated response)", rule("-"), String(pe.read_data), "");
  } else {
    const ev = focus.matched_value || focus.snippet || "";
    if (ev && ev !== pe.matched_value) L.push("MATCHED EVIDENCE", rule("-"), String(ev), "");
  }
  L.push(rule("-"), "Captured by GreyIQ BugHunter. Review before sharing — screenshots and captured responses are not auto-redacted.");
  return L.join("\n");
}

// One-click PoC bundle: report + PoC/evidence summary + a runnable PoC web page + a plain-text
// steps/evidence file + every captured screenshot + the finding JSON, zipped in the browser. Works
// for any finding (board / campaign / history) with no run.
async function ckDownloadPocZip(focus, btn) {
  const old = btn.textContent; btn.disabled = true; btn.textContent = "Zipping…";
  try {
    const enc = new TextEncoder();
    const files = [];
    const pkg = await ckFullReportMarkdown(focus);
    files.push({ name: "report.md", data: enc.encode(pkg.text || "") });
    files.push({ name: "poc.md", data: enc.encode(ckBuildPocSummary(focus)) });
    files.push({ name: "poc.html", data: enc.encode(ckBuildPocHtml(focus)) });
    files.push({ name: "steps-and-evidence.txt", data: enc.encode(ckBuildProofOfImpactText(focus)) });
    if (focus.sourceText) files.push({ name: "response-source.txt", data: enc.encode(String(focus.sourceText)) });
    if (focus.apiKeyAccessText) files.push({ name: "api-key-access.txt", data: enc.encode(String(focus.apiKeyAccessText)) });
    if (focus.apiKeyAccessProof) files.push({ name: "api-key-access.json", data: enc.encode(JSON.stringify(focus.apiKeyAccessProof, null, 2)) });
    const shots = [];
    if (focus.screenshot && focus.screenshot.data_url) shots.push({ data_url: focus.screenshot.data_url, kind: "evidence", path: "" });
    for (const s of (focus.shots || [])) if (s && s.data_url) shots.push(s);
    let n = 0; const shotNames = [];
    for (const s of shots) {
      const bytes = ckDataUrlBytes(s.data_url); if (!bytes) continue;
      n++;
      const base = s.path ? s.path.replace(/\\/g, "/").split("/").pop() : `${n}-${ckSlug(s.kind || "shot")}.png`;
      files.push({ name: "screenshots/" + base, data: bytes });
      shotNames.push(base);
    }
    files.push({ name: "finding.json", data: enc.encode(JSON.stringify({
      title: focus.title, severity: focus.severity, class: focus.className, class_id: focus.class_id,
      cwe: focus.cwe, location: focus.location, cvss: focus.cvss || null, proof: focus.proofObj || null,
      api_key_access: focus.apiKeyAccessProof || null,
      screenshots: shotNames,
    }, null, 2)) });
    const blob = ckZip(files);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `${ckSlug(focus.title)}-poc.zip`;
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    btn.textContent = `Downloaded ✓ (${files.length} files)`;
  } catch (err) {
    btn.textContent = "Zip failed";
  } finally {
    setTimeout(() => { btn.disabled = false; btn.textContent = old; }, 1800);
  }
}

function ckAppendScreenshot(wrap, dataUrl, nameBase, label) {
  if (label) wrap.append(cel("p", "ck-shot-label", label));
  const img = cel("img", "ck-shot-img");
  img.src = dataUrl;                       // data: URI, not markup — safe
  img.alt = "Proof-of-concept screenshot" + (label ? " — " + label : "");
  wrap.append(img);
  const bar = cel("div", "ck-actions"); bar.style.margin = "0.3rem 0 0";
  const dl = cel("button", "ck-btn", "Download screenshot");
  dl.type = "button";
  dl.addEventListener("click", () => {
    const base = ckSlug(nameBase || "finding") + (label ? "-" + ckSlug(label) : "");
    const ok = ckDownloadDataUrl(dataUrl, `${base}-screenshot.${ckShotExt(dataUrl)}`);
    if (!ok) { dl.textContent = "Download failed"; setTimeout(() => { dl.textContent = "Download screenshot"; }, 1600); }
  });
  bar.append(dl);
  wrap.append(bar);
}

// --- Reports & export bar: engagement (special) report for the current run, the full-run
// .zip bundle, and a CSV of every finding across all runs. ---
function ckReportsExportBar() {
  const wrap = cel("div", "ck-creds");
  const head = cel("div", "ck-creds-head");
  head.append(cel("strong", null, "Reports & export"));
  wrap.append(head);
  const row = cel("div", "ck-actions"); row.style.margin = "0";
  const preview = cel("div", "ck-report-preview");

  const engBtn = cel("button", "ck-btn primary", "Generate engagement report");
  engBtn.type = "button";
  engBtn.disabled = !ckState.runId;
  engBtn.title = ckState.runId ? "One document across all findings in this run" : "Run a hunt or campaign first";
  engBtn.addEventListener("click", () => ckGenerateEngagementReport({ run_id: ckState.runId }, engBtn, preview));
  row.append(engBtn);

  const zipBtn = cel("button", "ck-btn", "Download everything (.zip)");
  zipBtn.type = "button";
  zipBtn.disabled = !ckState.runId;
  const zipNote = cel("p", "ck-hint", "");
  zipBtn.addEventListener("click", () => ckDownloadBundle(zipBtn, zipNote));
  row.append(zipBtn);

  const csvBtn = cel("button", "ck-btn", "Export CSV (all findings)");
  csvBtn.type = "button";
  csvBtn.addEventListener("click", () => ckExportLedgerCsv(csvBtn));
  row.append(csvBtn);

  wrap.append(row);
  wrap.append(cel("p", "ck-hint",
    "Engagement report = one polished document across a run's findings. .zip = the whole run (reports, evidence, screenshots). CSV = every finding across all runs, for a spreadsheet."));
  wrap.append(zipNote);
  wrap.append(preview);
  return wrap;
}

async function ckGenerateEngagementReport(source, btn, previewEl) {
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = "Generating…";
  try {
    const res = await apiFetch("/api/bounty/report/aggregate", {
      method: "POST", timeoutMs: 60000,
      body: JSON.stringify({ ...source, platform: ckState.platform || "hackerone" }),
    });
    if (!res || res.ok === false) {
      previewEl.replaceChildren(cel("p", "ck-status is-error", (res && res.error) || "Could not build the report."));
    } else {
      ckRenderReportPreview(previewEl, "Engagement report", res.markdown || "", res.filename || "engagement-report.md");
    }
  } catch (err) {
    previewEl.replaceChildren(cel("p", "ck-status is-error", err.message || "Could not reach the engine."));
  } finally {
    btn.disabled = false; btn.textContent = old;
  }
}

// A generated report: a Copy + Download bar above a scrollable markdown preview.
function ckRenderReportPreview(container, title, markdown, filename) {
  container.replaceChildren();
  const bar = cel("div", "ck-actions"); bar.style.margin = "0.5rem 0 0.3rem";
  bar.append(cel("strong", null, title));
  const copy = cel("button", "ck-btn", "Copy");
  copy.type = "button";
  copy.addEventListener("click", async () => {
    const ok = await ckCopy(markdown);
    copy.textContent = ok ? "Copied ✓" : "Failed";
    setTimeout(() => { copy.textContent = "Copy"; }, 1500);
  });
  const dl = cel("button", "ck-btn", "Download .md");
  dl.type = "button";
  dl.addEventListener("click", () => ckDownloadText(filename, markdown));
  bar.append(copy, dl);
  container.append(bar);
  const pre = cel("pre", "ck-report-md");
  pre.textContent = markdown;
  container.append(pre);
}

async function ckExportLedgerCsv(btn) {
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = "Exporting…";
  try {
    const res = await apiFetch("/api/bounty/ledger-csv", { method: "GET", timeoutMs: 30000 });
    if (!res || res.ok === false || !res.csv) {
      btn.textContent = res && res.row_count === 0 ? "No findings yet" : "Failed";
    } else {
      ckDownloadText("greyiq-findings.csv", res.csv, "text/csv");
      btn.textContent = `Downloaded (${res.row_count || 0})`;
    }
  } catch (_) {
    btn.textContent = "Failed";
  } finally {
    setTimeout(() => { btn.textContent = old; btn.disabled = false; }, 1800);
  }
}

// --- All findings (history): the durable, cross-run ledger, grouped by program. ---
function ckHistorySection() {
  const wrap = cel("div", "ck-hist");
  const head = cel("div", "ck-row-between");
  head.append(cel("h2", "ck-section-title", "All findings — history"));
  const refresh = cel("button", "ck-btn", "Refresh");
  refresh.type = "button";
  refresh.title = "Reload finding history from the engine";
  refresh.addEventListener("click", () => { ckState._history = null; ckRenderSubmissions(); });
  head.append(refresh);
  wrap.append(head);
  const body = cel("div", "ck-hist-body");
  wrap.append(body);
  // Cache the loaded ledger so search / filter / sort re-renders filter it instantly instead
  // of refetching on every keystroke; the Refresh button clears the cache to reload.
  if (ckState._history) ckRenderHistory(body, ckState._history);
  else { body.append(cel("p", "ck-hint", "Loading finding history…")); void ckLoadHistory(body); }
  return wrap;
}

async function ckLoadHistory(body) {
  let res;
  try { res = await apiFetch("/api/bounty/findings", { method: "GET", timeoutMs: 15000 }); }
  catch (_) { body.replaceChildren(cel("p", "ck-hint", "Could not load history — the engine is unreachable.")); return; }
  if (!res || res.ok === false) { body.replaceChildren(cel("p", "ck-hint", "Could not load history.")); return; }
  ckState._history = { findings: res.findings || [], funnel: res.funnel || null, truncated: Boolean(res.truncated), archived: res.archived || [] };
  ckRenderHistory(body, ckState._history);
}

function ckRenderHistory(body, data) {
  const allRecs = data.findings || [];
  const opts = ckState.sub;
  body.replaceChildren();
  if (!allRecs.length) {
    body.append(cel("p", "ck-hint", "No findings recorded yet. Every hunt + campaign records its findings here — this list persists across restarts, unlike the current run above."));
    return;
  }
  const fn = (data.funnel && data.funnel.portfolio) || data.funnel || {};
  const st = fn.stages || {};
  body.append(cel("p", "ck-hint",
    `${fn.total || allRecs.length} findings · ${st.confirmed || 0} confirmed · ${st.submitted || 0} submitted · ${st.paid || 0} paid · $${fn.bounty_total || 0} to date`
    + (data.truncated ? ` · showing the ${allRecs.length} most recent (export CSV for all)` : "")));

  const findings = ckSubSort(allRecs.filter((r) => ckSubMatch(r, opts)), opts.sort);
  const archived = ckSubSort((data.archived || []).filter((r) => ckSubMatch(r, opts)), opts.sort);
  if (!findings.length && !archived.length) {
    body.append(cel("p", "ck-hint", `No findings match your search / filter (${allRecs.length} total).`));
    return;
  }

  // Group by program bucket; each program gets a header with a one-click engagement report.
  const byProg = {};
  for (const r of findings) (byProg[r.program] = byProg[r.program] || []).push(r);
  for (const [prog, recs] of Object.entries(byProg)) {
    const phead = cel("div", "ck-hist-prog");
    phead.append(cel("strong", null, prog || "(unnamed program)"));
    phead.append(cel("span", "ck-tag", `${recs.length}`));
    const engBtn = cel("button", "ck-btn", "Engagement report");
    engBtn.type = "button";
    const preview = cel("div", "ck-report-preview");
    engBtn.addEventListener("click", () => ckGenerateEngagementReport({ program: prog }, engBtn, preview));
    phead.append(engBtn);
    body.append(phead);
    const ul = cel("ul", "ck-list");
    for (const r of recs) ul.append(ckHistoryRow(r));
    body.append(ul, preview);
  }

  // History subcategory: HIGH/CRITICAL findings KEPT from deleted programs (read-only archive).
  if (archived.length) {
    const ahead = cel("div", "ck-hist-prog ck-hist-archived");
    ahead.append(cel("strong", null, "Archived — High/Critical from deleted programs"));
    ahead.append(cel("span", "ck-tag", `${archived.length}`));
    body.append(ahead);
    const aul = cel("ul", "ck-list");
    for (const r of archived) aul.append(ckHistoryRow(r));
    body.append(aul);
  }
}

function ckHistoryRow(rec) {
  const li = cel("li");
  li.style.flexWrap = "wrap";
  const left = cel("div");
  left.style.flex = "1";
  const sev = String(rec.severity || "info").toLowerCase();
  left.append(cel("span", `ck-sev sev-${sev}`, String(rec.severity || "info").toUpperCase()), document.createTextNode(" "));
  left.append(cel("span", "ck-ftitle", rec.title || "Finding"));
  const meta = cel("div", "ck-cd-finding-meta");
  if (rec.class_id) meta.append(cel("span", null, rec.class_id));
  const rproof = ckEffectiveProof(rec, rec.proof_status);
  if (rproof) meta.append(ckProofBadge(rproof));
  meta.append(cel("span", "ck-tag", ckEffectiveStage(rec) || rec.stage || "discovered"));
  if (Number(rec.bounty)) meta.append(cel("span", null, `$${rec.bounty}`));
  if (rec.h1_state) meta.append(cel("span", "ck-tag", rec.h1_state));
  if (rec.source_url) meta.append(cel("span", "ck-cd-finding-target", ckShortTarget(rec.source_url)));
  left.append(meta);
  li.append(left);

  const acts = cel("div", "ck-actions"); acts.style.margin = "0";
  const viewBtn = cel("button", "ck-btn", "View full report");
  viewBtn.type = "button";
  viewBtn.title = "Open the full report for this finding at the top of this page";
  viewBtn.addEventListener("click", () => ckViewFullReport(rec));
  acts.append(viewBtn);
  const copyBtn = cel("button", "ck-btn", "Copy report");
  copyBtn.type = "button";
  copyBtn.addEventListener("click", async () => {
    copyBtn.disabled = true; copyBtn.textContent = "Preparing…";
    try { const md = await ckReportFromLedger(rec); const ok = await ckCopy(md); copyBtn.textContent = ok ? "Copied ✓" : "Failed"; }
    finally { copyBtn.disabled = false; setTimeout(() => { copyBtn.textContent = "Copy report"; }, 1600); }
  });
  const dlBtn = cel("button", "ck-btn", "Download .md");
  dlBtn.type = "button";
  dlBtn.addEventListener("click", async () => {
    dlBtn.disabled = true; dlBtn.textContent = "Preparing…";
    try { const md = await ckReportFromLedger(rec); ckDownloadText(`${ckSlug(rec.title || "finding")}.md`, md); }
    finally { dlBtn.disabled = false; dlBtn.textContent = "Download .md"; }
  });
  // Delete from history — permanently suppress it (by its stored dedup key) so no future
  // hunt re-surfaces it and it drops out of the history + funnel + CSV export.
  const delBtn = cel("button", "ck-btn ck-btn-danger", "Delete");
  delBtn.type = "button";
  delBtn.title = "Remove this finding from history and never surface it again";
  delBtn.addEventListener("click", async () => {
    if (!window.confirm(`Delete "${rec.title || "this finding"}" from history?\n\nIt won't be surfaced again in future hunts or campaigns.`)) return;
    delBtn.disabled = true; delBtn.textContent = "Deleting…";
    let res;
    try {
      res = await apiFetch("/api/bounty/finding/dismiss", {
        method: "POST", timeoutMs: 15000,
        body: JSON.stringify({
          dedup_key: rec.dedup_key || "", class_id: rec.class_id || "",
          rule_id: rec.rule_id || "", location: rec.source_url || "", title: rec.title || "",
        }),
      });
    } catch (err) { delBtn.disabled = false; delBtn.textContent = "Delete"; window.alert(err.message || "Could not delete the finding."); return; }
    if (!res || res.ok === false) { delBtn.disabled = false; delBtn.textContent = "Delete"; window.alert((res && res.error) || "Could not delete the finding."); return; }
    // Drop it from the cached ledger too, or a search/filter re-render would resurrect the row.
    if (ckState._history && Array.isArray(ckState._history.findings)) {
      ckState._history.findings = ckState._history.findings.filter((x) => x !== rec);
    }
    li.remove();
  });
  acts.append(copyBtn, dlBtn, delBtn);
  li.append(acts);
  return li;
}

async function ckReportFromLedger(rec) {
  try {
    const res = await apiFetch("/api/bounty/finding/report", {
      method: "POST", timeoutMs: 30000,
      body: JSON.stringify({
        title: rec.title || "Security finding", severity: rec.severity || "info",
        class_name: rec.class_id || "", class_id: rec.class_id || "", location: rec.source_url || "",
        rule_id: rec.rule_id || "", target: rec.source_url || "", platform: ckState.platform || "hackerone",
      }),
    });
    if (res && res.ok && res.package) return res.package.vulnerability_information || "";
    return `# ${rec.title || "Finding"}\n\n_(Report could not be built: ${(res && res.error) || "unknown error"})_`;
  } catch (err) {
    return `# ${rec.title || "Finding"}\n\n_(Report could not be built: ${err.message || "engine unreachable"})_`;
  }
}

// Create proof of impact for a candidate (current-run queue): active re-probe + screenshot,
// scope-gated, in a separate track. Renders the fresh proof + screenshot inline.
async function ckCreateProofOfImpact(f, btn, statusEl, resultEl) {
  f._prepMsg = "";  // a manual prove invalidates the last "Prepare full report" caption
  const url = String(f.location || f.sourceUrl || "").trim();
  if (!url) { statusEl.textContent = "This finding has no URL to probe."; statusEl.className = "ck-status is-error"; return; }
  // Union THIS finding's own host into the scope so proving works even for a finding opened from
  // history (where the cockpit Scope box may be empty) — the host was already authorized when the
  // hunt that produced the finding ran. The server still SSRF-guards and rate-limits the probe.
  let scope = state.ckScope || "";
  try { const h = new URL(url).hostname; if (h && !scope.split(/\s+/).includes(h)) scope = `${scope} ${h}`.trim(); } catch (_) { /* non-URL location */ }
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = "Proving…";
  statusEl.className = "ck-status"; statusEl.textContent = `Actively probing ${url} in scope… (the campaign, if any, keeps running)`;
  let res;
  try {
    res = await apiFetch("/api/bounty/finding/prove", {
      method: "POST", timeoutMs: 120000,
      // run_id + ref let the engine persist the captured proof back onto THIS cached run
      // finding, so the rebuilt (canonical) report renders it confirmed — not just the badge.
      body: JSON.stringify({ url, scope, program_id: state.ckActiveProgramId || null,
        run_id: f.runId || "", ref: f.ref || "", authorized: true, screenshot: true }),
    });
  } catch (err) {
    statusEl.className = "ck-status is-error"; statusEl.textContent = err.message || "Could not reach the engine.";
    btn.disabled = false; btn.textContent = old; return;
  }
  btn.disabled = false; btn.textContent = old;
  if (!res || res.ok === false) {
    statusEl.className = "ck-status is-error"; statusEl.textContent = (res && res.error) || "Proof could not be gathered.";
    return;
  }
  const conf = res.confirmed || 0;
  statusEl.className = "ck-status";
  statusEl.textContent = conf
    ? `Confirmed ${conf} — proof of impact captured (${res.requests_used} request(s) to ${res.host}).`
    : `Nothing confirmable at ${res.host} right now (${res.requests_used} request(s)).`;
  resultEl.hidden = false;
  ckRenderProofResult(resultEl, res);
  // If the active pass confirmed THIS finding's class, promote it to confirmed everywhere
  // (dashboard, board, history) and persist. Only on a class match — never on an unrelated
  // confirmation at the same URL.
  if (conf && ckProofMatchesFinding(res.findings, f)) {
    // Fold the captured differential onto the finding so the rebuilt report shows it (the
    // /finding/report fallback reads f.proofObj), and drop the cached markdown so the preview
    // refetches the now-confirmed report instead of the stale "candidate" one. The engine has
    // also persisted this proof onto the cached run, so the canonical package agrees.
    const best = (res.findings || []).find((x) => x.status === "confirmed");
    if (best) {
      f.proofObj = { status: "confirmed", method: best.method || "", observed_result: best.observed || "",
                     control_result: best.control || "", evidence: best.evidence || "", affected_asset: best.affected_asset || "" };
    }
    f._md = null;
    ckMarkStatus(f, { proof: "confirmed" });
  }
}

// Shared renderer for a prove/re-probe result: summary + optional screenshot + per-check proof.
function ckRenderProofResult(box, res) {
  box.replaceChildren();
  const findings = res.findings || [];
  const summary = findings.length
    ? `${res.confirmed} confirmed · ${findings.length - res.confirmed} candidate — ${res.requests_used} request(s) to ${res.host}`
    : `Nothing confirmable at ${res.host} right now (${res.requests_used} request(s)).`;
  box.append(cel("p", "ck-cd-rv-summary" + (res.confirmed ? " is-hot" : ""), summary));
  if (res.rate_limited) box.append(cel("p", "ck-hint", "Host rate limit reached — some checks were skipped."));
  const shot = res.screenshot;
  if (shot && shot.ok && shot.data_url) {
    ckAppendScreenshot(box, shot.data_url, res.host || "finding");
    if (shot.warning) box.append(cel("p", "ck-hint", shot.warning));
  } else if (shot && !shot.ok && shot.error) {
    box.append(cel("p", "ck-hint", "Screenshot: " + shot.error));
  }
  for (const r of findings) {
    const card = cel("div", `ck-cd-rv-card is-${r.status || ""}`);
    const h = cel("div", "ck-cd-rv-card-head");
    h.append(cel("span", `ck-sev sev-${r.severity || "info"}`, String(r.severity || "info").toUpperCase()));
    h.append(cel("strong", null, r.title || r.class_hint || "Active check"));
    if (r.status) h.append(cel("span", `ck-cd-proof is-${r.status}`, r.status));
    card.append(h);
    const g = cel("dl", "ck-meta-grid");
    const add = (k, v) => { if (v) { g.append(cel("dt", null, k)); g.append(cel("dd", null, String(v))); } };
    add("Observed", r.observed); add("Control", r.control); add("Evidence", r.evidence);
    if (g.childNodes.length) card.append(g);
    box.append(card);
  }
}

// HackerOne credentials bar — shows configured state and a token-first save form. The
// credential is a password field, never read back from the server (only has_token +
// api_username are returned). HackerOne's Hacker API uses HTTP Basic auth with the API
// identifier as username and the token as password, so the single field accepts either
// "identifier:token" (what HackerOne shows together at Generate API token) or a bare
// token; the server splits it. A "Test" button probes a real authenticated endpoint so
// the operator gets a server-authoritative answer instead of guessing the username.
function ckCredsBar() {
  const wrap = cel("div", "ck-creds");
  const h1 = ckState.h1;
  const head = cel("div", "ck-creds-head");
  head.append(cel("strong", null, "HackerOne API"));
  const state = cel("span", "ck-tag", h1 && h1.has_token && h1.team_handle ? `connected · ${h1.team_handle}` : "not configured");
  head.append(state);
  wrap.append(head);

  const form = cel("form", "ck-learn-form");
  const handle = ckField("Team handle", "text", (h1 && h1.team_handle) || "");
  const cred = ckField("API credential", "password", "");
  cred.input.placeholder = h1 && h1.has_token ? "•••••• (saved — leave blank to keep)" : "paste identifier:token (or just the token)";
  const help = cel("p", "ck-hint", "Paste your HackerOne API token. HackerOne's API needs an identifier too — if it 401s below, paste them together as identifier:token (both are shown when you click “Generate API token”).");
  help.style.flexBasis = "100%";
  form.append(handle.wrap, cred.wrap, help);
  if (h1 && h1.api_username) {
    const who = cel("p", "ck-hint", `Saved identifier (username): ${h1.api_username}`);
    who.style.flexBasis = "100%";
    form.append(who);
  }
  const save = cel("button", "ck-btn primary", "Save");
  save.type = "submit";
  const test = cel("button", "ck-btn", "Test connection");
  test.type = "button";
  form.append(save, test);
  const note = cel("p", "ck-status");
  note.style.flexBasis = "100%";
  form.append(note);

  const doSave = async () => {
    const res = await apiFetch("/api/bounty/hackerone/creds", {
      method: "POST",
      body: JSON.stringify({ team_handle: handle.input.value.trim(), api_credential: cred.input.value })
    });
    ckState.h1 = res && res.ok ? res : ckState.h1;
    return res;
  };
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await doSave();
      note.classList.remove("is-error");
      note.textContent = "Saved.";
      ckRenderSubmissions();
    } catch (err) { note.textContent = err.message || "Could not save."; note.classList.add("is-error"); }
  });
  test.addEventListener("click", async () => {
    note.classList.remove("is-error");
    note.textContent = "Testing…";
    try {
      // Save first (so we test exactly what's in the box), then probe HackerOne.
      if (cred.input.value.trim() || handle.input.value.trim()) await doSave();
      const res = await apiFetch("/api/bounty/hackerone/test", { method: "POST", timeoutMs: 20000 });
      if (res && res.ok) { note.classList.remove("is-error"); note.textContent = `✓ ${res.message || "HackerOne accepted these credentials."}`; }
      else { note.classList.add("is-error"); note.textContent = `✗ ${(res && res.error) || "HackerOne rejected these credentials."}`; }
    } catch (err) { note.classList.add("is-error"); note.textContent = err.message || "Could not reach HackerOne."; }
  });
  wrap.append(form);
  return wrap;
}

function ckHackeroneActivityPanel() {
  const wrap = cel("div", "ck-creds");
  const head = cel("div", "ck-creds-head");
  head.append(cel("strong", null, "My HackerOne activity"));
  wrap.append(head);
  wrap.append(cel("p", "ck-hint", "Your own report statuses and reward history, straight from the HackerOne API — refreshed on demand, never automatically."));

  const connected = ckState.h1 && ckState.h1.has_token && ckState.h1.team_handle;
  if (!connected) {
    wrap.append(cel("p", "ck-status", "Save your HackerOne API credentials above to use this."));
    return wrap;
  }

  const row = cel("div", "ck-import-row");
  const reportsBtn = cel("button", "ck-btn", "Refresh my reports"); reportsBtn.type = "button";
  const earningsBtn = cel("button", "ck-btn", "Refresh earnings"); earningsBtn.type = "button";
  row.append(reportsBtn, earningsBtn);
  wrap.append(row);

  const reportsOut = cel("div", "ck-hacktivity-panel");
  const earningsOut = cel("div", "ck-hacktivity-panel");
  wrap.append(reportsOut, earningsOut);

  reportsBtn.addEventListener("click", async () => {
    const label = reportsBtn.textContent; reportsBtn.disabled = true; reportsBtn.textContent = "Loading…";
    reportsOut.replaceChildren(cel("p", "ck-status", "Loading your reports…"));
    try {
      const res = await apiFetch("/api/hackerone/my-reports", { method: "POST", timeoutMs: 30000, body: JSON.stringify({ page: 1 }) });
      reportsOut.replaceChildren();
      if (!res || res.ok === false) { reportsOut.append(cel("p", "ck-status is-error", (res && res.error) || "Could not fetch reports.")); return; }
      const items = res.items || [];
      if (!items.length) { reportsOut.append(cel("p", "ck-status", "No reports found on your HackerOne account.")); return; }
      for (const item of items) {
        reportsOut.append(cel("p", "ck-floc", `${item.title || "(untitled)"} — ${item.state || "?"}${item.bounty_awarded_at ? " · rewarded" : ""}`));
      }
    } catch (err) {
      reportsOut.replaceChildren(cel("p", "ck-status is-error", err.message || "Fetch failed."));
    } finally {
      reportsBtn.disabled = false; reportsBtn.textContent = label;
    }
  });

  earningsBtn.addEventListener("click", async () => {
    const label = earningsBtn.textContent; earningsBtn.disabled = true; earningsBtn.textContent = "Loading…";
    earningsOut.replaceChildren(cel("p", "ck-status", "Loading your earnings…"));
    try {
      const res = await apiFetch("/api/hackerone/earnings", { method: "POST", timeoutMs: 30000, body: JSON.stringify({ page: 1 }) });
      earningsOut.replaceChildren();
      if (!res || res.ok === false) { earningsOut.append(cel("p", "ck-status is-error", (res && res.error) || "Could not fetch earnings.")); return; }
      const items = res.items || [];
      if (res.balance != null) earningsOut.append(cel("p", "ck-ftitle", `Balance: $${res.balance}`));
      if (!items.length) { earningsOut.append(cel("p", "ck-status", "No earnings recorded on your HackerOne account.")); return; }
      for (const item of items) {
        earningsOut.append(cel("p", "ck-floc", `${item.type || "earning"} — ${item.amount != null ? `$${item.amount}` : "?"} · ${(item.created_at || "").slice(0, 10)}`));
      }
    } catch (err) {
      earningsOut.replaceChildren(cel("p", "ck-status is-error", err.message || "Fetch failed."));
    } finally {
      earningsBtn.disabled = false; earningsBtn.textContent = label;
    }
  });

  return wrap;
}

function ckField(label, type, value) {
  const w = cel("label");
  w.append(cel("span", null, label));
  const input = cel("input");
  input.type = type; input.value = value || ""; input.autocomplete = "off";
  w.append(input);
  return { wrap: w, input };
}

async function ckRenderLearn() {
  const host = ck.views.learn;
  host.replaceChildren();
  const titleRow = cel("div", "ck-row-between");
  titleRow.append(cel("h2", "ck-section-title", "What the engine has learned"));
  const program = (ck.program?.value || "").trim();
  const statsQs = program ? `?program=${encodeURIComponent(program)}` : (ck.target?.value ? `?target=${encodeURIComponent(ck.target.value.trim())}` : "");
  const exportBtn = cel("button", "ck-btn", "Export ledger (CSV)"); exportBtn.type = "button";
  exportBtn.title = program || ck.target?.value ? "Export this program/target's finding ledger" : "Export the whole portfolio's finding ledger";
  exportBtn.addEventListener("click", async () => {
    const label = exportBtn.textContent; exportBtn.disabled = true; exportBtn.textContent = "Exporting…";
    try {
      const res = await apiFetch(`/api/bounty/ledger-csv${statsQs}`, { timeoutMs: 15000 });
      if (res.ok === false || !res.csv) { window.alert(res.error || "No ledger data to export yet."); return; }
      ckDownloadText(`greyiq-ledger-${new Date().toISOString().slice(0, 10)}.csv`, res.csv, "text/csv");
    } catch (err) {
      window.alert(err.message || "Export failed.");
    } finally {
      exportBtn.disabled = false; exportBtn.textContent = label;
    }
  });
  titleRow.append(exportBtn);
  host.append(titleRow);
  let data = null;
  if (service.available || (await refreshServiceStatus({ silent: true }))) {
    try { data = await apiFetch(`/api/bounty/stats${statsQs}`, { timeoutMs: 8000 }); } catch (_) { data = null; }
  }
  const summary = data && data.summary ? data.summary : null;
  if (summary && summary.programs) {
    const progs = summary.programs;
    const keys = Object.keys(progs);
    if (!keys.length) host.append(cel("p", "ck-hint", "No bounty outcomes recorded yet. After you submit, record the outcome below to teach the engine."));
    else {
      const grid = cel("div", "ck-stats-grid");
      for (const k of keys.sort((a, b) => (progs[b].bounty_total || 0) - (progs[a].bounty_total || 0))) {
        const card = cel("div", "ck-stat");
        card.append(cel("div", "n", `$${progs[k].bounty_total || 0}`));
        card.append(cel("div", "l", `${k} · ${progs[k].rewarded || 0}/${progs[k].submitted || 0} rewarded`));
        grid.append(card);
      }
      host.append(grid);
    }
  } else if (summary) {
    const grid = cel("div", "ck-stats-grid");
    grid.append(statCard(summary.submitted || 0, "Submitted"));
    grid.append(statCard(summary.rewarded || 0, "Rewarded"));
    grid.append(statCard(`$${summary.bounty_total || 0}`, "Bounty"));
    host.append(grid);
    const intel = (data && Array.isArray(data.intelligence)) ? data.intelligence : [];
    if (intel.length) {
      host.append(cel("h3", "ck-section-title", "What pays here"));
      const ul = cel("ul", "ck-intel");
      for (const note of intel) ul.append(cel("li", null, note.replace(/`/g, "")));
      host.append(ul);
    }
  }

  // Pipeline funnel: already computed for the Operator tab -- surfaced here too so
  // "what the engine has learned" shows where findings actually get stuck (e.g. a
  // pile of confirmed findings never making it to reported/submitted), not just the
  // flat submitted/rewarded/$ aggregate above.
  const funnel = data && data.funnel ? data.funnel : null;
  const funnelStages = funnel ? (funnel.programs ? funnel.portfolio.stages : funnel.stages) : null;
  if (funnelStages) {
    const stageLabels = [["discovered", "Discovered"], ["confirmed", "Confirmed"], ["reported", "Reported"], ["submitted", "Submitted"], ["paid", "Paid"]];
    const counts = stageLabels.map(([k]) => Number(funnelStages[k]) || 0);
    if (counts.some((n) => n > 0)) {
      host.append(cel("h3", "ck-section-title", "Pipeline"));
      const maxCount = Math.max(1, ...counts);
      const box = cel("div", "ck-funnel");
      stageLabels.forEach(([key, label], i) => {
        const count = counts[i];
        const row = cel("div", "ck-funnel-row");
        row.append(cel("span", "ck-funnel-label", label));
        const track = cel("div", "ck-funnel-track");
        const fill = cel("div", "ck-funnel-fill");
        fill.style.width = `${Math.max(count > 0 ? 3 : 0, Math.round((count / maxCount) * 100))}%`;
        track.append(fill);
        row.append(track, cel("span", "ck-funnel-count", String(count)));
        box.append(row);
      });
      host.append(box);
      host.append(cel("p", "ck-hint", "Current stage counts per finding, not a strict conversion funnel — a finding can be recorded directly at any stage."));
    }
  }

  // Record-outcome form.
  host.append(cel("h3", "ck-section-title", "Record a finding outcome"));
  const form = cel("form", "ck-learn-form");
  const classField = labeledSelect("Class", "ckLearnClass", [...ck.klass?.options || []].filter((o) => o.value).map((o) => [o.value, o.textContent]));
  const statusField = labeledSelect("Status", "ckLearnStatus", [["accepted", "accepted"], ["resolved", "resolved"], ["triaged", "triaged"], ["duplicate", "duplicate"], ["informative", "informative"], ["not-applicable", "not-applicable"], ["submitted", "submitted"], ["spam", "spam"]]);
  const bountyField = labeledInput("Bounty $", "ckLearnBounty", "number");
  const sevField = labeledInput("Severity", "ckLearnSev", "text");
  form.append(classField.wrap, statusField.wrap, bountyField.wrap, sevField.wrap);
  const submit = cel("button", "ck-btn primary", "Record");
  submit.type = "submit";
  form.append(submit);
  const note = cel("p", "ck-status");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const program = (ck.program?.value || "").trim();
    const target = (ck.target?.value || "").trim();
    if (!program && !target) { note.textContent = "Set a target or program handle first."; note.classList.add("is-error"); return; }
    try {
      const res = await apiFetch("/api/bounty/learn", {
        method: "POST",
        body: JSON.stringify({
          class_id: classField.input.value, status: statusField.input.value,
          program: program || null, target, bounty: Number(bountyField.input.value) || 0, severity: sevField.input.value
        })
      });
      if (res.ok === false) { note.textContent = res.error || "Could not record."; note.classList.add("is-error"); }
      else { note.classList.remove("is-error"); note.textContent = `Recorded ${classField.input.value} → ${statusField.input.value}.`; void ckRenderLearn(); }
    } catch (err) { note.textContent = err.message || "Could not record."; note.classList.add("is-error"); }
  });
  host.append(form, note);

  function statCard(n, l) { const c = cel("div", "ck-stat"); c.append(cel("div", "n", n), cel("div", "l", l)); return c; }
  function labeledSelect(label, id, opts) {
    const wrap = cel("label", null); wrap.append(cel("span", null, label));
    const sel = cel("select"); sel.id = id;
    for (const [v, t] of opts) { const o = cel("option", null, t); o.value = v; sel.append(o); }
    wrap.append(sel); return { wrap, input: sel };
  }
  function labeledInput(label, id, type) {
    const wrap = cel("label", null); wrap.append(cel("span", null, label));
    const inp = cel("input"); inp.id = id; inp.type = type; if (type === "number") inp.min = "0";
    wrap.append(inp); return { wrap, input: inp };
  }
}

// ---- Operator: the autonomous portfolio control panel + money pipeline ----
async function ckRenderOperator() {
  const host = ck.views.operator;
  host.replaceChildren();
  host.append(cel("h2", "ck-section-title", "Autonomous operator"));
  host.append(cel("p", "ck-hint", "Add the programs you're authorized to hunt, then arm the operator. It runs each program on its schedule — recon, hunt, prove, dedup, report — and (only when you explicitly arm auto-submit per program) files confirmed, non-duplicate findings within a daily cap. The kill switch stops it immediately."));
  host.append(ckWalkthrough("operator"));

  let data = null;
  if (service.available || (await refreshServiceStatus({ silent: true }))) {
    try { data = await apiFetch("/api/operator/pipeline", { timeoutMs: 8000 }); } catch (_) { data = null; }
  }
  if (!data || data.ok === false) { host.append(cel("p", "ck-status is-error", "Local engine not running.")); return; }

  // --- Control bar: start / stop / arm auto-submit ---
  const ctl = cel("div", "ck-op-ctl");
  const running = Boolean(data.running);
  const statusPill = cel("span", `ck-pill ${running ? "is-armed" : ""}`);
  statusPill.append(cel("span", null, "Operator: "), cel("strong", null, running ? "running" : "stopped"));
  ctl.append(statusPill);

  const armWrap = cel("label", "ck-switch ck-auth");
  const arm = cel("input"); arm.type = "checkbox"; arm.id = "ckOpArm";
  armWrap.append(arm, ckArmLabel());
  ctl.append(armWrap);

  if (!running) {
    const startBtn = cel("button", "ck-btn primary", "Start operator");
    startBtn.type = "button";
    startBtn.addEventListener("click", () => ckOperatorStart(arm.checked));
    ctl.append(startBtn);
  } else {
    const stopBtn = cel("button", "ck-btn", "■ Kill switch — stop");
    stopBtn.type = "button";
    stopBtn.style.borderColor = "var(--danger)"; stopBtn.style.color = "var(--danger)";
    stopBtn.addEventListener("click", ckOperatorStop);
    ctl.append(stopBtn);
  }
  host.append(ctl);

  // --- Money pipeline funnel ---
  const pf = (data.funnel && data.funnel.portfolio) || { stages: {}, total: 0, bounty_total: 0 };
  host.append(cel("h3", "ck-section-title", "Money pipeline"));
  const funnel = cel("div", "ck-stats-grid");
  const stages = [["discovered", "Discovered"], ["confirmed", "Confirmed"], ["reported", "Reported"], ["submitted", "Submitted"], ["paid", "Paid"]];
  for (const [k, label] of stages) {
    const c = cel("div", "ck-stat");
    c.append(cel("div", "n", String((pf.stages || {})[k] || 0)), cel("div", "l", label));
    funnel.append(c);
  }
  const money = cel("div", "ck-stat");
  money.append(cel("div", "n", `$${pf.bounty_total || 0}`), cel("div", "l", "Bounty"));
  funnel.append(money);
  host.append(funnel);

  const syncBtn = cel("button", "ck-btn", "Sync submitted reports"); syncBtn.type = "button";
  syncBtn.title = "Poll HackerOne for the current status of every locally-submitted finding and reflect real outcomes (resolved/duplicate/etc.) back into this funnel.";
  const syncNote = cel("p", "ck-status");
  syncBtn.addEventListener("click", async () => {
    const label = syncBtn.textContent; syncBtn.disabled = true; syncBtn.textContent = "Syncing…";
    syncNote.classList.remove("is-error"); syncNote.textContent = "";
    try {
      const res = await apiFetch("/api/hackerone/sync-submitted", { method: "POST", timeoutMs: 60000, body: JSON.stringify({}) });
      if (!res || res.ok === false) {
        syncNote.classList.add("is-error"); syncNote.textContent = (res && res.error) || "Sync failed.";
      } else {
        syncNote.textContent = `Checked ${res.checked} report(s), ${res.updated} updated.` + (res.errors && res.errors.length ? ` ${res.errors.length} error(s).` : "");
        // Leave the summary on screen for a beat before the funnel re-render replaces
        // this whole view (a full ckRenderOperator() re-render happens immediately —
        // without the delay the toast would never actually be visible).
        setTimeout(() => { void ckRenderOperator(); }, 1500);
      }
    } catch (err) {
      syncNote.classList.add("is-error"); syncNote.textContent = err.message || "Sync failed.";
    } finally {
      syncBtn.disabled = false; syncBtn.textContent = label;
    }
  });
  host.append(syncBtn, syncNote);

  // --- Live event log ---
  host.append(cel("h3", "ck-section-title", "Activity"));
  const log = cel("div", "ck-op-log"); log.id = "ckOpLog";
  host.append(log);
  ckOpEventCount = 0;
  await ckOperatorPollEvents();
  if (ckOpPoll) clearInterval(ckOpPoll);
  ckOpPoll = setInterval(() => { void ckOperatorPollEvents(); }, 4000);

  // --- Programs ---
  host.append(cel("h3", "ck-section-title", `Programs (${(data.programs || []).length})`));
  const list = cel("ul", "ck-list");
  for (const prog of (data.programs || [])) list.append(ckProgramRow(prog, data.funnel));
  if (!(data.programs || []).length) host.append(cel("p", "ck-hint", "No programs yet — add one below."));
  else host.append(list);

  // --- Add / edit program form ---
  host.append(cel("h3", "ck-section-title", ckOpEdit ? `Edit program — ${ckOpEdit.name || ckOpEdit.id}` : "Add / update a program"));
  host.append(ckProgramForm());
}

function ckArmLabel() {
  const span = cel("span");
  span.append(cel("strong", null, "Arm auto-submit"));
  span.append(document.createTextNode(" — file confirmed, non-duplicate findings to HackerOne automatically (per-program opt-in + daily cap still apply). Off = review-only."));
  return span;
}

// Guards against a double Start (two /operator/start calls) and a Start racing a Stop —
// important because the operator can auto-submit to live bounty programs.
let ckOperatorBusy = false;

async function ckOperatorStart(allowSubmit) {
  if (ckOperatorBusy) return;
  if (allowSubmit && !window.confirm("ARM AUTO-SUBMIT?\n\nThe operator will FILE confirmed findings to your HackerOne programs automatically (only programs you set auto-submit on, only confirmed + non-duplicate findings, within each program's daily cap). Only do this for authorized, in-scope programs.")) return;
  if (!window.confirm("Start the operator on your portfolio? You confirm you are AUTHORIZED to test every enabled program's scope.")) return;
  ckOperatorBusy = true;
  try {
    await apiFetch("/api/operator/start", { method: "POST", body: JSON.stringify({ authorized: true, allow_submit: Boolean(allowSubmit) }) });
    void ckRenderOperator();
  } catch (err) { window.alert(err.message || "Could not start."); }
  finally { ckOperatorBusy = false; }
}

async function ckOperatorStop() {
  if (ckOperatorBusy) return;
  ckOperatorBusy = true;
  // A failed Stop must NOT be silent — an operator that thinks it stopped (but is still
  // auto-submitting) is the worst outcome here.
  try { await apiFetch("/api/operator/stop", { method: "POST", body: JSON.stringify({}) }); }
  catch (err) { window.alert((err.message || "Could not reach the engine") + "\n\nThe operator may still be running — reopen the Operator tab to check its status."); }
  finally { ckOperatorBusy = false; setTimeout(() => void ckRenderOperator(), 400); }
}

async function ckOperatorPollEvents() {
  const log = document.querySelector("#ckOpLog");
  if (!log) return;
  let res = null;
  try { res = await apiFetch("/api/operator/events", { method: "POST", timeoutMs: 6000, body: JSON.stringify({ after: ckOpEventCount }) }); } catch (_) { return; }
  for (const ev of (res.events || [])) {
    const row = cel("div", "ck-op-event");
    row.append(cel("span", "ck-op-time", (ev.at || "").slice(11, 19)), cel("span", null, ev.message || ""));
    log.append(row);
    // "submitted <pid>: <title> -> <url>" (operator.py's own _emit prefix) is the
    // single most important background event in the app -- a confirmed finding was
    // just auto-filed to a live bounty program while nobody was necessarily watching.
    if (String(ev.message || "").startsWith("submitted ") && document.hidden) {
      ckBumpTitleBadge(1);
      void ckNotify("GreyIQ — finding submitted", ev.message);
    }
  }
  if (res.events && res.events.length) { ckOpEventCount = res.count || (ckOpEventCount + res.events.length); log.scrollTop = log.scrollHeight; }
  if (!log.childNodes.length) log.append(cel("p", "ck-hint", "No activity yet. Start the operator to see live progress."));
}

function ckProgramRow(prog, funnel) {
  const li = cel("li"); li.style.flexWrap = "wrap";
  const left = cel("div"); left.style.flex = "1";
  left.append(cel("span", "ck-ftitle", prog.name || prog.id));
  if (prog.auto_submit) left.append(document.createTextNode(" "), cel("span", "ck-tag", "auto-submit"));
  if (!prog.enabled) left.append(document.createTextNode(" "), cel("span", "ck-tag", "disabled"));
  const fp = (funnel && funnel.programs && funnel.programs[prog.id]) || null;
  const meta = `${prog.scope_text || "(no scope)"} · ${(prog.seed_targets || []).length} target(s)` + (fp ? ` · ${fp.stages.submitted || 0} submitted · $${fp.bounty_total || 0}` : "");
  left.append(cel("div", "ck-floc", meta));
  li.append(left);

  const acts = cel("div", "ck-actions"); acts.style.margin = "0";
  const edit = cel("button", "ck-btn", "Edit");
  edit.type = "button";
  edit.addEventListener("click", () => {
    ckOpEdit = prog;
    void ckRenderOperator();
    setTimeout(() => {
      const f = document.querySelector(".ck-prog-form");
      if (f) { f.scrollIntoView({ behavior: "smooth", block: "center" }); const n = f.querySelector("input"); if (n) n.focus(); }
    }, 60);
  });
  acts.append(edit);
  const toggle = cel("button", "ck-btn", prog.enabled ? "Disable" : "Enable");
  toggle.type = "button";
  toggle.addEventListener("click", async () => {
    try {
      await apiFetch("/api/operator/programs", { method: "POST", body: JSON.stringify({ id: prog.id, name: prog.name, scope_text: prog.scope_text, seed_targets: prog.seed_targets, active: prog.active, live: prog.live, auto_submit: prog.auto_submit, platform: prog.platform, platform_handle: prog.platform_handle, interval_minutes: prog.interval_minutes, max_submits_per_day: prog.max_submits_per_day, max_pages: prog.max_pages, enabled: !prog.enabled }) });
      await ckRefreshProgramsEverywhere();
      void ckRenderOperator();
    } catch (err) { window.alert(err.message || "Could not update the program — the engine may be unreachable, so the change may not have applied."); }
  });
  acts.append(toggle);
  const del = cel("button", "ck-btn", "Delete");
  del.type = "button";
  del.addEventListener("click", async () => {
    if (await ckDeleteProgram(prog.id, prog.name)) void ckRenderOperator();
  });
  acts.append(del);
  li.append(acts);
  return li;
}

function ckProgramForm() {
  const editing = ckOpEdit;  // a program object when editing, else null (adding new)
  const form = cel("form", "ck-prog-form");
  const name = ckField("Program name", "text", editing ? (editing.name || "") : "");
  const scope = ckField("Scope (hosts/wildcards — the active gate)", "text", editing ? (editing.scope_text || "") : "");
  const targets = ckField("Seed targets (comma/space separated URLs)", "text", editing ? (editing.seed_targets || []).join(", ") : "");
  const handle = ckField("HackerOne team handle (for auto-submit)", "text", editing ? (editing.platform_handle || "") : "");
  const interval = ckField("Re-run every (minutes)", "number", editing ? String(editing.interval_minutes || 1440) : "1440");
  const cap = ckField("Max auto-submits / day", "number", editing ? String(editing.max_submits_per_day ?? 3) : "3");
  form.append(name.wrap, scope.wrap, targets.wrap, handle.wrap, interval.wrap, cap.wrap);
  form.append(ckTargetImport(targets, scope));

  const toggles = cel("div", "ck-toggles");
  const active = ckToggle("Capture proof of impact (active)", editing ? !!editing.active : true);
  const live = ckToggle("Dynamic Playwright pass", editing ? !!editing.live : false);
  const deep = ckToggle("Deep auto-work (time-based SQLi + screenshot + research per confirmed lead)", editing ? !!editing.deep : false);
  const auto = ckToggle("Auto-submit confirmed findings (per-program opt-in)", editing ? !!editing.auto_submit : false);
  toggles.append(active.wrap, live.wrap, deep.wrap, auto.wrap);
  form.append(toggles);

  const submit = cel("button", "ck-btn primary", editing ? "Update program" : "Save program");
  submit.type = "submit";
  form.append(submit);
  if (editing) {
    const cancel = cel("button", "ck-btn", "Cancel");
    cancel.type = "button";
    cancel.addEventListener("click", () => { ckOpEdit = null; void ckRenderOperator(); });
    form.append(cancel);
  }
  const note = cel("p", "ck-status");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!name.input.value.trim() || !scope.input.value.trim()) { note.textContent = "Name and scope are required."; note.classList.add("is-error"); return; }
    const seeds = targets.input.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    const payload = {
      name: name.input.value.trim(), scope_text: scope.input.value.trim(), seed_targets: seeds,
      platform: handle.input.value.trim() ? "hackerone" : "manual", platform_handle: handle.input.value.trim(),
      active: active.input.checked, live: live.input.checked, deep: deep.input.checked, auto_submit: auto.input.checked,
      interval_minutes: Number(interval.input.value) || 1440, max_submits_per_day: Number(cap.input.value) || 3
    };
    if (editing) {
      // Update the existing record: carry its id + the fields the form doesn't expose so
      // they're preserved (enabled state, recon depth) rather than reset to defaults.
      payload.id = editing.id;
      payload.enabled = editing.enabled;
      if (editing.max_pages != null) payload.max_pages = editing.max_pages;
    }
    const submitBtn = e.submitter;  // the Save button that fired this submit
    if (submitBtn) submitBtn.disabled = true;  // no double upsert on a slow save
    try {
      await apiFetch("/api/operator/programs", { method: "POST", body: JSON.stringify(payload) });
      ckOpEdit = null;
      note.classList.remove("is-error"); note.textContent = "Saved.";
      await ckRefreshProgramsEverywhere();
      void ckRenderOperator();
    } catch (err) { note.textContent = err.message || "Could not save."; note.classList.add("is-error"); }
    finally { if (submitBtn) submitBtn.disabled = false; }
  });
  form.append(note);
  return form;
}

function ckToggle(label, checked) {
  const wrap = cel("label", "ck-switch");
  const input = cel("input"); input.type = "checkbox"; input.checked = Boolean(checked);
  wrap.append(input, cel("span", null, label));
  return { wrap, input };
}

// Merge `additions` into a current "a, b c" free-text field value, de-duplicating
// case-sensitively and joining with `sep`. Used to fold imported targets/hosts into the
// seed-targets (comma) and scope (space) inputs without clobbering what's already typed.
function mergeList(current, additions, sep) {
  const out = (current || "").split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  const have = new Set(out);
  for (const a of (additions || [])) {
    const v = String(a || "").trim();
    if (v && !have.has(v)) { have.add(v); out.push(v); }
  }
  return out.join(sep);
}

// Import targets/scope from a CSV / Burp Suite XML / HAR export, or a HackerOne-style
// structured-scope CSV. Parsing is server-side and PURE (no network, never touches scope);
// the operator reviews the result and clicks to fold it in. Wired into the Operator program
// form (targetsField/scopeField) and the Program-setup form (onStructuredRows) — pass null
// for whichever pair isn't relevant at a given call site.
function ckTargetImport(targetsField, scopeField, onStructuredRows) {
  const box = cel("details", "ck-import");
  box.append(cel("summary", null, "Import targets — CSV / Burp XML / HAR / HackerOne scope"));
  box.append(cel("p", "ck-hint", "Paste, or load a file: a CSV of hosts/URLs (or a HackerOne scope export/paste — identifier, asset type, eligible for submission/bounty, instruction, max severity), a Burp Suite items/sitemap XML export, or a HAR capture. Parsing is local and never adds anything to scope by itself — review the result, then add it."));

  const row = cel("div", "ck-import-row");
  const kind = cel("select");
  const kindOptions = [["auto", "Auto-detect"], ["csv", "CSV"], ["burp", "Burp XML"], ["har", "HAR"]];
  if (onStructuredRows) kindOptions.splice(2, 0, ["hackerone_scope", "HackerOne scope CSV/paste"]);
  for (const [v, l] of kindOptions) {
    const o = cel("option", null, l); o.value = v; kind.append(o);
  }
  const file = cel("input"); file.type = "file"; file.accept = ".csv,.tsv,.xml,.har,.json,.txt";
  row.append(kind, file);
  box.append(row);

  const ta = cel("textarea", "ck-import-ta");
  ta.rows = 4; ta.spellcheck = false; ta.placeholder = "Paste CSV / Burp XML / HAR here, or choose a file above…";
  box.append(ta);

  const parse = cel("button", "ck-btn", "Parse"); parse.type = "button";
  const note = cel("p", "ck-status");
  const result = cel("div");
  box.append(parse, note, result);

  file.addEventListener("change", () => {
    const f = file.files && file.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => { ta.value = String(reader.result || ""); note.className = "ck-status"; note.textContent = `Loaded ${f.name} — click Parse.`; };
    reader.onerror = () => { note.className = "ck-status is-error"; note.textContent = "Could not read that file."; };
    reader.readAsText(f);
  });

  parse.addEventListener("click", async () => {
    const content = ta.value.trim();
    if (!content) { note.className = "ck-status is-error"; note.textContent = "Paste or load something first."; return; }
    const label = parse.textContent; parse.disabled = true; parse.textContent = "Parsing…";
    note.className = "ck-status"; note.textContent = ""; result.replaceChildren();
    try {
      const res = await apiFetch("/api/bounty/ingest-targets", {
        method: "POST", timeoutMs: 30000, body: JSON.stringify({ content, kind: kind.value })
      });
      if (!res || res.ok === false) {
        note.className = "ck-status is-error";
        note.textContent = ((res && res.error) || "Nothing parsed.") + (res && (res.notes || []).length ? " " + res.notes.join(" ") : "");
        return;
      }
      note.className = "ck-status";
      note.textContent = `Parsed ${res.count} target(s) · ${res.host_count} host(s)`
        + (res.param_names && res.param_names.length ? ` · ${res.param_names.length} param name(s)` : "")
        + (res.kind ? ` (${res.kind})` : "");
      const preview = cel("pre", "ck-import-preview");
      const previewLines = res.structured_scope && res.structured_scope.length
        ? res.structured_scope.map((e) => e.identifier)
        : (res.targets || []);
      const shown = previewLines.slice(0, 12);
      preview.textContent = shown.join("\n") + (previewLines.length > 12 ? `\n… +${previewLines.length - 12} more` : "");
      result.append(preview);
      const acts = cel("div", "ck-import-acts");
      if (targetsField) {
        const addTargets = cel("button", "ck-btn", `Add ${res.count} to seed targets`); addTargets.type = "button";
        addTargets.addEventListener("click", () => { targetsField.input.value = mergeList(targetsField.input.value, res.targets, ", "); note.className = "ck-status"; note.textContent = `Added ${res.count} target(s) to seed targets.`; });
        acts.append(addTargets);
      }
      if (scopeField) {
        const addScope = cel("button", "ck-btn", `Add ${res.host_count} host(s) to scope`); addScope.type = "button";
        addScope.addEventListener("click", () => { scopeField.input.value = mergeList(scopeField.input.value, res.hosts, " "); note.className = "ck-status"; note.textContent = `Added ${res.host_count} host(s) to scope.`; });
        acts.append(addScope);
      }
      if (onStructuredRows) {
        // A HackerOne-shaped parse already carries the full row; a plain CSV/Burp/HAR
        // success only has flat hosts — synthesize bare identifier rows from those so
        // this callback (and its button) is never a dead end just because the operator
        // picked (or auto-detect fell back to) a non-HackerOne kind.
        const rows = (res.structured_scope && res.structured_scope.length)
          ? res.structured_scope
          : (res.hosts || []).map((h) => ({
              identifier: h, asset_type: "", eligible_for_submission: true,
              eligible_for_bounty: false, instruction: "", max_severity: "",
            }));
        if (rows.length) {
          const addRows = cel("button", "ck-btn", `Add ${rows.length} scope entries`); addRows.type = "button";
          addRows.addEventListener("click", () => {
            onStructuredRows(rows);
            note.className = "ck-status"; note.textContent = `Added ${rows.length} scope entries.`;
          });
          acts.append(addRows);
        }
      }
      result.append(acts);
    } catch (err) {
      note.className = "ck-status is-error"; note.textContent = err.message || "Parse failed.";
    } finally {
      parse.disabled = false; parse.textContent = label;
    }
  });

  return box;
}

function ckBadgeCount(view, n) {
  const btn = ck.navButtons.find((b) => b.dataset.ckView === view);
  if (!btn) return;
  btn.replaceChildren(document.createTextNode(view[0].toUpperCase() + view.slice(1)));
  if (n) btn.append(cel("span", "ck-badge", String(n)));
}

// Portfolio Hunt: run campaigns across several selected programs at once. Reuses the live
// campaign dashboard (programs are its units) + the Findings board + Submissions hub.
async function ckRunPortfolio() {
  const ids = ck.portfolioList ? [...ck.portfolioList.querySelectorAll("input[type=checkbox]:checked")].map((c) => c.value) : [];
  if (!ids.length) { ckStatus("Pick at least one program to hunt.", true); return; }
  if (!ck.authorized?.checked) { ckStatus("Confirm you are authorized to test these programs' scopes (tick the box).", true); return; }
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) { ckStatus("Local GreyIQ engine is not running.", true); return; }
  state.ckActive = Boolean(ck.active?.checked);
  state.ckTimeBased = Boolean(ck.timeBased?.checked);
  state.ckDeep = Boolean(ck.deep?.checked);
  state.ckLive = Boolean(ck.live?.checked);
  state.ckAuthCookie = (ck.authCookie?.value || "").trim();
  state.ckAuthHeaders = (ck.authHeaders?.value || "");
  saveState();
  const authHeaderLines = state.ckAuthHeaders.split("\n").map((s) => s.trim()).filter(Boolean);
  ck.run.disabled = true;
  ckStatus(`Portfolio hunt running — campaigns across ${ids.length} program(s), several at once (this can take a while)…`);
  const progressRunId = crypto.randomUUID();
  // Union the selected programs' scopes so the dashboard's on-demand re-verify / proof-of-impact
  // can gate a finding's host correctly regardless of which program it came from.
  const unionScope = (ckProgramsCache || []).filter((p) => ids.includes(p.id))
    .map((p) => String(p.scope_text || "").trim()).filter(Boolean).join("\n");
  ckStartCampaignDashboard(progressRunId, `Portfolio · ${ids.length} program(s)`, { scope: unionScope, programId: null, authorized: true });
  try {
    const res = await apiFetch("/api/bounty/portfolio", {
      method: "POST", timeoutMs: 3600000,
      body: JSON.stringify({
        program_ids: ids, authorized: true, active: state.ckActive, time_based: state.ckTimeBased,
        deep: state.ckDeep, live: state.ckLive, max_pages: Number(ck.maxPages?.value) || 12,
        auth_cookie: state.ckAuthCookie, auth_headers: authHeaderLines, run_id: progressRunId,
      }),
    });
    if (res.ok === false) { ckStatus(res.error || "The portfolio hunt could not complete.", true); return; }
    ckState.result = res;
    ckState.runId = res.run_id || "";
    ckState.triage = {};
    ckState.findings = ckNormalizeFindings(res);
    ckState.surface = res.surface || null;
    ckState.selectedUid = "";
    ckCloseDetail();
    ckBadgeCount("findings", ckState.findings.length);
    ckBadgeCount("submissions", ckState.findings.filter((f) => f.proof === "confirmed" || f.proof === "candidate").length);
    const confirmed = ckState.findings.filter((f) => f.proof === "confirmed").length;
    const errNote = (res.errors || []).length ? ` (${res.errors.length} note(s) — see the report)` : "";
    const doneMsg = `Portfolio done — ${res.programs_hunted ?? "?"}/${res.programs_total ?? "?"} program(s), ${ckState.findings.length} finding(s), ${confirmed} confirmed${errNote}. Report: ${res.campaign_path || "the reports folder"}`;
    ckStatus(doneMsg);
    if (document.hidden) { ckBumpTitleBadge(confirmed || ckState.findings.length); void ckNotify("GreyIQ — portfolio hunt complete", doneMsg); }
    ckRenderFindings();
    if (ckState.view === "campaign") ckRenderCampaign();
  } catch (err) {
    ckStatus(err.message || "The portfolio hunt failed.", true);
  } finally {
    ck.run.disabled = false;
    void ckFinishCampaignDashboard();
  }
}

async function ckRun() {
  if (state.ckRunType === "portfolio") { await ckRunPortfolio(); return; }
  const isCampaign = state.ckRunType === "campaign";
  const spanning = isCampaign && Boolean(ck.spanScope?.checked) && !ck.spanScopeWrap?.hidden && Boolean(state.ckActiveProgramId);
  const target = (ck.target?.value || "").trim();
  if (!spanning && !target) { ckStatus("Enter a target URL or folder/repo path.", true); return; }
  if (!ck.authorized?.checked) { ckStatus("Confirm you are authorized to test " + (spanning ? "this program's scope" : "this target") + " (tick the box).", true); return; }
  if (!(service.available || (await refreshServiceStatus({ silent: true })))) { ckStatus("Local GreyIQ engine is not running.", true); return; }
  state.ckTarget = target;
  state.ckScope = (ck.scope?.value || "").trim();
  state.ckProgram = (ck.program?.value || "").trim();
  state.ckActive = Boolean(ck.active?.checked);
  state.ckTimeBased = Boolean(ck.timeBased?.checked);
  state.ckDeep = Boolean(ck.deep?.checked);
  state.ckLive = Boolean(ck.live?.checked);
  state.ckAuthCookie = (ck.authCookie?.value || "").trim();
  state.ckAuthHeaders = (ck.authHeaders?.value || "");
  state.bountyProfile = ck.profile?.value || state.bountyProfile;
  saveState();
  const authHeaderLines = state.ckAuthHeaders.split("\n").map((s) => s.trim()).filter(Boolean);
  ck.run.disabled = true;
  ckStatus(
    spanning ? "Campaign running — hunting every target in this program's scope (this can take a while for a large program)…"
      : isCampaign ? "Campaign running — mapping the surface, hunting each URL (this can take a few minutes)…"
      : "Hunting — running scanners and proving findings…"
  );
  const progressRunId = crypto.randomUUID();
  if (isCampaign) {
    // A campaign opens its live dashboard (per-target status + streamed findings);
    // a single hunt keeps the compact launch-rail activity log.
    const dashLabel = spanning
      ? ((ck.activeProgram?.selectedOptions?.[0]?.textContent || state.ckProgram || "Program").trim() + " — span scope")
      : `Campaign · ${target}`;
    // Capture the scope + program + authorization so the dashboard's on-demand re-verify
    // can re-probe a finding within the SAME authorized scope this campaign ran under.
    ckStartCampaignDashboard(progressRunId, dashLabel, {
      scope: state.ckScope, programId: spanning ? state.ckActiveProgramId : null, authorized: true,
    });
  } else {
    ckStartLiveLog(progressRunId);
  }
  try {
    let res;
    if (isCampaign) {
      res = await apiFetch("/api/bounty/campaign", {
        method: "POST", timeoutMs: 1800000,
        body: JSON.stringify({
          target, scope: state.ckScope, authorized: true, program: state.ckProgram || null,
          program_id: spanning ? state.ckActiveProgramId : null,
          active: state.ckActive, time_based: state.ckTimeBased, live: state.ckLive, deep: state.ckDeep,
          max_pages: Number(ck.maxPages?.value) || 12,
          auth_cookie: state.ckAuthCookie, auth_headers: authHeaderLines, run_id: progressRunId
        })
      });
    } else {
      res = await apiFetch("/api/bounty/scan", {
        method: "POST", timeoutMs: 600000,
        body: JSON.stringify({
          target, profile: state.bountyProfile, vuln_class: (ck.klass?.value || null) || null,
          scope: state.ckScope, authorized: true, active: state.ckActive, time_based: state.ckTimeBased, run_live: state.ckLive,
          auth_cookie: state.ckAuthCookie, auth_headers: authHeaderLines, run_id: progressRunId
        })
      });
    }
    if (res.ok === false) { ckStatus(res.error || "The run could not complete.", true); return; }
    ckState.result = res;
    ckState.runId = res.run_id || "";
    ckState.triage = {};
    ckState.findings = ckNormalizeFindings(res);
    ckState.surface = res.surface || (res.urls ? { urls: res.urls, sources: res.recon_sources, notes: res.recon_notes } : null);
    ckState.selectedUid = "";
    ckCloseDetail();
    ckBadgeCount("findings", ckState.findings.length);
    ckBadgeCount("submissions", ckState.findings.filter((f) => f.proof === "confirmed" || f.proof === "candidate").length);
    const confirmed = ckState.findings.filter((f) => f.proof === "confirmed").length;
    const where = res.report_path || res.campaign_path || "the reports folder";
    const scopeNote = spanning ? `${res.targets_hunted ?? "?"}/${res.targets_total ?? "?"} in-scope target(s), `
      : isCampaign ? `${res.urls_scanned ?? "?"}/${res.urls_discovered ?? "?"} target(s), ` : "";
    const errNote = spanning && (res.errors || []).length ? ` (${res.errors.length} note(s) — see the report)` : "";
    const doneMsg = `Done — ${scopeNote}${ckState.findings.length} finding(s), ${confirmed} confirmed${errNote}. Report: ${where}`;
    ckStatus(doneMsg);
    if (document.hidden) {
      ckBumpTitleBadge(confirmed || ckState.findings.length);
      void ckNotify("GreyIQ — hunt complete", doneMsg);
    }
    ckRenderFindings();
    // A campaign stays on its live dashboard (which shows the final summary); a single
    // hunt jumps to the Findings board as before.
    if (!isCampaign) ckSetView("findings");
    else if (ckState.view === "campaign") ckRenderCampaign();
  } catch (err) {
    ckStatus(err.message || "The run failed.", true);
  } finally {
    ck.run.disabled = false;
    if (isCampaign) {
      void ckFinishCampaignDashboard();  // stop polling, mark done, final render
    } else {
      ckStopLiveLog();
      void ckPollLiveLog(progressRunId); // catch any trailing line(s) emitted right before the response returned
    }
  }
}

function ckStartLiveLog(runId) {
  const log = document.querySelector("#ckLiveLog");
  if (!log) return;
  ckStopLiveLog();
  ckLiveEventCount = 0;
  log.hidden = false;
  log.replaceChildren(cel("p", "ck-hint", "Starting…"));
  ckLivePoll = setInterval(() => { void ckPollLiveLog(runId); }, 1200);
}

function ckStopLiveLog() {
  if (ckLivePoll) { clearInterval(ckLivePoll); ckLivePoll = null; }
}

async function ckPollLiveLog(runId) {
  const log = document.querySelector("#ckLiveLog");
  if (!log) return;
  let res = null;
  try { res = await apiFetch("/api/bounty/progress", { method: "POST", timeoutMs: 6000, body: JSON.stringify({ run_id: runId, after: ckLiveEventCount }) }); } catch (_) { return; }
  if (!res || res.ok === false) return;
  if (!(res.events || []).length) return;
  if (log.firstElementChild && log.firstElementChild.textContent === "Starting…") log.replaceChildren();
  for (const ev of res.events) {
    const row = cel("div", "ck-op-event");
    row.append(cel("span", "ck-op-time", (ev.at || "").slice(11, 19)), cel("span", null, ev.message || ""));
    log.append(row);
  }
  ckLiveEventCount = res.count || (ckLiveEventCount + res.events.length);
  log.scrollTop = log.scrollHeight;
}

function ckStatus(text, isError) {
  if (!ck.status) return;
  ck.status.textContent = text;
  ck.status.classList.toggle("is-error", Boolean(isError));
}

// --- Campaign dashboard: a live, easy-to-scan view of a running campaign. Polls the
// structured snapshot from /api/bounty/progress and renders overall progress, stat tiles,
// per-target status, and findings as they stream in — updating automatically. ---
// `scope`/`programId`/`authorized` are captured at launch so the dashboard's on-demand
// re-verify can re-probe a finding within the same authorized scope. `sortBy`/`filterSev`
// drive the findings controls; `selectedKey` is the finding open in the investigate drawer;
// `reverify` holds each finding's re-probe state (survives polls so the drawer can re-render
// without losing an in-flight/finished result); `dom` caches the built scaffold so polls
// UPDATE it in place instead of rebuilding (which was resetting the findings scroll to top).
const ckCampaign = {
  runId: "", poll: null, snapshot: null, events: [], eventCount: 0, done: false,
  stopRequested: false, label: "", startedAt: 0,
  scope: "", programId: null, authorized: false,
  sortBy: "severity", filterSev: "all", selectedKey: "", reverify: {}, report: {}, reverifyVersion: 0,
  dom: null,
};

function ckStartCampaignDashboard(runId, label, opts = {}) {
  if (ckCampaign.poll) { clearInterval(ckCampaign.poll); ckCampaign.poll = null; }
  Object.assign(ckCampaign, {
    runId, label: label || "Campaign", snapshot: null, events: [], eventCount: 0, done: false,
    stopRequested: false, startedAt: Date.now(),
    scope: opts.scope || "", programId: opts.programId || null, authorized: Boolean(opts.authorized),
    selectedKey: "", reverify: {}, report: {}, reverifyVersion: 0, dom: null,
  });
  ckSetView("campaign");
  void ckPollCampaign();
  ckCampaign.poll = setInterval(() => { void ckPollCampaign(); }, 1200);
}

// Ask the backend to cancel the running campaign. It winds down cooperatively (finishing
// the URL in flight) and the main /api/bounty/campaign request returns partial results,
// which ckFinishCampaignDashboard then renders as the final state.
async function ckStopCampaign() {
  if (!ckCampaign.runId || ckCampaign.done || ckCampaign.stopRequested) return;
  ckCampaign.stopRequested = true;
  if (ckState.view === "campaign") ckRenderCampaign();  // flip to "Stopping…" immediately
  try { await apiFetch("/api/bounty/campaign/stop", { method: "POST", timeoutMs: 6000, body: JSON.stringify({ run_id: ckCampaign.runId }) }); }
  catch (err) { window.alert((err.message || "Could not reach the engine") + "\n\nThe campaign may keep running — watch the dashboard."); }
}

async function ckPollCampaign() {
  if (!ckCampaign.runId) return;
  let res = null;
  try { res = await apiFetch("/api/bounty/progress", { method: "POST", timeoutMs: 6000, body: JSON.stringify({ run_id: ckCampaign.runId, after: ckCampaign.eventCount }) }); } catch (_) { return; }
  if (!res || res.ok === false) return;
  if ((res.events || []).length) {
    ckCampaign.events.push(...res.events);
    if (ckCampaign.events.length > 400) ckCampaign.events = ckCampaign.events.slice(-400);
    ckCampaign.eventCount = res.count || (ckCampaign.eventCount + res.events.length);
  }
  if (res.snapshot) ckCampaign.snapshot = res.snapshot;
  if (ckState.view === "campaign") ckRenderCampaign();
}

async function ckFinishCampaignDashboard() {
  if (ckCampaign.poll) { clearInterval(ckCampaign.poll); ckCampaign.poll = null; }
  ckCampaign.done = true;
  await ckPollCampaign();  // one last poll to capture the final target/finding
  if (ckState.view === "campaign") ckRenderCampaign();
}

function ckFmtElapsed(s) { const m = Math.floor(s / 60), sec = s % 60; return m ? `${m}m ${sec}s` : `${sec}s`; }

function ckShortTarget(t) {
  const s = String(t || "");
  try { const u = new URL(s); return (u.host + (u.pathname === "/" ? "" : u.pathname)) || s; }
  catch (_) { return s.length > 52 ? s.slice(0, 49) + "…" : s; }
}

function ckCdTile(value, label, cls) {
  const tile = cel("div", `ck-cd-tile ${cls || ""}`.trim());
  tile.append(cel("div", "ck-cd-tile-value", value), cel("div", "ck-cd-tile-label", label));
  return tile;
}

function ckCdTargetRow(t) {
  const status = String(t.status || "queued");
  const row = cel("div", "ck-cd-target");
  row.append(cel("span", `ck-cd-dot is-${status}`));
  const main = cel("div", "ck-cd-target-main");
  main.append(cel("div", "ck-cd-target-name", ckShortTarget(t.target)));
  const meta = cel("div", "ck-cd-target-meta");
  meta.append(cel("span", "ck-cd-target-status", status));
  if (t.findings) meta.append(cel("span", null, `${t.findings} finding${t.findings === 1 ? "" : "s"}`));
  if (t.top_severity) meta.append(cel("span", `ck-sev sev-${t.top_severity}`, t.top_severity));
  if (t.elapsed_s != null && status === "done") meta.append(cel("span", null, `${t.elapsed_s}s`));
  if (t.error) meta.append(cel("span", "ck-cd-err", String(t.error).slice(0, 70)));
  main.append(meta);
  row.append(main);
  return row;
}

// Newest findings sort to the TOP (severity desc, then newest-first). Their stable key is
// their index in snapshot.findings (append-only server-side, never reordered), so sorting/
// filtering never breaks selection or the skip-if-unchanged signature.
function ckSortFilterFindings(all, sortBy, filterSev) {
  const list = filterSev === "all" ? all.slice() : all.filter((f) => (f.severity || "info") === filterSev);
  if (sortBy === "severity") list.sort((a, b) => ((CK_SEV_RANK[b.severity] ?? 0) - (CK_SEV_RANK[a.severity] ?? 0)) || (b._i - a._i));
  else list.sort((a, b) => b._i - a._i);
  return list;
}

// Rebuild a scroll container's children while keeping the user's reading position stable.
// New rows are added at/near the TOP (our sort order), so growth happens above the viewport —
// adding the height delta keeps the row they were reading in place instead of yanking to top.
function ckPreserveScroll(container, rebuild) {
  const prevTop = container.scrollTop;
  const prevH = container.scrollHeight;
  rebuild();
  const delta = container.scrollHeight - prevH;
  container.scrollTop = (prevTop > 2 && delta > 0) ? prevTop + delta : prevTop;
}

function ckCdFindingRow(f, selectedKey) {
  const sev = f.severity || "info";
  const selected = String(f._i) === String(selectedKey);
  const row = cel("div", "ck-cd-finding" + (selected ? " is-selected" : ""));
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.append(cel("span", `ck-cd-sevpill sev-${sev}`, sev.slice(0, 4)));
  const main = cel("div", "ck-cd-finding-main");
  main.append(cel("div", "ck-cd-finding-title", f.title || "Finding"));
  const meta = cel("div", "ck-cd-finding-meta");
  if (f.cls) meta.append(cel("span", null, f.cls));
  const proof = ckEffectiveProof(f);
  if (proof) meta.append(cel("span", `ck-cd-proof is-${proof}`, proof));
  if (ckEffectiveStage(f) === "submitted") meta.append(cel("span", "ck-tag", "submitted"));
  meta.append(cel("span", "ck-cd-finding-target", ckShortTarget(f.target)));
  main.append(meta);
  row.append(main);
  row.append(cel("span", "ck-cd-finding-go", "›"));
  const open = () => ckOpenFindingDrawer(f._i);
  row.addEventListener("click", open);
  row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
  return row;
}

// Build the dashboard scaffold ONCE per run and cache element refs on ckCampaign.dom, so
// each 1.2s poll UPDATES it in place (ckUpdateCampaign) rather than rebuilding the whole
// view — which was resetting the findings list's scroll to the top on every poll.
function ckBuildCampaignScaffold(host) {
  host.replaceChildren();
  host.append(cel("h2", "ck-section-title", "Campaign dashboard"));

  const head = cel("div", "ck-cd-head");
  const label = cel("div", "ck-cd-label", ckCampaign.label);
  const statusEl = cel("span", "ck-cd-status is-running", "● Running");
  const elapsedEl = cel("span", "ck-cd-elapsed", "0s");
  const stopSlot = cel("span", "ck-cd-stopslot");
  head.append(label, statusEl, elapsedEl, stopSlot);
  host.append(head);

  const progLabel = cel("p", "ck-cd-progress-label", "Mapping the surface…");
  const bar = cel("div", "ck-cd-progress");
  const progFill = cel("div", "ck-cd-progress-fill");
  progFill.style.width = "6%";
  bar.append(progFill);
  host.append(progLabel, bar);

  const tilesWrap = cel("div", "ck-cd-tiles");
  host.append(tilesWrap);

  const cols = cel("div", "ck-cd-cols");
  const tcol = cel("div", "ck-cd-col");
  const targetsTitle = cel("h3", "ck-cd-subtitle", "Targets (0)");
  const targetsList = cel("div", "ck-cd-targets");
  tcol.append(targetsTitle, targetsList);
  cols.append(tcol);

  const fcol = cel("div", "ck-cd-col");
  const fhead = cel("div", "ck-cd-fhead");
  const findingsTitle = cel("h3", "ck-cd-subtitle", "Findings so far (0)");
  const controls = cel("div", "ck-cd-controls");
  const sortSel = cel("select", "ck-cd-select");
  for (const [val, txt] of [["severity", "Severity"], ["recent", "Most recent"]]) {
    const o = cel("option", null, txt); o.value = val; sortSel.append(o);
  }
  sortSel.value = ckCampaign.sortBy;
  sortSel.addEventListener("change", () => { ckCampaign.sortBy = sortSel.value; if (ckState.view === "campaign") ckRenderCampaign(); });
  const filterSel = cel("select", "ck-cd-select");
  const filterOpts = {};
  for (const val of ["all", "critical", "high", "medium", "low", "info"]) {
    const o = cel("option", null, val === "all" ? "All severities" : val); o.value = val; filterSel.append(o); filterOpts[val] = o;
  }
  filterSel.value = ckCampaign.filterSev;
  filterSel.addEventListener("change", () => { ckCampaign.filterSev = filterSel.value; if (ckState.view === "campaign") ckRenderCampaign(); });
  const sortLbl = cel("label", "ck-cd-ctl"); sortLbl.append(cel("span", null, "Sort"), sortSel);
  const filterLbl = cel("label", "ck-cd-ctl"); filterLbl.append(cel("span", null, "Filter"), filterSel);
  controls.append(sortLbl, filterLbl);
  fhead.append(findingsTitle, controls);
  const findingsList = cel("div", "ck-cd-findings");
  fcol.append(fhead, findingsList);
  cols.append(fcol);
  host.append(cols);

  const viewAllSlot = cel("div", "ck-cd-viewall");
  host.append(viewAllSlot);

  host.append(cel("h3", "ck-cd-subtitle", "Activity"));
  const log = cel("div", "ck-op-log ck-cd-log");
  host.append(log);

  const drawer = cel("aside", "ck-cd-drawer");
  drawer.hidden = true;
  host.append(drawer);

  return {
    runId: ckCampaign.runId,
    statusEl, elapsedEl, stopSlot, stopBtn: null, progLabel, progFill, tilesWrap,
    targetsTitle, targetsList, findingsTitle, sortSel, filterSel, filterOpts, findingsList,
    viewAllSlot, viewAllBtn: null, log, drawer,
    targetsSig: "", findingsSig: "", drawerSig: "", logSeen: -1,
  };
}

function ckRenderCampaign() {
  const host = ck.views.campaign;
  if (!host) return;
  if (!ckCampaign.runId) {
    ckCampaign.dom = null;
    host.replaceChildren();
    host.append(cel("h2", "ck-section-title", "Campaign dashboard"));
    const hero = cel("div", "ck-cd-hero");
    const globe = document.createElement("img");
    globe.src = "./globe.svg"; globe.alt = ""; globe.width = 150; globe.height = 150;
    hero.append(globe);
    hero.append(cel("p", "ck-hint",
      "No campaign is running. Start a Full campaign or a Portfolio hunt from the launch rail — pick a saved program (tick “span scope” for its whole scope) or select several programs to hunt at once — and every target's status and each finding appears here live."));
    host.append(hero);
    return;
  }
  if (!ckCampaign.dom || ckCampaign.dom.runId !== ckCampaign.runId) {
    ckCampaign.dom = ckBuildCampaignScaffold(host);
  }
  ckUpdateCampaign(ckCampaign.dom);
}

function ckUpdateCampaign(dom) {
  const snap = ckCampaign.snapshot || { targets: [], findings: [], stats: {} };
  const st = snap.stats || {};
  const sev = st.severity_counts || {};
  const running = !ckCampaign.done;
  const stopping = ckCampaign.stopRequested;

  // Status pill + elapsed (cheap text updates — not scroll containers).
  dom.statusEl.className = "ck-cd-status " + (running ? (stopping ? "is-stopping" : "is-running") : (stopping ? "is-stopped" : "is-done"));
  dom.statusEl.textContent = running ? (stopping ? "● Stopping…" : "● Running") : (stopping ? "■ Stopped" : "✓ Done");
  dom.elapsedEl.textContent = ckFmtElapsed(Math.max(0, Math.round((Date.now() - ckCampaign.startedAt) / 1000)));

  // Stop button — present only while running.
  if (running) {
    if (!dom.stopBtn) {
      const b = cel("button", "ck-btn ck-cd-stop", "Stop campaign");
      b.type = "button";
      b.addEventListener("click", () => void ckStopCampaign());
      dom.stopSlot.append(b);
      dom.stopBtn = b;
    }
    dom.stopBtn.textContent = stopping ? "Stopping…" : "Stop campaign";
    dom.stopBtn.disabled = stopping;
  } else if (dom.stopBtn) {
    dom.stopBtn.remove();
    dom.stopBtn = null;
  }

  // Progress.
  const total = st.targets_total || 0, done = st.targets_done || 0;
  const pct = total ? Math.round((done / total) * 100) : (running ? 6 : 100);
  dom.progLabel.textContent = total ? `${done} / ${total} target(s) complete` : (running ? "Mapping the surface…" : "Complete");
  dom.progFill.style.width = pct + "%";
  dom.progFill.className = "ck-cd-progress-fill" + (running ? "" : " is-done");

  // Tiles (5 cheap tiles, no scroll — rebuild is fine).
  dom.tilesWrap.replaceChildren(
    ckCdTile(String(st.findings_total || 0), "Findings"),
    ckCdTile(String(st.confirmed_total || 0), "Confirmed", (st.confirmed_total || 0) ? "is-ok" : ""),
    ckCdTile(String((sev.critical || 0) + (sev.high || 0)), "Critical / high", ((sev.critical || 0) + (sev.high || 0)) ? "is-hot" : ""),
    ckCdTile(String(sev.medium || 0), "Medium"),
    ckCdTile(String(sev.low || 0), "Low"),
  );

  // Targets — skip the rebuild entirely when nothing changed (so an idle poll never disturbs
  // scroll); otherwise rebuild while preserving the reading position.
  const targets = snap.targets || [];
  dom.targetsTitle.textContent = `Targets (${targets.length})`;
  const tSig = running + "|" + targets.map((t) => `${t.target}:${t.status}:${t.findings}:${t.top_severity}:${t.error}:${t.elapsed_s}`).join("~");
  if (tSig !== dom.targetsSig) {
    dom.targetsSig = tSig;
    ckPreserveScroll(dom.targetsList, () => {
      dom.targetsList.replaceChildren();
      if (!targets.length) dom.targetsList.append(cel("p", "ck-hint", running ? "Discovering targets…" : "No targets."));
      else for (const t of targets) dom.targetsList.append(ckCdTargetRow(t));
    });
  }

  // Findings — controls (with live per-severity counts), then the sorted/filtered list, only
  // rebuilt when the effective list, sort, filter, or selection actually changed.
  const all = (snap.findings || []).map((f, i) => ({ ...f, _i: i }));
  dom.findingsTitle.textContent = `Findings so far (${all.length})`;
  const counts = { all: all.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of all) counts[f.severity] = (counts[f.severity] || 0) + 1;
  for (const k of Object.keys(dom.filterOpts)) {
    dom.filterOpts[k].textContent = (k === "all" ? "All severities" : k[0].toUpperCase() + k.slice(1)) + ` (${counts[k] || 0})`;
  }
  dom.sortSel.value = ckCampaign.sortBy;
  dom.filterSel.value = ckCampaign.filterSev;
  const eff = ckSortFilterFindings(all, ckCampaign.sortBy, ckCampaign.filterSev);
  const fSig = ckCampaign.sortBy + "|" + ckCampaign.filterSev + "|" + ckCampaign.selectedKey + "|" + running + "|" + eff.map((f) => f._i + ":" + ckEffectiveProof(f) + ":" + ckEffectiveStage(f)).join(",");
  if (fSig !== dom.findingsSig) {
    dom.findingsSig = fSig;
    ckPreserveScroll(dom.findingsList, () => {
      dom.findingsList.replaceChildren();
      if (!all.length) dom.findingsList.append(cel("p", "ck-hint", running ? "No findings yet — hunting…" : "No findings surfaced."));
      else if (!eff.length) dom.findingsList.append(cel("p", "ck-hint", "No findings match this filter."));
      else for (const f of eff) dom.findingsList.append(ckCdFindingRow(f, ckCampaign.selectedKey));
    });
  }

  // "View all" jump to the full Findings board.
  if (all.length) {
    if (!dom.viewAllBtn) {
      const b = cel("button", "ck-btn", "");
      b.type = "button";
      b.addEventListener("click", () => ckSetView("findings"));
      dom.viewAllSlot.append(b);
      dom.viewAllBtn = b;
    }
    dom.viewAllBtn.textContent = `View all ${all.length} finding${all.length === 1 ? "" : "s"} →`;
  } else if (dom.viewAllBtn) {
    dom.viewAllBtn.remove();
    dom.viewAllBtn = null;
  }

  // Activity log — rebuilt (last 120) only when the absolute event count changed, then
  // scrolled to the bottom (a log wants its newest line visible).
  if (ckCampaign.eventCount !== dom.logSeen) {
    dom.logSeen = ckCampaign.eventCount;
    dom.log.replaceChildren();
    const recent = ckCampaign.events.slice(-120);
    if (!recent.length) dom.log.append(cel("p", "ck-hint", "Starting…"));
    else for (const ev of recent) {
      const row = cel("div", "ck-op-event");
      row.append(cel("span", "ck-op-time", (ev.at || "").slice(11, 19)), cel("span", null, ev.message || ""));
      dom.log.append(row);
    }
    dom.log.scrollTop = dom.log.scrollHeight;
  }

  // Investigate drawer — re-rendered only on a selection change or a re-verify state change.
  const dsig = ckCampaign.selectedKey + ":" + ckCampaign.reverifyVersion;
  if (dsig !== dom.drawerSig) {
    dom.drawerSig = dsig;
    ckRenderFindingDrawer(dom);
  }
}

// --- Click-to-investigate: a read-only detail drawer + an on-demand active re-probe that
// runs in PARALLEL to the campaign (a separate engine track), so you can dig into a finding
// the moment it pops up without pausing the hunt. ---
function ckOpenFindingDrawer(key) {
  ckCampaign.selectedKey = String(key);
  if (ckState.view === "campaign") ckRenderCampaign();
}

function ckCloseFindingDrawer() {
  ckCampaign.selectedKey = "";
  if (ckState.view === "campaign") ckRenderCampaign();
}

function ckRenderFindingDrawer(dom) {
  const drawer = dom.drawer;
  const key = ckCampaign.selectedKey;
  const snap = ckCampaign.snapshot || { findings: [] };
  const raw = key === "" ? null : (snap.findings || [])[Number(key)];
  if (!raw) {
    drawer.hidden = true;
    drawer.replaceChildren();
    ck.views.campaign?.classList.remove("has-cd-drawer");
    return;
  }
  const f = { ...raw, _i: Number(key) };
  drawer.replaceChildren();
  drawer.hidden = false;
  ck.views.campaign?.classList.add("has-cd-drawer");

  const head = cel("div", "ck-cd-drawer-head");
  head.append(cel("h3", null, f.title || "Finding"));
  const close = cel("button", "ck-detail-close", "✕");
  close.type = "button";
  close.setAttribute("aria-label", "Close finding detail");
  close.addEventListener("click", ckCloseFindingDrawer);
  head.append(close);
  drawer.append(head);

  const badges = cel("div", "ck-summary");
  const sev = f.severity || "info";
  const dproof = ckEffectiveProof(f);
  badges.append(cel("span", `ck-sev sev-${sev}`, sev.toUpperCase()));
  if (dproof) badges.append(cel("span", `ck-cd-proof is-${dproof}`, dproof));
  if (ckEffectiveStage(f) === "submitted") badges.append(cel("span", "ck-tag", "submitted"));
  if (f.cwe) badges.append(cel("span", "ck-tag", f.cwe));
  drawer.append(badges);

  const meta = cel("dl", "ck-meta-grid");
  const add = (k, v) => { if (v) { meta.append(cel("dt", null, k)); meta.append(cel("dd", null, String(v))); } };
  add("Class", f.cls);
  add("Target", f.target);
  add("Location", f.location);
  add("Rule", f.rule);
  add("Proof", dproof);
  drawer.append(meta);

  drawer.append(cel("p", "ck-hint",
    "Live summary streamed during the hunt. Create proof of impact to actively probe + screenshot this finding now, then create a report — all without pausing the campaign."));

  // Jump to the full submission report on the Submissions page, carrying any proof of impact /
  // screenshot already captured in this drawer.
  const fullActs = cel("div", "ck-actions");
  const fullBtn = cel("button", "ck-btn primary", "View full report →");
  fullBtn.type = "button";
  fullBtn.title = "Open the full submission report (proof of impact, screenshot, everything to submit) on the Submissions page";
  fullBtn.addEventListener("click", () => {
    const rv = ckCampaign.reverify[String(f._i)];
    let proofObj = null, shot = null;
    if (rv && rv.state === "done" && rv.result) {
      const fnds = rv.result.findings || [];
      const best = fnds.find((x) => x.status === "confirmed") || fnds[0];
      if (best) proofObj = {
        status: best.status || "candidate", observed_result: best.observed || "",
        control_result: best.control || "", evidence: best.evidence || "", proof_obligation: best.proof_obligation || "",
      };
      if (rv.result.screenshot && rv.result.screenshot.ok && rv.result.screenshot.data_url) shot = rv.result.screenshot;
    }
    ckViewFullReport(f, { runId: ckCampaign.runId, proofObj, screenshot: shot });
  });
  fullActs.append(fullBtn);
  drawer.append(fullActs);

  drawer.append(ckRenderProveSection(f));
  drawer.append(ckRenderReportSection(f));
}

// Proof-of-impact section (drawer): active probe (verify_active) + screenshot, in a
// separate track. State lives in ckCampaign.reverify[key] so the poll-driven drawer
// re-render reproduces it whether the user stays on this finding or clicks away and back.
function ckRenderProveSection(f) {
  const key = String(f._i);
  const rv = ckCampaign.reverify[key];
  const running = rv && rv.state === "running";
  const wrap = cel("div", "ck-cd-reverify");
  wrap.append(cel("h4", null, "Proof of impact — active"));
  wrap.append(cel("p", "ck-hint", "Re-runs the scope-gated active checks against this finding's URL and captures a screenshot, in a separate track. The campaign keeps running."));
  const btn = cel("button", "ck-btn primary", running ? "Working…" : "Create proof of impact");
  btn.type = "button";
  btn.disabled = running || !ckCampaign.authorized;
  btn.addEventListener("click", () => void ckProveFinding(f));
  wrap.append(btn);
  if (!ckCampaign.authorized) wrap.append(cel("p", "ck-hint", "Needs an authorized campaign (the authorization box was ticked at launch)."));
  if (running) {
    const busy = cel("div", "ck-cd-rv-busy");
    busy.append(cel("span", "typing-dots"));
    busy.append(cel("span", null, "Actively probing " + (f.location || f.target || "the target") + " in scope…"));
    wrap.append(busy);
  } else if (rv && rv.state === "error") {
    wrap.append(cel("p", "ck-cd-rv-error", rv.error || "Proof of impact could not be gathered."));
  } else if (rv && rv.state === "done") {
    const box = cel("div", "ck-cd-rv-result");
    ckRenderProofResult(box, rv.result);
    wrap.append(box);
  }
  return wrap;
}

// Report section (drawer): build a well-authored report for this finding, folding in the
// strongest proof gathered above. State in ckCampaign.report[key].
function ckRenderReportSection(f) {
  const key = String(f._i);
  const rep = ckCampaign.report[key];
  const running = rep && rep.state === "running";
  const wrap = cel("div", "ck-cd-reverify");
  wrap.append(cel("h4", null, "Report"));
  wrap.append(cel("p", "ck-hint", "Builds a well-authored report for this finding, folding in any proof of impact captured above."));
  const btn = cel("button", "ck-btn", running ? "Building…" : "Create report");
  btn.type = "button";
  btn.disabled = running;
  btn.addEventListener("click", () => void ckDrawerReport(f));
  wrap.append(btn);
  if (running) {
    const busy = cel("div", "ck-cd-rv-busy");
    busy.append(cel("span", "typing-dots"));
    busy.append(cel("span", null, "Building the report…"));
    wrap.append(busy);
  } else if (rep && rep.state === "error") {
    wrap.append(cel("p", "ck-cd-rv-error", rep.error || "Report could not be built."));
  } else if (rep && rep.state === "done") {
    const box = cel("div", "ck-report-preview");
    ckRenderReportPreview(box, "Report", rep.markdown, rep.filename || (ckSlug(f.title || "finding") + ".md"));
    wrap.append(box);
  }
  return wrap;
}

// Create proof of impact: fires an independent /prove request (does NOT block the campaign
// poll), stashing state in ckCampaign.reverify[key].
async function ckProveFinding(f) {
  const key = String(f._i);
  const url = (f.location || f.target || "").trim();
  const setState = (s) => { ckCampaign.reverify[key] = s; ckCampaign.reverifyVersion++; if (ckState.view === "campaign") ckRenderCampaign(); };
  if (!url) { setState({ state: "error", error: "This finding has no URL to probe." }); return; }
  setState({ state: "running" });
  let res;
  try {
    res = await apiFetch("/api/bounty/finding/prove", {
      method: "POST", timeoutMs: 120000,
      // run_id + ref persist the captured proof onto the cached run finding so its canonical
      // submission report renders confirmed (no-op server-side until this finding has a ref).
      body: JSON.stringify({ url, scope: ckCampaign.scope, program_id: ckCampaign.programId,
        run_id: ckCampaign.runId || "", ref: f.ref || "", authorized: ckCampaign.authorized, screenshot: true }),
    });
  } catch (err) {
    setState({ state: "error", error: err.message || "Could not reach the engine." });
    return;
  }
  if (res && res.ok) {
    setState({ state: "done", result: res });
    // Promote this finding to confirmed across the app when the active pass confirmed its
    // OWN class (matched), so the dashboard/board/history/submissions all agree + it persists.
    if ((res.confirmed || 0) && ckProofMatchesFinding(res.findings, f)) ckMarkStatus(f, { proof: "confirmed" });
  } else {
    setState({ state: "error", error: (res && res.error) || "Proof of impact could not be gathered." });
  }
}

async function ckDrawerReport(f) {
  const key = String(f._i);
  const setState = (s) => { ckCampaign.report[key] = s; ckCampaign.reverifyVersion++; if (ckState.view === "campaign") ckRenderCampaign(); };
  setState({ state: "running" });
  // Fold in the strongest proof gathered above (prefer a confirmed active check).
  let proof = null;
  const rv = ckCampaign.reverify[key];
  if (rv && rv.state === "done" && (rv.result.findings || []).length) {
    const fnds = rv.result.findings;
    const best = fnds.find((x) => x.status === "confirmed") || fnds[0];
    proof = { status: best.status || "candidate", method: best.method || "", observed_result: best.observed || "",
              control_result: best.control || "", evidence: best.evidence || "", affected_asset: best.affected_asset || "" };
  }
  let res;
  try {
    res = await apiFetch("/api/bounty/finding/report", {
      method: "POST", timeoutMs: 30000,
      body: JSON.stringify({
        title: f.title || "Security finding", severity: f.severity || "info", class_name: f.cls || "",
        class_id: f.class_id || "", location: f.location || f.target || "", cwe: f.cwe || "", rule_id: f.rule || "",
        target: f.target || f.location || "", scope: ckCampaign.scope || "",
        platform: ckState.platform || "hackerone", proof,
      }),
    });
  } catch (err) {
    setState({ state: "error", error: err.message || "Could not reach the engine." });
    return;
  }
  if (res && res.ok && res.package) setState({ state: "done", markdown: res.package.vulnerability_information || "", filename: ckSlug(f.title || "finding") + ".md" });
  else setState({ state: "error", error: (res && res.error) || "Report could not be built." });
}

// --- Completion alerts: a hunt/campaign can run for minutes, and the autonomous
// operator auto-submitting a confirmed bounty is arguably the most important event
// in the app -- both need to reach an operator who has tabbed away, not just whoever
// happens to be staring at the launch rail when it finishes. Two independent,
// stacking signals: a tab-title badge (works everywhere, zero permissions) and a
// native OS notification (louder, but needs a one-time permission grant). Both are
// gated on document.hidden so a focused, watching operator never gets spammed with
// what they can already see happening live in the log. ---
const ckBaseTitle = document.title;
let ckTitleBadgeCount = 0;

// Adds -- never overwrites -- so a hunt-complete badge and an operator-submit badge
// (two independent async sources) both contribute to one running unseen-event count
// instead of the later call silently clobbering the earlier one's count.
function ckBumpTitleBadge(delta) {
  ckTitleBadgeCount = Math.max(0, ckTitleBadgeCount + (delta | 0));
  document.title = ckTitleBadgeCount > 0 ? `(${ckTitleBadgeCount}) ${ckBaseTitle}` : ckBaseTitle;
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) { ckTitleBadgeCount = 0; document.title = ckBaseTitle; }
});

async function ckNotify(title, body) {
  if (!("Notification" in window)) return;
  if (Notification.permission === "default") {
    try { await Notification.requestPermission(); } catch (_) { return; }
  }
  if (Notification.permission !== "granted") return;
  try {
    const n = new Notification(title, { body });
    n.onclick = () => { window.focus(); n.close(); };
  } catch (_) { /* best-effort -- OS/browser may still refuse (Do Not Disturb, etc.) */ }
}

function bootCockpit() {
  if (!ck.root) return;
  document.body.dataset.appMode = state.appMode || "hunt";
  ck.studio?.addEventListener("click", () => setAppMode("studio"));
  ck.huntReturn?.addEventListener("click", () => setAppMode("hunt"));
  ck.theme?.addEventListener("click", () => toggleTheme());
  for (const btn of ck.navButtons) btn.addEventListener("click", () => ckSetView(btn.dataset.ckView));
  ck.segHunt?.addEventListener("click", () => ckSetRunType("hunt"));
  ck.segCampaign?.addEventListener("click", () => ckSetRunType("campaign"));
  ck.segPortfolio?.addEventListener("click", () => ckSetRunType("portfolio"));
  ck.portfolioAll?.addEventListener("click", () => {
    const boxes = ck.portfolioList ? [...ck.portfolioList.querySelectorAll("input[type=checkbox]:not(:disabled)")] : [];
    const allOn = boxes.length && boxes.every((c) => c.checked);
    for (const c of boxes) c.checked = !allOn;
    ckUpdatePortfolioCount();
  });
  ck.activeProgram?.addEventListener("change", () => ckApplyActiveProgram(ck.activeProgram.value));
  ck.spanScope?.addEventListener("change", () => {
    state.ckSpanScope = Boolean(ck.spanScope.checked);
    saveState();
    ckUpdateAuthorizedLabel();
  });
  ck.profile?.addEventListener("change", () => { state.bountyProfile = ck.profile.value; saveState(); ckUpdateProfileHint(); });
  ck.launch?.addEventListener("submit", (e) => { e.preventDefault(); void ckRun(); });
  // Drop the (collapsed-by-default) hunt walkthrough at the top of the launch form.
  if (ck.launch) ck.launch.prepend(ckWalkthrough("hunt"));
  // Restore persisted form values.
  if (ck.target) ck.target.value = state.ckTarget || "";
  if (ck.scope) ck.scope.value = state.ckScope || "";
  if (ck.program) ck.program.value = state.ckProgram || "";
  if (ck.active) ck.active.checked = Boolean(state.ckActive);
  if (ck.timeBased) ck.timeBased.checked = Boolean(state.ckTimeBased);
  if (ck.deep) ck.deep.checked = Boolean(state.ckDeep);
  if (ck.live) ck.live.checked = Boolean(state.ckLive);
  if (ck.spanScope) ck.spanScope.checked = Boolean(state.ckSpanScope);
  if (ck.authCookie) ck.authCookie.value = state.ckAuthCookie || "";
  if (ck.authHeaders) ck.authHeaders.value = state.ckAuthHeaders || "";
  if (ck.authFold && (state.ckAuthCookie || state.ckAuthHeaders)) ck.authFold.open = true;
  ckSetRunType(state.ckRunType || "hunt");
  ckSyncService();
  void ckPopulateProfiles();
  void (async () => {
    await ckFetchCreds();
    await ckRenderProgram();   // also fetches + populates the launch rail's Program picker
    ckUpdateSpanScopeToggle();  // reflect a restored active program without clobbering the restored checked state
    ckMaybeShowWizard();
  })();
}

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
  void renderGpuAccel();
  render();
  setPanelMode(state.panelMode || "brain");
  bootCockpit();
  renderTemplateBar();
  renderWorkbench();
  if (state.agentMode && state.agentWorkspace) {
    void refreshWorkspaceTree();
  }
}

boot();

// Boot splash: hold the GreyNOC globe until the local engine is reachable (min ~0.7s so it
// registers as a brand moment; hard cap ~7s so a slow/absent engine can never block the app).
(function ckBootSplash() {
  const el = document.getElementById("ckSplash");
  if (!el) return;
  const started = Date.now();
  let done = false;
  const hide = () => { if (done) return; done = true; el.classList.add("is-hidden"); setTimeout(() => el.remove(), 650); };
  const tick = () => {
    const elapsed = Date.now() - started;
    if ((service && service.available && elapsed > 700) || elapsed > 7000) { hide(); return; }
    setTimeout(tick, 250);
  };
  setTimeout(tick, 700);
})();
