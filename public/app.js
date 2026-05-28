const STORE_KEY = "greyiq.local.ai.v1";
const DIMENSIONS = 384;
const MAX_MEMORY_ITEMS = 32;
const COLORS = ["#0e7c7b", "#6c5ce7", "#c95542", "#d69b2d", "#31572c", "#8f3985"];

const DEFAULT_BOTS = [
  {
    id: "astra",
    name: "Astra",
    color: COLORS[0],
    style: "direct",
    temperature: 42,
    persona:
      "Astra is concise, tactical, and practical. It turns fuzzy requests into concrete next moves and keeps answers grounded.",
    corpus: [
      "Start with the constraint that matters most, then choose the smallest useful action.",
      "A good answer names the next command, the expected result, and the decision after that.",
      "When the request is broad, narrow it into a useful working version and keep moving."
    ],
    weights: []
  },
  {
    id: "mira",
    name: "Mira",
    color: COLORS[1],
    style: "warm",
    temperature: 58,
    persona:
      "Mira is warm, reflective, and steady. It helps the user feel oriented while still giving crisp practical help.",
    corpus: [
      "Hold the feeling and the practical step at the same time.",
      "A steady answer can be kind without becoming vague.",
      "Reflect the goal, reduce the pressure, and offer one clean way forward."
    ],
    weights: []
  },
  {
    id: "Forge",
    name: "Forge",
    color: COLORS[2],
    style: "technical",
    temperature: 36,
    persona:
      "Forge is technical, skeptical, and systems-minded. It checks assumptions, traces failures, and favors verifiable fixes.",
    corpus: [
      "Inspect the boundary first because bugs often hide where two systems meet.",
      "Prefer evidence over hunches, but use the hunch to pick the first test.",
      "A repair is not done until the failure mode is exercised again."
    ],
    weights: []
  }
];

const state = loadState();
let backend = null;

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
  exampleForm: document.querySelector("#exampleForm"),
  exampleUser: document.querySelector("#exampleUser"),
  exampleBot: document.querySelector("#exampleBot"),
  trainButton: document.querySelector("#trainButton"),
  exampleCount: document.querySelector("#exampleCount"),
  choiceCount: document.querySelector("#choiceCount"),
  modelState: document.querySelector("#modelState"),
  memoryList: document.querySelector("#memoryList")
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
    backendPreference: "cpu"
  };

  try {
    const saved = JSON.parse(localStorage.getItem(STORE_KEY) || "null");
    if (!saved || !Array.isArray(saved.bots)) {
      return fallback;
    }

    return {
      ...fallback,
      ...saved,
      bots: saved.bots.map((bot) => ({
        ...bot,
        weights: normalizeWeights(bot.weights)
      }))
    };
  } catch {
    return fallback;
  }
}

function saveState() {
  localStorage.setItem(STORE_KEY, JSON.stringify(state));
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
      question: `Short answer: I would reduce ${topic} to the decision you need next, then test that decision.`,
      debug: `I would isolate ${topic}, run the smallest check, and only widen the search when that check passes.`,
      build: `I would ship the smallest usable version of ${topic}, then train the details from your feedback.`,
      preference: `I will treat ${topic} as a preference signal and weight future replies toward it.`,
      general: `I can work with ${topic}; the useful move is to make it specific and act on the next step.`
    },
    warm: {
      question: `The center of this is ${topic}; I would answer it plainly and keep the next step manageable.`,
      debug: `For ${topic}, I would slow the problem down, find the first reliable signal, and move from there.`,
      build: `For ${topic}, I would make a version that feels usable now and let your taste refine it.`,
      preference: `I will remember ${topic} as part of how you like the conversation to feel.`,
      general: `I am with you on ${topic}; let us turn it into something concrete enough to use.`
    },
    technical: {
      question: `For ${topic}, I would define the inputs, expected output, and the check that proves the answer.`,
      debug: `For ${topic}, start at the failing boundary, capture evidence, then change one variable at a time.`,
      build: `For ${topic}, separate the interface, state, training loop, and acceleration path before expanding scope.`,
      preference: `I will encode ${topic} as a weighted local feature for response ranking.`,
      general: `For ${topic}, I need the constraint, the current state, and the measurable result.`
    },
    creative: {
      question: `For ${topic}, I would find the sharpest angle first, then shape the answer around that pulse.`,
      debug: `For ${topic}, I would follow the strange edge first because that is where the hidden rule usually shows itself.`,
      build: `For ${topic}, I would make the first version tangible, responsive, and easy to reshape.`,
      preference: `I will fold ${topic} into the bot's taste so future answers lean closer to you.`,
      general: `There is a workable shape inside ${topic}; I would pull out the strongest thread and build from it.`
    }
  };
  return table[style]?.[intent] || table.direct.general;
}

function memorySentence(memories) {
  const latest = memories.slice().reverse().find((memory) => memory.kind === "preference" || memory.kind === "example");
  if (!latest) {
    return "No personal preference signals are loaded yet.";
  }
  if (latest.kind === "example") {
    return `I am weighting answers toward: ${latest.bot}`;
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
  els.exampleCount.textContent = memories.filter((memory) => memory.kind === "example").length;
  els.choiceCount.textContent = memories.filter((memory) => memory.kind === "preference").length;
  els.modelState.textContent = activeBot().trainedAt ? "Trained" : "Fresh";
  els.memoryList.replaceChildren();

  for (const memory of memories.slice().reverse().slice(0, 10)) {
    const item = document.createElement("article");
    item.className = "memory-item";
    const text =
      memory.kind === "example"
        ? `${memory.user} -> ${memory.bot}`
        : memory.text;
    item.innerHTML = `
      <p>${escapeHtml(text)}</p>
      <span class="memory-actions">
        <small>${escapeHtml(memory.kind)}</small>
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

function renderBackend() {
  els.backendStatus.textContent = backend?.status || "CPU ready";
  els.cpuButton.classList.toggle("is-active", backend?.mode !== "gpu");
  els.gpuButton.classList.toggle("is-active", backend?.mode === "gpu");
}

function rateMessage(id, rating) {
  const message = activeChat().find((item) => item.id === id);
  if (!message) {
    return;
  }
  message.rating = message.rating === rating ? null : rating;
  trainBot(activeBot());
  render();
}

function addMemory(memory) {
  const memories = activeMemories();
  memories.push({ id: crypto.randomUUID(), createdAt: Date.now(), ...memory });
  if (memories.length > MAX_MEMORY_ITEMS) {
    memories.splice(0, memories.length - MAX_MEMORY_ITEMS);
  }
  trainBot(activeBot());
  render();
}

function removeMemory(id) {
  const memories = activeMemories();
  const index = memories.findIndex((memory) => memory.id === id);
  if (index >= 0) {
    memories.splice(index, 1);
    trainBot(activeBot());
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
  const answer = await replyFor(text);
  chat.push({ id: crypto.randomUUID(), role: "bot", text: answer, createdAt: Date.now() });
  els.sendButton.disabled = false;
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

els.exampleForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const user = els.exampleUser.value.trim();
  const bot = els.exampleBot.value.trim();
  if (!user || !bot) {
    return;
  }
  els.exampleUser.value = "";
  els.exampleBot.value = "";
  addMemory({ kind: "example", user, bot, text: `${user} ${bot}` });
});

els.trainButton.addEventListener("click", () => {
  trainBot(activeBot());
  render();
});

els.cpuButton.addEventListener("click", async () => {
  state.backendPreference = "cpu";
  await backend.setMode("cpu");
  render();
});

els.gpuButton.addEventListener("click", async () => {
  state.backendPreference = "gpu";
  els.backendStatus.textContent = "GPU starting";
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
  render();
});

async function boot() {
  backend = new AccelerationBackend();
  await backend.setMode(state.backendPreference || "cpu");

  for (const bot of state.bots) {
    if (!bot.trainedAt) {
      trainBot(bot);
    }
  }

  render();
}

boot();
