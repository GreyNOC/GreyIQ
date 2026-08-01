# Coding with GreyIQ — what works offline and what needs a brain

GreyIQ's coding ability comes from a configurable **brain** plus an **agent loop** with
hands. The bundled offline model is a ~0.8M-parameter character-level network with a
64-character context and effectively no code in its corpus — it is a chat fallback, not a
programmer. This pack says exactly where the line is, so you never wait on something that
was never going to work.

## What the offline model can and cannot do
<!-- triggers: can greyiq write code, offline model, tinygpt, write me a function, generate code -->
The honest ceiling, stated up front.

- The offline TinyGPT model **cannot write or edit code**. Its own quality gate discards code-shaped output, so asking it to produces nothing useful and burns CPU.
- What it can do offline: chat, and quote GreyIQ's bundled playbooks (this pack, the bug-bounty playbooks, and the coding skills) with a citation.
- The **deterministic offline coder** is a separate, no-model path: it emits a small closed set of edit operations — scaffolds and mechanical edits such as a framework-aware test stub, a route file, a Dockerfile, or a CI file from a bundled template.
- The offline coder reads the repo first (dependency manifests decide pytest vs unittest; a Flask template is only offered in a Flask repo) and returns `needs_brain` rather than guessing business logic. It never invents application behaviour.
- Everything beyond scaffolds and mechanical edits needs a configured brain.

## Configuring a brain
<!-- triggers: configure a brain, set up ollama, local model, claude api key, settings brain -->
Two supported shapes: fully local, or Claude.

- **Local model (Ollama)** — an OpenAI-compatible endpoint on your own machine. Offline, free, private; runs a real code model on your own GPU. This is the recommended default if you want nothing leaving the machine.
- **Claude (Anthropic)** — the official SDK, the closest thing to a full coding assistant.
- **OpenAI-compatible** — any endpoint that speaks the OpenAI API.
- **Off** — the local TinyGPT fallback, i.e. chat only.
- API keys live in the runtime secrets file with owner-only permissions and are never echoed back to the UI.

## The Plan -> Change -> Verify -> Explain loop
<!-- triggers: workbench, agent loop, plan change verify, how does the agent work -->
The Workbench workflow, and why it is safe to let it edit files.

1. **Plan** — the agent reads the workspace (file tree, repo map, project memory, matching skills) and states what it intends to change before touching anything.
2. **Change** — every write goes through the agent's ToolBox, which snapshots the file first. Nothing edits the disk outside that path.
3. **Verify** — the change is gated by a verify step (the project's own tests/build). An unverified change is reported as unverified, not as done.
4. **Explain** — the run ends with a diff and a plain-language account of what changed and why.
- One agent run at a time per workspace, and **Undo last agent run** restores the snapshot.

## Agent safety envelope
<!-- triggers: agent safety, is the agent safe, sandbox, allow commands, prompt injection -->
The boundaries the agent cannot talk its way out of.

- Every file path is resolved and confined to the workspace root — no traversal outside it.
- Running shell commands is gated by `agent.allow_commands` (**off by default**), runs inside the workspace with a timeout, and captures output. It is never a live interactive shell.
- Network diagnostics are read-only (DNS/TCP/HTTP/TLS) in pure Python, gated by `agent.allow_network` and bounded by a timeout.
- The loop is capped at `agent.max_steps`.
- File content the agent reads from a repo is UNTRUSTED data: it is fenced and trust-labelled so a hostile README or source comment cannot issue instructions to the agent.

## When a coding answer needs a brain
<!-- triggers: needs brain, why cant it, no brain configured, what should i configure -->
Recognizing it early saves the round trip.

- Writing new business logic, debugging a real failure, refactoring across files, or reviewing a diff: needs a brain.
- Scaffolding a test stub, adding a templated config/CI/Docker file, or a mechanical rename: the deterministic offline coder may cover it.
- Explaining GreyIQ's own workflow, safety envelope, or playbooks: answered offline from this pack, quoted verbatim.
- If you asked for code and got this text, the fix is one step: configure a Local model (Ollama) or a Claude brain in Settings, then use the Workbench agent.
