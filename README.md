# GreyIQ

GreyIQ (GreyNOC-IQ) is a soft, friendly, powerful **local-first AI** desktop/web app. It's a GreyNOC product that runs as its own experience, separate from the GreyNOC SOC interface — your data stays on your machine.

It includes:

- **Editable bots** with name, color, persona, style, and response variation.
- A pluggable **coding brain** — answer with a local model (Ollama), Claude, or any OpenAI-compatible endpoint; falls back to the bundled local engine.
- **Agent mode + the Workbench IDE** — let the brain read, edit, and (optionally) run things in a workspace folder, with a file explorer, code preview, diffs, agent steps, and verification output.
- **BugHunter** — a static/passive security scanner, a **bug-bounty hunt** that writes reports with attack plans, and an **agent security red-team** that tests GreyIQ's own agent.
- Personal training from preferences, source-specific data, and 👍/👎 feedback; folder ingestion (PDF/DOCX/text/OCR).
- Browser fallback (CPU/WebGPU) when the Python service isn't running, plus an Electron launcher that boots the backend (and a bundled Ollama runtime) and opens the UI.

## Run

Browser-only fallback:

```powershell
npm start
```

Open [http://localhost:4173](http://localhost:4173).

Full local engine:

```powershell
python -m backend.greyiq_api
```

Open [http://localhost:8766](http://localhost:8766).

Desktop:

```powershell
npm install
npm run desktop
```

## Check

```powershell
npm run check
```

## Coding brain

In the **Coding brain** panel (training column) pick a provider:

- **Off** — local TinyGPT only (offline fallback).
- **Local model (Ollama)** — e.g. `qwen2.5-coder:14b`. The desktop build bundles an Ollama runtime and offers one-click model download.
- **Claude API** — paste an Anthropic key (default model `claude-opus-4-8`).
- **OpenAI-compatible** — any `/v1/chat/completions` endpoint.

The brain answers chat, drives Agent mode, and writes the analysis in BugHunter reports.

## Agent mode & the Workbench

Toggle **Agent** and pick a workspace folder. The agent reads/searches/edits files
(traversal-guarded, confined to the workspace) and verifies its work; `run_command`
is **off by default**. The **Workbench** opens an IDE-style layer — a file tree, a
read-only preview with line numbers + light syntax highlighting, a Changes/diff tab,
Agent Steps, and a Verify panel. Drag the divider to resize, or slide it to the top to
**dock** the workbench (chat moves to a 1/3 side panel). A light/dark theme toggle is in
the header.

## BugHunter

- **Scan** from chat: `scan code <path|repo>`, `scan web <url>`, `scan live <url>`.
- **Bug-bounty hunt** (training panel): pick a profile (Web app / API / Source-code /
  Secrets / Full sweep) and an optional vuln-class focus (XSS, SQLi, SSRF, IDOR/access
  control, auth, RCE, secrets). GreyIQ runs the right scanner, the brain writes
  reproduction steps + attack plans, and a Markdown report (+ JSON sidecar, optional
  per-finding files) is written to a folder you choose. **Authorized testing only** —
  a hunt won't run unless you confirm the target is in scope.
- **Agent security test** — red-teams GreyIQ's own agent in a throwaway sandbox
  (sandbox/policy probes always; opt-in prompt-injection + jailbreak behavioral probes)
  and reports a posture verdict.

## Local Security Defaults

GreyIQ binds local services to `127.0.0.1` by default. Set `GREYIQ_HOST`
or `HOST` only when you intentionally want another interface.

The Python API rejects browser requests whose `Origin` does not match the
running service. If you intentionally serve a separate trusted frontend, set
`GREYIQ_ALLOWED_ORIGINS` to a comma-separated list such as
`http://127.0.0.1:4173`.

Local code scans can be restricted to one folder with
`GREYIQ_CODE_SCAN_BASE_PATH`. Remote repository scans require HTTPS URLs from
the built-in host allowlist. Web/live scans refuse private/loopback hosts unless
`GREYIQ_SCAN_ALLOW_PRIVATE_URLS=1`.

## How Training Works

Each bot owns browser-side preference weights for instant fallback behavior. When the GreyIQ backend is running, preferences, rated examples, and source-specific training data are also written into the local runtime training data. The trainer can run against one or more selected sources, and the AI core store tracks the active bot as a local core. Data stays on the machine unless you explicitly move it.

## AI Cores

GreyIQ starts with companion, builder, researcher, and BugHunter cores. Each core carries a response contract, confidence policy, trust posture, and starter knowledge profile so first-run answers feel useful before personal training begins. Personal choices and imported documents become higher-priority local sources as the user trains the app.
