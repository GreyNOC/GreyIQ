# GreyIQ

GreyIQ (GreyNOC-IQ) is a **local-first AI** desktop/web app. It's a GreyNOC product that runs as its own experience, separate from the GreyNOC SOC interface — your data stays on your machine.

It includes:

- **DevOps/server setup playbooks** for PM2 ecosystem files, Ubuntu VPS setup, Nginx reverse proxies, environment variables/secrets, and `DEPLOY.md` runbooks.
- **Editable bots** with name, color, persona, style, and response variation.
- A pluggable **coding brain** — answer with a local model (Ollama), Claude, or any OpenAI-compatible endpoint; falls back to the bundled local engine.
- **Agent mode + the Workbench IDE** — let the brain read, edit, and (optionally) run things in a workspace folder, with a file explorer, code preview, diffs, agent steps, and verification output.
- **BugHunter** — a static/passive security scanner, a **bug-bounty hunt** that writes reports with attack plans, and an **agent security red-team** that tests GreyIQ's own agent.
- Personal training from preferences, source-specific data, and 👍/👎 feedback; folder ingestion (PDF/DOCX/text/OCR).
- Browser fallback (CPU/WebGPU) when the Python service isn't running, plus an Electron launcher that boots the backend and fetches a **GPU-accelerated** Ollama runtime on first use of the local model — NVIDIA (CUDA) works out of the box; AMD (ROCm) is auto-provisioned on first run.

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

The desktop cockpit includes a **TACNOC** option beside **AI Studio**. It opens
the companion TACNOC application in its own sandboxed desktop process. GreyIQ
detects standard TACNOC installs and the normal `GreyNOC Belcher` development
checkout on the current user's Desktop; set `GREYIQ_TACNOC_PATH` to a TACNOC
executable or project directory for any other layout.

## Debian 13

The Linux release includes a Debian package, an AppImage, and a headless CLI
tarball for amd64. On a Debian 13 desktop, install the package with:

```bash
sudo apt install ./GreyIQ-*-amd64.deb
greyiq-cli dashboard
```

`greyiq` opens the desktop app. `greyiq-cli` runs the same frozen backend's
command-line interface; `dashboard` is an interactive, read-only terminal view
of local health, system load, programs, findings, reports, and activity. Press
`q` to quit, `r` to refresh, and Tab or the arrow keys to change panels. The
dashboard requires a terminal and only probes the API on `127.0.0.1`. Both the
installed desktop and CLI use `$XDG_DATA_HOME/greyiq/runtime` (or
`~/.local/share/greyiq/runtime`) unless `GREYIQ_RUNTIME_DIR` is set. On first
launch after upgrading an older AppImage, the desktop copies existing data from
its previous Electron runtime directory when the new location is still absent.
Launch the desktop once before running CLI hunts after an upgrade so that copy
can complete.

For the headless CLI archive, extract it and run `./greyiq-cli path` for local
PATH guidance, then `./greyiq-cli dashboard`.
The included `INSTALL.txt` and [deployment guide](DEPLOY.md) show the exact
optional `~/.local/bin` PATH setup; the Debian package needs no PATH change.

For the AppImage, install its FUSE and local-model extraction dependencies,
then make it executable:

```bash
sudo apt install libfuse2t64 zstd
chmod +x GreyIQ-*-x86_64.AppImage
./GreyIQ-*-x86_64.AppImage
```

From a source checkout, install [Node.js 22.12 or newer](https://nodejs.org/en/download),
plus Debian's `python3-venv`, `tesseract-ocr`, and `poppler-utils` packages.
Debian 13's own `nodejs` package is Node 20, which is too old for the Electron
version used here. Then run `npm ci`, create and
activate a Python virtual environment, and install `requirements.txt`.
`./gn dashboard` opens the terminal view. See [DEPLOY.md](DEPLOY.md) for exact
commands, build steps, and optional OCR and model setup.

## Check

Install the Python runtime and test dependencies before running the full check:

```powershell
python -m pip install -r requirements.txt -r requirements-test.txt
```

```powershell
npm run check
```

Reusable checks are also available:

```powershell
npm run check:js
npm run check:python
npm run check:devops
```

## Coding brain

In the **Coding brain** panel (training column) pick a provider:

- **Off** — local TinyGPT only (offline fallback).
- **Local model (Ollama)** — e.g. `qwen2.5-coder:14b`. The Ollama runtime isn't shipped in the installer — GreyIQ fetches it (with its bundled NVIDIA/CUDA runner) the first time you select the local model, offers one-click model download, and uses your GPU automatically: NVIDIA works out of the box; on an AMD box GreyIQ fetches Ollama's ROCm runtime separately on first run. No supported GPU → it runs on CPU.
- **Claude API** — paste an Anthropic key (default model `claude-opus-4-8`).
- **OpenAI-compatible** — any `/v1/chat/completions` endpoint.

For a local Hugging Face model, paste a **public GGUF model page** such as
`https://huggingface.co/owner/model-GGUF`, an `hf.co/owner/model-GGUF:quant`
reference, or its `ollama run ...` command into the model field. Click
**Download and use** once. GreyIQ starts Ollama if needed, downloads the selected
model, checks that it appears locally, and tests chat and structured tool calls
before switching the active brain. A model that only supports chat stays
available for manual selection; the previous brain remains active. Private,
gated, and non-GGUF repositories need their own access or conversion steps.

The dedicated **Import from Hugging Face** control also accepts a GGUF model
page URL or `hf.co/owner/model-GGUF:Q4_K_M` reference. Choose **Import and select**
to download through Ollama and select it for chat and Agent mode. Use **Test**
to confirm it responds. The import control requires a loopback Ollama server
URL such as `http://127.0.0.1:11434/v1`; inference then runs locally. Review
each model's license and card before use. Agent mode requires a model that can
follow tool calls. See the [Hugging Face Ollama guide](https://huggingface.co/docs/hub/main/ollama).
If Ollama reports a blocked Hugging Face download redirect, update Ollama to
0.34.3 or newer; 0.34.2 has a [known redirect bug](https://github.com/ollama/ollama/issues/18526).

The brain answers chat, drives Agent mode, and writes the analysis in BugHunter reports.
For security and root-cause work, Agent mode can call a shared evidence-grounded
investigator that scans code read-only, ranks hypotheses, names the proof still needed,
and detects contradictions before proposing a fix. Raw credential values are never
included in the brief sent to a configured model.

## Agent mode & the Workbench

Toggle **Agent** and pick a workspace folder. The agent plans, then reads/searches/edits
files (traversal-guarded, confined to the workspace) and verifies its work; `run_command`
is **off by default**. The **Workbench** opens an IDE-style layer — a **Project** tab
(source cards of what GreyIQ knows about the workspace: purpose, tech stack, run
commands, key files, plus your own notes — one-click **Scan project**, and the agent
gets it on every run), a **Workflow** tab that lays each run out as
**Plan → Change → Verify → Explain**, plus a file tree, a read-only preview with line
numbers + light syntax highlighting, a Changes/diff tab, Agent Steps, and a Verify
panel. **Undo last agent run** rolls the workspace back to its exact state before the
run, and each card in the Changes tab can **Revert** just that one file. Neither will
overwrite a file you have edited since the run — it is reported and left alone, because
an undo that destroys work the agent never touched is worse than no undo.
Drag the divider to resize, or slide it to the top to
**dock** the workbench (chat moves to a 1/3 side panel). A light/dark theme toggle is in
the header.

One-click **task templates** above the composer (Review project, Explain repo, Create
README, Fix failing tests, Find security risks, Package for release, Issue / PR plan)
prefill a vetted prompt and switch on Agent mode when the task needs it.

**Security trust labels.** GreyIQ scans files for prompt-injection and labels them in the
preview (*trusted local file* → *prompt-injection risk*, with the matched signals). When
the agent reads a flagged file, its contents are handed to the model as untrusted **data,
not instructions**, so an embedded "ignore your instructions / exfiltrate secrets" can't
hijack the run — the same thinking as the agent red-team, in the daily UI.

For deployment work, GreyIQ injects deterministic project setup detection into the
agent prompt before the repo map, then applies bundled playbooks for PM2, Ubuntu VPS,
Nginx, env/secrets, and deployment docs. PM2 ecosystem generation prefers localhost
binding, avoids secrets, and updates `DEPLOY.md` when deployment behavior changes.
Verification is stronger for scripts and configs: Python, JSON, JavaScript, PM2
ecosystem files, shell scripts, YAML files, and `.env.example` secret-shaped values are
checked where the local command settings allow it. Command execution remains off by
default. The offline coder can also scaffold a bounded authorized HTTP/C2 traffic simulator
for a local lab; it sends finite attributed requests and treats every response as data, never
as commands to execute.

## BugHunter

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for the full Hunt-cockpit walkthrough —
Program setup (including starting an inactive draft from only a public forge repository link,
or browsing visible programs through HackerOne, YesWeHack, Bugcrowd, and Intigriti APIs,
previewing their scope and rules, or importing a CSV/paste table),
opt-in shallow cloning/adversarial scanning of program-provided public source repositories,
per-program SSRF/OOB setup, running a hunt, and reports & submission. The cockpit also opens
a short guided tour on first launch (reopen anytime via **🧭 Guide me** in the top bar).

- **Scan** from chat: `scan code <path|repo>`, `scan web <url>`, `scan live <url>`.
- **Unauthenticated ATO and RCE, including the blind half.** The active prover confirms command
  injection the target echoes back or delays; with an OOB collaborator configured, a hunt also
  proves the blind kind — a shell-wrapped callback in parameters *and* in the request headers that
  reach a shell without any parameter existing. A hit is only called RCE when a matched control
  carrying the same URL as a bare value stays silent, so an app that merely fetches URLs is
  reported as that instead. On the takeover side the prover forges `alg:none`, RS→HS confusion, a
  cracked weak HMAC secret and a self-signed `jwk` embedded key against the token the site hands an
  ANONYMOUS visitor (no session needed), and the collaborator additionally proves `jku`/`x5u`
  key-source injection — the verifier fetching a signing key the token itself named.
- **Leads** — after a hunt finishes, the **Leads** button in the Hunt cockpit's export row renders
  the whole investigation queue in the app: every lead with its evidence state, the exact artifact
  that would confirm it, the gaps still open, and anything the engine says contradicts it. The same
  panel downloads it as one Markdown brief — that file is what you hand to an analyst (or paste to
  Claude) to work the leads. (A *Download leads (.md)* button also exists in the AI Studio surface;
  the cockpit is where a hunt actually runs, which is why the queue is rendered there.)
- **Investigate leads with Claude**: `gn leads <bounty-*.json | engagement-folder>` exports a
  finished hunt's ranked investigation queue — the cortex's hypotheses, ordered attack chains,
  contradictions, and the exact proof obligation for each lead — as a stable, **redaction-safe**
  `greyiq-lead-queue-v1`. Each lead carries its own evidence state, the contradictions that cite it,
  and the chains it belongs to, inline. `--json` emits the machine queue; `--brief` renders a
  Markdown investigation brief wrapped as untrusted data, ready to hand to a configured Claude brain
  (or to Claude Code) to work lead by lead; `--status` / `--ref` / `--min-confidence` filter it. It
  is assembled from a strict field allowlist and scrubs every field, so no raw credential, response
  body, page source, or screenshot path ever leaves the machine — only the differential and the
  safe sensitive-data labels.
- **OSINT campaigns from the local CLI**: `gn osint example.com` correlates two public
  certificate-transparency indexes with Google and Cloudflare DNS, keeps claim-level source
  provenance, and writes `OSINT.md` + `osint.json`. Add `--hunt --scope "*.example.com" -y`
  to pass only independently DNS-verified public hosts into the normal BugHunter campaign;
  OSINT discovery never grants authorization.
- **Bug-bounty hunt** (training panel): pick a profile (Web app / API / Source-code /
  Secrets / Full sweep) and an optional vuln-class focus (XSS, SQLi, SSRF, IDOR/access
  control, auth, RCE, secrets). GreyIQ runs the right scanner, the brain writes
  reproduction steps + attack plans, and a Markdown report (+ JSON sidecar, optional
  per-finding files) is written to a folder you choose. **Authorized testing only** —
  a hunt won't run unless you confirm the target is in scope.
- Bounty reports now add triage, class mix, submission-readiness checks, and an
  **Investigation intelligence** brief: calibrated confidence, typed evidence state,
  explicit proof gaps, contradiction detection, a ranked hypothesis queue, and
  correlated attack-chain leads. The same graph is available in the JSON sidecar and
  hunt API.
- **Theorizing, not just scanning.** The hypothesis queue is ranked by *expected information
  gain* — how much a test would collapse the unknown, and how many attack chains rest on it —
  so the top lead is the one worth testing next rather than merely the biggest number. GreyIQ
  also derives theories no single finding shows: three routes sharing one weakness on one
  property is reported as a control missing at the framework layer, clearly marked as derived
  and routed to the "worth testing" queue rather than presented as a result. Each lead names
  the chains that confirming it would complete.
- **Acting on it.** Set `GREYIQ_HUNT_REPLAN=1` to let a finished pass chase its own strongest
  unresolved lead: the engine turns each proof obligation into a concrete (endpoint, class)
  probe and runs one bounded extra wave through the same scope- and SSRF-gated prover, capped
  at three endpoints and eight requests. It confirms nothing on its own — the captured-artifact
  gate still decides — and it is off by default because it spends real requests. Reports also include retest guidance and platform-friendly one-file-per-finding
  exports. Reports reshape for
  HackerOne, YesWeHack, Bugcrowd, Intigriti, and **HackenProof** (web3: exchanges, protocols,
  smart contracts) — pick the format in Submissions. HackerOne is the only live-API submit;
  the rest, HackenProof included, are export-only (HackenProof has no researcher API — you
  submit on its dashboard). URL targets can
  opt into the live browser pass, and focus classes also cover CSRF, CORS, open
  redirect, unsafe file upload, business logic, and supply-chain/dependency risk.
- **Negative knowledge** — GreyIQ remembers what it already probed and did **not** confirm. A
  planned `(endpoint, class)` that yields nothing becomes a *miss*; after two misses the pair is
  downranked on the next hunt so the capped probe budget goes to surface that has never been looked
  at, instead of re-testing inert ground. It can never blind a hunt: anything ever confirmed is
  immune forever, misses decay after 45 days, a pair is re-enabled the moment **surface drift**
  reports its endpoint changed, and suppression only reorders (dropping an endpoint only when every
  class on it is cooled). Set `GREYIQ_NO_NEGATIVE_KNOWLEDGE=1` to turn it off. **Campaigns share this
  memory too** — they read cooled pairs, hunt what surface drift says moved first, and write both
  memories back, so the unattended mode stops re-testing ground it has already exhausted. A miss is
  only ever learned from a campaign that finished its fan-out with every per-URL pass running clean,
  and anything the prover confirmed is banked before the report's own filters can hide it.
- **Each target teaches the next.** Within a campaign, a class confirmed on one URL moves to the
  front of the probe order for the URLs not yet hunted on the same registrable domain — so a proven
  IDOR on one object endpoint is a reason to try IDOR on its siblings. A matched CVE advisory does
  the same job earlier: the component fingerprint now runs *before* the active pass and maps each
  advisory's CWE to the class the prover can confirm, so an outdated jQuery aims the prober at
  reflected XSS. Both only reorder; the differential prover still owns every confirmation, and a
  version match never becomes a finding by itself.
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

Every `/api/*` call (except the health check) requires a **per-session token** the
backend mints at startup and injects into the page it serves — so another local
process on `127.0.0.1` can't drive the API (allowlisted cross-origin frontends are
exempt). Request bodies are capped (`GREYIQ_MAX_REQUEST_BYTES`, default 16 MB).
**API keys are kept in a permission-restricted `secrets.json`**, separate from the
main config and migrated out of it on first run, and are never sent back to the UI.
The agent's `run_command` stays **off by default**, and even when enabled a denylist
refuses catastrophic commands (`rm -rf`, disk formats, pipe-to-shell, power control,
privilege escalation, …).

Local code scans can be restricted to one folder with
`GREYIQ_CODE_SCAN_BASE_PATH`. Remote repository scans require public HTTPS repository-root
URLs from the built-in forge allowlist; GreyIQ shallow-clones them into a temporary directory
and removes it after the scan. Web/live scans refuse private/loopback hosts unless
`GREYIQ_SCAN_ALLOW_PRIVATE_URLS=1`.

Fixed third-party egress is narrow and documented. HackerOne import/submission uses
`api.hackerone.com` only on its corresponding operator action. YesWeHack program search,
scope import and sign-in use `api.yeswehack.com` the same way — read-only apart from the
sign-in exchange, on an explicit click only, host-pinned, and with redirects refused so a
credential can never follow a hop off that host. Bugcrowd and Intigriti program intake
uses `api.bugcrowd.com` and `api.intigriti.com`, respectively, for explicit read-only
program discovery and previews. Imported programs are saved paused until you review
the current policy and authorize testing. The optional **Enrich from
forge (read-only)** action uses one unauthenticated GET per selected repository to
`api.github.com` (GitHub) or `gitlab.com` (GitLab); it has a hard timeout, never runs in the
background, and only returns homepage/web domains as **unticked** scope suggestions. Enrichment
never authorizes or probes those hosts. Other supported forges are not queried for metadata.

## How Training Works

Each bot owns browser-side preference weights for instant fallback behavior. When the GreyIQ backend is running, preferences, rated examples, and source-specific training data are also written into the local runtime training data. The trainer can run against one or more selected sources, and the AI core store tracks the active bot as a local core. Data stays on the machine unless you explicitly move it.

## AI Cores

GreyIQ starts with companion, builder, researcher, and BugHunter cores. Each core carries a response contract, confidence policy, trust posture, and starter knowledge profile so first-run answers feel useful before personal training begins. Personal choices and imported documents become higher-priority local sources as the user trains the app.
