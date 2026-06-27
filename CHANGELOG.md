# Changelog

Notable changes to GreyIQ.

## v0.11.1

_(Re-tag of the v0.11.0 work — the v0.11.0 release tag was consumed by GitHub's
immutable-releases feature and could not carry the binaries; no code difference.)_

### Added
- **Active verification — prove findings, don't just flag them.** A new opt-in layer
  turns provable leads into *confirmed* findings with a captured request/response. For
  a URL target, ticking **Active verification** fires at most one benign
  GET/HEAD/OPTIONS per check to prove: reflected XSS (unescaped, HTML-context, with a
  no-marker control), CORS Origin reflection with credentials, open redirect
  (off-origin `Location` captured, never followed), host-header reflection, error-based
  SQL injection (a single quote eliciting a real **SQL** error banner), and clickjacking
  framability (a candidate with a PoC obligation). Each confirmed check writes a
  `status: confirmed` proof — backed by a same-run **negative control** — into the
  proof-of-impact slot, so the report renders "Confirmed" with the artifact in hand.
  Safety: strictly double-gated (active + authorized + URL), **scope-bound and
  fail-closed** (a host you didn't name in Scope is never probed — exact/suffix host
  matching, not substring), reuses the passive scanner's SSRF/private-host/port guard
  on every request, never follows redirects off-host, GET/HEAD/OPTIONS-only with benign
  markers, a per-host token-bucket plus a per-hunt request budget, and every artifact
  redacted. Default OFF. New `active_verify_service.py` + `rate_limit.py`; env knobs
  `GREYIQ_ACTIVE_MAX_REQUESTS_PER_HOST`, `GREYIQ_ACTIVE_MIN_INTERVAL_MS`,
  `GREYIQ_ACTIVE_SCAN_ALLOWLIST`.

## v0.10.0

### Added
- **Proof of impact, built in.** Every bug-bounty finding now ships a real impact
  model — attacker capability → affected asset → business impact — plus a
  **finding-specific proof obligation** (the exact artifact to capture to *prove* the
  impact for a submission) and an estimated **CVSS v3.1 vector with a computed base
  score** (the calculator is verified against NVD reference scores). This is
  deterministic and works fully offline; the LLM brain enriches it rather than being
  the only source — previously the proof-of-impact renderer sat empty on every offline
  run. New `impact_model.py`; `cvss` / `proof_obligation` fields in the report Markdown
  and JSON.
- **Captured passive proof for web findings.** Header/cookie/version/mixed-content/
  error findings now carry the exact request line, response status, and offending
  header/Set-Cookie value as redacted `proof_evidence`, so the report shows what
  produced each finding.
- BugHunter proof-of-impact report sections and readiness checks so impact claims
  require concrete evidence (confirmed/candidate/missing, with method, actor, observed
  result, control result, affected asset, and limitations).

### Fixed (whole-app QA/QC audit)
- **Stronger honesty on proof status.** A finding is marked "confirmed" only with a
  real captured artifact (authenticated replay, live secret, or a response carrying an
  HTTP status) — concrete-sounding LLM prose alone, or passive web evidence ("a GET
  returned 200"), can no longer flip an unproven lead to submission-ready.
- **Secret-leak redaction holes closed:** a truncated PEM private key (END marker
  clipped) and credentials on a whitespace-collapsed `.env`-style line are now
  redacted; live-scan runtime evidence is redacted before it reaches the report.
- BugHunter JWT exposure triage suppresses OAuth flow-token false positives, gates
  session-impact reporting on replay confirmation, and uses CWE-200; web-scan secret
  evidence is redacted before report generation.
- **SSRF hardening:** the agent's `net_probe` refuses cloud-metadata / link-local
  targets (including via HTTP redirect) while still allowing legitimate loopback/
  private ops diagnostics.
- **Agent engine:** the destructive-command denylist now catches `rm -r -f` with split
  flags; ranged file reads are memory-bounded yet can still page through a large file;
  `grep`/`find_code` output goes through the untrusted-data boundary; rollback removes
  directories the run created.
- **Reliability:** atomic writes for the secrets store, runtime config, and project
  memory (no torn files, no world-readable window); the API no longer reflects raw
  exception text on a 500; Electron shows the error page instead of a stuck spinner on a
  boot failure and reaps the backend/Ollama process tree on quit; assorted
  scanner-accuracy and unbounded-growth fixes (yaml.load detection, minified-file skip,
  repo-map walk, BPE cache, live-capture caps).

## v0.9.9

### Fixed
- **Empty "Bounty type" dropdown when the backend is late.** The Security panel's
  selectors (bounty type, focus class, toolkit) were populated once at boot and gated
  on the local API being reachable at that instant — so if the API lagged the UI (the
  packaged build unpacking on first launch, or the PM2/phone split where the Node UI
  serves before the Python API), the dropdowns stayed blank with no retry. They now
  (re)load whenever the Security panel is shown and the moment the service becomes
  reachable, via an idempotent `ensureSecurityData()`.

## v0.9.8

### Added
- **Guided next steps for the bounty hunt.** Every hunt now ends with an ordered,
  prioritized operator action plan — "what do I do now?" answered as numbered steps
  grouped into phases (*stabilize coverage → confirm findings → hunt by hand → chain &
  escalate → expand coverage → prepare submission → retest*). Each confirmation step is
  emitted highest-impact first (severity, confidence, **and intrinsic class value**
  weighted), names the opening reproduction move, and points at the single best tool
  from the curated toolkit. The plan is deterministic (works fully offline) and, when a
  brain is configured, folds in target-specific analyst leads. It renders as a clean,
  color-coded checklist in the UI (the full Markdown report is one click away) and ships
  in the report's Markdown and JSON, plus a new `next_steps` field on the scan response.
- **10 modern high-bounty vuln classes.** The focus taxonomy nearly doubles with
  server-side template injection (SSTI), XXE, NoSQL injection, JWT forgery/weakness,
  GraphQL abuse, prototype pollution, race conditions / TOCTOU, HTTP request smuggling,
  subdomain takeover, and exposed cloud storage/metadata — each with CWE/OWASP mapping,
  a sharp 3-step hunt checklist, curated tool recommendations, and chain leads (e.g.
  *SSRF + cloud-exposure → metadata credentials*). They flow into the web-app, API, and
  source-code profiles and the full sweep.
- **Coverage & gaps summary.** The report and UI now state what the pass actually
  covered and — more importantly — what it structurally could not (no dynamic pass, no
  authenticated testing, git history unscanned, partial on scanner error), so the
  operator knows where the blind spots are before trusting a low finding count.

### Changed
- **Runs without PyTorch — bug-hunting goes anywhere.** The local TinyGPT brain is the
  only component that needs PyTorch; its import is now lazily guarded, so the backend
  boots even where torch is absent or won't load (e.g. an ARM phone running the API
  under PM2/Termux). The bug-hunting engine and the Claude API brain are entirely
  torch-free and stay fully functional; local-model train/infer is cleanly gated off
  with a clear message, and `status` reports `local_model_available`.
- **Honest agent completion status.** A run now reports an explicit `completed` /
  `verified` / `outstanding` triple instead of implying success by default: it only
  claims "done" when the model finished on its own *and* its changed files verified
  clean. Hitting the step limit runs a final verify, names exactly what is still
  outstanding (unverified files, remaining work), and tells you a re-run will continue
  from the current state. The Workbench surfaces a ✓/⚠ completion line accordingly.

## v0.9.7

### Added
- **Task templates.** A row of one-click starter workflows sits above the composer —
  *Review project, Explain repo, Create README, Fix failing tests, Find security
  risks, Package for release,* and *Issue / PR plan*. Each one prefills the composer
  (you review and send it) and enables Agent mode where the task needs to read or edit
  files; *Find security risks* runs BugHunter's code scanner on your workspace.
- **Project memory & source cards.** A new **Project** tab (the Workbench's default
  view) shows what GreyIQ knows about the current workspace as source cards — purpose,
  tech stack, run commands, and key files, derived by a one-click **Scan project**
  (stack/run/files are detected offline; the one-line purpose uses your brain) — plus
  your own preferences, constraints, and open tasks. The agent is handed this memory at
  the start of every run, and it persists per workspace.
- **Guided "Plan → Change → Verify → Explain" workflow.** A new first tab in the
  Workbench presents every agent run as four ordered stages: the up-front plan the
  agent is told to follow, the files it changed, the verification result (pass/fail),
  and a plain-language summary — with quick links into the Changes and Verify tabs.
- **One-click rollback.** Each agent run snapshots the pre-edit state of every file it
  touches; **Undo last agent run** restores them exactly and removes files the run
  created. The snapshot is kept per workspace and survives an app restart.
- **Security trust labels.** Files are scanned for prompt-injection: the Workbench
  preview shows a per-file trust label ("trusted local file" → "prompt-injection risk"
  with the matched signals), and when the agent reads a risky file its contents are
  handed to the model inside an explicit untrusted-DATA boundary — so an embedded
  "ignore your instructions / use write_file / exfiltrate secrets" is treated as data to
  report, not a command to follow. An agent run shows a Trust-check note for any flagged
  reads, and the agent bar shows whether shell commands require approval. This brings the
  agent red-team's injection thinking into the daily UI.

### Changed
- `scan` / `bughunt` chat commands now always run the BugHunter scanner, even when
  Agent mode is on (previously they were routed to the agent).

## v0.9.6

### Changed
- **Dark mode is now the default.** New installs and the browser fallback open in
  dark. An explicit theme choice (via the header toggle) is remembered and always
  wins; users who never picked — including those with a stale light preference from
  the old default — now open in dark.

## v0.9.5

### Added
- **Delete personalities and local models.** A "Delete this bot" button in the bot
  editor removes a personality along with its chat history, learned memory, and
  backend AI core (always keeping at least one). The Coding brain panel now lists
  installed Ollama models with a **Remove** button to free their disk space.

## v0.9.4

### Added
- **Out-of-the-box GPU acceleration for the local model (Ollama).** NVIDIA (CUDA)
  is bundled and used automatically. AMD (ROCm) is auto-provisioned on first run:
  when an AMD GPU is detected, GreyIQ downloads Ollama's ROCm runtime (~1 GB,
  one-time) and overlays it on a writable copy of the bundled runtime. Any failure
  falls back to the bundled runtime, so GPU setup can never break the app.
- A **"Local model GPU: …"** status line in the Coding brain panel (desktop) showing
  the detected GPU vendor and the active runtime (CUDA/ROCm), or CPU.

### Fixed
- Restored the bundled **CUDA** runner on Linux. A prior release pruned it to fit
  GitHub's 2 GiB asset cap, which disabled NVIDIA acceleration; the CPU-only torch
  wheel already keeps assets small, so the prune was unnecessary.

### Docs
- Clarified GPU support in the README and the package description.

## v0.9.3

### Added
- **Pentest & OSINT Toolkit** — a curated, queryable catalog of 172 tools across 10
  categories (from [awesome-pentest](https://github.com/enaqx/awesome-pentest),
  CC-BY 4.0, and [awesome-osint](https://github.com/jivoi/awesome-osint), MIT),
  mapped to BugHunter's vuln classes, surfaced in a browsable panel, in BugHunter
  "Recommended tooling", and via an agent skill.

### Fixed (release CI, Linux)
- Ollama's Linux asset moved to `.tar.zst`; download/extract updated (was a 404).
- Free ~30 GB on the runner before the build (was "No space left on device").
- CPU-only torch + slimmer bundle so release assets stay under GitHub's 2 GiB
  per-asset limit.

## v0.9.2
- Workbench: collapsible, readable file tree.

## v0.9.1
- QA/QC: fixed BugHunter vuln-class mapping and assorted cleanups.

## v0.9.0
- Agent security red-team; Workbench slide-to-dock; GreyNOC-IQ rename.
