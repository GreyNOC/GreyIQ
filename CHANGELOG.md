# Changelog

Notable changes to GreyIQ.

## v0.27.0

### Find more — discovered parameters now feed the active prover
The active verification checks (reflected XSS, SSTI, error/boolean/time-based SQL
injection, open redirect, CRLF) used to inject only into parameters that were already
present in a URL's query string. Recon mined parameter names from the target's own
JavaScript — but the campaign discarded them, so an endpoint discovered without a query
string (for example `/search` with no `?q=`) was never probed for the parameters it
actually takes.

Now the parameter names recon discovers are threaded into every parameter-keyed active
check. Coverage is strictly wider with **no extra requests on already-parametered URLs**:
the URL's own parameters are tried first and the discovered names only fill the slots a
URL leaves empty (capped per check), so a param-less endpoint that previously tested
nothing now probes its real parameters. The SQL-injection checks still refuse to invent
an injection point — they act only on a parameter the URL carries or that recon actually
found.

Recon also mines more parameter sources: HTML form fields (`input`/`select`/`textarea`/
`button` names) on every crawled page, plus the query-string parameter names of every
discovered URL (so a parameter seen on one endpoint is tried against a param-less
sibling). The safety envelope is unchanged — GET-only, scope-bound and fail-closed,
marker-plus-negative-control confirmation, and a per-host/per-hunt request budget; every
discovered name is validated and capped before it is ever used as a probe key.

## v0.23.0

### Much smaller download + faster first launch — Ollama is now on-demand
Ollama (the local-model runtime) was **~1.4 GB — about 86% of the portable** — and
the bug-hunting engine and the Claude/OpenAI brains never use it. It is **no longer
bundled**: the portable/installer drop to roughly **~250 MB**, and the first-launch
unpack shrinks accordingly (on top of the v0.15.0 boot-time fix).

Ollama is now **downloaded on demand** to a writable `userData` dir the first time the
operator actually selects the **local** model in the Brain settings — reusing the same
proven download/extract path the AMD/ROCm runtime already used. The renderer triggers
it via a new `greyiq:ensure-ollama` IPC; nothing downloads at boot, and a system-
installed Ollama (already serving on the port) is used directly. NVIDIA GPUs still work
on the downloaded base runner; AMD/ROCm is still fetched on first run. Removed the now-
redundant Ollama bundling step from the Windows + Linux release CI (also relieving the
Linux runner's disk pressure).

## v0.22.0

### Headless operator — run the loop with no GUI (`gn operator`)
The autonomous operator is now drivable from the terminal, so it can run on a server,
a VPS, or a phone:
- `gn operator add --name acme --scope "*.acme.com" --targets https://acme.com [--active] [--auto-submit --handle <team>]`
- `gn operator list` / `remove <id>` / `pipeline` (the money funnel)
- `gn operator run -y [--once] [--allow-submit]` — runs the unattended loop (continuous
  with a live event stream + Ctrl-C kill switch, or `--once` for a single pass).

It builds the loop's callables directly over the torch-free engine, so the submit path
goes through the **same** hard-gated `submit_to_hackerone` (confirm + server-recomputed
`proof_status=='confirmed'` + the creds the desktop app stored). `run` requires an
explicit `-y/--authorize`; auto-submission stays off unless `--allow-submit` is passed
**and** the program opted in **and** has a HackerOne handle.

## v0.21.0

### Surface expansion — find far more, still in scope
Recon now mines the real attack surface, not just the landing page:
- **Served-JS mining** (`recon_js.py`) — pulls in-scope API **endpoints**, query-param
  **names**, same-apex **hosts**, and (already-**redacted**) leaked **secrets** out of
  bundled JavaScript. Discovered endpoints become hunt targets (so the active prover's
  XSS/SQLi/redirect/CRLF checks get real parameters to bite on), and JS secrets are
  folded into the campaign findings.
- **In-scope cross-host discovery** — recon now follows hosts the program scope allows
  (a wildcard like `*.acme.com`), gated by the **same fail-closed
  `host_in_active_scope`** the active prover uses. Every new host is checked **before**
  it's fetched; out-of-scope hosts are counted, never fetched.
- **Tech fingerprinting** (`fingerprint.py`) — names the stack from already-fetched
  headers/cookies/body and emits advisory hints (e.g. Django → emphasize SSTI/SQLi).
  Advisory only: it reorders which already-gated checks run, never enables one.

### Safety
A new **global per-campaign request budget** (default 40) bounds total fetches — the
kill switch for host fan-out under a wildcard scope, on top of the per-host governor.
Served-JS mining is bounded (≤8 bundles), secrets are redacted inside `recon_js`
before they leave it, and the SSRF/private-host/port guard runs on every fetch. No new
deps; pure stdlib.

## v0.20.0

### Report polish — land more reports
- **Clickable CWE / OWASP references.** Every `CWE-<n>` becomes a link to its MITRE
  page (compound `CWE-639 / CWE-284` handled) and each `Axx:2021` OWASP token links to
  its Top-10 category page, in both the per-finding report and the main report.
- **Bugcrowd VRT alongside the HackerOne rating.** Each finding carries an estimated
  Bugcrowd VRT category (`impact_model.bugcrowd_vrt`), rendered in the report header
  and included in the submission package — so a report speaks both platforms' language.
- **Evidence-completeness score.** The submission-readiness checklist and a new
  machine-readable `completeness` map ({score, max, missing}) now share one predicate
  list (they can't drift), with two added evidence-grade checks (a captured request/PoC
  artifact, a negative control). It's **advisory only** — never a submit precondition;
  the submit gate stays confirm + confirmed proof + creds.

## v0.19.0

### The autonomous operator — run the whole bounty loop unattended
Point GreyIQ at a **portfolio of programs** and it runs the money loop on a schedule
without hand-holding: recon → hunt → prove → consolidate → **dedup across runs** →
rank by expected value → submission packages → (only when explicitly armed) **file
confirmed findings**, then reschedule and move on. A new **Operator** tab in the
cockpit is the control panel: program management, a live activity log, the kill
switch, and a money pipeline funnel (discovered → confirmed → reported → submitted →
paid, with $ per program).

New modules, all pure/frozen-safe (stdlib + the existing stores):
- **`portfolio.py`** — the program list (`RUNTIME_DIR/portfolio.json`): scope, seed
  targets, cadence, and **fail-closed** automation flags (active/live/auto_submit all
  default OFF; an empty scope or missing HackerOne handle forces auto-submit off).
- **`ledger.py`** — a persistent finding ledger keyed by a stable dedup key
  (`class|rule|digit-normalized-location`). It powers **cross-run dedup** (a re-run
  never re-reports — or re-files — a finding it already reported) and the pipeline
  funnel. `stage='confirmed'` is set *only* when the server-truth `proof_status` is
  confirmed, so the funnel can't inflate the submit-eligible pool.
- **`ranking.py`** — expected-value ordering (`severity × learned prior × confirmed
  weight × program-pay factor`, every factor bounded), with **confirmed as the
  outermost sort key** so a confirmed finding never sinks below a lead.
- **`operator.py`** — the unattended loop: a background supervisor that runs due,
  enabled programs sequentially, a stop-event **kill switch** checked between every
  program and before every submit, and the run-cycle that hunts each target and
  (when armed) auto-files.

Campaign consolidation now ranks by EV and records every finding in the ledger,
skipping a submission package for anything already reported in a prior run.

### Safety (unattended automation, done right)
Auto-submission is **quadruple-gated** and optimizes for high signal, never volume:
the loop must be started with **arm auto-submit** *and* the program must opt in *and*
the finding must be server-recomputed **confirmed** *and* not already
reported/submitted (ledger dedup) *and* within the program's daily cap. The operator
adds **zero new network/scanning code** — it calls the same `run_campaign` (recon
stays same-origin, active probing stays scope-bound and fail-closed) and the same
**unbypassable** `submit_to_hackerone` gate (confirm + server-recomputed
`proof_status=='confirmed'` + real creds). Starting it requires an explicit
authorization confirmation.

New API: `GET/POST /api/operator/programs`, `/programs/delete`, `/start` (authorized +
arm), `/stop` (kill switch), `/events`, `GET /api/operator/pipeline`. +13 tests
covering the dedup, throttle, fail-closed scope, and "review-only never submits"
invariants.

## v0.18.0

### Prove more — three new GET-only active confirmations (more submittable findings)
More leads become **Confirmed** (the bar for filing), all inside the existing
double-gated, scope-bound, negative-control, budgeted active envelope:
- **Boolean-based blind SQLi** — an `AND '1'='1'` vs `AND '1'='2'` differential that
  reads **one boolean bit** and extracts no data. Confirms only when two unmodified
  baselines are near-identical (the page is stable enough to differentiate — its own
  negative control) AND the TRUE branch tracks the baseline while the FALSE branch
  diverges materially; a flapping/dynamic page or an ignored parameter degrades to
  no-finding rather than over-claiming. No timing, no `SLEEP`, no `UNION`.
- **CRLF / response-header injection** — injects an encoded CRLF + a benign custom
  header marker into a parameter and confirms only when the server **splits it into a
  real response header** equal to the marker AND a control without the CRLF does not.
- **Two more CORS confirmations** — `Origin: null` trusted with credentials, and an
  arbitrary **subdomain** Origin reflected with credentials — each gated by a distinct
  negative control so the reflection is proven attacker-driven.

All GET-only with benign markers; every "confirmed" is backed by a same-run control.

## v0.17.0

### Find more — five declared-but-empty vuln classes now detect
Static sink rule packs take five bounty classes that previously found *nothing*
(only a manual checklist) to real findings, each classified accurately with CWE/OWASP:
- **Open redirect** (`open_redirect` → `redirect`): Flask/Django/Express redirect to a
  request value, and DOM-based `location` from a URL param.
- **SSTI source** (`ssti`): Jinja2 `render_template_string` built from input,
  `Template(var)`, Handlebars/EJS/Pug compiled from a variable — complements the
  active `{{7*7}}` confirmation.
- **XXE** (`xxe`): lxml/stdlib/PHP/Java XML parsers without entity/DTD hardening
  (suppressed when a hardened-parser token is on the line).
- **Weak JWT** (`jwt`): `alg:none`, signature verification disabled, short hardcoded
  HMAC secret.
- **Insecure deserialization** (`deserialization` → `rce`): PHP `unserialize($_GET)`,
  Ruby `Marshal.load`, Java `ObjectInputStream.readObject` (Python pickle/yaml/marshal
  were already covered by the eval/exec pack).

All sink-only, HIGH severity with honest LOW/MEDIUM confidence, pure-regex and
frozen-safe; safe forms (parameterized, hardened-parser, constant target) don't match.

### Report — every finding is submission-grade
- **Remediation + references floor.** Every vuln class now carries a concrete,
  verifiable fix sentence and 2–3 authoritative links (OWASP cheat sheet + CWE +
  PortSwigger). A fully offline run now renders a **Remediation** and a **References**
  section on every finding (previously present only on some scanner rules / when the
  brain was configured), and the submission-readiness "concrete fix" checkbox now
  passes. New `impact_model.remediation_for_class` / `references_for_class`.

New tests: the five sink packs (positive + negative-control per pack, no rule_id
collisions, accurate classification) and the remediation/references coverage +
offline-report rendering.

## v0.16.0

### After-testing workflow — submit a report straight from the app
The cockpit's Submissions tab is now a real worklist: after a run you can get the
**canonical** server-built report per finding, export it, and file a confirmed
finding to HackerOne — without leaving the app.

- **Canonical packages, not client drafts.** A new `POST /api/bounty/submission`
  rebuilds the exact `build_finding_markdown`/`build_submission` package the CLI and
  campaign use (title, severity rating, CWE, CVSS, steps, proof, remediation), keyed
  by a `run_id` the scan/campaign response now returns (bounded in-memory run cache —
  no re-scan). The detail drawer and Submissions queue **Copy report** / **Download
  .md** now use this canonical output, falling back to the offline draft only if the
  run was evicted.
- **File to HackerOne, hard-gated.** A new `POST /api/bounty/submit` calls the
  existing `submit_to_hackerone`, which **refuses unless** an explicit confirm, a
  **server-recomputed `proof_status == "confirmed"`**, and real credentials are all
  present — a forged client request can't push a non-confirmed finding. The cockpit's
  **Submit to HackerOne** button is disabled until a finding is Confirmed *and* creds
  are configured (a UI mirror of the gate, never a replacement), and asks for an
  explicit confirmation naming the team + finding before it fires.
- **Credentials in the perms-restricted secrets store.** `GET/POST
  /api/bounty/hackerone/creds` store the team handle + API username/token alongside
  the provider keys (atomic, private file); the status endpoint returns only
  `has_token` — the token is **never echoed** back to the browser.
- A successful submit records the outcome to the learning store (`status: submitted`)
  and marks the finding submitted in the queue, closing the run → submit → learn loop.

New tests: canonical package build, the server-authoritative submit gate (refuses
non-confirmed even with creds + confirm), creds round-trip (token never leaked), and
the bounded run cache.

## v0.15.0

### Much faster startup — the portable opens in a fraction of the time
Profiling the double-click → window path found two avoidable costs, both fixed:

- **PyTorch dropped from the packaged binary (~1.2 GB → gone).** Torch was 86% of the
  1.4 GB payload and the bug-hunting engine never uses it — it only powered the
  offline TinyGPT chat brain and the Train tab (both now in the demoted Studio). The
  portable download and the **one-time first-launch unpack shrink ~6×** (the old
  fresh-run unpack was measured at ~200 s). The Ollama/Claude coding brain and every
  bug-bounty feature are unaffected; the offline local model degrades to a clear
  "local model unavailable" message in the packaged app (still available from source,
  and re-bundlable via the build spec).
- **Torch + pandas are no longer imported at boot.** The backend imported the
  torch-backed local-model runtime (`solin_core`, ~3.9 s) and document ingestion
  (`pytesseract`→`pandas`, ~1.4 s) at module load, before it could answer
  `/api/health` — the gate the desktop window blocks on. Both are now imported
  **lazily on first actual use**, cutting the API's import time from **~6.0 s to
  ~0.65 s on every launch**. `/api/status` still reports local-model availability via
  a cheap `find_spec` probe (no torch import).

New regression tests pin both invariants (no torch/pandas on the boot path; the
service boots and degrades gracefully when torch is absent — the frozen condition).

## v0.14.0

### Bug-bounty cockpit — the app is now bug-bounty-first
GreyIQ opens into a dedicated **Hunt cockpit** instead of the AI-studio chat. The
studio (chat, coding brain, training, Workbench) is preserved behind a single
**Studio ↗** toggle (a **◀ Hunt** button returns) — nothing was removed, the
default surface just changed.

The cockpit is a full bug-bounty workflow built directly on the engine:
- **Launch rail** — one form for a **Single hunt** or a **Full campaign**: target,
  scope/program, profile + focus class (hunt) or program handle + recon depth
  (campaign), and prominent safety switches (**Test for proof of impact**, dynamic
  Playwright pass, and a required **authorized** toggle). Authorization and active
  scoping stay enforced server-side, fail-closed.
- **Findings board** — the center stage: a sortable, filterable table (severity ·
  class/CWE · **proof-status pill** confirmed/candidate/missing · finding · location
  · CVSS), with a run-summary strip (risk, severity counts, an active-verification
  armed/disarmed chip) and filter chips (All / Confirmed / by severity).
- **Finding detail drawer** — click any finding for the full proof pane: numbered
  reproduction steps, the captured proof-of-impact (observed / control / evidence),
  the **“To confirm” obligation** for unproven leads, CVSS vector, impact,
  remediation, and a one-click **Copy submission draft**.
- **Surface** — the recon map for a campaign (discovered URLs + robots/sitemap/
  security.txt sources). **Submissions** — a confirmed-first draft queue.
  **Learn** — the per-program stats dashboard with an inline *record-outcome* form,
  so the learning loop closes without dropping to the CLI.

Every dynamic node is built DOM-only (`createElement`/`textContent`, never
`innerHTML`) so scanner- and brain-derived finding text can't inject markup.

### API
- `run_campaign` now also returns a compact structured payload (campaign-global
  finding refs + proof/CVSS maps + a `surface` block + severity counts + risk) so
  the cockpit renders one board for campaigns exactly like single hunts.

## v0.13.0

A whole-engine QA/QC pass (multi-agent audit of the find → prove → report
pipeline, every recommendation adversarially verified against the code) plus the
API surface the upcoming bug-bounty cockpit needs.

### Find — close real blind spots
- **Static SQL-injection sink pack.** A new `sqli` rule pack flags queries built by
  string-formatting (f-string / `%` / `+` / `.format` / template literal) handed to
  a DB `execute`/`query` across Python, Node, Go, Django, and PHP — HIGH severity,
  MEDIUM confidence. Parameterized calls and constant SQL do not match. The `sqli`
  bounty class now maps to real findings instead of an empty manual checklist.
- **Static SSRF sink pack.** A new `ssrf` rule pack flags server-side fetches of a
  non-literal URL (`requests`/`httpx`/`urlopen`, `axios`/`fetch`, Go `http.Get`,
  PHP) — HIGH severity, LOW confidence (the first argument is often a benign
  constant, so these are honest leads, not confirmed bugs). The `ssrf` class now
  produces findings.
- **Sensitive-path probe.** A hunt's web scan now probes a short, **constant**
  wordlist of well-known exposed paths (`/.git/config`, `/.git/HEAD`, `/.env`,
  `/.svn/entries`, `/server-status`, `/actuator/health`, swagger/openapi,
  `/.DS_Store`) and **content-validates** every hit — an SPA that returns its 200
  HTML shell for unknown paths is never flagged. Same-origin, GET-only through the
  existing SSRF/redirect guard, governor-throttled, redacted evidence, and **off by
  default** for the bare passive `/api/scan/web` (a quick scan stays a single GET).

### Prove — one more confirmation, fuller artifacts
- **Active SSTI check.** A new opt-in active check confirms server-side template
  injection with a benign `{{7*7}}` → `49` differential against a literal-string
  negative control (a coincidental "49" can't confirm — the marker must be evaluated
  adjacent to it). GET-only, inside the existing double-gated, scope-bound,
  budgeted active envelope.
- **Captured request header + raw HTTP repro block.** Active proofs now render the
  crafted `Origin:`/`Host:` request header (previously captured but silently
  dropped) and a copy-pasteable fenced `http` request→response block reconstructed
  purely from the already-redacted captured fields — the single most convincing
  artifact for a triager.

### Report
- **curl reproduction step.** The deterministic attack plan for a passive web
  finding now leads with a benign `curl -sSiL <url> | head -n 40` (shell-escaped) so
  an offline report still hands the operator a one-line repro. Source-code findings
  are unchanged.

### API — make the engine reachable from the browser
- **Structured findings on `/api/bounty/scan`.** The scan response now includes the
  per-finding `findings`, `attack_plans`, `proof_of_impact`, `cvss`, `class_counts`,
  and submission/retest checklists it already computed (and previously threw away),
  so a GUI can render a findings board + proof pane without re-parsing the markdown.
  Additive; redacted/scope-filtered exactly like the on-disk sidecar.
- **`POST /api/bounty/campaign`, `POST /api/bounty/learn`, `GET /api/bounty/stats`** —
  the end-to-end campaign and the learning loop are now reachable over the API
  (previously CLI-only), authorization still fails closed server-side.

### Fixed
- **Learning priors no longer self-corrupt on re-scan.** `learned_priors` now drives
  the reward-rate denominator off *adjudicated* outcomes (rewarded + duplicate/N-A)
  only — a weekly campaign auto-logging the same confirmed finding as "submitted" no
  longer dilutes an earned prior back toward neutral.

## v0.12.0

### Added
- **`gn campaign` — run the whole bounty end-to-end.** One command takes a target
  through the full bounty: **recon** maps the surface (a bounded, same-origin,
  depth/page-capped crawl plus passive recon of `robots.txt`, `sitemap.xml`, and
  `/.well-known/security.txt`), then the engine **hunts every discovered URL**
  (scan + optional `--active` proof of impact), **consolidates and ranks** the
  findings (deduped across the surface; ranked by severity × learned program priors
  × CVSS × confirmed-proof), and emits a **`CAMPAIGN.md` index plus a
  submission-ready package per reportable finding** under `submissions/`. Gated on
  `-y/--authorize`; `--active` captures proof, `--live` adds the dynamic Playwright
  pass, `--max-pages` caps discovery. Works on both URL targets (recon-crawled) and
  local repo/folder targets (single source-code hunt). Recon reuses the passive
  scanner's SSRF/private-host/port guard on **every** fetch (input URL, each redirect
  hop, and the final URL), is GET-only, same-origin-only, and rate-limited by the
  shared per-host governor.
- **Learn from the bounty.** A local, deterministic feedback loop: `gn learn -c
  <class> --status <accepted|resolved|duplicate|informative|not-applicable|triaged|
  submitted|spam> [--bounty N] [--program H | --target URL]` records a finding's
  outcome, and `gn stats [--program H | --target URL]` shows what the engine has
  learned per program. Outcomes build a per-program, per-class memory that sharpens
  the **next** campaign — classes a program has paid out for get a priority boost,
  classes that are consistently duplicate/N-A get a penalty — and the campaign report
  surfaces this "program intelligence" so the operator focuses where the program
  actually rewards. Pure JSON store under the runtime dir; no network, no ML.
- **Submission packaging.** Every reportable finding is exported as a HackerOne-shaped
  package (title, severity rating, CWE, impact, and the self-contained
  `vulnerability_information` body). Pushing to the HackerOne API is a separate,
  **hard-gated** action — it refuses unless given an explicit confirmation, a
  **confirmed** proof status, and real credentials, and is the only path that touches
  the network.

### Fixed
- **Windows long-path safety (`MAX_PATH`).** A deep install dir plus the campaign's
  nested `campaign-…/targets/` layout could push a report path past Windows' 260-char
  limit, surfacing as a misleading "file not found" on write (and a silently empty
  read). All report/submission/campaign reads and writes now route through a
  long-path-safe helper that transparently retries over the `\\?\` extended-length
  prefix on Windows. New `bughunter/fsutil.py`.
- The `gn` CLI now forces UTF-8 (with graceful fallback) on stdout/stderr so help text
  and output never crash on a `cp1252` Windows console.

## v0.11.1

_(The v0.11.0 release tag was consumed by GitHub's immutable-releases feature and
could not carry the binaries, so this re-tag also folds in the `gn` CLI.)_

### Added
- **`gn` — a short bug-bounty CLI.** Drive the same engine from the terminal:
  `gn hunt <url|repo> -y [-p profile] [-c class] [-s "scope"] [--active] [--live]`,
  plus `gn scan`, `gn profiles`, `gn classes`, and `gn tools <class…>`. A hunt is
  gated on `-y/--authorize`; `--active` runs the proof-of-impact testing. Torch-free
  and frozen-safe — the shipped backend binary doubles as the CLI
  (`greyiq-backend hunt …`), and `gn`/`gn.cmd` wrap it for source checkouts
  (`npm run gn -- …`).
- The Security tab's active option is now labelled **"Test for proof of impact"** to
  make the capture-the-proof workflow discoverable.
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
