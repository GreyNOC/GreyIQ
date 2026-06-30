# Changelog

Notable changes to GreyIQ.

## v0.43.0

### Phase C — NoSQL injection (error-based, confirm-grade)
A new active check that finds NoSQL injection, added to the active suite (so it runs in every
active hunt/campaign):

- Sends a parameter as a NoSQL **operator object** (`param` → `{$ne: ...}`); a NoSQL backend
  error banner that appears **only** for the operator (not the scalar control) confirms the
  injection point — e.g. Mongoose casting `{$ne:...}` to a typed field (CastError). High
  precision, mirroring the trusted SQL-error check.
- Only **unambiguous** Mongo / Mongoose / BSON / PyMongo / Couchbase banners count; a generic
  stack trace never confirms, and a page that always shows the banner fails the negative
  control. Maps to the existing NoSQLi class (CWE-943, A03:2021 Injection).

399 tests green (+4).

## v0.42.0

### Phase C — BFLA (broken function-level authorization)
Confirms a privilege-escalation class with the same proven dual-session machinery as IDOR,
GET-only:

- A **three-session differential** (admin / low-privilege user / anonymous): confirms only
  when the low-privilege user's response ~matches the **admin** response **and** an anonymous
  request is denied/different — so the endpoint is genuinely access-controlled, not a public
  page. Otherwise reported honestly as `enforced` or a `candidate`.
- The privileged body is **never embedded** — the proof is the differential only (statuses +
  similarity ratios), exactly like IDOR.
- Wired everywhere: `POST /api/bounty/bfla`, `gn bfla <url> -y` (high-/low-priv sessions), and
  a BFLA panel in the cockpit access-control view. A confirmed bypass caches as a run.

395 tests green (+7).

## v0.41.0

### Phase C — API surface discovery (OpenAPI/Swagger + GraphQL)
Recon now maps the machine-readable API surface, multiplying what every active check reaches:

- Fetches the common **OpenAPI/Swagger** spec locations (`/openapi.json`, `/swagger.json`,
  `/v3/api-docs`, …), parses OpenAPI 3.x **and** Swagger 2.0, and feeds the concrete GET
  endpoints + declared parameter names into the prover's surface. A public spec is treated as
  surface expansion, **not** a finding (it's often intentional).
- Probes the common **GraphQL** routes with a GET introspection query; if the schema comes
  back, introspection-enabled is added as a **candidate** finding (type/field evidence + an
  inline plan). It runs inside the campaign, so the operator surfaces it automatically.
- GET-only, scope-gated (fail-closed), SSRF-guarded, and budget-shared with recon.

388 tests green (+10).

## v0.40.0

### Blind XXE over OOB (assisted + opt-in auto-send)
Confirms blind XML External Entity (XXE) injection out of band — the XML parser resolving an
attacker-supplied external entity makes a request to your collaborator, proving the bug
**without exfiltrating any file** (the entity only fetches the callback).

- **Assisted (default, GET-only):** GreyIQ mints a token and hands you ready payload variants
  (classic, parameter-entity, SVG, SOAP) with the callback embedded; deliver one to an XML
  endpoint, then re-poll the token to confirm.
- **Auto (opt-in `send`):** GreyIQ POSTs the benign payload itself — its first and only
  non-GET egress, gated, scope-bound, SSRF-guarded, no-redirect. Same negative-control +
  crawler-UA hardening as the SSRF path.
- Wired: `POST /api/bounty/oob-xxe` and a "blind XXE" panel in the cockpit OOB section.
  Confirmed/candidate hits cache as runs (report / bundle / submit); the hard submit gate
  still only auto-files confirmed findings.
- **DNS OOB channel — deferred.** A DNS channel needs an authoritative DNS server logging
  queries, which the phone-behind-an-HTTP-Cloudflare-tunnel collaborator can't host (tunnels
  carry HTTP, not UDP:53). Revisit with a small VPS or a delegated domain running a logging
  resolver.

378 tests green (+8), plus a no-network end-to-end smoke (auto-send confirms + caches a run;
assisted returns the payload kit without sending).

## v0.39.0

### Wider known-CVE coverage — more libraries + CMS detection
The outdated-component check now fingerprints more of the front-end stack:

- Added **jQuery UI** (with a guard so it's never confused with jQuery core), **Axios**,
  **Underscore.js**, and **Mustache.js** to the curated CVE table, plus **WordPress core**
  via the `<meta generator>` tag and an `X-Powered-By` header.
- `detect_components` is now header- and meta-aware (it reads response headers and the
  generator tag, not just the body).
- Server-software banner versions (`Server:`, `X-Powered-By:` nginx/Apache/PHP) are
  **deliberately not** mapped to CVEs — version-alone is low-signal and routinely rejected,
  which would be a false positive against the engine's confirm-grade promise. Only products
  with a clean version and a real, accepted CVE are matched.

370 tests green (+5).

## v0.38.0

### Known-CVE detection now runs inside every campaign (passive earnings)
The outdated-component check (v0.37.0) is now part of the campaign pipeline — so the
autonomous operator surfaces it automatically on every program it runs, with no separate step.

- After recon, a single scope-bound, SSRF-guarded GET of the target fingerprints its
  front-end libraries; each outdated component with known CVEs is folded into the campaign as
  a **candidate** finding (one per library), carrying its own attack plan, CVSS, EPSS-style
  score, and KEV flag. It shows on the cockpit's findings board, in `CAMPAIGN.md`, and in the
  downloadable bundle.
- Honest as ever: candidates, never "confirmed" — the hard submit gate still refuses to
  auto-file them. Scope defaults to the target's own host when a campaign is run without an
  explicit scope (matching recon), and the pass is best-effort (never breaks a campaign).

365 tests green (+1).

## v0.37.0

### New earner — known-CVE / outdated-component detection (Phase B)
A new passive check that finds a class programs pay for: outdated front-end libraries with
published CVEs.

- Fingerprints the **versions** of jQuery, Lodash, Bootstrap, Moment, AngularJS, Handlebars,
  and DOMPurify from script `src` filenames and the libraries' own version banners (with a
  guard so `jquery-ui` / `jquery-migrate` don't masquerade as jQuery core), then maps each
  detected version to a curated, offline table of real CVEs whose fix is in a higher version
  — each with its CVSS, CWE, an estimated EPSS-style exploit-likelihood, and a KEV flag for
  prioritisation.
- **Honest tiering:** results are version-fingerprint *candidates*, not claimed exploits.
  They cache as runs so you can export the outdated-component report / bundle, but the hard
  submit gate refuses to auto-file a candidate — it recomputes proof status server-side and
  only CONFIRMED findings can be auto-submitted.
- Wired everywhere: `POST /api/bounty/cve`, `gn cve <url> -y`, and a "Known-CVE components"
  panel on the cockpit's Surface view. GET-only, scope-bound (fail-closed), SSRF-guarded.

364 tests green (+15), plus a no-network end-to-end smoke proving the candidate path caches a
run and the submit gate refuses it.

## v0.36.0

### QA hardening round 3 — confirm-route robustness + one severity source of truth
The audit's architecture items, landed:

- **No more opaque 500s on the confirm routes.** The IDOR / takeover / OOB-SSRF routes now
  share one `_persist_finding_run` tail (build ctx → render → write `.md` **+ `.json`** →
  cache the run) instead of three drifting ~30-line copies, and each is wrapped so an
  unexpected service/render exception returns a structured `{ok: false, error}` the cockpit
  can show (the full traceback is logged server-side). The OOB route — which silently
  skipped its JSON evidence sidecar — now writes one like the others.
- **A finding's severity can no longer disagree across outputs.** A single
  `resolve_severity()` (CVSS-preferred, then the raw scanner label) is the source of truth,
  resolved once at confirm time and written back onto the finding — so the cockpit toast,
  the default report's table/detail/triage, the per-platform report, and the HackerOne
  `severity_rating` always show the same word.
- **PoC screenshots embed on every report surface**, not just the per-platform package —
  the default report (`build_markdown` + `build_finding_markdown`) now renders the captured
  screenshot too (by basename, with the not-auto-redacted caveat).

349 tests green (+10), plus a live end-to-end smoke of the refactored confirm path.

## v0.35.0

### QA hardening round 2 — boolean-SQLi precision + the safety-critical tests
Continuing the audit-driven hardening:

- **Boolean-blind SQLi** now rejects an *infrastructure* differential: the TRUE/FALSE
  divergence must be two clean **200s with no SQL-error banner** (a WAF/error block page of
  a different length no longer confirms), and must **reproduce on a second pass** before it
  confirms.
- Added targeted tests for the two **most safety-critical functions, previously untested**:
  the SSRF/URL policy (`web_ingest._enforce_url_policy` — refuses non-http schemes, embedded
  credentials, non-standard ports, and private/loopback/link-local/cloud-metadata IPs) and
  the archive **zip-slip / tar-slip** guard (rejects traversal, absolute, and null-byte
  member names).

339 tests green (+14).

## v0.34.0

### QA hardening — fewer false positives, accurate severity (engine-wide audit)
A multi-agent QA/QC audit of the whole engine drove a round of precision fixes so a
"confirmed" finding stays trustworthy:

- **Subdomain takeover:** removed two generic-404-grade fingerprints (Webflow, Heroku
  "There's nothing here, yet.") that fire on normal sites, and now require an **error
  (4xx/5xx) response** — a normal 200 page that merely *quotes* an "unclaimed" phrase no
  longer confirms. Added **wildcard-DNS detection** (a catch-all record no longer makes
  every label "resolve"), and reconciled the finding severity with its CVSS (high).
- **OOB blind SSRF:** added a **pre-probe negative control** (the fresh, unguessable token
  must be empty), confirm only on the token going 0→1 after the probe, **downgrade
  callbacks from social unfurlers / search crawlers to a candidate** (generic HTTP-library
  UAs, which a real SSRF backend uses, stay confirmed), and make a transient collaborator-
  poll error non-fatal across params.
- **Host-header injection:** a Host reflected only into the **response body** (common and
  usually harmless) is now a low **candidate** with a proof obligation; only a Host
  reflected into the **Location header** stays confirmed.
- **Report taxonomy:** corrected the GraphQL Bugcrowd VRT (was a DNS-misconfig category)
  and the XSS VRT (over-asserted "stored" → "reflected").

325 tests green (4 new regression tests).

## v0.33.0

### Confirm blind bugs out-of-band (OOB collaborator)
GreyIQ can now **confirm blind, out-of-band vulnerabilities** — blind SSRF above all —
using your own OOB collaborator (e.g. the greynoc-chat `/oob` receiver running on your
phone). It mints a unique callback URL, injects it into the target's server-side-fetch
parameters, sends a benign GET probe, then polls your collaborator for an inbound hit: a
recorded callback **proves** the target reached out of band, where nothing reflects in its
own response.

- New **Out-of-band** panel in the cockpit's Access-control tab: configure your collaborator
  (URL + secret, write-only), auto-confirm blind SSRF against a target, or **mint a callback
  URL** to paste into a manual XXE / blind-XSS payload.
- `POST /api/bounty/oob-ssrf` (a confirmed hit is cached as a run, so the per-platform
  report / screenshot / research / bundle / submit all work on it), plus `/api/oob/config`,
  `/api/oob/mint`, `/api/oob/poll`.
- Scope-bound + SSRF-guarded target probes; the collaborator secret lives in GreyIQ's
  secrets store and is never embedded. Pairs with the new greynoc-chat OOB receiver.

## v0.32.0

### Subdomain enumeration + takeover — more surface, a high-value easy win
GreyIQ now maps more of the attack surface and confirms **dangling subdomain takeovers** —
a DNS record still pointing at a deleted third-party resource (GitHub Pages, S3, Heroku,
Fastly, Shopify, …) that an attacker can claim to serve content on the target's own
subdomain.

Give it an in-scope apex; it enumerates subdomains from a bounded label wordlist (resolved
via DNS — no external API) plus any hosts recon already found, fetches each resolving,
in-scope host **GET-only through the same SSRF/private-host guard**, and confirms a takeover
only on a **strong, service-specific "unclaimed" fingerprint** (curated to unique signatures
so a normal page or a plain 404 never matches). No resource is ever claimed.

A confirmed takeover is a first-class finding: a **Subdomain takeover** form in the cockpit's
Surface tab, `gn takeover example.com -s example.com -y`, and `POST /api/bounty/takeover` —
all flowing into the per-platform report, screenshot, research, downloadable bundle, and the
hard-gated submit.

## v0.31.0

### Confirm IDOR / broken access control — the #1 paying class
GreyIQ can now **prove** IDOR/BOLA (broken access control), the highest-value bug class
and the one a single-session scanner can't touch because it needs two accounts. You supply
**two of your own authorized test accounts** and one object URL each; the engine runs a
GET-only, scope-bound, three-request differential:

- account A reads A's object (ground truth),
- account B reads B's own object (control — proves B's session is valid),
- account B reads **A's** object (the attack).

It confirms a cross-tenant read only when B's response to A's object is ~identical to A's
own **and** matches A clearly more than it matches B's own object — so a real IDOR is told
apart from a properly-scoped endpoint or a shared/static page (no false "confirmed").

Crucially, the captured proof is the **differential only** (statuses + similarity ratios) —
the other user's data is **never shown, stored, or written into the report**. Each session
is attached same-site only, so neither credential ever leaves the target host.

A confirmed IDOR becomes a first-class finding: a new **Access control** cockpit tab,
`gn idor <A-url> <B-url> --a-cookie ... --b-cookie ... -y`, and `POST /api/bounty/idor` —
all flowing into the per-platform report, screenshot, research dossier, downloadable
bundle, and the hard-gated HackerOne submit.

## v0.30.0

### Deep mode runs unattended — the operator works leads aggressively on a schedule
The autonomous operator can now run programs in **deep mode**. Add a program with **Deep
auto-work** on (a new toggle in the operator program form, `gn operator add --deep`, or
`deep: true` on `POST /api/operator/programs`) and each scheduled cycle runs the campaign
aggressively: proof-of-impact + time-based blind SQLi, then a screenshot and a researched
dossier for every confirmed lead — all written into the engagement folder, hands-off.

Same safety model: deep is **fail-closed** (a program with no scope can't be deep, exactly
like active/live), deep **implies proof-of-impact** (a deep program is always active), and
it adds **no new egress** — it reuses the operator's existing scope-bound campaign and the
unchanged, hard-gated auto-submit path (armed + per-program opt-in + server-confirmed +
ledger-dedup + per-day throttle).

## v0.29.0

### Work the lead end to end — research, prove, and download the whole engagement
GreyIQ can now take a lead all the way to a submittable result and hand you the entire
engagement as one download.

- **Research each lead (your brain, your choice).** A new **Research this lead** action
  writes a research dossier per finding — what the bug is here, why it matters, an ordered
  plan to confirm it, exploitation notes, variants to try, and references. It uses the
  **brain you plug in** (Claude / ChatGPT / local Ollama) and makes **no internet calls**;
  with no brain configured it still produces a complete deterministic dossier. (`POST
  /api/bounty/research`.)

- **Screenshot the exploit.** A new **Capture screenshot** action drives a headless
  browser to a finding's proof-of-concept URL and saves a PNG that's embedded in the
  report and the submission package. Opt-in, scope-bound and SSRF-guarded, and clearly
  flagged as **not auto-redacted — review before you submit** (an image can't be scrubbed
  the way text evidence is). Needs Playwright (`pip install playwright && python -m
  playwright install chromium`); degrades cleanly when absent. (`POST
  /api/bounty/screenshot`.)

- **Deep mode — commit to the plan automatically.** A new **Deep auto-work** toggle (and
  `gn campaign --deep`) implies proof-of-impact + time-based blind SQLi, then for each
  *confirmed* lead auto-captures a screenshot and writes a researched dossier into the
  engagement folder. Still GET-only, scope-bound, and bounded.

- **Download everything (.zip).** A new **Download everything** button (and `gn bundle
  <folder>`, `POST /api/bounty/bundle`) packages the whole engagement — reports,
  per-platform submission packages, captured evidence, screenshots, research dossiers,
  and JSON — into a single .zip you can submit from.

## v0.28.0

### Choose your reporting format — HackerOne, YesWeHack, Bugcrowd, Intigriti
Submission reports can now be shaped for the destination platform. The **same finding —
and the same gathered evidence —** is reframed with each platform's own conventions:

- **HackerOne** — Weakness (CWE) + severity rating; Summary / Steps / Supporting material / Impact.
- **YesWeHack** — Bug type (CWE) + CVSS vector; Description / Steps / PoC / Impact / Remediation.
- **Bugcrowd** — VRT-led with a P1–P5 priority; Description / Steps / PoC / Impact / Remediation.
- **Intigriti** — Type (OWASP/CWE) + CVSS; Description / Endpoint / PoC / Impact / Recommended fix.

Pick the format in the Hunt cockpit's **Submissions** tab (a new selector). **Copy report**
and **Download .md** produce the chosen platform's layout, and the gathered evidence — the
captured request/response, matched values, `Set-Cookie`, and code/response excerpt — is
always included when the finding carries it. The one-click API submit still files to
HackerOne (the only wired platform API); use Copy/Download to file on the others.

On the CLI, `gn platforms` lists the formats and `gn campaign --platform <id>` writes the
submission packages in that format. New `GET /api/bounty/platforms`. The report framing is
done by a new `report_formats` module that re-shapes `report.py`'s output per platform
without changing what the HackerOne API submit sends.

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
