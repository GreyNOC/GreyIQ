# GreyIQ BugHunter — Operator's Guide

This is the practical walkthrough for the Hunt cockpit: **Program → Hunt → Reports**. It
assumes you already have GreyIQ running (see the main [README](../README.md) for install/run).
Everything in this guide is also reachable in the app itself — each tab has a collapsible
**walkthrough** panel (a `<details>` block near the top) carrying the same content inline,
and a first-time launch opens a short guided tour automatically (reopen it anytime with the
**🧭 Guide me** button in the top bar).

## Before anything else: authorization

GreyIQ is built for **authorized testing only** — your own assets, an engagement you're
contracted for, or a bug-bounty program you're enrolled in. In the Hunt cockpit, active
probes require an authorization checkbox and an enforceable host in **Scope**. In chat,
network probes require `-y` and an exact host through `--scope`. Both paths fail closed
before probing a host that the operator has not named. Nothing here authorizes you to
test anything — that authorization has to already exist before you open the app.

Optional MCP servers are configured under **Brain → MCP servers**. Chat tool calls
still require explicit `mcp tools -y` or `mcp call -y` commands; the chat model
does not choose tools. During an authorized hunt, GreyIQ automatically calls a
built-in, in-memory MCP tool to review captured evidence without making target
requests. To include an external evidence-only tool, enable and test its server,
approve its exact advertised tool, and check **External MCP evidence analysis**
for that run. The automatic payload contains fixed categories and counts, not
the target URL, scope text, or raw evidence. The external server controls its
own network requests outside GreyIQ's guard, so approve only tools verified to
avoid target requests. MCP
review is advisory and cannot promote a finding or change a probe. The built-in
chat scan commands below enforce GreyIQ's exact-host gate.

Chat network scans also require an explicit assertion and exact host: `scan web -y
--scope app.example.com https://app.example.com/`. Local source scans use
`scan code <local-path>`. The short chat command
assumes the entire named host is permitted; use a saved program hunt when the
policy has path limits, exclusions, time windows, or required request markers.
Remote source URLs are recognized but cloning is currently disabled because
Git can fetch alternate object stores beyond the named repository. Scan a
local clone with `scan code <local-path>`.
For a bounded active proof pass, use `scan active -y --scope app.example.com
https://app.example.com/`. It runs in the background, uses up to 16 GET/HEAD/OPTIONS
requests, and updates the chat bubble with observed results and negative controls.
Time-based probes are disabled in this command.
Scoped live browser scans refuse to run until the browser's DNS connection can
be pinned to the address checked by the scope guard.

## 1. Program setup

The **Program** tab (first tab in the cockpit) is where a bug-bounty program's identity
and scope live. One saved program feeds three things: the launch rail's **Program** picker
(autofills Target/Scope for a hunt), the **Operator** tab's autonomous scheduling, and — once
you set up SSRF/OOB testing — the Access-control tab's collaborator panel.

A program record has: a name, an optional HackerOne team handle, a **structured scope**
table (one row per in-scope/out-of-scope asset), optional program-provided source repository
links, an `oob_allowed` flag, and free-text notes.

### Getting a program and scope in

**Repository-link setup is paused.** The Program wizard disables **From a repo link**
while remote Git transport cannot be constrained to the authorized repository.
Create the program manually if its scope includes source code, and scan an
operator-supplied local clone through the local-path scanner.

**Fetch from HackerOne (API).** If you have a HackerOne API username + token saved (see
[HackerOne credentials](#hackerone-credentials) below), enter the program's team handle and
click **Fetch scope from HackerOne**. GreyIQ calls HackerOne's own hacker API —
`GET /v1/hackers/programs/{handle}` for the program's name/policy, then
`GET /v1/hackers/programs/{handle}/structured_scopes` (paginated) for every scope entry —
using HTTP Basic auth with the same credentials you already entered. This is one of the
small, documented set of calls that can reach a host other than your target, and it only
fires on this explicit click — never automatically or in the background.

Many programs restrict structured-scope visibility to invited or paid researchers, so a
403/404 here is common and is *not* a bug — GreyIQ tells you plainly and points at the CSV
fallback instead of failing silently.

**Fetch from YesWeHack (API).** Pick **From YesWeHack** in the program wizard, or set the
Platform to YesWeHack and click **Fetch scope from YesWeHack**. Search by name, or paste the
program slug (or the full `yeswehack.com/programs/…` URL). GreyIQ calls YesWeHack's own API —
`GET /programs?page=N` to search, then `GET /programs/{slug}` for the program itself.

Unlike HackerOne's, **no credential is needed for a public program**: YesWeHack serves public
programs' scope, rules and marker anonymously, so the common case works with an empty
Submissions bar. Sign in only for a private or invited program (a 403 says so). Like every
other non-target call, this fires only on your explicit click.

One fetch fills in everything the hunt needs:

- **Scope** — every `scopes[]` entry becomes a structured-scope row, with its asset type, its
  value tier (`asset_value`) as Max severity, and the reward range that tier actually pays
  (YesWeHack prices assets per tier via `reward_grid_*`, falling back to the default grid).
- **Out of scope** — YesWeHack's out-of-scope list mixes real host patterns with prose. Host-
  shaped lines become **unticked** scope rows, which is what GreyIQ turns into enforced
  out-of-scope hosts; the prose stays readable in Notes rather than being pushed into the host
  matcher as a fake hostname.
- **Rules of engagement** — the program's rules text, qualifying and non-qualifying
  vulnerability classes, test-account instructions, VPN requirement and source-IP restrictions
  are written into **Notes**, binding constraints first.
- **The required user-agent marker** — most YesWeHack programs require a per-program tag on
  every request so they can attribute your traffic. GreyIQ puts it straight into **Required
  user-agent suffix**, the same field the hunt engine appends verbatim to every in-scope
  request, so an imported program is in-policy without extra setup. A re-fetch never
  overwrites a marker or Notes you have edited by hand.

A program that is disabled on YesWeHack, requires the VPN, or restricts testing to specific
source IPs is called out in the fetch result *and* tagged on the saved program row.

- Your **API token**: hackerone.com → Settings → **API Token** (this is a token, not your
  account password).
- Your **API username**: shown right next to the token on that same settings page.
- The **program handle**: the segment right after `hackerone.com/` in the program's URL
  (e.g. `hackerone.com/acme` → handle is `acme`).

**Import a CSV, or paste a table.** No API access to that program's scope? Copy the scope
table straight off the program's HackerOne page (or export it if the program offers that),
and paste it — or upload the file — into the **Import targets** box, with kind set to
**HackerOne scope CSV/paste**. GreyIQ recognizes the real column names HackerOne uses
(`asset_identifier`/`identifier`, `asset_type`, `eligible_for_submission`,
`eligible_for_bounty`, `instruction`, `max_severity`) case-insensitively, so it keeps every
column instead of collapsing the row to a single URL. If it doesn't recognize any header at
all, it falls back to treating each cell as a bare in-scope identifier — still useful for a
plain list of hosts.

**Type it by hand.** Click **+ Add scope row** and fill in an identifier — that's the only
required field. Everything else (asset type, bounty eligibility, severity cap, instructions)
is optional metadata.

**Record a program-provided source repository.** Paste each public HTTPS repository-root link
into **Program-provided source repositories**. HackerOne/CSV imports that contain supported
GitHub, GitLab, Bitbucket, Codeberg, or SourceHut roots are detected and copied into this
review list. The **Clone and adversarially scan** control is currently fail closed even when
enabled: Git cannot yet guarantee that every fetch stays at the authorized repository. To
scan source, supply a local clone under the local-path scanner instead. Issue, pull-request,
blob, and tree pages are not accepted as repository roots; embedded credentials are refused.

### Review before you hunt

Whichever way scope arrived, review the table before saving:

- Untick **In scope** on any row you don't want probed. This is an **exclusion filter
  only** — unticking a row never expands what GreyIQ is allowed to touch; it only narrows it.
- Forge-enriched host suggestions start unticked. Check the program's published policy and
  confirm you are authorized to test a host before ticking **In scope**; the suggestion alone
  grants no authorization.
- A program with **no** in-scope rows (and no hand-typed Scope text) can never be marked
  active — this is the same fail-closed gate the launch rail and Operator already use, just
  applied one level up: an empty structured scope can't silently become "active everywhere."
- A URL asset limited to a path, port, or scheme does not authorize the whole host.
  GreyIQ stops manual program hunts and proof requests when its host-only probe
  guard cannot enforce that narrower asset. Add a separate host or wildcard row
  only if the current program policy explicitly permits testing the whole host.
- For an ad hoc URL hunt, enter only bare hosts or explicit wildcards in Scope,
  separated by spaces, commas, or semicolons. Keep policy prose in program Notes.
  Enter a host grant only
  when the published policy permits that host. A pasted URL or path by itself
  cannot be widened into host authorization by the preflight gate, and an
  out-of-scope host is refused before the initial passive request.
- For a remote repository hunt, name the exact supported HTTPS repository-root
  URL in Scope. A forge hostname does not grant every repository on that service.
  Remote cloning currently refuses to run; use a local clone for source analysis.
- Re-fetching program scope keeps existing exclusions. If all excluded rows cannot
  fit within the bounded scope table, review and narrow the rows before saving.
- Scope text you enter in the Operator tab stays exactly as entered when you
  refresh the structured scope table, including line breaks and spacing. Clearing
  that text turns active testing off until you enter a new scope.
- Click **Save program**.
- For a source-code hunt, click **Hunt repository** on the saved program or pick the repository
  from the launch rail's Target suggestions. GreyIQ makes a depth-1, single-branch temporary
  clone, scans the whole eligible code tree with the adversarial static rule set, sends the
  resulting leads through the configured hunt brain for red-team reproduction/impact planning,
  performs the normal authorized credential-validation and reporting stages, then removes the clone.

### HackerOne credentials

Saved once, in the **Submissions** tab's "HackerOne API" bar: your team handle, API
username, and API token. The token field is write-only — GreyIQ never reads it back to the
UI once saved. These same credentials power both the read-only scope import described above
and the (separately gated) HackerOne report submission described in
[Reports & submission](#4-reports--submission).

### Browse platform APIs

In **Programs → Add program → Browse platform APIs**, choose HackerOne, YesWeHack,
or Intigriti. **Browse programs** reads a bounded list visible to the API
identity; select a result or enter its program ID/handle and choose **Preview selected
program**. Review the scope rows, exclusions, policy excerpt, status, and warnings before
continuing to the Program form. Every program saved through this path starts **paused**.
The listing and preview are evidence to review, not permission to test. The operator
still needs a current authorization record and policy check before scheduled work.

HackerOne uses the credentials in Submissions. YesWeHack can list public programs
anonymously; private access may require its sign-in. Intigriti uses a researcher
bearer token saved in the Browse step. GreyIQ keeps the token in its local
owner-only secrets store and returns only whether one is saved. Credentialed requests are read-only, HTTPS host-pinned,
redirect-refusing, and bounded. These APIs may omit free-text exclusions or other
policy details, so always check the current human-facing program page. If your account
cannot access a program through its API, use manual or CSV intake.

Bugcrowd researcher programs are entered manually or through CSV intake. The
Bugcrowd organization API is not used for researcher program discovery or scope
preview; review the current Bugcrowd brief before recording authorization or scope.

### YesWeHack credentials

Optional — the **YesWeHack** bar in **Submissions** starts at *anonymous · public programs
only*, and that is a fully working state. Sign in only to reach a private or invited program.

Signing in posts your email and password once to the local backend, which exchanges them with
YesWeHack for a session token (`POST /login`, then `POST /account/totp` when your account has
2FA). **Only the returned token is stored — the password is never written to disk, never
logged, and never read back to the UI.** YesWeHack tokens are short-lived; when one expires
the fetch says so and you sign in again. **Sign out** clears the stored token.

A Personal Access Token can be pasted instead (tucked under *Use a Personal Access Token*) —
YesWeHack issues those to program-manager and business-unit roles rather than hunter accounts.

There is no YesWeHack submit API for researchers, so YesWeHack stays **export-only**: GreyIQ
formats the report for YesWeHack's form and you file it on the platform.

## 2. SSRF / OOB setup, per program

Blind SSRF (and blind XXE) can't be proven by looking at the response — the target fetches
a URL you control, out of band, and you watch for the callback. GreyIQ's detection engine
for this already exists in the **Access-control** tab's OOB panel; the Program tab just
removes the friction of setting it up per program:

1. **Confirm the policy allows it.** Some bounty programs explicitly forbid interacting
   with third-party/out-of-network infrastructure during testing. Read the program's policy,
   then tick **"This program's policy allows out-of-band / collaborator testing"** on its
   Program-setup form. This isn't cosmetic — clicking "Set up SSRF/OOB →" on a program that
   hasn't confirmed this asks you to double check before continuing.
2. **Set up a collaborator once** (global, not per-program) in the Access-control tab's OOB
   panel: a collaborator base URL + secret. See that panel's own walkthrough for the
   one-time setup.
3. **Jump over with scope pre-filled.** Click **"Set up SSRF/OOB →"** on a saved program's
   row — it carries that program's scope straight into the Access-control tab's Scope box, so
   you don't retype it.
4. **Mint a callback + probe.** In the OOB panel, mint a callback URL, then run the
   blind-SSRF probe against a candidate endpoint. GreyIQ injects the callback into likely
   parameters and polls for a hit, with a same-run negative control before anything is ever
   marked confirmed.

Common places SSRF sinks hide, worth trying first: webhook/callback URL fields, "import a
file from a link" features, avatar or link/thumbnail proxies, PDF/screenshot-export tools
that "render this URL," and any parameter that already looks like a URL (`redirect`, `next`,
`return_to`, `source`, …).

## 3. Running a hunt

Three ways to actually run the engine, all reading the same Target/Scope from the launch
rail (which the Program picker can autofill):

- **Single hunt** — one target, one profile (Web app / API / Source-code / Secrets / Full
  sweep), optional vuln-class focus. A supported public repository URL is automatically routed
  to the remote-clone source scanner. The fastest way to check one asset. Start here.
- **Full campaign** — recon-crawls the target first (robots/sitemap/security.txt,
  same-origin links, served-JS mining), then hunts every discovered URL, dedupes and ranks
  findings, and (in **Deep** mode) auto-captures a screenshot + writes a research dossier
  for every confirmed lead.
- **Autonomous operator** (Operator tab) — works your whole **portfolio** of programs
  on a schedule: recon → hunt → prove → dedup → local report, repeated per program at
  its configured interval. It queues findings for human review and never submits them.
  To start, enter the authorization record and current policy source for each enabled
  program, confirm its scope and restrictions, and choose a 24-hour or seven-day
  authorization window. The operator stops at expiry or its cycle limit; re-arm it
  only after checking the current policy again. Verified hunt outcomes inform later
  priority. After five new local hunt traces, GreyIQ tries a bounded offline ranker
  retrain; it promotes weights only when at least 200 checked/confirmed examples
  exist and held-out recall matches or beats both rules and the active model. Set
  `GREYIQ_NO_AUTO_TRAIN_BRAIN=1` to disable these automatic retrain attempts. The kill
  switch requests cancellation and prevents further cycles. Automated hunts use
  only a loopback local model or the offline fallback; a cloud or remote model
  remains available for deliberate manual work.

**TinyGPT / AI Studio.** The **Verified Lessons** source contains local coding
experiences admitted by the verification gate. It is selected for new Studio
training setups and available to the BugHunter core's source-filtered retrieval,
including migrated default setups. A running TinyGPT engine refreshes this source
on its next retrieval after a verified lesson is admitted. Starting a TinyGPT
weight-training run remains an operator action. Bounty verdicts and hunt traces
feed the separate local hunt priorities and ranker described above; they are
not inserted into TinyGPT's
verified coding replay.
For a local Windows release that runs TinyGPT, build with
`scripts/release.sh --include-tinygpt`; the build verifies the frozen checkpoint.

The CLI's continuous `gn operator run` uses the same grant validation. Pass
`-y --grant-file path/to/grants.json`; the file must contain one entry for each
enabled program:

```json
{"grants":[{"program_id":"saved-program-id","authorization_ref":"engagement record","policy_source":"current program policy URL","policy_checked_at":"UTC ISO-8601 timestamp","expires_at":"UTC ISO-8601 timestamp within seven days","max_cycles":7}]}
```

The `--once` legacy shortcut is disabled because it lacked the guard and audit
path. Active grants are held in process memory and must be re-armed after a
restart. The authorization audit is stored locally as
`runtime/operator_authorization_audit.jsonl` (or under the configured runtime
directory); it records the governing references and cycle outcomes without
making old grants executable.

All three default to **passive-only**. Ticking **"Test for proof of impact (active)"** turns
on benign, in-scope-only active probes that can mark a finding **Confirmed** instead of just
flagged; deep SQLi and deep auto-work still only ever fire against a host
actually named in Scope. The live browser option is disabled until its DNS
egress can be pinned to the same checked host.

### Passive OSINT campaigns (local CLI)

The shipped `gn` command can build a domain evidence ledger before you spend any request
budget on the target:

```text
gn osint example.com
gn osint example.com --json
gn osint example.com --hunt --scope "*.example.com" --active -y
gn campaign https://example.com --scope "*.example.com" --osint -y
```

`gn osint` queries public indexes, not the investigated website: crt.sh + Cert Spotter for
certificate history, then Google + Cloudflare DNS-over-HTTPS for current resolution. Every
claim carries its provider IDs and retrieval time. Exact agreement from two independent
providers is **verified**; one-source DNS facts stay **observed**; CT-only hostnames stay
**historical**. The report and complete JSON ledger land under `runtime/osint/` by default.

`--hunt` is a deliberate handoff, not automatic authorization. It requires explicit Scope and
`-y`, includes only hosts independently present in current public DNS, withholds private or
reserved answers, and then routes the targets through the same bounded campaign and per-request
scope checks described above. Use `--max-hosts` to control the DNS-validation budget (25 by
default, hard-capped at 100). `gn campaign --osint` is the lighter alternative: it opts the
existing recon crawl into crt.sh seeding while retaining the normal page and request caps.

The OSINT input checks are format and boundary checks, not organization filtering: commercial,
nonprofit, and non-U.S. domains are accepted. Entity-specific policy restrictions are limited to
explicitly selected U.S. federal VDP profiles (currently NASA); a `.gov` domain or organization name
does not silently activate a profile. Authorization, scope, private-address, rate, and evidence gates
remain universal because they prevent false attribution and out-of-scope traffic.

### The terminal cockpit — `gn dash`

`gn dash` is `gn hunt` with the whole terminal: live panels for targets, findings over time,
per-host rate limiting and the activity log, plus a command line you can type other `gn` verbs
into while the run continues.

```text
gn dash https://example.com --scope "*.example.com" --active -y
gn dash --attach                       # watch a run the desktop app is already running
gn dash --attach --run-id <id>         # ...or a specific one
gn dash --self-test                    # check this terminal without starting a hunt
```

It takes every option `gn hunt` takes, and **anything that makes panels inappropriate falls back
to running exactly `gn hunt`** — `--json`, a redirected stdout, a pipe on stdin, `NO_COLOR`,
`TERM=dumb`, `GN_NO_FX=1` or `GN_NO_DASH=1`. `gn dash … --json | jq` is one clean JSON document,
and `gn dash … > report.txt` is byte-for-byte what `gn hunt` would have written. A terminal
smaller than 60×18 is the one exception: it refuses and says so, because you clearly wanted the
panels, and quietly hunting without them would be a different command from the one you typed.

**Keys.** `Tab` cycles LOG / OUTPUT / TARGETS, `PgUp`/`PgDn` scroll whichever has focus, `Up`/`Down`
walk the command history, `Ctrl-L` repaints, `q` quits. Type `help` in the pane for the verb table
— it lists each control verb with its **real** latency, and greys out the ones this run does not
offer.

**`--attach`** watches a run another process is already holding, over loopback only
(`127.0.0.1`, `::1`, `localhost`) and only after `GET /api/health` has answered on the port —
nothing sends the session token to a port that has not identified itself. It finds the port from
`$GREYIQ_PORT`, then `--port`, then a walk of 8766–8845, and the token from `--token`, then
`$GREYIQ_SESSION_TOKEN`, then `session.token` under `$GREYIQ_RUNTIME_DIR` or the desktop app's own
runtime folder. With no `--run-id` it attaches to the newest run that has not been asked to stop.
If the backend restarts, the header pill goes `NO BACKEND` and the panels **freeze on the last
good snapshot** behind a `stale Ns` badge — they are never cleared to zeros, because an empty
panel reads as "nothing found", which is a different claim from "we lost contact".

**`--self-test`** enters the alternate screen, draws one frame, hands the terminal back, and
prints what it picked: glyph tier, key reader, console VT state, measured size, and which host
counters answered. Run it first on an unfamiliar terminal — it is the fastest way to find out why
a console is showing a wall of empty boxes.

**Glyphs.** Block-bar sparklines by default, dropping to `░▒▓` on a cp437/cp850 console and to
`_.:|` on an ASCII-only one. Braille is **off by default even on UTF-8**: `gn` forces both streams
to UTF-8 at startup, so the encoding probe always says yes and cannot tell that your font has no
U+28xx glyphs. Override with `GN_DASH_GLYPHS=braille|rich|box|ascii`, or `--braille` for that one
run. `GN_NO_DASH=1` turns the cockpit off for a shell (same vocabulary as `GN_NO_FX`: `1`, `true`,
`yes`, `on`).

**What the panels claim, exactly.** The dashboard is deliberately pedantic about the difference
between a measurement and a guess:

- **`probe rate ~N/s (est, local)`** — *estimated*, derived from per-host token-bucket deltas, not
  counted requests. Nothing in the engine counts requests per second, so this is labelled `est`
  rather than presented as a reading.
- **`n/a — local only`** — the rate panel and the host buckets in `--attach` mode. Those numbers
  exist only inside the hunting process and are not exposed over HTTP, so they are reported as
  unavailable rather than as zero.
- **`--`** — any host counter (CPU, memory, disk) this machine would not answer. Never `0`: zero
  is a claim.
- **`total 400 (cap)`** — the findings stream is capped at 400 per run. A flat line that is really
  a truncation is labelled as one.
- **`stopping — after the current step`** — what the `stop` verb actually promises. The engine
  checks the stop flag *between* probes, so a stop can take a full active pass (up to ~80s per
  ranked endpoint) to take effect. The pill turns `DONE` only when the run itself returns. It is
  never reported as "stopped" on request.
- **Completion (`done/total`) counts skipped targets.** A stopped campaign marks its remaining
  targets `skipped`, and a percentage that ignored them would sit below 100% forever.

The dashboard writes **no files** — no frame log, no panel capture. Reports come from the hunt,
exactly as they do without it.

## 4. Reading results

The **Findings** board shows every finding with a proof-status pill:

- **Confirmed** — GreyIQ proved it with an actual benign probe (a real differential, a real
  out-of-band callback, a real timing signature) — not a pattern match.
- **Candidate** — a plausible lead the passive/static side surfaced, not yet actively proven.

Click any row for the evidence pane: the captured request/response, the differential that
proved it, CVSS, CWE/OWASP mapping, remediation guidance, and (when available) a proof
screenshot.

The **Leads** view and `gn leads` brief also show each proposed probe's predicted
confirming result, a matched negative control, and the condition that leaves it
unconfirmed or stops testing. These are planning notes. Check the current program
scope and authorization before any active probe, and treat only captured evidence
as proof.

## 5. Reports & submission

Confirmed (and reportable candidate) findings appear in the **Submissions** tab:

- **Copy report** / **Download .md** — a concise, plain-language description with
  Summary, numbered Proof of Concept steps, captured result and control, and Impact.
  Choose the platform format at the top of the tab (HackerOne, YesWeHack,
  Bugcrowd, Intigriti, or HackenProof). Fill the platform's title, asset,
  severity, and classification fields separately. The per-finding package also
  keeps a detailed `.details.md` analyst report and `.json` sidecar with the
  evidence and review context. Check every claim and attachment against the
  saved capture before submitting.
- **Submit to HackerOne** — the one place GreyIQ pushes a report over the network on your
  behalf. It's hard-gated: only enabled once proof status is Confirmed *and* your HackerOne
  creds are saved, requires an explicit confirmation dialog, and the server independently
  re-checks the confirmed status (a forged client request can't push an unproven finding).
  Every other platform — including HackenProof — is **export-only for submission**: HackenProof publishes no
  researcher API for scope, submission, or metrics (its programmatic surface is a triage-side
  MCP server, not a hunter API), so GreyIQ formats the report and you submit it on the
  platform's own dashboard.
- **Download everything (.zip)** — the whole engagement folder (reports, JSON sidecars,
  screenshots, per-finding packages) as one archive.

## Safety model, summarized

- **Scope-bound, fail-closed everywhere.** A host not named in Scope (or, now, a program's
  own in-scope structured-scope table) is never probed — this is checked server-side on
  every request, including every redirect hop, not just trusted from the UI.
- **GET-only by default.** Active checks default to safe, idempotent, benign requests. A
  few opt-in checks (time-based SQLi, blind XXE/stored-XSS auto-send) can send a single
  bounded non-GET request, always explicitly opted into per-call.
- **Egress is deliberately narrow.** Everything talks to your authorized target, except:
  the HackerOne report submission (`api.hackerone.com`, write, hard-gated, manual), the
  HackerOne scope import described above (`api.hackerone.com`, read-only, manual), the
  YesWeHack program search / scope import and sign-in (`api.yeswehack.com`, read-only apart
  from the sign-in exchange itself, manual),
  Intigriti (`api.intigriti.com`) program discovery and scope preview
  (read-only, manual), and optional
  repo-draft enrichment (`api.github.com` or `gitlab.com`, unauthenticated read-only, one GET
  per repository, explicit click only), an
  optional certificate-transparency lookup for subdomain seeding (`crt.sh`, read-only), the
  explicit local OSINT command (`crt.sh`, Cert Spotter, Google DNS, and Cloudflare DNS;
  read-only public-index queries), and
  polling your own OOB collaborator server (a host you configured). An explicit
  local-model picker reads Ollama's public catalog (`ollama.com`, read-only)
  when opened or refreshed. Selecting a model asks the chosen Ollama server to
  download it. Hugging Face setup also checks public model metadata and asks
  local Ollama to download the selected model. The direct Hugging Face import runs chat
  and agent-tool readiness checks before selecting it for chat or hunt planning;
  the packaged desktop starts its saved local Ollama runtime again after restart.
- **Only you submit reports.** The Operator queues findings and report packages locally.
  Review the evidence and use the manual submission action if you decide to file a report.
  The kill switch requests cancellation and prevents further scheduled work.
