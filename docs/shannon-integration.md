# Baking Shannon into GreyIQ

Status: **slice 1 implemented and tested. Driving Shannon is blocked — see [Blockers](#blockers).**
Audience: whoever implements the remaining slices.

Shannon (`KeygraphHQ/shannon`, AGPL-3.0) is Keygraph's open-source autonomous AI
pentester. It pairs agentic source-code analysis with live exploitation against a running
app, and reports only what it could exploit — "No exploit, no report."

Pinned at commit `2468b67d9e40d70d0b189462c5041c24e1dc886c` (2026-10-07). Every claim below
is from that tree or from GreyIQ's own at the current checkout. This doc follows
[tacnoc-integration.md](tacnoc-integration.md), whose §5/§6/§7 contract it is bound by.

## Verdict

Feasible in one direction. **Reading** Shannon's output into GreyIQ is done and shipped
(slice 1). **Driving** Shannon from GreyIQ is not, and must not be attempted until the
shared-budget work lands — the same hard ordering constraint `tacnoc-integration.md` §7
placed on TACNOC, for a sharper reason: TACNOC had a rate limiter GreyIQ couldn't see,
whereas **Shannon has no rate limiter at all.**

The enabler is that Shannon's value is exactly the capability GreyIQ lacks. GreyIQ's
`code_scanner` is a rule-based static analyzer; Shannon runs agents that tie runtime
behaviour back to source and then try to exploit it. And GreyIQ already shallow-clones the
authorized repo mid-hunt (`backend/bughunter/bounty.py:2152`), so the source tree Shannon's
`-r` wants is already on disk at the moment it would be useful.

What makes this safe to ship read-only is that **the import never claims a proof.**

## What is implemented

| Path | File |
|---|---|
| `report.sarif` → neutral candidate records | `backend/bughunter/shannon/sarif.py` |
| candidate records → GreyIQ hunt findings | `backend/bughunter/shannon/ingest.py` |
| find a finished run on disk, import it | `backend/bughunter/shannon/workspace.py` |
| the confirm veto | `backend/bughunter/report.py`, first guard in `_has_captured_artifact` |
| the submit refusal | `backend/bughunter/submission.py`, `submit_to_hackerone` + `preflight` |
| operator entry point | `gn shannon <path>` (`backend/gn_cli.py`, `_cmd_shannon`) |
| tests, incl. conformance vs real output | `backend/test_shannon_ingest.py` (53 tests) |

```bash
gn shannon ~/.shannon/workspaces
```

Prints each candidate with its class, how the class was resolved, and what would confirm
it; `--json` emits the finding dicts. Verified against Shannon's real
`benchmark/photoview-opus-5.sarif`: 24 candidates, correct abstentions, no `rce` inflation.

`backend/bughunter/shannon/` is first-party code that talks to Shannon across a process
boundary. **No Shannon file is vendored.** Shannon is AGPL-3.0 while GreyIQ's
original source is Apache-2.0; the clone lives outside the repo so its
license remains separate. Point `GREYIQ_SHANNON_DIR` at it.

## The output split (load-bearing)

A finished run leaves two tiers, and the tiers are not what the directory listing suggests.

| Surfaced to the run root (or `-o`) | Internal, under `.shannon/` |
|---|---|
| `Security-Assessment-Report.md` | `deliverables/report.json` ← **the rich findings** |
| `Security-Assessment-Report.pdf` | `deliverables/*_exploitation_queue.json` |
| `report.sarif` (exploit runs only) | `deliverables/*_exploitation_evidence.md` |
| | `auth-state.json` ← **live cookies/tokens** |
| | `scratchpad/*.png`, `workflow.log`, `agents/*.log`, `capella/` |

Two traps in that table:

1. **`report.json` is never surfaced.** The complete surfaced list is closed, at
   `apps/worker/src/services/report-output-surface.ts:164-180`. The machine-readable
   findings file stays in `.shannon/deliverables/`.
2. **`-o` replaces the workspace root, it does not add to it.**
   `apps/worker/src/temporal/activities.ts:1465-1468` picks `/app/output` *instead of* the
   workspace dir. Take a path; never assume the workspace.

### Why the import reads SARIF and not `report.json`

`report.json` is richer — true severity, confidence, reproduction steps, proof of impact.
We read the SARIF anyway, for two independent reasons.

**There is no `report.json` fixture.** Not a sample, not a test, not a golden file; upstream
has no `*.test.ts` at all. A parser written against its TypeBox schema alone would be a
parser written against bytes nobody has seen — the exact failure
`tacnoc-integration.md` refused to repeat when it blocked itself on a real capture. The
SARIF, by contrast, ships three real generated files under `benchmark/`
(`photoview-opus-5`, `photoview-grok-4-6`, `photoview-deepseek-v4-flash`: 52 results
between them), and the parser is tested against all three.

**We do not want the evidence.** Shannon's own prompt rule
(`apps/worker/prompts/shared/exploitation/_credentials-in-findings.txt`) redacts the
credentials it was *configured* with, then says the quiet part out loud — a captured
session token, an extracted key, exfiltrated data "is evidence and belongs in your
submission." So `exploitation_steps` and `proof_of_impact` carry live third-party secrets
by design. The SARIF omits both by construction (`sarif-renderer.ts`: "Exploitation steps
and proof of impact are deliberately absent"), which makes it the *safer* surface, not just
the testable one. A candidate does not need evidence; it needs a proof obligation.

Costs of that choice, accepted deliberately:

- **Severity granularity is gone.** `severityToLevel` maps both `critical` and `high` to
  `"error"` and there is no `security-severity` property, so the import stamps the band
  floor (`high`) and records `shannon_severity_band: "critical-or-high"`. Claiming a
  critical nobody measured is a fabrication; `report.resolve_severity` re-rates from the
  plan's CVSS if anything ever proves it.
- **No `confidence`.** Analysis-only runs carry it; exploit runs do not emit the key.
- **A finding with no location at all is dropped by Shannon's own renderer**
  (`sarif-renderer.ts`: `if (locations.length === 0) return null;`), so SARIF is not a
  complete view of `report.json`.
- **No fingerprints.** Shannon writes no `partialFingerprints` anywhere;
  `properties.findingId` is the only stable key, and the import refuses any result without
  one rather than synthesizing a key.

## Findings — candidates, never proofs

This is the section the whole slice exists to satisfy. `tacnoc-integration.md` §6: *"Block
the submit path for any finding whose proof status was never raised by GreyIQ's own
prover."*

The danger is specific and was easy to get wrong. GreyIQ's single confirm authority is
`report._has_captured_artifact`, and its real distinguishing signal is a populated
`observed_result` **and** `control_result` pair that differ — a captured response plus its
negative-control differential. Shannon produces exactly that shape of material, and it
believes its findings are exploited: **every result in a Shannon SARIF carries
`status: "exploited"`**, because unproven candidates never reach that file (the report
prompt's SKIP block drops `## Potential Vulnerabilities (Validation Blocked)` entirely).

So a naive import that dropped Shannon's evidence into those two fields would promote every
imported finding to `confirmed` and walk it to the auto-submit gate on Shannon's word.

Two independent mechanisms prevent it:

1. **The ingest never writes them.** `ingest.py` supplies a `proof_of_impact` dict whose
   `status` is the literal `"candidate"` and whose `evidence` / `observed_result` /
   `control_result` are empty. It carries a `proof_obligation` instead. Shannon's own
   verdict is kept as provenance under `source_detail.shannon_status`, never under a key
   the gate reads.
2. **A source veto inside the gate.** The first guard in `_has_captured_artifact` returns
   `False` for any finding whose `source` is not GreyIQ's own, unless
   `_greyiq_proved` is set — mirroring the existing `secret_classification` veto. One guard
   covers every downstream path (`investigator.has_confirming_artifact`,
   `_proof_of_impact_detail`, `qa_validate_report` Q6, `submission.build_submission`'s
   `proof_status`) and cannot drift.

Findings with no `source` are GreyIQ's own, so every pre-existing finding is unaffected —
asserted in `test_blank_and_native_sources_are_not_external`.

`source` is a new field. `tacnoc-integration.md` §6 asked for it and nothing had been built
(repo-wide grep for `tacnoc` in `**/*.py`: zero hits), so this is its first implementation.
The house pattern for a typed provenance record is
`backend/bughunter/wardrive/model.py:279-430`'s `CapabilityFact`.

### The proof obligation, and the classes that have none

An imported lead is only worth having if it states what would confirm it. But three of
Shannon's five classes are not confirmable by GreyIQ's active prover at all — `ssrf`, `auth`
and `access-control` are absent from `prover_classes.PROVER_CLASSES`. Telling an operator
to "run with `--active`" for those is an obligation GreyIQ cannot discharge, so the ingest
names the real path instead (`access_control_service`'s cross-tenant differential,
`oob_service` with a collaborator, or `jwt` as the nearest confirmable neighbour of `auth`).

### Class and CWE are resolved, never guessed

GreyIQ keys findings on CWE. Shannon emits none — only a coarse six-value `category` and an
OWASP 2025 taxon. Measured across the three benchmark SARIFs those two disagree constantly:
`shannon/auth` findings carry A01, A02, A04 *and* A07; `shannon/miscellaneous` carries six
different taxa. Neither is a usable CWE source.

What *is* usable is `properties.sastRuleId`, which in practice holds a real CWE
(`CWE-89`, `CWE-639`, `CWE-613`, `CWE-476`, …). So:

| Source | Behaviour |
|---|---|
| validated SAST rule id | exact — resolves the CWE, then the class |
| `shannon/xss`, `shannon/ssrf`, `shannon/auth`, `shannon/authz` | class-level fallback (`79`, `918`, `287`, `284` — the generic parents GreyIQ itself uses) |
| `shannon/injection`, `shannon/miscellaneous` | **abstain** |

`injection` abstains because it spans SQLi, command injection, path traversal and SSTI —
and because GreyIQ's own cortex aliases the bare word `"injection"` to `rce`
(`investigator.py:82`), so honouring it would silently turn a SQLi candidate into a
remote-code-execution claim. An abstaining finding carries no `_active_class_hint` and flows
through `bounty.py`'s existing `_classify` pass like any other unclassified finding.
`test_bare_injection_never_becomes_rce` and the conformance test both pin this.

Two CWE edges worth keeping:

- **CWE-200 is excluded from the reverse map.** In GreyIQ it means "exposed secret /
  credential" and routes into `secret_classification`, which clamps severity and owns its
  own confirm veto. In Shannon it means ordinary information disclosure. Mapping one onto
  the other would file a disclosure as a leaked credential.
- **A resolved CWE with no GreyIQ class is kept anyway**, in `source_detail.cwe`.
  `CWE-476`, `-613`, `-833` and `-209` all appear in the benchmark runs and have no GreyIQ
  class; `bounty.py`'s annotation pass overwrites a finding's own `cwe`, so that field is
  the only place the most precise fact Shannon supplied survives.

Everything Shannon wrote goes through `code_scanner.redaction.redact_text` — the same
scrubber `active_verify_service._redact` uses — because all of it is untrusted text.

## Scope — GreyIQ owns it, and Shannon cannot be told

`tacnoc-integration.md` §5 projects GreyIQ's scope into the tool. With Shannon that is not
available, and it is important to be exact about why.

**Shannon has no allowlist.** No in-scope host list, no denylist, no "do not test" list —
no such key exists in `apps/worker/configs/config-schema.json`. The only target is the
single `-u <url>`.

**Its scope-shaped config is prompt text.** `rules.avoid` accepts seven types, and the
authoritative comment at `apps/worker/src/types/config.ts:11-13` says every variant but
`code_path` "scopes network requests" — but the enforcement is
`prompt-manager.ts:379-388` substituting them into a `<rules>` block. There is no proxy, no
request interceptor and no network ACL behind `url_path` / `subdomain` / `domain` /
`method` / `header` / `parameter`. Only `code_path` becomes a real deny rule, via the pi
permission system (`permission-system.ts:7-20`) — and that gates *filesystem* access, not
traffic. `rules_of_engagement` is likewise free text "render[ed] into every prompt."

The only hard network block in the product is a preflight guard that refuses a target URL
resolving into `169.254.0.0/16` (`preflight.ts:65-79`), which explicitly allows RFC1918 and
loopback because local targets are a supported use case. It constrains the target URL at
preflight and nothing the agent does afterwards.

**If GreyIQ ever projects scope into Shannon, note the semantic inversion.**
`tacnoc-integration.md` §5 warns "never emit `wildcard` — `*.example.com` does not match the
apex." GreyIQ's own gate is the opposite: `_scope_hosts` does `lstrip("*").lstrip(".")`, so
a GreyIQ wildcard **does** match the apex. Emit the apex explicitly. Also carry
`out_of_scope_hosts` across as exclusions — in `host_in_active_scope` exclusions are checked
first and win absolutely — and never project a bare public suffix, which GreyIQ refuses via
`is_bare_public_suffix` and a naive projection of `herokuapp.com` would authorize every
tenant on it.

## Budget — GreyIQ is not the authority, and cannot currently become one

`tacnoc-integration.md` §7 is unmet, and this is the single largest piece of work remaining.

**Shannon side.** No rate limit, no request cap, no concurrency setting, no cost cap. None
of those keys exist. Concurrency is hardcoded (`CAPELLA_TRIAGE_CONCURRENCY = 4`,
`CAPELLA_AUDIT_CONCURRENCY = 2`). Cost is *tracked* (`total_cost_usd`) and printed, never
capped. The only safety switch is `exploit: "false"`, which turns off exploitation entirely.

**GreyIQ side.** `HostRateGovernor` exposes `throttle()`, which **blocks** (`time.sleep`),
and `remaining()`, which its own docstring says is "not a reservation". **There is no
`reserve(host, n)`** — confirmed by two independent passes over `backend/bughunter/`. A
blocking call is unusable as an RPC for an out-of-process engine, so nothing in GreyIQ can
hand a request allowance to Shannon today.

For scale: GreyIQ believes it caps a host at 1.0 req/s sustained with a 500 ms inter-send
floor and a 700-token process-wide ceiling, sized so that "700 covers 4 x 160 plus the
wave". Shannon, unthrottled, would make that ceiling a fiction.

**Hard ordering constraint, enforced in code and not in documentation:** no GreyIQ code path
may launch Shannon until `reserve(host, n)` exists and Shannon's egress is bound by it. The
`shannon` package is read-only by construction today — it parses files and nothing else.

### What every invariant Shannon bypasses

An external engine sending its own HTTP bypasses all of this, and nothing in GreyIQ can
observe it: `_SAFE_METHODS` (GET/HEAD/OPTIONS only — the invariant that makes GreyIQ's "safe
by construction" claim auditable), `_guard_url`, `guarded_dns_scope`'s DNS-rebinding pin,
`_NoRedirect`, same-site credential binding via `auth_headers_for`, the governor, and the
per-hunt budget. All are enforced in-process, in Python.

### The egress chokepoint (the design for slice 4)

Because none of Shannon's own config is enforcing, the containment has to sit below it, at
the one place every client it ships shares: the network.

Shannon's runtime image carries `curl`, `python3`, `bash` and Chromium, so a
browser-level control covers only some traffic. But `apps/cli/src/docker.ts:429` pins
`--network shannon-net` with no flag to change it — and Docker reuses an existing network by
name. GreyIQ pre-creates `shannon-net` with no default route and attaches its own
policy-enforcing egress proxy as the only way out. That one chokepoint delivers, for every
client at once:

- scope — refuse any host not in the projected allowlist, re-derived from
  `host_in_active_scope` rather than trusted from Shannon;
- budget — meter against `reserve(host, n)`, and fail the run (not the request) when
  refused, mirroring `_RateLimited`'s "stop the whole pass, no bursting";
- an identifying header on every request — see below;
- capture — the request/response log GreyIQ needs for evidence anyway;
- a kill switch — closing the proxy, which is the only cross-process stop that exists.

The LLM provider host must be allowlisted too, which is exactly why this is a policy proxy
and not an air gap.

### Shannon is stealth-by-default, which is backwards for authorized work

`apps/worker/src/ai/playwright-config-writer.ts` writes a Playwright config that spoofs a
Chrome UA, passes `--disable-blink-features=AutomationControlled`, and injects a script
deleting `navigator.webdriver` and faking `window.chrome` and `navigator.plugins`. Bug
bounty programs generally require the opposite — an identifying header or UA so the target
can attribute the traffic. Shannon also hardcodes `extraHTTPHeaders` to `Accept-Language`,
with no operator hook for an attribution header.

The lever: that writer **skips when a config already exists** ("so user-provided files are
never clobbered"), and the host-side `.shannon/.playwright/` directory is bind-mounted
before the container starts. GreyIQ can pre-write an honest, non-stealth, header-carrying
config and Shannon will respect it. That covers Chromium; the proxy covers `curl` and
`python3`. **Both are needed** — neither alone can prove an attribution header was on every
request, and a tool that cannot prove that should not be pointed at a third party's asset.

Also note `--security-opt seccomp=unconfined`, whose own source comment concedes it is
"container-wide … every process here runs unfiltered, the worker included — not just the
browser automation that motivates it."

## Slices

| # | Slice | Effort | State |
|---|---|---|---|
| 1 | SARIF ingest → candidate findings, the confirm veto, the submit refusal, `gn shannon` | medium | **done** |
| 2 | Cockpit surface: a Shannon tab, provenance chip, "adopt endpoints into hunt surface"; splice candidates into a hunt's `raw_findings` and append `"shannon"` to `scanners_run` | medium | not started |
| 3 | `reserve(host, n)` on `HostRateGovernor`, plus a cross-process stop signal | large | not started |
| 4 | Egress proxy + pre-written Playwright config; **then** drive Shannon from a hunt | large | blocked on 3 |
| 5 | `report.json` ingest for severity granularity and confidence | small | blocked on a fixture |

Slice 1 is independently useful: an operator who runs Shannon by hand gets its findings in
GreyIQ's queue, correctly labelled, ranked by GreyIQ's own model, feeding negative knowledge
and the lead brief, and structurally unable to auto-submit.

Slice 5 is small but must not be started early — see Blockers.

## Blockers

1. **Shannon does not run on this machine.** WSL2 is present (Ubuntu 26.04.1), but the
   Docker daemon is unreachable and Node is absent from the distro. Fix with
   `wsl -d Ubuntu -- sudo service docker start` and a Node 18+ install in that distro.
2. **Shannon's CLI refuses native Windows.** `apps/cli/src/index.ts:65-74`: *"Shannon does
   not run on native Windows." / "Run Shannon inside WSL2."* GreyIQ on Windows must drive it
   through `wsl.exe`. Do **not** reimplement the CLI's own `docker run` to dodge the refusal
   — it would fork Shannon's Temporal lifecycle and drift from upstream every release.
3. **No end-to-end run has happened.** Because of (1), the ingest is verified against
   Shannon's three committed benchmark SARIFs and synthetic fixtures, not against a run this
   project performed. Before slice 4, run a real scan against a target you own and commit
   the resulting SARIF — redacted — as a second golden file.
4. **`report.json` has no fixture** (slice 5). Writing that parser now would be fabricating
   against inferred bytes. It unblocks itself the moment (3) happens: a real run produces a
   real `report.json` at `.shannon/deliverables/report.json`.
5. **`reserve(host, n)` does not exist** (slice 3), and there is no cross-process stop
   signal in either direction — `progress._stopped` is an in-memory `set[str]` behind a
   `threading.Lock` and `Operator.stop_event` a `threading.Event`, neither reachable from
   outside the backend process.

### Handling Shannon's output on disk

Shannon's workspace is unredacted by design: `.shannon/auth-state.json` is Playwright
storage state — live cookies and localStorage for an authenticated session — present for the
whole run and left behind on a crash. Never read it, never copy a workspace into the repo,
and never into a OneDrive-synced path (both GreyIQ checkouts currently live under OneDrive).
Note also that `_atomic_write(..., private=True)`'s `0o600` buys atomicity and nothing else
on Windows; credential-bearing output there is protected only by the user-profile ACL.

## Rejected

- **Vendoring Shannon into `backend/`.** This would place AGPL-3.0 material
  inside GreyIQ's Apache-2.0 source distribution. Keep the separate process
  integration and review any proposed distribution change on its own terms.
- **Importing `report.json`'s `exploitation_steps` / `proof_of_impact` as GreyIQ evidence.**
  It is the single largest exposure in the output — raw HTTP transcripts, cookies, bearer
  headers, exfiltrated rows, password hashes — and Shannon's redaction rule explicitly keeps
  captured secrets in it. A candidate needs an obligation, not a transcript.
- **Treating `status: "exploited"` as a proof state.** It is Shannon's own verdict and it is
  on every SARIF result. Also unreliable in `report.json`, where an absent `status` is
  coerced to `exploited` (`report-json-adapter.ts:78-79, 189-196`) and an unknown string
  becomes `Exploited` too.
- **Expressing the request budget via `rules_of_engagement`.** It is prompt text with a
  1000-character cap and nothing enforces it. A budget that depends on a model choosing to
  honour prose is not a budget.
- **A loopback TCP control port for the proxy.** Same reasoning `tacnoc-integration.md`
  rejected it under: reachable by any local process, and Shannon has no authentication.
- **Widening `_SAFE_METHODS` so GreyIQ could replay Shannon's requests.** Already rejected
  in `tacnoc-integration.md`; the GET-only invariant is the auditable safety claim.

## Known defects found during this analysis

**In Shannon:**

- `sample-reports/shannon-report-{crapi,juice-shop,capital-api}.md` are in a **stale
  format**: `INJ-VULN-03`-style ids the current report prompt explicitly forbids
  ("Do not mint a new ID or insert a `VULN` segment"), a `## Network Reconnaissance` section
  the current renderer never emits, and no `Status:` / `Confidence:` / `OWASP:` rows. Do not
  derive a parser from them; use `benchmark/*.sarif`.
- `docs/development.md` documents `.shannon/prompts/` for rendered prompts. No code at this
  commit creates or writes it.

**In GreyIQ:**

- `oob_service._post_xml`'s docstring claims it is "The only non-GET egress in the engine."
  There are two — `stored_xss_service._post_form` is the other, and its own module docstring
  says so.
- `vdp_policy`'s `avoid_dos` and a program's `oob_allowed` are read only by
  `filter_findings`, for reporting. Neither is enforced at probe time. Do not inherit the
  assumption that they gate anything.

**In `tacnoc-integration.md`** (it pre-dates the code it describes, and an implementer would
act on these):

- §"Architecture" has Electron main writing the export "via the existing
  `_atomic_write(..., private=True)`". That function is Python, at
  `backend/greyiq_api.py:127`, and is not present in `electron/` — Electron cannot call it.
- It cites a 2 s cockpit poll. The hunt/campaign poll is **1200 ms**
  (`public/app.js:11125`); the 2 s one (`LIVE_BASE_MS`, `public/app.js:702`) is a different,
  app-wide notify stream.
- Its §7 `reserve(host, n)` is described as the thing to add. It still has not been added,
  so any reader treating §7 as implemented is wrong.

**Repo hazard:** `.claude/worktrees/` holds seven full copies of the repo, so a `grep -r`
from the root returns duplicate hits with wrong line numbers. Scope greps to `backend/`.
