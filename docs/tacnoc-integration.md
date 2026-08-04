# Baking TACNOC into GreyIQ

Status: **design accepted, implementation blocked on a real capture fixture.**
Audience: whoever implements the slices below.

TACNOC (repo `greynoc-tacnoc`, checkout `Desktop/GreyNOC Belcher`) is GreyNOC's
intercepting-proxy web-app research workbench. GreyIQ currently "integrates" it
with a single topbar button that spawns its executable detached and forgets it —
`launchTacnoc()` / `greyiq:launch-tacnoc` in `electron/main.cjs`, wired to
`#ckTacnoc` in `public/app.js`. No data crosses in either direction.

This document is the plan to replace that with a real feature.

## Verdict

Feasible. The enabler is that TACNOC's engine is already a clean UI-independent
facade (`TacnocSession`, `src/engine/session.ts`) sitting behind a
parity-asserted 66-method registry (`src/shared/ipc.ts` + `src/main/ipc.ts`,
`assertHandlerParity()`). It simply has no transport other than `ipcMain.handle`.

The blocker is not crypto and not transport — see [Blockers](#blockers).

## The at-rest split (load-bearing)

A TACNOC project directory (`*.tacnocproj`; `*.gnbproj` is the legacy name)
holds `belcher.db`, `blobs/`, `ca.pem`, `secrets.enc.json`.

`belcher.db` is a **plain SQLite file** — CPython opens it at `mode=ro` and
reads the schema. But the contents are split:

| Plaintext (searchable) | AES-256-GCM sealed |
|---|---|
| `url`, `method`, `host`, `port`, `scheme` | `req_headers`, `res_headers` |
| `status_code`, `mime`, timings, `tags` | `req_body_inline`, `res_body_inline` |
| `in_scope`, `source`, `automated`, sizes | blob files under `blobs/` |
| all of `findings`, `suppressions`, `audit_log`, `project_meta` | `notes`, WebSocket payloads |

Sealing is under a per-project 32-byte DEK held in the SecretStore and wrapped
by Electron `safeStorage` (DPAPI on Windows). `docs/project-format.md` in the
TACNOC repo states this explicitly.

**Naming trap:** `req_body_enc` / `res_body_enc` do *not* mean "encrypted". They
hold the wire `Content-Encoding` (e.g. `gzip`) — bodies are stored exactly as
they came off the wire, still compressed
(`historyRepo.ts`, `req.body.contentEncoding ?? null`). Any consumer must gunzip.

## Architecture

> GreyIQ owns authorization and the request budget.
> TACNOC owns capture and stays the only writer to its own project.

Two data paths and one control plane. **GreyIQ's Python backend never touches a
`.tacnocproj` directory.**

### 1. Batch evidence path — headless `ProjectExportV1`

Add argv handling to TACNOC's `src/main/index.ts` before `createWindow()`:

```
--export-project <projectDir> --out <file>
  -> session.openProject(dir) -> session.exportProject() -> write JSON -> app.exit(0)
```

No window, no proxy, no packet. It runs *inside* Electron, so
`ElectronSecretStore` unwraps the DEK legitimately and bodies come out
decrypted. GreyIQ's Electron main spawns it, writes to
`RUNTIME_DIR/tacnoc/<id>.json` private-mode via the existing
`_atomic_write(..., private=True)`, POSTs it to the backend, then deletes it.

The export format is already versioned and portable: `greynoc-belcher-project`,
`PROJECT_FORMAT_VERSION = 1`. The importer must assert
`format === 'greynoc-belcher-project'` and refuse a higher `formatVersion` with
an actionable message, exactly as `ProjectStore.import` does — never
best-effort a newer export.

### 2. Live control plane — GreyIQ serves, TACNOC dials out

A duplex NDJSON JSON-RPC 2.0 channel. GreyIQ's Electron main creates a Windows
named pipe (`\\.\pipe\greyiq-tacnoc-<uuid4>`) / unix domain socket, mints a
per-launch token, and passes both **via env at spawn** — never argv, never from
the renderer, preserving the existing invariant that no renderer-controlled path
or command-line argument crosses IPC.

TACNOC gains `src/main/controlChannel.ts`, which activates only when both
`GREYIQ_CONTROL_PIPE` and `GREYIQ_CONTROL_TOKEN` are present, connects *out*,
and authenticates in its `initialize` frame.

Inverting the listener is the load-bearing choice. TACNOC gains **no new
listening socket**, so its threat model's "the intercepting proxy is the only
listener" survives. A loopback TCP control port would be reachable by any local
process, and TACNOC has no authentication anywhere — that is a posture
regression, and it is why option (d)-as-stated was rejected.

### 3. Method surface — reuse, don't reinvent

Refactor `registerIpc()` into an exported
`dispatch(session, getWindow, method, args)` with two bindings: the existing
`ipcMain.handle`, and the control channel. Add `EXTERNAL_METHODS` to
`src/shared/ipc.ts` as a strict subset of `INVOKE_METHODS`, with its own parity
assertion (`EXTERNAL ⊆ INVOKE`).

**Allowed** (read + scope + safety): `getProjectInfo`, `getScope`, `setScope`,
`getTargetMap`, `listFindings`, `listSuppressions`, `queryHistory`,
`getExchangeDetail`, `listWsMessages`, `historyCount`, `listAudit`,
`getProxyStatus`, `scannerModules`, `emergencyStop`.

**Forbidden**: the dialog/file-bound methods (`pickDirectory`, `createProject`,
`exportProjectToFile`, `importProjectFromFile`, `saveCaCertificate`,
`loadExampleExtension`), the destructive ones (`clearHistory`, `closeProject`),
and — until the shared budget lands — every traffic primitive (`sendRepeater`,
`createVariationJob`, `runVariationJob`).

### 4. Events, CSP, preload

The 15 forwarded session events ride the same channel as JSON-RPC
notifications. GreyIQ's main relays `exchange` / `finding` / `scope-changed`
into the Python backend, which republishes via `progress.global_log()`. The
cockpit's existing 2s poll carries it — no second poller, no SSE.

`connect-src 'self'` stays as-is, which makes renderer→TACNOC impossible by
construction. All TACNOC data reaches the cockpit through `apiFetch()` on new
`/api/tacnoc/*` routes gated by `_session_authorized()`. No path, port, or token
ever crosses into the renderer, and nothing is written to `state` — localStorage
is plaintext.

### 5. Scope — one source of truth, two enforcers

GreyIQ owns authorization and projects it *into* TACNOC via `setScope`: each
in-scope host token becomes
`{hostMatch: 'subdomain', host: token, schemes: [], ports: []}`, each exclusion
an identically-shaped exclude rule.

Never emit `wildcard` — `*.example.com` does not match the apex. Never emit a
rule for an empty token; an empty include list is the correct fail-closed
outcome, a `{host: ''}` rule is not.

TACNOC's `inScope` flag on an imported exchange is a **hint**. Every adopted URL
is re-gated through `host_in_active_scope` before any probe.

Refuse to import a TACNOC `ScopeConfig` whose rules contain a scheme, slash, or
`@` — real projects on this machine contain rules like
`{hostMatch: 'subdomain', host: 'https://www.tiffany.com'}`, which `normalizeHost`
does not strip, so they silently never match. Surface it as a TACNOC defect;
do **not** auto-normalize, because stripping the scheme would *broaden* a gate
TACNOC currently treats as closed.

### 6. Findings — candidates, never proofs

TACNOC's 11 passive modules emit header/cookie/CORS-class observations. Severity
is byte-identical to GreyIQ's enum; confidence maps `certain` →
confirmed-eligible, `firm`/`tentative` → candidate.

Import at `proof: candidate`, `source: "tacnoc"`, carrying `moduleVersion` for
provenance, rendered with a provenance chip in both the Class cell and the
detail badge row. Block the submit path for any finding whose proof status was
never raised by GreyIQ's own prover.

Import evidence via raw `bodyBase64` from `getExchangeDetail`, **not** via
`Finding.evidence[].excerpt` — that excerpt is masked to the bare constant
`[REDACTED]`, which destroys GreyIQ's `sha256:12` correlation tag and its
live-credential validation. Classify raw, redact once at artifact-render time.

### 7. Budget — GreyIQ becomes the authority

Today TACNOC's variation engine builds a fresh per-job `TokenBucket` at 8 req/s
with burst 8 and no per-host keying, while GreyIQ believes it is capping the
same host at ~0.5 req/s sustained with a hard 20-request ceiling. That is a
~17x overshoot with neither side able to see the other.

Add a non-blocking `reserve(host, n) -> bool` to `HostRateGovernor` without
disturbing `throttle()`'s sleep semantics, and serve `budget.reserve` from
GreyIQ over the same control channel in the reverse direction.

**Hard ordering constraint, enforced in code and not in documentation:** no
traffic-generating method may appear on `EXTERNAL_METHODS` until this lands.

## Slices

| # | Slice | Effort |
|---|---|---|
| 1 | Headless export → TACNOC cockpit tab (candidates only) + "Adopt endpoints into hunt surface" | medium |
| 2 | Control channel + scope projection (GreyIQ → TACNOC) | medium |
| 3 | Live event relay + shared finding-adoption helper | medium |
| 4 | Authenticated session handoff (real proxied login replaces pasted cookies) | small |
| 5 | Shared per-host budget, **then** drive-capability | large |

Slice 1 is independently shippable and is what turns the launch button into a
feature: the operator captures traffic through a real authenticated browser
session, clicks once in GreyIQ, and the cockpit gains a TACNOC tab showing
captured sites, endpoints with real methods/params/status codes, and TACNOC's
passive findings as clearly-labelled candidates.

Slice 4 is where the value compounds: authenticated surface is where the
high-severity access-control and IDOR findings actually live, and
`account_login_service._playwright_login`'s own docstring concedes it fails on
JS-heavy and CAPTCHA-guarded logins. A real proxied session does not.

## Blockers

1. **No populated TACNOC project exists on this machine.** Every project checked
   has zero exchanges, zero findings, and an empty `blobs/` tree. Every claim
   about how a populated `ProjectExportV1` looks on the wire — sealed column
   framing, gzip bodies, blob spill at 5 MiB, truncation flags — is
   source-verified only.

   Before a line of ingest code is written: run TACNOC, capture 20–50 real
   exchanges against a benign in-scope target you own (include at least one gzip
   response, one body over 5 MiB to force blob spill, one POST with a body, and
   one WebSocket), run the new headless export, and commit the resulting JSON —
   redacted, or a synthetic re-capture against a local test server — as the
   parser's golden fixture. Writing the parser first would be fabricating
   against inferred bytes.

2. **Export is unredacted by design.** It will contain live session cookies and
   `Authorization` headers. Write only to `RUNTIME_DIR/tacnoc/`, never the repo
   and never a OneDrive-synced path (note both GreyIQ checkouts currently live
   under OneDrive). Delete in a `finally` block. Never attach an export to a POC
   or report bundle.

## Rejected

- **(a) Python reads the `.tacnocproj` SQLite directly.** It only ever sees half
  the data — headers and bodies are sealed. Getting the key means DPAPI against
  the Electron os_crypt master key, which is Windows-only, same-OS-user-only,
  and deliberately falsifies a security property TACNOC's own docs publish.
  Concurrency is also unfixable: `node-sqlite3-wasm` uses a *directory* lock
  (`belcher.db.lock` via `mkdirSync`) that CPython's byte-range locking cannot
  see, and `journal_mode` is `delete` (WAL is impossible under the WASM VFS), so
  a read landing mid-write returns a malformed image or an inconsistent
  snapshot. The headless export gets the same data decrypted, versioned, and
  race-free.
- **(b) Ship a TACNOC extension via its SDK.** There are six grantable
  permissions and none grants filesystem, network, process, or secret access, so
  the extension physically cannot call GreyIQ's backend. `onTraffic` omits
  bodies and pre-redacts headers and URLs. `ui-tabs` registrations are validated
  and then never rendered. And `loadExtension` is absent from the IPC allowlist.
- **(c) Spawn TACNOC's MCP server and call its tools.** It is a calculator, not
  a data source: all 8 tools are pure functions over caller-supplied strings,
  with nothing from `storage/` or `ca/` in the emitted build. It cannot see a
  single captured exchange. Keep it as-is for Claude Code.
- **Widening `active_verify_service._SAFE_METHODS` to replay captured
  POST/PUT bodies.** The GET-only invariant is what makes GreyIQ's "safe by
  construction" claim auditable. Replaying a captured non-GET request is a
  genuine capability change requiring a new opt-in prover that re-derives scope,
  SSRF, and governor itself.

## Known defects found during this analysis

- TACNOC's `SECURITY.md` is stale in two ways an integrator would act on: it
  claims no external calls (false since the AI mesh posts tool results to the
  Anthropic API behind an `egressAcknowledged` gate) and claims at-rest
  encryption "is not yet implemented" (false since `ContentCipher` shipped — it
  contradicts `THREAT_MODEL.md` in the same repo).
- TACNOC's `audit_log` has no hash chain, signature, or integrity column, and
  has blind spots: proxy start/stop, every Repeater send, `setScope`, CA export,
  and project open/export are unaudited. Export also caps audit at the last 5000
  rows. Do not rest a bounty report's reproducibility claim on TACNOC audit
  rows; GreyIQ should audit its own side at ingest and set the TACNOC-side actor
  to `greyiq:<hunt_id>` so the two records can be joined.
