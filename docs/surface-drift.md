# Surface-drift engine

`backend/bughunter/surface_drift.py`

Every other engine in GreyIQ reasons about **one moment**. Recon maps the surface, the prover
probes it, the cortex weighs the evidence, the chain engine composes it — and then the run ends
and all of it is thrown away. `operator.OperatorLoop` re-runs whole campaigns on a cadence, and
each cycle rediscovers the world from scratch.

So the engine could not notice the single highest-signal event in bug bounty: **something
changed**. A newly deployed endpoint, a JS bundle that grew an API route, an auth gate that came
off `/admin` in a refactor, a security header that disappeared, a response that grew an
`is_admin` key. Asset monitoring and JS-change alerting are staple human techniques, and none of
them had any representation here.

This engine is the hunt's memory.

## Model

| Concept | Meaning |
|---|---|
| **observation** | one crawled URL's name-only response shape: status, a magnitude bucket for length, a structure fingerprint, present security headers, cookie names + flag letters |
| **snapshot** | every observation for one `(program, host)` in one run, plus the surface lists and the chains that run left **blocked** |
| **delta** | a typed change between the last snapshot and this one, with a decayed score |

The store is an append-only JSONL under the runtime dir, ring-buffered to eight snapshots per
key, sitting beside `hunt_traces.jsonl` and the ledger. Nothing leaves the machine.

### The fingerprint is the whole ballgame

Hashing the body is the naive failure mode: it moves on every request on any real site
(timestamps, CSRF nonces, prices, ad ids), so every run would report that everything changed and
the engine would be pure noise.

Instead the fingerprint hashes the **name-only structure** the response digest already extracts —
JSON key names, form field names, the error family, the JWT algorithm, which security headers are
present. A price change does not move the hash; a new `is_admin` key does.

Two guards keep it honest:

- **A truncated fingerprint is never compared.** The digest caps its key extraction and fills that
  cap in *encounter order*, so two runs over the same unchanged response can legitimately keep
  different key sets. A capped observation is stored but excluded from shape diffing — sorting
  before hashing is not sufficient, because the *set* differs.
- **A redeploy is one row, not a hundred.** If most shared URLs change shape at once, that is a
  release, not a signal about any one of them, and it collapses to a single row.

## Zero new requests

This is the engine's primary safety property, and it is **structural rather than enforced**. Every
observation is derived from a response `recon.discover` already fetched and currently discards;
this module makes no HTTP request, so it has no method, no host and no URL of its own. The scope
gate, the SSRF guard, the per-host governor and the request budget are untouched by construction,
and denial-of-wallet is not merely capped but impossible. A contract test scans the module source
for every egress symbol to keep it that way.

The only change to `recon` is an additive, default-off `observe=True` flag: it keeps what was
already in memory instead of dropping it.

## What it changes about a hunt

| Surface | What it gets |
|---|---|
| `bounty` (active recon) | up to **2 of the 4** probe slots go to what changed, so a fixed budget stops being spent on the same hot-word URLs every run — a stable target still gets normal coverage |
| `investigator.chain_probes` | **re-opened chains** (`CR1`…): a chain blocked for N runs whose missing capability a delta may have just supplied |
| `next_steps` | a "What changed" phase, first, because being early on a change is most of the edge |
| `report` | a **Surface drift** section, deliberately far from the findings table |
| `report.build_json` | a `drift` key and `stale_proofs` |

### Re-opening a blocked chain is the payoff

`build_attack_chains` already computes which step a chain is blocked on and which capability that
step would have granted — and then throws it away at report time. So a chain blocked at step 2 on
`disclose.identifier` in run N-1 is re-derived identically and re-blocked in run N, **even when
run N's surface just started leaking object identifiers**.

The snapshot persists `{shape, impact, blocking_step, needs}` for each blocked chain, and the next
run matches this run's deltas against the missing capability through `_CAPABILITY_UNBLOCKERS`:

> AC1 (unauthenticated → read another tenant's data) has been blocked at step 2 for 4 runs,
> waiting on `read.other-object`. This run's JS bundle changed and now exposes
> `/api/v2/orders/{id}` — go test step 2.

Chain identity is the chain's **shape** (impact plus its ordered technique ids), never its
rendered id: `AC1` is a position in one report's sorted list and is reassigned at every render, so
keying the matcher on it would match whichever chain happened to rank first this time.

## Honesty invariants

All enforced by contract tests in `backend/test_surface_drift.py`:

- **A delta is never a finding.** The module returns no finding dicts and sets no severity, class
  or ref. A hunt's reportable findings are byte-identical with drift present and absent.
- **A delta never confirms anything.** It deliberately emits **no chain-engine signal at all**: a
  statement that something *changed* is not a statement that anything is exploitable, and the
  chain layer's whole discipline is that steps rest on observations of the target's behaviour
  rather than on inferences about its history.
- **A re-opened chain is a probe, not a chain.** It carries `status: untested`, joins the probe
  queue, and never inherits the confidence of the run that built it.
- **A missing baseline is not a clean baseline.** A first run reports `first-observation`, never
  "surface stable" or "no changes detected" — the operator must be able to tell *stable* from
  *never looked*.
- **A degraded baseline is refused, not diffed**, and so is a degraded *run*. A prior run cut
  short by a WAF, an outage or an exhausted budget would make every URL it missed look new; below
  half this run's coverage, the diff is declined outright. The mirror case is the more dangerous
  one: when *this* run is the degraded one there are no shared URLs left to compare, so every
  behavioural delta is structurally undetectable and the diff would return zero — which renders as
  an all-clear. That returns `degraded-run` instead, and such a run is not stored as the next
  baseline. "We could not look" must never read as "nothing changed".
- **Absence is never evidence of a fix.** An endpoint that stopped answering, or that started
  returning 401, is an observation explicitly annotated as *not* a verified remediation. Nothing
  here closes a finding or advances a ledger stage.
- **Decay is monotone.** A delta that persists never scores higher than the run it first appeared
  in — a change that has sat there for six runs has already been looked at, and re-shouting about
  it at full volume is how a change feed stops being read.
- **Shapes are names, never values.** Names, flag facts, status codes and a hash; body length only
  as a magnitude bucket; every stored string passes the shared redactor.
- **Identity is scope-bound.** Snapshots are keyed by `(program, host)`; a diff never compares
  across hosts or programs.

The module is pure stdlib, deterministic, bounded on every dimension, and total — every entry
point degrades to an empty result rather than raising, because it runs inside a hunt and must
never cost one.

## Known limits

- **Behavioural deltas cover only the URLs recon actually fetched.** Measured against a live
  target: recon spends its request budget on a constant list of well-known paths
  (`/swagger.json`, `/.well-known/…`) *before* walking the links it just discovered, so on that
  run 17 of 18 fetches were 404s and neither `/admin` nor `/api/me` was ever fetched — they were
  discovered, listed, and never looked at. Those not-found rows are now filtered out (an
  observation describes a surface that *exists*), so the store is clean, but the consequence
  stands: a status or shape change on a discovered-but-uncrawled URL is invisible. Structural
  deltas (`endpoint.new`, `param.new`, `form.new`) still cover them, because those come from the
  discovery lists rather than from fetches. Rebalancing recon's crawl order would fix it and is a
  wider behavioural change than this engine should make on its own.
- The substrate is a 6–12 URL crawl per run. That is thin for the asset-monitoring technique this
  emulates; the engine gets sharper the wider the crawl, and a campaign's larger crawl feeds it
  better than a single hunt's.
- There is **no revisit mode**. Re-fetching a previously-seen URL that nothing links to any more
  (did the gate come off `/admin`?) is the highest-value observation the crawl can miss, and it is
  deliberately left out of v1 so that "this engine issues zero requests" stays an unqualified
  structural fact rather than a flag someone can turn on.
- A program hunted standalone and then under a named campaign accumulates two `program_key`
  buckets that never diff against each other. Snapshots are keyed by `(program_key, host)`, so the
  host half still matches within each bucket.
