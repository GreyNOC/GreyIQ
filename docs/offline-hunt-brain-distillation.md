# Offline hunt brain — distillation & learned-ranker design

**Goal:** give GreyIQ's *offline* hunt reasoning (the no-LLM path in
`backend/bughunter/offline_hunt.py`) genuinely more skill, at low runtime compute,
**fully offline**, with capability that grows as the program earns bounties.

**Constraints (chosen by the operator):**

- Primary target = the **offline hunt brain**, not general chat/coding.
- **Stay tiny / pure** — no 7–14B model at runtime, no network call during a hunt.
- Willing to **build a training/distillation pipeline** (training may use a big
  model and the GPU; the *shipped weights* run offline).
- Priorities = **privacy/offline** (nothing leaves the machine at hunt time) and
  **capability** (be measurably smarter than the hand-tuned rules).

---

## 1. The core reframe: this is structured prediction, not language modeling

The offline brain must emit exactly the shape `hunt_brain.plan_hunt` returns:

```
{ param_hypotheses:   [param NAME, ...],           # bounded vocab of real param names
  probe_priority:     [{endpoint, classes, why}],  # SELECT an in-scope endpoint + RANK 10 classes
  idor_candidates:    [endpoint, ...],             # SELECT from discovered endpoints
  privileged_endpoints:[endpoint, ...],            # SELECT from discovered endpoints
  ssrf_params:        [param NAME, ...],           # bounded vocab
  xss_params:         [param NAME, ...] }           # bounded vocab
```

Every field is either a **selection/ranking over inputs we already have** or a
**name from a bounded vocabulary**. There is no open-ended prose to generate
(`why` is cosmetic and can be templated). Therefore:

> **A GPT — char-level *or* a distilled 30M BPE transformer — is the wrong tool.**
> The task is ranking + classification + constrained name suggestion. The right
> tool is a handful of **small learned scoring functions** that replace the
> hand-guessed constants in `offline_hunt.py`, trained on real hunt outcomes.

Footprint of the learned models: **hundreds of KB**. Inference: **microseconds**,
CPU-only, zero network. This is *smaller and faster* than the current TinyGPT, not
bigger — and far more accurate on this task because it learns from ground truth.

The current TinyGPT (`solin_core.py`, 0.8M char-level) stays exactly where it is:
the general-chat offline fallback. It is not on this path.

## 2. How this realizes the "zip → compute → extract" idea (no quantum needed)

| Intuition            | Mechanism                                                        |
|----------------------|-----------------------------------------------------------------|
| heavy burst compute  | offline training over all hunt history + LLM teacher traces     |
| "zip it"             | compress learned skill into a few-hundred-KB weight file        |
| "extract" cheaply    | microsecond inference at hunt time — offline, no big model      |
| gets better over time| retrain on new `accepted`/`resolved`/`bounty` outcomes          |

Quantum computing does not help here (no local QPU; no speedup for this workload;
measurement collapses state so you can't "extract" a full answer). But the
underlying instinct — *compute the expensive thing once, compress it, extract it
cheap at runtime* — is exactly the distillation pattern below.

## 3. Architecture — the distilled offline hunt brain

Replace the hand-tuned pieces of `offline_hunt.offline_plan` with learned models,
keeping the **identical output shape and the identical safety contract**. Drop-in:
`plan_hunt` still calls one function that returns the same dict; only the internals
of scoring change, and it stays behind `_validate_plan` + the prover gate.

### 3a. Endpoint→class ranker (highest value, lowest cost)
Replaces `_classes_for_endpoint` + `_TECH_CLASS` + `_reorder_by_priors`.

- **Input features (all cheap, deterministic, from recon):** path tokens/segments
  (login, admin, download, search, api, `.json`, numeric/uuid segment), parameter-
  name features (hits against the existing hint tables as *features*, not verdicts),
  tech-stack one-hots, form method/field cues, and the existing `learned_priors`
  for the program.
- **Model:** gradient-boosted trees or logistic regression per class (10 classes) —
  or one small multi-label model. Sub-1 MB. Outputs a calibrated score per class per
  endpoint → produces `probe_priority` ordering directly.
- **Label:** did that class **confirm** on that endpoint (from the ledger), weighted
  up if it **paid** (`bounty > 0`).
- **Why it beats hand-rules:** it learns *interactions* the flat hint lists can't
  (e.g. "`id` param **and** PHP tech **and** `/search` path → SQLi confirms often").

### 3b. Param-name suggestion model
Replaces the static `_SUGGEST` set and the hint-list membership tests.

- **Model:** a learned conditional frequency / nearest-neighbor table:
  `P(param_name | endpoint-purpose-bucket, tech)` built from param names seen on
  confirmed findings. KB-scale. Emits `param_hypotheses`, and ranks
  `ssrf_params`/`xss_params` by learned association with SSRF/XSS confirmations.
- Only *new* names (not already in recon) are added — same rule as today.

### 3c. Object/priv-endpoint selectors
Replaces `_NUMERIC_SEG_RE` / `_UUID_SEG_RE` heuristics and `_PRIV_PATH_HINTS` for
`idor_candidates` / `privileged_endpoints` with small binary classifiers over the
same path/param features, labeled by IDOR/BFLA confirmations.

### 3d. (Optional, later) tiny generative fallback
Only if 3a–3c leave a real gap in *inventing param names never seen in training*.
A small BPE model (~10–30M, distilled from Claude plans, ~15–60 MB int8, CPU-OK) —
but expect the frequency model in 3b to cover most of this. Deferred by default.

## 4. Three teachers — and why *outcomes* are the gold

The student can learn from three signals, in increasing quality:

1. **The rules themselves** (`offline_hunt.offline_plan`) — a *prior* / bootstrap
   so the student is never worse than today. Distilling rules alone is pointless;
   use them only as a floor and for cold-start.
2. **LLM teacher traces** — run `hunt_brain.plan_hunt` with Claude/Qwen over many
   surfaces to generate rich gold plans. **Training-time only**; shipped weights
   never call out. Great for coverage before real outcomes accumulate.
3. **Real hunt outcomes (the gold)** — `(surface → what actually confirmed/paid)`
   from `ledger.py` + `learning.py`. This is what lets the student **exceed both
   teachers** on the only axis that matters: what turns into a real, paid finding.

Training curriculum: bootstrap on (1)+(2), then continually fine-tune on (3).

## 5. Data pipeline & the one real gap

**Already persisted (durable, the label side):**
- `ledger.py` → per finding: `class_id`, `source_url`, `proof_status`, `stage`
  (discovered→confirmed→reported→submitted→paid), `bounty`, `captured_proof`.
- `learning.py` → per program/class `submitted/rewarded/noise/bounty_total` and
  `learned_priors` (already a reward multiplier in ~[0.5, 2.0]).

**Gap (the input side):** the full recon **surface** (endpoints/params/tech/forms)
that fed each plan, and the **plan that was proposed**, are not logged as a joined
training triple. `ledger` keeps one `source_url` per finding, not the whole surface.

**Phase 0 fix (small, additive, non-invasive):** at hunt time write one JSONL line
per hunt — `hunt_traces.jsonl` under the runtime dir:
```
{ ts, program_key, surface: {endpoints, params, tech, forms},
  plan: {param_hypotheses, probe_priority, ...},
  outcomes: [{endpoint, class, proof_status, bounty}] }
```
Emit it where `plan_hunt` is called in `hunt_loop`/`campaign`, then backfill
`outcomes` from the ledger by dedup key. This is the training corpus. Scrub/keep it
local (privacy). No runtime cost.

You do **not** wait for this to fill up: bootstrap from teachers (1)+(2) immediately,
and let (3) sharpen the model as traces accumulate.

## 6. Safety — why an imperfect student is still 100% safe

Unchanged from today, and it's the whole reason this is low-risk:

- The brain's output passes `hunt_brain._validate_plan`: param names regex-checked
  (never a URL/payload), endpoints must be **verbatim in-scope**, classes must be in
  the prover's allowlist.
- The **deterministic, scope+SSRF-gated prover owns every confirmation** — a plan is
  a *targeting hint*, never a finding.
- Net: the learned model **can only raise recall, never precision** (the
  `offline_hunt` docstring's existing invariant). A 70%-good student wastes a little
  probe budget at worst. **Ship early, improve continuously.**

## 7. Phased build plan

- **Phase 0 — trace logging. ✅ SHIPPED.** `backend/bughunter/hunt_trace.py` appends
  one `hunt_traces.jsonl` line per hunt (recon surface + plan + confirm outcomes), an
  immutable append-only corpus with a lazy ledger join (`training_examples`) for the
  final stage/bounty. Wired into BOTH hunt paths: `campaign._run_campaign_body` (covers
  `run_campaign`, spans, portfolios) and the standalone `bounty.run_bounty_hunt` (the
  guard `hunt_trace_plan is not None` avoids double-logging the campaign-driven per-URL
  path). Fail-closed (a trace write never breaks a hunt) and payload/secret-free by
  construction. Visible via `gn traces` (+ `--json`). Tests: `test_hunt_trace.py`,
  `test_campaign.py::test_url_campaign_writes_hunt_trace`, `test_gn_cli.py`. *Deferred:
  the iterative re-plan loop (`hunt_loop._react_plan`) is not yet traced — it has no
  `runtime_dir`/program in scope; tracing per-turn refinements is a later enhancement.*
- **Phase 1 — teacher corpus + feature extractor.** A deterministic
  `surface → feature-vector` function (reuse the existing hint tables *as features*).
  Generate teacher plans from the rules and (optionally) Claude. ~2–3 days.
- **Phase 2 — endpoint→class ranker (3a).** Train, calibrate, and wire it behind a
  `use_learned_ranker` flag inside `offline_plan`; fall back to rules if the model
  file is absent (frozen-safe, offline-safe). First measurable capability win.
- **Phase 3 — param-name model (3b) + selectors (3c).** Complete the learned plan.
- **Phase 4 — outcome fine-tuning loop.** Retrain on `hunt_traces.jsonl`; add an
  offline eval (recall@k of confirmed classes vs. the current rules) as the metric.
- **Phase 5 (optional).** Tiny generative param-name fallback (3d) only if evals show
  a novel-name gap.

**First shippable milestone:** Phase 0 + Phase 2 — trace logging plus a learned
class ranker that beats the hand-tuned ordering on held-out confirmed outcomes.

### Phase 0 known limitation — program keying across paths

The standalone `run_bounty_hunt` has no program handle in its signature, so its traces key by
`program_key(None, target)` = the target's registrable domain; a campaign with an explicit
`--program` handle keys by that handle. So the same real program hunted both ad-hoc (`gn hunt`)
and under a named campaign can appear under two different `program` keys in the corpus. This
mirrors how `ledger.py`/`learning.py` already key an ad-hoc run, and it does **not** affect the
training join — `training_examples` joins to the ledger by `dedup_key`, not by program — so the
only impact is per-program grouping in `gn traces`. Threading a program handle through
`run_bounty_hunt` (and the API/CLI) would unify it; deferred as out of Phase 0 scope.

## 8. Honest limits

- This makes the brain a **better targeter**, not a reasoner. Novel business-logic
  bugs that need genuine multi-step reasoning still want the LLM brain (Claude/Qwen)
  — which the operator opted out of at runtime. That ceiling is real and accepted.
- Cold start: with little history, the student ≈ the rules (by design). Value grows
  with hunt volume and the teacher corpus.
- Keep the models versioned + frozen-safe: absent/corrupt model file must degrade to
  the current rule engine, exactly like the existing fail-closed contract.

## 9. Model/runtime footprint summary

| Component            | Size      | Runtime      | Offline | Trains on            |
|----------------------|-----------|--------------|---------|----------------------|
| endpoint→class ranker| < 1 MB    | microseconds | yes     | confirmed outcomes   |
| param-name model     | KB        | microseconds | yes     | confirmed param names|
| object/priv selectors| < 1 MB    | microseconds | yes     | IDOR/BFLA confirms   |
| (opt) generative     | 15–60 MB  | ms, CPU      | yes     | Claude teacher plans |

Total default footprint (3a–3c): **a few hundred KB to ~1–2 MB** — smaller than the
current TinyGPT, and it never touches the network during a hunt.
