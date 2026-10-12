# The offline brains

GreyIQ has to be useful with **no brain configured** — no Claude key, no Ollama, no network. That
path is what the shipped build actually runs: `build/greyiq-backend.spec` hard-excludes PyTorch, so
`solin_core` (TinyGPT) is not even importable in a release install.

This document is the map of what answers you in that state, and the rules every offline engine obeys.

## Four engines, one surface

| Domain | Engine | Entry point |
|---|---|---|
| Knowledge / chat | `solin_domain.py` + `seed/domain/*.md` | `GreyIQRuntime._domain_brain_reply` |
| Hunting | `bughunter/offline_hunt.py` (+ learned ranker) | `hunt_brain.plan_hunt` |
| Coding | `offline_coder.py` + `edit_ops.py` + `offline_repair.py` | `agent._run_offline` |
| RF / wardriving | `bughunter/wardrive/` | `gn wardrive`, `wardrive -y <path>` in chat |

`GreyIQRuntime.chat()` is the router. In order: **wardrive command → authorized scan commands** → a configured
coding brain → the codegen honesty short-circuit → the domain brain → TinyGPT (dev only) → and, if
the engine raised (which is *always* the case in a frozen install), one last domain-brain attempt
before the canned fallback.

The assessment cards in `seed/domain/assessment.md` add a fixed, cited reasoning workflow:
choose a falsifiable hypothesis, design a matched negative control, check authorization
and stop conditions, distinguish candidates from confirmed findings, and verify a fix.
When a reasoning brain is configured, chat supplies at most two short, source-labelled
excerpts from the bundled cards as untrusted reference data. The model still needs
observed evidence before it can claim a target finding.

Chat web scans require `-y --scope <exact-host>`; the scope is checked
before the first network request and again on redirects. Scoped live browser
scans currently refuse to run because Chromium's DNS connection cannot yet be
pinned to the address checked by the Python scope guard.
Remote code scan requests check `-y --scope <exact-repository-root-URL>` so a
shared forge host cannot authorize unrelated repositories. The clone itself
currently refuses to run because the Git transport cannot be kept within that
repository; scan a local clone instead.
`scan active -y --scope <exact-host> <url>` runs a single background proof pass,
bounded to 16 GET/HEAD/OPTIONS requests with time-based probes disabled. Its
result appears in chat with observed and control evidence; the command itself
does not supply evidence or certify the operator's authorization.
The short command is suitable only when the whole host is permitted. Use a saved
program hunt for path exclusions, required request markers, and other policy limits.

The first two are ordered deliberately and must not be swapped: the wardrive trigger is the more
specific one, and `scan wardrive -y ./capture` also satisfies `detect_scan_command` (unknown
subtype, remainder looks like a path → a CODE scan). Putting scan first hands an RF survey to the
source-code scanner. See the comment above `_maybe_wardrive_reply` in `greyiq_api.py`.

## The rules

**1. A plan is a hint; the prover owns every confirmation.**
`offline_hunt.offline_plan` only ever emits parameter *names*, verbatim in-scope endpoint
selections, and class orderings. Everything passes `hunt_brain._validate_plan` and is executed by
the deterministic, scope+SSRF-gated prover. The offline brain can raise recall, never precision.

**2. The offline coder never guesses correctness.**
It emits a closed set of edit ops applied through the agent's `ToolBox` (so every write is
snapshotted and undoable), and every Python result must re-parse with stdlib `ast` or the file is
left untouched. `verify` owns the "it works" claim. Ceiling: scaffolds and mechanical edits.
Anything else returns an honest `needs_brain` naming the concrete gap.

**3. The chat brain quotes; it does not generate.**
`compose_answer` returns a contiguous slice of a curated pack file plus a fixed authored opener and
a `Source:` line. `verbatim_excerpt(card) in card.body` is asserted by test — that is the mechanical
guarantee that a 0.8M-parameter char model is not writing security advice.

**4. Wardriving is read-only analysis of exports you already captured.**
No transmission, no monitor-mode control, no handshake capture, no cracking — enforced by a
source-scan test over the package's own imports. The CLI requires `-y/--authorize`, and so does the
chat command; a chat message is never authorization on its own.

**5. No fabrication.** This is the one that bites hardest in RF work.

## Undetermined is a first-class answer

WPS state and PMF (802.11w) live in fields that most capture formats simply do not export.
airodump-ng CSV carries neither. netsh carries neither. Kismet netxml carries WPS but not PMF.

So each capability fact is a `CapabilityFact(value, basis, observed_by, evidence, source_path,
source_row)`, and `AccessPoint.apply_capability_fact` **discards any fact whose observing format
cannot see that capability** (`model.CAPABILITY_SUPPORT`). Merging uses a total order that prefers a
DIRECT observation over an INFERENCE regardless of arrival order, so parse order can never change a
verdict. A finding cites the provenance of *the fact*, not of the merged record — so a WPS finding
on an airodump+WiGLE directory points at the WiGLE line that carried `[WPS]`, quoting that token.

When nothing observed the fact, there is no finding and the BSS stays in `result["undetermined"]`,
which the report renders **above** the findings so it can never read as a clean bill of health:

```
undetermined (the export cannot tell us; absence of a finding is NOT a clean bill of health):
  wps: 4 BSS - no export in this survey observed WPS for these BSS ...
  pmf: 1 BSS - no export observed the RSN Capability bits ...
```

An airodump-only survey therefore produces **zero** WPS findings and **zero** PMF findings. A
confidently wrong "PMF missing" line in a client deliverable is worse than an honest "this capture
cannot tell us", and it is the exact failure the house rule exists to prevent.

## The learned hunt ranker

`hunt_traces.jsonl` records `(surface, plan, outcomes)` per hunt. `gn train-brain` trains a
pure-stdlib logistic ranker over deterministic features and writes JSON weights — but only if it
**beats the hand-tuned rules on a held-out split**. Otherwise it refuses and says so.

GreyIQ ships **no pre-trained weights**. A model appears only once your own corpus earns one:

```bash
gn train-brain --show
```

Absent or corrupt weights mean the rules run, byte-identically. The ranker may only *permute* the
candidate classes an endpoint already produced — `offline_hunt._rank` discards any return value that
is not a permutation, so a corrupt model cannot add, drop, or invent a class.

Committing hand-written weights to make the directory look populated would be fabrication, and the
model file's own `eval` block would be a lie. Hence: no seed weights.

## Reasoning brain vs. coding capability

`offline`/`deterministic` are real, selectable **coder** providers — they scaffold and edit through
the AST ops — but they have no chat completion at all. So:

- `coder.coder_enabled(cfg)` — "is some coding capability selected?" (True for them)
- `coder.reasoning_brain_enabled(cfg)` — "is there a brain that can answer a free-form prompt?" (False)

Anything gating an **LLM prompt** must use the second. Gating on the first meant selecting the
deterministic coder took the LLM branch into a guaranteed `CoderError` and silently lost the offline
fallback — strictly worse than provider `off`. That bit both `hunt_brain.plan_hunt` (empty plan, the
hunt flew blind) and `hunt_loop._react_plan` (loop started, died at turn 0).

## Extending

**A new `gn` verb**: add a module exposing `register_cli(sub)` and list it in `gn_cli._VERB_PLUGINS`.
`CLI_COMMANDS` is derived from the parser, so the frozen exe dispatches it with no `run_frozen.py`
change. Keep the module's *import* light — it runs on every `import gn_cli`; import your engine
inside the command function.

**Packaging**: anything under `backend/bughunter/` is bundled automatically
(`collect_submodules`), as is everything under `backend/seed/`. A new **top-level** backend module
needs a `hiddenimports` entry. Never give a bundled data file a `.pt` extension — the seed walk
drops those silently, so the feature works in dev and vanishes in the release.

**Degradation is the contract**: absent or corrupt data file ⇒ behave exactly as before that file
existed. Never crash, never half-answer.
