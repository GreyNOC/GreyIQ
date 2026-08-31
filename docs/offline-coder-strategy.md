# Offline code-writing strategy — "useful code at low compute, no bigger model"

## The one idea that reframes everything

**Stop trying to make the ~0.8M-param char model *emit* code. It cannot, and every
defect the QAQC audit found on the offline path is a symptom of forcing it to.** The
product already contains the correct architecture for a low-compute offline capability —
it's just wired to the *hunt* side, not the *coding* side:

| Hunt side (shipped, blessed safe) | Coding side (what to build) |
|---|---|
| `offline_hunt.offline_plan` — deterministic, no-LLM planner over a recon **surface** | `offline_coder.plan_edits` — deterministic, no-LLM planner over a repo **surface** |
| Emits only param **names** + class orderings; a deterministic prover owns every confirm | Emits only template/anchor **edits**; the deterministic `verify` owns every "it compiles/passes" |
| `hunt_trace.record_trace` / `training_examples` — distills real Claude/Ollama runs into learned priors | `edit_trace.record_trace` — distills real Claude/Ollama edits into reusable skills/snippets |
| "can raise recall, never precision" | can raise **coverage of templated tasks, never correctness** (verify-gated) |

The offline coder's intelligence lives in **retrieval + templates + AST-constrained
edits + a verify→repair loop over the existing `ToolBox`** — all sub-second, all
deterministic. TinyGPT is demoted from "code writer" to, at most, natural-language glue
(naming, one-line explanations); the already-built-but-unused `solin_bpe.py` is what
makes even that glue tolerable. This is honest: a 0.8M model will never write a correct
function; a template library + `ast` + `py_compile` will.

## Why the char model cannot write code (the audit's proof)

- **64-*character* context** (`block_size=64`, char-level): it cannot see a full function
  signature, let alone condition on a spec.
- **~0% code in the corpus** (~99.5% English prose): it never learned brackets,
  indentation grammar, keyword syntax, valid identifiers.
- **0.84M params**: far below the scale where syntactic validity emerges even with good data.
- **The pipeline fights code on purpose**: `clean_text` strips every line's indentation;
  `_tighten_response` caps to ≤4 lines / ≤3 sentences / 360 chars; the degenerate-tail
  guard aborts on the repetition indentation/braces create; and — decisively — the
  `_response_looks_low_quality` gate rejects code-shaped text (>10% special chars, <45%
  letters) and swaps a **canned non-code fallback**. Even a lucky valid snippet is discarded.
- CPU inference caps output at ~48 chars; coding `max_new_tokens` tops out at 192 even on GPU.

## Ranked plan (impact ÷ effort)

| # | Move | Impact | Effort |
|---|---|---|---|
| **1** | Offline coding-intent short-circuit: stop generating + discarding; return an honest "configure a brain" message | High (honesty; saves guaranteed-discarded compute) | XS |
| **2** | `offline_coder.py` deterministic provider wired into the existing `ToolBox` (write/edit/verify/snapshot/undo) | Very high (the actual capability) | M–L |
| **3** | Retrieval-augment: `repomap.search_repo` + `skills.select_skills` + a new `seed/snippets/` template library feed the plan | High | S–M |
| **4** | Verify→repair loop feeding `py_compile` / `code_scanner` / test errors into the deterministic planner | High ("emitted" → "correct") | M |
| **5** | `edit_trace.py` distillation: mine real Claude/Ollama runs into replayable skills/snippets | High, compounding | M |
| **6** | Tokenizer: adopt existing `solin_bpe.py`, for **glue/routing only**, never codegen | Low (honest) | M |

**Status:** moves **1, 2, 3, and move 5's logging half are SHIPPED** (v1.8.1–v1.8.4). Move 1 (honest
short-circuit) + move 2 (`offline_coder.py` deterministic provider, wired into `run_agent`) + move 3
(retrieval + `seed/snippets/`) are live; move 5's `edit_trace.py` corpus records every verified
real-brain run (structure only, redacted). **Deferred:** move 4 (the verify→repair table — premature
while ops are pre-vetted templates that always pass verify; do it when `wrap_ast`/`insert_anchor` ops
can produce invalid code), move 5's **mining/promotion** step (cluster `edit_traces.jsonl` shapes →
auto-propose `seed/snippets/` + skills, behind a review gate), and move 6 (BPE glue).

The closed template set also includes an authorized HTTP traffic client for requests such as
"build a C2 traffic simulator script" or "create an HTTP traffic sender." It is deliberately a
transport test harness, not an implant: finite `--count`, bounded bodies/timeouts, no redirect
following, no task polling or response execution, no persistence/evasion, and no TLS-disable switch.
It exposes explicit `--user-agent`, `--ca-cert`, `--client-cert`, and `--client-key` options so private
PKI and mTLS tests remain reproducible. `--dry-run` prints a stable JSON request plan without sending
traffic.

### 1 — Stop the char model from pretending (do first)
Add a coding-intent guard in `greyiq_api.chat()` before `engine.generate_reply`: when no
brain is configured and the message is coding intent, return immediately —
> "The offline model can't write or edit code. Configure a Local model (Ollama) or Claude
> brain in Settings, then use the Workbench agent — it edits files, runs `verify`, and can undo."

This removes up to ~48 discarded forward passes per coding request (net *saves* time) and is
the honest baseline while #2 is built. Do **not** relax the code-quality gate to let
char-code through — that ships garbage; the right fix is to not generate.

### 2 — `offline_coder.py` (north star)
`run_agent` dispatches `anthropic → _run_anthropic`, `local/openai → _run_tool_loop`, and
**everything else raises "No coding brain is configured"** — that `else` is the dead end.
Add `elif provider in {"offline","deterministic"}: return _run_offline(...)`. `plan_edits`
emits a **small closed set** of deterministic `EditOp`s (not free text):
`new_file(template, slots)`, `insert_anchor(anchor, block)`, `wrap_ast(target_fn, transform)`
(stdlib `ast`-validated — rejected if it doesn't re-parse), `add_test(template)`. Anything
the intent classifier can't map → the honest "needs a configured brain" result. Applies each
op through the *existing* `ToolBox.edit_file`/`write_file` (so every write is snapshotted and
the Track-A undo/lock fixes protect it for free), then runs `_tool_verify`.

Honest scope: **scaffolds and mechanical edits** — new endpoint, test stub, Dockerfile/CI
yaml, add-import, add-field, null-check, try-wrap. It will **not** write novel business logic.

### 3 — Retrieval
Reuse `repomap.search_repo` (anchor lines), `skills.select_skills` (already a deterministic
keyword matcher), and a new `seed/snippets/` template dir (`flask_route.py`, `pytest_case.py`,
`dockerfile`, `github_workflow.yml`) with `{{slot}}` markers filled from search results +
request parse. Seed templates are trusted; workspace-supplied ones get `trust.wrap_for_model`.

### 4 — Verify→repair
`_tool_verify` already does `py_compile` / `node --check` / `bash -n` / YAML / auto-detected
`pytest`/`npm test`. Add a loop that feeds failures into a **deterministic repair table**
(unbalanced bracket → reject+re-emit; missing import → `insert_anchor`; failed scaffold
assertion → `xfail` stub), bounded to N=2 iterations, no LLM. Wire `bughunter/code_scanner`
as an extra gate: refuse to ship an edit the tool's own bug scanner flags.

### 5 — `edit_trace.py` distillation
A near-copy of `bughunter/hunt_trace.py`: append-only `edit_traces.jsonl`, one line per
**verify-passing** agent run, recording `(intent, skill, files-touched, minimal-diff-shape,
verify-result)` — structure only, `redact_text`-scrubbed, fail-closed. A mining step clusters
recurring diff shapes and (behind a review/`verify`-on-fixtures gate) promotes them to
`seed/snippets/` + `skills/*.md`, so the offline planner replays online-brain patterns it
never had to learn.

### 6 — Tokenizer (glue only, last)
`solin_bpe.py` already exists (dependency-free BPE, load-compatible with `load_vocab`), turning
`block_size=64` from ~10 words to ~250 at the same weights/compute. It does **not** make the
model write code — use it only to route between skills, fill a docstring/commit-message slot,
or explain a diff in one sentence, behind the same verify/honesty gates.

## The honest bottom line
- A 0.8M char model **cannot and should not** write code; remove codegen from that path, don't tune its gates.
- Useful **offline** code comes from a **deterministic retrieval + template + AST engine,
  verify-gated, plugged into the `ToolBox` the agent already has** — the exact pattern
  `offline_hunt.py` / `hunt_trace.py` already proved safe on the hunt side.
- Ceiling: **scaffolds and mechanical edits**, growing as real Claude/Ollama runs are
  distilled — coverage rises, correctness is never guessed (`verify` + `code_scanner` own the
  "it works" claim). Ollama/Claude remain the brains for novel logic; the offline path
  degrades **gracefully and truthfully** instead of dead-ending or emitting garbage.

Key files: `greyiq_api.py` (chat short-circuit), `agent.py` (`run_agent` dispatch + `_run_offline`,
reuses `_tool_verify`), new `offline_coder.py`, new `edit_trace.py` (mirror `bughunter/hunt_trace.py`),
new `seed/snippets/`, and adoption of `solin_bpe.py`. Reused as-is: `skills.py`, `repomap.py`,
`bughunter/code_scanner/*`, `bughunter/offline_hunt.py` (architectural template).
