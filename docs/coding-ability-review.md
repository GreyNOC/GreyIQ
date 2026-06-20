# GreyIQ coding-ability review

A grounded read of the coding brain (`backend/coder.py`) and agent loop
(`backend/agent.py`), with prioritized recommendations. The architecture is
clean and the safety story is strong — the gaps below are about *capability* and
*perceived responsiveness*, not correctness.

## What's already good (keep)

- **Clean provider abstraction** (`coder.py`): `local` (Ollama), `anthropic`,
  `openai`, and `off` (TinyGPT fallback) behind one `generate()`. Claude uses
  adaptive thinking + `effort` and retries without them on older models. Error
  messages are actionable (model-not-pulled vs. outdated-Ollama are kept
  distinct).
- **Solid agent loop** (`agent.py`): plan → act → verify, workspace-confined
  paths, a hard command denylist on top of the `allow_commands` gate, trust
  scanning of file reads (prompt-injection defense with an untrusted-data
  wrapper), before/after change tracking, full-snapshot one-click rollback, and
  repo-map + skills + project-memory injection. It even recovers tool calls that
  weaker local models emit as `<tool_call>` text.

## Recommendations (prioritized)

### P0 — high leverage, low risk — ✅ implemented

1. **Stream tool events.** ✅ Done. The agent now takes an optional `on_event`
   callback (`run_agent` → `_run_anthropic`/`_run_tool_loop`) that fires a `plan`
   event and a `step` event per tool call. The API runs the agent on a background
   thread and buffers events (`start_agent_run` / `agent_run_events`, endpoints
   `POST /api/agent/stream` + `/api/agent/events`); the UI polls and renders the
   Workbench **Agent Steps** panel live (`runAgent` in `public/app.js`), matching
   the existing model-pull streaming pattern. Falls back to the one-shot
   `/api/agent` if streaming is unavailable. *(Future: token-level streaming of
   the final summary on top of step events.)*
2. **Claude prompt caching.** ✅ Done. `_run_anthropic` marks the system block
   (which the workspace + repo map + skills + memory feed) as an ephemeral cache
   breakpoint — caching the whole tools+system prefix that's resent every step —
   with a fallback to a plain string system prompt if a model rejects
   `cache_control`.
3. **Retry/backoff.** ✅ Done. `coder.with_retries` wraps the Ollama/OpenAI
   `urlopen` calls with bounded exponential backoff (1s/2s/4s) on retryable
   statuses (429/5xx/timeout) only — never on auth/bad-request. The Anthropic SDK
   paths set `max_retries` so the SDK backs off natively.

### P1 — capability gains

4. **Make `edit_file` less brittle.** It requires an exact, unique substring and
   fails on non-unique or whitespace-mismatched matches — a top failure mode for
   weaker local models. Add (a) an occurrence index / `replace_all`, (b) optional
   whitespace-tolerant matching, and (c) a `multi_edit` tool to batch edits to one
   file. Consider an `apply_patch` (unified-diff) tool as an alternative surface.
5. **Deepen `verify`.** Today it's `compile()` for `.py`, `json.loads` for
   `.json`, plus one optional shell command. Add pluggable per-language checks
   (`node --check`, `tsc --noEmit`, `ruff`) and auto-detect a test command from
   the project so "verify" means more than syntax on two file types.
6. **Semantic code search.** `find_code`/`repomap.search_repo` rank by keyword
   overlap; on a large repo the model can't find code it can't already name. Add
   an optional local embedding index (fits the offline-first ethos) with the
   current keyword ranker as fallback.
7. **Let the agent ask.** The loop only acts or finishes — it can't pause for
   input. The system prompt says "explain it instead of guessing" but gives no
   mechanism. Add an `ask_user` tool that surfaces a question in chat and waits,
   so ambiguous tasks don't burn a whole run on a wrong assumption.

### P2 — scale & polish

8. **Compact history.** `history_turns` keeps the last N raw turns; long sessions
   silently drop early context. Summarize older turns when near the context
   budget.
9. **Surface tokens/cost.** Capture `usage` from Claude/OpenAI and show
   per-run token + cost in the Workbench so a run's price is visible.
10. **Split planner / executor models.** `plan_task` reuses the main brain; allow
    a cheaper planner, or skip the separate plan call for Claude (it plans inline
    via thinking).
11. **Respect `.gitignore`.** `grep`/`find` only skip
    `.git/node_modules/__pycache__`; large `dist`/build trees still get walked.
12. **Graceful step-limit handoff.** Hitting `max_steps` dead-ends with "Re-run
    to continue." Summarize progress into the next run automatically.

## Suggested order

Ship **P0** first (streaming → prompt caching → retry): biggest responsiveness
and cost wins, minimal risk. Then **#4** (edit ergonomics) and **#5** (verify
depth), which most improve real task success — especially on local models.
