# Investigation cortex

GreyIQ's coding, hunting, and reporting paths now share one deterministic reasoning
layer. Its purpose is to answer four analyst questions consistently:

1. What is the strongest hypothesis right now?
2. What captured evidence supports it?
3. What contradicts it or remains unproven?
4. What is the next bounded action that would change the verdict?

## Core invariant

Reasoning is not authority. Models, scanner rules, route semantics, and learned priors
may propose hypotheses. Only typed captured artifacts can support confirmation. Free-text
claims, including text marked `confirmed`, do not count as evidence.

The cortex therefore does not execute probes, change scope, create findings, set CVSS,
or bypass submission gates. Existing workspace, scope, SSRF, rate, authorization, and
proof controls remain authoritative.

## Decision model

`bughunter/investigator.py` builds a bounded JSON-friendly graph containing:

- `hypotheses`: normalized class, severity, calibrated confidence, evidence artifacts,
  gaps, next proof obligation, decision, and report-readiness state;
- `attack_chains`: concrete finding references joined through a curated class recipe,
  with projected impact clearly separated from proven impact;
- `contradictions`: blocking evidence conflicts such as confirmation without an artifact,
  identical observed/control results, rejected verdicts, or an inflated public-client key;
- `coverage`: observed endpoints/parameters, verified classes, and request use;
- `metrics` and `verdict`: a concise, deterministic investigation summary.

Typed evidence currently includes captured request/response pairs, response bodies,
matched values, observed/control differentials, OOB callbacks, live credential
validation, and screenshots. A source snippet earns only a small static-evidence weight.

## Coding integration

The coding agent exposes `investigate_code`, a read-only workspace-confined tool. It
runs the existing code scanner and returns a compact ranked brief. The brief contains
locations and proof obligations but excludes snippets and uses an explicit field
allowlist, so a scanner's raw `secret_value` never reaches a remote coding model.

The system prompt tells the agent to investigate before editing security-sensitive or
root-cause work, inspect the cited source, trace attacker-controlled input to the sink,
and keep static matches in candidate state until reachability or runtime proof exists.

## Hunt integration

Every heuristic, offline, or configured-brain probe plan gains a `hypotheses` queue.
Each row preserves the already validated in-scope endpoint and allowed class, adds a
bounded likelihood score, and states the captured evidence required to confirm it.

The iterative hunt loop also emits an `investigation` snapshot in its metadata. The loop
still performs no HTTP itself; it only schedules the existing scope-gated differential
prover under the same shared request budget.

## Reporting integration

After proof handling and downgrade-only QA are final, bounty orchestration builds the
canonical investigation graph. Markdown reports render its decision brief, ranked queue,
chain leads, and contradictions. The JSON sidecar and hunt API return the identical graph
for dashboards and downstream automation.

This ordering matters: report intelligence sees the final evidence and QA-corrected
attack plans, not an earlier model-authored draft.

## Failure behavior

The module is dependency-free, deterministic, input-bounded, and tolerant of malformed
finding shapes. Advisory integration fails closed: empty or malformed input yields an
empty or conservative candidate investigation, never a fabricated confirmation. Existing
scanners and reports continue to function if there is no hypothesis to add.
