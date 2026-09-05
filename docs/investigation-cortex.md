# Investigation cortex

GreyIQ's coding, hunting, and reporting paths now share one deterministic reasoning
layer. Its purpose is to answer four analyst questions consistently:

1. What is the strongest hypothesis right now?
2. What captured evidence supports it?
3. What contradicts it or remains unproven?
4. What is the next bounded action that would change the verdict?

## Core invariant

Reasoning is not authority. Models, scanner rules, route semantics, and learned priors
may propose hypotheses. Free-text claims, including text marked `confirmed`, do not count
as evidence.

**The cortex does not decide what counts as confirmation.** `report._has_captured_artifact`
is the engine's single confirm authority, and `investigator.has_confirming_artifact`
delegates to it rather than re-deriving the rule. This is load-bearing: the two DID drift
once. The cortex treated a passive web `proof_evidence` (a request line plus a response
status — which every header, cookie and disclosure finding carries) as a confirming typed
artifact, while the canonical gate deliberately refuses it because it proves a GET
happened, not impact. A configured brain — or prompt-injected text echoed through one —
could then pair a claimed `status: confirmed` with one passive GET and have the delivered
report print "confirmed / report-ready" for a missing-header finding whose canonical proof
status was still `candidate`. Delegating is what keeps that closed.

Two consequences follow, and both are tested:

- A claimed confirmation the gate does not accept raises a blocking
  `confirmation-without-artifact` contradiction. The claim is surfaced to the operator, not
  silently rewritten into a weaker status.
- Without an artifact the gate accepts, calibrated confidence is capped below the
  `supported` band. Evidence that a request was made is a lead, never support.

The cortex therefore does not execute probes, change scope, create findings, set CVSS,
or bypass submission gates. Existing workspace, scope, SSRF, rate, authorization, and
proof controls remain authoritative.

## Decision model

`bughunter/investigator.py` builds a bounded JSON-friendly graph containing:

- `hypotheses`: normalized class, severity, calibrated confidence, evidence artifacts,
  gaps, next proof obligation, decision, and report-readiness state;
- `attack_chains`: ordered, multi-step attack paths built by the attack-chain engine
  (`bughunter/attack_chain.py`), with projected impact clearly separated from proven
  impact — see [attack-chains.md](attack-chains.md);
- `chain_probes`: chains built from observed structure alone, citing no finding. They are
  test plans for the planner, kept out of `attack_chains` so nothing unobserved can be read
  as a result;
- `contradictions`: blocking evidence conflicts such as confirmation without an artifact,
  identical observed/control results, rejected verdicts, or an inflated public-client key;
- `coverage`: observed endpoints/parameters, verified classes, and request use;
- `metrics` and `verdict`: a concise, deterministic investigation summary.

## Ranking by information gain

A hypothesis carries `expected_information_gain` alongside its payoff-based `priority_score`, and
that term sharpens the ordering of **leads**. Payoff answers "which finding is worth the most?"; the
queue exists to answer "which single test should I run next?", which is a different question. Two
factors decide it:

- **uncertainty** peaks for a lead near 50/100 and falls to zero at either pole. A lead at 95 or at 5
  is settled in practice, so testing it teaches almost nothing.
- **chain leverage** counts the chains resting on the lead, and replaces a flat membership bonus that
  could not tell one projected ladder from three.

It deliberately does not touch confirmed rows: ranking captured evidence by how little is left to
learn about it would sink it in a queue the operator reads top-down. `unlocks_chains` (and
`project_if_confirmed`) name the chains a lead would complete if it became sound — a pure projection
that assumes an outcome which has not happened, mutates nothing, and never reaches the confirm gate.

## Derived theories

`build_investigation` maps each finding to exactly one hypothesis, and the chain engine composes only
the class pairs its technique table knows. Neither can conclude that the same control is absent on
nine routes, which is often the real and higher-severity bug behind a pile of unremarkable rows. A
synthesis pass emits those as **derived** rows (`kind: synthesis`, ids `SH*`) into `chain_probes` —
the queue that already means "worth testing" and never "found" — each carrying only a proof
obligation. Header runs and source-only findings are excluded: a header absent on nine routes is one
server default, and a claim about a property cannot be built out of files.

## From obligation to probe

`build_probe_plan` reads the finished graph and states, per unproven lead and per blocked chain, the
exact `(endpoint, class)` whose outcome would change the verdict. A chain's blocking step outranks a
loose lead of the same class, because it is what stands between a part-proven ladder and a real
impact.

It **emits a plan**. It runs nothing and authorizes nothing; every row is an input to the same
scope-gated prover. Two restrictions keep it inside the engine's existing box: a row's class must be
one the prover can actually confirm, so a plan cannot steer budget at a guaranteed non-result, and a
row's endpoint must be a verbatim `http(s)` location the graph already observed, so a plan cannot
introduce a host the hunt did not reach.

Typed evidence currently includes captured request/response pairs, response bodies,
matched values, observed/control differentials, OOB callbacks, live credential
validation, and screenshots. A source snippet earns only a small static-evidence weight.

Being a typed artifact is not the same as being a confirming one — a captured
request/response pair is inventoried and shown, but only the confirm authority above
decides whether anything confirms. Live credential validation is listed only for a
credential strict classification actually confirmed: a live public client key answering
its own issuer is the expected behaviour of that key, not proof of impact.

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

The loop's **observe** step reads `meta['probe_digest']` — what this turn's probes provoked — rather
than only the landing-page digest. That distinction is load-bearing: the landing digest is identical
on every call against one URL, so a loop reading only it observes nothing new after turn 0 and can do
no better than reschedule the pass it already ran. The probe digest changes as the probes change, so
an error family a probe *triggered* can promote its injection class on the next turn. The loop also
uses `build_probe_plan` to promote a chain's blocking class deterministically, which is what gives an
offline hunt the chain steering that previously existed only as prose for a model to read.

## Acting on the plan

The cortex still executes nothing. What changed is that something now consumes what it decides.

An opt-in **re-plan wave** (`GREYIQ_HUNT_REPLAN`, default off) runs one bounded extra pass aimed at
the rows `build_probe_plan` ranks highest, reading every scanner's findings rather than the seed URL
the iterative loop probes. It sits immediately after active verification and **before** classification,
attack planning and the QA gate, so whatever it captures flows through the normal pipeline; running it
after the authoritative graph would let those findings skip the downgrade-only QA the report depends
on. It calls the same `verify_active`, so scope, SSRF, GET-only and the process-wide per-host governor
are unchanged, and it is capped at three endpoints, three classes each and eight requests.

None of this widens what counts as proof. The wave confirms nothing itself; it produces candidate
findings that the same confirm authority then judges from a captured differential, exactly as for the
first pass.

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
