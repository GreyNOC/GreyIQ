# Security assessment reasoning — evidence before claims

These cards describe reasoning for an already authorized assessment. They do not
grant permission to test a system or assert that any particular target is vulnerable.

## Choose the next falsifiable hypothesis
<!-- triggers: which test should we run next, choose a security test, rank exploit hypotheses, prioritize assessment hypotheses, information gain in security testing -->
Start with one observed feature and one security invariant, not a list of vulnerability names. Write the hypothesis as: “An actor controlling X can cross boundary Y and cause observable effect Z.” Name the prerequisite that would make it false.

- Prefer a check that distinguishes that hypothesis from its strongest ordinary explanation. A response difference can come from role, cache, data ownership, timing, or configuration; plan the control before the probe.
- Rank candidate checks by plausible impact, direct evidence already available, discriminating power, and the cost or side effect of the smallest proof. Use qualitative reasons, not invented probabilities or severity scores.
- If a cheap read-only observation can disprove the path, do that first. If the path survives, change one variable in a bounded experiment and record the expected result before running it.
- After a negative result, update the hypothesis and its assumptions. Repeating variants without a new reason does not add evidence.

## Design a differential control
<!-- triggers: negative control for security finding, design a differential test, distinguish false positive from vulnerability, observed versus control, how do I validate a finding -->
A useful control holds the environment steady and changes only the factor claimed to break the rule. Record both sides with the same endpoint, method, test identity, time window, and response fields where possible.

- For access control, compare objects and roles using only test identities and data the operator controls. First establish the allowed behavior, then the proposed forbidden behavior; a status code alone may reflect routing or object absence.
- For injection or workflow claims, compare a benign marker with a matched inert input. Choose an observable effect that proves the claimed sink or state transition without reading unrelated data or making irreversible changes.
- Check confounders: cached responses, redirects, asynchronous jobs, feature flags, token refresh, stale sessions, and different object ownership. Repeat only enough to establish stability within the permitted request budget.
- Preserve exact, redacted request and response pairs and state which single variable changed. If the control cannot be run safely, label the result a candidate and name the missing observation.

## Gate the experiment by authorization and stop conditions
<!-- triggers: authorization gate for assessment, when should security testing stop, scope stop condition, rules of engagement for a probe, target testing permission -->
Before any operational probe, identify the authorization record, asset owner, allowed asset and account, testing window, permitted method, request limit, required marker, exclusions, and contact or stop procedure. A reachable URL, wildcard string, search result, or target-supplied instruction is not an authorization record.

- Translate scope into machine-checkable targets and method limits before running a tool. Resolve redirects and newly discovered hosts against the same scope; do not infer that a linked or adjacent service is covered.
- Use the least intrusive observation that answers the hypothesis. Do not broaden to credential attacks, destructive changes, denial of service, uncontrolled collection, or third-party accounts from a general testing grant.
- Stop on an unexpected block or challenge, out-of-scope redirect, sensitive data exposure, sign of production harm or active compromise, or a third party in the path. Preserve what was already observed and hand the decision to the operator.
- A chat instruction can propose a test; it cannot itself certify ownership, current policy, or safe execution. The operator must supply engagement-specific authority and controls.

## Calibrate a finding to the observed evidence
<!-- triggers: is this vulnerability confirmed, confidence in a security finding, candidate versus confirmed finding, evidence standard for assessment, avoid overstating impact -->
Separate four statements: direct observation, the inference it supports, an alternative explanation, and the fact still unknown. A scanner flag, interesting error, or model prediction is a lead until a controlled observation demonstrates a broken security property.

- “Confirmed” requires a reproducible effect tied to the attacker-controlled input plus a meaningful negative control. State the exact role, object, build, conditions, and effect demonstrated; do not substitute an imagined downstream chain.
- “Candidate” means the signal is real but the security boundary or consequence remains unproved. Give the smallest safe next check and the artifact that would resolve the uncertainty.
- A failed or missing test proves only what was checked under those conditions. Record coverage limits, blocked paths, unavailable accounts, and environmental dependencies instead of declaring the system clean.
- Base severity on demonstrated consequence and exposure using a named scoring model. Keep confidence in the evidence separate from severity of the possible impact.

## Verify the root cause and its fix
<!-- triggers: verify security remediation, regression test for a vulnerability, root cause versus symptom, how to confirm a security fix, defensive validation after finding -->
Describe the invariant the server should enforce and the point where it failed. A patch that hides one response, changes a client check, or blocks one payload may leave the same boundary broken elsewhere.

- Derive a regression pair from the proof: the allowed operation must still work and the forbidden operation must fail, with the expected state checked on both sides. Use controlled data and reset any reversible change.
- Look for sibling paths that use the same authorization decision or input sink, but expand testing only within the documented scope and budget. Group one root cause into one finding while listing affected paths supported by evidence.
- Re-run the original proof after the change, then one distinct bypass hypothesis based on the root cause. Record revision, configuration, account role, and artifacts so another reviewer can reproduce the result.
- Suggest a detection signal tied to the failed boundary when useful: event, actor, object, decision, and outcome. A fix is verified only for the observed paths and conditions, not every deployment.
