# Red team — authorized engagement playbook

**Authorized, scoped engagements only.** Everything here assumes a signed rules-of-engagement
document naming the client, the in-scope estate, the test window, the permitted techniques,
the stop conditions, and a named trusted agent reachable during the window. Without that
paperwork on file, none of this applies. This pack is engagement METHODOLOGY and reporting
discipline; it ships no payloads, no tradecraft for evading a defender, and no operational
capability.

## Rules of engagement come first
<!-- triggers: rules of engagement, roe, authorization, scope document, get started red team -->
No activity begins before the ROE is signed and on file.

- Record the authorizing party, the legal entity that owns each in-scope asset, and written confirmation for any third-party/hosted asset.
- Record the window (dates, hours, timezone), the permitted techniques, and everything explicitly forbidden.
- Record the deconfliction path: who to call, how fast, and the exact stop conditions that end the engagement immediately.
- Prefer least-impact and read-only actions. Destructive testing, denial of service, and real user data handling stay out unless explicitly and separately authorized.
- Keep an evidence log from the first action: timestamp, source host, target, action, result. It is what makes the report reproducible and what protects you.

## Engagement phases
<!-- triggers: red team phases, engagement phases, kill chain, attack lifecycle -->
A red-team engagement is a sequence of goals, not a tool run.

1. **Planning** — agree objectives (the "crown jewels"), success criteria, the threat actor being emulated, and what the blue team will and will not be told.
2. **Reconnaissance** — build the authorized attack surface from open sources and in-scope assets only. Record provenance for every asset so scope can be audited later.
3. **Initial access** — exercise the agreed vector inside scope. Document exactly what was sent, to whom, and when.
4. **Post-access objectives** — pursue the agreed objective with the least intrusive action that proves it. Prove reachability, do not harvest.
5. **Reporting and debrief** — one finding per root cause, with the detection opportunity each step offered the defenders.

## Purple-team value beats a flag capture
<!-- triggers: purple team, detection gap, blue team value, deliverable -->
The deliverable a client can act on is a detection gap list, not a trophy.

- For every step you took, record whether it was logged, whether it alerted, and how long detection took.
- Map each step to ATT&CK so the client's detection engineering has a concrete target.
- A step that was detected is as valuable a finding as one that was not — it validates a control.
- Recommend the specific telemetry (log source, field, rule shape) that would have caught the step.

## Evidence and data handling
<!-- triggers: evidence handling, data handling, redaction, minimal proof -->
Minimal proof, minimum data, always redacted.

- Capture the smallest artifact that proves the claim: a screenshot of an access decision, a hash, a directory listing header — not a dump.
- Never exfiltrate real customer data. If access to a live data store is proven, prove the ACCESS and stop.
- Redact secrets, tokens, and personal data in every artifact before it enters the report.
- Store engagement artifacts encrypted, on the engagement host, and destroy them on the schedule the ROE specifies.

## Reporting a red-team finding
<!-- triggers: red team report, engagement report, write up findings -->
Impact and reproducibility, same standard as a bounty report.

- **Narrative**: the path taken, in order, with timestamps — a defender must be able to replay it against their logs.
- **Root cause**: the control that failed, not the tool that worked.
- **Evidence**: observed result plus the control case that shows the intended behaviour.
- **Detection opportunity**: what telemetry existed at that step and what rule would have fired.
- **Remediation**: the specific control change, ranked by how many steps of the path it breaks.
- **Limitations**: what was out of scope, what was not tested, and what the window prevented.

## Stop conditions
<!-- triggers: stop condition, when to stop, incident, deconfliction -->
Stopping correctly is part of the job.

- Stop and call the trusted agent immediately on: evidence of a real (non-test) intrusion, unexpected production impact, exposure of data outside the agreed classes, or any action that leaves the authorized scope.
- Stop if an asset you believed in scope turns out to be owned or hosted by a third party without written authorization.
- Document the stop, the time, and who was notified. Resume only on written confirmation.
