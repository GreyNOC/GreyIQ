---
name: adaptive-attack-chains
description: Build evidence-gated attack chains from mapped surfaces and learn from confirmations and clean controls.
when: attack chain, exploit chain, hunt, recon, proof, poe, idor, xss, sqli, ssrf, authorization
---
# Adaptive attack-chain technique

Use this only on an operator-authorized, explicitly scoped target.

1. Start from discovered in-scope endpoints; never invent a host or widen scope.
2. Establish a clean baseline before any hypothesis. Identify stable response fields for differential comparison.
3. Rank hypotheses by endpoint purpose, observed parameters, stack fingerprints, impact, and prior local outcomes.
4. Run one bounded check through the existing prover. The technique never supplies arbitrary payloads or direct network actions.
5. On a weak or absent signal, branch to the next ranked class or parameter without increasing scope or request ceilings.
6. On a stable differential, reproduce it against a control and capture redacted request/response POE.
7. Promote only deterministic confirmation. Record both confirmation and no-confirmation outcomes so future ranking adapts.

## Chain quality gates

- Authorization and scope precede every probe.
- A model suggestion is a hypothesis, never a finding.
- No proof means no confirmed report.
- A failed chain reduces priority gradually; one miss does not erase a technique.
- Payout/triage outcomes and technical confirmation are separate learning signals.
