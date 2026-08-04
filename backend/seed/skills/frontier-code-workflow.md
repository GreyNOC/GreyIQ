---
name: frontier-code-workflow
description: Run a resilient plan, evidence, change, verify, reflect loop for complex coding work.
when: architecture, refactor, complex task, debugging, autonomous, implementation, frontier, code brain
---
# Frontier code workflow

1. Translate the request into explicit acceptance checks and constraints. Separate observed facts from assumptions.
2. Map the smallest relevant slice of the repository: entry points, state, interfaces, tests, and failure boundaries.
3. Generate two candidate approaches. Choose the one with the smallest blast radius and clearest rollback.
4. Make one coherent change at a time. Preserve unrelated work and existing public contracts unless the task changes them.
5. Verify at the narrowest useful level first, then run the broader relevant suite. Treat warnings and skipped proof honestly.
6. If verification fails, classify the failure as implementation, assumption, environment, or pre-existing. Adapt the plan from evidence.
7. Finish only when the requested behavior is demonstrated. Record incomplete work as an unsuccessful procedure, not a success.

## Decision discipline

- Prefer repository evidence over model memory.
- Never hide a failed check by weakening a test or deleting evidence.
- Keep security controls, trust boundaries, and rollback paths visible in the implementation.
- Explain the outcome, what proved it, and any remaining uncertainty.
