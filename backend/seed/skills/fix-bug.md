---
name: fix-bug
description: Diagnose and fix a bug, then prove it is fixed
when: bug, error, broken, fails, failing, crash, traceback, exception, not working, wrong
---
Fix the cause, not the symptom, and prove it.

1. Reproduce / locate: read the error or failing behavior. `grep` for the error text,
   function, or symbol to find the exact file:line. `read_file` around it.
2. Form one specific hypothesis about the root cause and say it in one sentence.
3. Make the smallest `edit_file` that addresses that cause.
4. `verify`. If a test command is configured, that runs it; otherwise it syntax-checks
   the files you touched. If verify FAILS, fix and verify again.
5. If you cannot run the real failing scenario, say exactly what still needs to be
   checked rather than claiming it is fixed.

Finish with: the root cause, the one change you made (file:line), and the verification
result.
