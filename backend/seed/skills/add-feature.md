---
name: add-feature
description: Add a new capability (endpoint, function, command, test) end to end
when: add, new, feature, endpoint, route, function, command, test, support, implement
---
Build the feature in small steps and wire it in fully — half-wired features are the
most common failure.

1. Find the pattern to copy: `grep` for an existing thing of the same kind (an existing
   route, command, test) and `read_file` it. Match the project's conventions.
2. Make the change in the right places — usually more than one: the implementation
   AND its registration (route table, exports, CLI dispatch, config), so it is actually
   reachable.
3. Add or update a test that exercises the new behavior when the project has tests.
4. `verify` after each file. Fix any FAILED result before continuing.
5. When done and verify passes, summarize: the files you added/changed (file:line),
   how the feature is reached, and the verification result.

Do only what was asked. If a design choice is genuinely ambiguous or risky, state it
instead of guessing.
