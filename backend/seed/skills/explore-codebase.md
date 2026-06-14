---
name: explore-codebase
description: Orient yourself in an unfamiliar workspace before changing anything
when: explore, understand, how does, where is, find, look at, what does, overview
---
Before answering questions about the code or making changes, build a quick map:

1. `list_dir` at the root to see the top-level layout and entry points.
2. Read the obvious anchors if present: `README*`, `package.json`, `pyproject.toml`,
   `requirements.txt`, `Makefile` — they reveal language, scripts, and how to run/test.
3. `grep` for the names the user mentioned (functions, routes, classes) to find where
   they live, instead of guessing paths.
4. `read_file` only the few files that matter. Don't read large files wholesale —
   grep for the relevant lines first.

Then answer or plan with concrete file:line references. Do not claim something exists
until you have seen it with read_file or grep.
