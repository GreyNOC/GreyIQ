---
name: explore-codebase
description: Orient yourself in an unfamiliar workspace before changing anything
when: explore, understand, how does, where is, find, look at, what does, overview
---
Before answering questions about the code or making changes, build a quick map:

1. A repository map is already in your context — skim it first for the layout and
   the files/symbols that look relevant. `list_dir` only if you need more detail.
2. Read the obvious anchors if present: `README*`, `package.json`, `pyproject.toml`,
   `requirements.txt`, `Makefile` — they reveal language, scripts, and how to run/test.
3. Use `find_code` with what you're looking for ("login handler", "config parser") to
   rank the most relevant files; fall back to `grep` for an exact string/regex.
4. `read_file` only the few files that matter. Don't read large files wholesale —
   find_code/grep for the relevant lines first.

Then answer or plan with concrete file:line references. Do not claim something exists
until you have seen it with read_file or grep.
