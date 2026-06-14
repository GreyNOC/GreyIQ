---
name: edit-code
description: Make a focused code change to existing files and verify it
when: change, edit, modify, update, implement, refactor, rename, replace, adjust
---
Make small, verifiable changes — never rewrite a whole file when an edit will do.

1. `read_file` the file you intend to change so your edit matches the real content.
2. Use `edit_file` with an `old_string` that is unique and copied exactly (include a
   few lines of surrounding context so it is unambiguous). Prefer several small edits
   over one giant one. Use `write_file` only for brand-new files.
3. After each edit, call `verify`. If it reports FAILED, read the error, fix it, and
   verify again. Do not move on with a broken file.
4. When all edits are done and `verify` passes, stop and summarize what changed
   (file:line) and that verification passed.

Keep the change minimal: only what was asked. Don't add unrelated refactors,
helpers, or error handling for cases that cannot happen.
