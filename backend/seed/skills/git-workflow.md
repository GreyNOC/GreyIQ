---
name: git-workflow
description: Use Git commands safely for status, branches, commits, remotes, diffs, logs, fetch, pull, push, and conflict handling
when: git, github, branch, commit, checkout, switch, status, diff, log, stash, pull, push, fetch, merge, rebase, remote, tag, conflict
---
Use Git as a workspace inspection and delivery tool. Prefer read-only commands first, and do not discard work unless the user explicitly asks.

1. Start by checking repository state:
   - `git status --short --branch`
   - `git remote -v`
   - `git branch --show-current`
2. Inspect before changing:
   - changed files: `git diff --name-only`
   - unstaged changes: `git diff -- <path>`
   - staged changes: `git diff --cached -- <path>`
   - recent history: `git log --oneline --decorate -n 10`
   - one commit: `git show --stat <ref>` or `git show -- <path>`
3. Use modern branch syntax when available:
   - create and switch: `git switch -c <branch-name>`
   - switch existing: `git switch <branch-name>`
   - list branches: `git branch -a`
   - delete local branch only when asked: `git branch -d <branch-name>`
4. Stage and commit intentionally:
   - stage exact files: `git add <path> ...`
   - review staged patch: `git diff --cached`
   - commit: `git commit -m "<short imperative summary>"`
   - amend only when asked: `git commit --amend`
5. Sync with remotes carefully:
   - update remote refs: `git fetch --all --prune`
   - inspect incoming changes: `git log --oneline --decorate HEAD..origin/<branch>`
   - pull with rebase only if the project/user prefers it: `git pull --rebase origin <branch>`
   - push current branch: `git push -u origin <branch>`
6. Handle conflicts explicitly:
   - identify files: `git status --short`
   - inspect markers in each conflicted file, edit the final intended content, then `git add <path>`
   - continue the operation with `git rebase --continue` or `git merge --continue` as appropriate.
7. Be careful with destructive commands:
   - Do not run `git reset --hard`, `git checkout -- <path>`, `git clean`, forced push, branch deletion, or history rewriting unless the user clearly requested it.
   - If user changes are present, preserve them and explain any risk before continuing.
8. After Git work, summarize the exact commands run, current branch, clean/dirty status, and any remote/push result.
