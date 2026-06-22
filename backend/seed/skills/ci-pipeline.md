---
name: ci-pipeline
description: Create, repair, or run a CI pipeline (GitHub Actions and friends) that gates tests, lint, and build
when: ci, continuous integration, pipeline, workflow, github actions, gitlab ci, circleci, jenkins, azure pipelines, build, lint, test, tests, gate, status check, checks, pre-commit, green build, failing build, ci failing, actions
---
Use this playbook to set up, fix, or run a project's CI — the automated checks that
run on every push/PR. The golden rule: CI must run the *same* checks that pass
locally, so reproduce them locally first and never invent commands.

1. Find what already exists before changing anything:
   - Read the "Detected project setup" block for the CI provider and the project's check/test commands.
   - List existing CI config: `.github/workflows/*.yml`, `.gitlab-ci.yml`, `.circleci/config.yml`, `Jenkinsfile`, `azure-pipelines.yml`.
   - Read the package manifest for the real gate scripts (test, lint, typecheck, build) and the language/runtime versions the project targets.

2. Reproduce CI locally first (this is how you "do a CI test"):
   - Run the project's own check/test/lint commands with run_command (e.g. `npm run check`, `npm test`, `python -m pytest`, `pytest -q`). Use the exact commands the project defines — do not guess a runner.
   - If a check fails, fix the underlying code or test before touching the pipeline. A workflow that codifies a broken command is worse than none.
   - Note the runtime versions (Node, Python) and how dependencies install (`npm ci`, `pip install -r requirements.txt`).

3. Create or repair the workflow so it mirrors the local checks exactly:
   - Trigger on `push` and `pull_request` for the main branch.
   - Steps: check out, set up the runtime at the project's version, install dependencies deterministically (`npm ci`, not `npm install`), then run the SAME check/test/lint/build commands you just ran locally — in the same order.
   - Add a build matrix only if the project must support multiple runtimes; otherwise keep one job.
   - Keep one source of truth: if the project has an aggregate script (e.g. `npm run check`), call it rather than duplicating each step.

4. Harden and tidy the workflow:
   - Set least-privilege permissions (`permissions: contents: read`) unless a step needs more.
   - Pin actions to a major version or commit SHA; do not float on a moving tag.
   - Never hardcode secrets — reference them through the provider's secrets context. Keep tokens out of logs.
   - Add dependency caching and a `concurrency` group to cancel superseded runs when it speeds feedback.

5. Verify before finishing:
   - The workflow file is YAML — call the `verify` tool so it is parsed; fix any YAML error.
   - Re-read the file and confirm every local check is represented and the install/runtime steps match the project.
   - Do not claim CI is green from a static edit — you cannot run the hosted CI from here. State that it must be confirmed on the next push, and that the same commands pass locally.

6. Rollback and safety:
   - Preserve the previous workflow (note its contents) so it can be restored; describe how to disable the new one (delete the file or turn the workflow off).
   - Do not enable auto-merge, deploy, or release steps unless the user explicitly asks — keep this pipeline to checks/tests only by default.
