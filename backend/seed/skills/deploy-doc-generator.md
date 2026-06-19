---
name: deploy-doc-generator
description: Generate or update DEPLOY.md with repeatable install, run, PM2, proxy, and rollback steps
when: deploy docs, deployment guide, DEPLOY.md, runbook, server setup, install steps, rollback
---
Use this playbook when the task asks for deployment documentation, a runbook,
server setup notes, or when deployment behavior changes.

1. Inspect the repo before writing:
   - Read `README.md`, `package.json`, Python dependency files, PM2 configs, `.env.example`, and existing `DEPLOY.md`.
   - Identify ports, entrypoints, build commands, start commands, health checks, and logs.
2. Generate or update `DEPLOY.md` with these sections when relevant:
   - Prerequisites
   - Install
   - Environment variables
   - Build
   - Start locally
   - PM2 persistence
   - Reverse proxy
   - Health checks
   - Logs
   - Update
   - Rollback
3. Keep docs safe and repeatable:
   - Do not invent domains, credentials, secret values, usernames, or IP addresses.
   - Prefer localhost binding (`127.0.0.1`) behind a reverse proxy.
   - Prefer commands that can be re-run.
4. Verification:
   - Include the repo's check/build commands.
   - Include config syntax checks such as `node --check ecosystem.config.cjs` when PM2 config exists.
   - Include Nginx verification (`nginx -t`) only as a server-side step, not a local repo test.
5. Rollback:
   - Explain PM2 stop/delete, config restore, Git revert/checkout, dependency rollback, and Nginx reload where applicable.
   - Keep rollback steps specific to files and processes that actually exist.
