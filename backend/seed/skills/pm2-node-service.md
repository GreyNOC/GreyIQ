---
name: pm2-node-service
description: Create or repair a PM2 ecosystem config for a Node, Python, or mixed service app
when: pm2, ecosystem, process manager, node service, python service, deploy, server setup, startup
---
Use this playbook when the task involves PM2, process management, Node services,
Python services, mixed frontend/backend apps, or startup reliability.

1. Inspect before writing anything:
   - Read `package.json` first if it exists.
   - Identify `start`, `dev`, `build`, `check`, `test`, frontend, backend, and worker scripts.
   - Inspect the likely entrypoints and config files to identify frontend and backend ports.
   - Check for existing `ecosystem.config.js`, `ecosystem.config.cjs`, or `ecosystem.config.mjs`.
   - Check whether `.env.example`, `DEPLOY.md`, and `.gitignore` already cover deployment behavior.
2. Make a short setup plan before editing:
   - Name each PM2 process and the exact command it should run.
   - Prefer `ecosystem.config.cjs` for CommonJS compatibility.
   - Bind services to `127.0.0.1` by default unless the user explicitly asks for another host.
   - Use environment variable names only. Never hardcode credentials, tokens, passwords, or real secrets.
3. Create or repair the PM2 config:
   - Use stable `cwd`, `script`, `args`, `interpreter`, `env`, and `time` fields.
   - Include separate processes for frontend, backend, workers, or schedulers when the repo actually has them.
   - Point logs to a predictable local logs directory, or add clear PM2 log guidance if custom logs are not needed.
   - Avoid guessing domains, TLS paths, usernames, or secret values.
4. Add verification commands:
   - Syntax-check the ecosystem file with `node --check ecosystem.config.cjs` or the actual config filename.
   - Run the repo's build/check/test scripts when they exist and commands are enabled.
   - Include a PM2 dry-run/start command only when it is safe for the user's environment.
5. Update deployment docs:
   - Update or create `DEPLOY.md` whenever PM2 setup files are added or deployment behavior changes.
   - Document install, build, start, `pm2 save`, `pm2 startup`, logs, health checks, update, and rollback steps.
6. Finish with rollback notes:
   - Explain how to stop/delete PM2 processes.
   - Explain how to revert the config or restore the previous process command.
   - Include the verification result.
