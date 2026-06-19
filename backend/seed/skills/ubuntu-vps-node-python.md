---
name: ubuntu-vps-node-python
description: Prepare an Ubuntu VPS for a Node, Python, or mixed GreyIQ-style service
when: ubuntu, vps, linux server, node install, python install, pm2 startup, firewall, deploy
---
Use this playbook for Ubuntu VPS setup, repeatable server bootstrap, and mixed
Node/Python service deployment.

1. Inspect the repo first:
   - Read `package.json`, `requirements.txt`, `pyproject.toml`, PM2 configs, and `.env.example` if present.
   - Identify Node and Python version requirements from `package.json`, docs, and source files.
   - Identify build, check, start, and health check commands.
2. Plan the host setup before editing:
   - Do not invent domains, usernames, IPs, credentials, or secret values.
   - Prefer services listening on `127.0.0.1` behind Nginx unless the user asks otherwise.
   - Use `.env.example` only. Never create or fill a real `.env` with secrets.
3. Document or script prerequisites:
   - Node version check: `node -v`, `npm -v`, and package manager lockfile inference.
   - Python version check: `python3 --version` and virtual environment guidance when useful.
   - Dependency install: `npm ci` or the detected package manager, plus Python dependency install.
   - Optional build and check commands from the repo.
4. Cover process persistence:
   - Use PM2 for Node/Python services when requested or already present.
   - Include `pm2 start ecosystem.config.cjs`, `pm2 save`, and `pm2 startup` guidance.
   - Include `pm2 status`, `pm2 logs`, and restart commands.
5. Cover firewall and exposure:
   - Mention UFW rules for SSH, HTTP, and HTTPS when the deployment is public.
   - Keep app ports bound to localhost by default.
   - Do not open backend ports directly unless explicitly requested.
6. Add health checks:
   - Use local curl checks for frontend and backend ports.
   - Include any repo-specific `/api/health` or equivalent endpoint.
7. Add rollback:
   - Stop/delete PM2 processes.
   - Restore previous code or config.
   - Reinstall previous dependencies or check out the previous Git revision.
