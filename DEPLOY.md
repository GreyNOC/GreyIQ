# GreyIQ Deployment Guide

GreyIQ is local-first. Keep services bound to `127.0.0.1` by default and put
Nginx or another reverse proxy in front when exposing it on a server.

## Prerequisites

- Node.js 18 or newer
- Python 3.10 or newer recommended
- npm
- PM2 for process persistence when running as a server: `npm install -g pm2`
- Nginx and Certbot only when exposing GreyIQ through a domain

## Install

```powershell
npm ci
python -m pip install -r requirements.txt
```

On Ubuntu, use `python3` and a virtual environment if that is your standard:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Environment Variables

Use `.env.example` as the reference for shell, PM2, or service-manager
environment values. Do not commit a real `.env` file.

Important local defaults:

- `HOST=127.0.0.1` and `PORT=4173` for the Node static server.
- `GREYIQ_HOST=127.0.0.1` and `GREYIQ_PORT=8766` for the Python backend.
- `GREYIQ_ALLOWED_ORIGINS` allows a separate trusted frontend origin.
- `GREYIQ_RUNTIME_DIR` controls local runtime data location.
- `GREYIQ_CODE_SCAN_BASE_PATH` and `GREYIQ_SCAN_ALLOW_PRIVATE_URLS` control BugHunter scan scope.

GreyIQ provider keys are configured through the app UI. Do not place real API
keys or tokens in `.env.example`.

## Local Run

Browser-only static fallback:

```powershell
npm start
```

Open `http://127.0.0.1:4173`.

Full Python backend, UI, and API:

```powershell
python -m backend.greyiq_api
```

Open `http://127.0.0.1:8766`.

## Desktop Run

```powershell
npm run desktop
```

The Electron launcher starts the backend on `127.0.0.1:8766` unless
`GREYIQ_PORT` is set.

## PM2 Persistence

GreyIQ includes `ecosystem.config.cjs` with two localhost-bound processes:

- `greyiq-web`: Node static server on `127.0.0.1:4173`
- `greyiq-api`: Python backend on `127.0.0.1:8766`

Verify and start:

```bash
npm run check:devops
pm2 start ecosystem.config.cjs
pm2 status
pm2 logs
pm2 save
pm2 startup
```

The PM2 config detects Python in this order: `GREYIQ_PYTHON`, `PYTHON`, then
platform defaults (`python`/`py -3` on Windows, `python3`/`python` on Linux).
Set `GREYIQ_PYTHON` only when you want to force a virtual environment or a
specific Python executable.

## Reverse Proxy

The Python backend serves both the UI and API, so a public Nginx site usually
proxies to `127.0.0.1:8766`. Replace `example.com` with your real domain.

```nginx
server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://127.0.0.1:8766;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Verify and reload on the server:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Use Certbot for TLS after the domain is pointed at the server.

## Health Checks

```bash
curl -fsS http://127.0.0.1:4173/
curl -fsS http://127.0.0.1:8766/api/health
pm2 status
```

The health endpoint should return JSON with `status: ok`.

## Logs

```bash
pm2 logs greyiq-web
pm2 logs greyiq-api
pm2 monit
```

Do not paste logs containing provider keys, credentials, or user-private data
into public issues or chats.

## Update

```bash
git pull
npm ci
python -m pip install -r requirements.txt
npm run check
npm run check:devops
pm2 reload ecosystem.config.cjs --update-env
pm2 save
```

If you use a Python virtual environment, activate it before installing
dependencies and reloading PM2.

## Rollback

1. Check the previous Git revision or release tag.
2. Restore the previous `ecosystem.config.cjs`, `.env.example`, or Nginx config if changed.
3. Reinstall dependencies if `package-lock.json` or `requirements.txt` changed.
4. Run `npm run check` and `npm run check:devops`.
5. Restart PM2:

```bash
pm2 restart ecosystem.config.cjs --update-env
```

To stop the PM2 deployment entirely:

```bash
pm2 delete greyiq-web greyiq-api
pm2 save
```
