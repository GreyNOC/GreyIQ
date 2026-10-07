# GreyIQ Deployment Guide

GreyIQ is local-first. Keep services bound to `127.0.0.1` by default and put
Nginx or another reverse proxy in front when exposing it on a server.

## Prerequisites

- Node.js 22.12 or newer for the desktop build (Debian 13's `nodejs` package is Node 20)
- Python 3.10 or newer recommended
- npm
- PM2 for process persistence when running as a server: `npm install -g pm2`
- Nginx and Certbot only when exposing GreyIQ through a domain

## Install

### Debian 13 desktop package

Use the `amd64.deb` release asset on Debian 13 amd64. `apt` installs the desktop
libraries and `zstd`, which the on-demand Ollama download needs:

```bash
sudo apt install ./GreyIQ-*-amd64.deb
greyiq
```

The package also installs `greyiq-cli`. Its btop-style local monitor is:

```bash
greyiq-cli dashboard
```

The dashboard is read-only. It reports API health, system load, programs,
findings, reports, and recent activity. Press `q` to quit, `r` to refresh, and
Tab or arrow keys to move between panels. It only probes `127.0.0.1` and does
not start hunts. Other CLI verbs remain available through `greyiq-cli --help`.
For a headless install without the desktop package, extract the Linux CLI
tarball. Keep the launcher and `greyiq-backend/` directory together:

```bash
tar -xzf GreyIQ-*-linux-cli.tar.gz
./greyiq-cli path
./greyiq-cli dashboard
```

`path` prints the runtime data directory and optional shell PATH syntax without
changing your profile. The archive includes `INSTALL.txt` with these commands.
To make `greyiq-cli` available from any directory without root access, run from
the extracted directory:

```bash
mkdir -p "$HOME/.local/opt/greyiq" "$HOME/.local/bin"
cp -a greyiq-cli greyiq-backend "$HOME/.local/opt/greyiq/"
ln -sfn "$HOME/.local/opt/greyiq/greyiq-cli" "$HOME/.local/bin/greyiq-cli"
export PATH="$HOME/.local/bin:$PATH"
greyiq-cli dashboard
```

If `~/.local/bin` is not already on your PATH, add
`export PATH="$HOME/.local/bin:$PATH"` to `~/.profile` for future login shells.
The Debian `.deb` installs `greyiq-cli` in `/usr/bin`, so this setup is only
for the headless archive.

The desktop and CLI share `$XDG_DATA_HOME/greyiq/runtime` (default
`~/.local/share/greyiq/runtime`); `GREYIQ_RUNTIME_DIR` overrides both. When that
directory is absent, the packaged desktop copies data from an older AppImage's
`~/.config/GreyIQ/runtime` on first launch and leaves the old copy in place.
Launch the desktop once before using CLI commands that write runtime data after
an upgrade.

For the portable AppImage, install `libfuse2t64` and `zstd`, then use `chmod +x`
and launch it. A desktop session with working unprivileged user namespaces is
required for Electron's sandbox; keep the sandbox enabled.

### Debian 13 source checkout

Debian 13 supplies Python 3.13. Use a virtual environment for Python packages:
Install [Node.js 22.12 or newer](https://nodejs.org/en/download) before `npm ci`;
Debian 13's `nodejs` package does not meet Electron's build requirement.

```bash
sudo apt update
sudo apt install python3-venv tesseract-ocr poppler-utils zstd xz-utils binutils
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "torch>=2.13,<3.0" --index-url https://download.pytorch.org/whl/cpu
python -m pip install -r requirements.txt -r requirements-test.txt
npm ci
npm run check
npm run desktop
```

Use `./gn dashboard` for the interactive source CLI. On Linux, it and
`npm run desktop` share the checkout's `runtime/` directory. The desktop uses a system
`ollama` command or `GREYIQ_OLLAMA_PATH` when set; packaged Linux builds do the
same before offering an on-demand runtime download. If a desktop package is
needed from source, install `build/requirements-build.txt`, run
`python -m playwright install --with-deps chromium`, then run
`npm run build:linux`. This creates the Debian package and AppImage in `release/`.
The build must run on Linux; the release workflow freezes on Ubuntu 24.04 and
smoke-tests the `.deb` in Debian 13.

The optional OCR tools are `tesseract-ocr` and `poppler-utils`. `TESSERACT_CMD`
and `POPPLER_PATH` can override discovery when installed outside normal paths.

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
- `GREYIQ_ACCESS_KEY` — **required before exposing the backend beyond `127.0.0.1`/`localhost`** (see
  [Reverse Proxy](#reverse-proxy) below). The backend's own per-session token is generated for
  same-machine use only and is embedded in the page it serves; it is not a substitute for real
  authentication once the process can be reached by anyone. Setting `GREYIQ_ACCESS_KEY` requires
  every request (via HTTP Basic Auth — any username, the key as the password) before the backend
  serves anything, including the home page. If `GREYIQ_HOST` is set to anything other than
  `127.0.0.1`/`::1`/`localhost` and this is unset, the backend refuses to start (set
  `GREYIQ_ALLOW_INSECURE_PUBLIC_BIND=1` only if you already have an equivalent auth layer in front
  of it and accept the risk).

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

**Do not expose the Python backend on a public domain without an authentication layer in
front of it.** The backend's own per-session token exists only to stop *other local
processes* on the same machine from driving the API — it is generated once per process
and is embedded, in plain text, in the home page it serves. Once the backend (or anything
that proxies to it) is reachable from the internet, that page — and the token in it — is
reachable by anyone, and the token can then be replayed against every `/api/*` route
(including endpoints that read/write files and make outbound requests). Set
`GREYIQ_ACCESS_KEY` (see [Environment Variables](#environment-variables)) **before** putting
GreyIQ on a public domain; the backend refuses to start on a non-loopback `GREYIQ_HOST`
without it. Nginx's own `auth_basic` (below) is a good *additional* layer but is not a
substitute — `GREYIQ_HOST` normally stays `127.0.0.1` in this setup (Nginx does the public
listening), so GreyIQ's own startup check can't detect a reverse proxy exposing it; the
`GREYIQ_ACCESS_KEY` check runs per-request inside the backend itself and protects it
regardless of what's in front of it.

The Python backend serves both the UI and API, so a public Nginx site usually
proxies to `127.0.0.1:8766`. Replace `example.com` with your real domain, and
generate `/etc/nginx/.htpasswd` with `sudo htpasswd -c /etc/nginx/.htpasswd <user>`.

```nginx
server {
    listen 80;
    server_name example.com;

    auth_basic "GreyIQ";
    auth_basic_user_file /etc/nginx/.htpasswd;

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
python -m pip install -r requirements.txt -r requirements-test.txt
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
3. Reinstall dependencies if `package-lock.json`, `requirements.txt`, or `requirements-test.txt` changed.
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
