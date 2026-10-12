#!/usr/bin/env bash
# Install the release .deb in a clean Debian 13 container, then boot its CLI,
# frozen API, and Electron desktop as an ordinary user under a virtual display.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
shopt -s nullglob
packages=("$repo_root"/release/GreyIQ-*.deb)
if [[ ${#packages[@]} -ne 1 ]]; then
  echo "Expected exactly one GreyIQ .deb in release/; found ${#packages[@]}." >&2
  exit 1
fi

docker run --rm --security-opt seccomp=unconfined \
  --mount "type=bind,src=${packages[0]},dst=/tmp/greyiq.deb,readonly" \
  debian:13-slim bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends /tmp/greyiq.deb curl xvfb xauth >/tmp/install.log 2>&1 || {
      cat /tmp/install.log >&2
      exit 1
    }

    package_name="$(dpkg-deb -f /tmp/greyiq.deb Package)"
    backend="$(dpkg -L "$package_name" | grep "/resources/backend/greyiq-backend$" | head -n 1)"
    gui="$(command -v greyiq)"
    cli="$(command -v greyiq-cli)"
    test -x "$backend"
    test -x "$gui"
    test -x "$cli"
    if ldd "$(readlink -f "$gui")" | grep -q "not found"; then
      ldd "$(readlink -f "$gui")" >&2
      echo "Debian 13 desktop has unresolved shared libraries." >&2
      exit 1
    fi
    useradd -m -s /bin/sh greyiq-ci

    runuser -u greyiq-ci -- "$cli" --version >/tmp/cli.log 2>&1 || {
      cat /tmp/cli.log >&2
      exit 1
    }
    runuser -u greyiq-ci -- "$cli" dashboard --help >/dev/null
    runuser -u greyiq-ci -- "$cli" path >/tmp/cli-path.log
    grep -q "greyiq-cli is already on PATH" /tmp/cli-path.log
    grep -q "/home/greyiq-ci/.local/share/greyiq/runtime" /tmp/cli-path.log
    runuser -u greyiq-ci -- env PATH=/usr/local/sbin "$cli" path >/tmp/cli-path-missing.log
    grep -Fq "Current shell: export PATH=/usr/bin:" /tmp/cli-path-missing.log

    runuser -u greyiq-ci -- env GREYIQ_HOST=127.0.0.1 GREYIQ_PORT=8799 \
      "$backend" >/tmp/backend.log 2>&1 &
    backend_pid=$!
    backend_ok=0
    for i in $(seq 1 30); do
      if curl -fsS http://127.0.0.1:8799/api/health >/tmp/health.json 2>/dev/null; then
        backend_ok=1
        break
      fi
      if ! kill -0 "$backend_pid" 2>/dev/null; then break; fi
      sleep 2
    done
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    if [[ "$backend_ok" -ne 1 ]]; then
      cat /tmp/backend.log >&2
      echo "Debian 13 frozen backend did not become healthy." >&2
      exit 1
    fi

    # The desktop owns a separate frozen backend. A non-root account verifies
    # writable XDG paths and Chromium sandbox startup without disabling it.
    runuser -u greyiq-ci -- env GREYIQ_PORT=8800 GREYIQ_STARTUP_TIMEOUT_MS=60000 \
      LIBGL_ALWAYS_SOFTWARE=1 xvfb-run -a "$gui" --disable-gpu \
      >/tmp/desktop.log 2>&1 &
    desktop_pid=$!
    desktop_ok=0
    for i in $(seq 1 45); do
      if curl -fsS http://127.0.0.1:8800/api/health >/tmp/desktop-health.json 2>/dev/null; then
        desktop_ok=1
        break
      fi
      if ! kill -0 "$desktop_pid" 2>/dev/null; then break; fi
      sleep 2
    done
    kill "$desktop_pid" 2>/dev/null || true
    wait "$desktop_pid" 2>/dev/null || true
    if [[ "$desktop_ok" -ne 1 ]]; then
      cat /tmp/desktop.log >&2
      echo "Debian 13 desktop did not start its backend." >&2
      exit 1
    fi
    echo "Debian 13 package, CLI, frozen API, and desktop startup passed."
  '
