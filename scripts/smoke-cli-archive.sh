#!/usr/bin/env bash
# Exercise the relocatable CLI archive and its PATH guidance on Debian 13.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
shopt -s nullglob
archives=("$root"/release/GreyIQ-*-linux-cli.tar.gz)
if [[ ${#archives[@]} -ne 1 ]]; then
  echo "Expected exactly one GreyIQ Linux CLI archive in release/." >&2
  exit 1
fi

docker run --rm \
  --mount "type=bind,src=${archives[0]},dst=/tmp/greyiq-cli.tar.gz,readonly" \
  debian:13-slim bash -euo pipefail -c '
    target="/tmp/GreyIQ CLI"
    mkdir -p "$target/bin"
    tar -xzf /tmp/greyiq-cli.tar.gz -C "$target"
    env PATH=/usr/bin:/bin "$target/greyiq-cli" --version
    env PATH=/usr/bin:/bin "$target/greyiq-cli" defend status --json >/tmp/defend-status.json 2>/tmp/defend-status.err || {
      cat /tmp/defend-status.err >&2
      cat /tmp/defend-status.json >&2
      echo "Debian 13 CLI archive defender status command failed." >&2
      exit 1
    }
    env PATH=/usr/bin:/bin "$target/greyiq-cli" defend rules --json >/tmp/defend-rules.json 2>/tmp/defend-rules.err || {
      cat /tmp/defend-rules.err >&2
      cat /tmp/defend-rules.json >&2
      echo "Debian 13 CLI archive defender rules command failed." >&2
      exit 1
    }
    # The surrounding bash -c body is single-quoted by the host shell.
    grep -Fq "defender.risky_listener" /tmp/defend-rules.json || {
      cat /tmp/defend-rules.json >&2
      echo "Debian 13 CLI archive is missing the frozen defender rule." >&2
      exit 1
    }
    env PATH=/usr/bin:/bin "$target/greyiq-cli" path > /tmp/path-direct.txt
    grep -F "export PATH=" /tmp/path-direct.txt
    ln -s "$target/greyiq-cli" "$target/bin/greyiq-cli"
    (cd / && env PATH="$target/bin:/usr/bin:/bin" greyiq-cli dashboard --help >/dev/null)
    (cd / && env PATH="$target/bin:/usr/bin:/bin" greyiq-cli path) > /tmp/path-installed.txt
    grep -F "already on PATH" /tmp/path-installed.txt
  '
