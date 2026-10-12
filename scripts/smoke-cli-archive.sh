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
    env PATH=/usr/bin:/bin "$target/greyiq-cli" path > /tmp/path-direct.txt
    grep -F "export PATH=" /tmp/path-direct.txt
    ln -s "$target/greyiq-cli" "$target/bin/greyiq-cli"
    (cd / && env PATH="$target/bin:/usr/bin:/bin" greyiq-cli dashboard --help >/dev/null)
    (cd / && env PATH="$target/bin:/usr/bin:/bin" greyiq-cli path) > /tmp/path-installed.txt
    grep -F "already on PATH" /tmp/path-installed.txt
  '
