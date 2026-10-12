#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-$(cd "$root" && node -p "require('./package.json').version")}"
backend="$root/dist/greyiq-backend/greyiq-backend"
launcher="$root/build/portable-cli/greyiq-cli"
archive="$root/release/GreyIQ-${version}-linux-cli.tar.gz"

if [[ ! -x "$backend" ]]; then
  printf 'Frozen Linux CLI backend missing or not executable: %s\n' "$backend" >&2
  exit 1
fi

chmod +x "$launcher"
mkdir -p "$root/release"
tar -czf "$archive" -C "$root/build/portable-cli" greyiq-cli INSTALL.txt -C "$root/dist" greyiq-backend
printf 'CLI tarball: %s (%s)\n' "$archive" "$(du -h "$archive" | cut -f1)"
