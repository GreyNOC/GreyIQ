#!/usr/bin/env bash
# Build one native macOS architecture. CI calls this only after the tagged
# commit's quality gate and the Windows/Linux draft assets have succeeded.
set -euo pipefail

arch="${1:-}"
case "$arch" in
  arm64) expected_host=arm64 ;;
  x64) expected_host=x86_64 ;;
  *) echo "Usage: $0 arm64|x64" >&2; exit 2 ;;
esac
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != "$expected_host" ]]; then
  echo "The $arch release must be built natively on macOS $expected_host." >&2
  exit 1
fi
if [[ "$(python -c 'import platform; print(platform.machine())')" != "$expected_host" ||
      "$(node -p 'process.arch')" != "$arch" ]]; then
  echo "Node and Python must match the native $arch release architecture." >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
version="$(node -p "require('./package.json').version")"
backend=dist/greyiq-backend/greyiq-backend
temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"

python -m playwright install chromium
pyinstaller --noconfirm --clean build/greyiq-backend.spec
test -x "$backend"
"$backend" --self-test-browser
expected="GreyIQ gn $version"
actual="$("$backend" --version)"
test "$actual" = "$expected" || { echo "Frozen CLI version mismatch: $actual" >&2; exit 1; }

export GREYIQ_HOST=127.0.0.1 GREYIQ_PORT=8799 GREYIQ_RUNTIME_DIR="$temp_root/greyiq-smoke"
"$backend" &
backend_pid=$!
cleanup_backend() {
  kill "$backend_pid" 2>/dev/null || true
  wait "$backend_pid" 2>/dev/null || true
}
trap cleanup_backend EXIT
healthy=0
for i in $(seq 1 60); do
  sleep 3
  if ! kill -0 "$backend_pid" 2>/dev/null; then
    echo "Frozen backend exited before /api/health answered." >&2
    exit 1
  fi
  if curl -fsS "http://127.0.0.1:8799/api/health" >/dev/null 2>&1; then healthy=1; break; fi
done
test "$healthy" -eq 1 || { echo "Frozen backend did not answer /api/health within 180s." >&2; exit 1; }
cleanup_backend
trap - EXIT

# Draft builds may be unsigned. A partially configured signing identity must
# fail rather than silently create artifacts that appear to be notarized.
signed=0
if [[ -n "${CSC_LINK:-}" || -n "${CSC_KEY_PASSWORD:-}" || -n "${APPLE_API_KEY:-}" ||
      -n "${APPLE_API_KEY_ID:-}" || -n "${APPLE_API_ISSUER:-}" || -n "${APPLE_TEAM_ID:-}" ]]; then
  if [[ -z "${CSC_LINK:-}" || -z "${CSC_KEY_PASSWORD:-}" || -z "${APPLE_API_KEY:-}" ||
        -z "${APPLE_API_KEY_ID:-}" || -z "${APPLE_API_ISSUER:-}" || -z "${APPLE_TEAM_ID:-}" ]]; then
    echo "Incomplete macOS signing/notarization secrets: configure all six or none." >&2
    exit 1
  fi
  signed=1
fi

if [[ "$signed" -eq 1 ]]; then
  # @electron/notarize expects APPLE_API_KEY to name a .p8 file, whereas the
  # GitHub secret is base64 text so it can be stored without line wrapping.
  key_dir="$(mktemp -d "$temp_root/greyiq-notary.XXXXXX")"
  key_file="$key_dir/AuthKey.p8"
  printf '%s' "$APPLE_API_KEY" | base64 -D > "$key_file"
  chmod 600 "$key_file"
  export APPLE_API_KEY="$key_file"
  trap 'rm -f "$key_file"; rmdir "$key_dir"' EXIT
  npx electron-builder --mac dmg zip "--$arch" --publish never
else
  echo "::warning::Apple Developer secrets absent; macOS draft assets are unsigned and unnotarized."
  CSC_IDENTITY_AUTO_DISCOVERY=false npx electron-builder --mac dmg zip "--$arch" \
    --config.mac.hardenedRuntime=false --config.mac.notarize=false --publish never
fi

app="$(find release -maxdepth 2 -type d -name GreyIQ.app -print -quit)"
test -n "$app" && test -x "$app/Contents/Resources/backend/greyiq-backend"
test "$("$app/Contents/Resources/backend/greyiq-backend" --version)" = "$expected"
for ext in dmg zip; do
  test -s "release/GreyIQ-$version-mac-$arch.$ext"
done
if [[ "$signed" -eq 1 ]]; then
  codesign --verify --deep --strict --verbose=2 "$app"
  xcrun stapler validate "$app"
  spctl --assess --verbose --type execute "$app"
fi

(
  cd release
  shasum -a 256 "GreyIQ-$version-mac-$arch.dmg" \
                "GreyIQ-$version-mac-$arch.zip" > "SHA256SUMS-mac-$arch.txt"
)
ls -lh "release/GreyIQ-$version-mac-$arch.dmg" \
       "release/GreyIQ-$version-mac-$arch.zip" \
       "release/SHA256SUMS-mac-$arch.txt"
