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

# PyInstaller rewrites Mach-O load commands in files listed as datas. Playwright's
# headless shell includes libEGL.dylib without enough header padding for that
# rewrite, so stage the exact browser revision only after the frozen build exists.
pw_revision="$(python - <<'PY'
import importlib.util
import json
from pathlib import Path

spec = importlib.util.find_spec("playwright")
if not spec or not spec.origin:
    raise SystemExit("Playwright is missing from the build environment")
manifest = Path(spec.origin).parent / "driver" / "package" / "browsers.json"
for browser in json.loads(manifest.read_text(encoding="utf-8"))["browsers"]:
    if browser["name"] == "chromium-headless-shell":
        print(browser["revision"])
        break
else:
    raise SystemExit(f"Playwright manifest lacks chromium-headless-shell: {manifest}")
PY
)"
if [[ -n "${PLAYWRIGHT_BROWSERS_PATH:-}" && -d "$PLAYWRIGHT_BROWSERS_PATH" ]]; then
  pw_cache="$PLAYWRIGHT_BROWSERS_PATH"
else
  pw_cache="$HOME/Library/Caches/ms-playwright"
fi
pw_source="$pw_cache/chromium_headless_shell-$pw_revision"
test -f "$pw_source/INSTALLATION_COMPLETE" || {
  echo "Playwright headless shell $pw_revision is missing from $pw_cache." >&2
  exit 1
}
pw_destination="dist/greyiq-backend/_internal/playwright-browsers/$(basename "$pw_source")"
mkdir -p "$(dirname "$pw_destination")"
ditto "$pw_source" "$pw_destination"
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
  # GitHub Actions exports absent secrets as empty strings. electron-builder treats
  # even an empty CSC_LINK as a certificate path and rejects the project directory.
  unset CSC_LINK CSC_KEY_PASSWORD APPLE_API_KEY APPLE_API_KEY_ID APPLE_API_ISSUER APPLE_TEAM_ID
  echo "::warning::Apple Developer secrets absent; macOS draft assets are unsigned and unnotarized."
  CSC_IDENTITY_AUTO_DISCOVERY=false npx electron-builder --mac dmg zip "--$arch" \
    --config.mac.hardenedRuntime=false --config.mac.notarize=false --publish never
fi

# Bash glob works on the native macOS runner; BSD find has no portable -quit.
apps=(release/mac*/GreyIQ.app)
if [[ "${#apps[@]}" -ne 1 || ! -d "${apps[0]}" ]]; then
  echo "Expected exactly one packaged GreyIQ.app under release/mac*." >&2
  exit 1
fi
app="${apps[0]}"
test -x "$app/Contents/Resources/backend/greyiq-backend"
packaged_backend="$app/Contents/Resources/backend/greyiq-backend"
test "$("$packaged_backend" --version)" = "$expected"
"$packaged_backend" --self-test-browser
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
