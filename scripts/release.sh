#!/usr/bin/env bash
#
# GreyIQ — one-command local release build.
#
#   scripts/release.sh [--dry-run] [--here] [--purge-venv] [--skip-check] [--yes]
#
# What it does, in order:
#   1. Verifies package.json and backend/_version.py agree (the same drift check CI runs).
#   2. DELETES the previous build outputs — release/ and dist/ — so the artifacts left
#      behind are unambiguously this version's. Nothing else is deleted: never a git tag,
#      never a GitHub release, never anything tracked by git.
#   3. Runs the quality gate (npm run check).
#   4. Builds the portable + installer via build/build-portable.ps1, which freezes the
#      backend from an isolated .venv-build built from requirements.txt.
#   5. Writes release/SHA256SUMS.txt and prints the artifact list.
#
# Windows MAX_PATH: PyInstaller bundles Playwright's Chromium at a very deep path, and the
# freeze dies with a misleading FileNotFoundError if the repo root is long (a
# .claude/worktrees/<name> checkout is). This script measures that up front and, by
# default, builds in a throwaway short-path worktree instead of failing 10 minutes in.
# Pass --here to force the build in place.

set -euo pipefail

DRY_RUN=0; BUILD_HERE=0; PURGE_VENV=0; SKIP_CHECK=0; ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --dry-run)    DRY_RUN=1 ;;
    --here)       BUILD_HERE=1 ;;
    --purge-venv) PURGE_VENV=1 ;;
    --skip-check) SKIP_CHECK=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    -h|--help)    sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\n\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not inside a git repository"
cd "$ROOT"
[ -f package.json ] && [ -f build/build-portable.ps1 ] || die "not a GreyIQ checkout: $ROOT"

# ---------------------------------------------------------------- version + drift gate
VERSION="$(node -p "require('./package.json').version")"
PY_VERSION="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' backend/_version.py)"
[ -n "$VERSION" ] || die "could not read the version from package.json"
[ "$VERSION" = "$PY_VERSION" ] ||
  die "version drift: package.json is $VERSION, backend/_version.py is $PY_VERSION — bump both."

say "GreyIQ $VERSION"
info "repo root : $ROOT"
info "commit    : $(git rev-parse --short HEAD)$(git diff --quiet || echo ' (dirty working tree)')"

# ------------------------------------------------------- Windows MAX_PATH pre-flight
# The longest path the freeze writes, measured rather than guessed.
DEEPEST_REL="dist/greyiq-backend/_internal/playwright-browsers/chromium_headless_shell-0000/chrome-headless-shell-win64/PrivacySandboxAttestationsPreloaded/privacy-sandbox-attestations.dat"
if [ "$(uname -s 2>/dev/null)" != "Linux" ] || [ -n "${WINDIR:-}" ]; then
  WIN_ROOT="$(cygpath -w "$ROOT" 2>/dev/null || echo "$ROOT")"
  DEEPEST_LEN=$(( ${#WIN_ROOT} + 1 + ${#DEEPEST_REL} ))
  LONG_PATHS="$(reg query 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem' /v LongPathsEnabled 2>/dev/null | grep -o '0x[0-9]*' || echo 0x0)"
  if [ "$DEEPEST_LEN" -gt 260 ] && [ "$LONG_PATHS" = "0x0" ]; then
    if [ "$BUILD_HERE" = "1" ]; then
      die "repo root is too deep for this build ($DEEPEST_LEN > 260 chars, LongPathsEnabled=0). Drop --here."
    fi
    SHORT_WT="${GREYIQ_BUILD_DIR:-C:/gqb}"
    say "Repo root too deep for Windows MAX_PATH ($DEEPEST_LEN > 260) — building elsewhere"
    info "build worktree: $SHORT_WT"
    if [ "$DRY_RUN" = "1" ]; then
      info "(dry run) would: git worktree add --detach $SHORT_WT HEAD && $SHORT_WT/scripts/release.sh --here"
      exit 0
    fi
    # A detached worktree only contains committed files. Refuse to silently
    # build yesterday's commit when the source checkout has local release edits.
    [ -z "$(git status --porcelain --untracked-files=all)" ] ||
      die "the checkout has uncommitted files; commit them before a short-path release build"
    [ ! -e "$SHORT_WT" ] || die "short-path build directory already exists: $SHORT_WT"
    git worktree add --detach "$SHORT_WT" HEAD >/dev/null
    info "created; building there"
    # --here in the short worktree: it is already short enough, and this guard must not recurse.
    SHORT_ARGS=(--here)
    [ "$PURGE_VENV" = "1" ] && SHORT_ARGS+=(--purge-venv)
    [ "$SKIP_CHECK" = "1" ] && SHORT_ARGS+=(--skip-check)
    [ "$ASSUME_YES" = "1" ] && SHORT_ARGS+=(--yes)
    ( cd "$SHORT_WT" && bash scripts/release.sh "${SHORT_ARGS[@]}" )
    say "Artifacts are in $SHORT_WT/release"
    ls -lh "$SHORT_WT/release" 2>/dev/null | sed 's/^/    /' || true
    info "remove the build worktree with: git worktree remove $SHORT_WT --force"
    exit 0
  fi
fi

# ------------------------------------------------------------- delete previous versions
# Only ever these two, only ever under $ROOT, and both are gitignored build output.
STALE=()
for d in release dist; do [ -e "$ROOT/$d" ] && STALE+=("$ROOT/$d"); done
if [ "$PURGE_VENV" = "1" ] && [ -e "$ROOT/.venv-build" ]; then STALE+=("$ROOT/.venv-build"); fi

if [ ${#STALE[@]} -gt 0 ]; then
  say "Deleting previous build output"
  for d in "${STALE[@]}"; do
    case "$d" in
      "$ROOT"/release|"$ROOT"/dist|"$ROOT"/.venv-build) ;;
      *) die "refusing to delete an unexpected path: $d" ;;
    esac
    # Anything tracked by git under here means this is not a pure build directory.
    if [ -n "$(git ls-files "$d" 2>/dev/null)" ]; then
      die "refusing to delete $d — it contains git-tracked files"
    fi
    SIZE="$(du -sh "$d" 2>/dev/null | cut -f1 || echo '?')"
    if [ "$DRY_RUN" = "1" ]; then
      info "(dry run) would delete $d ($SIZE)"
    else
      info "deleting $d ($SIZE)"
      rm -rf -- "$d"
    fi
  done
else
  say "No previous build output to delete"
fi

if [ "$DRY_RUN" = "1" ]; then say "Dry run complete — nothing was built"; exit 0; fi

# -------------------------------------------------------------------------- quality gate
if [ "$SKIP_CHECK" = "1" ]; then
  say "Skipping npm run check (--skip-check)"
else
  say "Running the quality gate (npm run check)"
  npm run check
fi

# -------------------------------------------------------------------------------- build
say "Building the portable + installer"
info "this freezes the backend from an isolated .venv-build; the first run downloads CPU torch + Chromium"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File build/build-portable.ps1 -Installer

# ---------------------------------------------------------------------------- checksums
say "Checksums"
[ -d "$ROOT/release" ] || die "build finished but release/ does not exist"
( cd "$ROOT/release"
  # Top-level artifacts only — win-unpacked/ is the staging tree, not something you ship.
  mapfile -t ARTIFACTS < <(find . -maxdepth 1 -type f ! -name 'SHA256SUMS.txt' -printf '%P\n' | sort)
  [ ${#ARTIFACTS[@]} -gt 0 ] || die "no artifacts were produced in release/"
  sha256sum "${ARTIFACTS[@]}" > SHA256SUMS.txt
  cat SHA256SUMS.txt | sed 's/^/    /'
)

say "GreyIQ $VERSION built"
ls -lh "$ROOT/release" | sed 's/^/    /'
cat <<EOF

Next, if you are publishing:
  git tag -a v$VERSION -m "Release v$VERSION" && git push origin v$VERSION
The pushed tag triggers .github/workflows/release.yml, which builds Windows + Linux,
checks the tagged commit, and uploads the assets to a DRAFT release. This script
never tags, pushes, or publishes a release. After both platform jobs pass and you
verify the draft assets and checksums, a human operator can publish it with:
  gh release edit v$VERSION --repo GreyNOC/GreyIQ --draft=false --latest
EOF
