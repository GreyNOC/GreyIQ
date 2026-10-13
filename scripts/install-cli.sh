#!/usr/bin/env bash
# Put this checkout's `gn` bug-bounty CLI on PATH, for the clone-and-run case:
#
#   git clone https://github.com/GreyNOC/GreyIQ.git && cd GreyIQ
#   ./scripts/install-cli.sh
#   gn dashboard
#
# No root, no .deb, no venv: the CLI boot path is stdlib-only, so a distribution
# python3 (3.11+) is the whole requirement. This is the supported install on any
# Debian-family distro — Debian, Ubuntu, Kali, Parrot — and on arm64, where the
# amd64 release .deb cannot be installed at all.
#
# `--extras` adds the two optional pure-Python engine libraries in a checkout
# .venv (see requirements-cli.txt). The release .deb/AppImage/CLI tarball remain
# the no-Python-needed options; this script never touches them.
set -euo pipefail

command_name="gn"
bin_dir="${GN_BIN_DIR:-$HOME/.local/bin}"
extras=0
force=0

usage() {
  cat <<'USAGE'
Usage: scripts/install-cli.sh [options]

  --extras           also create .venv and install requirements-cli.txt
                     (YAML spec parsing + cryptographic key-liveness proofs)
  --bin-dir DIR      install the launcher here (default: $HOME/.local/bin,
                     override with GN_BIN_DIR)
  --name NAME        command name to install (default: gn; use this when the
                     Google GN build tool already owns `gn` on your PATH)
  --force            overwrite an existing command not installed by this script
  -h, --help         show this message

The command is a small wrapper that execs this checkout's ./gn, so `git pull`
updates the CLI in place. Re-run this script after moving the checkout.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --extras) extras=1 ;;
    --force) force=1 ;;
    --bin-dir) shift; [ "$#" -gt 0 ] || { echo "install-cli.sh: --bin-dir needs a directory" >&2; exit 2; }; bin_dir="$1" ;;
    --bin-dir=*) bin_dir="${1#*=}" ;;
    --name) shift; [ "$#" -gt 0 ] || { echo "install-cli.sh: --name needs a command name" >&2; exit 2; }; command_name="$1" ;;
    --name=*) command_name="${1#*=}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "install-cli.sh: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# Resolve symlinks so running this through a link still finds the checkout.
self="${BASH_SOURCE:-$0}"
hops=0
while [ -L "$self" ] && [ "$hops" -lt 40 ]; do
  link="$(readlink "$self")"
  case "$link" in
    /*) self="$link" ;;
    *) self="$(dirname "$self")/$link" ;;
  esac
  hops=$((hops + 1))
done
root="$(cd "$(dirname "$self")/.." && pwd)"

if [ ! -f "$root/backend/gn_cli.py" ] || [ ! -f "$root/gn" ]; then
  echo "install-cli.sh: $root is not a GreyIQ checkout (backend/gn_cli.py and gn must be present)." >&2
  exit 1
fi

# The wrapper single-quotes the checkout path. Rather than escape a quote inside
# single quotes (a construct no reviewer should have to verify), refuse such a
# path and say so: ./gn keeps working, and nothing else here is affected.
case "$root" in
  *"'"*)
    echo "install-cli.sh: the checkout path contains a single quote, which the generated" >&2
    echo "  /bin/sh wrapper cannot quote safely: $root" >&2
    echo "install-cli.sh: move the checkout to a path without quotes, or just run ./gn." >&2
    exit 1
    ;;
esac

# The launcher owns the Python discovery and the version floor, so smoke-testing
# it HERE surfaces exactly the message the operator would get later, before any
# file is written.
chmod +x "$root/gn" 2>/dev/null || true
if ! version="$("$root/gn" --version)"; then
  echo "install-cli.sh: the CLI did not start, so nothing was installed." >&2
  exit 1
fi

if [ "$extras" -eq 1 ]; then
  venv="$root/.venv"
  if [ ! -x "$venv/bin/python" ]; then
    python=""
    for candidate in python3 python; do
      if command -v "$candidate" >/dev/null 2>&1 \
        && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
        python="$candidate"
        break
      fi
    done
    [ -n "$python" ] || { echo "install-cli.sh: no python3 3.11+ for --extras." >&2; exit 1; }
    # Debian splits venv support out of python3; ensurepip fails without it.
    if ! "$python" -m venv "$venv"; then
      echo "install-cli.sh: could not create $venv. On Debian/Ubuntu/Kali/Parrot: sudo apt install python3-venv" >&2
      exit 1
    fi
  fi
  "$venv/bin/python" -m pip install --upgrade pip
  "$venv/bin/python" -m pip install -r "$root/requirements-cli.txt"
  echo "Extras installed in $venv; ./gn prefers it automatically."
fi

marker="# installed by GreyIQ scripts/install-cli.sh"
target="$bin_dir/$command_name"
if [ -e "$target" ] && [ "$force" -eq 0 ] && ! grep -qF "$marker" "$target" 2>/dev/null; then
  echo "install-cli.sh: $target already exists and was not installed by this script." >&2
  echo "install-cli.sh: re-run with --force to replace it, or --name <other> to pick a different command." >&2
  exit 1
fi

mkdir -p "$bin_dir"
tmp="$target.tmp.$$"
cat > "$tmp" <<WRAPPER
#!/bin/sh
$marker
# Execs the GreyIQ checkout's own launcher, so \`git pull\` updates this command.
GREYIQ_HOME='$root'
if [ ! -x "\$GREYIQ_HOME/gn" ]; then
  echo "$command_name: GreyIQ checkout not found at \$GREYIQ_HOME." >&2
  echo "$command_name: it was moved or removed - re-run scripts/install-cli.sh from the checkout." >&2
  exit 1
fi
exec "\$GREYIQ_HOME/gn" "\$@"
WRAPPER
chmod 755 "$tmp"
mv -f "$tmp" "$target"

# Prove the installed command works from an unrelated directory before claiming it.
if ! installed_version="$(cd / && "$target" --version)"; then
  echo "install-cli.sh: $target was written but did not run." >&2
  exit 1
fi
if [ "$installed_version" != "$version" ]; then
  echo "install-cli.sh: $target reported '$installed_version', expected '$version'." >&2
  exit 1
fi

echo "Installed $target -> $root/gn ($installed_version)"

resolved="$(command -v "$command_name" 2>/dev/null || true)"
if [ "$resolved" = "$target" ]; then
  echo "Try: $command_name dashboard"
  exit 0
fi

on_path=0
case ":$PATH:" in
  *":$bin_dir:"*) on_path=1 ;;
esac

# Shadowed by an earlier PATH entry: the Google GN build tool also installs `gn`.
if [ "$on_path" -eq 1 ]; then
  echo
  echo "Note: '$command_name' still resolves to $resolved, which shadows the launcher"
  echo "just installed. Put $bin_dir earlier in PATH, or re-run with --name <other>."
  echo "Meanwhile, run it by path: $target dashboard"
  exit 0
fi

echo
echo "$bin_dir is not on this shell's PATH yet. For this shell:"
echo "  export PATH=\"$bin_dir:\$PATH\""
echo "For future login shells, add that line to ~/.profile (bash/sh) or ~/.zshrc (zsh)."
echo "Until then, run it by path: $target dashboard"
if [ -n "$resolved" ]; then
  echo
  echo "Note: a different '$command_name' is already on PATH at $resolved (the Google GN"
  echo "build tool installs one too). Re-run with --name <other> if you need both."
fi
