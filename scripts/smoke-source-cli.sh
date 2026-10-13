#!/usr/bin/env bash
# Prove the documented SOURCE install of the `gn` CLI on the Debian family:
# clone, scripts/install-cli.sh, then `gn` from an unrelated directory as an
# ordinary user. The container gets python3 and nothing else — no python3-venv,
# no python3-pip, no .deb, no network beyond apt — because that is exactly what
# the README promises Parrot/Kali/Ubuntu operators, for whom the release package
# may not apply at all (its dependencies track current Debian stable and its
# architecture is amd64 only).
#
# debian:12-slim is the bookworm base under Parrot 6 and Kali; debian:13-slim is
# the current release target. Pass image names to override the pair.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
images=("$@")
if [[ ${#images[@]} -eq 0 ]]; then
  images=(debian:12-slim debian:13-slim)
fi

# `git archive HEAD` reproduces a clone from the INDEX: only tracked files, with
# their recorded modes. An un-chmod-ed launcher — the classic "works on my
# machine, not after a clone" defect — fails here rather than for an operator.
container_script="$(cat <<'CONTAINER'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates git python3 >/dev/null
echo "distribution python: $(python3 --version)"

useradd -m -s /bin/bash hunter
git config --system --add safe.directory /src
install -d -o hunter -g hunter /home/hunter/GreyIQ
git -C /src archive --format=tar HEAD | tar -x -C /home/hunter/GreyIQ
chown -R hunter:hunter /home/hunter/GreyIQ

test -x /home/hunter/GreyIQ/gn || { echo "gn is not executable after a clone (git index mode)" >&2; exit 1; }
test -x /home/hunter/GreyIQ/scripts/install-cli.sh || { echo "install-cli.sh is not executable after a clone" >&2; exit 1; }

runuser -u hunter -- bash -c 'cd "$HOME/GreyIQ" && ./scripts/install-cli.sh'

# The PATH line the installer prints, from a directory unrelated to the checkout.
runuser -u hunter -- bash -c 'cd /tmp && export PATH="$HOME/.local/bin:$PATH" && gn --version'
runuser -u hunter -- bash -c 'cd /tmp && export PATH="$HOME/.local/bin:$PATH" && gn path'
runuser -u hunter -- bash -c 'cd /tmp && export PATH="$HOME/.local/bin:$PATH" && gn profiles >/dev/null'

# A hand-made symlink is the other obvious install, and the one that used to
# break: dirname of the LINK has no backend/ beside it.
runuser -u hunter -- bash -c 'ln -sfn "$HOME/GreyIQ/gn" "$HOME/.local/bin/gn-linked" && cd / && "$HOME/.local/bin/gn-linked" --version'

# A relative --bin-dir has to be made absolute before the installer verifies the
# launcher from /, or it writes the file and then fails looking for it there.
runuser -u hunter -- bash -c 'cd "$HOME/GreyIQ" && ./scripts/install-cli.sh --bin-dir relbin >/dev/null'
runuser -u hunter -- bash -c 'cd / && "$HOME/GreyIQ/relbin/gn" --version >/dev/null'

# The engine itself, not just argparse: a planted defect must be found with no
# third-party package installed anywhere on the system.
runuser -u hunter -- bash -c 'set -e
  mkdir -p /tmp/target
  printf "eval(location.hash);\n" > /tmp/target/app.js
  export PATH="$HOME/.local/bin:$PATH"
  gn scan /tmp/target > /tmp/scan.log
  grep -q "js.eval" /tmp/scan.log'

# A moved checkout must fail loudly with the repair instruction, not silently.
mv /home/hunter/GreyIQ /home/hunter/GreyIQ-moved
if runuser -u hunter -- bash -c 'export PATH="$HOME/.local/bin:$PATH"; gn --version' >/tmp/moved.log 2>&1; then
  echo "the installed wrapper still ran after the checkout moved." >&2
  cat /tmp/moved.log >&2
  exit 1
fi
grep -q "checkout not found" /tmp/moved.log || { cat /tmp/moved.log >&2; exit 1; }
mv /home/hunter/GreyIQ-moved /home/hunter/GreyIQ

# python3 is the only requirement claimed, so prove nothing else crept in.
if runuser -u hunter -- bash -c 'command -v pip3 || command -v pip' >/dev/null 2>&1; then
  echo "pip is present in the image; this smoke test must prove the no-pip path." >&2
  exit 1
fi
test ! -d /home/hunter/GreyIQ/.venv || { echo "a .venv appeared without --extras" >&2; exit 1; }

echo "source CLI install passed: clone -> install-cli.sh -> gn on PATH."
CONTAINER
)"

for image in "${images[@]}"; do
  echo "=== $image ==="
  docker run --rm \
    --mount "type=bind,src=${repo_root},dst=/src,readonly" \
    "$image" bash -euo pipefail -c "$container_script"
done
