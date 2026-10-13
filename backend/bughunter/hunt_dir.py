"""GreyIQ BugHunter — resolve a DIRECTORY into a hunt plan.

The entry point behind ``gn auto``: open a terminal in a repo or a hunt folder that already
lists its targets, and GreyIQ works out what to hunt without a single flag beyond the
authorization confirmation.

Before this module nothing in the engine inferred anything from the working directory, and
no per-project config file was read anywhere. So this file DEFINES the convention rather
than following one. It is deliberately small and fail-closed: resolution only ever produces
*candidates*, and `gn auto` still routes them through the same `portfolio` record and the
same `host_in_active_scope` gate as any other hunt.

WHAT IT LOOKS FOR, most explicit first
--------------------------------------
1. ``.greyiq/hunt.json`` — the full plan::

       {"program": "acme", "platform": "hackerone", "handle": "acme",
        "scope": "acme.com\\n*.acme.com",
        "targets": ["https://app.acme.com", "https://api.acme.com"],
        "active": true, "iterate": true, "interval_minutes": 1440}

2. ``.greyiq/targets.txt`` / ``targets.txt`` — one target per line, ``#`` comments.
   Scope from ``.greyiq/scope.txt`` / ``scope.txt`` when present, else derived (see below).
3. A git repository — when the folder is a repo and lists no targets, the REPOSITORY is the
   target. `portfolio` already holds this precedent: *"A manually entered source repository
   is itself the saved authorization scope."*

THE TWO RULES THAT MATTER
-------------------------
**Authorization is never read from the directory.** A file on disk cannot assert that a
human is authorized to test a target. ``-y/--authorize`` is a per-invocation human
assertion and stays the only source — every state-touching verb in this CLI repeats that
gate, and there is no prompt, env var or config path into it anywhere in the engine. If a
hunt file tries to set it, this module strips the key and says so out loud rather than
silently ignoring it, because an operator who wrote it believed it worked.

**No scope means no active probing, stated rather than silent.** An empty scope makes
``host_in_active_scope`` return False for every host, so `--active` becomes a no-op that
sends zero probes and reports nothing unusual. `portfolio._normalize` already couples these
fail-closed (empty ``scope_text`` forces ``active``/``live``/``deep``/``auto_submit`` off);
this module surfaces WHY instead of quietly downgrading, so the operator can fix it.

Pure / frozen-safe: standard library only, no network, no writes. Every function is total —
a malformed hunt file yields refusals in the plan, never an exception.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bughunter.registrable_domain import is_bare_public_suffix, is_ip_literal, registrable_domain

CONFIG_DIR = ".greyiq"
HUNT_FILE = "hunt.json"
#: Target lists, most explicit first.
TARGET_FILES = (f"{CONFIG_DIR}/targets.txt", "targets.txt")
#: Scope lists, most explicit first.
SCOPE_FILES = (f"{CONFIG_DIR}/scope.txt", "scope.txt")

#: Keys an operator might put in a hunt file believing they grant authorization. They do
#: not, and silently ignoring them is worse than refusing them.
_AUTHORIZATION_KEYS = ("authorized", "authorize", "authorised", "yes", "confirm", "consent")

_MAX_TARGETS = 25          # mirrors campaign._MAX_PROGRAM_TARGETS — a real prober, never a fan-out
_MAX_FILE_BYTES = 1_000_000


@dataclass
class HuntPlan:
    """What a directory resolved to. ``ok`` is False when there is nothing safe to hunt."""

    ok: bool = False
    source: str = ""                  # which file/heuristic produced the targets
    root: str = ""
    name: str = ""                    # program display name (defaults to the folder name)
    platform: str = "manual"
    platform_handle: str = ""
    scope_text: str = ""
    scope_source: str = ""
    targets: list[str] = field(default_factory=list)
    repository_urls: list[str] = field(default_factory=list)
    active: bool = False
    iterate: bool = False
    max_pages: int = 12
    interval_minutes: int = 1440
    notes: list[str] = field(default_factory=list)      # informational
    refusals: list[str] = field(default_factory=list)   # why something was NOT armed


def _read_text(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _lines(text: str) -> list[str]:
    """Non-empty, non-comment lines. ``#`` starts a comment, inline or whole-line."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _host_of(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else "http://" + raw)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def _scope_token(host: str) -> str:
    """The scope token a target host implies.

    An IP keys on itself — it has no registrable domain, and folding one through
    ``registrable_domain`` maps 127.0.0.1 and 10.0.0.1 both onto ``0.1``. A bare public
    suffix is refused outright: a token like ``herokuapp.com`` would authorize every
    unrelated tenant on that platform, which is exactly what ``is_bare_public_suffix``
    exists to stop.
    """
    if not host:
        return ""
    if is_ip_literal(host):
        return host.strip("[]")
    apex = registrable_domain(host)
    if not apex or is_bare_public_suffix(apex):
        return ""
    return apex


def _derive_scope(targets: list[str]) -> tuple[str, list[str]]:
    """(scope_text, notes) from the targets themselves.

    Derived scope is the apex of each target, which is WIDER than the literal targets (it
    admits their subdomains, matching how ``_scope_hosts`` strips a leading ``*.``). That is
    the standard shape of a bounty scope and it is what recon needs to expand at all — but
    it is inferred, not authorized, so it is always reported.
    """
    tokens: list[str] = []
    skipped: list[str] = []
    for target in targets:
        host = _host_of(target)
        token = _scope_token(host)
        if token and token not in tokens:
            tokens.append(token)
        elif not token and host:
            skipped.append(host)
    notes: list[str] = []
    if tokens:
        notes.append("scope was DERIVED from the targets (" + ", ".join(tokens) + ") — "
                     "it admits their subdomains. Write .greyiq/scope.txt to set it exactly.")
    for host in skipped:
        notes.append(f"{host}: no usable scope token (a bare public suffix authorizes every "
                     "tenant on it, so it is refused) — name the scope explicitly")
    return "\n".join(tokens), notes


def _git_remote(root: Path) -> str:
    """The repo's origin fetch URL, read straight from .git/config. No subprocess."""
    text = _read_text(root / ".git" / "config")
    if not text:
        return ""
    in_origin = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_origin = line.replace(" ", "").lower().startswith('[remote"origin"]')
            continue
        if in_origin and line.lower().startswith("url"):
            _, _, value = line.partition("=")
            return value.strip()
    return ""


def _clean_targets(raw: Any, refusals: list[str]) -> list[str]:
    out: list[str] = []
    for item in (raw if isinstance(raw, list) else []):
        token = str(item or "").strip()
        if not token:
            continue
        if token not in out:
            out.append(token)
    if len(out) > _MAX_TARGETS:
        refusals.append(f"{len(out)} targets listed; capped at {_MAX_TARGETS} — this feeds a real "
                        "active prober, never an unbounded fan-out")
        out = out[:_MAX_TARGETS]
    return out


def _safe_name(root: Path) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", root.name).strip("-.")
    return name or "hunt"


def from_scope(scope: str, *, interval_minutes: int = 1440) -> HuntPlan:
    """A plan from a SCOPE the operator typed, with no directory involved. Total — never raises.

    ``gn auto -s acme.example`` is the shortest honest way to start: name what you are authorized
    on and GreyIQ works out the rest. This is the same :class:`HuntPlan` a directory resolves to —
    so the portfolio record, the learning memory, the ledger and the ``host_in_active_scope`` gate
    are reached by exactly one path — built from the one thing the operator said.

    The scope is used VERBATIM (it is theirs), and each host token becomes an ``https://`` seed
    target. ``*.acme.example`` seeds its apex, since a wildcard names no host of its own to fetch.
    A token that is not a host-only grant — a path, a URL, a bare public suffix — is refused by
    name rather than guessed at, because a seed target invented out of a malformed grant is a
    request sent somewhere nobody authorized.

    ``active`` is left OFF here even with a scope, unlike a hunt FILE which may ask for it: a
    directory's ``hunt.json`` is a considered artifact an operator wrote, while this is one line
    typed at a prompt, and arming live probing is not something to infer from brevity. ``--active``
    (or ``hunt.active`` in the profile) is how it gets armed.
    """
    text = str(scope or "").strip()
    if not text:
        return HuntPlan(refusals=["no scope given — `gn auto -s <host>` names what to hunt"])
    plan = HuntPlan(source="the --scope you gave", scope_source="--scope", scope_text=text)
    seen: set[str] = set()
    for raw in re.split(r"[\s,;]+", text):
        token = raw.strip().strip("\"'")
        if not token:
            continue
        host = token[2:] if token.startswith("*.") else token
        if any(ch in host for ch in "/?:#@%\\"):
            # Named, with the fix, rather than widened for them: a URL or path policy cannot prove
            # permission for its whole host, which is why _scope_hosts refuses to widen one.
            suggestion = _host_of(token) or ""
            plan.refusals.append(
                f"{token!r} is a URL or path — scope takes hosts and wildcards"
                + (f"; try -s {suggestion}" if _scope_token(suggestion) else ""))
            continue
        if not _scope_token(host):
            plan.refusals.append(f"{token!r} is not a host this can seed a target from")
            continue
        if host.lower() in seen:
            continue
        seen.add(host.lower())
        plan.targets.append(f"https://{host.lower()}")
    if not plan.targets:
        plan.refusals.append("nothing in that scope could be hunted")
        return plan
    plan.name = _safe_name(Path(plan.targets[0].split("://", 1)[1]))
    plan.root = str(Path.cwd())
    plan.notes.append(f"scope is what you typed; {len(plan.targets)} seed target(s) came from it")
    plan.ok = True
    return plan


def resolve(path: str | Path = ".") -> HuntPlan:
    """Resolve a directory into a :class:`HuntPlan`. Total — never raises."""
    # An empty/whitespace path must NOT silently become the current directory. Path("")
    # resolves to the cwd, so `gn auto ""` would quietly hunt whatever folder the operator
    # happened to be standing in. The default is an explicit "." at the CLI, never a blank.
    if not str(path or "").strip():
        return HuntPlan(refusals=["no directory given — pass a path, or '.' for this one"])
    try:
        root = Path(path).expanduser().resolve()
    except (OSError, ValueError, RuntimeError):
        return HuntPlan(refusals=[f"could not interpret {path!r} as a directory"])
    if not root.is_dir():
        return HuntPlan(refusals=[f"not a directory: {root}"])

    plan = HuntPlan(root=str(root), name=_safe_name(root))

    # --- 1. the explicit hunt file -------------------------------------------------
    doc: dict[str, Any] = {}
    hunt_path = root / CONFIG_DIR / HUNT_FILE
    text = _read_text(hunt_path)
    if text is not None:
        try:
            loaded = json.loads(text)
            doc = loaded if isinstance(loaded, dict) else {}
            if not isinstance(loaded, dict):
                plan.refusals.append(f"{hunt_path.name} is not a JSON object — ignored")
        except (json.JSONDecodeError, ValueError) as error:
            plan.refusals.append(f"{hunt_path.name} is not valid JSON ({error}) — ignored")

    # Authorization can never come from a file. Strip it loudly.
    for key in _AUTHORIZATION_KEYS:
        if key in doc:
            doc.pop(key, None)
            plan.refusals.append(
                f"{hunt_path.name} sets {key!r}: ignored. A file cannot assert that you are "
                "authorized to test a target — pass -y/--authorize yourself, per run."
            )

    if doc.get("program") or doc.get("name"):
        plan.name = str(doc.get("program") or doc.get("name")).strip() or plan.name
    plan.platform = str(doc.get("platform") or "manual").strip().lower() or "manual"
    plan.platform_handle = str(doc.get("handle") or doc.get("platform_handle") or "").strip()
    plan.max_pages = max(1, min(_int(doc.get("max_pages"), 12), 50))
    plan.interval_minutes = max(5, _int(doc.get("interval_minutes"), 1440))

    targets = _clean_targets(doc.get("targets"), plan.refusals)
    if targets:
        plan.source = f"{CONFIG_DIR}/{HUNT_FILE}"

    # --- 2. a targets file ---------------------------------------------------------
    if not targets:
        for rel in TARGET_FILES:
            body = _read_text(root / rel)
            if body is None:
                continue
            targets = _clean_targets(_lines(body), plan.refusals)
            if targets:
                plan.source = rel
                break

    # --- 3. a git repository is its own target -------------------------------------
    if not targets and (root / ".git").exists():
        plan.source = "git repository"
        plan.targets = [str(root)]
        remote = _git_remote(root)
        if remote:
            plan.repository_urls = [remote]
            plan.notes.append(f"git remote: {remote}")
        plan.notes.append(
            "no targets listed, so the REPOSITORY is the target — a source scan of this "
            "folder. Add .greyiq/targets.txt to hunt live hosts as well."
        )
        targets = plan.targets

    if not targets:
        plan.refusals.append(
            f"nothing to hunt in {root}. Write {CONFIG_DIR}/targets.txt (one target per line) "
            f"or {CONFIG_DIR}/{HUNT_FILE}, or run this inside a git repository to scan its source."
        )
        return plan

    plan.targets = targets

    # --- scope ---------------------------------------------------------------------
    scope_text = str(doc.get("scope") or doc.get("scope_text") or "").strip()
    if scope_text:
        plan.scope_source = f"{CONFIG_DIR}/{HUNT_FILE}"
    if not scope_text:
        for rel in SCOPE_FILES:
            body = _read_text(root / rel)
            if body is None:
                continue
            scope_text = "\n".join(_lines(body))
            if scope_text:
                plan.scope_source = rel
                break
    if not scope_text and plan.repository_urls:
        # portfolio._normalize's own precedent: a source repository IS the saved scope.
        scope_text = "\n".join(plan.repository_urls)
        plan.scope_source = "git remote"
    if not scope_text:
        scope_text, notes = _derive_scope(targets)
        plan.notes.extend(notes)
        if scope_text:
            plan.scope_source = "derived from targets"
    plan.scope_text = scope_text

    # --- what may be armed ---------------------------------------------------------
    want_active = bool(doc.get("active", True))
    want_iterate = bool(doc.get("iterate", True))
    if not scope_text.strip():
        # Said out loud instead of silently downgraded: with no scope,
        # host_in_active_scope refuses every host, so active probing sends nothing at all.
        plan.refusals.append(
            "no scope could be established, so active probing stays OFF — with an empty "
            "scope every host fails the scope gate and a hunt sends zero probes. "
            f"Write {CONFIG_DIR}/scope.txt with the hosts you are authorized to test."
        )
        plan.active = False
        plan.iterate = False
    else:
        plan.active = want_active
        plan.iterate = want_iterate

    plan.ok = True
    return plan


def _int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default
