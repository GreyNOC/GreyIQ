"""Detect and dispatch BugHunter scan commands typed in chat.

Lets a user drive the scanners conversationally, e.g.:
    scan code C:/path/to/repo
    scan web -y --scope example.com https://example.com
    scan -y --scope example.com https://example.com  (type inferred: URL -> web)
    scan active -y --scope example.com https://example.com

Remote Git URL scans currently refuse at the transport layer; scan a local
clone with ``scan code <path>`` instead.
    bughunt ./src                     (type inferred: path -> code)
    wardrive -y ./capture/            (read-only RF survey analysis; -y is REQUIRED)

Returns a (kind, target) pair or None so non-scan messages fall through to the
normal chat engine untouched.

IMPORT WEIGHT. This module is on the chat hot path — ``greyiq_api`` imports it at module
scope and every single chat turn calls :func:`detect_scan_command`. The three scan services
above are already imported here, but the wardrive engine is NOT: its parsers/analyzer/
renderer are imported INSIDE :func:`run_wardrive`, so a user who never types ``wardrive``
never pays for them. Same rule ``bughunter.wardrive.cli`` follows for the same reason.
"""

from __future__ import annotations

import re
import ipaddress
from typing import Any
from urllib.parse import urlsplit

from bughunter.code_scanner.sources.git_remote import canonical_repo_root
from bughunter.live_scan_service import run_live_scan
from bughunter.scan_service import run_code_scan
from bughunter.web_scan_service import run_web_scan

_TRIGGER = re.compile(r"^\s*(?:/?scan|bughunt)\b[:\s]+(?P<rest>.+)$", re.IGNORECASE | re.DOTALL)

_SUBTYPES: dict[str, str] = {
    "code": "code", "repo": "code", "path": "code", "codebase": "code", "folder": "code",
    "web": "web", "site": "web", "url": "web", "website": "web", "page": "web",
    "live": "live", "app": "live", "dynamic": "live", "runtime": "live", "browser": "live",
}
_SCAN_AUTHORIZE_FLAG = re.compile(r"(?<!\S)(?:-y|--authorize|--authorized)(?!\S)", re.IGNORECASE)
_SCOPE_FLAG = re.compile(r"(?<!\S)--scope(?:=|\s+)(?P<host>\S+)", re.IGNORECASE)
_BARE_SCOPE_FLAG = re.compile(r"(?<!\S)--scope(?:=|(?=\s|$))", re.IGNORECASE)
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ACTIVE_TRIGGER = re.compile(r"^\s*/?scan\s+active\b(?P<rest>.*)$", re.IGNORECASE | re.DOTALL)


def _looks_like_url(target: str) -> bool:
    lowered = target.lower()
    if lowered.startswith(("http://", "https://")):
        return True
    if lowered.startswith(("git@", "ssh://")):
        return False
    return " " not in target and bool(re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:/.*)?$", lowered))


def _looks_like_path(target: str) -> bool:
    return bool(re.search(r"[\\/]", target)) or bool(re.match(r"^[A-Za-z]:", target)) or target in {".", "./"}


def _code_target_type(target: str) -> str:
    lowered = target.lower()
    if lowered.startswith(("http://", "https://", "git@", "ssh://")):
        return "git_remote"
    return "path"


def detect_scan_command(message: str) -> tuple[str, str] | None:
    if not message:
        return None
    match = _TRIGGER.match(message)
    if not match:
        return None
    rest = match.group("rest").strip()
    parts = rest.split(None, 1)

    kind: str | None = None
    target = rest
    if parts and parts[0].lower() in _SUBTYPES:
        kind = _SUBTYPES[parts[0].lower()]
        target = parts[1].strip() if len(parts) > 1 else ""

    target = target.strip().strip("`\"'<>").strip()
    if not target:
        return None

    if kind is None:
        if _looks_like_url(target):
            kind = "web"
        elif _looks_like_path(target):
            kind = "code"
        else:
            # Ambiguous free text after "scan" - let normal chat handle it.
            return None
    return kind, target


def run_scan(kind: str, target: str, *, scope_host: str = "") -> dict[str, Any]:
    if kind == "web":
        return run_web_scan(target, scope_host=scope_host) if scope_host else run_web_scan(target)
    if kind == "live":
        return run_live_scan(target, scope_host=scope_host) if scope_host else run_live_scan(target)
    return run_code_scan(target, _code_target_type(target))


def _exact_host(value: str) -> str:
    """Normalize one host token, never a URL, wildcard, suffix grant, or port."""
    raw = value.strip().strip("\"'").rstrip(".").lower()
    if not raw or any(char in raw for char in "/\\?#@%*"):
        return ""
    try:
        return str(ipaddress.ip_address(raw.strip("[]"))).lower()
    except ValueError:
        pass
    if ":" in raw or raw.startswith("[") or raw.endswith("]"):
        return ""
    try:
        ascii_host = raw.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(ascii_host) > 253 or not all(_DNS_LABEL.fullmatch(label) for label in ascii_host.split(".")):
        return ""
    return ascii_host


def _target_host(kind: str, target: str) -> str:
    """Extract a network target's host without DNS or network activity."""
    raw = target.strip()
    if kind == "code" and not raw.lower().startswith("https://"):
        return ""
    if kind in {"web", "live"} and "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        if kind == "code" and parsed.scheme.lower() != "https":
            return ""
        if "@" in parsed.netloc or "\\" in parsed.netloc:
            return ""
        return _exact_host(parsed.hostname)
    except ValueError:
        return ""


def validate_scoped_network_target(kind: str, target: str, scope_host: str,
                                   authorized: bool) -> dict[str, Any]:
    """Validate an exact host or repository-root grant before network activity."""
    if not authorized:
        return {"ok": False, "error": "Network scans require explicit authorization and --scope for the exact target."}
    if kind == "code":
        repository = canonical_repo_root(target)
        grant = canonical_repo_root(scope_host)
        if not repository:
            return {"ok": False, "error": "Remote repository target must be a supported public HTTPS repository-root URL."}
        if not grant or grant != repository:
            return {"ok": False, "error": "Remote repository scope must name the exact authorized repository-root URL."}
        return {"ok": True, "scope_repository": grant}
    exact_host = _exact_host(scope_host)
    if not exact_host:
        return {"ok": False, "error": "Scope must be one exact host, without a wildcard, scheme, path, or port."}
    target_host = _target_host(kind, target)
    if not target_host:
        return {"ok": False, "error": "Network target must be a valid HTTP(S) URL (HTTPS for a remote repository) with no embedded credentials."}
    if target_host != exact_host:
        return {"ok": False, "error": f"Target host '{target_host}' is outside the exact authorized scope '{exact_host}'."}
    return {"ok": True, "scope_host": exact_host}


def parse_active_chat_command(message: str) -> dict[str, Any] | None:
    """Parse an explicitly authorized, one-host active chat assessment.

    Only a complete HTTP(S) URL is accepted. The host token is an exact grant;
    whole-host GET/HEAD/OPTIONS authorization must also be permitted by the
    operator's rules of engagement. Narrower program rules use the saved-program
    hunt workflow instead of this short command.
    """
    match = _ACTIVE_TRIGGER.match(message or "")
    if not match:
        return None
    rest = match.group("rest")
    authorized = bool(_SCAN_AUTHORIZE_FLAG.search(rest))
    rest = _SCAN_AUTHORIZE_FLAG.sub(" ", rest)
    scopes = [item.group("host") for item in _SCOPE_FLAG.finditer(rest)]
    rest = _SCOPE_FLAG.sub(" ", rest)
    target_parts = rest.split()
    if not authorized:
        return {"ok": False, "error": "Active assessment requires -y (or --authorized) and --scope <exact-host>. Use it only when whole-host GET/HEAD/OPTIONS testing is permitted."}
    if len(scopes) != 1 or _BARE_SCOPE_FLAG.search(rest):
        return {"ok": False, "error": "Active assessment requires exactly one --scope <exact-host> value."}
    scope_host = _exact_host(scopes[0])
    if not scope_host:
        return {"ok": False, "error": "Scope must be one exact host, without a wildcard, scheme, path, or port."}
    if len(target_parts) != 1 or len(target_parts[0]) > 2048:
        return {"ok": False, "error": "Give one complete HTTP(S) target URL for active assessment."}
    target = target_parts[0]
    if not target.lower().startswith(("http://", "https://")):
        return {"ok": False, "error": "Active assessment needs a complete HTTP(S) URL."}
    target_host = _target_host("web", target)
    if not target_host:
        return {"ok": False, "error": "Active target must be a valid HTTP(S) URL with no embedded credentials."}
    if target_host != scope_host:
        return {"ok": False, "error": f"Target host '{target_host}' is outside the exact authorized scope '{scope_host}'."}
    return {"ok": True, "target": target, "scope_host": scope_host}


def dispatch_authorized_scan_command(message: str) -> dict[str, Any] | None:
    """Execute a chat scan only after explicit authorization and exact host scope.

    Local code scans do not make a network request. Web/live scans and remote
    repository clones require ``-y --scope <exact-host>`` in the command itself.
    The scope host is forwarded to web/live services so redirects and browser
    subresources can be checked at the network boundary as well.
    """
    if not _TRIGGER.match(message or ""):
        return None
    authorized = bool(_SCAN_AUTHORIZE_FLAG.search(message))
    without_auth = _SCAN_AUTHORIZE_FLAG.sub(" ", message)
    scopes = [match.group("host") for match in _SCOPE_FLAG.finditer(without_auth)]
    without_scope = _SCOPE_FLAG.sub(" ", without_auth)
    if _BARE_SCOPE_FLAG.search(without_scope):
        return {"ok": False, "error": "Supply --scope <exact-host> for this scan; wildcards and URLs are not accepted."}
    command = detect_scan_command(without_scope)
    if command is None:
        return {"ok": False, "error": "Give a scan type and target, for example: scan web -y --scope app.example.com https://app.example.com/"}
    kind, target = command
    remote = kind in {"web", "live"} or (kind == "code" and _code_target_type(target) == "git_remote")
    if not remote:
        return run_scan(kind, target)
    if not authorized:
        return {"ok": False, "scan_type": kind, "target": target,
                "error": "Network scans require explicit authorization: add -y (or --authorized) and --scope for the exact target."}
    if len(scopes) != 1:
        return {"ok": False, "scan_type": kind, "target": target,
                "error": "Network scans require exactly one --scope value."}
    grant = validate_scoped_network_target(kind, target, scopes[0], authorized)
    if not grant["ok"]:
        return {"ok": False, "scan_type": kind, "target": target,
                "error": str(grant["error"])}
    if kind == "code":
        return run_scan(kind, target)
    return run_scan(kind, target, scope_host=str(grant["scope_host"]))


# --- wardrive: read-only RF survey analysis from chat --------------------------------

# Its own trigger rather than a ``scan`` subtype: ``scan`` means "go look at that target",
# and wardrive does the opposite — it reads an export the operator ALREADY captured and
# never touches a radio. ``scan wardrive <path>`` is accepted too because operators type it.
_WARDRIVE_TRIGGER = re.compile(
    r"^\s*(?:/?scan\s+)?/?(?:wardrive|wardriving|rf[ -]survey|wifi[ -]survey)\b[:\s]+(?P<rest>.+)$",
    re.IGNORECASE | re.DOTALL,
)
# HOW AUTHORIZATION IS EXPRESSED IN CHAT: the operator types the SAME -y/--authorize flag the
# `gn wardrive` CLI demands, in the message itself. A chat message is never treated as
# authorization on its own — typing "wardrive ./capture" runs nothing and is answered with
# what the flag asserts and how to give it. The flag is not a formality: a survey export is a
# recording of other people's networks and of client devices that never consented to being in
# it, so the operator has to state that the capture is theirs and the site is in scope.
_AUTHORIZE_FLAG = re.compile(r"(?:^|\s)(?:-y|--authorize|--authorized)(?=\s|$)", re.IGNORECASE)
# Export formats bughunter.wardrive.parsers can read. Used ONLY to recognize a bare filename
# ("wardrive -y survey.csv") as a path; a real extension check happens in the parsers.
_SURVEY_SUFFIXES = (".csv", ".netxml", ".xml", ".txt")
# The chat bubble is not a report. The full markdown goes to disk via `gn wardrive --out`;
# here it is capped — and when it IS capped that is stated, never silently truncated.
_WARDRIVE_CHAT_CHARS = 6000


def detect_wardrive_command(message: str) -> tuple[str, bool] | None:
    """``(export_path, authorized)`` for a wardrive chat command, else ``None``.

    ``None`` for anything ambiguous — no trigger, no target, a URL (this engine reads local
    files and nothing else), or free text that does not look like a path — so ordinary chat
    is completely untouched. ``authorized`` is reported separately from the path rather than
    being folded into the detection so the caller can REFUSE and explain, which is a better
    answer than pretending the message was never a command."""
    if not message:
        return None
    match = _WARDRIVE_TRIGGER.match(message)
    if not match:
        return None
    rest = match.group("rest").strip()
    authorized = bool(_AUTHORIZE_FLAG.search(f" {rest} "))
    target = _AUTHORIZE_FLAG.sub(" ", f" {rest} ").strip()
    target = target.strip().strip("`\"'<>").strip()
    if not target:
        return None
    # Read-only file analysis: a URL is not something this engine can or should fetch.
    if target.lower().startswith(("http://", "https://", "git@", "ssh://")):
        return None
    if not _looks_like_path(target) and not target.lower().endswith(_SURVEY_SUFFIXES):
        # Ambiguous free text after "wardrive" ("wardrive best practices") - normal chat.
        return None
    return target, authorized


def _rf_table_dirs() -> tuple[Any, Any]:
    """``(seed_dir, runtime_dir)`` for the wardrive OUI / default-SSID tables.

    Without this the operator's ``<runtime>/rf/oui.tsv`` override is DEAD on the chat surface:
    ``analyze_survey`` defaults both to None, so tier 2 of the OUI lookup is unreachable while the
    assessment still prints "add the prefix to <runtime>/rf/oui.tsv" as the remediation for every
    undetermined vendor — telling the operator to perform a step that provably does nothing. The
    ``gn wardrive`` CLI wires this through ``cli._table_dirs``; chat has to do the same or the two
    surfaces disagree about vendor attribution on the same capture.

    ``greyiq_api`` is tried first because it is the process that actually serves chat; ``gn_cli`` is
    the fallback for a CLI/test caller. Both resolve ``GREYIQ_RUNTIME_DIR`` identically. Imported
    INSIDE the function: ``greyiq_api`` imports this module, so a module-scope import would be a
    cycle, and the module docstring's import-weight rule applies either way."""
    for module_name in ("greyiq_api", "gn_cli"):
        try:
            module = __import__(module_name)
            return module.SEED_DIR, module.RUNTIME_DIR
        except Exception:  # noqa: BLE001 - a table-path lookup must never fail the survey
            continue
    return None, None


def run_wardrive(target: str, authorized: bool) -> dict[str, Any]:
    """Analyze a survey export and return a JSON-serializable result; never raises.

    Delegates entirely to the wardrive package's own public API — ``parsers.load_survey``,
    ``analyze.analyze_survey``, ``report.build_rf_markdown`` — so the chat surface and
    ``gn wardrive`` can never disagree about a finding. Those imports are INSIDE this
    function: see the module docstring's import-weight rule.

    ``undetermined`` is carried through and rendered explicitly. That ledger is the whole
    point of the engine: an airodump-only capture cannot report WPS or PMF state, and
    "the export cannot tell us" is a different fact from "it is off". Dropping it to keep the
    chat bubble short would turn a bounded assessment into a false clean bill of health."""
    path = str(target or "").strip()
    if not path:
        return {"ok": False, "scan_type": "wardrive", "target": "", "authorized": bool(authorized),
                "error": "No survey export path provided."}
    if not authorized:
        # Refuse and explain. The message asked for it; the message is not the authorization.
        return {
            "ok": False,
            "scan_type": "wardrive",
            "target": path,
            "authorized": False,
            "error": (
                "A survey export records other people's networks and client devices that never "
                "consented to being in it, so GreyIQ needs you to say the capture is yours and "
                "the site is in scope — the same assertion `gn wardrive` requires.\n\n"
                f"Re-send as: `wardrive -y {path}`\n\n"
                "Nothing was read and nothing was analyzed."
            ),
        }

    try:
        from pathlib import Path  # noqa: PLC0415 - lazy by design, see the module docstring

        from bughunter.wardrive import analyze as analyze_mod  # noqa: PLC0415
        from bughunter.wardrive import parsers, report  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001 - a missing/partial wardrive package costs this command only
        return {"ok": False, "scan_type": "wardrive", "target": path, "authorized": True,
                "error": f"The wardrive engine is unavailable: {type(exc).__name__}: {exc}"}

    try:
        if not Path(path).exists():
            return {"ok": False, "scan_type": "wardrive", "target": path, "authorized": True,
                    "error": f"Survey export not found: {path}"}
        survey = parsers.load_survey([path])
        seed_dir, runtime_dir = _rf_table_dirs()
        result = analyze_mod.analyze_survey(survey, seed_dir=seed_dir, runtime_dir=runtime_dir)
    except Exception as exc:  # noqa: BLE001 - a malformed export must answer, never crash the chat turn
        return {"ok": False, "scan_type": "wardrive", "target": path, "authorized": True,
                "error": f"Could not analyze {path}: {type(exc).__name__}: {exc}"}

    if not result.get("ok"):
        return {"ok": False, "scan_type": "wardrive", "target": path, "authorized": True,
                "error": str(result.get("error") or "analysis failed")}

    findings = list(result.get("findings") or [])
    undetermined = list(result.get("undetermined") or [])
    stats = result.get("stats") or {}
    markdown = report.build_rf_markdown(result, ctx={"title": "RF survey — wireless posture assessment",
                                                     "scope": path})
    truncated = len(markdown) > _WARDRIVE_CHAT_CHARS
    if truncated:
        markdown = markdown[:_WARDRIVE_CHAT_CHARS].rstrip()
        # State the truncation AND restate the undetermined ledger, because the cut above may
        # have removed the section that says which facts this export could not establish.
        markdown += (
            "\n\n_(Report truncated for chat. Write the full assessment with "
            f"`gn wardrive -y --out report.md {path}`.)_"
        )
        if undetermined:
            markdown += "\n\nUndetermined — the export cannot establish these; absence is NOT a clean result:\n"
            markdown += "\n".join(
                f"- {row.get('fact')}: {row.get('ap_count')} BSS — {row.get('reason')}"
                for row in undetermined
            )
    return {
        "ok": True,
        "scan_type": "wardrive",
        "target": path,
        "authorized": True,
        # The highest severity actually PRESENT, not a synthesized risk grade — this engine
        # scores nothing and neither does this wrapper.
        "risk": _wardrive_risk(findings),
        "finding_count": len(findings),
        "undetermined_count": len(undetermined),
        "access_points": int(stats.get("access_points") or 0),
        "stations": int(stats.get("stations") or 0),
        "source_formats": list(result.get("source_formats") or []),
        "warnings": list(result.get("warnings") or []),
        "summary": markdown,
        "summary_truncated": truncated,
    }


def _wardrive_risk(findings: list[dict[str, Any]]) -> str:
    """The highest severity present in the findings, or ``"none"``. Observed, not computed:
    there is no risk model here and inventing one would be a claim the analysis cannot make."""
    order = ("critical", "high", "medium", "low", "info")
    present = {str(f.get("severity") or "").lower() for f in findings or []}
    for severity in order:
        if severity in present:
            return severity
    return "none"
