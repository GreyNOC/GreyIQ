"""GreyIQ BugHunter — program portfolio (the operator's target list).

A small, atomically-written JSON store of the bug-bounty PROGRAMS the autonomous
operator works: each carries its scope (fed verbatim to the same fail-closed
``host_in_active_scope`` gate the active prover uses), its cadence, and its
fail-closed automation flags (active/live default off; legacy auto_submit is always off).

Pure / dependency-free / frozen-safe: one JSON file under the runtime dir, written
atomically, mutations serialized behind a process lock. No network. Storing a
program sends zero packets — the data model alone can never probe or submit; the
operator engine reads these flags and is the only thing that acts on them.

SCOPE POSTURE (fail-closed): a host is NEVER auto-added to in-scope. ``scope_text``
is the single source of truth handed to the scanner; ``out_of_scope_hosts`` is only
ever an EXCLUSION filter, never an expansion. A program with empty scope cannot be
marked active (an empty scope makes the active gate no-op silently).
"""

from __future__ import annotations

import json
import os
import hashlib
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from bughunter.learning import program_key
from bughunter.code_scanner.sources.git_remote import is_supported_remote_git_url

_STORE_NAME = "portfolio.json"
_LOCK = threading.Lock()  # serialize read-modify-write (os.replace is atomic but not RMW-safe)
_MAX_SCOPE_ENTRIES = 500  # bound a program's structured scope (an imported program is a convenience, never an unbounded loader)
_MAX_REPOSITORIES = 25    # each repository becomes a full source campaign; keep program fan-out bounded

# A scheduled operator grant binds to the executable program configuration, not to
# mutable run timestamps. Any change to scope, targets, credentials, policy notes,
# cadence, or testing methods revokes that grant before another request is sent.
_GRANT_EXCLUDED_FIELDS = frozenset({"created_at", "last_run_at", "next_run_at"})


def execution_fingerprint(program: dict[str, Any]) -> str:
    """Stable digest of the program settings an unattended run would use.

    Include every persisted program field except scheduler bookkeeping so new
    fields fail closed by changing the digest. The digest does not expose stored
    research-account secrets; it merely binds authorization to their current
    values, so replacing credentials also requires a fresh grant.
    """
    normalized = _normalize(program)
    snapshot = {key: value for key, value in normalized.items() if key not in _GRANT_EXCLUDED_FIELDS}
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

# Field defaults — every automation flag defaults to the SAFE/off value.
_DEFAULTS: dict[str, Any] = {
    "name": "",
    "platform": "manual",          # 'hackerone' | 'yeswehack' | 'hackenproof' | 'manual' — report-format + display tag; only the human operator submits.
    "platform_handle": "",         # HackerOne team handle for manual routing / YesWeHack or HackenProof program slug
    "scope_text": "",              # free-text, passed verbatim to run_campaign(scope=)
    "in_scope_hosts": [],
    "out_of_scope_hosts": [],
    "seed_targets": [],            # URLs/hosts to hunt (each within scope)
    "repository_urls": [],         # public HTTPS repository roots explicitly selected for source-code hunting
    "clone_repositories": False,   # explicit opt-in: shallow-clone + adversarially scan repository_urls
    # Internal review marker for /api/programs/from-repo. While true, the repo URL is
    # selected but has not yet passed through the existing Program form's Save action,
    # so it must not become scope merely because _normalize runs on a read. The form's
    # resync_scope write clears this marker and the normal source-only derivation resumes.
    "repo_draft_pending": False,
    "structured_scope": [],        # [{identifier, asset_type, eligible_for_submission, eligible_for_bounty, instruction, max_severity}], from HackerOne API/CSV import or hand entry
    "oob_allowed": False,          # operator-confirmed: this program's policy permits out-of-band/collaborator testing
    "disclose_automation": False,  # operator-confirmed: this program's terms require disclosing automated-tool assistance in submitted reports
    "h1_program_stats": {},        # real signals from HackerOne's program resource (offers_bounties, fast_payments, etc.) — see hackerone_import.fetch_structured_scope
    "ywh_program_stats": {},       # the same, for YesWeHack (reward range, VPN/IP constraints, the required UA marker) — see yeswehack_import.fetch_program_scope
    "intake_source": {},           # bounded API provenance only; never grants scope or authorization
    "notes": "",                   # free text — policy excerpt, reward table, anything pasted in
    "account_access": {},          # program research-account access (email/password/login_url/cookie) — see _clean_account_access. SENSITIVE: only ever sent to the program's OWN login page / in-scope hosts, never logged, password redacted in API responses.
    "admin_account_access": {},    # OPTIONAL second, HIGHER-privilege research account (same shape as account_access). When set, unlocks the autonomous BFLA / cross-tenant checks — the low-priv account_access is the "attacker" session, this is the ground-truth admin session. SENSITIVE, same handling.
    "idor_pairs": [],              # OPTIONAL operator-supplied cross-tenant IDOR test pairs [{url_a, url_b, label}] — url_a is an object the PRIMARY account owns, url_b a DIFFERENT object the SECOND account owns. NEVER auto-derived (auto-pairing corrupts the ownership control); the operator asserts ownership. Object URLs only, no secrets. See _clean_idor_pairs.
    "policy_profile": "",          # OPTIONAL VDP policy profile id (e.g. "nasa") — binds the program to a program's rules of engagement (scope + excluded endpoints/classes + confirmed-only + no-DoS). See bughunter.vdp_policy.
    "user_agent_suffix": "",       # a mandatory UA tag some programs require appended to every in-scope request (e.g. " -BugBounty-acme-31337 ")
    "active": False,               # capture proof-of-impact (active verification)
    "live": False,                 # dynamic Playwright pass
    "deep": False,                 # aggressive: time-based SQLi + auto screenshot + research per confirmed lead
    "auto_submit": False,          # legacy field: always normalized off; only a human submits
    "max_pages": 12,
    "interval_minutes": 1440,      # how often the operator re-runs this program
    "max_submits_per_day": 3,      # legacy stored field; automatic submission is disabled
    "enabled": True,               # the operator schedules it
    "created_at": None,
    "last_run_at": None,
    "next_run_at": None,
}


def _store_path(runtime_dir: str | Path) -> Path:
    return Path(runtime_dir) / _STORE_NAME


def _load(runtime_dir: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(_store_path(runtime_dir).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"programs": {}}
    except (OSError, json.JSONDecodeError, RecursionError):
        # RecursionError: a hand-edited/corrupt store with deeply-nested JSON makes
        # json.loads blow the recursion limit; degrade to empty like any other bad load.
        return {"programs": {}}


def _save(runtime_dir: str | Path, data: dict[str, Any]) -> None:
    path = _store_path(runtime_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
    replaced = False
    try:
        tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, path)
        replaced = True
    finally:
        if not replaced:
            tmp.unlink(missing_ok=True)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_int(value: Any, default: int) -> int:
    """Tolerant int() for a field that may arrive as a non-numeric string (a hand-edited
    portfolio.json, the CLI, or any direct upsert_program caller -- only the HTTP API is
    shielded by Pydantic's int fields). A bad value degrades to ``default`` instead of
    raising and aborting the whole write."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clean_scope_entry(entry: Any) -> dict[str, Any] | None:
    """Validate one structured-scope row (from HackerOne API/CSV import or hand entry).
    Returns None for a row with no identifier — never invents a scope entry."""
    if not isinstance(entry, dict):
        return None
    identifier = str(entry.get("identifier") or entry.get("asset_identifier") or "").strip()
    if not identifier:
        return None
    return {
        "identifier": identifier[:500],
        # The HackerOne structured_scope id (from import), so a filed report can be routed
        # to this exact in-scope asset. Preserved verbatim; '' for CSV/hand-entered rows.
        "id": str(entry.get("id") or "").strip()[:64],
        "asset_type": str(entry.get("asset_type") or "").strip()[:60],
        "eligible_for_submission": bool(entry.get("eligible_for_submission", True)),
        "eligible_for_bounty": bool(entry.get("eligible_for_bounty", False)),
        "instruction": str(entry.get("instruction") or "")[:2000],
        "max_severity": str(entry.get("max_severity") or "").strip()[:20],
    }


def _clean_repository_urls(value: Any) -> list[str]:
    """Keep only bounded, deduplicated public repository-root URLs the remote
    scanner can actually clone. Invalid forge pages (issues/blob/tree) and private
    credential-bearing URLs are dropped here, before they can become hunt targets."""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        url = str(item or "").strip().rstrip("/")[:2000]
        key = url.lower()
        if url and key not in seen and is_supported_remote_git_url(url):
            seen.add(key)
            out.append(url)
        if len(out) >= _MAX_REPOSITORIES:
            break
    return out


_H1_STATS_BOOL_FIELDS = ("offers_bounties", "open_scope", "fast_payments", "gold_standard_safe_harbor", "allows_bounty_splitting")
_H1_STATS_STR_FIELDS = ("submission_state", "currency", "state", "started_accepting_at")
_H1_STATS_INT_FIELDS = ("number_of_reports_for_user", "number_of_valid_reports_for_user")


def _clean_h1_program_stats(stats: Any) -> dict[str, Any]:
    """Coerce HackerOne program-resource stats to a fixed known-key shape — never store
    an unbounded blob straight from a third-party API response."""
    if not isinstance(stats, dict):
        return {}
    out: dict[str, Any] = {}
    for field in _H1_STATS_BOOL_FIELDS:
        if field in stats:
            out[field] = bool(stats.get(field))
    for field in _H1_STATS_STR_FIELDS:
        if field in stats:
            out[field] = str(stats.get(field) or "")[:60]
    for field in _H1_STATS_INT_FIELDS:
        if field in stats:
            out[field] = _safe_int(stats.get(field), 0)
    if "bounty_earned_for_user" in stats:
        try:
            out["bounty_earned_for_user"] = float(stats.get("bounty_earned_for_user") or 0.0)
        except (TypeError, ValueError):
            out["bounty_earned_for_user"] = 0.0
    return out


_YWH_STATS_BOOL_FIELDS = ("public", "vdp", "disabled", "offers_bounty", "offers_gift",
                          "vpn_required", "ip_restricted", "hall_of_fame")
_YWH_STATS_STR_FIELDS = ("program_type", "status", "currency", "business_unit", "user_agent_marker")
_YWH_STATS_INT_FIELDS = ("bounty_reward_min", "bounty_reward_max", "reports_count",
                         "average_reward", "max_reward", "average_first_response_days")


def _clean_ywh_program_stats(stats: Any) -> dict[str, Any]:
    """Coerce YesWeHack program-resource stats to a fixed known-key shape — same rule as
    _clean_h1_program_stats: never store an unbounded blob straight from a third-party API."""
    if not isinstance(stats, dict):
        return {}
    out: dict[str, Any] = {}
    for field in _YWH_STATS_BOOL_FIELDS:
        if field in stats:
            out[field] = bool(stats.get(field))
    for field in _YWH_STATS_STR_FIELDS:
        if field in stats:
            # Same sanitizer as user_agent_suffix, not just a length clamp:
            # user_agent_marker is a copy of the value that drives the outbound UA header,
            # so a CR/LF from a compromised API response must not be persisted here either
            # — even though the live UA path sanitizes again downstream. 120 chars matches
            # user_agent_suffix's bound; the other strings are short labels.
            out[field] = _clean_ua_suffix(stats.get(field))
    for field in _YWH_STATS_INT_FIELDS:
        if field in stats:
            out[field] = _safe_int(stats.get(field), 0)
    return out


def _clean_intake_source(value: Any) -> dict[str, Any]:
    """Retain a small, inert provenance record from a reviewed platform import.

    This metadata never participates in scope derivation or authorization. It is
    deliberately a known-key shape, with no credential-bearing URL components or
    unbounded platform response fields copied into the portfolio store.
    """
    if not isinstance(value, dict):
        return {}

    def clean_text(item: Any, limit: int) -> str:
        return "".join(ch for ch in str(item or "") if ch.isprintable()).strip()[:limit]

    platform = "".join(ch for ch in clean_text(value.get("platform"), 40).lower()
                       if ch.isascii() and (ch.isalnum() or ch in "_-"))[:40]
    provider_id = clean_text(value.get("provider_id"), 200)
    status = clean_text(value.get("status"), 40)
    source_url = ""
    raw_url = clean_text(value.get("source_url"), 1000)
    if raw_url:
        try:
            parsed = urlsplit(raw_url)
            if (parsed.scheme.lower() == "https" and parsed.hostname and not parsed.username
                    and not parsed.password and parsed.port is None and not parsed.query
                    and not parsed.fragment):
                source_url = f"https://{parsed.hostname}{parsed.path or ''}"[:500]
        except ValueError:
            pass

    fetched_at = ""
    raw_time = clean_text(value.get("fetched_at"), 40)
    if raw_time:
        try:
            stamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            if stamp.tzinfo is not None:
                fetched_at = stamp.isoformat()
        except ValueError:
            pass

    raw_warnings = value.get("warnings")
    warnings = ([clean_text(item, 240) for item in raw_warnings[:8]]
                if isinstance(raw_warnings, list) else [])
    return {
        "platform": platform,
        "provider_id": provider_id,
        "source_url": source_url,
        "fetched_at": fetched_at,
        "status": status,
        "scope_complete": value.get("scope_complete") is True,
        "warnings": [item for item in warnings if item],
    }


def _excluded_host(identifier: Any) -> str:
    """Turn a URL-shaped exclusion into the host both network gates compare.

    Structured scope keeps its original identifier for operator review. The
    derived ``out_of_scope_hosts`` list is a host exclusion, so preserving a
    full URL there would silently fail to block a broader wildcard scope.
    Existing bare-host and wildcard exclusions retain their prior spelling.
    """
    raw = str(identifier or "").strip()
    if not raw or "://" not in raw:
        return raw
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw
    return parsed.hostname or raw


# The program research-account block: the operator's OWN credentials for THIS program's authorized
# research account (email + password to auto-login, or a pasted session cookie / auth headers as a
# fallback), plus the login/register URLs. Sent ONLY to the program's own login page (same-site,
# scope-gated by the login service), never to a third party. `cookie`/`notes` may be long; the rest
# are short. Nothing here is ever logged; the HTTP API redacts `password`/`cookie` on read-back.
_ACCOUNT_ACCESS_SHORT = ("email", "login_url", "register_url")
_ACCOUNT_ACCESS_LONG = ("password", "cookie", "notes")


def _clean_account_access(value: Any) -> dict[str, Any]:
    """Coerce the research-account block to a fixed known-key shape (never an unbounded blob).
    Drops empty fields; returns {} when nothing is configured."""
    if not isinstance(value, dict):
        return {}
    out: dict[str, Any] = {}
    for f in _ACCOUNT_ACCESS_SHORT:
        v = str(value.get(f) or "").strip()
        if v:
            out[f] = v[:500]
    for f in _ACCOUNT_ACCESS_LONG:
        v = str(value.get(f) or "").strip()
        if v:
            out[f] = v[:8000]
    return out


# Operator-supplied cross-tenant IDOR test pairs. Each is two object URLs on the same app: url_a is an
# object the PRIMARY research account owns, url_b a DIFFERENT object the SECOND account owns. The
# autonomous loop NEVER guesses these (auto-pairing a neighbour id corrupts the ownership control and
# yields false confirmeds) — the operator supplies them, asserting the ownership. No secrets, URLs only.
_MAX_IDOR_PAIRS = 12


def _clean_idor_pairs(value: Any) -> list[dict[str, str]]:
    """Coerce the cross-tenant IDOR test-pair list to a bounded, known-key shape. Each kept entry has a
    non-empty ``url_a`` and ``url_b`` (distinct) plus an optional short ``label``; junk/incomplete pairs
    and exact duplicates are dropped; the list is capped."""
    if not isinstance(value, list):
        return []
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        url_a = str(item.get("url_a") or "").strip()[:2000]
        url_b = str(item.get("url_b") or "").strip()[:2000]
        if not url_a or not url_b or url_a == url_b:
            continue
        key = (url_a, url_b)
        if key in seen:
            continue
        seen.add(key)
        pair = {"url_a": url_a, "url_b": url_b}
        label = str(item.get("label") or "").strip()[:200]
        if label:
            pair["label"] = label
        out.append(pair)
        if len(out) >= _MAX_IDOR_PAIRS:
            break
    return out


def _clean_ua_suffix(value: Any) -> str:
    """A program's mandatory user-agent tag, appended verbatim to the UA header. Keep the operator's
    intended spaces (the requirement value often has them), but STRIP control chars — a CR/LF here
    would be HTTP header injection into every request. Printable ASCII + space only, bounded."""
    raw = str(value or "")
    return "".join(c for c in raw if c == " " or 0x20 < ord(c) < 0x7f)[:120]


def _normalize(record: dict[str, Any]) -> dict[str, Any]:
    out = {**_DEFAULTS, **{k: v for k, v in record.items() if k in _DEFAULTS or k == "id"}}
    out["structured_scope"] = [
        e for e in (_clean_scope_entry(x) for x in (out.get("structured_scope") or [])) if e
    ][:_MAX_SCOPE_ENTRIES]
    out["clone_repositories"] = bool(out.get("clone_repositories"))
    out["repo_draft_pending"] = bool(out.get("repo_draft_pending"))
    out["repository_urls"] = _clean_repository_urls(out.get("repository_urls"))
    # A fetched/imported program can already carry repository roots in structured
    # scope. Once the operator opts in, use those links automatically when no
    # narrower repository selection was saved.
    if out["clone_repositories"] and not out["repository_urls"]:
        out["repository_urls"] = _clean_repository_urls([
            entry.get("identifier")
            for entry in out["structured_scope"]
            if entry.get("eligible_for_submission", True)
        ])
    out["oob_allowed"] = bool(out.get("oob_allowed"))
    out["disclose_automation"] = bool(out.get("disclose_automation"))
    out["h1_program_stats"] = _clean_h1_program_stats(out.get("h1_program_stats"))
    out["ywh_program_stats"] = _clean_ywh_program_stats(out.get("ywh_program_stats"))
    out["intake_source"] = _clean_intake_source(out.get("intake_source"))
    out["notes"] = str(out.get("notes") or "")[:4000]
    out["account_access"] = _clean_account_access(out.get("account_access"))
    out["admin_account_access"] = _clean_account_access(out.get("admin_account_access"))
    out["idor_pairs"] = _clean_idor_pairs(out.get("idor_pairs"))
    # policy_profile: a short id validated against the known VDP profiles (unknown -> "" = no policy).
    from bughunter import vdp_policy
    _pp = str(out.get("policy_profile") or "").strip().lower()[:40]
    out["policy_profile"] = _pp if vdp_policy.get_profile(_pp) else ""
    out["user_agent_suffix"] = _clean_ua_suffix(out.get("user_agent_suffix"))
    # Convenience default ONLY: derive scope_text/in_scope_hosts/out_of_scope_hosts from
    # structured_scope when the caller hasn't already typed a scope. Never overrides a
    # hand-edited scope_text -- structured_scope is a source to pull FROM, not a mirror.
    if out["structured_scope"] and not str(out.get("scope_text") or "").strip():
        in_ids = [e["identifier"] for e in out["structured_scope"] if e["eligible_for_submission"]]
        out_ids = [_excluded_host(e["identifier"]) for e in out["structured_scope"]
                   if not e["eligible_for_submission"]]
        out["scope_text"] = " ".join(in_ids)
        if not out.get("in_scope_hosts"):
            out["in_scope_hosts"] = in_ids
        if not out.get("out_of_scope_hosts"):
            out["out_of_scope_hosts"] = out_ids
    # A manually entered source repository is itself the saved authorization scope.
    # This keeps repository-only programs usable without inventing a live web host.
    if (out["clone_repositories"] and out["repository_urls"]
            and not out["repo_draft_pending"] and not str(out.get("scope_text") or "").strip()):
        out["scope_text"] = "\n".join(out["repository_urls"])
    # Fail-closed coupling: active/live/deep require a non-empty scope.
    if not str(out.get("scope_text") or "").strip():
        out["active"] = False
        out["live"] = False
        out["deep"] = False
    # Deep implies proof-of-impact (it adds time-based SQLi + screenshot/research per
    # confirmed lead), so a deep program is always active.
    if out.get("deep"):
        out["active"] = True
    # Old portfolio.json records and API clients may still carry auto_submit=True.
    # Normalize it off on both reads and writes so persisted flags cannot arm a loop.
    out["auto_submit"] = False
    out["max_pages"] = max(1, min(_safe_int(out.get("max_pages") or 12, 12), 50))
    out["interval_minutes"] = max(5, _safe_int(out.get("interval_minutes") or 1440, 1440))
    # Keep the legacy cap for storage compatibility; it no longer controls filing.
    out["max_submits_per_day"] = max(0, min(_safe_int(out.get("max_submits_per_day", 3), 3), 25))
    out["in_scope_hosts"] = [str(h).strip() for h in (out.get("in_scope_hosts") or []) if str(h).strip()]
    out["out_of_scope_hosts"] = [_excluded_host(h) for h in (out.get("out_of_scope_hosts") or [])
                                 if str(h or "").strip()]
    out["seed_targets"] = [str(t).strip() for t in (out.get("seed_targets") or []) if str(t).strip()]
    return out


def list_programs(runtime_dir: str | Path) -> list[dict[str, Any]]:
    """Every record is re-normalized on read (idempotent for anything already written via
    ``upsert_program``) so a record from BEFORE a field existed (e.g. one hand-written or
    saved by an older GreyIQ version) always carries every current field's safe default,
    instead of a caller needing to know which fields might be missing."""
    progs = _load(runtime_dir).get("programs", {})
    return [_normalize({**progs[k], "id": k}) for k in sorted(progs) if isinstance(progs[k], dict)]


def get_program(runtime_dir: str | Path, program_id: str) -> dict[str, Any] | None:
    prog = _load(runtime_dir).get("programs", {}).get(str(program_id))
    return _normalize({**prog, "id": str(program_id)}) if isinstance(prog, dict) else None


def upsert_program(runtime_dir: str | Path, record: dict[str, Any]) -> dict[str, Any]:
    """Create or update a program. The id is derived from the program name/handle via
    the shared program_key, so the portfolio, ledger, and learning store all key on
    the SAME id (one program = one memory).

    ``record["resync_scope"]`` (not a stored field — read here, never persisted) is an
    explicit signal from a caller that owns the structured/repository scope controls (the
    Program-setup UI) that scope_text/in_scope_hosts/out_of_scope_hosts should be RE-derived
    from whatever structured/repository scope this call carries, even if scope_text already
    exists from a prior save. Without it, ``_normalize``'s derivation only ever fires once (when
    scope_text starts out empty) -- a later edit that changes structured_scope would
    otherwise leave the stale, previously-derived scope_text in place forever, since a
    caller that doesn't expose a scope_text field of its own has no other way to ask for
    a refresh without risking clobbering a scope some OTHER caller (e.g. the Operator
    tab's plain-text scope field) hand-typed on purpose."""
    name = str(record.get("name") or "").strip()
    handle = str(record.get("platform_handle") or "").strip()
    seed = str((record.get("seed_targets") or [""])[0] if record.get("seed_targets") else "")
    pid = str(record.get("id") or "").strip() or program_key(name or handle, record.get("scope_text") or seed)
    with _LOCK:
        data = _load(runtime_dir)
        programs = data.setdefault("programs", {})
        existing = programs.get(pid, {})
        merge_source = {**existing, **record, "id": pid}
        if record.get("resync_scope"):
            # A Save from the full Program form is the explicit review action that
            # finalizes a repo-link draft. Once cleared, _normalize may derive the
            # repository-only source scope exactly as it did before this onboarding path.
            merge_source["repo_draft_pending"] = False
            should_clear_scope = bool(merge_source.get("structured_scope"))
            # The Program form also owns repository-only scope. If the existing scope
            # was auto-derived from its old repository selection, clear it before
            # normalizing so changing/removing that selection cannot leave a stale repo
            # URL behind. A hand-typed Operator scope is preserved.
            if not should_clear_scope and ("repository_urls" in record or "clone_repositories" in record):
                old_repository_scope = "\n".join(_clean_repository_urls(existing.get("repository_urls")))
                current_scope = str(existing.get("scope_text") or "").strip()
                should_clear_scope = not current_scope or current_scope == old_repository_scope.strip()
            if should_clear_scope:
                merge_source["scope_text"] = ""
                merge_source["in_scope_hosts"] = []
                merge_source["out_of_scope_hosts"] = []
        merged = _normalize(merge_source)
        merged["name"] = name or existing.get("name") or pid
        merged["created_at"] = existing.get("created_at") or _now()
        programs[pid] = merged
        _save(runtime_dir, data)
        return merged


def remove_program(runtime_dir: str | Path, program_id: str) -> bool:
    with _LOCK:
        data = _load(runtime_dir)
        if str(program_id) in data.get("programs", {}):
            del data["programs"][str(program_id)]
            _save(runtime_dir, data)
            return True
    return False


def set_enabled(runtime_dir: str | Path, program_id: str, enabled: bool) -> dict[str, Any] | None:
    with _LOCK:
        data = _load(runtime_dir)
        prog = data.get("programs", {}).get(str(program_id))
        if not prog:
            return None
        prog["enabled"] = bool(enabled)
        _save(runtime_dir, data)
        return prog


def touch_run(runtime_dir: str | Path, program_id: str, *, next_run_at: str | None) -> None:
    """Stamp last_run_at=now and the scheduled next_run_at after a cycle completes."""
    with _LOCK:
        data = _load(runtime_dir)
        prog = data.get("programs", {}).get(str(program_id))
        if not prog:
            return
        prog["last_run_at"] = _now()
        prog["next_run_at"] = next_run_at
        _save(runtime_dir, data)
