"""Read-only previews of programs visible to a researcher on Bugcrowd or Intigriti.

This adapter never writes portfolio records or grants testing authority. It uses
only the platforms' documented researcher-readable GET endpoints, pins each
credentialed request to its API host, refuses redirects, and bounds both network
responses and fan-out. A preview is evidence for operator review, not a scope
authorization. In particular, free-text exclusions are not converted to targets.

Schemas: Bugcrowd API 1.1.0 (program -> engagement -> engagement brief/target
groups/targets); Intigriti researcher API v1.0 (program domains and rules of
engagement). Both can expose less than the complete human-facing program policy.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any, Callable

_BASE = {
    "bugcrowd": "https://api.bugcrowd.com",
    "intigriti": "https://api.intigriti.com/external/researcher",
}
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}\Z")
_MAX_LIST = 100
_PAGE_SIZE = 25
_MAX_PAGES = 4
_MAX_ENGAGEMENTS = 8
_MAX_SCOPE = 300
_MAX_RESPONSE_BYTES = 4_000_000
_TIMEOUT = 15.0
_UA = "GreyIQ-BugHunter/program-preview"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, N802
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _uuid(value: Any) -> str:
    text = str(value or "")
    return text.lower() if _UUID.fullmatch(text) else ""


def _plain(value: Any, limit: int = 200) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = "".join(ch if ch.isprintable() and ch not in "<>" else " " for ch in value)
    return " ".join(cleaned.split())[:limit]


def _excerpt(value: Any, limit: int = 4000) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(ch if ch.isprintable() or ch in "\r\n\t" else " " for ch in value).replace("<", " ").replace(">", " ").strip()[:limit]


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_api_url(platform: str, url: str) -> bool:
    """Validate even injected-fetch URLs before constructing auth headers."""
    try:
        parts = urllib.parse.urlsplit(url)
        if (parts.scheme != "https" or parts.username or parts.password or parts.fragment
                or parts.hostname != urllib.parse.urlsplit(_BASE[platform]).hostname
                or parts.port not in (None, 443)):
            return False
        query = urllib.parse.parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
        if any(len(values) != 1 for values in query.values()):
            return False
        path = parts.path
        if platform == "bugcrowd":
            if path == "/programs":
                allowed = {"page[limit]", "page[offset]"}
            elif re.fullmatch(r"/programs/" + _UUID.pattern[:-2], path):
                allowed = {"include"}
                if query.get("include", ["engagements"])[0] != "engagements":
                    return False
            elif re.fullmatch(r"/engagements/" + _UUID.pattern[:-2], path):
                allowed = {"include"}
                if query.get("include", ["engagement_brief.engagement_brief_target_groups.targets"])[0] != "engagement_brief.engagement_brief_target_groups.targets":
                    return False
            else:
                return False
        else:
            if path == "/external/researcher/v1/programs":
                allowed = {"limit", "offset"}
            elif re.fullmatch(r"/external/researcher/v1/programs/" + _UUID.pattern[:-2], path):
                allowed = set()
            else:
                return False
        if not set(query) <= allowed:
            return False
        for key in ({"page[limit]", "page[offset]", "limit", "offset"} & set(query)):
            if not query[key][0].isdigit():
                return False
        return True
    except (ValueError, KeyError):
        return False


def _fetch_json(url: str, *, headers: dict[str, str], timeout: float) -> Any:
    request = urllib.request.Request(url, headers=headers, method="GET")
    with _OPENER.open(request, timeout=timeout) as response:  # noqa: S310 - exact API URL validated by _request
        body = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(body) > _MAX_RESPONSE_BYTES:
            raise ValueError("API response exceeded the preview size limit")
    return json.loads(body.decode("utf-8"))


def _request(platform: str, url: str, credential: str, fetch: Callable[..., Any] | None) -> Any:
    if not _safe_api_url(platform, url):
        raise ValueError("Unsafe platform API URL")
    auth = "Token " if platform == "bugcrowd" else "Bearer "
    accept = "application/vnd.bugcrowd+json" if platform == "bugcrowd" else "application/json"
    return (fetch or _fetch_json)(url, headers={"Authorization": auth + credential, "Accept": accept,
                                          "User-Agent": _UA}, timeout=_TIMEOUT)


def _valid_credential(platform: str, credential: Any) -> bool:
    if not isinstance(credential, str) or len(credential) > 2000 or not credential:
        return False
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in credential):
        return False
    return platform != "bugcrowd" or credential.count(":") == 1 and all(credential.split(":"))


def _error(platform: str, exc: Exception) -> dict[str, Any]:
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (301, 302, 303, 307, 308):
            return {"status": exc.code, "error": f"{platform.title()} API redirect refused."}
        if exc.code == 401:
            return {"status": 401, "error": f"{platform.title()} rejected the API credential (401)."}
        if exc.code == 403:
            return {"status": 403, "error": f"{platform.title()} denied access to this program (403)."}
        if exc.code == 404:
            return {"status": 404, "error": f"{platform.title()} did not expose this program (404)."}
        return {"status": exc.code, "error": f"{platform.title()} API returned HTTP {exc.code}."}
    if isinstance(exc, ValueError):
        return {"error": str(exc) if str(exc) in ("Unsafe platform API URL", "API response exceeded the preview size limit")
                else f"{platform.title()} returned an invalid API response."}
    return {"error": f"Could not read the {platform.title()} API."}


def _candidate(platform: str, row: Any) -> dict[str, str] | None:
    if not isinstance(row, dict):
        return None
    if platform == "bugcrowd":
        if row.get("type") != "program":
            return None
        program_id = _uuid(row.get("id"))
        attrs = _mapping(row.get("attributes"))
        handle = _plain(attrs.get("code"), 100)
        name = _plain(attrs.get("name"), 200)
        status = "unknown"  # State lives on the program's engagements, not the program.
    else:
        program_id = _uuid(row.get("id"))
        handle = _plain(row.get("handle"), 100)
        name = _plain(row.get("name"), 200)
        status = _plain(_mapping(row.get("status")).get("value"), 60) or "unknown"
    if not program_id or not _HANDLE.fullmatch(handle) or not name:
        return None
    return {"id": program_id, "handle": handle, "name": name, "status": status,
            "source_url": f"{_BASE[platform]}{'/programs/' if platform == 'bugcrowd' else '/v1/programs/'}{program_id}"}


def list_programs(platform: str, credential: str, *, fetch: Callable[..., Any] | None = None,
                  limit: int = 100) -> dict[str, Any]:
    """List bounded, non-authorizing program candidates visible to the API token."""
    platform = str(platform or "").lower()
    if platform not in _BASE:
        return {"ok": False, "programs": [], "warnings": [], "error": "Unsupported platform."}
    if not _valid_credential(platform, credential):
        return {"ok": False, "programs": [], "warnings": [], "error": f"Enter a valid {platform.title()} API credential."}
    try:
        cap = max(1, min(int(limit), _MAX_LIST))
    except (TypeError, ValueError):
        cap = _MAX_LIST
    programs: list[dict[str, str]] = []
    warnings: list[str] = []
    seen: set[str] = set()
    offset = 0
    for page_no in range(_MAX_PAGES):
        size = min(_PAGE_SIZE, cap - len(programs))
        if size <= 0:
            break
        query = urllib.parse.urlencode({("page[limit]" if platform == "bugcrowd" else "limit"): size,
                                         ("page[offset]" if platform == "bugcrowd" else "offset"): offset})
        url = f"{_BASE[platform]}{'/programs' if platform == 'bugcrowd' else '/v1/programs'}?{query}"
        try:
            payload = _request(platform, url, credential, fetch)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            if not programs:
                return {"ok": False, "programs": [], "warnings": [], **_error(platform, exc)}
            warnings.append("Program listing stopped early after an API error; results may be incomplete.")
            break
        if not isinstance(payload, dict):
            if not programs:
                return {"ok": False, "programs": [], "warnings": [], "error": "Unexpected program-list response."}
            warnings.append("Program listing stopped at a malformed page; results may be incomplete.")
            break
        rows = payload.get("data") if platform == "bugcrowd" else payload.get("records")
        if not isinstance(rows, list):
            if not programs:
                return {"ok": False, "programs": [], "warnings": [], "error": "Unexpected program-list response."}
            warnings.append("Program listing stopped at a malformed page; results may be incomplete.")
            break
        bad_rows = 0
        for row in rows[:size]:
            item = _candidate(platform, row)
            if item is None:
                bad_rows += 1
            elif item["id"] not in seen:
                seen.add(item["id"])
                programs.append(item)
        if bad_rows:
            warnings.append(f"Skipped {bad_rows} malformed program row(s) on page {page_no + 1}.")
        if len(rows) > size:
            warnings.append("API returned more rows than requested; extra rows were ignored.")
        total = (_mapping(payload.get("meta")).get("total_hits") if platform == "bugcrowd"
                 else payload.get("maxCount"))
        offset += size
        if isinstance(total, int) and not isinstance(total, bool) and total <= offset:
            break
        if len(rows) < size:
            if isinstance(total, int) and total > offset:
                warnings.append("API pagination ended before its advertised total; listing may be incomplete.")
            break
        if len(programs) >= cap or page_no + 1 >= _MAX_PAGES:
            warnings.append(f"Discovery is capped at {cap} programs and {_MAX_PAGES} pages; more may be available.")
            break
    return {"ok": True, "programs": programs, "warnings": warnings, "count": len(programs)}


def _relation_refs(resource: dict[str, Any], name: str, expected_type: str) -> list[str] | None:
    relation = _mapping(_mapping(resource.get("relationships")).get(name))
    data = relation.get("data")
    if not isinstance(data, list):
        return None
    refs: list[str] = []
    for item in data:
        if not isinstance(item, dict) or item.get("type") != expected_type or not _uuid(item.get("id")):
            return None
        refs.append(_uuid(item["id"]))
    meta = _mapping(_mapping(relation.get("links")).get("related")).get("meta")
    total = _mapping(meta).get("total_hits")
    if isinstance(total, int) and total > len(refs):
        return None
    return refs


def _included_index(payload: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    included = payload.get("included")
    if not isinstance(included, list):
        return {}
    out = {}
    for row in included[:_MAX_SCOPE * 3]:
        if isinstance(row, dict) and isinstance(row.get("type"), str) and _uuid(row.get("id")):
            out[(row["type"], _uuid(row["id"]))] = row
    return out


def _scope_row(identifier: str, asset_type: str, included: bool, instruction: str = "") -> dict[str, Any]:
    return {"identifier": identifier[:500], "asset_type": asset_type[:60],
            "eligible_for_submission": included, "eligible_for_bounty": False,
            "instruction": instruction[:2000], "max_severity": ""}


def _preview_bugcrowd(program_id: str, credential: str, fetch: Callable[..., Any] | None) -> dict[str, Any]:
    source_url = f"{_BASE['bugcrowd']}/programs/{program_id}"
    payload = _request("bugcrowd", source_url + "?include=engagements", credential, fetch)
    row = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(row, dict) or row.get("type") != "program" or _uuid(row.get("id")) != program_id:
        raise ValueError("Malformed program detail")
    attrs = _mapping(row.get("attributes"))
    handle = _plain(attrs.get("code"), 100)
    name = _plain(attrs.get("name"), 200)
    if not _HANDLE.fullmatch(handle) or not name:
        raise ValueError("Malformed program detail")
    warnings: list[str] = []
    entries: list[dict[str, Any]] = []
    excerpts: list[str] = []
    statuses: set[str] = set()
    complete = True
    engagement_ids = _relation_refs(row, "engagements", "engagement")
    if engagement_ids is None or not engagement_ids:
        complete = False
        warnings.append("Bugcrowd did not provide a complete engagement relation; no scope can be confirmed.")
        engagement_ids = []
    if len(engagement_ids) > _MAX_ENGAGEMENTS:
        complete = False
        warnings.append(f"Only the first {_MAX_ENGAGEMENTS} engagements were previewed.")
    for engagement_id in engagement_ids[:_MAX_ENGAGEMENTS]:
        url = (f"{_BASE['bugcrowd']}/engagements/{engagement_id}"
               "?include=engagement_brief.engagement_brief_target_groups.targets")
        try:
            detail = _request("bugcrowd", url, credential, fetch)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError, TimeoutError):
            complete = False
            warnings.append("An engagement could not be read; scope preview is incomplete.")
            continue
        engagement = detail.get("data") if isinstance(detail, dict) else None
        if (not isinstance(engagement, dict) or engagement.get("type") != "engagement"
                or _uuid(engagement.get("id")) != engagement_id):
            complete = False
            warnings.append("Bugcrowd returned a malformed engagement; scope preview is incomplete.")
            continue
        state = _plain(_mapping(engagement.get("attributes")).get("state"), 60)
        if state:
            statuses.add(state)
        brief_ref = _mapping(_mapping(engagement.get("relationships")).get("engagement_brief")).get("data")
        included = _included_index(detail)
        if not isinstance(brief_ref, dict) or brief_ref.get("type") != "engagement_brief":
            complete = False
            warnings.append("An engagement brief is missing; scope preview is incomplete.")
            continue
        brief = included.get(("engagement_brief", _uuid(brief_ref.get("id"))))
        if not brief:
            complete = False
            warnings.append("An engagement brief was not included; scope preview is incomplete.")
            continue
        brief_attrs = _mapping(brief.get("attributes"))
        for key in ("description", "targets_overview"):
            excerpt = _excerpt(brief_attrs.get(key), 2000)
            if excerpt and excerpt not in excerpts:
                excerpts.append(excerpt)
        groups = _relation_refs(brief, "engagement_brief_target_groups", "target_group")
        if groups is None:
            complete = False
            warnings.append("Target-group relation is incomplete; no scope was inferred from it.")
            continue
        for group_id in groups:
            group = included.get(("target_group", group_id))
            if not group:
                complete = False
                warnings.append("A target group was omitted from the API response.")
                continue
            group_attrs = _mapping(group.get("attributes"))
            in_scope = group_attrs.get("in_scope")
            if not isinstance(in_scope, bool):
                complete = False
                warnings.append("A target group has no explicit in-scope flag; its targets were ignored.")
                continue
            targets = _relation_refs(group, "targets", "target")
            if targets is None:
                complete = False
                warnings.append("A target relation is incomplete; no scope was inferred from it.")
                continue
            instruction = _excerpt(group_attrs.get("description"), 1800)
            for target_id in targets:
                target = included.get(("target", target_id))
                target_attrs = _mapping(target.get("attributes")) if target else {}
                identifier = _plain(target_attrs.get("name"), 500)
                if not identifier:
                    complete = False
                    warnings.append("A target was missing its identifier and was ignored.")
                    continue
                entries.append(_scope_row(identifier, _plain(target_attrs.get("category"), 60), in_scope,
                                          instruction))
                if len(entries) >= _MAX_SCOPE:
                    complete = False
                    warnings.append(f"Scope preview is capped at {_MAX_SCOPE} targets.")
                    break
            if len(entries) >= _MAX_SCOPE:
                break
        if len(entries) >= _MAX_SCOPE:
            break
    if not any(entry["eligible_for_submission"] for entry in entries):
        complete = False
        warnings.append("No explicitly in-scope targets were returned.")
    warnings.append("Review the current Bugcrowd brief and free-text exclusions before saving or testing.")
    return {"ok": True, "platform": "bugcrowd", "program_id": program_id, "program_name": name,
            "handle": handle, "structured_scope": entries, "scope_complete": complete,
            "policy_excerpt": "\n\n".join(excerpts)[:4000], "source_url": source_url,
            "fetched_at": datetime.now(UTC).isoformat(), "warnings": warnings,
            "status": next(iter(statuses)) if len(statuses) == 1 else "unknown"}


def _preview_intigriti(program_id: str, credential: str, fetch: Callable[..., Any] | None) -> dict[str, Any]:
    source_url = f"{_BASE['intigriti']}/v1/programs/{program_id}"
    row = _request("intigriti", source_url, credential, fetch)
    if not isinstance(row, dict) or _uuid(row.get("id")) != program_id:
        raise ValueError("Malformed program detail")
    handle = _plain(row.get("handle"), 100)
    name = _plain(row.get("name"), 200)
    if not _HANDLE.fullmatch(handle) or not name:
        raise ValueError("Malformed program detail")
    warnings = ["Intigriti's researcher API does not expose the full out-of-scope section; review the current program page before saving or testing."]
    domains = _mapping(row.get("domains")).get("content")
    entries: list[dict[str, Any]] = []
    if not isinstance(domains, list):
        warnings.append("Program domains are missing; no scope can be confirmed.")
        domains = []
    for domain in domains[:_MAX_SCOPE]:
        if not isinstance(domain, dict):
            warnings.append("A malformed domain row was ignored.")
            continue
        identifier = _plain(domain.get("endpoint"), 500)
        if not identifier:
            warnings.append("A domain without an endpoint was ignored.")
            continue
        tier = _plain(_mapping(domain.get("tier")).get("value"), 60)
        instruction = _excerpt(domain.get("description"), 1800)
        if tier:
            instruction = (instruction + f"\nBounty tier: {tier}").strip()
        # Intigriti labels excluded assets as the explicit "Out of scope" tier.
        # A missing tier is ambiguous and therefore cannot become actionable.
        normalized_tier = " ".join(tier.casefold().replace("-", " ").split())
        eligible = bool(tier) and normalized_tier != "out of scope"
        if not tier:
            warnings.append("A domain had no scope tier and was not treated as in-scope.")
        entries.append(_scope_row(identifier, _plain(_mapping(domain.get("type")).get("value"), 60),
                                  eligible, instruction))
    if len(domains) > _MAX_SCOPE:
        warnings.append(f"Scope preview is capped at {_MAX_SCOPE} domains.")
    rules = _mapping(_mapping(row.get("rulesOfEngagement")).get("content"))
    policy = _excerpt(rules.get("description"), 3500)
    requirements = _mapping(rules.get("testingRequirements"))
    details = []
    for key, label in (("automatedTooling", "Automated tooling setting"),
                       ("userAgent", "Required User-Agent"), ("requestHeader", "Required request header"),
                       ("intigritiMe", "Intigriti researcher email")):
        if key in requirements and requirements[key] is not None:
            details.append(f"{label}: {_plain(str(requirements[key]), 200)}")
    if not rules:
        warnings.append("Rules of engagement are missing from the API response.")
    if not entries:
        warnings.append("No program domains were returned.")
    if details:
        policy = (policy + "\n\n" + "\n".join(details)).strip()[:4000]
    return {"ok": True, "platform": "intigriti", "program_id": program_id, "program_name": name,
            "handle": handle, "structured_scope": entries, "scope_complete": False,
            "policy_excerpt": policy, "source_url": source_url,
            "fetched_at": datetime.now(UTC).isoformat(), "warnings": warnings,
            "status": _plain(_mapping(row.get("status")).get("value"), 60) or "unknown"}


def preview_program(platform: str, program_id: str, credential: str, *,
                    fetch: Callable[..., Any] | None = None) -> dict[str, Any]:
    """Preview one API program by strict UUID; never persist or authorize it."""
    platform = str(platform or "").lower()
    if platform not in _BASE:
        return {"ok": False, "warnings": [], "error": "Unsupported platform."}
    safe_id = _uuid(program_id)
    if not safe_id:
        return {"ok": False, "warnings": [], "error": "A canonical program UUID is required."}
    if not _valid_credential(platform, credential):
        return {"ok": False, "warnings": [], "error": f"Enter a valid {platform.title()} API credential."}
    try:
        return (_preview_bugcrowd if platform == "bugcrowd" else _preview_intigriti)(safe_id, credential, fetch)
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return {"ok": False, "warnings": [], **_error(platform, exc)}
