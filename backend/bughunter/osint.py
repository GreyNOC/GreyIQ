"""GreyIQ passive OSINT campaigns with evidence-calibrated asset promotion.

The engine queries public indexes, never the investigated target:

* crt.sh and Cert Spotter provide independent certificate-transparency observations;
* Google and Cloudflare DNS-over-HTTPS provide independent current DNS observations.

Every fact keeps its source IDs and retrieval time.  Exact agreement from two independent
providers is ``verified``; a single-provider observation stays ``observed``; a CT-only hostname is
explicitly ``historical``.  Only hostnames independently observed in current public DNS are eligible
for the optional BugHunter handoff.  OSINT discovers candidates -- it never grants authorization.

Stdlib-only, bounded, frozen-safe, and deliberately free of model-generated facts.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from bughunter import fsutil
from bughunter.registrable_domain import is_bare_public_suffix, registrable_domain

SCHEMA_VERSION = 1
DEFAULT_MAX_HOSTS = 25
MAX_HOSTS = 100
_MAX_RESPONSE_BYTES = 4_000_000
_MAX_WORKERS = 8
_ALLOWED_PROVIDER_HOSTS = frozenset({"crt.sh", "api.certspotter.com", "dns.google", "cloudflare-dns.com"})
_HOST_RE = re.compile(r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$", re.IGNORECASE)
_DNS_TYPES = {1: "dns-a", 2: "dns-ns", 5: "dns-cname", 15: "dns-mx", 28: "dns-aaaa"}

FetchJSON = Callable[..., Any]


class OsintInputError(ValueError):
    """The operator supplied an invalid OSINT subject or option."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def normalize_domain(value: str) -> str:
    """Return a lower-case IDNA hostname from a hostname or URL.

    IP literals, single-label names, wildcard inputs, and known shared/public suffixes are rejected:
    an OSINT campaign needs one real domain boundary, not an authorization-expanding pattern.
    """
    raw = str(value or "").strip()
    if not raw or any(ch in raw for ch in "\r\n\0"):
        raise OsintInputError("a domain or https:// URL is required")
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password:
            raise OsintInputError("URL input must be an absolute http(s) URL without credentials")
        host = parsed.hostname or ""
    else:
        if any(ch in raw for ch in "/?#@"):
            raise OsintInputError("use a bare domain or an absolute http(s) URL")
        host = raw.strip(".")
    if host.startswith("*."):
        raise OsintInputError("use the owned apex domain, not a wildcard")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise OsintInputError("OSINT campaigns require a domain, not an IP literal")
    try:
        host = host.encode("idna").decode("ascii").lower().strip(".")
    except UnicodeError as exc:
        raise OsintInputError("the domain is not valid IDNA") from exc
    if not _HOST_RE.fullmatch(host):
        raise OsintInputError("the domain is not a valid dotted hostname")
    apex = registrable_domain(host)
    if not apex or is_bare_public_suffix(apex):
        raise OsintInputError("use a registrable domain, not a public/shared suffix")
    return host


def _safe_provider_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in _ALLOWED_PROVIDER_HOSTS:
        raise ValueError("OSINT provider URL is not allowlisted")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("OSINT provider URL contains unsupported authority data")
    return url


def _fetch_json(url: str, *, headers: dict[str, str] | None = None, timeout: float = 10.0) -> Any:
    """Bounded JSON GET to one fixed public-OSINT provider, with one transient retry."""
    safe_url = _safe_provider_url(url)
    req_headers = {"User-Agent": "GreyIQ-OSINT/1.0", "Accept": "application/json"}
    req_headers.update(headers or {})
    request = urllib.request.Request(safe_url, headers=req_headers, method="GET")
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - host allowlist above
                body = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise ValueError("OSINT provider response exceeded the size limit")
                return json.loads(body.decode("utf-8", "replace"))
        except urllib.error.HTTPError:
            raise  # a provider answer is not transient
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt:
                raise
            time.sleep(0.25)
    return None  # pragma: no cover - loop either returns or raises


def _valid_child(raw: Any, apex: str) -> str:
    candidate = str(raw or "").strip().lower().lstrip("*.").rstrip(".")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if not _HOST_RE.fullmatch(candidate):
        return ""
    return candidate if candidate == apex or candidate.endswith("." + apex) else ""


def _ct_names(provider: str, apex: str, data: Any, cap: int) -> list[str]:
    names: set[str] = set()
    rows = data if isinstance(data, list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        values: list[Any]
        if provider == "crtsh":
            values = str(row.get("name_value") or "").splitlines()
        else:
            values = row.get("dns_names") if isinstance(row.get("dns_names"), list) else []
        for value in values:
            host = _valid_child(value, apex)
            if host:
                names.add(host)
        if len(names) >= cap:
            break
    return sorted(names)[:cap]


def _normalize_dns_value(record_type: int, value: Any) -> str:
    text = str(value or "").strip().rstrip(".")
    if record_type == 15:  # MX: normalize "priority mail.example.com."
        parts = text.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            return f"{int(parts[0])} {parts[1].lower().rstrip('.')}"
    if record_type in {2, 5}:
        return text.lower()
    if record_type in {1, 28}:
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return ""
    return text[:500]


def _dns_observations(host: str, data: Any) -> list[tuple[str, str, str]]:
    """Return normalized ``(kind, subject, value)`` tuples from RFC 8484 JSON."""
    if not isinstance(data, dict) or int(data.get("Status", -1)) != 0:
        return []
    out: list[tuple[str, str, str]] = []
    for row in data.get("Answer") if isinstance(data.get("Answer"), list) else []:
        if not isinstance(row, dict):
            continue
        try:
            rtype = int(row.get("type"))
        except (TypeError, ValueError):
            continue
        kind = _DNS_TYPES.get(rtype)
        value = _normalize_dns_value(rtype, row.get("data"))
        subject = _valid_child(row.get("name") or host, registrable_domain(host)) or host
        if kind and value:
            out.append((kind, subject, value))
    return out


def _is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private or address.is_loopback or address.is_link_local or address.is_multicast
        or address.is_reserved or address.is_unspecified
    )


def _source(source_id: str, provider: str, kind: str, url: str, retrieved_at: str,
            *, ok: bool, records: int = 0, error: str = "") -> dict[str, Any]:
    return {
        "id": source_id, "provider": provider, "kind": kind, "url": url,
        "retrieved_at": retrieved_at, "ok": ok, "records": records, "error": error[:300],
    }


def _confidence(status: str) -> str:
    return {"verified": "high", "observed": "medium", "historical": "low"}.get(status, "low")


def _render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    out = [
        f"# OSINT Campaign — {result['domain']}", "",
        "| | |", "|---|---|",
        f"| **Status** | {result['status']} |",
        f"| **Assets** | {summary['assets_total']} observed · {summary['hunt_eligible']} DNS-verified |",
        f"| **Claims** | {summary['claims_verified']} verified · {summary['claims_observed']} observed/historical |",
        f"| **Providers** | {summary['providers_ok']} reached · {summary['providers_failed']} unavailable |",
        f"| **Queries** | {summary['queries_ok']} succeeded · {summary['queries_failed']} failed |",
        f"| **Generated** | {result['completed_at']} |", "",
        "## Decision rule", "",
        "Exact agreement from two independent providers is **verified**. Single-provider facts remain "
        "**observed**; CT-only hostnames remain **historical**. Only hosts independently present in "
        "current public DNS are eligible for the BugHunter handoff. OSINT evidence does not grant scope.", "",
        "## Assets", "",
        "| Host | State | CT | Public addresses | Hunt handoff |", "|---|---|---|---|---|",
    ]
    for asset in result["assets"]:
        addresses = ", ".join(asset["public_addresses"]) or "—"
        out.append(
            f"| `{asset['hostname']}` | {asset['state']} | {asset['ct_status']} | {addresses} | "
            f"{'eligible' if asset['hunt_eligible'] else 'withheld'} |"
        )
    out.extend(["", "## Sources", ""])
    for source in result["sources"]:
        state = f"ok ({source['records']} records)" if source["ok"] else f"failed: {source['error']}"
        out.append(f"- **{source['provider']}** `{source['kind']}` — {state} — {source['url']}")
    out.extend(["", "## Accuracy notes", ""])
    if result["notes"]:
        out.extend(f"- {note}" for note in result["notes"])
    else:
        out.append("- All configured providers completed.")
    out.extend(["", "---", "_GreyIQ passive OSINT. Re-check volatile DNS immediately before acting._"])
    return "\n".join(out)


def run_campaign(
    target: str,
    *,
    output_dir: str | Path,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    timeout: float = 10.0,
    fetch_json: FetchJSON | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Run a bounded passive domain campaign and write JSON + Markdown evidence artifacts."""
    domain = normalize_domain(target)
    apex = registrable_domain(domain)
    try:
        max_hosts = int(max_hosts)
    except (TypeError, ValueError) as exc:
        raise OsintInputError("max_hosts must be an integer") from exc
    if not 1 <= max_hosts <= MAX_HOSTS:
        raise OsintInputError(f"max_hosts must be between 1 and {MAX_HOSTS}")
    try:
        timeout = float(timeout)
    except (TypeError, ValueError) as exc:
        raise OsintInputError("timeout must be a number") from exc
    if not 0.5 <= timeout <= 30.0:
        raise OsintInputError("timeout must be between 0.5 and 30 seconds")
    fetch = fetch_json or _fetch_json
    started_at = now or _utc_now()
    sources: list[dict[str, Any]] = []
    observations: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    ct_by_provider: dict[str, set[str]] = {"crtsh": set(), "certspotter": set()}
    notes: list[str] = []

    ct_requests = [
        ("crtsh", f"https://crt.sh/?q=%25.{urllib.parse.quote(apex)}&output=json", {}),
        ("certspotter", "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode({
            "domain": apex, "include_subdomains": "true", "expand": "dns_names", "match_wildcards": "true",
        }), {}),
    ]
    for provider, url, headers in ct_requests:
        sid = f"{provider}:ct:{apex}"
        retrieved = _utc_now()
        try:
            data = fetch(url, headers=headers, timeout=timeout)
            names = _ct_names(provider, apex, data, max_hosts * 4)
            ct_by_provider[provider].update(names)
            sources.append(_source(sid, provider, "certificate-transparency", url, retrieved,
                                   ok=True, records=len(names)))
            for host in names:
                observations[("ct-hostname", host, host)].add(sid)
        except Exception as exc:  # noqa: BLE001 - one public provider must never abort the campaign
            sources.append(_source(sid, provider, "certificate-transparency", url, retrieved,
                                   ok=False, error=f"{type(exc).__name__}: {exc}"))
            notes.append(f"{provider} failed; CT coverage is partial.")

    # Put the requested domain first, then CT-agreed names, then single-index names.  This keeps the
    # bounded DNS budget focused on the strongest candidates while preserving deterministic output.
    ct_all = ct_by_provider["crtsh"] | ct_by_provider["certspotter"]
    ct_both = ct_by_provider["crtsh"] & ct_by_provider["certspotter"]
    candidates = [domain]
    candidates.extend(sorted(ct_both - {domain}))
    candidates.extend(sorted(ct_all - set(candidates)))
    candidates = list(dict.fromkeys(candidates))[:max_hosts]

    dns_jobs: list[tuple[str, str, str, str]] = []
    for host in candidates:
        for provider, base in (
            ("google-doh", "https://dns.google/resolve"),
            ("cloudflare-doh", "https://cloudflare-dns.com/dns-query"),
        ):
            for rtype in ("A", "AAAA"):
                url = base + "?" + urllib.parse.urlencode({"name": host, "type": rtype})
                dns_jobs.append((provider, host, rtype, url))
    # Apex ownership/routing context is useful but stays bounded: four additional requests.
    for provider, base in (
        ("google-doh", "https://dns.google/resolve"),
        ("cloudflare-doh", "https://cloudflare-dns.com/dns-query"),
    ):
        for rtype in ("NS", "MX"):
            dns_jobs.append((provider, apex, rtype, base + "?" + urllib.parse.urlencode({"name": apex, "type": rtype})))

    def query(job: tuple[str, str, str, str]) -> tuple[dict[str, Any], list[tuple[str, str, str]]]:
        provider, host, rtype, url = job
        sid = f"{provider}:dns:{rtype.lower()}:{host}"
        retrieved = _utc_now()
        headers = {"Accept": "application/dns-json"} if provider == "cloudflare-doh" else {}
        try:
            data = fetch(url, headers=headers, timeout=timeout)
            rows = _dns_observations(host, data)
            return _source(sid, provider, f"dns-{rtype.lower()}", url, retrieved,
                           ok=True, records=len(rows)), rows
        except Exception as exc:  # noqa: BLE001 - one public provider must never abort the campaign
            return _source(sid, provider, f"dns-{rtype.lower()}", url, retrieved,
                           ok=False, error=f"{type(exc).__name__}: {exc}"), []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(dns_jobs))) as executor:
        dns_results = list(executor.map(query, dns_jobs))
    for source, rows in dns_results:
        sources.append(source)
        if not source["ok"]:
            continue
        for kind, subject, value in rows:
            observations[(kind, subject, value)].add(source["id"])

    claims: list[dict[str, Any]] = []
    for index, ((kind, subject, value), source_ids) in enumerate(sorted(observations.items()), 1):
        providers = {sid.split(":", 1)[0] for sid in source_ids}
        if len(providers) >= 2:
            status = "verified"
        elif kind == "ct-hostname":
            status = "historical"
        else:
            status = "observed"
        claims.append({
            "id": f"C{index}", "kind": kind, "subject": subject, "value": value,
            "status": status, "confidence": _confidence(status),
            "source_ids": sorted(source_ids), "independent_sources": len(providers),
            "observed_at": started_at,
        })

    assets: list[dict[str, Any]] = []
    for host in candidates:
        ct_sources = {
            sid.split(":", 1)[0]
            for (kind, subject, _), ids in observations.items() if kind == "ct-hostname" and subject == host
            for sid in ids
        }
        dns_providers: set[str] = set()
        addresses: set[str] = set()
        blocked_addresses: set[str] = set()
        cname_values: set[str] = set()
        for (kind, subject, value), ids in observations.items():
            if subject != host or kind not in {"dns-a", "dns-aaaa", "dns-cname"}:
                continue
            dns_providers.update(sid.split(":", 1)[0] for sid in ids)
            if kind in {"dns-a", "dns-aaaa"}:
                (addresses if _is_public_address(value) else blocked_addresses).add(value)
            elif kind == "dns-cname":
                cname_values.add(value)
        hunt_eligible = len(dns_providers) >= 2 and bool(addresses) and not blocked_addresses
        if hunt_eligible:
            state = "dns-verified"
        elif dns_providers:
            state = "dns-observed"
        elif ct_sources:
            state = "historical-only"
        else:
            state = "unresolved"
        assets.append({
            "hostname": host, "state": state,
            "ct_status": "verified" if len(ct_sources) >= 2 else ("historical" if ct_sources else "not-observed"),
            "ct_providers": sorted(ct_sources), "dns_providers": sorted(dns_providers),
            "public_addresses": sorted(addresses), "blocked_addresses": sorted(blocked_addresses),
            "cnames": sorted(cname_values), "hunt_eligible": hunt_eligible,
        })

    failed = [source for source in sources if not source["ok"]]
    if failed:
        notes.append(f"{len(failed)} of {len(sources)} bounded provider queries failed; no missing answer was treated as a fact.")
    if len(ct_all) + 1 > len(candidates):
        notes.append(f"DNS validation capped at {max_hosts} candidates; {len(ct_all) + 1 - len(candidates)} lower-ranked CT names were withheld.")
    if any(asset["blocked_addresses"] for asset in assets):
        notes.append("Private/reserved DNS answers were recorded as blocked and withheld from the hunt handoff.")

    completed_at = _utc_now()
    all_providers = {s["provider"] for s in sources}
    reached_providers = {s["provider"] for s in sources if s["ok"]}
    providers_ok = len(reached_providers)
    providers_failed = len(all_providers - reached_providers)
    campaign_status = "failed" if not reached_providers else ("partial" if failed else "complete")
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": hashlib.sha256(f"{apex}|{started_at}".encode()).hexdigest()[:16],
        "domain": domain, "apex": apex, "started_at": started_at, "completed_at": completed_at,
        "status": campaign_status,
        "summary": {
            "assets_total": len(assets), "hunt_eligible": sum(1 for a in assets if a["hunt_eligible"]),
            "claims_total": len(claims), "claims_verified": sum(1 for c in claims if c["status"] == "verified"),
            "claims_observed": sum(1 for c in claims if c["status"] != "verified"),
            "providers_ok": providers_ok, "providers_failed": providers_failed,
            "queries_ok": sum(1 for source in sources if source["ok"]),
            "queries_failed": len(failed),
        },
        "assets": assets, "claims": claims, "sources": sources, "notes": notes,
        "hunt_targets": [f"https://{a['hostname']}/" for a in assets if a["hunt_eligible"]],
    }

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    fingerprint = result["campaign_id"][:8]
    campaign_dir = Path(output_dir) / f"osint-{re.sub(r'[^a-z0-9.-]+', '-', apex)}-{stamp}-{fingerprint}"
    json_path = campaign_dir / "osint.json"
    markdown_path = campaign_dir / "OSINT.md"
    # Paths are intentionally added before serialization so the JSON artifact is self-describing.
    result["output_dir"] = str(campaign_dir)
    result["json_path"] = str(json_path)
    result["report_path"] = str(markdown_path)
    fsutil.write_text_safe(json_path, json.dumps(result, indent=2, ensure_ascii=False, default=str))
    fsutil.write_text_safe(markdown_path, _render_markdown(result))
    return result
