"""GreyIQ BugHunter — target/scope ingest from CSV, Burp Suite XML, and HAR.

Parses an operator-supplied export — a **CSV** of hosts/URLs, a **Burp Suite** "save
selected items" / sitemap XML export, or a **HAR** capture — into a NORMALIZED,
de-duplicated list of:
  * ``targets`` — full URLs (query strings PRESERVED, so the active prover mines their
    params via the same path it uses for recon-discovered params), and
  * ``hosts`` — the bare hostnames, for the Scope box.

SAFETY: ingest is pure / no-network / frozen-safe (stdlib only) and **never** acts on
its own. It NEVER probes, NEVER auto-arms, and NEVER adds a host to in-scope — it only
returns a list the operator reviews and chooses to use; the fail-closed
``host_in_active_scope`` gate still governs every probe. XML is parsed defensively: a
``<!DOCTYPE``/``<!ENTITY`` declaration is REFUSED (blocks billion-laughs entity expansion
and external-entity reads) and the whole input is byte-bounded, so a hostile file can do
nothing but be rejected.
"""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlparse

from bughunter.web_ingest import WebsiteFetchError, normalize_website_url

# Hard ceilings — ingest is a convenience, never an unbounded loader.
MAX_INPUT_BYTES = 4_000_000   # ~4 MB of pasted/loaded text
MAX_TARGETS = 2000            # cap the produced target list
MAX_PARAM_NAMES = 200

# CSV column-name hints (substring match, case-insensitive). URL columns win over host
# columns when both are present (a full URL carries more — path + params).
_URL_HINTS = ("url", "uri", "endpoint", "request", "link", "address", "location")
_HOST_HINTS = ("host", "domain", "asset", "hostname", "fqdn", "site", "scope", "target")
_DOCTYPE_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
# A query-param name worth surfacing (mirrors the active prover's accepted token shape).
_PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-\[\]\.]{0,39}$")


def _err(kind: str, message: str) -> dict[str, Any]:
    return {"ok": False, "kind": kind, "error": message, "targets": [], "hosts": [],
            "param_names": [], "count": 0, "host_count": 0, "notes": []}


def _normalize_one(raw: str) -> str:
    """Normalize one raw token (a host or a URL) into a full ``https?://…`` URL, or ""
    when it is not a plausible target. Requires a DOTTED host (or an IP literal) so a
    stray cell like ``n/a`` / ``comment`` / a header label never becomes a bogus target."""
    token = (raw or "").strip().strip("\"'<>()[]{}").rstrip(".,;")
    if not token or any(c.isspace() for c in token):
        return ""
    try:
        norm = normalize_website_url(token)   # prepends https:// when scheme-less; no network
    except WebsiteFetchError:
        return ""
    host = (urlparse(norm).hostname or "").strip()
    if not host:
        return ""
    if "." not in host and ":" not in host:   # bare single-label word -> not a target
        return ""
    return norm


def _host_of(url: str) -> str:
    return (urlparse(url).hostname or "").strip().lower()


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        v = (item or "").strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _param_names(urls: Iterable[str]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for url in urls:
        for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
            low = key.lower()
            if low not in seen and _PARAM_NAME_RE.match(key):
                seen.add(low)
                names.append(key)
                if len(names) >= MAX_PARAM_NAMES:
                    return names
    return names


def _finalize(kind: str, targets: list[str], notes: list[str]) -> dict[str, Any]:
    uniq = _dedupe(targets)
    out_notes = list(notes)
    if len(uniq) > MAX_TARGETS:
        uniq = uniq[:MAX_TARGETS]
        out_notes.append(f"Capped to the first {MAX_TARGETS} targets.")
    hosts = _dedupe(_host_of(t) for t in uniq)
    if not uniq:
        out_notes.append("No valid targets found (need dotted hosts or http(s) URLs).")
    return {
        "ok": bool(uniq), "kind": kind, "targets": uniq, "hosts": hosts,
        "param_names": _param_names(uniq), "count": len(uniq), "host_count": len(hosts),
        "notes": out_notes,
    }


def _pick_column(header: list[str]) -> int | None:
    """Return the index of the best target column in a header row, or None when the row
    has no recognizable target column (then the caller scans every cell)."""
    cells = [str(c or "").strip().lower() for c in header]
    for hints in (_URL_HINTS, _HOST_HINTS):
        for index, cell in enumerate(cells):
            if cell and any(h in cell for h in hints):
                return index
    return None


def parse_csv(text: str) -> dict[str, Any]:
    """A CSV of hosts/URLs. Uses a recognized column when the header names one
    (url/host/domain/…), otherwise scans every cell — so a bare one-column list works
    too. Non-target cells (labels, ``n/a``, counts) are dropped by ``_normalize_one``."""
    body = text.lstrip("﻿")
    try:
        try:
            dialect: Any = csv.Sniffer().sniff(body[:4096], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        rows = list(csv.reader(io.StringIO(body), dialect))
    except csv.Error as exc:
        return _err("csv", f"Could not parse CSV: {exc}")
    if not rows:
        return _finalize("csv", [], [])
    column = _pick_column(rows[0])
    collected: list[str] = []
    if column is not None:
        for row in rows[1:]:            # skip the header row
            if column < len(row):
                collected.append(row[column])
    else:
        for row in rows:               # no header column -> scan everything
            collected.extend(row)
    return _finalize("csv", [n for n in (_normalize_one(c) for c in collected) if n], [])


def parse_burp_xml(text: str) -> dict[str, Any]:
    """A Burp Suite items / sitemap XML export. Reads each <item>'s <url> (falling back to
    protocol+host+path). DOCTYPE/ENTITY-bearing XML is refused before parsing."""
    if _DOCTYPE_RE.search(text):
        return _err("burp", "XML carrying a DOCTYPE/ENTITY declaration is refused (entity-expansion guard).")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return _err("burp", f"Could not parse Burp XML: {exc}")
    targets: list[str] = []
    for item in root.iter("item"):
        url = (item.findtext("url") or "").strip()
        if not url:
            host = (item.findtext("host") or "").strip()
            if host:
                proto = (item.findtext("protocol") or "https").strip() or "https"
                url = f"{proto}://{host}{(item.findtext('path') or '').strip()}"
        norm = _normalize_one(url)
        if norm:
            targets.append(norm)
    return _finalize("burp", targets, [] if targets else ["No <item><url> entries found — is this a Burp items/sitemap export?"])


def parse_har(text: str) -> dict[str, Any]:
    """A HAR capture (browser/Burp/ZAP). Reads log.entries[].request.url."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return _err("har", f"Could not parse HAR JSON: {exc}")
    entries = (((data or {}).get("log") or {}).get("entries")) if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return _err("har", "Not a HAR file (no log.entries array).")
    targets: list[str] = []
    for entry in entries:
        request = (entry or {}).get("request") or {} if isinstance(entry, dict) else {}
        norm = _normalize_one(str(request.get("url") or ""))
        if norm:
            targets.append(norm)
    return _finalize("har", targets, [])


def _detect(text: str) -> str:
    head = text.lstrip("﻿ \t\r\n")
    if head.startswith("<"):
        return "burp"
    if head[:1] in ("{", "["):
        return "har"
    return "csv"


def ingest(content: str, kind: str = "auto") -> dict[str, Any]:
    """Parse ``content`` (CSV / Burp XML / HAR) into normalized targets + hosts.

    ``kind`` is ``auto`` (sniff by the leading character), ``csv``, ``burp`` (or ``xml``),
    or ``har``. Pure / no-network; the result is for the operator to review and apply —
    it is never auto-added to scope."""
    raw = content or ""
    if len(raw.encode("utf-8", "ignore")) > MAX_INPUT_BYTES:
        return _err((kind or "auto"), f"Input is too large (limit {MAX_INPUT_BYTES // 1_000_000} MB).")
    chosen = (kind or "auto").strip().lower()
    if chosen == "auto":
        chosen = _detect(raw)
    if chosen == "csv":
        return parse_csv(raw)
    if chosen in ("burp", "xml"):
        return parse_burp_xml(raw)
    if chosen == "har":
        return parse_har(raw)
    return _err(chosen, f"Unknown ingest kind '{kind}' (use auto, csv, burp, or har).")
