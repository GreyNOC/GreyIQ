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
MAX_SCOPE_ENTRIES = 500       # cap a HackerOne-style structured-scope import (mirrors portfolio._MAX_SCOPE_ENTRIES)

# CSV column-name hints (substring match, case-insensitive). URL columns win over host
# columns when both are present (a full URL carries more — path + params).
_URL_HINTS = ("url", "uri", "endpoint", "request", "link", "address", "location")
_HOST_HINTS = ("host", "domain", "asset", "hostname", "fqdn", "site", "scope", "target", "identifier")
_DOCTYPE_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)

# HackerOne structured-scope CSV column hints (substring match, case-insensitive).
_H1_ID_HINTS = ("asset_identifier", "identifier", "asset")
_H1_TYPE_HINTS = ("asset_type", "type")
_H1_SUBMIT_HINTS = ("eligible_for_submission", "eligible for submission", "in_scope", "in scope", "submission")
_H1_BOUNTY_HINTS = ("eligible_for_bounty", "eligible for bounty", "bounty")
_H1_INSTRUCTION_HINTS = ("instruction", "notes")
_H1_SEVERITY_HINTS = ("max_severity", "max severity", "severity")
_TRUE_WORDS = {"true", "yes", "y", "1", "eligible", "in scope", "in_scope"}
_FALSE_WORDS = {"false", "no", "n", "0", "not eligible", "out of scope", "out_of_scope", "ineligible"}
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
    has no recognizable target column (then the caller scans every cell). Prefers an
    EXACT header match over a substring one within each hint tier, so a generic hint
    (bare "asset" in _HOST_HINTS) can't shadow a more specific column ("asset_type"
    coming before an actual host/identifier column just because of column order) --
    the same collision class fixed in _match_column for the HackerOne CSV parser,
    reported live: a real HackerOne scope export with `asset_type` before the real
    identifier column silently mis-picked asset_type, yielding zero valid targets."""
    cells = [str(c or "").strip().lower() for c in header]
    for hints in (_URL_HINTS, _HOST_HINTS):
        for index, cell in enumerate(cells):
            if cell and cell in hints:
                return index
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
    # A single-column list has NO header column to pick: _pick_column's substring tier would match a
    # hint inside the first value itself ("host" in "host1.example.com"), mis-flag row 0 as a header,
    # and silently drop the first (often most important) target. Scan every cell instead — a genuine
    # one-column header word (url/host/domain) isn't a valid target, so _normalize_one drops it anyway.
    column = None if len(rows[0]) == 1 else _pick_column(rows[0])
    collected: list[str] = []
    if column is not None:
        for row in rows[1:]:            # skip the header row
            if column < len(row):
                collected.append(row[column])
    else:
        for row in rows:               # no header column -> scan everything
            collected.extend(row)
    return _finalize("csv", [n for n in (_normalize_one(c) for c in collected) if n], [])


def _match_column(cells: list[str], hints: tuple[str, ...]) -> int | None:
    """Prefer an EXACT header match over a substring one, so a generic hint (e.g. bare
    "asset" in _H1_ID_HINTS) can't shadow a more specific column ("asset_type" coming
    before "asset_identifier") just because of column order. Falls back to substring
    matching (first hint, first matching column) when nothing matches exactly."""
    for index, cell in enumerate(cells):
        if cell and cell in hints:
            return index
    for index, cell in enumerate(cells):
        if cell and any(h in cell for h in hints):
            return index
    return None


def _parse_bool_cell(raw: str, default: bool) -> bool:
    v = (raw or "").strip().lower()
    if not v:
        return default
    if v in _TRUE_WORDS:
        return True
    if v in _FALSE_WORDS:
        return False
    return default


def _finalize_scope(entries: list[dict[str, Any]], notes: list[str]) -> dict[str, Any]:
    """Same shape contract as ``_finalize`` (ok/kind/targets/hosts/count/host_count/notes,
    so the existing generic import widget keeps working unmodified) PLUS the full
    ``structured_scope`` rows a HackerOne-aware importer needs."""
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        key = entry["identifier"].lower()
        if key and key not in seen:
            seen.add(key)
            deduped.append(entry)
    out_notes = list(notes)
    if len(deduped) > MAX_SCOPE_ENTRIES:
        deduped = deduped[:MAX_SCOPE_ENTRIES]
        out_notes.append(f"Capped to the first {MAX_SCOPE_ENTRIES} scope entries.")
    # Best-effort URL view for the "seed targets" / "scope" quick-add buttons — many
    # structured-scope identifiers aren't URLs at all (mobile bundle IDs, CIDRs, repo
    # names), so this list is a subset of structured_scope, never a replacement for it.
    targets = _dedupe(
        n for n in (_normalize_one(e["identifier"]) for e in deduped if e["eligible_for_submission"]) if n
    )
    hosts = _dedupe(_host_of(t) for t in targets)
    if not deduped:
        out_notes.append("No scope entries found (need an identifier column, or at least one non-empty cell).")
    return {
        "ok": bool(deduped), "kind": "hackerone_scope", "structured_scope": deduped, "scope_count": len(deduped),
        "targets": targets, "hosts": hosts, "param_names": [], "count": len(targets),
        "host_count": len(hosts), "notes": out_notes,
    }


def parse_hackerone_scope_csv(text: str) -> dict[str, Any]:
    """A HackerOne-style scope export (or any CSV with asset/type/eligibility columns).
    Unlike ``parse_csv`` (which collapses a row to a single URL/host cell), this keeps the
    WHOLE row as a structured scope entry — identifier, asset_type, eligible_for_submission,
    eligible_for_bounty, instruction, max_severity — matching the same shape the HackerOne
    API import returns (``hackerone_import.fetch_structured_scope``), so both paths feed the
    same table. Falls back to treating every cell as a bare in-scope identifier when no
    recognizable header is present (still useful for a plain one-column asset list)."""
    body = text.lstrip("﻿")
    try:
        try:
            dialect: Any = csv.Sniffer().sniff(body[:4096], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        rows = list(csv.reader(io.StringIO(body), dialect))
    except csv.Error as exc:
        return _err("hackerone_scope", f"Could not parse CSV: {exc}")
    if not rows:
        return _finalize_scope([], [])

    header_cells = [str(c or "").strip().lower() for c in rows[0]]
    id_col = _match_column(header_cells, _H1_ID_HINTS)
    columns: dict[str, int | None] | None = None
    data_rows = rows
    if id_col is not None:
        columns = {
            "identifier": id_col,
            "asset_type": _match_column(header_cells, _H1_TYPE_HINTS),
            "eligible_for_submission": _match_column(header_cells, _H1_SUBMIT_HINTS),
            "eligible_for_bounty": _match_column(header_cells, _H1_BOUNTY_HINTS),
            "instruction": _match_column(header_cells, _H1_INSTRUCTION_HINTS),
            "max_severity": _match_column(header_cells, _H1_SEVERITY_HINTS),
        }
        data_rows = rows[1:]

    entries: list[dict[str, Any]] = []
    notes: list[str] = []
    for row in data_rows:
        if columns is not None:
            def cell(key: str, row: list[str] = row, columns: dict[str, int | None] = columns) -> str:
                idx = columns.get(key)
                return str(row[idx]).strip() if idx is not None and idx < len(row) else ""
            identifier = cell("identifier")
            if not identifier:
                continue
            entries.append({
                "identifier": identifier,
                "asset_type": cell("asset_type"),
                "eligible_for_submission": _parse_bool_cell(cell("eligible_for_submission"), True),
                "eligible_for_bounty": _parse_bool_cell(cell("eligible_for_bounty"), False),
                "instruction": cell("instruction"),
                "max_severity": cell("max_severity"),
            })
        else:
            for raw_cell in row:
                identifier = str(raw_cell or "").strip()
                if identifier:
                    entries.append({
                        "identifier": identifier, "asset_type": "", "eligible_for_submission": True,
                        "eligible_for_bounty": False, "instruction": "", "max_severity": "",
                    })
    if columns is None and entries:
        notes.append("No recognizable header (identifier/asset type/eligibility) — treated every cell as a bare in-scope identifier.")
    return _finalize_scope(entries, notes)


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


def _looks_like_hackerone_scope(text: str) -> bool:
    """Best-effort sniff of the header row: does this look like a HackerOne-style
    structured-scope export (an identifier column PLUS at least one asset-type/
    eligibility column)? Deliberately narrow (requires the literal substring
    "identifier", not the bare "asset" hint _H1_ID_HINTS also accepts) so an unrelated
    CSV that merely has an "asset_type"-ish column doesn't get swept in. Only used to
    steer kind="auto" toward the richer parser (which keeps asset_type/instruction/
    eligible_for_bounty/max_severity instead of flattening to a bare host list) --
    an explicit kind selection is never overridden."""
    head_line = text.lstrip("﻿").split("\n", 1)[0]
    try:
        dialect: Any = csv.Sniffer().sniff(head_line[:2048], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    try:
        row = next(csv.reader(io.StringIO(head_line), dialect), None)
    except csv.Error:
        return False
    if not row:
        return False
    cells = [str(c or "").strip().lower() for c in row]
    has_id = any("identifier" in cell for cell in cells)
    has_signal = any(
        any(h in cell for h in hints)
        for cell in cells
        for hints in (_H1_TYPE_HINTS, _H1_SUBMIT_HINTS, _H1_BOUNTY_HINTS)
    )
    return has_id and has_signal


def _detect(text: str) -> str:
    head = text.lstrip("﻿ \t\r\n")
    if head.startswith("<"):
        return "burp"
    if head[:1] in ("{", "["):
        return "har"
    if _looks_like_hackerone_scope(text):
        return "hackerone_scope"
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
    if chosen == "hackerone_scope":
        return parse_hackerone_scope_csv(raw)
    return _err(chosen, f"Unknown ingest kind '{kind}' (use auto, csv, burp, har, or hackerone_scope).")
