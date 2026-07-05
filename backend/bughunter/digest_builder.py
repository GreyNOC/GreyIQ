"""Deterministic Response Digest — turn a captured HTTP response into compact, redacted, STRUCTURAL
metadata the reasoning brain can actually reason over.

The hunt already fetches full responses (active_verify_service holds the ``_consume`` dict: status,
headers, cookies, body) but distills each to a ~200-char ``observed_result`` excerpt before the brain
ever sees it — so the brain reasons blind and can only nudge parameter names. ``build_digest`` extracts
the security-relevant STRUCTURE an expert reads off a Burp response — JSON key NAMES, HTML form field
names, present/missing security headers, auth-cookie flag gaps, JWT header shape, and the matched
error-signature family — plus a short list of the security-INTERESTING names it saw (``role``,
``is_admin``, ``owner_id``, a token, …). Fed to the re-plan brain, that turns "nudge more param names
blindly" into "this endpoint returns JSON with ``owner_id``+``is_admin`` and 403s on /admin → prioritise
IDOR/BFLA here" — the exact reasoning a human does reading a response.

SAFE BY CONSTRUCTION:
- EXTRACTED, never synthesized. Key NAMES / flags / shapes only — NEVER a value; the JWT payload is
  never decoded, only the header's ``alg``/``typ``.
- Every emitted string is passed through ``redact_text`` so a secret that lands in a key name can't leak.
- Fixed-schema deterministic parsing (no model). Bounded (depth + counts capped). Any parse failure
  yields ``{}`` — the caller falls back to today's excerpt (fail-open to current behaviour).
- Carries no secret and confirms nothing: ``report._has_captured_artifact`` stays the sole confirm
  authority. This is a LEAF module (stdlib + redaction only) so it can be imported anywhere.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from bughunter.code_scanner.redaction import redact_text

# --- bounds (a digest must stay a small, cheap prompt fragment) ---
_MAX_JSON_KEYS = 40
_MAX_FORM_FIELDS = 30
_MAX_DEPTH = 4
_MAX_INTERESTING = 16
_BODY_SCAN_CAP = 200_000  # never scan more than ~200 KB of body for structure

# Field/key NAMES that an expert treats as high-signal for a target-specific hypothesis. Substring
# match on a lowercased name. Purely a REASONING HINT surfaced to the brain — it triggers no probe and
# confirms nothing; it just tells the brain "look here" (mass-assignment, IDOR/BOLA, auth, business logic).
_INTERESTING_NAME_RE = re.compile(
    r"(?:^|[_\-])(?:role|roles|is[_\-]?admin|admin|is[_\-]?staff|superuser|owner|owner[_\-]?id|user[_\-]?id"
    r"|account[_\-]?id|customer[_\-]?id|org[_\-]?id|tenant|is[_\-]?verified|verified|approved|enabled|active"
    r"|permission|permissions|scope|scopes|price|amount|balance|quantity|discount|credit|token|secret|api[_\-]?key"
    r"|password|passwd|email|ssn|internal|debug|_id)(?:$|[_\-])",
    re.IGNORECASE,
)
# An auth-ish cookie NAME — only these are flagged for missing Secure/HttpOnly/SameSite (a tracking
# cookie without HttpOnly is not a finding).
_AUTH_COOKIE_RE = re.compile(r"sess|sid|token|auth|jwt|login|remember|csrf|xsrf|identity|account", re.IGNORECASE)
# A JWT-shaped token: base64url header that begins with the encoding of `{"` (eyJ), dot-separated.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
# The gap between the tag and its name= is BOUNDED ({0,300}) — an unbounded lazy `[^>]*?` backtracks
# across the whole body on adversarial input like `<input name=<input name=...` (the capture fails at
# each position, so the engine rescans forward every time = O(n^2), ~22 s on a 200 KB body = ReDoS).
_FORM_FIELD_RE = re.compile(r"""<(?:input|select|textarea)\b[^>]{0,300}?\bname\s*=\s*["']?([A-Za-z0-9_\-\[\]\.]{1,64})""", re.IGNORECASE)
# Error-signature families (a leaf copy — kept deliberately conservative; the deterministic prover owns
# any actual SQLi/SSTI confirmation, this is only a reasoning hint about what the response leaked).
_ERROR_FAMILIES: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("sql", re.compile(r"SQL syntax|SQLSTATE|ORA-\d{5}|PG::|psycopg2|mysql_fetch|sqlite3\.|unclosed quotation mark|"
                       r"quoted string not properly terminated", re.IGNORECASE)),
    ("nosql", re.compile(r"MongoError|BSONError|E11000|CastError|couchdb|Unexpected token .* in JSON", re.IGNORECASE)),
    ("template", re.compile(r"jinja2\.|TemplateSyntaxError|Twig_Error|freemarker|Velocity|ognl\.", re.IGNORECASE)),
    ("stacktrace", re.compile(r"Traceback \(most recent call last\)|at [\w.$]+\([\w.]+\.java:\d+\)|"
                              r"\bin /[\w./-]+\.php on line \d+|System\.\w+Exception", re.IGNORECASE)),
)
_SECURITY_HEADERS = {
    "content-security-policy": "csp",
    "x-frame-options": "x-frame-options",
    "strict-transport-security": "hsts",
    "x-content-type-options": "x-content-type-options",
    "referrer-policy": "referrer-policy",
}


def _red(text: str) -> str:
    """Redact + trim a single string field (secrets scrubbed before it can reach the brain)."""
    out, _ = redact_text(str(text or ""))
    return out[:120]


def _walk_json_keys(node: Any, out: list[str], seen: set[str], depth: int) -> None:
    if depth > _MAX_DEPTH or len(out) >= _MAX_JSON_KEYS:
        return
    if isinstance(node, dict):
        for k in node.keys():
            key = _red(str(k))
            low = key.lower()
            if key and low not in seen:
                seen.add(low)
                out.append(key)
                if len(out) >= _MAX_JSON_KEYS:
                    return
        for v in node.values():
            _walk_json_keys(v, out, seen, depth + 1)
    elif isinstance(node, list):
        for v in node[:20]:
            _walk_json_keys(v, out, seen, depth + 1)


def _bounded_join(chunks: Any, cap: int) -> str:
    """Join ``chunks`` with newlines but stop once ``cap`` chars are accumulated — so the haystack (and
    its peak memory) is bounded even when header/cookie VALUES are large and attacker-controlled (the
    body is capped separately, but a naive join of all headers is not)."""
    out: list[str] = []
    used = 0
    for c in chunks:
        if used >= cap:
            break
        s = str(c)[: cap - used]
        out.append(s)
        used += len(s) + 1  # +1 for the joining newline
    return "\n".join(out)


def _jwt_alg(body: str, headers: dict[str, str], cookies: list[str]) -> dict[str, str]:
    """The ``alg``/``typ`` of the FIRST JWT-shaped token seen (header segment only — the payload is
    NEVER decoded). Empty dict if none/undecodable."""
    # Bounded haystack: body + header values + cookies, capped so large attacker-controlled headers
    # can't blow up memory/time (the module's invariant is that EVERY path is bounded).
    hay = _bounded_join([body[:_BODY_SCAN_CAP], *headers.values(), *cookies], _BODY_SCAN_CAP)
    m = _JWT_RE.search(hay)
    if not m:
        return {}
    header_seg = m.group(0).split(".", 1)[0]
    try:
        pad = header_seg + "=" * (-len(header_seg) % 4)
        obj = json.loads(base64.urlsafe_b64decode(pad).decode("utf-8", "replace"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return {}
    if not isinstance(obj, dict):
        return {}
    out: dict[str, str] = {}
    if obj.get("alg"):
        out["alg"] = _red(str(obj.get("alg")))
    if obj.get("typ"):
        out["typ"] = _red(str(obj.get("typ")))
    return out


def _cookie_flag_gaps(cookies: list[str]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for raw in (cookies or [])[:20]:
        name = str(raw or "").split("=", 1)[0].strip()
        if not name or not _AUTH_COOKIE_RE.search(name):
            continue
        low = str(raw).lower()
        missing = [flag for flag, present in (
            ("Secure", "secure" in low),
            ("HttpOnly", "httponly" in low),
            ("SameSite", "samesite" in low),
        ) if not present]
        if missing:
            gaps.append({"cookie": _red(name), "missing": missing})
        if len(gaps) >= 8:
            break
    return gaps


def build_digest(fetch_result: dict[str, Any] | None) -> dict[str, Any]:
    """Extract redacted, structural metadata from a captured response dict (the ``_consume`` shape:
    ``{status, headers, cookies, body}``). Returns a small dict, or ``{}`` on any problem so the caller
    keeps today's behaviour. NEVER raises."""
    try:
        if not isinstance(fetch_result, dict):
            return {}
        body = str(fetch_result.get("body") or "")[:_BODY_SCAN_CAP]
        headers = {str(k).lower(): str(v) for k, v in (fetch_result.get("headers") or {}).items()} \
            if isinstance(fetch_result.get("headers"), dict) else {}
        cookies = [str(c) for c in (fetch_result.get("cookies") or [])] if isinstance(fetch_result.get("cookies"), list) else []

        digest: dict[str, Any] = {"status": int(fetch_result.get("status") or 0)}

        # JSON key structure (names only) — the "what does this API expose" signal.
        json_keys: list[str] = []
        stripped = body.lstrip()
        if stripped[:1] in ("{", "["):
            try:
                _walk_json_keys(json.loads(body), json_keys, set(), 0)
            except (ValueError, RecursionError):
                json_keys = []
        if json_keys:
            digest["json_keys"] = json_keys

        # HTML form field names (hidden fields included — the mass-assignment / CSRF surface).
        form_fields: list[str] = []
        seen_f: set[str] = set()
        for m in _FORM_FIELD_RE.finditer(body):
            f = _red(m.group(1))
            low = f.lower()
            if f and low not in seen_f:
                seen_f.add(low)
                form_fields.append(f)
            if len(form_fields) >= _MAX_FORM_FIELDS:
                break
        if form_fields:
            digest["form_fields"] = form_fields

        # The security-INTERESTING subset of everything we saw — the reasoning hint.
        interesting = [n for n in (json_keys + form_fields) if _INTERESTING_NAME_RE.search(n)]
        if interesting:
            digest["interesting_names"] = list(dict.fromkeys(interesting))[:_MAX_INTERESTING]

        # Present/missing security headers + a CORS note.
        missing_headers = [label for hdr, label in _SECURITY_HEADERS.items() if hdr not in headers]
        if missing_headers:
            digest["missing_security_headers"] = missing_headers
        acao = headers.get("access-control-allow-origin", "")
        if acao:
            digest["cors_acao"] = _red(acao)
            if headers.get("access-control-allow-credentials", "").strip().lower() == "true":
                digest["cors_allow_credentials"] = True

        gaps = _cookie_flag_gaps(cookies)
        if gaps:
            digest["cookie_flag_gaps"] = gaps

        jwt = _jwt_alg(body, headers, cookies)
        if jwt:
            digest["jwt"] = jwt

        for family, rx in _ERROR_FAMILIES:
            if rx.search(body):
                digest["error_family"] = family
                break

        return digest
    except Exception:  # noqa: BLE001 - a digest must NEVER break a hunt; fail open to the excerpt
        return {}
