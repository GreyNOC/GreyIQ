"""JWT exposure classification for secret scanning.

The code scanner should not treat every syntactically valid JWT as a
credential. OAuth return/state/nonce/PKCE transport tokens are often public
client-side grammar. This module parses the token, classifies its role from
claims, and scans only claim values for concrete secret material.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

IDENTITY_CLAIMS = frozenset({"sub", "uid", "user_id", "email", "account_id", "customer_id"})
SESSION_MARKERS = frozenset({"exp", "iat", "sid", "jti"})
FLOW_ONLY_CLAIMS = frozenset(
    {"iss", "aud", "u", "url", "redirect", "redirect_uri", "state", "nonce", "code_challenge"}
)
SCOPE_CLAIMS = frozenset({"scope", "scopes"})

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key-pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY( BLOCK)?-----")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe-secret-key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b")),
)


@dataclass(frozen=True)
class JwtSecretHit:
    kind: str
    claim: str


@dataclass(frozen=True)
class JwtExposureClassification:
    finding: bool | str
    severity: str
    role: str
    cwe: str = ""
    impact: str = ""
    replay_authenticated: bool | None = None
    has_identity: bool = False
    has_session: bool = False
    flow_only: bool = False
    alg: str = ""
    secret_hits: tuple[JwtSecretHit, ...] = field(default_factory=tuple)
    scope_names: tuple[str, ...] = field(default_factory=tuple)


def _b64url_json(segment: str) -> dict[str, Any] | None:
    try:
        padded = segment + ("=" * (-len(segment) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def parse_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    header = _b64url_json(parts[0])
    payload = _b64url_json(parts[1])
    if header is None or payload is None:
        return None
    return header, payload


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float, bool)) or value is None:
        return [str(value)]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_string_values(item))
        return out
    if isinstance(value, dict):
        out = []
        for item in value.values():
            out.extend(_string_values(item))
        return out
    return [str(value)]


def _extract_scopes_from_text(value: str) -> list[str]:
    scopes: list[str] = []
    try:
        split = urlsplit(value)
        query = parse_qsl(split.query, keep_blank_values=True)
    except ValueError:
        query = []
    for key, param_value in query:
        if key.lower() == "scope":
            scopes.extend(part for part in re.split(r"[\s,+]+", param_value) if part)
    for match in re.finditer(r"(?:^|[?&])scope=([^&#\s\"']+)", value):
        scopes.extend(part for part in re.split(r"[\s,+]+", match.group(1)) if part)
    return scopes


def extract_oauth_scope_names(payload: dict[str, Any]) -> tuple[str, ...]:
    scopes: list[str] = []
    for key, value in payload.items():
        lowered = str(key).lower()
        if lowered in SCOPE_CLAIMS:
            for item in _string_values(value):
                scopes.extend(part for part in re.split(r"[\s,+]+", item) if part)
            continue
        for item in _string_values(value):
            scopes.extend(_extract_scopes_from_text(item))
    return tuple(dict.fromkeys(scopes))


def _without_scope_values(value: str) -> str:
    try:
        split = urlsplit(value)
        if split.query:
            kept = [(key, val) for key, val in parse_qsl(split.query, keep_blank_values=True) if key.lower() != "scope"]
            value = urlunsplit((split.scheme, split.netloc, split.path, urlencode(kept, doseq=True), split.fragment))
    except ValueError:
        pass
    return re.sub(r"([?&])scope=[^&#\s\"']+", r"\1scope=", value, flags=re.IGNORECASE)


def _scan_claim_values(payload: dict[str, Any]) -> tuple[JwtSecretHit, ...]:
    hits: list[JwtSecretHit] = []
    for claim, raw_value in payload.items():
        if str(claim).lower() in SCOPE_CLAIMS:
            continue
        for item in _string_values(raw_value):
            candidate = _without_scope_values(item)
            for kind, pattern in SECRET_PATTERNS:
                if pattern.search(candidate):
                    hits.append(JwtSecretHit(kind=kind, claim=str(claim)))
    return tuple(hits)


def classify_jwt_exposure(
    token: str,
    *,
    replay_authenticated: bool | None = None,
    hs_secret_cracked: bool = False,
) -> JwtExposureClassification | None:
    parsed = parse_jwt(token)
    if parsed is None:
        return None
    header, payload = parsed
    claim_names = {str(key).lower() for key in payload}
    has_identity = bool(claim_names & IDENTITY_CLAIMS)
    has_session = bool(claim_names & SESSION_MARKERS)
    flow_only = bool(claim_names) and claim_names <= (FLOW_ONLY_CLAIMS | SCOPE_CLAIMS)
    alg = str(header.get("alg") or "")
    scope_names = extract_oauth_scope_names(payload)
    secret_hits = _scan_claim_values(payload)

    if hs_secret_cracked and alg.upper().startswith("HS"):
        return JwtExposureClassification(
            finding=True,
            severity="high",
            role="jwt_forgery",
            cwe="CWE-347",
            impact="JWT signing secret is cracked; token forgery is possible.",
            replay_authenticated=replay_authenticated,
            has_identity=has_identity,
            has_session=has_session,
            flow_only=flow_only,
            alg=alg,
            secret_hits=secret_hits,
            scope_names=scope_names,
        )

    if secret_hits:
        return JwtExposureClassification(
            finding=True,
            severity="high",
            role="embedded_secret",
            cwe="CWE-200",
            impact="A concrete secret value is embedded inside a JWT claim.",
            replay_authenticated=replay_authenticated,
            has_identity=has_identity,
            has_session=has_session,
            flow_only=flow_only,
            alg=alg,
            secret_hits=secret_hits,
            scope_names=scope_names,
        )

    if replay_authenticated is True:
        return JwtExposureClassification(
            finding=True,
            severity="high",
            role="session_token",
            cwe="CWE-200",
            impact="Session takeover confirmed by unauthenticated replay.",
            replay_authenticated=True,
            has_identity=has_identity,
            has_session=has_session,
            flow_only=flow_only,
            alg=alg,
            secret_hits=secret_hits,
            scope_names=scope_names,
        )

    if has_identity or has_session:
        return JwtExposureClassification(
            finding="needs_confirmation",
            severity="info",
            role="possible_session_token",
            replay_authenticated=replay_authenticated,
            has_identity=has_identity,
            has_session=has_session,
            flow_only=flow_only,
            alg=alg,
            secret_hits=secret_hits,
            scope_names=scope_names,
        )

    return JwtExposureClassification(
        finding=False,
        severity="info",
        role="flow_token" if flow_only else "non_credential_token",
        replay_authenticated=replay_authenticated,
        has_identity=has_identity,
        has_session=has_session,
        flow_only=flow_only,
        alg=alg,
        secret_hits=secret_hits,
        scope_names=scope_names,
    )

