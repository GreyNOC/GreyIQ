"""Strict classification for exposed-secret / API-key findings.

A value appearing in page source is NOT proof of a vulnerability, and a regex match is NOT proof of a
secret. A Google/Firebase browser key (``AIza…``) is designed to be public — a live ``getProjectConfig``
200 is the EXPECTED behaviour of a public client key, not an exploit. This module makes BugHunter say so
instead of shipping a scary "confirmed secret / High" report from a page-source match alone.

Every exposed-key finding is classified as exactly one of:

  * ``confirmed_secret``     — a real, privileged secret PROVEN usable (a server-side token the issuer
                               authenticated as live, or a Firebase data store proven readable). Only
                               this class may be Medium / High / Critical.
  * ``public_client_key``    — a browser-embeddable public key (Firebase web config, Google Maps / GA /
                               GTM id, OAuth client id without a secret, CDN/endpoint URL). Info by
                               default; informational only.
  * ``candidate_unverified`` — a plausible secret shape with no validation / inconclusive liveness.
                               Info/Low, not reportable yet.
  * ``false_positive``       — the issuer rejected it (dead/revoked) or it is a known non-secret shape.

Design invariant: only ``classify_secret_finding`` → ``confirmed_secret`` may map to Medium+, and it can
only reach that via ``has_confirmed_secret_proof``, which is gated on REAL liveness / a captured artifact
— never on the value's shape. The confirm authority (``report._has_captured_artifact``) stays the sole
gate; this module never invents proof.

Pure / leaf module (stdlib + redaction helper only).
"""

from __future__ import annotations

import re
from typing import Any

from bughunter.code_scanner.redaction import redact_secret, redact_text

# --- The four classifications ---------------------------------------------------------------------
CONFIRMED_SECRET = "confirmed_secret"
PUBLIC_CLIENT_KEY = "public_client_key"
CANDIDATE_UNVERIFIED = "candidate_unverified"
FALSE_POSITIVE = "false_positive"

# rule_ids whose ``_credential_proof.live is True`` is GENUINE proof of a usable privileged secret —
# these are validator-backed server-side tokens (the key authenticating IS the impact). A live one of
# these is confirmed. Google/Firebase browser keys are DELIBERATELY absent: a live AIza key is public,
# not confirmed.
_CONFIRMED_VIA_LIVENESS = frozenset({
    "secret.github-pat", "secret.slack-bot-token", "secret.openai-key", "secret.anthropic-key",
    "secret.stripe-key", "secret.gitlab-pat", "secret.npm-token", "secret.sendgrid-key",
    "secret.digitalocean-token", "secret.gcp-service-account", "secret.aws-access-key-id",
})

# rule_ids whose SHAPE alone marks a browser-embeddable public key (never confirmed from shape).
_PUBLIC_CLIENT_RULE_IDS = frozenset({"secret.google-api-key"})

# rule_ids that are a GENUINE exposed secret ARTIFACT by their very nature — a private key, a
# service-account JSON, a committed .env, an AWS secret access key. Their PRESENCE in source IS the
# exposure (not public, not a pattern-guess), so they are real reportable secrets even with no live
# validator to hit. They keep their (Critical/High) severity and are never downgraded to Info/Low.
_SECRET_ARTIFACT_RULES = frozenset({
    "secret.private-key-pem", "secret.gcp-service-account", "secret.aws-secret-access-key",
    "secret.dotenv-committed",
})

# Value shapes that are UNAMBIGUOUSLY a real secret (server tokens / private keys) — a value matching
# one of these is never a public client key, no matter what config fields sit next to it.
_REAL_SECRET_VALUE_RES = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY"),
)


def _looks_like_real_secret(value: str) -> bool:
    """True when the value itself is an unambiguous real secret (server token / private key) — used to
    stop a genuine leaked secret from being mislabelled a public client key just because it sits inside
    a Firebase/analytics config blob."""
    v = str(value or "")
    return any(r.search(v) for r in _REAL_SECRET_VALUE_RES)

# Value/context shapes that mark a browser-safe public key even when a generic rule flagged it.
_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_OAUTH_CLIENT_ID_RE = re.compile(r"[0-9]+-[0-9a-z]+\.apps\.googleusercontent\.com", re.IGNORECASE)
_GA_MEASUREMENT_RE = re.compile(r"\b(?:G-[A-Z0-9]{6,}|UA-\d{4,}-\d+|GTM-[A-Z0-9]{4,})\b")
_PUBLIC_CONTEXT_TERMS = (
    "authdomain", "messagingsenderid", "measurementid", "storagebucket", "appid",
    "apps.googleusercontent.com", "firebaseapp.com", "firebaseio.com", "maps.googleapis.com",
    "googletagmanager", "google-analytics", "gtag", "public_key", "publishable",
)
# A private-key / server-token shape must NEVER be mislabelled public even if it shares a var name.
_DEFINITELY_SECRET_RULE_PREFIXES = (
    "secret.github", "secret.slack", "secret.openai", "secret.anthropic", "secret.stripe",
    "secret.gitlab", "secret.npm", "secret.sendgrid", "secret.digitalocean", "secret.gcp",
    "secret.aws", "secret.private-key", "secret.jwt",
)


def _base_rule_id(finding: dict[str, Any]) -> str:
    """Strip the live-web ``web.exposed.`` prefix so a page-source finding classifies like its source
    twin (``web.exposed.secret.google-api-key`` == ``secret.google-api-key``)."""
    rid = str(finding.get("rule_id") or "")
    return rid[len("web.exposed."):] if rid.startswith("web.exposed.") else rid


def _context_text(finding: dict[str, Any]) -> str:
    return " ".join(str(finding.get(k) or "") for k in (
        "secret_value", "variable_name", "snippet", "title", "description", "location", "file_path")).lower()


def is_public_client_key(finding: dict[str, Any]) -> bool:
    """True when the finding is a browser-embeddable PUBLIC key/config, not a real secret: a Google/
    Firebase ``AIza`` key, an OAuth client id (``*.apps.googleusercontent.com``), a GA/GTM analytics id,
    a Firebase web-config object, or a value living amongst public-config fields. Never True for a
    definitely-secret rule (server tokens / private keys)."""
    if not isinstance(finding, dict):
        return False
    base = _base_rule_id(finding)
    if any(base.startswith(p) for p in _DEFINITELY_SECRET_RULE_PREFIXES):
        return False
    if base in _PUBLIC_CLIENT_RULE_IDS:
        return True
    value = str(finding.get("secret_value") or "")
    # A value that is itself an unambiguous real secret is NEVER a public key — even if it sits inside a
    # Firebase/analytics config blob. This stops a genuine leaked token/private key next to public config
    # from being force-downgraded to Info.
    if value and _looks_like_real_secret(value):
        return False
    # The extracted VALUE is a public key/id shape (Google browser key, OAuth client id, GA/GTM id).
    if value and (_AIZA_RE.search(value) or _OAUTH_CLIENT_ID_RE.search(value) or _GA_MEASUREMENT_RE.search(value)):
        return True
    ctx = _context_text(finding)
    if _looks_like_real_secret(ctx):
        return False
    if _AIZA_RE.search(ctx) or _OAUTH_CLIENT_ID_RE.search(ctx) or _GA_MEASUREMENT_RE.search(ctx):
        return True
    # A finding with NO extractable secret value (a web finding carrying only a redacted snippet) that
    # sits amongst public Firebase/analytics config fields — a public config blob, not a real secret.
    if not value and any(term in ctx for term in _PUBLIC_CONTEXT_TERMS):
        return True
    return False


def has_confirmed_secret_proof(finding: dict[str, Any]) -> bool:
    """True ONLY when there is real proof this is a usable, privileged secret — never from shape:
      * a captured active-proof artifact (``_active_proof.status == 'confirmed'``, e.g. an open Firebase
        data store proven readable), OR
      * concrete embedded secret material (``secret_hits`` from the JWT classifier), OR
      * a validator-backed server token the issuer authenticated as live (``_credential_proof.live is
        True`` AND the rule is in ``_CONFIRMED_VIA_LIVENESS`` — NOT a Google/Firebase browser key).
    Never True from ``live is None`` (inconclusive/no-network) or ``live is False`` (dead)."""
    if not isinstance(finding, dict):
        return False
    ap = finding.get("_active_proof")
    if isinstance(ap, dict) and str(ap.get("status") or "").lower() == "confirmed":
        return True
    if finding.get("secret_hits"):
        return True
    cred = finding.get("_credential_proof")
    if isinstance(cred, dict) and cred.get("live") is True and _base_rule_id(finding) in _CONFIRMED_VIA_LIVENESS:
        return True
    return False


_PLACEHOLDER_MARKERS = ("example", "placeholder", "your-", "dummy", "sample", "xxxx", "changeme", "redacted")


def _looks_placeholder(finding: dict[str, Any]) -> bool:
    val = str(finding.get("secret_value") or "").lower()
    return any(m in val for m in _PLACEHOLDER_MARKERS)


def _is_real_secret_artifact(finding: dict[str, Any]) -> bool:
    """True only when the finding is a genuine secret-artifact rule AND real artifact material is
    actually present (a PEM body, a service-account JSON, a 40-char AWS secret, a non-empty .env value).
    The value guard is what stops a CLIENT-FORGED on-demand report (rule_id set, no real value) from
    reaching confirmed_secret on the rule_id alone."""
    base = _base_rule_id(finding)
    if base not in _SECRET_ARTIFACT_RULES or _looks_placeholder(finding):
        return False
    value = str(finding.get("secret_value") or "")
    hay = value or str(finding.get("snippet") or "")
    if not hay:
        return False
    if base == "secret.private-key-pem":
        return "PRIVATE KEY" in hay
    if base == "secret.gcp-service-account":
        return "service_account" in hay and "private_key" in hay
    if base == "secret.aws-secret-access-key":
        return bool(re.search(r"[A-Za-z0-9/+=]{40}", hay))
    if base == "secret.dotenv-committed":
        return "=" in hay and len((value or hay).strip()) >= 8
    return False


def classify_secret_finding(finding: dict[str, Any]) -> str:
    """THE single classification decision for an exposed-key finding. Order matters:
    proven impact wins, then public-client shape, then dead/placeholder, else unverified candidate."""
    if has_confirmed_secret_proof(finding):
        return CONFIRMED_SECRET
    cred = finding.get("_credential_proof") if isinstance(finding.get("_credential_proof"), dict) else {}
    # A validator RAN and the issuer rejected the credential: a public key is still just a public key;
    # a server token that's dead is a false-positive lead.
    if cred.get("live") is False:
        return PUBLIC_CLIENT_KEY if is_public_client_key(finding) else FALSE_POSITIVE
    # A GENUINE secret ARTIFACT with real material present (private key, service-account JSON, committed
    # .env, AWS secret key) is a real exposed secret by its nature — keep it a reportable secret at its
    # rule severity, and let it WIN over a public-shape match (a real .env beside a GA/OAuth id must not
    # be hidden as "public"). Value-guarded so a CLIENT-FORGED on-demand report (rule_id set, no real
    # value) can't reach confirmed_secret from the rule_id alone.
    if _is_real_secret_artifact(finding):
        return CONFIRMED_SECRET
    if is_public_client_key(finding):
        return PUBLIC_CLIENT_KEY
    if _looks_placeholder(finding):
        return FALSE_POSITIVE
    return CANDIDATE_UNVERIFIED


# Severity ceiling for each non-confirmed class — a confirmed_secret keeps its impact-based severity.
_SEVERITY_FOR_CLASS = {
    PUBLIC_CLIENT_KEY: "info",
    CANDIDATE_UNVERIFIED: "low",
    FALSE_POSITIVE: "info",
}


def severity_for_classification(cls: str, current_severity: str) -> str:
    """The severity a finding of class ``cls`` may carry. Only ``confirmed_secret`` keeps its
    (impact-based) severity; everything else is capped to Info/Low so a regex/page-source match can
    never read Medium+."""
    if cls == CONFIRMED_SECRET:
        return str(current_severity or "info")
    return _SEVERITY_FOR_CLASS.get(cls, "low")


def redact_value_in(text: str, secret_value: str) -> str:
    """Redact ``secret_value`` out of ``text`` (a PoC command / issuer response) to a safe prefix…suffix,
    THEN apply the pattern-based ``redact_text`` as a backstop. Explicitly replacing the KNOWN value first
    means the report never leaks a key that ``redact_text``'s vendor patterns happen not to match."""
    t = str(text or "")
    raw = str(secret_value or "").strip()
    if raw and len(raw) >= 6 and raw in t:
        t = t.replace(raw, redact_secret(raw))
    return redact_text(t)[0]


def _redacted_value(finding: dict[str, Any]) -> str:
    """A safe prefix…suffix of the secret for the evidence block — never the full key. Falls back to the
    already-redacted snippet marker for a web finding that never carried the raw value."""
    raw = str(finding.get("secret_value") or "").strip()
    if raw:
        return redact_secret(raw)
    m = _AIZA_RE.search(_context_text(finding))
    if m:
        return redact_secret(m.group(0))
    return ""


# The specific proof a confirmed_secret would require — surfaced as "what is missing" for anything less.
_MISSING_PROOF_PUBLIC = (
    "HTTP referrer / app / IP restriction proof (is the key actually unrestricted?)",
    "API restriction proof (which paid APIs the key may call)",
    "unauthorized API access proof (a benign call that returns data/quota you shouldn't have)",
    "Firebase security-rules proof (a data store readable without auth)",
    "billing-abuse proof (a paid API served the key at cost)",
)
_MISSING_PROOF_CANDIDATE = (
    "validation that the credential authenticates to its issuer",
    "proof it grants access beyond its intended context",
    "private-data or unauthorized-access proof",
)


def _not_reportable_note(finding: dict[str, Any], cls: str) -> str:
    """The exact operator-facing line for a non-confirmed secret, per the required wording."""
    if cls == PUBLIC_CLIENT_KEY:
        return "Informational only: public client key or unverified browser key."
    if cls == FALSE_POSITIVE:
        return "Not reportable: the issuer rejected this credential (dead/revoked) or it is a non-secret placeholder."
    # candidate_unverified: distinguish "only appears in source" from "only a regex match".
    cred = finding.get("_credential_proof")
    if isinstance(cred, dict) and cred.get("checked"):
        return "Not reportable yet: candidate secret without confirmed impact."
    return "Not reportable yet: regex match without validation."


def normalize_secret_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    """Assemble the structured evidence block for an exposed-key finding — the fields a triager needs to
    trust (or discount) it, with the secret redacted. Pure: reads ``_credential_proof`` / ``_active_proof``
    / ``secret_hits``; does not mutate severity (the caller does that from ``severity_for_classification``)."""
    cls = classify_secret_finding(finding)
    cred = finding.get("_credential_proof") if isinstance(finding.get("_credential_proof"), dict) else {}
    live = cred.get("live")
    confirmed = cls == CONFIRMED_SECRET

    evidence_status = ("confirmed" if confirmed else "public_client" if cls == PUBLIC_CLIENT_KEY
                       else "false_positive" if cls == FALSE_POSITIVE else "unverified")
    if cred.get("checked"):
        validation_method = str(cred.get("endpoint") or "benign read-only request to the credential's own issuer")
    else:
        validation_method = "none — regex / page-source match only, no validation performed"
    raw_secret = str(finding.get("secret_value") or "")
    request_evidence = redact_value_in(str(cred.get("poc") or "").strip(), raw_secret) or "no validation request was sent"
    if cred.get("checked"):
        excerpt = redact_value_in(str(cred.get("response_excerpt") or cred.get("detail") or "").strip(), raw_secret)
        response_evidence = f"HTTP {cred.get('http_status', '?')}" + (f" — {excerpt[:400]}" if excerpt else "")
    else:
        response_evidence = "no issuer response — not validated"

    if confirmed:
        impact_summary = str(cred.get("detail") or "").strip() or "A privileged credential was proven usable (see the credential block)."
        reportability = "reportable"
        missing: tuple[str, ...] = ()
    elif cls == PUBLIC_CLIENT_KEY:
        impact_summary = ("No unauthorized access proven. A Google/Firebase browser key is designed to be "
                          "public and to identify its project; being accepted by the issuer is expected, not an exploit.")
        reportability = "informational_only"
        missing = _MISSING_PROOF_PUBLIC
    elif cls == FALSE_POSITIVE:
        impact_summary = "The credential was rejected by its issuer (not live) or is a placeholder — no real secret."
        reportability = "not_reportable_yet"
        missing = ()
    else:
        impact_summary = "No proof the key is usable or grants unauthorized access."
        reportability = "not_reportable_yet"
        missing = _MISSING_PROOF_CANDIDATE

    return {
        "secret_classification": cls,
        "evidence_status": evidence_status,
        "proof_required": True,
        "proof_present": confirmed,
        "validation_method": validation_method,
        "request_evidence": request_evidence,
        "response_evidence": response_evidence,
        "impact_proven": confirmed,
        "impact_summary": impact_summary,
        "redacted_secret": _redacted_value(finding),
        "reportability": reportability,
        "missing_proof": list(missing),
        "not_reportable_note": _not_reportable_note(finding, cls),
        "live": live,
    }


def _scrub_raw_secret(finding: dict[str, Any]) -> None:
    """Remove RAW key material from the finding dict once the (redacted) evidence has been captured, so
    NO downstream surface can leak it — the JSON sidecar (report.build_json), the run-result returned to
    the API, the ledger, and the submission package all serialize the finding wholesale. The safe
    prefix…suffix redaction already lives in ``secret_evidence.redacted_secret``; the Markdown render
    uses ``redact_secret`` / ``redact_value_in``. This closes the gap where all the added redaction lived
    only in the Markdown helpers while the structured JSON kept the full key + the token-bearing PoC."""
    raw = str(finding.get("secret_value") or "")
    if raw:
        finding["secret_value"] = redact_secret(raw)
    # The raw match also lives in snippet / description / the captured evidence's matched_value — redact
    # the known value out of those too (redact_value_in also runs the pattern backstop), so no vendor
    # token whose shape the scanner's redaction list happens to miss can leak through them.
    for field in ("snippet", "description"):
        if raw and finding.get(field):
            finding[field] = redact_value_in(str(finding[field]), raw)
    pe = finding.get("proof_evidence")
    if isinstance(pe, dict):
        for k in ("matched_value", "read_data", "request_header", "response_header"):
            if raw and pe.get(k):
                pe[k] = redact_value_in(str(pe[k]), raw)
    cred = finding.get("_credential_proof")
    if isinstance(cred, dict):
        for k in ("poc", "response_excerpt"):
            if cred.get(k):
                cred[k] = redact_value_in(str(cred[k]), raw)


def _is_secret_finding(finding: dict[str, Any]) -> bool:
    if not isinstance(finding, dict):
        return False
    cat = str(finding.get("category") or "").lower()
    base = _base_rule_id(finding)
    # class_id == "secrets" is included so a finding RECONSTRUCTED from client fields (the on-demand
    # /api/bounty/finding/report path sets class_id but no category, and rule_id may be empty) is still
    # recognized as a secret and classified — otherwise every strict-secret gate would silently no-op.
    return (cat in ("secret", "secret_exposed") or base.startswith("secret.")
            or str(finding.get("class_id") or "").lower() == "secrets")


def apply_secret_classification(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize every exposed-key finding in ``findings`` IN PLACE: stamp ``secret_classification`` +
    ``secret_evidence``, and DOWNGRADE the severity of anything not proven (public_client_key /
    candidate_unverified / false_positive) to Info/Low so a page-source or regex match can never read
    Medium+. A ``confirmed_secret`` is left untouched. Never raises — a classification error must not
    break a hunt; the finding is left as-is on any doubt."""
    for finding in findings or []:
        try:
            if not _is_secret_finding(finding):
                continue
            cls = classify_secret_finding(finding)
            finding["secret_classification"] = cls
            finding["secret_evidence"] = normalize_secret_evidence(finding)
            if cls != CONFIRMED_SECRET:
                finding["severity"] = severity_for_classification(cls, str(finding.get("severity") or "info"))
            # Strip the raw key from the finding LAST — after the redacted evidence is captured — so no
            # serialized surface (JSON sidecar / ledger / submission / run cache) can leak it.
            _scrub_raw_secret(finding)
        except Exception:  # noqa: BLE001 - classification must never break a hunt
            continue
    return findings
