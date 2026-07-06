"""GreyIQ BugHunter — code scan service.

A thin, JSON-friendly wrapper around the vendored ``code_scanner``. It maps an
API/chat request into a ``ScanRequest``, runs the scanner, and serializes the
``ScanResult`` into a plain dict that the GreyIQ API can return and the chat
layer can cite.

Authorization: code scanning reads source from a local path, a local git repo,
a remote git URL (cloned to a temp dir), or an archive. Point it only at code
you own or are authorized to review. Set ``GREYIQ_CODE_SCAN_BASE_PATH`` to
refuse any local target outside that root.
"""

from __future__ import annotations

from typing import Any

from bughunter.code_scanner import ScanRequest, scan_target
from bughunter.code_scanner.model import Finding, ScanResult, ScanTargetType

_TARGET_TYPES: dict[str, ScanTargetType] = {t.value: t for t in ScanTargetType}
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}
_CONFIDENCE_RANK: dict[str, int] = {"high": 3, "medium": 2, "low": 1}
_MAX_FINDINGS_RETURNED = 500


def _finding_to_dict(finding: Finding, *, redacted: bool = False) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "category": finding.category,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "snippet": finding.snippet,
        "remediation": finding.remediation,
        "redacted": redacted,
        # The exact variable the secret is assigned to (for the report's "exact location"), and the
        # RAW credential value. secret_value is deliberately NOT redacted — it is shown only in the
        # report's clearly-labelled credential section and used to validate the key; it is never
        # persisted to the ledger (which builds its own metadata record). Present only for
        # category=="secret" findings.
        **({"variable_name": finding.variable_name} if finding.variable_name else {}),
        **({"secret_value": finding.secret_value} if finding.secret_value else {}),
    }


def _result_to_dict(result: ScanResult) -> dict[str, Any]:
    ordered = sorted(
        result.findings,
        key=lambda f: (
            _SEVERITY_RANK.get(f.severity.value, 0),
            _CONFIDENCE_RANK.get(f.confidence.value, 0),
        ),
        reverse=True,
    )
    finding_dicts = [
        _finding_to_dict(f, redacted=f"{f.rule_id}@{f.file_path}:{f.line_start}" in result.redacted_findings)
        for f in ordered[:_MAX_FINDINGS_RETURNED]
    ]
    return {
        "ok": True,
        "scan_type": "code",
        "target": result.target,
        "target_type": result.target_type.value,
        "risk": result.risk,
        "score": result.score,
        "recommendation": result.recommendation,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "bytes_scanned": result.bytes_scanned,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "finding_count": len(result.findings),
        "suppressed_count": result.suppressed_count,
        "git_metadata": result.git_metadata,
        "findings": finding_dicts,
        "findings_truncated": len(result.findings) > _MAX_FINDINGS_RETURNED,
    }


def run_code_scan(
    target: str,
    target_type: str = "path",
    max_files: int = 5000,
    include_globs: tuple[str, ...] = (),
    exclude_globs: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Scan a code target and return a JSON-serializable result.

    Returns ``{"ok": False, "error": ...}`` on bad input or an unreachable
    target instead of raising, so the API surfaces a clean message rather than
    a 500.
    """
    clean_target = str(target or "").strip()
    if not clean_target:
        return {"ok": False, "error": "No scan target provided."}

    resolved_type = _TARGET_TYPES.get(str(target_type or "path").strip().lower())
    if resolved_type is None:
        return {
            "ok": False,
            "error": (
                f"Unknown target_type '{target_type}'. "
                f"Use one of: {', '.join(sorted(_TARGET_TYPES))}."
            ),
        }

    request = ScanRequest(
        target=clean_target,
        target_type=resolved_type,
        max_files=max(1, int(max_files)),
        include_globs=tuple(include_globs),
        exclude_globs=tuple(exclude_globs),
    )

    try:
        result = scan_target(request)
    except Exception as exc:  # noqa: BLE001 - surface any scan failure as data
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "target": clean_target,
        }

    # Idempotent; ensures score/risk/recommendation are populated.
    result.compute_score()
    return _result_to_dict(result)
