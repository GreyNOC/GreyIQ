"""Data model for code scanner results.

Frozen dataclasses keep the public contract narrow. The Pydantic API
schemas in ``app.models.schemas`` mirror these structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanTargetType(str, Enum):
    PATH = "path"
    GIT_LOCAL = "git_local"
    GIT_REMOTE = "git_remote"
    ARCHIVE = "archive"


# Severity weights used by the composite scorer. The scorer applies
# `(weight * confidence) / file_count` so a thousand low-confidence
# medium findings don't dominate a single critical finding.
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.02,
    Severity.LOW: 0.06,
    Severity.MEDIUM: 0.18,
    Severity.HIGH: 0.32,
    Severity.CRITICAL: 0.50,
}

_CONFIDENCE_MULTIPLIER: dict[Confidence, float] = {
    Confidence.LOW: 0.5,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 1.0,
}


def finding_score(severity: Severity, confidence: Confidence) -> float:
    return _SEVERITY_WEIGHT[severity] * _CONFIDENCE_MULTIPLIER[confidence]


@dataclass(frozen=True)
class Finding:
    """A single rule hit on a single span of source code."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: str
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    remediation: str = ""
    column_start: int | None = None
    column_end: int | None = None


@dataclass(frozen=True)
class LlmVerification:
    """Result of optionally asking a user-supplied LLM about a finding.

    The provider and model strings are echoed so analysts can attribute
    a verdict. The verdict is always one of {"likely_true_positive",
    "likely_false_positive", "uncertain", "error"} — we never let the
    raw LLM output drive routing logic.
    """

    provider: str
    model: str
    verdict: str
    rationale: str


@dataclass
class ScanResult:
    target: str
    target_type: ScanTargetType
    algorithm: str
    files_scanned: int
    files_skipped: int
    bytes_scanned: int
    elapsed_seconds: float
    findings: list[Finding] = field(default_factory=list)
    skipped_examples: list[str] = field(default_factory=list)
    git_metadata: dict[str, str] = field(default_factory=dict)
    llm_verifications: dict[str, LlmVerification] = field(default_factory=dict)
    redacted_findings: set[str] = field(default_factory=set)
    suppressed_count: int = 0
    rule_errors: list[dict[str, str]] = field(default_factory=list)
    score: float = 0.0
    risk: str = "low"
    recommendation: str = ""

    def compute_score(self) -> None:
        if self.files_scanned <= 0 or not self.findings:
            self.score = 0.0
            self.risk = "low"
            self.recommendation = "No suspicious code patterns detected at this scan depth."
            return
        # Normalize by sqrt(files) so a large clean codebase doesn't
        # drown signal, but a single finding in a tiny tree doesn't max
        # out the score either.
        import math

        denominator = max(1.0, math.sqrt(self.files_scanned))
        raw = sum(finding_score(f.severity, f.confidence) for f in self.findings) / denominator
        # Severity / category floors. A single high-confidence secret or
        # critical backdoor / CI exfil pushes the composite into high
        # risk regardless of how many clean files dilute the average.
        for finding in self.findings:
            if (
                finding.severity in (Severity.HIGH, Severity.CRITICAL)
                and finding.confidence == Confidence.HIGH
                and finding.rule_id.startswith("secret.")
            ):
                raw = max(raw, 0.70)
            if finding.severity == Severity.CRITICAL and finding.category in (
                "backdoor",
                "ci",
            ):
                raw = max(raw, 0.70)
        # Any critical finding at all still floors at 0.65.
        if any(f.severity == Severity.CRITICAL for f in self.findings):
            raw = max(raw, 0.65)
        self.score = round(min(raw, 1.0), 3)
        if self.score >= 0.65:
            self.risk = "high"
            self.recommendation = (
                "Critical patterns detected. Stop the merge and have an analyst "
                "walk through every critical and high finding before continuing."
            )
        elif self.score >= 0.30:
            self.risk = "moderate"
            self.recommendation = (
                "Review the high and critical findings; many of these become "
                "exploitable when combined with untrusted input."
            )
        else:
            self.risk = "low"
            self.recommendation = (
                "Findings present but none individually severe. Triage as routine."
            )


@dataclass(frozen=True)
class ScanRequest:
    target: str
    target_type: ScanTargetType
    max_bytes_per_file: int = 1_048_576  # 1 MiB
    max_total_bytes: int = 256 * 1024 * 1024  # 256 MiB
    max_files: int = 25_000
    include_globs: tuple[str, ...] = ()
    exclude_globs: tuple[str, ...] = ()
