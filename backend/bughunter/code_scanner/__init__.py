"""GreyNOC code scanner.

A static analyzer that finds backdoor patterns, hardcoded secrets,
unsafe sinks (eval/exec/command injection), CI-workflow exfil shapes,
and weak-crypto / known-vulnerable dependency primitives across a
repository tree. No machine-learning model is bundled in the engine —
all detection is regex- and AST-based.

The public surface is intentionally narrow:

>>> from bughunter.code_scanner import scan_target, ScanRequest
>>> result = scan_target(ScanRequest(target="./my-repo", target_type="path"))
>>> result.score, result.risk
(0.42, 'moderate')
"""

from bughunter.code_scanner.model import (
    Confidence,
    Finding,
    ScanRequest,
    ScanResult,
    ScanTargetType,
    Severity,
)
from bughunter.code_scanner.scanner import scan_target

__all__ = [
    "Confidence",
    "Finding",
    "ScanRequest",
    "ScanResult",
    "ScanTargetType",
    "Severity",
    "scan_target",
]
