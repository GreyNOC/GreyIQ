"""GreyIQ BugHunter — vendored security and code-analysis engines.

This package gives GreyIQ a real, deterministic bug-finding capability that the
~0.8M-parameter local model cannot provide on its own. The first engine is the
GN Slop Detection ``code_scanner`` (a rule-based static analyzer with
severity/confidence-scored findings), vendored here and rewired onto GreyIQ's
import layout.

Entry point: :func:`bughunter.scan_service.run_code_scan`.
"""
