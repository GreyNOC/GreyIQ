"""Top-level scan orchestrator.

Dispatches the target to the right source adapter, walks the resulting
tree, applies every registered rule, and assembles a ``ScanResult``
with score, risk, and recommendation. The orchestrator never raises
for an unscannable file — those count toward ``files_skipped``.
"""

from __future__ import annotations

import time
from pathlib import Path

from bughunter.code_scanner.model import ScanRequest, ScanResult, ScanTargetType
from bughunter.code_scanner.redaction import redact_finding_snippets
from bughunter.code_scanner.rules import ALL_RULES
from bughunter.code_scanner.sources import resolve_source
from bughunter.code_scanner.sources.git_local import LocalGitSource
from bughunter.code_scanner.sources.local import LocalPathSource
from bughunter.code_scanner.suppression import is_suppressed
from bughunter.code_scanner.walker import detect_language, walk_collect
from bughunter.settings import get_settings


class ScanTargetForbidden(PermissionError):
    """Raised when a scan target falls outside the configured base path."""

ALGORITHM_VERSION = "code-picture-v2"


def scan_target(request: ScanRequest) -> ScanResult:
    """Scan ``request.target``. Returns a populated ``ScanResult`` even on failure."""
    start = time.monotonic()
    source = resolve_source(request)
    try:
        root: Path = source.root

        # Optional containment: refuse to scan anywhere outside the
        # configured base path. The default empty string keeps the
        # behaviour the local CLI / Electron user expects; deployments
        # set CODE_SCAN_BASE_PATH to lock the API down.
        #
        # Gate on the resolved source type, not on target_type == PATH:
        # a git_local target (LocalGitSource) also walks an arbitrary
        # in-place host path, so it must be contained too. Remote git and
        # archive sources extract into a private tempdir, so they are
        # exempt (their root is never an operator-chosen host path).
        base = get_settings().code_scan_base_path
        if base and isinstance(source, (LocalPathSource, LocalGitSource)):
            base_path = Path(base).expanduser().resolve()
            resolved_root = root.resolve()
            if not (
                resolved_root == base_path
                or resolved_root.is_relative_to(base_path)
            ):
                raise ScanTargetForbidden(
                    f"Scan target {resolved_root} is outside the configured base path {base_path}."
                )

        # When a LocalPathSource resolved a *file* target we narrow the
        # walker to that single file via include_globs. This stops
        # callers from accidentally scanning every sibling file in the
        # parent dir just because they pointed at /path/to/one.py.
        include_globs = tuple(request.include_globs)
        if (
            request.target_type == ScanTargetType.PATH
            and isinstance(source, LocalPathSource)
            and source.single_file_relative
        ):
            include_globs = (source.single_file_relative,)

        files, walk_stats = walk_collect(
            root,
            max_bytes_per_file=request.max_bytes_per_file,
            max_total_bytes=request.max_total_bytes,
            max_files=request.max_files,
            include_globs=include_globs,
            exclude_globs=tuple(request.exclude_globs),
        )

        findings = []
        rule_errors: list[dict[str, str]] = []
        for walked in files:
            language = detect_language(walked.relative_path)
            for rule in ALL_RULES:
                if not rule.applies_to(language, walked.relative_path):
                    continue
                try:
                    findings.extend(rule.scan(path=walked.relative_path, text=walked.text))
                except Exception as error:
                    # A single broken rule shouldn't kill the whole
                    # scan; record what failed so the response can show
                    # it. Bounded message length to keep responses tight.
                    rule_errors.append(
                        {
                            "rule_id": rule.rule_id,
                            "file": walked.relative_path,
                            "error": f"{type(error).__name__}: {error}"[:240],
                        }
                    )

        # Suppression pass — drop findings annotated with `gn-slop: ignore`.
        # Build a lookup from relative path → text so we don't re-read files.
        text_by_path = {w.relative_path: w.text for w in files}
        kept: list = []
        suppressed_count = 0
        for finding in findings:
            text = text_by_path.get(finding.file_path)
            if text and is_suppressed(text, finding.rule_id, finding.line_start):
                suppressed_count += 1
                continue
            kept.append(finding)
        findings = kept

        # Redaction pass — secret findings get their snippets sanitized.
        findings, redacted_map = redact_finding_snippets(findings)

        elapsed = time.monotonic() - start
        result = ScanResult(
            target=request.target,
            target_type=request.target_type,
            algorithm=ALGORITHM_VERSION,
            files_scanned=walk_stats.files_scanned,
            files_skipped=walk_stats.files_skipped,
            bytes_scanned=walk_stats.bytes_scanned,
            elapsed_seconds=round(elapsed, 3),
            findings=list(findings),
            skipped_examples=list(walk_stats.skipped_examples),
            git_metadata=source.git_metadata,
            redacted_findings=set(redacted_map.keys()),
            suppressed_count=suppressed_count,
            rule_errors=rule_errors[:50],
        )
        result.compute_score()

        if request.target_type == ScanTargetType.PATH:
            # Echo the resolved target back so the dashboard / CLI can
            # show what was actually scanned (absolute path or the
            # specific file if single-file).
            if isinstance(source, LocalPathSource) and source.single_file_relative:
                result.target = str(Path(root) / source.single_file_relative)
            else:
                result.target = str(root)
        return result
    finally:
        # Always run cleanup, even when the body raised, so temp dirs
        # from RemoteGitSource / ArchiveSource don't leak.
        try:
            source.cleanup()
        except Exception:
            pass
