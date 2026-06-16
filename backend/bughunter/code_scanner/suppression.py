"""Suppression-comment support.

A reviewer can annotate a line with ``gn-slop: ignore <rule_id>`` to
silence a specific rule's hit on that line. The comment can sit on the
same line as the offending code, or on the line immediately before.
Optional ``reason="..."`` is recorded in the suppression count so a
report can show how many findings were dismissed by author intent.

Recognized forms:

    # gn-slop: ignore py.eval-on-input reason="internal DSL parser"
    // gn-slop: ignore js.eval reason="test fixture"
    -- gn-slop: ignore sql.injection
    /* gn-slop: ignore js.function-constructor */

We don't try to parse the reason; we just check whether the line that
covers the finding's start (or the line above it) mentions
``gn-slop: ignore <rule_id>``. Substring match keeps the implementation
small and predictable.
"""

from __future__ import annotations

import re
from typing import Final

_SUPPRESSION_RE: Final = re.compile(
    r"gn-slop\s*:\s*ignore\s+([A-Za-z0-9_.\-]+)",
)


def line_suppresses(line: str, rule_id: str) -> bool:
    if "gn-slop" not in line:
        return False
    for match in _SUPPRESSION_RE.finditer(line):
        if match.group(1) == rule_id:
            return True
    return False


def is_suppressed(text: str, rule_id: str, line_start: int) -> bool:
    """Return True when the finding at ``line_start`` is suppressed.

    ``line_start`` is 1-based, matching ``Finding.line_start``.
    """
    if not text or "gn-slop" not in text:
        return False
    lines = text.splitlines()
    # 1-based to 0-based
    target = line_start - 1
    if target < 0 or target >= len(lines):
        return False
    if line_suppresses(lines[target], rule_id):
        return True
    if target - 1 >= 0 and line_suppresses(lines[target - 1], rule_id):
        return True
    return False
