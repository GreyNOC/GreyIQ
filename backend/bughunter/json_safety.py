"""Small, interpreter-independent nesting guard for untrusted JSON text."""

from __future__ import annotations


def exceeds_json_depth(text: str, *, limit: int = 128) -> bool:
    """Reject excessive container nesting before handing text to a JSON parser.

    The parser's own recursion threshold varies by Python build and process
    recursion limit. Scan outside quoted strings so brackets in values do not
    count as structure. The JSON parser still validates syntax afterward.
    """
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                return True
        elif char in "]}":
            depth -= 1
    return False
