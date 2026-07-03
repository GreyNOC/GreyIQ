"""Rule base class + the regex rule that powers most of the v1 packs.

Each rule produces zero or more ``Finding`` objects when invoked on a
single file. Rules are stateless so the scanner can apply them in any
order.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatch

from bughunter.code_scanner.model import Confidence, Finding, Severity


def _path_matches(path: str, pattern: str) -> bool:
    """Match a path against a glob that may use ``**/`` recursive prefix.

    Python's ``fnmatch`` doesn't honor ``**`` specially: it just treats
    each ``*`` as "anything including ``/``" but still requires that
    every literal segment of the pattern lines up against the string.
    That means ``**/package.json`` misses a root-level ``package.json``
    because there's no prefix to consume.

    This matcher peels the ``**/`` prefix and matches the remainder
    against every suffix of the path (including the path itself).
    """
    if pattern.startswith("**/"):
        remainder = pattern[3:]
        if fnmatch(path, remainder):
            return True
        parts = path.split("/")
        for index in range(1, len(parts)):
            if fnmatch("/".join(parts[index:]), remainder):
                return True
        return False
    return fnmatch(path, pattern)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: str
    remediation: str = ""
    # Restrict matches to these language tags (see walker.detect_language).
    # Empty tuple => apply to every text file.
    languages: tuple[str, ...] = ()
    # Restrict matches to files whose path matches at least one fnmatch
    # pattern. Useful for CI rules (`*.github/workflows/*.yml`).
    path_globs: tuple[str, ...] = ()

    def applies_to(self, language: str, path: str) -> bool:
        if self.languages and language not in self.languages:
            return False
        if self.path_globs:
            if not any(_path_matches(path, pattern) for pattern in self.path_globs):
                return False
        return True

    def scan(self, *, path: str, text: str) -> Iterable[Finding]:
        raise NotImplementedError


def _snippet_around(text: str, match: re.Match[str], context: int = 60) -> str:
    """Return a printable snippet around a regex hit, line-clipped.

    Keeps a small amount of context to either side and collapses
    whitespace so the snippet fits in a JSON cell without leaking long
    strings of binary garbage.
    """
    start = max(0, match.start() - context)
    end = min(len(text), match.end() + context)
    raw = text[start:end]
    return re.sub(r"\s+", " ", raw).strip()[:240]


def _line_span(text: str, match: re.Match[str]) -> tuple[int, int]:
    line_start = text.count("\n", 0, match.start()) + 1
    line_end = text.count("\n", 0, match.end()) + 1
    return line_start, line_end


# The identifier immediately to the LEFT of the matched secret's assignment operator — captures
# `apiKey = "..."`, `"apiKey": "..."`, `FIREBASE_KEY=...`, `const apiKey = '...'`. Anchored to the
# end of the pre-match text so it's the nearest assignment target, not some earlier token.
_ASSIGN_NAME_RE = re.compile(r"""([A-Za-z_$][\w$.\-]{0,60})['"]?\s*[:=]\s*(?:f|r|b|u|rb|br)?['"]?\s*$""")


def _assignment_name(pre_match_text: str) -> str:
    m = _ASSIGN_NAME_RE.search(pre_match_text)
    return m.group(1) if m else ""


@dataclass(frozen=True)
class RegexRule(Rule):
    """A rule whose hit set is a regex search over the raw file text.

    Use ``compiled`` for the underlying pattern. Setting ``unique``
    de-duplicates matches that produce identical snippets — common for
    secret patterns where the same key appears in two test fixtures.
    """

    pattern: str = ""
    flags: int = re.MULTILINE
    unique: bool = False
    # Optional second filter: the match's surrounding line must include
    # one of these substrings. Cheap way to require a related keyword
    # without writing a multi-step matcher.
    line_must_contain: tuple[str, ...] = ()
    # Optional third filter: the match's surrounding line must NOT
    # include any of these substrings. Used to suppress obvious
    # false-positive contexts (e.g. comments saying "this is fake").
    line_must_not_contain: tuple[str, ...] = ()

    def _compiled(self) -> re.Pattern[str]:
        return re.compile(self.pattern, self.flags)

    def _line_of(self, text: str, offset: int) -> str:
        line_start = text.rfind("\n", 0, offset) + 1
        line_end = text.find("\n", offset)
        if line_end == -1:
            line_end = len(text)
        return text[line_start:line_end]

    def scan(self, *, path: str, text: str) -> Iterable[Finding]:
        seen_snippets: set[str] = set()
        for match in self._compiled().finditer(text):
            line = self._line_of(text, match.start())
            if self.line_must_contain and not any(token in line for token in self.line_must_contain):
                continue
            if self.line_must_not_contain and any(
                token in line for token in self.line_must_not_contain
            ):
                continue
            snippet = _snippet_around(text, match)
            if self.unique:
                key = (snippet, path)
                if key in seen_snippets:  # type: ignore[comparison-overlap]
                    continue
                seen_snippets.add(key)  # type: ignore[arg-type]
            line_start, line_end = _line_span(text, match)
            # For a secret finding, capture the assigned variable name and the RAW value so the
            # report can name the exact variable and (for a credential) validate + show the real
            # key. Non-secret rules keep both empty — no raw match value is ever retained.
            variable_name = secret_value = ""
            if self.category == "secret":
                line_offset = text.rfind("\n", 0, match.start()) + 1
                variable_name = _assignment_name(text[line_offset:match.start()])
                secret_value = match.group(0)
            yield Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                category=self.category,
                file_path=path,
                line_start=line_start,
                line_end=line_end,
                snippet=snippet,
                remediation=self.remediation,
                variable_name=variable_name,
                secret_value=secret_value,
            )


__all__ = ["RegexRule", "Rule"]
