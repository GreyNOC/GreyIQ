from __future__ import annotations

import re
from collections.abc import Iterable

WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9+#-]*")

COMMON_SHORT_TYPOS = {
    "adn": "and",
    "hte": "the",
    "hwo": "how",
    "hye": "hey",
    "teh": "the",
    "taht": "that",
    "thsi": "this",
    "whta": "what",
    "waht": "what",
    "yuo": "you",
    "oyu": "you",
}


def is_single_typo(left: str, right: str, *, min_length: int = 4) -> bool:
    """Return True for one substitution, insertion/deletion, or adjacent swap."""
    left = (left or "").lower()
    right = (right or "").lower()
    if left == right:
        return True
    if min(len(left), len(right)) < min_length:
        return False
    if abs(len(left) - len(right)) > 1:
        return False

    if len(left) == len(right):
        diffs = [index for index, pair in enumerate(zip(left, right, strict=False)) if pair[0] != pair[1]]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2:
            first, second = diffs
            return second == first + 1 and left[first] == right[second] and left[second] == right[first]
        return False

    short, long = (left, right) if len(left) < len(right) else (right, left)
    i = j = edits = 0
    while i < len(short) and j < len(long):
        if short[i] == long[j]:
            i += 1
            j += 1
            continue
        edits += 1
        if edits > 1:
            return False
        j += 1
    return True


def token_similarity(left: str, right: str) -> float:
    left = (left or "").lower()
    right = (right or "").lower()
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    if COMMON_SHORT_TYPOS.get(left) == right or COMMON_SHORT_TYPOS.get(right) == left:
        return 0.92
    if is_single_typo(left, right):
        return 0.88
    return 0.0


def normalize_known_typos(text: str, vocabulary: Iterable[str]) -> str:
    """Correct only words that are one typo away from a known routing term."""
    if not text:
        return ""
    vocab = frozenset(term.lower() for term in vocabulary if term)
    if not vocab:
        return text

    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        lowered = token.lower()
        if lowered in vocab:
            return token

        short = COMMON_SHORT_TYPOS.get(lowered)
        if short and short in vocab:
            return _match_case(token, short)

        if len(lowered) < 4:
            return token

        candidates = [
            candidate
            for candidate in vocab
            if abs(len(candidate) - len(lowered)) <= 1 and is_single_typo(lowered, candidate)
        ]
        if len(candidates) != 1:
            return token
        return _match_case(token, candidates[0])

    return WORD_RE.sub(replace, text)


def _match_case(source: str, replacement: str) -> str:
    if source.isupper():
        return replacement.upper()
    if source[:1].isupper() and source[1:].islower():
        return replacement.capitalize()
    return replacement
