"""Pure-Python Byte-Pair Encoding tokenizer for GreyIQ.

Why this exists
---------------
GreyIQ's first tokenizer was character-level: a 501-entry vocab where every
token is one Unicode code point. With ``block_size=64`` that meant the model
saw 64 *characters* of context — about ten English words. No model size,
however large, can reason from that.

A BPE tokenizer keeps the same model architecture but compresses common
sequences ("the ", "tion", "import ") into single tokens. Typical English
text shrinks 4-5×. ``block_size=64`` BPE tokens covers ~250 words. Same
weights, same compute, dramatically more usable context.

The module is dependency-free: it implements training and inference in
pure Python so it ships in the wheel without pulling in HuggingFace
``tokenizers``. Training a 16k-vocab model on 8 MB of text takes ~3-10
minutes on a laptop CPU; inference is sub-millisecond per token.

File format
-----------
Saved as JSON, compatible with ``solin_core.load_vocab`` via the
``tokenizer_kind`` field::

    {
      "tokenizer_kind": "bpe",
      "stoi":     { token_str -> id },
      "merges":   [ [left, right], ... ],   // ordered by training rank
      "vocab_size": int
    }

The end-of-word marker ``</w>`` is the canonical word boundary; the decoder
turns it back into a space.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable, Iterable
from pathlib import Path

END_OF_WORD = "</w>"

# Bounds for the per-word BPE encode cache so it stays flat over a long-lived engine.
_ENCODE_CACHE_MAX = 50_000
_ENCODE_CACHE_MAX_WORD = 64

# Pre-tokenize on word characters / individual punctuation. Whitespace is
# not preserved as a token — END_OF_WORD restores spaces between words on
# decode. Newlines do survive because we split text into lines upstream.
_PRE_TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


def pre_tokenize(text: str) -> list[str]:
    return _PRE_TOKEN_RE.findall(text)


# ---------------------------------------------------------------- tokenizer


class BPETokenizer:
    def __init__(self, stoi: dict[str, int] | None = None, merges: list[tuple[str, str]] | None = None) -> None:
        self.stoi: dict[str, int] = dict(stoi) if stoi else {}
        self.merges: list[tuple[str, str]] = list(merges) if merges else []
        self.itos: dict[int, str] = {v: k for k, v in self.stoi.items()}
        # Lower rank = applied first.
        self.merge_ranks: dict[tuple[str, str], int] = {pair: i for i, pair in enumerate(self.merges)}
        self._encode_cache: dict[str, list[str]] = {}

    @property
    def vocab_size(self) -> int:
        return len(self.stoi)

    # ----------------------------------------------------------- training

    @classmethod
    def train(
        cls,
        texts: Iterable[str],
        vocab_size: int = 8192,
        min_pair_count: int = 2,
        progress: Callable[[str], None] | None = None,
    ) -> BPETokenizer:
        """Train BPE merges over ``texts`` until the vocabulary reaches
        ``vocab_size`` tokens or no pair occurs more than ``min_pair_count``.

        Memory model: we keep a dict of ``word -> [symbols]`` plus per-word
        counts. Merges are applied per-word (cheap) and pair counts are
        rebuilt from scratch each iteration (slow but correct and simple)."""

        # 1. Collect word frequencies from the entire corpus.
        word_counts: Counter[str] = Counter()
        for chunk in texts:
            for tok in pre_tokenize(chunk):
                word_counts[tok] += 1
        if not word_counts:
            raise ValueError("No tokens in input — corpus is empty.")

        if progress:
            progress(f"corpus: {sum(word_counts.values()):,} tokens, " f"{len(word_counts):,} unique words")

        # 2. Each word becomes a symbol list ending in END_OF_WORD.
        word_splits: dict[str, list[str]] = {word: list(word) + [END_OF_WORD] for word in word_counts}

        # 3. Initial vocab = every base symbol used anywhere.
        base: set[str] = {END_OF_WORD}
        for symbols in word_splits.values():
            base.update(symbols)
        stoi: dict[str, int] = {tok: i for i, tok in enumerate(sorted(base))}
        merges: list[tuple[str, str]] = []
        if progress:
            progress(f"base vocab: {len(stoi)} chars + EOW marker")

        # 4. Iteratively merge the most-frequent adjacent pair.
        while len(stoi) < vocab_size:
            pair_counts: Counter[tuple[str, str]] = Counter()
            for word, symbols in word_splits.items():
                count = word_counts[word]
                for i in range(len(symbols) - 1):
                    pair_counts[(symbols[i], symbols[i + 1])] += count
            if not pair_counts:
                break
            best_pair, best_count = pair_counts.most_common(1)[0]
            if best_count < min_pair_count:
                if progress:
                    progress(f"stopped: best pair {best_pair} count " f"{best_count} < min {min_pair_count}")
                break

            merged = best_pair[0] + best_pair[1]
            if merged in stoi:
                # Defensive: shouldn't happen, but skip gracefully.
                merges.append(best_pair)
                continue
            stoi[merged] = len(stoi)
            merges.append(best_pair)

            # Apply the merge to every word.
            for word, symbols in list(word_splits.items()):
                if best_pair[0] not in symbols:
                    continue
                new_symbols: list[str] = []
                i = 0
                limit = len(symbols)
                while i < limit:
                    if i < limit - 1 and symbols[i] == best_pair[0] and symbols[i + 1] == best_pair[1]:
                        new_symbols.append(merged)
                        i += 2
                    else:
                        new_symbols.append(symbols[i])
                        i += 1
                word_splits[word] = new_symbols

            if progress and len(stoi) % 250 == 0:
                progress(f"vocab={len(stoi):>5} last={best_pair} " f"freq={best_count}")

        if progress:
            progress(f"done: {len(stoi)} tokens, {len(merges)} merges")
        return cls(stoi=stoi, merges=merges)

    # ----------------------------------------------------------- encoding

    def _encode_word(self, word: str) -> list[str]:
        cached = self._encode_cache.get(word)
        if cached is not None:
            return cached
        if not word:
            return []
        symbols: list[str] = list(word) + [END_OF_WORD]

        # Greedy lowest-rank merge until no more apply.
        while len(symbols) > 1:
            best_idx = -1
            best_rank: int | None = None
            for i in range(len(symbols) - 1):
                rank = self.merge_ranks.get((symbols[i], symbols[i + 1]))
                if rank is not None and (best_rank is None or rank < best_rank):
                    best_rank = rank
                    best_idx = i
            if best_rank is None:
                break
            merged = symbols[best_idx] + symbols[best_idx + 1]
            symbols[best_idx : best_idx + 2] = [merged]

        # Bound the cache so it can't grow without limit over a long-lived engine:
        # skip pathologically long tokens, and drop the cache when it hits the cap
        # (a cheap reset — the common words simply repopulate).
        if len(word) <= _ENCODE_CACHE_MAX_WORD:
            if len(self._encode_cache) >= _ENCODE_CACHE_MAX:
                self._encode_cache.clear()
            self._encode_cache[word] = symbols
        return symbols

    def encode(self, text: str) -> list[int]:
        ids: list[int] = []
        for word in pre_tokenize(text):
            for tok in self._encode_word(word):
                idx = self.stoi.get(tok)
                if idx is not None:
                    ids.append(idx)
                # Unknown tokens silently dropped — same convention as the
                # existing char encoder. Train with a larger vocab if this
                # becomes lossy.
        return ids

    def decode(self, ids: list[int]) -> str:
        parts: list[str] = []
        for idx in ids:
            tok = self.itos.get(idx)
            if tok is not None:
                parts.append(tok)
        text = "".join(parts)
        # END_OF_WORD becomes a space so word boundaries survive.
        text = text.replace(END_OF_WORD, " ")
        # Collapse the trailing space the last word leaves behind.
        return text.rstrip(" ")

    # ------------------------------------------------------------ persistence

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(
                {
                    "tokenizer_kind": "bpe",
                    "stoi": self.stoi,
                    "merges": [list(p) for p in self.merges],
                    "vocab_size": len(self.stoi),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> BPETokenizer:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("tokenizer_kind") != "bpe":
            raise ValueError(f"{path} is not a BPE tokenizer file " "(missing tokenizer_kind: 'bpe').")
        merges = [tuple(p) for p in payload.get("merges", [])]
        return cls(stoi=payload["stoi"], merges=merges)


__all__ = ["BPETokenizer", "pre_tokenize", "END_OF_WORD"]
