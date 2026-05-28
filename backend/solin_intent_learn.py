"""Tiny on-device intent classifier for GreyIQ's conversational router.

The chat UI uses regex for intent routing — fast, deterministic, but
brittle: every new way a user might phrase "who's talking to my
computer" needs a new pattern. This module sits behind the regex layer
as a fallback. It scores incoming text against a corpus of known
phrasings per handler using IDF-weighted Jaccard similarity over
tokens, and returns the best match if it clears a confidence threshold.

The corpus has two sources:
  1. Hard-coded ``SEED_PHRASES`` — the canonical phrasings each handler
     should always recognize.
  2. ``intent_phrases.jsonl`` — every phrasing the user (or the regex
     layer) confirms in practice gets appended here, so coverage grows
     monotonically without needing code changes.

No ML deps. Pure stdlib. Works offline, persists locally, no PII leaves
the box.
"""

from __future__ import annotations

import json
import math
import re
import threading
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from solin_typo import token_similarity

DEFAULT_PATH = Path.home() / ".solin" / "state" / "intent_phrases.jsonl"
REGRET_PATH = Path.home() / ".solin" / "state" / "intent_regret.jsonl"

# Stopwords kept small on purpose — over-aggressive stopword removal
# eats discriminating tokens like "running" / "listening".
_STOP = frozenset(
    """
a an the and or but is are was were be been being have has had do does did
of in on at to for with from by about as if then than there here so just
i me my mine you your we us our they them their it its this that these those
can could would should will shall may might do does did
what who whom whose where when why how which
please tell show me list see find any anything something
""".split()
)

_TOKEN = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if len(t) >= 2 and t not in _STOP]


# Canonical phrasings. Keep these short and varied — the learner will
# fill in the long tail from real user traffic.
SEED_PHRASES: dict[str, list[str]] = {
    "lan_devices": [
        "what devices are on my network",
        "list devices on my lan",
        "show me everything on my network",
        "who is on my wifi",
        "who is connected to my router",
        "arp table",
        "what hosts are on my subnet",
    ],
    "hunt_network": [
        "hunt for devices on my network",
        "hunt the network for devices",
        "hunt the lan",
        "scan the network for devices",
        "scan my local network",
        "scan the lan",
        "scan my lan",
        "scan my subnet",
        "scan the wifi for devices",
        "find every device on my network",
        "find all devices on the network",
        "find every host on my subnet",
        "discover all devices on my network",
        "discover network devices",
        "enumerate devices on my network",
        "enumerate the lan",
        "map the network",
        "map my network",
        "map the lan",
        "build a network map",
        "refresh the network map",
        "refresh the radar",
        "refresh the network radar",
        "rescan the network",
        "rescan the lan",
        "run the device hunter",
        "run a deep network scan",
        "deep scan the lan",
        "scan my network and tell me what is on it",
        "go find every device on the wifi",
    ],
    "listening_ports": [
        "what ports are listening",
        "open ports on this machine",
        "show listening sockets",
        "what is listening on this computer",
        "which services are bound to ports",
    ],
    "outbound_connections": [
        "what is talking to the internet",
        "show outbound connections",
        "what apps are connecting out",
        "what processes have external connections",
        "what is reaching the internet right now",
    ],
    "top_talkers": [
        "who is talking to this computer the most",
        "top talkers on this machine",
        "busiest connections",
        "noisiest peers",
        "who is connecting to me",
        "what hosts are hitting this machine",
        "who talks to my computer the most",
        "biggest talkers",
        "most active remote peers",
    ],
    "safety_check": [
        "is my network safe",
        "anything suspicious going on",
        "am i under attack",
        "is my computer compromised",
        "do you see anything wrong",
        "network health check",
        # Casual phrasings — "how does the network look today",
        # "everything ok with my computer", "give me a sitrep".
        "how does the network look today",
        "how is the network looking",
        "what does the network look like",
        "how is wifi looking",
        "how does my computer look",
        "how are things on my network",
        "how do things look on my network",
        "everything ok with my network",
        "everything fine on my computer",
        "does the network look ok",
        "is anything off with my network",
        "any problems with my network",
        "any issues on my host",
        "give me a status on my network",
        "network status",
        "security status",
        "rundown on my computer",
        "how do we look security wise",
        "how is my machine doing",
        "is everything good on my pc",
    ],
    "recent_alerts": [
        "any new alerts",
        "what changed recently",
        "show watcher events",
        "any warnings",
        "what did you see",
        "what has happened recently",
    ],
    "watcher_start": [
        "start the watcher",
        "begin monitoring",
        "start watching the network",
        "fire up the watcher",
        "turn on monitoring",
    ],
    "watcher_stop": [
        "stop the watcher",
        "halt monitoring",
        "stop watching",
        "turn off the watcher",
    ],
    "watcher_status": [
        "watcher status",
        "is the watcher running",
        "is monitoring on",
    ],
}


class IntentLearner:
    """Persistent fuzzy intent classifier.

    ``score(text)`` returns ranked (handler, confidence) pairs.
    ``best(text, threshold)`` returns the top match if it's confident
    enough AND has a clear margin over the runner-up — otherwise None.
    ``learn(text, handler)`` appends a positive example and updates IDF.
    ``regret(text)`` logs a phrasing that we mis-routed; useful for an
    offline review pass.
    """

    def __init__(
        self,
        path: Path = DEFAULT_PATH,
        regret_path: Path = REGRET_PATH,
        seeds: dict[str, list[str]] | None = None,
    ) -> None:
        self.path = Path(path)
        self.regret_path = Path(regret_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        seeds = seeds if seeds is not None else SEED_PHRASES
        # examples[handler] -> list[set[str]] of token sets.
        self.examples: dict[str, list[set[str]]] = {
            h: [set(tokenize(p)) for p in phrases if tokenize(p)] for h, phrases in seeds.items()
        }
        self._load_persisted()
        self._idf: dict[str, float] = {}
        self._recompute_idf()

    # ------------------------------------------------------------- internals

    def _load_persisted(self) -> None:
        if not self.path.exists():
            return
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                handler = rec.get("handler")
                text = rec.get("text") or ""
                if not handler or not text:
                    continue
                toks = set(tokenize(text))
                if toks:
                    self.examples.setdefault(handler, []).append(toks)
        except OSError:
            pass

    def _recompute_idf(self) -> None:
        df: Counter[str] = Counter()
        n_docs = 0
        for ex_list in self.examples.values():
            for ex in ex_list:
                n_docs += 1
                for t in ex:
                    df[t] += 1
        if n_docs == 0:
            self._idf = {}
            return
        self._idf = {t: math.log((n_docs + 1) / (df[t] + 1)) + 1.0 for t in df}

    def _w(self, tokens: Iterable[str]) -> float:
        return sum(self._idf.get(t, 1.0) for t in tokens)

    def _fuzzy_jaccard(self, query: set[str], example: set[str]) -> float:
        used_example: set[str] = set()
        overlap = 0.0

        for query_token in sorted(query, key=lambda t: self._idf.get(t, 1.0), reverse=True):
            best_token = ""
            best_weight = 0.0
            for example_token in example:
                if example_token in used_example:
                    continue
                similarity = token_similarity(query_token, example_token)
                if similarity <= 0:
                    continue
                weight = (
                    min(
                        self._idf.get(query_token, 1.0),
                        self._idf.get(example_token, 1.0),
                    )
                    * similarity
                )
                if weight > best_weight:
                    best_token = example_token
                    best_weight = weight
            if best_token:
                used_example.add(best_token)
                overlap += best_weight

        if overlap <= 0:
            return 0.0

        union = query | example
        weighted_jaccard = overlap / self._w(union) if union else 0.0
        query_coverage = overlap / max(self._w(query), 1e-9)
        coverage_score = query_coverage * (0.72 if len(query) <= 3 else 0.58)
        return max(weighted_jaccard, coverage_score)

    # ---------------------------------------------------------------- public

    def score(self, text: str) -> list[tuple[str, float]]:
        toks = set(tokenize(text))
        if not toks:
            return []
        results: list[tuple[str, float]] = []
        with self._lock:
            for handler, ex_list in self.examples.items():
                best_j = 0.0
                for ex in ex_list:
                    if not ex:
                        continue
                    jw = self._fuzzy_jaccard(toks, ex)
                    if jw > best_j:
                        best_j = jw
                if best_j > 0:
                    results.append((handler, best_j))
        results.sort(key=lambda x: -x[1])
        return results

    def best(
        self,
        text: str,
        threshold: float = 0.30,
        min_margin: float = 0.05,
    ) -> tuple[str, float] | None:
        scored = self.score(text)
        if not scored:
            return None
        top_h, top_s = scored[0]
        if top_s < threshold:
            return None
        # Require a clear gap over the runner-up so we don't fire on
        # genuinely ambiguous phrasings (better to ask than guess wrong).
        if len(scored) > 1 and (top_s - scored[1][1]) < min_margin:
            return None
        return top_h, top_s

    def learn(self, text: str, handler: str) -> None:
        text = (text or "").strip()
        toks = set(tokenize(text))
        if not toks or not handler:
            return
        with self._lock:
            self.examples.setdefault(handler, []).append(toks)
            self._recompute_idf()
            try:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({"text": text, "handler": handler}) + "\n")
            except OSError:
                pass

    def regret(self, text: str, predicted: str | None = None) -> None:
        """Record a phrasing the system handled badly. Doesn't change
        scoring — it's a queue for offline review / `/teach`."""
        text = (text or "").strip()
        if not text:
            return
        try:
            self.regret_path.parent.mkdir(parents=True, exist_ok=True)
            with self.regret_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"text": text, "predicted": predicted}) + "\n")
        except OSError:
            pass

    def list_regret(self, limit: int = 50) -> list[dict]:
        if not self.regret_path.exists():
            return []
        out: list[dict] = []
        try:
            for line in self.regret_path.read_text(encoding="utf-8").splitlines():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError:
            return []
        return out[-limit:]

    def handlers(self) -> list[str]:
        with self._lock:
            return sorted(self.examples.keys())

    def stats(self) -> dict:
        with self._lock:
            return {
                "handlers": {h: len(ex) for h, ex in self.examples.items()},
                "vocab": len(self._idf),
                "path": str(self.path),
            }


__all__ = ["IntentLearner", "SEED_PHRASES", "tokenize", "DEFAULT_PATH", "REGRET_PATH"]


if __name__ == "__main__":
    L = IntentLearner()
    tests = [
        "who is talking to this computer the most?",
        "what's hitting my pc",
        "noisiest hosts on the wire",
        "list lan devices",
        "stop the watcher",
        "is my computer compromised",
        "tell me a joke",
    ]
    for t in tests:
        b = L.best(t)
        s = L.score(t)[:3]
        print(f"{t!r:55} -> best={b}   top={s}")
