"""Guard: the test suite must never write to the operator's real learning stores.

WHY THIS FILE EXISTS
--------------------
Two test files ran genuine hunts and campaigns against a local HTTP fixture while passing
``runtime_dir=REPO_ROOT / "runtime"`` — the LIVE store: ``test_bounty_progress.py`` in
eight places and ``test_web_scan_service.py`` in two. Every suite run therefore appended
to the operator's own learning data. Measured on this checkout before the fix, one run of
``test_bounty_progress.py`` alone added ~3.9 KB to ``hunt_traces.jsonl`` and ~16.3 KB to
``surface_snapshots.jsonl`` and rewrote ``bughunter_ledger.json``; the full suite added
more again, which is how the second file was found — by this guard, after the first fix.
That is the argument for a guard rather than a one-time cleanup: the pattern recurs, and
each instance looks locally harmless.

The damage is not "a few junk rows". Three separate things break:

* ``hunt_traces.jsonl`` IS the offline brain's distillation corpus — ``hunt_train`` builds
  its training rows straight from it, and the learned ranker it produces is ON by default
  (``settings.offline_ranker_enabled``). A corpus of localhost fixtures trains the probe
  ordering that every real hunt then uses.
* ``negative_knowledge`` immunizes an ``(endpoint, class)`` pair **permanently** once it
  has ever confirmed — there is no TTL on that side (``TTL_DAYS`` only decays misses). A
  fixture-injected confirmation can never age out.
* ``surface_snapshots.jsonl`` feeds surface-drift comparison, so injected snapshots are
  phantom history for hosts that were never hunted.

It also made the learning store unmeasurable: before this fix every one of the 142
``hunt_traces`` rows on this machine carried ``program: '0.1'`` (the key ``learning``
derives for ``127.0.0.1``), i.e. the entire corpus was test output and nothing in it came
from a real hunt.

HOW THIS GUARD WORKS
--------------------
Hashes are captured at MODULE IMPORT. Both runners — pytest collection and
``unittest discover`` — import every test module before executing any test, so the
snapshot is taken before the suite runs and the assertion below is checked after the
polluting file would have run (``b`` sorts before ``r``). A test that escapes into the
real store fails this test, the same control ``hunt-process`` applies to its own append-
only store by hashing it around the run.

It is deliberately NOT a fixture or a conftest: ``npm run check:python`` is
``unittest discover``, which never loads a ``conftest.py``, so a pytest-only guard would
not cover the project's own gate.

A test that legitimately needs the real store's CONTENT may read it. Nothing may write it:
pass a ``tempfile.TemporaryDirectory()`` as ``runtime_dir``, which is what every call site
in ``test_bounty_progress.py`` now does.
"""
from __future__ import annotations

import hashlib
import os
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

#: The real runtime directory, resolved exactly as gn_cli/greyiq_api resolve it so the
#: guard watches the same path the engine would write.
RUNTIME_DIR = Path(os.getenv("GREYIQ_RUNTIME_DIR", BACKEND_DIR.parent / "runtime")).resolve()

#: The append-only / accumulating learning stores. Each is written by a module that takes
#: an explicit ``runtime_dir``, so a test can only touch these by passing the real one.
WATCHED = (
    "hunt_traces.jsonl",           # hunt_trace — the offline brain's training corpus
    "surface_snapshots.jsonl",     # surface_drift — snapshot history
    "bughunter_negative_knowledge.json",  # negative_knowledge — misses + permanent immunity
    "bughunter_ledger.json",       # ledger — submissions and outcomes
    "portfolio.json",              # portfolio — the operator's programs
)


def _fingerprint() -> dict[str, tuple[str, int]]:
    """sha256 + size for each watched store that exists. Absent files are omitted, so a
    fresh checkout with no runtime data simply has nothing to guard."""
    out: dict[str, tuple[str, int]] = {}
    for name in WATCHED:
        path = RUNTIME_DIR / name
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        out[name] = (hashlib.sha256(raw).hexdigest(), len(raw))
    return out


#: Captured at import, i.e. before any test in the suite has run.
_AT_IMPORT = _fingerprint()


class RuntimeStoreIsolationTests(unittest.TestCase):
    def test_the_suite_has_not_written_to_the_live_learning_stores(self) -> None:
        if not _AT_IMPORT:
            self.skipTest(f"no learning stores present under {RUNTIME_DIR}")
        now = _fingerprint()
        damage: list[str] = []
        for name, (digest, size) in _AT_IMPORT.items():
            current = now.get(name)
            if current is None:
                damage.append(f"{name}: DELETED")
            elif current[0] != digest:
                damage.append(f"{name}: {size} -> {current[1]} bytes")
        self.assertEqual(
            damage,
            [],
            "a test wrote to the operator's REAL learning store under "
            f"{RUNTIME_DIR}:\n  " + "\n  ".join(damage) + "\n"
            "Pass a tempfile.TemporaryDirectory() as runtime_dir instead. "
            "hunt_traces.jsonl is the offline ranker's training corpus and a confirmed "
            "negative-knowledge pair is immune permanently, so fixture data written here "
            "changes how real hunts are ordered.",
        )

    def test_the_guard_watches_the_path_the_engine_writes(self) -> None:
        """If the engine's own resolution ever diverges from this guard's, the guard goes
        quietly blind — so pin them together rather than trusting they match."""
        from bughunter import hunt_trace

        self.assertEqual(
            hunt_trace._store_path(RUNTIME_DIR).name,
            "hunt_traces.jsonl",
            "hunt_trace's store filename changed; update WATCHED",
        )
        self.assertIn("hunt_traces.jsonl", WATCHED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
