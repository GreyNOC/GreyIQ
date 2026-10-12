"""Which discovered URLs a direct active hunt actually probes.

``bounty._rank_active_targets`` decides, from the seed URL plus everything recon found, the small set
of endpoints the active pass spends its request budget on. The cap is a spend bound, so the selection
is the whole of the engine's active reach on a direct (non-campaign) hunt: an endpoint that does not
make this list is never probed, silently.

Two of the highest-value checks are ROOT-ONLY by construction. ``_check_sensitive_paths`` (a served
``.git/config`` or ``.env`` — source and live credentials) and ``_check_debug_endpoints``
(``/actuator/heapdump``, Jolokia, ``/.aws/credentials``) both bail unless the URL's path is empty,
because they walk a fixed list once per host rather than once per endpoint. Meanwhile the ranking
scores a bare root LOWEST — no query string, no hot word, and an explicit -1 — so on any target where
recon surfaced ``limit`` parametered URLs the root was evicted and those checks never ran at all.
These tests pin the reserved root slot, and pin that reserving it did not loosen the cap.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty  # noqa: E402


_SEED = "https://t.example/search?q=x"
# Five discovered URLs, every one of which outscores a bare root (each has a query string, worth 6,
# and most carry a hot word) — the exact condition under which the root used to be dropped.
_DISCOVERED = [
    "https://t.example/api/v1/orders?id=1",
    "https://t.example/download?file=a",
    "https://t.example/oauth/callback?redirect=z",
    "https://t.example/graphql?query=x",
    "https://t.example/export?format=csv",
]


def _has_root(urls: list[str]) -> bool:
    return any(not urlparse(u).path.strip("/") for u in urls)


class OriginRootIsAlwaysProbedTests(unittest.TestCase):
    def test_the_root_survives_a_surface_full_of_higher_scoring_urls(self) -> None:
        selected = bounty._rank_active_targets(_SEED, _DISCOVERED, limit=4)
        self.assertTrue(_has_root(selected),
                        f"the origin root was evicted, so .git/.env/heapdump are never probed: {selected}")

    def test_the_root_is_the_real_origin_and_not_invented(self) -> None:
        # Scope safety: the reserved slot must be the SEED's own origin, never another host.
        selected = bounty._rank_active_targets(_SEED, _DISCOVERED, limit=4)
        for url in selected:
            self.assertEqual(urlparse(url).netloc, "t.example")
        self.assertIn("https://t.example/", selected)

    def test_reserving_the_slot_does_not_exceed_the_request_budget(self) -> None:
        # The cap bounds how many hosts' worth of requests the active pass spends. Growing past it to
        # make room would spend budget the caller never authorised.
        for limit in (1, 2, 3, 4, 6, 8):
            with self.subTest(limit=limit):
                selected = bounty._rank_active_targets(_SEED, _DISCOVERED, limit=limit)
                self.assertLessEqual(len(selected), limit)
                self.assertEqual(len(selected), len(set(selected)), "a target would be probed twice")

    def test_a_single_slot_keeps_the_operators_own_url(self) -> None:
        # With room for one target, the URL the operator typed wins: swapping it for the root would
        # mean never probing the thing they actually asked about.
        selected = bounty._rank_active_targets(_SEED, [], limit=1)
        self.assertEqual(len(selected), 1)
        self.assertFalse(_has_root(selected), f"the seed was replaced by the root: {selected}")

    def test_a_root_seed_is_not_duplicated_by_the_reservation(self) -> None:
        # The seed may already BE the root, with or without a trailing slash. Either way it must
        # appear exactly once — a duplicate would re-run the whole fixed path list against one host.
        for seed in ("https://t.example/", "https://t.example"):
            with self.subTest(seed=seed):
                selected = bounty._rank_active_targets(seed, _DISCOVERED, limit=4)
                roots = [u for u in selected if not urlparse(u).path.strip("/")]
                self.assertEqual(len(roots), 1, f"root probed {len(roots)} times: {selected}")

    def test_a_seed_with_no_host_degrades_instead_of_inventing_a_target(self) -> None:
        # A malformed seed must not produce a bare "://" origin, and must not add anything unrelated.
        allowed = set(_DISCOVERED) | {"not a url"}
        selected = bounty._rank_active_targets("not a url", _DISCOVERED, limit=4)
        for url in selected:
            self.assertIn(url, allowed, "an out-of-surface target was invented")

    def test_selection_stays_verbatim_and_deterministic(self) -> None:
        allowed = set(_DISCOVERED) | {_SEED, "https://t.example/"}
        first = bounty._rank_active_targets(_SEED, _DISCOVERED, limit=4)
        self.assertEqual(first, bounty._rank_active_targets(_SEED, _DISCOVERED, limit=4))
        for url in first:
            self.assertIn(url, allowed, "the ranker returned a URL recon never discovered")


class RootOnlyChecksJustifyTheReservationTests(unittest.TestCase):
    """If these checks stop being root-only, the reserved slot is dead weight — say so out loud."""

    def test_the_checks_the_slot_exists_for_still_bail_on_a_pathed_url(self) -> None:
        from bughunter import active_verify_service

        class _NeverFetches:
            """Any request at all is the failure — these checks must return before touching HTTP."""

            def fetch(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN202
                raise AssertionError("the check sent a request for a non-root URL")

        for name in ("_check_sensitive_paths", "_check_debug_endpoints"):
            with self.subTest(check=name):
                check = getattr(active_verify_service, name)
                self.assertIsNone(check(_NeverFetches(), "https://t.example/search?q=x"),
                                  f"{name} is no longer root-only, so the reserved root slot is dead weight")

    def test_the_checks_do_run_at_the_root_the_slot_reserves(self) -> None:
        # The other half: the reservation is only worth a slot if these checks proceed at a bare root.
        # Fail the control fetch so neither goes on to probe — reaching the fetch at all is the proof.
        from bughunter import active_verify_service

        class _RecordsThenBails:
            def __init__(self) -> None:
                self.calls = 0

            def fetch(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN202
                self.calls += 1
                raise active_verify_service._ActiveError("stop here")

        for name in ("_check_sensitive_paths", "_check_debug_endpoints"):
            with self.subTest(check=name):
                http = _RecordsThenBails()
                getattr(active_verify_service, name)(http, "https://t.example/")
                self.assertEqual(http.calls, 1, f"{name} never probed at the root")


if __name__ == "__main__":
    unittest.main()
