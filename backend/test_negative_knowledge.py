"""Negative knowledge (bughunter.negative_knowledge): remember what was probed and did NOT confirm,
so a re-scan's capped budget stops re-testing inert (endpoint, class) ground.

The subsystem must be genuinely useful AND genuinely self-limiting — these tests pin both halves:
it downranks a repeatedly-inert pair, but it never suppresses a route that ever confirmed, never
survives its TTL, is re-enabled the moment surface_drift flags the endpoint, never mutates the plan
it is handed, and turns fully off under the kill switch. The record→cool→suppress cycle is exercised
end to end against the real store on disk."""
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import negative_knowledge as nk  # noqa: E402

_TARGET = "https://app.example.com"


def _plan(*pairs: tuple[str, list[str]]) -> dict:
    return {"probe_priority": [{"endpoint": ep, "classes": list(cls)} for ep, cls in pairs]}


def _outcome(endpoint: str, class_id: str, status: str) -> dict:
    return {"endpoint": endpoint, "class": class_id, "proof_status": status}


def _iso(days_ago: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat()


class EndpointKeyTests(unittest.TestCase):
    def test_numeric_and_uuid_segments_collapse(self) -> None:
        a = nk.endpoint_key("https://app.example.com/api/order/1001/export")
        b = nk.endpoint_key("https://app.example.com/api/order/2999/export")
        self.assertEqual(a, b)
        self.assertEqual(a, "app.example.com/api/order/{id}/export")
        u = nk.endpoint_key("https://app.example.com/u/9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f/profile")
        self.assertEqual(u, "app.example.com/u/{id}/profile")

    def test_query_and_trailing_slash_dropped(self) -> None:
        self.assertEqual(
            nk.endpoint_key("https://app.example.com/search/?q=secret123"),
            "app.example.com/search",
        )

    def test_unparseable_is_empty(self) -> None:
        self.assertEqual(nk.endpoint_key(""), "")
        self.assertEqual(nk.endpoint_key(None), "")


class RecordTests(unittest.TestCase):
    def test_planned_unconfirmed_pair_accrues_misses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for _ in range(2):
                nk.record_hunt(tmp, program=None, target=_TARGET,
                               plan=_plan(("https://app.example.com/login", ["sqli", "xss"])),
                               outcomes=[], complete=True)
            s = nk.summary(tmp, program=None, target=_TARGET)
            self.assertEqual(s["pairs"], 2)
            self.assertEqual(s["cooled"], 2)  # both hit MIN_MISSES=2

    def test_confirmed_pair_is_immunized_and_never_cools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Miss it once, then confirm it — confirmation must clear the miss and immunize forever.
            nk.record_hunt(tmp, program=None, target=_TARGET,
                           plan=_plan(("https://app.example.com/pay", ["idor"])), outcomes=[], complete=True)
            nk.record_hunt(tmp, program=None, target=_TARGET,
                           plan=_plan(("https://app.example.com/pay", ["idor"])),
                           outcomes=[_outcome("https://app.example.com/pay", "idor", "confirmed")],
                           complete=True)
            # Even many later inconclusive runs must not re-cool a proven route.
            for _ in range(3):
                nk.record_hunt(tmp, program=None, target=_TARGET,
                               plan=_plan(("https://app.example.com/pay", ["idor"])), outcomes=[], complete=True)
            self.assertEqual(nk.cooled_pairs(tmp, program=None, target=_TARGET), set())
            self.assertEqual(nk.summary(tmp, program=None, target=_TARGET)["confirmed"], 1)

    def test_single_miss_is_below_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nk.record_hunt(tmp, program=None, target=_TARGET,
                           plan=_plan(("https://app.example.com/x", ["rce"])), outcomes=[], complete=True)
            self.assertEqual(nk.cooled_pairs(tmp, program=None, target=_TARGET), set())

    def test_none_runtime_and_empty_inputs_are_noops(self) -> None:
        self.assertFalse(nk.record_hunt(None, program=None, target=_TARGET, plan=_plan(), outcomes=[]))
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(nk.record_hunt(tmp, program=None, target=_TARGET, plan={}, outcomes=[]))

    def test_incomplete_run_records_no_misses(self) -> None:
        """THE guard against the tail bias: the prover walks probe_priority in order and stops when
        its budget is gone, so a truncated run never probed the tail. Recording those as misses would
        cool exactly the endpoints that never got a fair chance. complete defaults to False."""
        with tempfile.TemporaryDirectory() as tmp:
            for _ in range(5):
                nk.record_hunt(tmp, program=None, target=_TARGET,
                               plan=_plan(("https://app.example.com/deep", ["sqli", "rce"])),
                               outcomes=[])  # complete omitted -> defaults False
            self.assertEqual(nk.cooled_pairs(tmp, program=None, target=_TARGET), set())
            self.assertEqual(nk.summary(tmp, program=None, target=_TARGET)["pairs"], 0)

    def test_incomplete_run_still_grants_confirmation_immunity(self) -> None:
        """A confirmation only ever GRANTS immunity, so it is safe to record from a partial run."""
        with tempfile.TemporaryDirectory() as tmp:
            nk.record_hunt(tmp, program=None, target=_TARGET,
                           plan=_plan(("https://app.example.com/pay", ["idor"])),
                           outcomes=[_outcome("https://app.example.com/pay", "idor", "confirmed")])
            self.assertEqual(nk.summary(tmp, program=None, target=_TARGET)["confirmed"], 1)
            # And that immunity holds against later complete runs that miss it.
            for _ in range(3):
                nk.record_hunt(tmp, program=None, target=_TARGET,
                               plan=_plan(("https://app.example.com/pay", ["idor"])),
                               outcomes=[], complete=True)
            self.assertEqual(nk.cooled_pairs(tmp, program=None, target=_TARGET), set())


class CoolingTests(unittest.TestCase):
    def _seed_cooled(self, tmp: str, days_ago: int = 0) -> None:
        for _ in range(2):
            nk.record_hunt(tmp, program=None, target=_TARGET,
                           plan=_plan(("https://app.example.com/login", ["sqli"])),
                           outcomes=[], complete=True, now=_iso(days_ago))

    def test_cooled_within_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._seed_cooled(tmp, days_ago=1)
            cooled = nk.cooled_pairs(tmp, program=None, target=_TARGET)
            self.assertIn(nk._pair_id("app.example.com/login", "sqli"), cooled)

    def test_decays_past_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._seed_cooled(tmp, days_ago=nk.TTL_DAYS + 5)
            # Old misses earn a fresh look — nothing cooled today.
            self.assertEqual(nk.cooled_pairs(tmp, program=None, target=_TARGET), set())

    def test_kill_switch_disables_recording_and_cooling(self) -> None:
        import os
        with tempfile.TemporaryDirectory() as tmp:
            os.environ[nk._ENV_DISABLE] = "1"
            try:
                self.assertFalse(nk.enabled())
                self.assertFalse(nk.record_hunt(tmp, program=None, target=_TARGET,
                                                plan=_plan(("https://app.example.com/x", ["sqli"])),
                                                outcomes=[], complete=True))
                self.assertEqual(nk.cooled_pairs(tmp, program=None, target=_TARGET), set())
            finally:
                del os.environ[nk._ENV_DISABLE]
            self.assertTrue(nk.enabled())

    def test_malformed_store_fails_soft(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / nk._STORE_NAME).write_text("{ not json", encoding="utf-8")
            self.assertEqual(nk.cooled_pairs(tmp, program=None, target=_TARGET), set())


class ParamLevelTests(unittest.TestCase):
    """Parameter-level negatives come ONLY from a prover that reports what it actually sent.

    The main in-pass prover computes its candidate list locally, returns early on the first hit,
    and skips a parameter whose fetch raised — so re-deriving that list yields an upper bound on
    what was tried, not what was tried. The out-of-band provers are different: each parameter
    carried a unique collaborator token and the poll window closed with no callback, which is a
    real negative observation. Only that reaches this store."""

    EP = "https://app.example.com/fetch"

    def test_a_probed_parameter_cools_after_repetition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for _ in range(2):
                nk.record_param_misses(tmp, program=None, target=_TARGET, endpoint=self.EP,
                                       class_id="ssrf", params=["url", "next"])
            cooled = nk.cooled_params(tmp, program=None, target=_TARGET,
                                      endpoint=self.EP, class_id="ssrf")
            self.assertEqual(cooled, {"url", "next"})

    def test_one_probe_is_below_the_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nk.record_param_misses(tmp, program=None, target=_TARGET, endpoint=self.EP,
                                   class_id="ssrf", params=["url"])
            self.assertEqual(nk.cooled_params(tmp, program=None, target=_TARGET,
                                              endpoint=self.EP, class_id="ssrf"), set())

    def test_params_are_scoped_to_their_class_and_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for _ in range(2):
                nk.record_param_misses(tmp, program=None, target=_TARGET, endpoint=self.EP,
                                       class_id="ssrf", params=["url"])
            # Same parameter name, different class -> not cooled.
            self.assertEqual(nk.cooled_params(tmp, program=None, target=_TARGET,
                                              endpoint=self.EP, class_id="rce"), set())
            # Same parameter and class, different endpoint -> not cooled.
            self.assertEqual(nk.cooled_params(tmp, program=None, target=_TARGET,
                                              endpoint="https://app.example.com/other",
                                              class_id="ssrf"), set())

    def test_param_rows_never_leak_into_the_endpoint_cooled_set(self) -> None:
        """A parameter row carries a third key segment. Returned from cooled_pairs it could never
        match a probe_priority pair, but it would inflate every count built from that set."""
        with tempfile.TemporaryDirectory() as tmp:
            for _ in range(2):
                nk.record_param_misses(tmp, program=None, target=_TARGET, endpoint=self.EP,
                                       class_id="ssrf", params=["url", "next", "dest"])
            self.assertEqual(nk.cooled_pairs(tmp, program=None, target=_TARGET), set())

    def test_a_confirming_parameter_clears_its_cooled_state(self) -> None:
        """Without this the parameter half had the immunity hole the endpoint half was fixed for
        twice: a sink could carry two earlier misses, then prove a bug, and still be ordered behind
        untried names for the whole TTL."""
        with tempfile.TemporaryDirectory() as tmp:
            for _ in range(2):
                nk.record_param_misses(tmp, program=None, target=_TARGET, endpoint=self.EP,
                                       class_id="ssrf", params=["url"])
            self.assertEqual(nk.cooled_params(tmp, program=None, target=_TARGET,
                                              endpoint=self.EP, class_id="ssrf"), {"url"})
            nk.record_param_confirmation(tmp, program=None, target=_TARGET, endpoint=self.EP,
                                         class_id="ssrf", param="url")
            self.assertEqual(nk.cooled_params(tmp, program=None, target=_TARGET,
                                              endpoint=self.EP, class_id="ssrf"), set())
            # And it stays immune through later inconclusive runs.
            for _ in range(3):
                nk.record_param_misses(tmp, program=None, target=_TARGET, endpoint=self.EP,
                                       class_id="ssrf", params=["url"])
            self.assertEqual(nk.cooled_params(tmp, program=None, target=_TARGET,
                                              endpoint=self.EP, class_id="ssrf"), set())

    def test_deprioritise_reaches_url_local_params_before_the_cap(self) -> None:
        """The caller cannot get this right by reordering its own extra list: names parsed from the
        target URL are merged AHEAD of it, so on an already-parametered target two cooled URL-local
        names consume the entire per-check cap and a fresh name is never probed."""
        from bughunter.active_verify_service import _candidate_params

        url = "https://app.example.com/?old1=x&old2=x"
        self.assertEqual(_candidate_params(url, ["fresh"], ("cmd",), 2), ["old1", "old2"])
        capped = _candidate_params(url, ["fresh"], ("cmd",), 2, deprioritise={"old1", "old2"})
        self.assertEqual(capped[0], "fresh")
        # Reorder, never remove — the full set survives when the cap allows it.
        full = _candidate_params(url, ["fresh"], ("cmd",), 9, deprioritise={"old1", "old2"})
        self.assertEqual(full, ["fresh", "old1", "old2"])

    def test_prioritise_untried_reorders_and_never_drops(self) -> None:
        """Dropping would risk blinding a re-scan; the provers cap their walk, so order alone
        decides what gets a token."""
        params = ["url", "image", "next", "callback"]
        out = nk.prioritise_untried(params, {"url", "next"})
        self.assertEqual(sorted(out), sorted(params), "a parameter was dropped")
        self.assertEqual(out, ["image", "callback", "url", "next"])
        self.assertEqual(nk.prioritise_untried(params, set()), params)

    def test_empty_and_disabled_paths_are_noops(self) -> None:
        import os
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(nk.record_param_misses(tmp, program=None, target=_TARGET,
                                                    endpoint=self.EP, class_id="ssrf", params=[]), 0)
            self.assertEqual(nk.record_param_misses(None, program=None, target=_TARGET,
                                                    endpoint=self.EP, class_id="ssrf", params=["url"]), 0)
            os.environ[nk._ENV_DISABLE] = "1"
            try:
                self.assertEqual(nk.record_param_misses(tmp, program=None, target=_TARGET,
                                                        endpoint=self.EP, class_id="ssrf",
                                                        params=["url"]), 0)
                self.assertEqual(nk.cooled_params(tmp, program=None, target=_TARGET,
                                                  endpoint=self.EP, class_id="ssrf"), set())
            finally:
                del os.environ[nk._ENV_DISABLE]


class SuppressionTests(unittest.TestCase):
    def test_cold_classes_are_downranked_within_an_endpoint(self) -> None:
        cooled = {nk._pair_id("app.example.com/login", "sqli")}
        plan = _plan(("https://app.example.com/login", ["sqli", "xss", "redirect"]))
        out, stats = nk.apply_suppression(plan, cooled)
        self.assertEqual(out["probe_priority"][0]["classes"], ["xss", "redirect", "sqli"])
        self.assertEqual(stats["downranked"], 1)
        self.assertEqual(stats["fully_cooled"], 0)

    def test_all_cold_endpoint_is_kept_but_fully_cooled(self) -> None:
        """Rows are reordered, NEVER removed. Dropping looked like it freed a probe slot, but the
        caller does not work from this list — active_targets is fixed before suppression and the only
        consumer falls back to an INFERRED priority for an endpoint it cannot find. Dropping saved no
        requests and replaced an evidence-based ordering with a guess."""
        cooled = {nk._pair_id("app.example.com/login", "sqli"),
                  nk._pair_id("app.example.com/login", "xss")}
        plan = _plan(("https://app.example.com/login", ["sqli", "xss"]),
                     ("https://app.example.com/search", ["xss"]))
        out, stats = nk.apply_suppression(plan, cooled)
        eps = [r["endpoint"] for r in out["probe_priority"]]
        self.assertEqual(eps, ["https://app.example.com/login", "https://app.example.com/search"])
        self.assertEqual(stats["fully_cooled"], 1)
        self.assertEqual(stats["downranked"], 2)

    def test_changed_endpoint_is_re_enabled(self) -> None:
        cooled = {nk._pair_id("app.example.com/login", "sqli")}
        plan = _plan(("https://app.example.com/login", ["sqli", "xss"]))
        out, stats = nk.apply_suppression(plan, cooled, changed_endpoints={"app.example.com/login"})
        self.assertEqual(out["probe_priority"][0]["classes"], ["sqli", "xss"])  # untouched
        self.assertEqual(stats, {"downranked": 0, "fully_cooled": 0})

    def test_input_plan_is_never_mutated_and_other_fields_survive(self) -> None:
        cooled = {nk._pair_id("app.example.com/login", "sqli")}
        plan = {"probe_priority": [{"endpoint": "https://app.example.com/login", "classes": ["sqli", "xss"]}],
                "param_hypotheses": ["returnUrl"], "notes": "keep me", "used": True}
        original = [dict(r) for r in plan["probe_priority"]]
        out, _ = nk.apply_suppression(plan, cooled)
        self.assertEqual(plan["probe_priority"], original)          # input untouched
        self.assertIsNot(out["probe_priority"], plan["probe_priority"])
        self.assertEqual(out["param_hypotheses"], ["returnUrl"])    # carried through
        self.assertEqual(out["notes"], "keep me")
        self.assertTrue(out["used"])

    def test_empty_cooled_returns_owned_copy_unchanged(self) -> None:
        plan = _plan(("https://app.example.com/login", ["sqli"]))
        out, stats = nk.apply_suppression(plan, set())
        self.assertEqual(out["probe_priority"], plan["probe_priority"])
        self.assertEqual(stats, {"downranked": 0, "fully_cooled": 0})


class DriftBridgeTests(unittest.TestCase):
    def test_changed_endpoint_keys_reads_the_relevant_delta_kinds(self) -> None:
        drift = {"deltas": [
            {"kind": "shape.changed", "subject": "https://app.example.com/login?x=1"},
            {"kind": "endpoint.new", "subject": "https://app.example.com/api/v2/orders/5"},
            {"kind": "param.new", "subject": "some_param"},          # not an endpoint kind
        ]}
        keys = nk.changed_endpoint_keys(drift)
        self.assertIn("app.example.com/login", keys)
        self.assertIn("app.example.com/api/v2/orders/{id}", keys)
        self.assertEqual(len(keys), 2)

    def test_defenses_coming_off_also_re_enable(self) -> None:
        """auth.removed is surface_drift's highest-weighted signal ("a gate came off"). A route that
        was inert WHILE PROTECTED is the first thing to re-probe once the protection is gone, so
        these kinds must lift a cooled pair exactly like a new endpoint does."""
        drift = {"deltas": [
            {"kind": "auth.removed", "subject": "https://app.example.com/admin"},
            {"kind": "cookie.flag-lost", "subject": "https://app.example.com/session"},
            {"kind": "header.security-removed", "subject": "https://app.example.com/app"},
        ]}
        keys = nk.changed_endpoint_keys(drift)
        self.assertEqual(keys, {"app.example.com/admin", "app.example.com/session", "app.example.com/app"})

    def test_collapsed_site_wide_delta_re_enables_everything(self) -> None:
        """surface_drift._collapse folds a site-wide control loss into ONE delta whose subject is
        prose ("3 endpoint(s)"), not a URL. Keying that as an endpoint produced an unmatched string
        and re-enabled nothing — in exactly the case with the strongest reason to re-probe."""
        drift = {"deltas": [{"kind": "header.security-removed", "subject": "3 endpoint(s)"}]}
        self.assertEqual(nk.changed_endpoint_keys(drift), {nk.ALL_ENDPOINTS})

    def test_site_wide_change_suppresses_nothing(self) -> None:
        cooled = {nk._pair_id("app.example.com/login", "sqli"),
                  nk._pair_id("app.example.com/login", "xss")}
        plan = _plan(("https://app.example.com/login", ["sqli", "xss"]))
        out, stats = nk.apply_suppression(plan, cooled, changed_endpoints={nk.ALL_ENDPOINTS})
        self.assertEqual(out["probe_priority"][0]["classes"], ["sqli", "xss"])  # untouched
        self.assertEqual(stats, {"downranked": 0, "fully_cooled": 0})

    def test_url_subjects_still_resolve_to_one_endpoint(self) -> None:
        # The wildcard must not swallow the normal per-endpoint path.
        drift = {"deltas": [{"kind": "auth.removed", "subject": "https://app.example.com/admin"}]}
        self.assertEqual(nk.changed_endpoint_keys(drift), {"app.example.com/admin"})

    def test_none_drift_is_empty(self) -> None:
        self.assertEqual(nk.changed_endpoint_keys(None), set())
        self.assertEqual(nk.changed_endpoint_keys({}), set())


class EndToEndTests(unittest.TestCase):
    def test_record_then_cool_then_suppress_a_fresh_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            probe = ("https://app.example.com/download", ["path-traversal", "rce"])
            # Two inert hunts probe /download for path-traversal + rce, nothing confirms.
            for _ in range(2):
                nk.record_hunt(tmp, program=None, target=_TARGET, plan=_plan(probe), outcomes=[], complete=True)
            cooled = nk.cooled_pairs(tmp, program=None, target=_TARGET)
            self.assertEqual(len(cooled), 2)
            # A third hunt plans the same endpoint plus a brand-new one; suppression frees the inert slot.
            fresh = _plan(probe, ("https://app.example.com/invoice", ["ssti"]))
            out, stats = nk.apply_suppression(fresh, cooled)
            eps = [r["endpoint"] for r in out["probe_priority"]]
            self.assertEqual(eps, ["https://app.example.com/download", "https://app.example.com/invoice"])
            self.assertEqual(stats["fully_cooled"], 1)
            self.assertEqual(stats["downranked"], 2)

    def test_confirmed_route_keeps_being_hunted_across_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            probe = ("https://app.example.com/pay", ["idor", "xss"])
            # idor confirmed; xss never does.
            nk.record_hunt(tmp, program=None, target=_TARGET, plan=_plan(probe), complete=True,
                           outcomes=[_outcome("https://app.example.com/pay", "idor", "confirmed")])
            for _ in range(2):
                nk.record_hunt(tmp, program=None, target=_TARGET, plan=_plan(probe), outcomes=[], complete=True)
            cooled = nk.cooled_pairs(tmp, program=None, target=_TARGET)
            # xss cooled, idor immune.
            self.assertIn(nk._pair_id("app.example.com/pay", "xss"), cooled)
            self.assertNotIn(nk._pair_id("app.example.com/pay", "idor"), cooled)
            out, _ = nk.apply_suppression(_plan(probe), cooled)
            self.assertEqual(out["probe_priority"][0]["classes"], ["idor", "xss"])  # idor stays first, endpoint kept


class VocabularyFoldTests(unittest.TestCase):
    """A plan speaks CHECK TAGS; an outcome speaks the IMPACT the finding carries. Five checks
    report an impact under a different name than their tag, so without a fold the two halves of a
    pair id could never meet — and the store cooled the exact checks that had proven bugs."""

    # (check tag the plan carries, impact class the finding reports)
    DIVERGENT = (("crlf", "redirect"), ("host-header", "redirect"),
                 ("clickjacking", "headers"), ("sensitive", "disclosure"), ("debug", "rce"))

    def test_a_confirmed_impact_immunises_the_tag_that_produced_it(self) -> None:
        for tag, impact in self.DIVERGENT:
            with self.subTest(tag=tag):
                with tempfile.TemporaryDirectory() as tmp:
                    probe = ("https://app.example.com/download", [tag])
                    # Two clean runs that CONFIRM the bug. The check reports its impact class.
                    for _ in range(2):
                        nk.record_hunt(tmp, program=None, target=_TARGET, plan=_plan(probe),
                                       complete=True,
                                       outcomes=[_outcome("https://app.example.com/download",
                                                          impact, "confirmed")])
                    cooled = nk.cooled_pairs(tmp, program=None, target=_TARGET)
                    self.assertNotIn(
                        nk._pair_id("app.example.com/download", tag), cooled,
                        f"{tag!r} confirmed as {impact!r} twice and was still cooled")

    def test_an_unrelated_class_on_the_same_route_still_cools(self) -> None:
        """The fold must not become blanket route-level immunity — a class that really is inert
        on a productive route is still what the capped probe budget should skip."""
        with tempfile.TemporaryDirectory() as tmp:
            probe = ("https://app.example.com/download", ["crlf", "xss"])
            for _ in range(2):
                nk.record_hunt(tmp, program=None, target=_TARGET, plan=_plan(probe), complete=True,
                               outcomes=[_outcome("https://app.example.com/download",
                                                  "redirect", "confirmed")])
            cooled = nk.cooled_pairs(tmp, program=None, target=_TARGET)
            self.assertIn(nk._pair_id("app.example.com/download", "xss"), cooled)
            self.assertNotIn(nk._pair_id("app.example.com/download", "crlf"), cooled)


if __name__ == "__main__":
    unittest.main()
