"""Offline hunt intelligence — the no-LLM hunt brain. Knowledge rules over the recon surface produce
targeted param/class/idor guidance, sharpened by what the program has confirmed before (learned
priors), and it steers an offline hunt that previously flew blind. Safe: names/verbatim-endpoints only."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hunt_brain, offline_hunt  # noqa: E402
from bughunter.prover_classes import PROVER_CLASSES  # noqa: E402

_SURFACE = {"endpoints": ["https://t/search?q=x", "https://t/order/1042", "https://t/download?file=a.pdf",
                          "https://t/api/me", "https://t/redirect?url=x", "https://t/users/9f8e7d6c-1234-4321-8888-abcdef012345",
                          "https://t/admin/users", "https://t/settings/roles"],
            "params": ["q", "file"], "tech": ["Flask", "Jinja"]}


class OfflinePlanTests(unittest.TestCase):
    def test_targets_ssrf_xss_and_idor_surface(self) -> None:
        p = offline_hunt.offline_plan(_SURFACE)
        self.assertIn("url", p["ssrf_params"])                      # redirect?url= is SSRF surface
        self.assertIn("q", p["xss_params"])                        # search q= reflects
        self.assertIn("https://t/order/1042", p["idor_candidates"])  # numeric-id object endpoint
        self.assertIn("https://t/users/9f8e7d6c-1234-4321-8888-abcdef012345", p["idor_candidates"])  # uuid too

    def test_admin_path_endpoints_recon_feed_is_verbatim_and_bounded(self) -> None:
        urls = ["https://t/admin/users", "https://t/api/orders/42", "https://t/settings/roles",
                "https://t/internal/config", "https://t/home", "https://t/manage/billing"]
        got = offline_hunt.admin_path_endpoints(urls)
        self.assertIn("https://t/admin/users", got)          # /admin
        self.assertIn("https://t/settings/roles", got)       # /settings + /role
        self.assertIn("https://t/internal/config", got)      # /internal + /config
        self.assertIn("https://t/manage/billing", got)       # /manage + /billing
        self.assertNotIn("https://t/api/orders/42", got)     # an object endpoint is IDOR, not a privileged FUNCTION
        self.assertNotIn("https://t/home", got)              # a plain page is not privileged
        for u in got:
            self.assertIn(u, set(urls))                      # verbatim in-scope only, never invented
        self.assertLessEqual(len(offline_hunt.admin_path_endpoints(["https://t/admin/%d" % i for i in range(40)])), 8)

    def test_flags_admin_privileged_endpoints_for_bfla(self) -> None:
        p = offline_hunt.offline_plan(_SURFACE)
        self.assertIn("https://t/admin/users", p["privileged_endpoints"])   # /admin function
        self.assertIn("https://t/settings/roles", p["privileged_endpoints"])  # /settings + /role
        # object endpoints are NOT privileged-function candidates (that's IDOR, not BFLA)
        self.assertNotIn("https://t/order/1042", p["privileged_endpoints"])
        for ep in p["privileged_endpoints"]:
            self.assertIn(ep, set(_SURFACE["endpoints"]))                    # verbatim in-scope only

    def test_probe_priority_endpoints_are_verbatim_in_scope(self) -> None:
        p = offline_hunt.offline_plan(_SURFACE)
        allowed = set(_SURFACE["endpoints"])
        for row in p["probe_priority"]:
            self.assertIn(row["endpoint"], allowed)                # never invents a URL

    def test_learned_priors_reorder_classes(self) -> None:
        # the LEARNING signal: a class the program has rewarded is tried first.
        # Boost a class that /search?q= genuinely admits (its own q= is a sink for both xss and sqli)
        # rather than one it does not, because priors REORDER candidates — they cannot conjure one.
        base = offline_hunt.offline_plan(_SURFACE)
        search = next(r for r in base["probe_priority"] if "search" in r["endpoint"])
        self.assertEqual(search["classes"][:2], ["xss", "sqli"])     # untouched order
        boosted = offline_hunt.offline_plan(_SURFACE, priors={"sqli": 5.0})
        search2 = next(r for r in boosted["probe_priority"] if "search" in r["endpoint"])
        self.assertEqual(search2["classes"][0], "sqli")              # boosted to the front

    def test_class_cues_come_from_the_endpoints_own_params_not_the_whole_host(self) -> None:
        """A param seen elsewhere on the host must not re-class an endpoint that does not take it.

        offline_plan used to pass `names + sorted(recon_params)` — every endpoint got cues from the
        WHOLE host's param list, so the per-endpoint ranking said the same thing about all of them.
        Because _classes_for_endpoint caps the set and appends newly-reachable classes last, the
        shared params saturated the cap and truncated the endpoint's own classes away, and with every
        score then equal the priority cap broke ties by discovery order — evicting high-signal
        endpoints in favour of whatever happened to be crawled first.
        """
        plan = offline_hunt.offline_plan(_SURFACE)
        by_endpoint = {row["endpoint"]: row["classes"] for row in plan["probe_priority"]}

        # `file` belongs to /download; it must not make /search a path-traversal target...
        self.assertNotIn("path-traversal", by_endpoint["https://t/search?q=x"])
        # ...nor `q` make /download an xss/sqli one...
        for leaked in ("xss", "sqli"):
            self.assertNotIn(leaked, by_endpoint["https://t/download?file=a.pdf"])
        # ...while each endpoint still leads with the class its OWN input justifies.
        self.assertEqual(by_endpoint["https://t/download?file=a.pdf"][0], "path-traversal")
        self.assertEqual(by_endpoint["https://t/search?q=x"][0], "xss")
        self.assertEqual(by_endpoint["https://t/redirect?url=x"][0], "redirect")

        # The consequence that matters: distinct endpoints get distinct guidance. Host-wide cues
        # collapsed a whole surface onto a couple of identical class-sets.
        distinct = {tuple(classes) for classes in by_endpoint.values()}
        self.assertGreaterEqual(len(distinct), 5, f"per-endpoint ranking collapsed: {distinct}")

        # Scoping the CUES must not narrow COVERAGE. The host-wide recon params reach the prover as
        # extra_params, which _candidate_params unions into every param-keyed check on every
        # endpoint, so `file` is still tried on /search — it just no longer re-classes it. Pin that
        # union here, because it is the reason this scoping is safe.
        from bughunter.active_verify_service import _candidate_params  # noqa: PLC0415

        tried = _candidate_params("https://t/search?q=x", sorted(_SURFACE["params"]), (), 4)
        self.assertEqual([n.lower() for n in tried[:1]], ["q"])   # its own param leads
        self.assertIn("file", [n.lower() for n in tried])         # the host-wide name is still tried

        # param_hypotheses, by contrast, deliberately omits already-discovered names: they are
        # already in extra_params, so proposing them again would only burn the hypothesis cap.
        self.assertNotIn("file", plan["param_hypotheses"])

    def test_form_fields_of_the_endpoints_own_form_do_count_as_its_cues(self) -> None:
        # The flip side of scoping: a POST target's cues live in its form, not its query string.
        surface = {
            "endpoints": ["https://t/upload", "https://t/about"],
            "params": [],
            "tech": [],
            "forms": [{"action": "https://t/upload", "method": "post", "params": ["filename", "template"]}],
        }
        plan = offline_hunt.offline_plan(surface)
        by_endpoint = {row["endpoint"]: row["classes"] for row in plan["probe_priority"]}
        self.assertIn("path-traversal", by_endpoint["https://t/upload"])   # from the form's filename
        self.assertNotIn("path-traversal", by_endpoint.get("https://t/about", []))

    def test_noisy_prior_falls_below_unseen_neutral_classes(self) -> None:
        # learned_priors are multipliers around neutral=1.0. A known-noisy 0.5
        # class must be deprioritized below unseen classes, not accidentally
        # promoted because unseen was treated as zero.
        endpoint = "https://t.example/search?q=x"
        plan = offline_hunt.offline_plan(
            {"endpoints": [endpoint], "params": [], "tech": []},
            priors={"xss": 0.5},
        )
        classes = plan["probe_priority"][0]["classes"]
        self.assertLess(classes.index("sqli"), classes.index("xss"))

    def test_cold_start_plan_order_is_explicit_and_deterministic(self) -> None:
        surface = {"endpoints": ["https://t.example/thing"], "params": [], "tech": ["PHP", "WordPress"]}
        first = offline_hunt.offline_plan(surface)
        second = offline_hunt.offline_plan(surface)
        self.assertEqual(first, second)
        self.assertEqual(first["param_hypotheses"][:4], ["url", "redirect", "next", "callback"])
        self.assertEqual(first["probe_priority"][0]["classes"][:3], ["rce", "sqli", "xss"])

    def test_tech_stack_boosts_ssti(self) -> None:
        p = offline_hunt.offline_plan(_SURFACE)                     # Flask/Jinja -> ssti in the surface
        self.assertTrue(any("ssti" in r["classes"] for r in p["probe_priority"]))

    def test_empty_surface_is_a_clean_empty_plan(self) -> None:
        p = offline_hunt.offline_plan({"endpoints": [], "params": [], "tech": []})
        self.assertFalse(p["used"])
        self.assertEqual(p["probe_priority"], [])

    def test_names_only_never_a_payload(self) -> None:
        p = offline_hunt.offline_plan(_SURFACE)
        for n in p["ssrf_params"] + p["xss_params"] + p["param_hypotheses"]:
            self.assertNotIn(" ", n)
            self.assertNotIn("<", n)
            self.assertNotIn("/", n)


class ProverVocabularyTests(unittest.TestCase):
    """The offline brain's class vocabulary is now DERIVED from the prover's own check tags rather
    than hand-listed, closing the recall hole where 8 provable classes were unreachable offline."""

    def test_offline_classes_are_a_subset_of_what_the_prover_can_confirm(self) -> None:
        # The invariant that makes a wider vocabulary safe: the brain can never propose a class the
        # deterministic prover has no check for, so a suggestion is always actionable-or-ignored.
        self.assertLessEqual(set(offline_hunt._ACTIVE_CLASSES), set(PROVER_CLASSES))

    def test_the_eight_previously_unreachable_classes_are_now_proposable(self) -> None:
        # Before this change _ACTIVE_CLASSES held 10 names and these were silently undroppable-
        # because-unproposable. Pin them so a future narrowing of the set fails loudly.
        for cls in ("jwt", "graphql", "debug", "websocket", "sensitive", "cloud-exposure",
                    "csrf", "clickjacking"):
            self.assertIn(cls, offline_hunt._ACTIVE_CLASSES)


class NewCueCoverageTests(unittest.TestCase):
    """The cue block appended LAST in _classes_for_endpoint. It may only ADD classes to endpoints
    that had spare room in the 6-class cap; it must never displace a pre-existing class."""

    def _classes(self, endpoint: str, **surface) -> list[str]:
        plan = offline_hunt.offline_plan({"endpoints": [endpoint], "params": [], "tech": [], **surface})
        self.assertTrue(plan["probe_priority"], f"{endpoint} produced no classes at all")
        self.assertEqual(plan["probe_priority"][0]["endpoint"], endpoint)
        return plan["probe_priority"][0]["classes"]

    def test_graphql_path_proposes_the_graphql_check(self) -> None:
        classes = self._classes("https://t.example/graphql")
        self.assertIn("graphql", classes)
        self.assertEqual(classes[0], "cors")   # the pre-existing /api cue still owns slot 0

    def test_actuator_path_proposes_the_debug_check(self) -> None:
        self.assertIn("debug", self._classes("https://t.example/actuator/env"))
        self.assertIn("debug", self._classes("https://t.example/admin/jolokia/list"))

    def test_websocket_path_proposes_the_cswsh_check(self) -> None:
        self.assertIn("websocket", self._classes("https://t.example/ws/chat"))
        self.assertIn("websocket", self._classes("https://t.example/socket.io/"))

    def test_token_param_and_auth_path_propose_the_jwt_checks(self) -> None:
        self.assertIn("jwt", self._classes("https://t.example/v1/me?access_token=abc"))
        self.assertIn("jwt", self._classes("https://t.example/oauth/authorize"))

    def test_exposed_file_upload_and_state_change_cues(self) -> None:
        self.assertIn("sensitive", self._classes("https://t.example/.git/config"))
        self.assertIn("cloud-exposure", self._classes("https://t.example/upload"))
        self.assertIn("csrf", self._classes("https://t.example/account/delete"))

    def test_new_cues_never_displace_a_pre_existing_class(self) -> None:
        # A saturated endpoint (6 classes from the OLD cues alone) must be byte-identical: the new
        # adds land past the classes[:6] cap. This is what keeps the cold-start training corpus valid.
        saturated = "https://t.example/api/search?q=x&file=y&template=z&cmd=w&id=1"
        self.assertEqual(self._classes(saturated, tech=["Flask"]),
                         ["xss", "sqli", "cors", "path-traversal", "ssti", "rce"])

    def test_class_count_is_still_hard_capped_at_six(self) -> None:
        # every new cue fires at once + the old cues + a tech boost -> still 6, never more
        greedy = "https://t.example/graphql/actuator/ws/oauth/.git/upload/account?file=a&q=b&cmd=c&token=d"
        self.assertEqual(len(self._classes(greedy, tech=["Flask", "PHP"])), 6)


class ColdStartBaselineTests(unittest.TestCase):
    """Plans are persisted verbatim as training traces, so their exact values are the contract --
    NOT a subset check. These pin the byte-level baseline the corpus is keyed to."""

    def test_cold_start_plan_order_v2_is_explicit_and_deterministic(self) -> None:
        # Two intended behaviour changes, recorded explicitly so each is a reviewed decision rather
        # than silent corpus drift:
        #   1. an endpoint that previously produced ZERO classes was omitted from probe_priority
        #      entirely; /actuator/env matched no old cue and was absent, and now appears;
        #   2. probe_priority is now ordered STRONGEST-SIGNAL-FIRST (_priority_sort_key) instead of
        #      by discovery order, because the list is hard-capped and the prover walks it in order.
        #      /search?q=x leads on sqli(92); /actuator/env follows on debug(78); /graphql last on
        #      cors(40)+graphql(60) -> max 60.
        surface = {"endpoints": ["https://t.example/actuator/env", "https://t.example/graphql",
                                 "https://t.example/search?q=x"], "params": [], "tech": []}
        first = offline_hunt.offline_plan(surface)
        self.assertEqual(first, offline_hunt.offline_plan(surface))   # still deterministic
        self.assertEqual(first["probe_priority"], [
            {"endpoint": "https://t.example/search?q=x", "classes": ["xss", "sqli"]},
            {"endpoint": "https://t.example/actuator/env", "classes": ["debug"]},
            {"endpoint": "https://t.example/graphql", "classes": ["cors", "graphql"]},
        ])
        # param_hypotheses are cue-independent and must be UNCHANGED by this workstream
        self.assertEqual(first["param_hypotheses"][:4], ["url", "redirect", "next", "callback"])
        self.assertEqual(first["notes"], "offline knowledge-rule plan over 3 endpoint(s)")

    def test_model_none_is_byte_identical_to_the_rules_only_plan(self) -> None:
        # model=None is the default and MUST mean "exactly today's behaviour".
        self.assertEqual(offline_hunt.offline_plan(_SURFACE), offline_hunt.offline_plan(_SURFACE, model=None))


class PriorityCapRankingTests(unittest.TestCase):
    """probe_priority is HARD-CAPPED and the prover walks it in order, so the cap is a zero-sum
    contest between endpoints. Widening the class vocabulary made endpoints that used to produce ZERO
    classes eligible, and in discovery order a run of low-signal ones evicted already-planned
    high-signal ones off the end of the cap. ADDED RECALL MUST NEVER COST EXISTING RECALL."""

    # The reviewed failure surface: ten /ws/* rooms (the widened vocabulary's `websocket` cue is the
    # ONLY class they score) discovered BEFORE fifteen /download?file= path-traversal candidates.
    _WS = [f"https://t/ws/chan{i}" for i in range(10)]
    _DOWNLOADS = [f"https://t/download{i}?file=a" for i in range(15)]

    @staticmethod
    def _endpoints(surface: dict) -> list[str]:
        return [r["endpoint"] for r in offline_hunt.offline_plan(surface)["probe_priority"]]

    def test_low_signal_endpoints_never_evict_an_already_planned_endpoint(self) -> None:
        # The regression itself: planning the SAME high-signal endpoints alongside newly-eligible
        # low-signal ones must not drop any of them. Before the fix the ten websocket-only rooms took
        # the first ten slots and download10..download14 fell off the 20-row cap.
        before = self._endpoints({"endpoints": self._DOWNLOADS})
        after = self._endpoints({"endpoints": self._WS + self._DOWNLOADS})
        self.assertEqual(len(before), 15)
        self.assertEqual([e for e in before if e not in after], [], "an already-planned endpoint was evicted")
        self.assertEqual(after[:15], before)          # and they still lead the plan, in order

    def test_the_cap_keeps_the_highest_signal_endpoints(self) -> None:
        after = self._endpoints({"endpoints": self._WS + self._DOWNLOADS})
        self.assertEqual(len(after), offline_hunt._MAX_PRIORITY)
        # what survives past the 15 traversal candidates is the strongest 5 of the websocket rooms,
        # in discovery order — the cap truncates the WEAKEST tail, not an arbitrary one.
        self.assertEqual(after[15:], self._WS[:5])

    def test_ordering_is_non_increasing_in_signal_and_total(self) -> None:
        plan = offline_hunt.offline_plan({"endpoints": self._WS + self._DOWNLOADS})
        keys = [offline_hunt._priority_sort_key(r, i) for i, r in enumerate(plan["probe_priority"])]
        self.assertEqual(keys, sorted(keys, key=lambda k: k[:2]))   # strongest first
        # total + stable: the same surface must produce a byte-identical plan (persisted as a trace)
        self.assertEqual(plan, offline_hunt.offline_plan({"endpoints": self._WS + self._DOWNLOADS}))

    def test_endpoint_selection_is_not_reachable_by_priors_or_a_ranker(self) -> None:
        # The sort key is permutation-invariant in a row's class list, so the two seams that may
        # reorder classes WITHIN an endpoint cannot decide WHICH endpoints survive the cap.
        surface = {"endpoints": self._WS + self._DOWNLOADS, "params": [], "tech": []}
        rules = [r["endpoint"] for r in offline_hunt.offline_plan(surface)["probe_priority"]]
        with_priors = [r["endpoint"] for r in
                       offline_hunt.offline_plan(surface, {"websocket": 9.0, "path-traversal": 0.1})["probe_priority"]]
        with_model = [r["endpoint"] for r in
                      offline_hunt.offline_plan(surface, model=_StubRanker())["probe_priority"]]
        self.assertEqual(with_priors, rules)
        self.assertEqual(with_model, rules)

    def test_the_signal_table_covers_every_provable_class(self) -> None:
        # Drift guard: a class the prover learns to confirm must be weighted deliberately, not left
        # to inherit the neutral default by accident.
        self.assertEqual(set(offline_hunt._CLASS_SIGNAL), set(PROVER_CLASSES))
        self.assertTrue(all(isinstance(v, int) for v in offline_hunt._CLASS_SIGNAL.values()))


class _StubRanker:
    """A learned ranker stand-in. Records its inputs so the narrow call contract can be asserted."""

    version_tag = "stub-v1"

    def __init__(self, reply=None, boom: bool = False) -> None:
        self.reply, self.boom, self.calls = reply, boom, []
        self.forms: list = []

    def rank_endpoint_classes(self, url, names, recon, tech, candidates, priors, *, form=None):
        self.calls.append((url, list(names), list(recon), tech, list(candidates), priors))
        self.forms.append(form)
        if self.boom:
            raise RuntimeError("corrupt weights")
        return self.reply if self.reply is not None else list(reversed(candidates))


class _LearningRanker(_StubRanker):
    """A ranker that also answers the two heads the trainer learns but nothing used to serve."""

    def __init__(self, params=None, selects=(), boom_params: bool = False) -> None:
        super().__init__()
        self.params = list(params or [])
        self.selects = set(selects)
        self.boom_params = boom_params
        self.seen_kinds: list[str] = []

    def rank_endpoint_classes(self, url, names, recon, tech, candidates, priors, *, form=None):
        return list(candidates)          # identity: keep these tests about the other two seams

    def suggest_params_for_endpoint(self, url, tech, cap):
        if self.boom_params:
            raise RuntimeError("corrupt weights")
        return self.params[:cap]

    def selects_endpoint(self, kind, url, names, recon, tech, form=None):
        self.seen_kinds.append(kind)
        return kind in self.selects


class LearnedParamAndSelectorSeamTests(unittest.TestCase):
    """``gn train-brain`` learns three things and promotes them all into hunt_ranker.json, but only
    the class ranker was ever served — the learned parameter table and the idor/privileged selectors
    had no hunt-time caller at all, so what the engine learned from its own confirmed hunts never
    reached the next one. Both are additive: they may only ADD, never remove or replace."""

    SURFACE = {"endpoints": ["https://t.example/download?file=x"], "params": [], "tech": ["PHP"]}

    def _plan(self, model=None, surface=None):
        return offline_hunt.offline_plan(surface or self.SURFACE, None, model=model)

    def test_learned_names_lead_and_the_curated_list_still_follows(self) -> None:
        names = self._plan(_LearningRanker(params=["filepath", "attachment"]))["param_hypotheses"]
        self.assertEqual(names[:2], ["filepath", "attachment"])
        for curated in offline_hunt._SUGGEST:
            self.assertIn(curated, names, "the curated list must survive, so recall cannot drop")

    def test_no_learned_opinion_is_byte_identical_to_no_model(self) -> None:
        self.assertEqual(self._plan(_LearningRanker(params=[]))["param_hypotheses"],
                         self._plan(None)["param_hypotheses"])

    def test_a_raising_param_head_falls_back_to_the_curated_list(self) -> None:
        self.assertEqual(self._plan(_LearningRanker(boom_params=True))["param_hypotheses"],
                         self._plan(None)["param_hypotheses"])

    def test_a_ranker_without_the_new_heads_still_works(self) -> None:
        """A weight file (or stub) from before these heads existed must degrade, not explode."""
        self.assertEqual(self._plan(_StubRanker())["param_hypotheses"],
                         self._plan(None)["param_hypotheses"])

    def test_learned_names_are_still_only_names(self) -> None:
        """The learned table is operator-local but still untrusted input to the prober; the plan
        gate re-checks every name. Nothing that is not a parameter name may survive."""
        hostile = ["https://evil.example/x", "drop table users", "bad name", "<script>", "okname"]
        plan = self._plan(_LearningRanker(params=hostile))
        params, _pri, _i, _s, _x, _p = hunt_brain._validate_plan(plan, self.SURFACE)
        self.assertIn("okname", params)
        for bad in hostile[:-1]:
            self.assertNotIn(bad, params)

    # --- the access-control selectors -------------------------------------------------

    PLAIN = {"endpoints": ["https://t.example/reports/summary"], "params": [], "tech": []}
    OBJECT = {"endpoints": ["https://t.example/order/1001"], "params": [], "tech": []}

    def test_the_selector_adds_an_object_endpoint_the_hints_miss(self) -> None:
        """A program whose confirmed IDORs never matched _IDOR_PARAM_HINTS can still teach the
        engine what its own object endpoints look like."""
        self.assertEqual(self._plan(None, self.PLAIN)["idor_candidates"], [])
        self.assertEqual(self._plan(_LearningRanker(selects=["idor"]), self.PLAIN)["idor_candidates"],
                         ["https://t.example/reports/summary"])

    def test_the_selector_adds_a_privileged_endpoint_the_hints_miss(self) -> None:
        self.assertEqual(self._plan(None, self.PLAIN)["privileged_endpoints"], [])
        self.assertEqual(
            self._plan(_LearningRanker(selects=["privileged"]), self.PLAIN)["privileged_endpoints"],
            ["https://t.example/reports/summary"])

    def test_a_negative_selector_never_removes_a_heuristic_candidate(self) -> None:
        """It is OR'd with the rules, so an untrained or disagreeing selector costs nothing."""
        self.assertEqual(self._plan(_LearningRanker(selects=[]), self.OBJECT)["idor_candidates"],
                         self._plan(None, self.OBJECT)["idor_candidates"])

    def test_candidates_are_always_verbatim_in_scope_endpoints(self) -> None:
        plan = self._plan(_LearningRanker(selects=["idor", "privileged"]), self.PLAIN)
        allowed = set(self.PLAIN["endpoints"])
        self.assertTrue(set(plan["idor_candidates"]).issubset(allowed))
        self.assertTrue(set(plan["privileged_endpoints"]).issubset(allowed))

    def test_a_large_learned_table_never_evicts_the_curated_list(self) -> None:
        """The regression: param_hypotheses is truncated at _CAP, so prepending a learned table of
        _CAP names pushed every curated name past the end — a total, silent recall loss behind a
        docstring promising the opposite. Ordering may win; displacement may not."""
        big = [f"learned{i}" for i in range(30)]
        names = self._plan(_LearningRanker(params=big))["param_hypotheses"]
        for curated in offline_hunt._SUGGEST:
            self.assertIn(curated, names, f"curated name {curated} was evicted by the learned table")
        self.assertEqual(names[0], "learned0", "learned names must still lead")

    def test_model_selected_endpoints_never_evict_rule_derived_ones(self) -> None:
        """Both candidate lists are hard-capped at six and filled in discovery order, so a model
        firing on early endpoints would crowd out a rule hit found later. That is removal by
        crowding, and the selector's contract is that it may only ADD."""
        surface = {"endpoints": [f"https://t.example/plain/pg{i}" for i in range(8)]
                                + ["https://t.example/order/1001"],
                   "params": [], "tech": []}
        rule_only = self._plan(None, surface)["idor_candidates"]
        self.assertEqual(rule_only, ["https://t.example/order/1001"])
        with_model = self._plan(_LearningRanker(selects=["idor"]), surface)["idor_candidates"]
        for kept in rule_only:
            self.assertIn(kept, with_model, "a rule-derived candidate was crowded out")
        self.assertGreater(len(with_model), len(rule_only), "the model should still add")

    def test_the_model_cannot_change_which_endpoints_survive_the_cap(self) -> None:
        """The one seam deliberately left closed: endpoint selection under _MAX_PRIORITY stays
        rule-owned, because _priority_sort_key is permutation-invariant."""
        surface = {"endpoints": [f"https://t.example/p{i}/search?q=1" for i in range(40)],
                   "params": [], "tech": []}
        with_model = self._plan(_LearningRanker(params=["z"], selects=["idor"]), surface)
        without = self._plan(None, surface)
        self.assertEqual([r["endpoint"] for r in with_model["probe_priority"]],
                         [r["endpoint"] for r in without["probe_priority"]])


class RankerSeamTests(unittest.TestCase):
    """The learned ranker may only PERMUTE the rule-proposed candidates. Anything else is discarded
    and the deterministic prior ordering is used, so a corrupt/hostile weight file can shift budget
    at worst -- never add, drop, or invent a vuln class."""

    _SIMPLE = {"endpoints": ["https://t.example/api/search?q=x"], "params": [], "tech": []}

    def _classes(self, model, surface=None, priors=None) -> list[str]:
        plan = offline_hunt.offline_plan(surface or self._SIMPLE, priors, model=model)
        return plan["probe_priority"][0]["classes"]

    def test_rules_ordering_without_a_model(self) -> None:
        self.assertEqual(self._classes(None), ["xss", "sqli", "cors"])

    def test_a_valid_permutation_is_honoured(self) -> None:
        self.assertEqual(self._classes(_StubRanker(["cors", "xss", "sqli"])), ["cors", "xss", "sqli"])

    def test_an_invented_class_is_discarded_entirely(self) -> None:
        # a class the rules did not propose (and that the prover may not even confirm) must not leak
        for reply in (["xss", "sqli", "cors", "xxe"],      # added one
                      ["xss", "sqli"],                     # dropped one
                      ["xxe", "idor", "ssrf"],             # wholesale substitution
                      ["xss", "xss", "sqli"]):             # duplicated to smuggle a drop
            self.assertEqual(self._classes(_StubRanker(reply)), ["xss", "sqli", "cors"], reply)

    def test_a_raising_model_falls_back_to_the_rules(self) -> None:
        self.assertEqual(self._classes(_StubRanker(boom=True)), ["xss", "sqli", "cors"])

    def test_a_garbage_return_type_falls_back_to_the_rules(self) -> None:
        for reply in (None, 7, "xss"):
            model = _StubRanker()
            model.rank_endpoint_classes = lambda *a, _r=reply, **k: _r
            self.assertEqual(self._classes(model), ["xss", "sqli", "cors"], reply)

    def test_the_model_sees_only_the_narrow_feature_tuple(self) -> None:
        model = _StubRanker()
        offline_hunt.offline_plan({"endpoints": ["https://t.example/api/search?q=x"],
                                   "params": ["file"], "tech": ["Flask"]}, {"xss": 2.0}, model=model)
        url, names, recon, tech, candidates, priors = model.calls[0]
        self.assertEqual(url, "https://t.example/api/search?q=x")
        self.assertEqual(names, ["q"])                 # the endpoint's OWN query names
        self.assertEqual(recon, ["file"])              # recon-wide params, sorted for determinism
        self.assertEqual(tech, "flask")
        self.assertEqual(priors, {"xss": 2.0})
        self.assertLessEqual(set(candidates), set(PROVER_CLASSES))
        self.assertIsNone(model.forms[0])               # no form for this endpoint

    def test_a_form_crosses_the_seam_value_free(self) -> None:
        """The model needs form:* features (hunt_train fits on them) but must never be handed a
        field VALUE -- only the method and the field names hunt_features actually reads."""
        model = _StubRanker()
        url = "https://t.example/api/search?q=x"
        offline_hunt.offline_plan(
            {"endpoints": [url], "params": [], "tech": [],
             "forms": [{"action": url, "method": "POST",
                        "params": ["email", "token"],
                        "values": {"email": "victim@example.com"},
                        "csrf": "s3cr3t"}]},
            model=model)
        self.assertEqual(model.forms[0], {"method": "POST", "params": ["email", "token"]})
        blob = repr(model.forms[0])
        self.assertNotIn("victim@example.com", blob)
        self.assertNotIn("s3cr3t", blob)

    def test_a_model_cannot_reach_anything_but_the_class_ordering(self) -> None:
        # endpoint selection, param hypotheses, IDOR/privileged picks are all rule-owned.
        rules = offline_hunt.offline_plan(_SURFACE)
        ranked = offline_hunt.offline_plan(_SURFACE, model=_StubRanker())
        for key in ("param_hypotheses", "ssrf_params", "xss_params", "idor_candidates",
                    "privileged_endpoints", "used", "provider", "model"):
            self.assertEqual(ranked[key], rules[key], key)
        self.assertEqual([r["endpoint"] for r in ranked["probe_priority"]],
                         [r["endpoint"] for r in rules["probe_priority"]])
        self.assertTrue(any(r["classes"] != s["classes"]
                            for r, s in zip(ranked["probe_priority"], rules["probe_priority"])))

    def test_notes_record_which_brain_produced_the_plan(self) -> None:
        # notes is persisted in the hunt trace, so the corpus must say whether a ranker ran.
        self.assertNotIn("+ranker", offline_hunt.offline_plan(_SURFACE)["notes"])
        self.assertIn("+ranker stub-v1", offline_hunt.offline_plan(_SURFACE, model=_StubRanker())["notes"])

    def test_an_unlabelled_model_is_reported_undetermined_never_guessed(self) -> None:
        class _NoTag:
            def rank_endpoint_classes(self, *a, **k):
                return list(a[4])
        self.assertIn("+ranker undetermined", offline_hunt.offline_plan(_SURFACE, model=_NoTag())["notes"])


class PlanHuntOfflineFallbackTests(unittest.TestCase):
    def test_no_brain_uses_the_offline_engine(self) -> None:
        hp = hunt_brain.plan_hunt({"enabled": False, "provider": "off"}, "https://t", "t", _SURFACE)
        self.assertEqual(hp["provider"], "offline")
        self.assertTrue(hp["used"])
        self.assertTrue(hp["probe_priority"])                       # offline hunt is no longer blind
        # everything still passes the same validation (verbatim in-scope endpoints)
        for row in hp["probe_priority"]:
            self.assertIn(row["endpoint"], set(_SURFACE["endpoints"]))

    def test_offline_plan_is_validated_out_of_scope_endpoint_dropped(self) -> None:
        # a probe_priority endpoint not in the surface would be dropped by _validate_plan; the offline
        # engine only ever emits surface endpoints, so the plan is fully in-scope by construction
        hp = hunt_brain.plan_hunt(None, "https://t", "t", _SURFACE)
        self.assertEqual(hp["provider"], "offline")
        self.assertTrue(all(r["endpoint"] in set(_SURFACE["endpoints"]) for r in hp["probe_priority"]))


if __name__ == "__main__":
    unittest.main()
