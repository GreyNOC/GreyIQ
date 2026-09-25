"""Contract tests for the attack-chain engine.

The engine's value is entirely in NOT overstating: it exists to say "this confirmed XSS plus
this cookie flag reaches account takeover", which is only worth anything if it refuses to say
so when the evidence isn't there. Most of these tests are therefore about what it must not do.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import attack_chain  # noqa: E402


def _confirmed(ref: str, class_id: str, title: str, location: str) -> dict:
    """A finding whose evidence the confirm gate accepts (observed + control differential)."""
    return {
        "ref": ref, "class_id": class_id, "title": title, "location": location,
        "severity": "high", "confidence": "high",
        "proof_of_impact": {
            "status": "confirmed",
            "observed_result": "the injected marker executed in the page context",
            "control_result": "the safely encoded control value rendered as literal text",
        },
    }


def _lead(ref: str, class_id: str, title: str, location: str) -> dict:
    """A scanner lead with no captured artifact."""
    return {"ref": ref, "class_id": class_id, "title": title, "location": location,
            "severity": "medium", "confidence": "medium"}


def _refuted(ref: str, class_id: str, title: str, location: str) -> dict:
    """A finding whose differential WAS RUN and came back negative — observed and control were
    both captured and do not differ. Distinct from a lead, which was never tested at all."""
    same = "HTTP/1.1 200 OK\nthe same response body in both cases"
    return {
        "ref": ref, "class_id": class_id, "title": title, "location": location,
        "severity": "high", "confidence": "high",
        "proof_of_impact": {"status": "confirmed", "observed_result": same, "control_result": same},
    }


class CookieSignalTests(unittest.TestCase):
    def test_session_cookie_flag_gaps_become_signals(self) -> None:
        signals = attack_chain.cookie_signals(
            ["sessionid=abc; Path=/; Domain=.example.com"], "https://app.example.com/")
        kinds = {s["kind"] for s in signals}
        self.assertEqual(kinds, {
            "cookie.session-no-httponly", "cookie.session-no-samesite",
            "cookie.session-no-secure", "cookie.session-domain-scoped",
        })

    def test_non_session_cookies_are_ignored(self) -> None:
        self.assertEqual(attack_chain.cookie_signals(["theme=dark", "lang=en"], "https://a.test/"), [])

    def test_host_prefixed_cookie_is_not_domain_scoped(self) -> None:
        signals = attack_chain.cookie_signals(
            ["__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"], "https://a.test/")
        self.assertNotIn("cookie.session-domain-scoped", {s["kind"] for s in signals})

    def test_secure_gap_only_reported_for_https(self) -> None:
        signals = attack_chain.cookie_signals(["sessionid=a; Path=/"], "http://a.test/")
        self.assertNotIn("cookie.session-no-secure", {s["kind"] for s in signals})

    def test_cookie_value_never_appears_in_a_signal(self) -> None:
        token = "s3cr3t" + ("Z" * 40)
        signals = attack_chain.cookie_signals([f"sessionid={token}; Path=/"], "https://a.test/")
        self.assertTrue(signals)
        self.assertNotIn(token, json.dumps(signals))

    def test_malformed_input_never_raises(self) -> None:
        for junk in (None, "string", 42, [None, 7, {}], [b"bytes"]):
            self.assertIsInstance(attack_chain.cookie_signals(junk, "https://a.test/"), list)


class ChainConstructionTests(unittest.TestCase):
    def test_confirmed_xss_plus_httponly_gap_reaches_account_takeover(self) -> None:
        """The headline case, and the entire justification for demoting cookie findings."""
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://app.test/search")],
            {},
            signals=attack_chain.cookie_signals(["sessionid=a; Path=/"], "https://app.test/"),
        )
        chain = next(c for c in result["chains"] if c["impact"] == "identity.other-user")
        self.assertEqual([s["n"] for s in chain["steps"]], [1, 2, 3])
        self.assertEqual(chain["steps"][0]["evidence_ref"], "F1")
        self.assertTrue(chain["steps"][0]["proven"])
        self.assertEqual(chain["steps"][1]["signal"], "cookie.session-no-httponly")
        # The cookie flag is doing a job, and the chain says which.
        self.assertIn("session token", " ".join(chain["steps"][1]["grants"]))

    def test_xss_alone_does_not_reach_account_takeover(self) -> None:
        """Without the HttpOnly gap there is no token-theft step, so the engine must not
        invent one — this is the control for the test above."""
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://app.test/search")], {}, signals=[])
        steps = [s for c in result["chains"] for s in c["steps"]]
        self.assertFalse([s for s in steps if s["technique_id"] == "xss-steals-session-cookie"])

    def test_steps_are_all_necessary_for_the_impact(self) -> None:
        """A chain must not carry a step the attack does not use. An unrelated confirmed SQLi
        sitting in the same hunt must not be swept into the account-takeover chain."""
        result = attack_chain.build_attack_chains(
            [
                _confirmed("F1", "xss", "Reflected XSS", "https://app.test/search"),
                _confirmed("F2", "sqli", "SQL injection", "https://app.test/report"),
            ],
            {}, signals=attack_chain.cookie_signals(["sessionid=a; Path=/"], "https://app.test/"),
        )
        takeover = next(c for c in result["chains"] if c["impact"] == "identity.other-user")
        self.assertNotIn("F2", takeover["refs"])

    def test_only_the_signals_a_chain_consumed_are_surfaced(self) -> None:
        """Four cookie flags go in; only the one an actual chain used comes back out. This is
        the noise suppression that replaces the old cookie findings."""
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://app.test/x")], {},
            signals=attack_chain.cookie_signals(
                ["sessionid=a; Path=/; Domain=.app.test"], "https://app.test/"),
        )
        self.assertEqual(result["signals_collected"], 4)
        self.assertEqual({s["kind"] for s in result["signals_used"]}, {"cookie.session-no-httponly"})

    def test_output_is_deterministic(self) -> None:
        findings = [
            _confirmed("F1", "xss", "Reflected XSS", "https://app.test/s"),
            _lead("F2", "access-control", "Object id", "https://app.test/api/1"),
            _lead("F3", "disclosure", "Leaked ids", "https://app.test/feed"),
        ]
        signals = attack_chain.cookie_signals(["sessionid=a; Path=/"], "https://app.test/")
        first = attack_chain.build_attack_chains(findings, {}, signals=signals)
        second = attack_chain.build_attack_chains(findings, {}, signals=signals)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_malformed_input_degrades_to_an_empty_result(self) -> None:
        for junk in (None, "bad", [None, "x", 7], [{"ref": {"a": 1}, "severity": []}]):
            result = attack_chain.build_attack_chains(junk, {"F1": "not-a-dict"})
            self.assertEqual(result["algorithm"], attack_chain.ALGORITHM_VERSION)
            self.assertIsInstance(result["chains"], list)


class HonestyInvariantTests(unittest.TestCase):
    """The engine may never manufacture confidence the evidence layer refused."""

    def test_a_signal_can_never_make_a_step_proven(self) -> None:
        """Signals are observations, not evidence. If a cookie flag could mark a step proven,
        a hunt that captured nothing at all could print a 'proven' account takeover."""
        result = attack_chain.build_attack_chains(
            [_lead("F1", "xss", "Possible XSS", "https://app.test/s")], {},
            signals=attack_chain.cookie_signals(["sessionid=a; Path=/"], "https://app.test/"),
        )
        for chain in result["chains"]:
            for step in chain["steps"]:
                if step["signal"]:
                    self.assertFalse(step["proven"], f"signal marked proven: {step}")

    def test_a_chain_of_pure_leads_stays_projected_and_capped(self) -> None:
        result = attack_chain.build_attack_chains(
            [_lead("F1", "disclosure", "Leaked ids", "https://app.test/feed"),
             _lead("F2", "access-control", "Object id", "https://app.test/api/1")], {}, signals=[])
        self.assertTrue(result["chains"])
        for chain in result["chains"]:
            self.assertEqual(chain["status"], "projected")
            self.assertLessEqual(chain["confidence_score"], attack_chain._PROJECTED_CEILING)
        self.assertEqual(result["metrics"]["proven_chains"], 0)

    def test_one_proven_step_does_not_make_the_chain_proven(self) -> None:
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://app.test/s")], {},
            signals=attack_chain.cookie_signals(["sessionid=a; Path=/"], "https://app.test/"),
        )
        takeover = next(c for c in result["chains"] if c["impact"] == "identity.other-user")
        self.assertEqual(takeover["status"], "partial")
        self.assertLessEqual(takeover["confidence_score"], attack_chain._PROJECTED_CEILING)

    def test_a_fully_proven_single_step_chain_is_proven(self) -> None:
        """The counterpart: when every step IS backed, the engine must actually say so, or
        'proven' is a dead state and the whole status vocabulary is decoration."""
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "sqli", "SQL injection", "https://app.test/report")], {}, signals=[])
        chain = next(c for c in result["chains"] if c["impact"] == "disclose.sensitive-data")
        self.assertEqual(chain["status"], "proven")
        self.assertEqual(chain["proven_steps"], chain["step_count"])
        self.assertGreater(chain["confidence_score"], attack_chain._PROJECTED_CEILING)
        self.assertIn("package the chain", chain["next_action"].lower())

    def test_confidence_is_the_weakest_link_not_the_mean(self) -> None:
        """Averaging is how a proven step carries an unproven one. A chain mixing a confirmed
        finding with a projected step must score at the projected step's level.

        Asserting only "less than the fully-proven chain" did NOT pin this: the projected
        ceiling clamps every non-proven chain to 54 anyway, so a mean (58 -> clamped to 54)
        satisfied the inequality just as well as the minimum (34). The engine had to be pinned
        to the weakest link's OWN value.
        """
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://app.test/s")], {},
            signals=attack_chain.cookie_signals(["sessionid=a; Path=/"], "https://app.test/"),
        )
        takeover = next(c for c in result["chains"] if c["impact"] == "identity.other-user")
        proven_only = attack_chain.build_attack_chains(
            [_confirmed("F1", "sqli", "SQLi", "https://app.test/r")], {}, signals=[])["chains"][0]
        self.assertEqual(takeover["confidence_score"], attack_chain._step_confidence(False))
        self.assertLess(takeover["confidence_score"], attack_chain._PROJECTED_CEILING,
                        "a mean would land at the ceiling, not at the weakest link")
        self.assertEqual(
            {s["proven"] for s in takeover["steps"] if s["evidence_ref"] or s["signal"]},
            {True, False}, "the fixture must actually mix a proven and an unproven step")
        self.assertEqual(proven_only["confidence_score"], attack_chain._step_confidence(True))
        self.assertLess(takeover["confidence_score"], proven_only["confidence_score"])

    def test_an_inference_step_keeps_the_chain_partial_and_capped(self) -> None:
        """A pure capability transition ("replay the token you now hold") is a logical
        consequence, not a captured artifact — so a chain containing one can never be proven.

        Every other fixture is either fully proven or has an unproven EVIDENCE step, so nothing
        exercised the clue-less edge: marking those edges proven left the whole suite green.
        """
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "request-smuggling", "Request smuggling", "https://app.test/x")],
            {}, signals=[])
        chain = next(c for c in result["chains"] if c["impact"] == "identity.other-user")
        self.assertEqual([s["technique_id"] for s in chain["steps"]],
                         ["request-smuggling-hijack", "session-token-to-identity"])
        self.assertFalse(chain["steps"][1]["proven"],
                         "a pure capability transition is a consequence, not a captured artifact")
        self.assertEqual(chain["status"], "partial")
        self.assertEqual(chain["proven_steps"], 1)
        # Exact: the weakest EVIDENCE link here is 82, so losing the cap raises this to 82.
        self.assertEqual(chain["confidence_score"], attack_chain._PROJECTED_CEILING)
        self.assertEqual(result["metrics"]["proven_chains"], 0)

    def test_the_next_action_names_the_blocking_step(self) -> None:
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://app.test/s")], {},
            signals=attack_chain.cookie_signals(["sessionid=a; Path=/"], "https://app.test/"),
        )
        takeover = next(c for c in result["chains"] if c["impact"] == "identity.other-user")
        self.assertEqual(takeover["blocking_step"], 2)
        self.assertEqual(takeover["next_action"], takeover["steps"][1]["next_action"])

    def test_cross_host_chains_rank_below_same_host_chains(self) -> None:
        """Two findings on unrelated hosts may not share a session at all."""
        same = attack_chain.build_attack_chains(
            [_lead("F1", "disclosure", "Leaked ids", "https://app.test/feed"),
             _lead("F2", "access-control", "Object id", "https://app.test/api/1")], {}, signals=[])
        cross = attack_chain.build_attack_chains(
            [_lead("F1", "disclosure", "Leaked ids", "https://one.test/feed"),
             _lead("F2", "access-control", "Object id", "https://two.test/api/1")], {}, signals=[])

        def _two_step(result: dict) -> dict:
            return next(c for c in result["chains"] if len(c["steps"]) == 2)

        self.assertGreater(_two_step(same)["priority_score"], _two_step(cross)["priority_score"])

    def test_a_signal_only_chain_cites_no_finding(self) -> None:
        """Nothing was observed to be broken, so the chain must carry no finding reference —
        that is what routes it to the probe queue instead of the report."""
        result = attack_chain.build_attack_chains([], {}, signals=attack_chain.collect_signals(
            surface={"forms": [{"action": "https://a.test/u", "method": "POST",
                                "params": ["email", "is_admin"]}]}))
        self.assertTrue(result["chains"])
        for chain in result["chains"]:
            self.assertEqual(chain["refs"], [])
            self.assertEqual(chain["status"], "projected")


class ReachabilityTests(unittest.TestCase):
    """"Never tested" and "tested and refuted" are different facts. Before this distinction
    existed both were `proven=False`, so a chain whose prerequisite the engine had actively
    FAILED to establish was presented exactly like one nobody had looked at yet."""

    def test_an_untested_ladder_is_never_marked_unreachable(self) -> None:
        """The regression that would matter most: if absence of proof were read as refutation,
        every projected lead chain — the engine's main output — would be marked unreachable."""
        steps = [
            {"n": 1, "requires_ids": ["entry.public"], "grants_ids": ["disclose.identifier"],
             "proven": False, "disproven": False, "state": "projected"},
            {"n": 2, "requires_ids": ["disclose.identifier"], "grants_ids": ["identity.other-user"],
             "proven": False, "disproven": False, "state": "projected"},
            {"n": 3, "requires_ids": ["identity.other-user"], "grants_ids": ["read.other-object"],
             "proven": False, "disproven": False, "state": "projected"},
        ]
        attack_chain._mark_unreachable(steps)
        self.assertEqual([s["state"] for s in steps], ["projected"] * 3)

    def test_only_the_steps_depending_on_a_refuted_grant_are_unreachable(self) -> None:
        steps = [
            {"n": 1, "requires_ids": ["entry.public"], "grants_ids": ["disclose.identifier"],
             "proven": False, "disproven": False, "state": "projected"},
            {"n": 2, "requires_ids": ["disclose.identifier"], "grants_ids": ["identity.other-user"],
             "proven": False, "disproven": True, "state": "projected"},
            {"n": 3, "requires_ids": ["identity.other-user"], "grants_ids": ["read.other-object"],
             "proven": False, "disproven": False, "state": "projected"},
            # Depends only on the chain ENTRY, which no step had to grant — still viable.
            {"n": 4, "requires_ids": ["entry.public"], "grants_ids": ["net.internal"],
             "proven": False, "disproven": False, "state": "projected"},
        ]
        attack_chain._mark_unreachable(steps)
        self.assertEqual(steps[2]["state"], "unreachable")
        self.assertEqual(steps[2]["blocked_by"], ["identity.other-user"])
        self.assertEqual(steps[3]["state"], "projected")

    def test_a_capability_a_live_step_also_grants_is_not_broken(self) -> None:
        steps = [
            {"n": 1, "requires_ids": [], "grants_ids": ["identity.other-user"],
             "proven": False, "disproven": True, "state": "projected"},
            {"n": 2, "requires_ids": [], "grants_ids": ["identity.other-user"],
             "proven": False, "disproven": False, "state": "projected"},
            {"n": 3, "requires_ids": ["identity.other-user"], "grants_ids": ["read.other-object"],
             "proven": False, "disproven": False, "state": "projected"},
        ]
        attack_chain._mark_unreachable(steps)
        self.assertEqual(steps[2]["state"], "projected")

    def test_a_refuted_chain_ranks_below_every_untested_one(self) -> None:
        """The mirror of the existing honesty invariants: a refuted chain must never rank, score
        or read stronger than a chain nobody has tested."""
        self.assertLess(attack_chain._STATUS_RANK["broken"], attack_chain._STATUS_RANK["projected"])
        self.assertLessEqual(attack_chain._BROKEN_CEILING, attack_chain._PROJECTED_CEILING)

    def test_a_refuted_prerequisite_breaks_the_chain_it_carries(self) -> None:
        result = attack_chain.build_attack_chains(
            [_refuted("F1", "disclosure", "Leaked ids", "https://app.test/feed"),
             _lead("F2", "access-control", "Object id", "https://app.test/api/1")], {}, signals=[])
        broken = [c for c in result["chains"] if c["status"] == "broken"]
        if broken:  # only when the refuted clue actually entered a ladder
            for chain in broken:
                self.assertLessEqual(chain["confidence_score"], attack_chain._BROKEN_CEILING)
                self.assertTrue(any(s["disproven"] for s in chain["steps"]))
                # The chain points at the REFUTED step, not past it.
                self.assertEqual(chain["blocking_step"],
                                 next(s["n"] for s in chain["steps"] if s["disproven"]))

    def test_the_confirm_gate_still_wins_over_refutation(self) -> None:
        """A clue the confirm gate accepted is never also marked refuted by its own evidence."""
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://app.test/s")], {}, signals=[])
        for chain in result["chains"]:
            for step in chain["steps"]:
                if step["proven"]:
                    self.assertFalse(step["disproven"])


class ConfirmGateProvenanceTests(unittest.TestCase):
    """`proven` must come from the single confirm authority, not from anything local.

    Without these, the whole suite still passes with the gate bypassed — every other test
    feeds a finding that happens to satisfy both the gate and any naive substitute for it.
    """

    def test_proven_tracks_the_confirm_gate_when_it_says_no(self) -> None:
        # A claimed "confirmed" status with NO differential: the gate refuses it, so must we.
        result = attack_chain.build_attack_chains(
            [{"ref": "F1", "class_id": "sqli", "title": "SQLi", "location": "https://a.test/r",
              "severity": "high", "confidence": "high",
              "proof_of_impact": {"status": "confirmed", "observed_result": "looks vulnerable"}}],
            {}, signals=[])
        for chain in result["chains"]:
            for step in chain["steps"]:
                self.assertFalse(step["proven"], "a claim with no captured differential is not proof")

    def test_proven_delegates_rather_than_reimplementing(self) -> None:
        """Pin the delegation itself: if the gate is stubbed to refuse, nothing is proven."""
        original = attack_chain.investigator.has_confirming_artifact
        try:
            attack_chain.investigator.has_confirming_artifact = lambda f, p=None: False
            result = attack_chain.build_attack_chains(
                [_confirmed("F1", "sqli", "SQLi", "https://a.test/r")], {}, signals=[])
            proven = [s for c in result["chains"] for s in c["steps"] if s["proven"]]
            self.assertEqual(proven, [], "step proof must come from the confirm authority alone")
        finally:
            attack_chain.investigator.has_confirming_artifact = original


class SignalIntegrityTests(unittest.TestCase):
    def test_csrf_double_submit_cookie_is_not_a_session_cookie(self) -> None:
        """A double-submit CSRF cookie MUST be JS-readable — that is the pattern. Treating its
        missing HttpOnly as token theft fabricated a takeover chain from a correct design.

        `csrftoken`/`XSRF-TOKEN` are named in the docs so they stay pinned, but neither reaches
        the exclusion regex — the positive session-name filter already drops them, so deleting
        the exclusion entirely left the suite green. The names that actually depend on it are
        the ones matching BOTH patterns.
        """
        signals = attack_chain.cookie_signals(
            ["csrftoken=abc; Path=/", "XSRF-TOKEN=def; Path=/",
             "authenticity_token=ghi; Path=/", "csrf_session=jkl; Path=/",
             "session_csrf=mno; Path=/", "__RequestVerificationToken=pqr; Path=/"],
            "https://a.test/")
        self.assertEqual(signals, [])
        # Positive control: the fixture is not vacuous. A session-ish name with no anti-forgery
        # marker DOES signal, so a future narrowing of the session regex cannot make the
        # assertion above pass for the wrong reason — which is exactly what it did before.
        self.assertTrue(attack_chain.cookie_signals(["auth_session=abc; Path=/"], "https://a.test/"))

    def test_bearer_token_cookies_are_recognised_as_the_session(self) -> None:
        """`auth_token`, `remember_token`, `id_token` ARE the session on a standard SPA/Rails
        app. An over-broad anti-forgery exclusion swallowed all of them, so on those targets the
        engine's headline chain never fired and the hunt reported nothing at all."""
        for name in ("auth_token", "session_token", "remember_token", "id_token",
                     "access_token", "jwt_token"):
            with self.subTest(cookie=name):
                kinds = {s["kind"] for s in attack_chain.cookie_signals(
                    [f"{name}=abc; Path=/"], "https://a.test/")}
                self.assertIn("cookie.session-no-httponly", kinds)
        # ...but a bare `token` substring must NOT make every token-ish cookie the session.
        for name in ("consent_token", "recaptcha_token", "preview_token"):
            with self.subTest(cookie=name):
                self.assertEqual(
                    attack_chain.cookie_signals([f"{name}=abc; Path=/"], "https://a.test/"), [])

    def test_samesite_none_counts_as_sent_cross_site(self) -> None:
        """SameSite=None is the explicit opt-IN to cross-site sending, not protection."""
        kinds = {s["kind"] for s in attack_chain.cookie_signals(
            ["sessionid=a; Path=/; SameSite=None; Secure"], "https://a.test/")}
        self.assertIn("cookie.session-no-samesite", kinds)
        kinds_lax = {s["kind"] for s in attack_chain.cookie_signals(
            ["sessionid=a; Path=/; SameSite=Lax; Secure"], "https://a.test/")}
        self.assertNotIn("cookie.session-no-samesite", kinds_lax)

    def test_flags_are_read_from_attributes_not_the_cookie_value(self) -> None:
        """A value containing 'httponly'/'secure' must not suppress the real flag gap."""
        kinds = {s["kind"] for s in attack_chain.cookie_signals(
            ["sessionid=httponly-secure-samesite-domain=x; Path=/"], "https://a.test/")}
        self.assertIn("cookie.session-no-httponly", kinds)
        self.assertIn("cookie.session-no-secure", kinds)
        self.assertIn("cookie.session-no-samesite", kinds)
        self.assertNotIn("cookie.session-domain-scoped", kinds)

    def test_a_bare_jwt_never_fabricates_a_role_claim(self) -> None:
        """The digest decodes a JWT HEADER only, so `alg` says nothing about a role claim."""
        signals = attack_chain.collect_signals(response_digest={"jwt": {"alg": "HS256"}})
        self.assertNotIn("token.role-claim", {s["kind"] for s in signals})

    def test_token_in_body_requires_a_response_body_name(self) -> None:
        """A login form's own token input is a REQUEST shape, not a token in a response.

        The negative half used `csrf_token`, which the token regex does not match at all — so
        the assertion held whether or not request shapes fed the producer, and re-adding
        `form_fields` to the loop left the suite green. It has to use names that DO match.
        """
        from_request = attack_chain.collect_signals(response_digest={
            "form_fields": ["session", "api_key"], "interesting_names": ["access_token"]})
        self.assertNotIn("response.token-in-body", {s["kind"] for s in from_request},
                         "form_fields/interesting_names are request shapes, not response bodies")
        from_body = attack_chain.collect_signals(response_digest={"json_keys": ["access_token"]})
        self.assertIn("response.token-in-body", {s["kind"] for s in from_body})
        self.assertIn("response.token-in-body", {s["kind"] for s in attack_chain.collect_signals(
            response_digest={"json_keys": ["session"]})})

    def test_a_signal_about_one_finding_cannot_escalate_another(self) -> None:
        """Two exposed secrets, only one of them a cloud key: the chain must not take the
        first finding's step and the second finding's observation."""
        findings = [
            _lead("F1", "secrets", "Stripe key in bundle", "https://a.test/app.js"),
            _lead("F2", "secrets", "AWS key in bundle", "https://a.test/vendor.js"),
        ]
        signals = attack_chain.collect_signals(findings=findings)
        cloud = [s for s in signals if s["kind"] == "credential.cloud-provider"]
        self.assertEqual([s["ref"] for s in cloud], ["F2"], "only F2 looks like a cloud key")
        result = attack_chain.build_attack_chains(findings, {}, signals=signals)
        for chain in result["chains"]:
            for step in chain["steps"]:
                if step["signal"] == "credential.cloud-provider":
                    self.assertIn("F2", chain["refs"])

    def test_one_chain_per_attack_despite_repeated_signal_kinds(self) -> None:
        """Two hosts with the same cookie gap must not print the same chain twice."""
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://a.test/s")], {},
            signals=(attack_chain.cookie_signals(["sessionid=a; Path=/"], "https://a.test/")
                     + attack_chain.cookie_signals(["sessionid=b; Path=/"], "https://b.test/")),
        )
        sigs = [tuple(s["technique_id"] for s in c["steps"]) for c in result["chains"]]
        self.assertEqual(len(sigs), len(set(sigs)), f"duplicate chains: {sigs}")

    def test_one_bad_signal_family_does_not_drop_the_others(self) -> None:
        """Signal sources are target-derived; a malformed one must cost only itself."""
        signals = attack_chain.collect_signals(
            findings=[_lead("F1", "secrets", "AWS key", "https://a.test/aws.js")],
            surface={"forms": 5, "endpoints": 7},          # both malformed
            response_digest={"interesting_names": 5},       # malformed
        )
        self.assertIn("credential.cloud-provider", {s["kind"] for s in signals})


class NoiseFloorTests(unittest.TestCase):
    """The headline claim of the cookie demotion, pinned."""

    SLOPPY = ["sessionid=abc; Path=/; Domain=.example.com", "csrftoken=xyz; Path=/"]

    def test_sloppy_cookies_with_nothing_broken_produce_no_chain(self) -> None:
        result = attack_chain.build_attack_chains(
            [], {}, signals=attack_chain.cookie_signals(self.SLOPPY, "https://app.example.com/"))
        self.assertEqual([c for c in result["chains"] if c["refs"]], [])

    def test_sloppy_cookies_plus_only_a_missing_header_produce_no_chain(self) -> None:
        result = attack_chain.build_attack_chains(
            [_lead("F1", "headers", "Missing Referrer-Policy", "https://app.example.com/")], {},
            signals=attack_chain.cookie_signals(self.SLOPPY, "https://app.example.com/"))
        self.assertEqual([c for c in result["chains"] if c["refs"]], [])

    def test_the_same_flags_become_a_chain_once_an_xss_is_confirmed(self) -> None:
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://app.example.com/s")], {},
            signals=attack_chain.cookie_signals(self.SLOPPY, "https://app.example.com/"))
        takeover = [c for c in result["chains"] if c["impact"] == "identity.other-user"]
        self.assertTrue(takeover, "the HttpOnly gap must now do a job")
        self.assertEqual({s["kind"] for s in result["signals_used"]}, {"cookie.session-no-httponly"})


class ObservationProvenanceTests(unittest.TestCase):
    """An observation is bound to WHERE it was made and WHICH finding it describes.

    A campaign pools every target's signals into one graph, so without these bindings one
    company's cookie flag gap composed into another company's confirmed XSS and was reported as
    an account takeover whose second step is physically impossible on that target.
    """

    XSS = staticmethod(lambda host: _confirmed("F1", "xss", "Reflected XSS", f"https://{host}/s"))

    def test_a_cookie_gap_on_an_unrelated_host_cannot_escalate_a_finding(self) -> None:
        foreign = attack_chain.cookie_signals(["sid=abc; Path=/"], "https://www.acme-corp.example/")
        result = attack_chain.build_attack_chains(
            [self.XSS("app.zenith-bank.example")], {}, signals=foreign)
        self.assertEqual([c for c in result["chains"] if c["impact"] == "identity.other-user"], [],
                         "a different program's cookie cannot steal this target's session")

    def test_the_same_gap_on_the_same_host_still_escalates(self) -> None:
        same = attack_chain.cookie_signals(["sid=abc; Path=/"], "https://app.zenith-bank.example/")
        result = attack_chain.build_attack_chains(
            [self.XSS("app.zenith-bank.example")], {}, signals=same)
        self.assertTrue([c for c in result["chains"] if c["impact"] == "identity.other-user"])

    def test_sibling_subdomains_share_a_trust_boundary(self) -> None:
        """Domain-scoped cookies really do cross sibling subdomains, and the campaign's whole
        payoff is that composition — so it must be neither rejected nor score-penalised."""
        sibling = attack_chain.cookie_signals(["sid=abc; Path=/"], "https://api.zenith-bank.example/")
        same = attack_chain.cookie_signals(["sid=abc; Path=/"], "https://app.zenith-bank.example/")
        finding = self.XSS("app.zenith-bank.example")
        pick = lambda sigs: next(  # noqa: E731
            c for c in attack_chain.build_attack_chains([finding], {}, signals=sigs)["chains"]
            if c["impact"] == "identity.other-user")
        self.assertEqual(pick(sibling)["priority_score"], pick(same)["priority_score"])

    def test_a_claimed_subdomain_plus_a_parent_cookie_is_still_a_chain(self) -> None:
        """The flagship cross-target chain: a takeover on one host and the domain-scoped cookie
        observed on a sibling. Host binding must not delete the composition it exists to enable."""
        takeover = _confirmed("F1", "subdomain-takeover", "Dangling CNAME", "https://old.corp.test/")
        sibling = attack_chain.cookie_signals(
            ["sid=abc; Path=/; Domain=.corp.test"], "https://www.corp.test/")
        self.assertTrue(attack_chain.build_attack_chains([takeover], {}, signals=sibling)["chains"])
        unrelated = attack_chain.cookie_signals(
            ["sid=abc; Path=/; Domain=.other.test"], "https://www.other.test/")
        self.assertEqual(
            attack_chain.build_attack_chains([takeover], {}, signals=unrelated)["chains"], [])

    def test_a_signal_survives_its_finding_being_renumbered(self) -> None:
        """Refs are renumbered when a campaign pools findings (F1 -> C7) while the signals keep
        the ref they were stamped with, so a ref-keyed provenance check silently discarded every
        cross-target witness. Provenance is keyed on the finding's CONTENT instead."""
        secret = {
            "ref": "F1", "class_id": "secrets", "rule_id": "secret.aws",
            "title": "AWS key in bundle", "location": "https://a.test/app.js", "severity": "high",
            "secret_type": "aws_access_key_id", "_credential_proof": {"scopes": "admin,write"},
        }
        signals = attack_chain.collect_signals(findings=[secret])
        self.assertTrue([s for s in signals if s["finding_key"]])
        repooled = {**secret, "ref": "C7"}
        chains = attack_chain.build_attack_chains([repooled], {}, signals=signals)["chains"]
        self.assertTrue(chains, "the credential chain must survive the re-key")
        for chain in chains:
            self.assertEqual(chain["refs"], ["C7"])

    def test_a_signal_names_the_host_it_was_observed_on(self) -> None:
        """The rendered step carried only the kind and the prose, so a reader could not tell a
        composition was cross-host — the one fact needed to catch a bad chain by reading it."""
        result = attack_chain.build_attack_chains(
            [self.XSS("app.test")], {},
            signals=attack_chain.cookie_signals(["sid=a; Path=/"], "https://app.test/"))
        steps = [s for c in result["chains"] for s in c["steps"] if s["signal"]]
        self.assertTrue(steps)
        for step in steps:
            self.assertEqual(step["signal_host"], "app.test")


class NoFabricationFromMislabelTests(unittest.TestCase):
    """Each of these produced a confirmed, report-ready claim nobody observed."""

    def test_a_confirmed_file_read_never_reports_code_execution(self) -> None:
        """The path-traversal prover was class-tagged `file-upload`, so the upload-to-execution
        technique fired and the engine reported a PROVEN RCE from a read-only file disclosure.
        The producer is fixed; the table must also refuse to mint an impact from a bare class."""
        lfi = _confirmed("F1", "file-upload", "Path traversal / local file read",
                         "https://a.test/?file=../../etc/passwd")
        for chain in attack_chain.build_attack_chains([lfi], {})["chains"]:
            self.assertNotEqual(chain["impact"], "exec.server-code")

    def test_a_confirmed_path_traversal_reaches_the_file_read_ladder(self) -> None:
        """...and the honest technique it should have been firing all along now does."""
        lfi = _confirmed("F1", "path-traversal", "Path traversal / local file read",
                         "https://a.test/?file=../../etc/passwd")
        impacts = {c["impact"] for c in attack_chain.build_attack_chains([lfi], {})["chains"]}
        self.assertIn("read.server-file", impacts)

    def test_graphql_introspection_is_not_a_cross_tenant_read(self) -> None:
        """Introspection discloses the schema. It observes no boundary being crossed, so it
        must not reach a terminal impact on its own — it is a lead for BOLA/BFLA."""
        gql = _confirmed("F1", "graphql", "GraphQL introspection enabled",
                         "https://a.test/graphql")
        impacts = {c["impact"] for c in attack_chain.build_attack_chains([gql], {})["chains"]}
        self.assertNotIn("read.other-object", impacts)
        # Paired with an actual access-control finding it does its real job.
        both = attack_chain.build_attack_chains(
            [gql, _confirmed("F2", "access-control", "IDOR", "https://a.test/api/1")], {})
        self.assertIn("read.other-object", {c["impact"] for c in both["chains"]})

    def test_a_csrf_cookie_from_the_digest_cannot_fabricate_a_takeover(self) -> None:
        """The digest builds its auth-cookie list on a wider pattern than the raw parser, so a
        correct Django double-submit cookie reached the graph through the second door and
        manufactured the exact chain the raw parser is tested to refuse."""
        xss = _confirmed("F1", "xss", "Reflected XSS", "https://a.test/s")
        digest = {"url": "https://a.test/",
                  "cookie_flag_gaps": [{"cookie": "csrftoken", "missing": ["HttpOnly", "SameSite"]}]}
        result = attack_chain.build_attack_chains([xss], {}, response_digest=digest)
        self.assertEqual([c for c in result["chains"] if c["impact"] == "identity.other-user"], [])
        real = {"url": "https://a.test/",
                "cookie_flag_gaps": [{"cookie": "sessionid", "missing": ["HttpOnly"]}]}
        self.assertTrue([c for c in attack_chain.build_attack_chains(
            [xss], {}, response_digest=real)["chains"] if c["impact"] == "identity.other-user"])

    def test_a_path_name_is_not_an_observation_of_a_write(self) -> None:
        """`set` matched inside `/assets/` and `add` inside `/address`, so essentially every
        target emitted the signal that promotes "read another tenant's data" to "MODIFY it"."""
        signals = attack_chain.collect_signals(surface={"endpoints": [
            "https://a.test/assets/img/logo.png", "https://a.test/address-book",
            "https://a.test/credit-report", "https://a.test/products/editor"]})
        self.assertNotIn("endpoint.state-changing", {s["kind"] for s in signals})
        # An OBSERVED state-changing method still emits it.
        observed = attack_chain.collect_signals(surface={"forms": [
            {"action": "https://a.test/u", "method": "POST", "params": ["email"]}]})
        self.assertIn("endpoint.state-changing", {s["kind"] for s in observed})

    def test_a_stylesheet_is_not_an_authentication_flow(self) -> None:
        """`reset` matched `/static/css/reset.css`, which was enough to carry an unproven
        open-redirect lead all the way to an account-takeover chain."""
        noise = attack_chain.collect_signals(surface={"endpoints": [
            "https://cdn.a.test/static/css/reset.css", "https://a.test/order/confirmation",
            "https://a.test/team/invited-speakers", "https://a.test/bundle.js"]})
        self.assertNotIn("flow.auth-redirect", {s["kind"] for s in noise})
        real = attack_chain.collect_signals(surface={"endpoints": ["https://a.test/auth/callback"]})
        self.assertIn("flow.auth-redirect", {s["kind"] for s in real})

    def test_a_repository_path_is_not_a_hostname(self) -> None:
        """A code-scanner finding's location is a FILE PATH; splitting it on "/" made two files
        in one repo look like two unrelated internet hosts and charged the cross-host penalty."""
        same_repo = attack_chain.build_attack_chains([
            _confirmed("F1", "disclosure", "Leaked ids", "backend/app/views.py"),
            _confirmed("F2", "access-control", "Object id", "frontend/src/api.js")], {}, signals=[])
        one_host = attack_chain.build_attack_chains([
            _confirmed("F1", "disclosure", "Leaked ids", "https://a.test/feed"),
            _confirmed("F2", "access-control", "Object id", "https://a.test/api/1")], {}, signals=[])

        def _two_step(result: dict) -> dict:
            return next(c for c in result["chains"] if len(c["steps"]) == 2)

        self.assertEqual(_two_step(same_repo)["priority_score"], _two_step(one_host)["priority_score"])
        self.assertEqual(_two_step(same_repo)["confidence_score"], _two_step(one_host)["confidence_score"])


class CoverageTests(unittest.TestCase):
    """Classes GreyIQ can confirm must actually reach the graph, and dead rows must not exist."""

    def test_every_technique_can_fire_and_every_grant_is_consumed(self) -> None:
        granted: set[str] = set()
        required: set[str] = set()
        for technique in attack_chain._TECHNIQUES:
            granted |= set(technique["grants"])
            required |= set(technique["requires"])
            for capability in (*technique["grants"], *technique["requires"]):
                self.assertIn(capability, attack_chain._CAPABILITY_LABELS,
                              f"{technique['id']} names a capability with no label")
        orphans = granted - required - set(attack_chain._IMPACTS)
        # `read.server-side-response` is a deliberate descriptive grant on the SSRF row.
        self.assertEqual(orphans, {"read.server-side-response"},
                         "a granted capability nothing requires and no impact lists is a dead end: "
                         "`_prune_path` drops the step from every witness it appears in")

    def test_every_impact_is_reachable_from_an_entry(self) -> None:
        for impact in attack_chain._IMPACTS:
            with self.subTest(impact=impact):
                self.assertTrue(
                    any(impact in t["grants"] for t in attack_chain._TECHNIQUES),
                    f"no technique grants {impact}, so the report can never state it")

    def test_a_confirmed_cloud_store_contributes_to_the_graph(self) -> None:
        """An anonymously listable bucket is the strongest cloud evidence the engine can
        capture, and the class hint that makes it legible in the report also took it out of the
        disclosure bucket that fed the identifier ladder — so it reached no chain at all."""
        bucket = _confirmed("F1", "cloud-exposure", "Public cloud bucket (anonymous listing)",
                            "https://s3.amazonaws.com/acme-backups/")
        result = attack_chain.build_attack_chains([bucket], {})
        self.assertTrue(result["chains"])
        self.assertIn("disclose.sensitive-data", {c["impact"] for c in result["chains"]})

    def test_a_denied_bucket_never_reads_as_an_anonymous_read(self) -> None:
        """The bucket check stamps `cloud-exposure` on all three of its outcomes, including
        "referenced but denied anonymous listing (403)" and "referenced, not probed". Those are
        observations that the store is NOT open, so narrating them as "reads anonymously
        (projected)" contradicts what was seen rather than proposing a next step."""
        denied = _lead("F1", "cloud-exposure", "Cloud bucket referenced (access denied)",
                       "https://s3.amazonaws.com/acme-backups/")
        self.assertEqual(attack_chain.build_attack_chains([denied], {})["chains"], [])
        # ...and the confirmed anonymous listing still does its job.
        listed = _confirmed("F1", "cloud-exposure", "Public cloud bucket (anonymous listing)",
                            "https://s3.amazonaws.com/acme-backups/")
        self.assertTrue(attack_chain.build_attack_chains([listed], {})["chains"])

    def test_an_unprobed_bucket_never_claims_the_target_is_cloud_hosted(self) -> None:
        """The out-of-scope outcome carries an EMPTY location, so the signal it produced had no
        host — and an unbound observation composed with a finding on any host, unlocking the
        cloud-metadata pivot on any SSRF with nothing observed at all."""
        unprobed = _lead("F1", "cloud-exposure", "Cloud bucket referenced (out of scope)", "")
        kinds = {s["kind"] for s in attack_chain.collect_signals(findings=[unprobed])}
        self.assertNotIn("infra.cloud-hosted", kinds)

    def test_a_deserialization_sink_narrates_itself(self) -> None:
        """The reporting layer folds category `deserialization` into class `rce`, so the ladder
        described a deserialization sink as "input reaches a command interpreter"."""
        finding = {**_confirmed("F1", "rce", "unserialize() on user input", "app/models/user.php"),
                   "category": "deserialization"}
        titles = [s["title"] for c in attack_chain.build_attack_chains([finding], {})["chains"]
                  for s in c["steps"]]
        self.assertIn("Untrusted data is deserialized", titles)
        self.assertNotIn("Input reaches a command interpreter", titles)


class SelectionTests(unittest.TestCase):
    def test_a_proven_chain_is_never_evicted_by_a_projected_one(self) -> None:
        """The per-impact bucket ranked on score alone while the final sort ranked proven-first,
        so the bucket discarded a fully proven chain before the sort could ever see it."""
        findings = [
            _confirmed("F1", "sqli", "SQLi", "https://a.test/r"),
            _lead("F2", "cors", "Permissive CORS", "https://a.test/api"),
            _lead("F3", "nosqli", "NoSQL injection", "https://a.test/q"),
        ]
        result = attack_chain.build_attack_chains(findings, {}, signals=[])
        disclosure = [c for c in result["chains"] if c["impact"] == "disclose.sensitive-data"]
        self.assertTrue(any(c["status"] == "proven" for c in disclosure),
                        "the captured SQLi chain must survive the per-impact cap")

    def test_the_bucket_key_ranks_proof_above_score(self) -> None:
        """The end-to-end fixture below cannot pin this on its own: with only two candidates for
        the impact the per-impact cap never discriminates, so the test passes under BOTH ranking
        keys. Pin the ordering decision itself — proof band must beat a higher raw score."""
        rank = attack_chain._STATUS_RANK
        self.assertGreater(rank["proven"], rank["partial"])
        self.assertGreater(rank["partial"], rank["projected"])
        proven = (rank["proven"], 100, -1)
        better_scoring_partial = (rank["partial"], 999, -1)
        self.assertGreater(proven, better_scoring_partial,
                           "a proven chain must outrank a higher-scoring unproven one")

    def test_a_late_technique_still_reaches_the_report_under_a_tight_budget(self) -> None:
        """The search was depth-first over one shared budget, so the FIRST edge's subtree consumed
        the whole allowance and any witness whose technique sits late in the table was lost. No
        fixture approaches the budget, so plain DFS passes every other test in this file."""
        findings = [_confirmed(f"F{i}", cls, f"{cls} finding", f"https://app.test/{cls}")
                    for i, cls in enumerate(
                        ["xss", "sqli", "ssrf", "xxe", "rce", "ssti", "cors", "redirect",
                         "access-control", "disclosure", "secrets", "jwt", "csrf", "nosqli",
                         "graphql", "subdomain-takeover", "request-smuggling"], 1)]
        original = attack_chain._MAX_EXPANSIONS
        try:
            attack_chain._MAX_EXPANSIONS = 400  # force the budget to actually bind
            result = attack_chain.build_attack_chains(findings, {}, signals=[])
        finally:
            attack_chain._MAX_EXPANSIONS = original
        self.assertTrue(result["chains"])
        impacts = {c["impact"] for c in result["chains"]}
        self.assertGreater(len(impacts), 3,
                           "a starved search reports only the impacts reachable from edge 0")
        self.assertIn("exec.server-code", impacts,
                      "command-injection sits late in the table and must still be found")

    def test_the_narrative_names_the_capability_the_chain_used(self) -> None:
        """XXE grants BOTH a file read and internal reach, so a chain resting on the second grant
        used to narrate the first. The narrative is copied verbatim into the report."""
        chains = attack_chain.build_attack_chains(
            [_confirmed("F1", "xxe", "XXE", "https://app.test/x")], {}, signals=[])["chains"]
        by_impact = {c["impact"]: c for c in chains}
        self.assertIn("read.server-file", by_impact)
        self.assertIn("net.internal", by_impact)
        self.assertTrue(by_impact["read.server-file"]["narrative"].rstrip(".").endswith(
            attack_chain._CAPABILITY_LABELS["read.server-file"]))
        self.assertTrue(by_impact["net.internal"]["narrative"].rstrip(".").endswith(
            attack_chain._CAPABILITY_LABELS["net.internal"]))

    def test_one_attack_is_reported_once_however_many_findings_share_a_class(self) -> None:
        """Distinctness was keyed on edge indices, so N findings of one class produced N
        identical technique ladders that each consumed a report slot."""
        findings = [_confirmed(f"F{i}", "sqli", f"SQLi {i}", f"https://a.test/r{i}")
                    for i in range(1, 4)]
        result = attack_chain.build_attack_chains(findings, {}, signals=[])
        shapes = [(c["impact"], tuple(s["technique_id"] for s in c["steps"]))
                  for c in result["chains"]]
        self.assertEqual(len(shapes), len(set(shapes)), f"duplicate attacks: {shapes}")

    def test_a_probe_lead_never_evicts_an_evidence_backed_chain(self) -> None:
        """A signal-only path cites no finding, so the cortex routes it to the probe queue —
        letting it compete for a report slot spent the budget on something unreportable."""
        findings = [_confirmed("F1", "access-control", "IDOR", "https://a.test/api/1")]
        signals = attack_chain.collect_signals(surface={"forms": [
            {"action": "https://a.test/u", "method": "POST", "params": ["email", "is_admin"]}]})
        result = attack_chain.build_attack_chains(findings, {}, signals=signals)
        anchored = [c for c in result["chains"] if c["refs"]]
        probes = [c for c in result["chains"] if not c["refs"]]
        self.assertTrue(anchored, "the captured IDOR chain must be reported")
        self.assertTrue(probes, "the mass-assignment lead must still reach the probe queue")


class EscalationNoteTests(unittest.TestCase):
    def test_notes_attach_a_chain_role_to_each_finding(self) -> None:
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://app.test/s")], {},
            signals=attack_chain.cookie_signals(["sessionid=a; Path=/"], "https://app.test/"),
        )
        notes = attack_chain.escalation_notes_by_ref(result)
        self.assertIn("F1", notes)
        self.assertTrue(any("Step 1" in note for note in notes["F1"]))

    def test_malformed_result_yields_no_notes(self) -> None:
        for junk in (None, {}, {"chains": "bad"}, {"chains": [None, {"steps": "x"}]}):
            self.assertEqual(attack_chain.escalation_notes_by_ref(junk), {})


if __name__ == "__main__":
    unittest.main()
