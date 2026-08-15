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
        finding with a projected step must score at the projected step's level."""
        result = attack_chain.build_attack_chains(
            [_confirmed("F1", "xss", "Reflected XSS", "https://app.test/s")], {},
            signals=attack_chain.cookie_signals(["sessionid=a; Path=/"], "https://app.test/"),
        )
        takeover = next(c for c in result["chains"] if c["impact"] == "identity.other-user")
        proven_only = attack_chain.build_attack_chains(
            [_confirmed("F1", "sqli", "SQLi", "https://app.test/r")], {}, signals=[])["chains"][0]
        self.assertLess(takeover["confidence_score"], proven_only["confidence_score"])

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
        missing HttpOnly as token theft fabricated a takeover chain from a correct design."""
        signals = attack_chain.cookie_signals(
            ["csrftoken=abc; Path=/", "XSRF-TOKEN=def; Path=/"], "https://a.test/")
        self.assertEqual(signals, [])

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
        """A login form's own token input is a REQUEST shape, not a token in a response."""
        from_form = attack_chain.collect_signals(response_digest={"form_fields": ["csrf_token"]})
        self.assertNotIn("response.token-in-body", {s["kind"] for s in from_form})
        from_body = attack_chain.collect_signals(response_digest={"json_keys": ["access_token"]})
        self.assertIn("response.token-in-body", {s["kind"] for s in from_body})

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
