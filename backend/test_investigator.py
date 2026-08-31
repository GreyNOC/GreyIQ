"""Contract tests for the shared evidence-grounded investigation cortex."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import investigator, report  # noqa: E402


class InvestigationCortexTests(unittest.TestCase):
    def test_static_match_remains_a_candidate(self) -> None:
        graph = investigator.build_investigation([{
            "ref": "F1", "rule_id": "code.sql-string-format", "title": "SQL query built from input",
            "class_id": "sqli", "severity": "high", "confidence": "high",
            "file_path": "app.py", "snippet": "query = 'SELECT ' + value",
        }])
        item = graph["hypotheses"][0]
        self.assertEqual(item["status"], "candidate")
        self.assertEqual(item["decision"], "gather-proof")
        self.assertFalse(item["report_ready"])
        self.assertIn("differential", item["next_action"])

    def test_typed_differential_can_be_report_ready(self) -> None:
        finding = {
            "ref": "F1", "rule_id": "active.sqli", "title": "SQL injection differential",
            "class_id": "sqli", "severity": "high", "confidence": "high",
            "location": "https://app.example/api/search",
        }
        plans = {"F1": {"proof_of_impact": {
            "status": "confirmed", "method": "GET parameter differential",
            "observed_result": "true condition returned 17 rows",
            "control_result": "false condition returned 0 rows",
        }}}
        graph = investigator.build_investigation([finding], plans)
        item = graph["hypotheses"][0]
        self.assertEqual(item["status"], "confirmed")
        self.assertIn("observed-control-differential", item["artifacts"])
        self.assertTrue(item["report_ready"])
        self.assertEqual(graph["metrics"]["report_ready"], 1)

    def test_confirmation_prose_without_artifact_is_blocked(self) -> None:
        finding = {
            "ref": "F1", "rule_id": "web.cors", "title": "CORS",
            "class_id": "cors", "severity": "high", "confidence": "high",
            "location": "https://app.example/api/me",
        }
        plans = {"F1": {"proof_of_impact": {
            "status": "confirmed", "evidence": "The model says an attacker can read all records.",
        }}}
        graph = investigator.build_investigation([finding], plans)
        item = graph["hypotheses"][0]
        self.assertEqual(item["status"], "contradicted")
        self.assertEqual(item["decision"], "resolve-contradiction")
        self.assertFalse(item["report_ready"])
        self.assertEqual(graph["contradictions"][0]["code"], "confirmation-without-artifact")

    # The regression that shipped: the check above only covered a claim with ZERO artifacts.
    # Every passive web finding carries request_line + response_status, which the cortex counted
    # as a typed artifact while the canonical confirm gate deliberately refuses it -- so one
    # passive GET plus brain prose printed "confirmed / report-ready" for a missing header.
    PASSIVE_HEADER_FINDING = {
        "ref": "F1", "rule_id": "web.missing-header.x-frame-options",
        "title": "Missing X-Frame-Options", "severity": "low", "confidence": "high",
        "location": "https://app.example/",
        "proof_evidence": {"request_line": "GET https://app.example/", "response_status": "HTTP 200"},
    }

    def test_prose_confirmation_over_a_passive_request_is_blocked(self) -> None:
        plans = {"F1": {"proof_of_impact": {
            "status": "confirmed", "observed_result": "", "control_result": "",
            "summary": "Clickjacking confirmed on the login page.",
        }}}
        graph = investigator.build_investigation([dict(self.PASSIVE_HEADER_FINDING)], plans)
        item = graph["hypotheses"][0]
        self.assertTrue(item["artifacts"])  # it DOES have a typed artifact...
        self.assertNotEqual(item["status"], "confirmed")  # ...which still cannot confirm it
        self.assertFalse(item["report_ready"])
        self.assertEqual(item["decision"], "resolve-contradiction")
        self.assertEqual(graph["metrics"]["confirmed"], 0)
        self.assertEqual(graph["metrics"]["report_ready"], 0)
        self.assertTrue(any(row["code"] == "confirmation-without-artifact" for row in graph["contradictions"]))

    def test_a_passive_request_alone_cannot_reach_the_supported_band(self) -> None:
        """Proving a GET happened is a lead. It used to score 86/100 and read "supported"."""
        graph = investigator.build_investigation([dict(self.PASSIVE_HEADER_FINDING)])
        item = graph["hypotheses"][0]
        self.assertEqual(item["status"], "candidate")
        self.assertLess(item["confidence_score"], investigator._SUPPORTED_THRESHOLD)
        self.assertEqual(graph["metrics"]["supported"], 0)

    def test_a_live_public_client_key_is_not_a_validated_credential(self) -> None:
        """A live Google/Firebase browser key answering its own issuer is expected behaviour.
        The canonical gate refuses it, so the cortex must not weight it as validation."""
        graph = investigator.build_investigation([{
            "ref": "F1", "rule_id": "secret.google_api_key", "class_id": "secrets",
            "title": "Google API key", "severity": "info", "confidence": "high",
            "secret_classification": "public_client_key", "_credential_proof": {"live": True},
        }])
        item = graph["hypotheses"][0]
        self.assertNotIn("live-credential-validation", item["artifacts"])
        self.assertNotEqual(item["status"], "confirmed")
        self.assertLess(item["confidence_score"], investigator._SUPPORTED_THRESHOLD)

    def test_a_public_client_key_claimed_confirmed_raises_the_conflict(self) -> None:
        """Classification forces these classes to info/low, so a severity test never fires on
        the mainline path -- the claimed confirmation is the reachable conflict."""
        graph = investigator.build_investigation(
            [{
                "ref": "F1", "rule_id": "secret.google_api_key", "class_id": "secrets",
                "title": "Google API key", "severity": "info", "confidence": "high",
                "secret_classification": "public_client_key", "_credential_proof": {"live": True},
            }],
            {"F1": {"proof_of_impact": {"status": "confirmed"}}},
        )
        self.assertTrue(any(row["code"] == "secret-severity-conflict" for row in graph["contradictions"]))
        self.assertFalse(graph["hypotheses"][0]["report_ready"])

    def test_a_malformed_location_does_not_abort_the_report(self) -> None:
        """urlparse raises on a bad authority; this runs at report-writing time on a finished
        hunt, so an escape here would discard the whole run.

        The two findings MUST be of chainable classes: _location_scope is only reached from the
        chain builder, so a fixture of two same-class findings passes with the guard removed.
        """
        for location in ("https://app.example]/x", "http://[foo]/x", "https://[app.example/x"):
            with self.subTest(location=location):
                graph = investigator.build_investigation([
                    {"ref": "F1", "class_id": "disclosure", "title": "Directory listing",
                     "severity": "low", "confidence": "high", "location": location},
                    {"ref": "F2", "class_id": "access-control", "title": "Sequential object id",
                     "severity": "medium", "confidence": "high", "location": location},
                ])
                self.assertEqual(len(graph["hypotheses"]), 2)

    def test_a_chain_of_unproven_leads_stays_a_projection(self) -> None:
        """Averaging node confidence and adding the same-scope bonus must not lift a chain into
        a band none of its nodes earned -- two capped leads used to average out to 59."""
        graph = investigator.build_investigation([
            {"ref": "F1", "class_id": "disclosure", "title": "Directory listing",
             "severity": "low", "confidence": "high", "location": "https://app.example/files"},
            {"ref": "F2", "class_id": "access-control", "title": "Sequential object id",
             "severity": "medium", "confidence": "high", "location": "https://app.example/api/1"},
        ])
        self.assertTrue(graph["attack_chains"])
        for chain in graph["attack_chains"]:
            self.assertEqual(chain["status"], "candidate")
            self.assertLessEqual(chain["confidence_score"], investigator._UNPROVEN_CONFIDENCE_CEILING)

    def test_leads_stay_rankable_against_each_other(self) -> None:
        """The ranked queue is the cortex's deliverable precisely when nothing is confirmed yet.
        Clipping every unproven lead to the ceiling collapsed the order into input order."""
        graph = investigator.build_investigation([
            {"ref": "F1", "class_id": "disclosure", "title": "Directory listing", "severity": "medium",
             "confidence": "high", "location": "https://app.example/files/",
             "proof_evidence": {"request_line": "GET https://app.example/files/", "response_status": "HTTP 200",
                                "response_body": "index of /files\nbackup.sql\ncustomers.csv"}},
            {"ref": "F2", "class_id": "headers", "title": "Missing Referrer-Policy", "severity": "low",
             "confidence": "high", "location": "https://app.example/"},
            {"ref": "F3", "class_id": "sqli", "title": "String-built query", "severity": "high",
             "confidence": "low", "file_path": "app.py", "snippet": "q = 'SELECT ' + v"},
        ])
        scores = {item["ref"]: item["confidence_score"] for item in graph["hypotheses"]}
        self.assertGreater(scores["F1"], scores["F2"], f"captured body must outrank a bare GET: {scores}")
        self.assertGreater(scores["F2"], scores["F3"], f"a captured GET must outrank a static match: {scores}")
        for ref, score in scores.items():
            self.assertLess(score, investigator._SUPPORTED_THRESHOLD, ref)

    def test_a_confirmed_claim_on_one_carrier_cannot_borrow_another_carriers_proof(self) -> None:
        """The gate must be applied to the SAME proof the status is read from. Evaluating it
        across every carrier is more permissive than the report: a bare `confirmed` on
        `_active_proof` would borrow the differential sitting on the plan's proof."""
        finding = {"ref": "F1", "class_id": "sqli", "severity": "high", "confidence": "high",
                   "_active_proof": {"status": "confirmed", "observed_result": "something"}}
        plans = {"F1": {"proof_of_impact": {
            "status": "candidate", "observed_result": "o", "control_result": "c"}}}
        item = investigator.build_investigation([finding], plans)["hypotheses"][0]
        self.assertNotEqual(item["status"], "confirmed")
        self.assertFalse(item["report_ready"])

    def test_the_report_proof_vocabulary_is_honoured(self) -> None:
        """A prover writing "verified" beside a real differential rendered Confirmed in the
        report but only "supported" in the brief -- the mirror image of the drift above."""
        for word in ("verified", "proven", "reproduced"):
            with self.subTest(status=word):
                graph = investigator.build_investigation(
                    [{"ref": "F1", "class_id": "sqli", "title": "SQLi", "severity": "high",
                      "confidence": "high", "location": "https://app.example/api"}],
                    {"F1": {"proof_of_impact": {
                        "status": word,
                        "observed_result": "true condition returned 17 rows",
                        "control_result": "false condition returned 0 rows",
                    }}},
                )
                item = graph["hypotheses"][0]
                self.assertEqual(item["status"], "confirmed")
                self.assertTrue(item["report_ready"])

    def test_a_synthesized_ref_never_collides_with_an_explicit_one(self) -> None:
        graph = investigator.build_investigation([{"ref": "H2", "title": "a"}, {"title": "b"}, {"title": "c"}])
        refs = [item["ref"] for item in graph["hypotheses"]]
        self.assertEqual(len(set(refs)), len(refs))

    def test_a_non_finite_score_does_not_empty_the_probe_queue(self) -> None:
        """json.loads accepts a bare Infinity from a model reply; int() then raises OverflowError."""
        rows = investigator.build_probe_hypotheses({"probe_priority": [
            {"endpoint": "/a", "classes": ["idor"], "score": float("inf")},
            {"endpoint": "/b", "classes": ["xss"], "score": 90},
        ]})
        self.assertEqual({row["endpoint"] for row in rows}, {"/a", "/b"})

    def test_identical_control_is_not_a_differential(self) -> None:
        finding = {"ref": "F1", "class_id": "xss", "severity": "medium", "confidence": "high"}
        plans = {"F1": {"proof_of_impact": {
            "status": "confirmed", "observed_result": "HTTP 200 marker absent",
            "control_result": "HTTP   200 marker absent",
        }}}
        graph = investigator.build_investigation([finding], plans)
        self.assertEqual(graph["hypotheses"][0]["status"], "contradicted")
        self.assertTrue(any(row["code"] == "non-differential-control" for row in graph["contradictions"]))

    def test_secret_classification_conflict_is_explicit(self) -> None:
        graph = investigator.build_investigation([{
            "ref": "F1", "rule_id": "secret.google-api-key", "category": "secret",
            "title": "Browser API key", "severity": "high", "confidence": "high",
            "secret_classification": "public_client_key", "file_path": "public/app.js",
        }])
        self.assertTrue(any(row["code"] == "secret-severity-conflict" for row in graph["contradictions"]))
        self.assertEqual(graph["hypotheses"][0]["status"], "contradicted")

    def test_attack_chain_correlates_real_refs(self) -> None:
        findings = [
            {"ref": "F1", "class_id": "disclosure", "severity": "medium", "confidence": "high",
             "title": "Leaked object ids", "location": "https://app.example/api/debug"},
            {"ref": "F2", "class_id": "access-control", "severity": "high", "confidence": "medium",
             "title": "Object authorization lead", "location": "https://app.example/api/orders/1"},
        ]
        graph = investigator.build_investigation(findings)
        self.assertTrue(graph["attack_chains"])
        self.assertTrue(all(item["chain_candidate"] for item in graph["hypotheses"]))

        # The two-step chain: the disclosure is what makes the authorization lead reachable
        # WITHOUT an account, so it must be step 1 and the object read step 2.
        chained = next(c for c in graph["attack_chains"] if set(c["refs"]) == {"F1", "F2"})
        self.assertEqual([s["evidence_ref"] for s in chained["steps"]], ["F1", "F2"])
        self.assertEqual([s["n"] for s in chained["steps"]], [1, 2])
        self.assertIn("unauthenticated", chained["entry"].lower())
        self.assertIn("another tenant", chained["projected_impact"].lower())

    def test_chain_ids_never_collide_with_finding_refs(self) -> None:
        """A campaign pools findings under C1..Cn, and the cortex renumbered chains into the
        same namespace — so a span report printed "chain C1 cites C1", naming two unrelated
        things in one sentence. The chain side is the ephemeral one, so it is the one that moved.
        """
        findings = [
            {"ref": "C1", "class_id": "disclosure", "severity": "medium", "confidence": "high",
             "title": "Leaked object ids", "location": "https://app.example/api/debug"},
            {"ref": "C2", "class_id": "access-control", "severity": "high", "confidence": "medium",
             "title": "Object authorization lead", "location": "https://app.example/api/orders/1"},
        ]
        graph = investigator.build_investigation(findings)
        self.assertTrue(graph["attack_chains"])
        chain_ids = {c["id"] for c in graph["attack_chains"]}
        self.assertTrue(chain_ids.isdisjoint({f["ref"] for f in findings}))
        for chain_id in chain_ids:
            self.assertTrue(chain_id.startswith("AC"), chain_id)

    def test_a_downgraded_chain_is_never_described_as_packageable(self) -> None:
        """Every STEP captured an artifact, but the cited finding's own evidence is not sound,
        so the cortex refuses to call the chain confirmed. The engine's "package the chain as
        one report" line must not survive that downgrade — the guard used to cover only the
        `blocked` case, so this one still invited the submission."""
        # A secret whose severity conflicts with its classification: the confirm gate accepts
        # the artifact, the cortex marks the hypothesis contradicted.
        graph = investigator.build_investigation([{
            "ref": "F1", "class_id": "sqli", "severity": "high", "confidence": "high",
            "title": "SQL injection", "location": "https://app.example/r",
            "proof_of_impact": {
                "status": "confirmed",
                "observed_result": "the boolean differential held across ten requests",
                "control_result": "the control value returned the unmodified page",
            },
        }])
        for chain in graph["attack_chains"]:
            if chain["status"] == "confirmed":
                continue
            self.assertNotIn("package the chain as one report", chain["next_action"].lower(),
                             f"{chain['id']} is {chain['status']} but reads as submittable")

        # Pin the decision itself, so the guard is exercised whether or not a fixture happens
        # to reach the clamp. `blocking_step == 0` is the engine saying every step is proven.
        engine_chain = {
            "next_action": "Every step is backed by a captured artifact — package the chain as one report.",
            "blocking_step": 0,
        }
        by_ref = {"F1": {"status": "supported", "next_action": "Capture the second role's response."}}
        for status in ("supported", "candidate", "blocked"):
            with self.subTest(status=status):
                action = investigator._chain_next_action(engine_chain, status, ["F1"], by_ref)
                self.assertNotIn("package the chain", action.lower())
        self.assertEqual(
            investigator._chain_next_action(engine_chain, "confirmed", ["F1"], by_ref),
            engine_chain["next_action"], "a genuinely confirmed chain keeps the engine's action")
        # A partial chain's action is its blocking step's own instruction, which is more
        # specific than anything the cortex could write — it must survive untouched.
        partial = {"next_action": "Read document.cookie in a TEST account.", "blocking_step": 2}
        self.assertEqual(
            investigator._chain_next_action(partial, "supported", ["F1"], by_ref),
            partial["next_action"])

    def test_chain_reports_the_same_impact_once_per_distinct_attack(self) -> None:
        """The same object read is reachable two ways here — unauthenticated via the
        disclosure, or directly with an account. Those are different attacks with different
        prerequisites, so both are worth reporting; neither may be listed twice."""
        graph = investigator.build_investigation([
            {"ref": "F1", "class_id": "disclosure", "severity": "medium", "confidence": "high",
             "title": "Leaked object ids", "location": "https://app.example/api/debug"},
            {"ref": "F2", "class_id": "access-control", "severity": "high", "confidence": "medium",
             "title": "Object authorization lead", "location": "https://app.example/api/orders/1"},
        ])
        signatures = [tuple(s["technique_id"] for s in c["steps"]) for c in graph["attack_chains"]]
        self.assertEqual(len(signatures), len(set(signatures)), f"duplicate chains: {signatures}")
        entries = {c["entry"] for c in graph["attack_chains"]}
        self.assertGreater(len(entries), 1, "the two routes have different attacker prerequisites")

    def test_signal_only_chain_is_routed_to_probes_not_reported(self) -> None:
        """Nothing was observed broken, so it is a test plan. Deleting this routing prints an
        account-takeover chain citing no finding at all."""
        graph = investigator.build_investigation(
            [], surface={"forms": [{"action": "https://a.test/u", "method": "POST",
                                    "params": ["email", "is_admin"]}]})
        self.assertEqual(graph["attack_chains"], [])
        self.assertTrue(graph["chain_probes"])
        self.assertTrue(all(p["status"] == "untested" for p in graph["chain_probes"]))
        self.assertEqual(graph["metrics"]["chain_probes"], len(graph["chain_probes"]))

    def test_chain_never_reads_stronger_than_the_findings_it_cites(self) -> None:
        """The chain layer asks "did every step capture an artifact?", the cortex asks "is this
        finding's evidence sound?". A finding can pass the first and fail the second, and the
        chain must not then render as confirmed above a hypothesis queue that says candidate."""
        graph = investigator.build_investigation([{
            "ref": "F1", "class_id": "sqli", "title": "SQL injection", "severity": "high",
            "confidence": "high", "location": "https://app.example/r",
            # A real differential (so the chain layer proves the step) paired with a claimed
            # status the cortex will not accept as confirmation.
            "proof_of_impact": {"status": "candidate", "observed_result": "true/false differential",
                                "control_result": "baseline response"},
        }])
        hypothesis = graph["hypotheses"][0]
        for chain in graph["attack_chains"]:
            if "F1" not in chain["refs"]:
                continue
            if hypothesis["status"] != "confirmed":
                self.assertNotEqual(chain["status"], "confirmed",
                                    f"chain outran its finding: {chain['status']} vs {hypothesis['status']}")
                self.assertLessEqual(chain["confidence_score"],
                                     investigator._UNPROVEN_CONFIDENCE_CEILING)

    def test_a_blocked_chain_is_never_described_as_submittable(self) -> None:
        graph = investigator.build_investigation([{
            "ref": "F1", "rule_id": "secret.google-api-key", "category": "secret",
            "title": "Browser API key", "severity": "high", "confidence": "high",
            "secret_classification": "public_client_key", "file_path": "public/app.js",
            "proof_of_impact": {"status": "confirmed", "observed_result": "live", "control_result": "dead"},
        }])
        self.assertEqual(graph["hypotheses"][0]["status"], "contradicted")
        for chain in graph["attack_chains"]:
            if "F1" in chain["refs"]:
                self.assertEqual(chain["status"], "blocked")
                self.assertNotIn("package", chain["next_action"].lower())

    def test_probe_plan_becomes_explicit_evidence_queue(self) -> None:
        plan = {"probe_priority": [{
            "endpoint": "https://app.example/download?file=x",
            "classes": ["path-traversal", "xss"], "why": "file parameter", "score": 120,
        }]}
        first = investigator.build_probe_hypotheses(plan)
        self.assertEqual(first, investigator.build_probe_hypotheses(plan))
        self.assertEqual(first[0]["endpoint"], plan["probe_priority"][0]["endpoint"])
        self.assertEqual(first[0]["status"], "untested")
        self.assertTrue(first[0]["evidence_required"])
        self.assertGreater(first[0]["likelihood_score"], first[1]["likelihood_score"])

    def test_malformed_input_is_bounded_and_safe(self) -> None:
        graph = investigator.build_investigation([None, "bad", {"severity": {"x": 1}}], {"H3": 7})
        self.assertEqual(graph["algorithm"], investigator.ALGORITHM_VERSION)
        self.assertLessEqual(len(graph["hypotheses"]), investigator._MAX_HYPOTHESES)


class InvestigationReportTests(unittest.TestCase):
    def test_report_and_json_carry_the_same_investigation(self) -> None:
        finding = {
            "ref": "F1", "rule_id": "active.sqli", "title": "SQL injection",
            "class_id": "sqli", "class_name": "SQL injection", "severity": "high",
            "confidence": "high", "location": "https://app.example/search",
        }
        plans = {"F1": {"steps": ["Send a benign true/false differential."], "proof_of_impact": {
            "status": "confirmed", "method": "differential",
            "observed_result": "true condition changed row count",
            "control_result": "false condition did not change row count",
        }}}
        investigation = investigator.build_investigation([finding], plans)
        ctx = {
            "tool": "GreyIQ BugHunter", "version": "test", "target": "https://app.example",
            "profile": {"name": "Test"}, "risk": "high", "score": 0.8,
            "findings": [finding], "attack_plans": plans, "scanners_run": ["active"],
            "authorized": True, "brain": {}, "investigation": investigation,
            "next_steps": [], "coverage": {},
        }
        markdown = report.build_markdown(ctx)
        sidecar = report.build_json(ctx)
        self.assertIn("## Investigation intelligence", markdown)
        self.assertIn("Ranked hypothesis queue", markdown)
        self.assertEqual(sidecar["investigation"], investigation)

    def test_malformed_advisory_metrics_do_not_break_report(self) -> None:
        ctx = {
            "profile": {"name": "Test"}, "findings": [], "attack_plans": {},
            "scanners_run": [], "brain": {}, "next_steps": [], "coverage": {},
            "investigation": {
                "verdict": {"bad": True},
                "metrics": {"confirmed": "many", "average_confidence": {"bad": True}},
                "hypotheses": [], "attack_chains": [], "contradictions": [],
            },
        }
        markdown = report.build_markdown(ctx)
        self.assertIn("0 confirmed", markdown)
        self.assertIn("confidence 0/100", markdown)


if __name__ == "__main__":
    unittest.main()
