"""The lead bridge (bughunter.leads): a hunt's investigation queue exported as a redaction-safe,
stable hand-off for an analyst or a configured Claude brain.

These tests pin three things that matter for a hand-off that LEAVES the machine:
  1. Shape stability — the queue is built from the real report.build_json sidecar, and a consumer
     can rely on the documented per-lead fields (proof obligation, contradictions joined by ref,
     chain membership).
  2. Redaction — a secret planted anywhere a producer might leave one raw (source_text, a raw
     _credential_proof poc, a token in an observed_result, a snippet) must NOT survive into the
     exported queue OR the rendered brief. This is the allowlist's whole job.
  3. Fail-soft — malformed, empty, and non-hunt inputs degrade to an empty result, never a raise.

The end-to-end test runs a genuine build_json over a hand-built ctx, so the projection is exercised
against the actual sidecar schema rather than a mock of it."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import investigator, leads  # noqa: E402
from bughunter import report as report_lib  # noqa: E402

# A live-looking secret used to prove redaction. gh-token shape is in redaction.py's vendor patterns.
_SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _build_sidecar(findings: list[dict], attack_plans: dict) -> dict:
    """Produce a real JSON sidecar the way a hunt does: run the cortex, then build_json."""
    for i, f in enumerate(findings, 1):
        f.setdefault("ref", f"F{i}")
    investigation = investigator.build_investigation(findings, attack_plans)
    ctx = {
        "tool": "GreyIQ BugHunter", "version": "9.9.9", "generated_at": "2026-09-03 00:00 UTC",
        "target": "https://app.example.com", "scope": "*.example.com", "authorized": True,
        "scanners_run": ["web", "live"], "risk": "high", "score": 70,
        "findings": findings, "attack_plans": attack_plans, "investigation": investigation,
        "next_steps": [], "profile": {"id": "web-app", "name": "Web app"},
    }
    return report_lib.build_json(ctx)


def _confirmed_idor() -> tuple[list[dict], dict]:
    finding = {
        "ref": "F1", "title": "IDOR on /api/account/{id}/export", "class_id": "access-control",
        "severity": "high", "confidence": "high", "rule_id": "active.idor",
        "location": "https://app.example.com/api/account/1001/export",
        "proof_evidence": {
            "request_line": "GET /api/account/1001/export HTTP/1.1",
            "response_status": "HTTP 200",
            "sensitive_data_labels": "email address(es)",
        },
    }
    plan = {
        "cvss": {"vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "base_score": 6.5, "base_severity": "Medium"},
        "proof_of_impact": {
            "status": "confirmed",
            "observed_result": "HTTP 200 — account 1001's export was returned to the account-42 session",
            "control_result": "HTTP 403 — account 42's own id was refused, so the read is not public",
            "proof_obligation": "Replay as a lower-privilege actor and capture the authorized-vs-unauthorized differential.",
        },
    }
    return [finding], {"F1": plan}


class QueueShapeTests(unittest.TestCase):
    def test_unconfirmed_lead_shows_prediction_control_and_stop_in_operator_brief(self) -> None:
        doc = _build_sidecar([{
            "ref": "F1", "title": "Reflected input", "class_id": "xss",
            "severity": "medium", "confidence": "medium",
            "location": "https://app.example.com/search",
        }], {})
        report = leads.build_lead_report_from_doc(doc)
        lead = report["hunts"][0]["leads"][0]
        self.assertNotEqual(lead["status"], "confirmed")
        for key in ("predicted_positive_signal", "negative_control", "falsifier_stop_condition"):
            self.assertTrue(lead[key], key)
        brief = leads.render_lead_brief(report, wrap=False)
        self.assertIn("Predicted positive signal", brief)
        self.assertIn("Negative control", brief)
        self.assertIn("Falsifier / stop", brief)

    def test_confirmed_lead_projects_the_documented_fields(self) -> None:
        findings, plans = _confirmed_idor()
        doc = _build_sidecar(findings, plans)
        report = leads.build_lead_report_from_doc(doc)
        self.assertEqual(report["schema"], leads.SCHEMA_VERSION)
        self.assertEqual(len(report["hunts"]), 1)
        queue = report["hunts"][0]
        self.assertEqual(queue["hunt"]["target"], "https://app.example.com")
        lead = queue["leads"][0]
        for key in ("id", "kind", "title", "class_id", "severity", "status", "confidence_score",
                    "confidence_band", "priority_score", "rank", "decision", "report_ready",
                    "proof_obligation", "contradictions", "in_chains", "evidence"):
            self.assertIn(key, lead)
        self.assertEqual(lead["status"], "confirmed")
        self.assertTrue(lead["report_ready"])
        self.assertEqual(lead["evidence"]["proof_status"], "confirmed")
        self.assertIn("email address", lead["evidence"]["sensitive_data_labels"])

    def test_contradiction_is_joined_onto_its_lead(self) -> None:
        # An identical observed/control pair → the cortex raises a blocking contradiction; the
        # queue must carry it inline on the lead, so an analyst sees the problem without a join.
        finding = {"ref": "F1", "title": "Bogus confirm", "class_id": "xss", "severity": "medium",
                   "confidence": "high"}
        plan = {"proof_of_impact": {"status": "confirmed",
                                    "observed_result": "HTTP 200 marker absent",
                                    "control_result": "HTTP   200 marker absent"}}
        doc = _build_sidecar([finding], {"F1": plan})
        queue = leads.build_lead_report_from_doc(doc)["hunts"][0]
        lead = queue["leads"][0]
        self.assertEqual(lead["status"], "contradicted")
        codes = {c["code"] for c in lead["contradictions"]}
        self.assertIn("non-differential-control", codes)
        self.assertTrue(any(c["blocking"] for c in lead["contradictions"]))
        self.assertFalse(lead["report_ready"])

    def test_chain_membership_is_cross_linked(self) -> None:
        findings = [
            {"ref": "F1", "class_id": "disclosure", "severity": "medium", "confidence": "high",
             "title": "Leaked object ids", "location": "https://app.example.com/api/debug"},
            {"ref": "F2", "class_id": "access-control", "severity": "high", "confidence": "medium",
             "title": "Object authorization lead", "location": "https://app.example.com/api/orders/1"},
        ]
        doc = _build_sidecar(findings, {})
        queue = leads.build_lead_report_from_doc(doc)["hunts"][0]
        self.assertTrue(queue["attack_chains"])
        chain_ids = {c["id"] for c in queue["attack_chains"]}
        linked = {cid for lead in queue["leads"] for cid in lead["in_chains"]}
        self.assertTrue(linked & chain_ids)


class RedactionTests(unittest.TestCase):
    def test_planted_secrets_never_reach_the_queue_or_brief(self) -> None:
        finding = {
            "ref": "F1", "title": f"Token {_SECRET} in body", "class_id": "secrets",
            "severity": "high", "confidence": "high", "rule_id": "web.exposed.token",
            "location": "https://app.example.com/app.js",
            # Every raw carrier a producer might leave un-scrubbed:
            "secret_value": _SECRET,
            "source_text": f"...config = {{ apiToken: '{_SECRET}' }} ...",
            "snippet": f"const t = '{_SECRET}'",
            "_credential_proof": {"poc": f"curl -H 'Authorization: Bearer {_SECRET}' https://api", "live": False},
            "proof_evidence": {"matched_value": _SECRET, "read_data": f"body with {_SECRET} inside",
                               "request_line": "GET /app.js HTTP/1.1", "response_status": "HTTP 200"},
        }
        plan = {"proof_of_impact": {"status": "candidate",
                                    "observed_result": f"the response contained {_SECRET}",
                                    "control_result": "a request without the path returned nothing"}}
        doc = _build_sidecar([finding], {"F1": plan})
        report = leads.build_lead_report_from_doc(doc)
        blob = json.dumps(report, default=str)
        self.assertNotIn(_SECRET, blob, "raw secret leaked into the exported lead queue")
        brief = leads.render_lead_brief(report, wrap=True)
        self.assertNotIn(_SECRET, brief, "raw secret leaked into the investigation brief")
        # The brief must be wrapped as untrusted data for a model.
        self.assertIn("UNTRUSTED", brief.upper())

    def test_credential_in_the_target_url_is_not_exported(self) -> None:
        """Operator-supplied metadata is a real leak path: a hunt is routinely started against a
        signed URL or an OAuth callback carrying ?token=... . That value reaches `doc["target"]`
        verbatim, and the queue AND the model-bound brief both render it."""
        findings, plans = _confirmed_idor()
        doc = _build_sidecar(findings, plans)
        doc["target"] = f"https://app.example.com/cb?token={_SECRET}"
        doc["scope"] = f"in scope: https://app.example.com/cb?token={_SECRET}"
        report = leads.build_lead_report_from_doc(doc, source_path=f"/tmp/hunt?key={_SECRET}.json")
        self.assertNotIn(_SECRET, json.dumps(report, default=str))
        self.assertNotIn(_SECRET, leads.render_lead_brief(report, wrap=True))

    def test_plan_supplied_proof_obligation_is_scrubbed(self) -> None:
        """The cortex copies a plan's proof_of_impact.proof_obligation through verbatim into
        hypotheses[].next_action and .gaps, and service/brain-built plans interpolate live URLs and
        captured text into it with no redaction at the source."""
        findings, plans = _confirmed_idor()
        plans["F1"]["proof_of_impact"]["proof_obligation"] = (
            f"Replay with the captured session token {_SECRET} against /api/account/1001/export."
        )
        doc = _build_sidecar(findings, plans)
        report = leads.build_lead_report_from_doc(doc)
        lead = report["hunts"][0]["leads"][0]
        self.assertNotIn(_SECRET, lead["proof_obligation"])
        self.assertNotIn(_SECRET, json.dumps(report, default=str))
        self.assertNotIn(_SECRET, leads.render_lead_brief(report, wrap=True))

    def test_export_never_mutates_the_callers_document(self) -> None:
        """The defensive secret scrub assigns INTO nested proof_evidence/_credential_proof dicts, so
        a shallow copy would rewrite the caller's own live document as a side effect of exporting."""
        findings, plans = _confirmed_idor()
        findings[0]["secret_value"] = _SECRET
        findings[0]["proof_evidence"]["matched_value"] = _SECRET
        doc = _build_sidecar(findings, plans)
        before = json.dumps(doc, default=str)
        leads.build_lead_report_from_doc(doc)
        self.assertEqual(json.dumps(doc, default=str), before)

    def test_raw_carriers_are_not_even_keys_in_the_evidence(self) -> None:
        # Allowlist, not denylist: the dangerous fields are absent by construction, not stripped.
        findings, plans = _confirmed_idor()
        findings[0]["source_text"] = "raw page source"
        findings[0]["screenshot_path"] = "/runtime/reports/x/proof-artifacts/f1.png"
        findings[0]["_credential_proof"] = {"poc": "curl ...", "response_excerpt": "raw body"}
        doc = _build_sidecar(findings, plans)
        ev = leads.build_lead_report_from_doc(doc)["hunts"][0]["leads"][0]["evidence"]
        for forbidden in ("source_text", "screenshot_path", "_credential_proof", "read_data",
                          "matched_value", "secret_value", "snippet", "response_body"):
            self.assertNotIn(forbidden, ev)


class BriefTests(unittest.TestCase):
    def test_single_ref_brief_narrows_to_one_lead(self) -> None:
        findings, plans = _confirmed_idor()
        findings.append({"ref": "F2", "title": "Second lead", "class_id": "cors",
                         "severity": "low", "confidence": "low"})
        doc = _build_sidecar(findings, plans)
        report = leads.build_lead_report_from_doc(doc)
        brief = leads.render_lead_brief(report, ref="F1", wrap=False)
        self.assertIn("F1", brief)
        self.assertNotIn("Second lead", brief)

    def test_brief_includes_untested_chain_probes(self) -> None:
        """Chain probes are untested, signal-only or drift-reopened leads. They are never evidence,
        but on a hunt whose findings are all inert they can be the only actionable rows — so the
        brief must carry them, clearly labelled as probes rather than results."""
        findings, plans = _confirmed_idor()
        doc = _build_sidecar(findings, plans)
        doc["investigation"]["chain_probes"] = [{
            "id": "CP1", "title": "Mass assignment via is_admin",
            "hypothesis": "The signup form carries an is_admin field.",
            "impact": "privilege escalation", "next_action": "Submit the form with is_admin=true as a test user.",
            "signals": ["role-like field"], "status": "untested",
        }]
        brief = leads.render_lead_brief(leads.build_lead_report_from_doc(doc), wrap=False)
        self.assertIn("CP1", brief)
        self.assertIn("Mass assignment", brief)
        self.assertIn("nothing here is evidence", brief)

    def test_generated_chain_probe_discriminator_survives_operator_export(self) -> None:
        doc = _build_sidecar([], {})
        doc["investigation"] = investigator.build_investigation(
            [], surface={"forms": [{"action": "https://app.example.com/u", "method": "POST",
                                   "params": ["email", "is_admin"]}]})
        report = leads.build_lead_report_from_doc(doc)
        self.assertTrue(report["hunts"][0]["chain_probes"])
        probe = report["hunts"][0]["chain_probes"][0]
        self.assertTrue(probe["predicted_positive_signal"])
        self.assertTrue(probe["negative_control"])
        self.assertTrue(probe["falsifier_stop_condition"])
        brief = leads.render_lead_brief(report, wrap=False)
        self.assertIn("Predicted positive signal", brief)
        self.assertIn("Falsifier / stop", brief)

    def test_ref_can_select_a_chain_probe(self) -> None:
        """Probes carry their own id namespace (CP*/CR*). Narrowing on leads alone made
        `--ref CP1` report "No leads found" for a probe sitting right there in the queue."""
        findings, plans = _confirmed_idor()
        doc = _build_sidecar(findings, plans)
        doc["investigation"]["chain_probes"] = [{
            "id": "CP1", "title": "Mass assignment via is_admin",
            "hypothesis": "The signup form carries an is_admin field.",
            "impact": "privilege escalation", "next_action": "Submit with is_admin=true as a test user.",
            "signals": [], "status": "untested",
        }]
        report = leads.build_lead_report_from_doc(doc)
        brief = leads.render_lead_brief(report, ref="CP1", wrap=False)
        self.assertIn("CP1", brief)
        self.assertIn("Mass assignment", brief)
        self.assertNotIn("No leads found", brief)
        self.assertNotIn("F1", brief)  # the finding is not selected by this ref

    def test_brief_renders_only_the_probes_it_is_given(self) -> None:
        """The brief must not re-read the raw queue: a caller that filtered (e.g. --status
        confirmed) would otherwise still get every untested probe rendered."""
        findings, plans = _confirmed_idor()
        doc = _build_sidecar(findings, plans)
        doc["investigation"]["chain_probes"] = [
            {"id": "CP1", "title": "Untested lead", "hypothesis": "h", "impact": "i",
             "next_action": "n", "signals": [], "status": "untested"},
        ]
        report = leads.build_lead_report_from_doc(doc)
        # Simulate the CLI having filtered probes out (--status confirmed).
        report["hunts"][0]["chain_probes"] = []
        brief = leads.render_lead_brief(report, wrap=False)
        self.assertNotIn("CP1", brief)
        self.assertNotIn("nothing here is evidence", brief)  # section omitted entirely
        self.assertIn("F1", brief)                            # the confirmed lead still renders

    def test_brief_names_the_proof_obligation(self) -> None:
        findings, plans = _confirmed_idor()
        doc = _build_sidecar(findings, plans)
        brief = leads.render_lead_brief(leads.build_lead_report_from_doc(doc), wrap=False)
        self.assertIn("To confirm", brief)


class LoaderTests(unittest.TestCase):
    def test_is_hunt_sidecar_rejects_other_shapes(self) -> None:
        self.assertTrue(leads.is_hunt_sidecar({"findings": [], "attack_plans": {}, "investigation": {}}))
        self.assertFalse(leads.is_hunt_sidecar({"findings": [], "attack_plans": {}}))  # confirm-route sidecar
        self.assertFalse(leads.is_hunt_sidecar({"per_target": [], "chain_locations": []}))  # span.json
        self.assertFalse(leads.is_hunt_sidecar({}))
        self.assertFalse(leads.is_hunt_sidecar("nope"))

    def test_directory_sweep_finds_bounty_sidecars(self) -> None:
        findings, plans = _confirmed_idor()
        doc = _build_sidecar(findings, plans)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "targets").mkdir()
            (root / "targets" / "bounty-web-app-app-20260903-000000-abcd1234.json").write_text(
                json.dumps(doc), encoding="utf-8")
            # A decoy that must NOT be ingested (no investigation graph — a confirm-route sidecar).
            (root / "takeover-app-20260903.json").write_text(
                json.dumps({"findings": [], "attack_plans": {}}), encoding="utf-8")
            report = leads.build_lead_report(str(root))
        self.assertEqual(len(report["hunts"]), 1)
        self.assertEqual(report["hunts"][0]["leads"][0]["status"], "confirmed")

    def test_missing_and_malformed_paths_fail_soft(self) -> None:
        self.assertEqual(leads.build_lead_report("C:/nope/does/not/exist.json")["hunts"], [])
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bounty-x.json"
            bad.write_text("{ not json", encoding="utf-8")
            self.assertEqual(leads.discover_sidecars(str(bad)), [bad])   # a file resolves to itself
            self.assertEqual(leads._read_json(bad), {})                  # but parses to {}
            self.assertEqual(leads.build_lead_report(str(bad))["hunts"], [])  # and yields no hunts

    def test_empty_investigation_yields_no_leads_without_raising(self) -> None:
        doc = {"findings": [], "attack_plans": {}, "investigation": {}}
        queue = leads.build_lead_queue(doc)
        self.assertEqual(queue["leads"], [])
        self.assertEqual(queue["attack_chains"], [])


if __name__ == "__main__":
    unittest.main()
