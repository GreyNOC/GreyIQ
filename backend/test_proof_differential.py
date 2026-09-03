"""The shared observed-vs-control predicate (``report.proof_is_non_differential``) and the confirm
authority that now depends on it.

An observed result paired with an IDENTICAL control is, by definition, not a differential — yet
``report._has_captured_artifact`` used to accept any proof whose two sides were merely non-empty.
The investigation cortex simultaneously flagged the same pair as a blocking contradiction, so one
report could render ``proof_status: confirmed`` (and pass ``submission.submit_to_hackerone``'s
hard gate) while its own Investigation section called the finding ``contradicted``.

These tests pin the reconciled behaviour end to end — predicate → gate → rendered status →
cortex → QA section → submission package → submit gate — and, just as importantly, pin what
must NOT change: the credential/secret confirmation routes (branch order inside the gate), and
the static source-scanning profile, whose deterministic plans carry an EMPTY pair by design and
whose severity comes from a class template. A naive ``observed == control`` fires on ``"" == ""``
and a naive "no artifact ⇒ cap" fires on every static finding; both would gut source scanning."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty  # noqa: E402
from bughunter import investigator  # noqa: E402
from bughunter import report as report_lib  # noqa: E402
from bughunter import submission  # noqa: E402

_SAME = 'HTTP/1.1 200 OK\n{"balance": 100, "owner": "victim"}'
_SAME_VARIANT = 'http/1.1   200 ok\n{"balance":   100, "owner": "VICTIM"}'
_OBSERVED = "HTTP 200 — the victim's export was returned to the attacker session"
_CONTROL = "HTTP 403 — the attacker's own id was refused, so the read is not simply public"


def _plan(observed: str, control: str, status: str = "confirmed") -> dict:
    return {"proof_of_impact": {"status": status, "observed_result": observed, "control_result": control}}


class PredicateTests(unittest.TestCase):
    """report.proof_is_non_differential — the ONE definition both authorities share."""

    def test_identical_pair_is_non_differential(self) -> None:
        self.assertTrue(report_lib.proof_is_non_differential({"observed_result": _SAME, "control_result": _SAME}))

    def test_whitespace_and_case_variants_compare_equal(self) -> None:
        # The same bytes modulo run-length whitespace and case are the same observation.
        self.assertTrue(report_lib.proof_is_non_differential({"observed_result": _SAME, "control_result": _SAME_VARIANT}))

    def test_differing_pair_is_a_real_differential(self) -> None:
        self.assertFalse(report_lib.proof_is_non_differential({"observed_result": _OBSERVED, "control_result": _CONTROL}))

    def test_empty_pair_is_not_a_failed_differential(self) -> None:
        # THE static-plan default. "" == "" must read as 'nothing captured', never as 'identical'.
        self.assertFalse(report_lib.proof_is_non_differential({"observed_result": "", "control_result": ""}))
        self.assertFalse(report_lib.proof_is_non_differential({}))

    def test_one_sided_proof_is_not_non_differential(self) -> None:
        self.assertFalse(report_lib.proof_is_non_differential({"observed_result": _OBSERVED, "control_result": ""}))
        self.assertFalse(report_lib.proof_is_non_differential({"observed_result": "", "control_result": _CONTROL}))

    def test_non_dict_is_false(self) -> None:
        for value in (None, "", "confirmed", 7, [], ["a"]):
            self.assertFalse(report_lib.proof_is_non_differential(value), value)

    def test_normalize_collapses_whitespace_and_folds_case(self) -> None:
        raw = "   HTTP   200\n\tMARKER   absent   "
        self.assertEqual(report_lib.normalize_proof_text(raw), "http 200 marker absent")

    def test_equality_is_decided_on_the_whole_value_not_a_prefix(self) -> None:
        """A full HTTP/HTML capture routinely shares thousands of characters of boilerplate before
        the record that differs. Deciding "identical" from a prefix would refuse a REAL differential
        and silently downgrade a confirmed finding to candidate, so the normalization must not
        truncate into the comparison window."""
        shared = "HTTP/1.1 200 OK\n" + ("<div>boilerplate</div>\n" * 400)  # ~9 kB of common prefix
        observed = shared + "account 1001 balance 42"
        control = shared + "403 forbidden for account 42"
        self.assertNotEqual(report_lib.normalize_proof_text(observed), report_lib.normalize_proof_text(control))
        self.assertFalse(report_lib.proof_is_non_differential(
            {"observed_result": observed, "control_result": control}))
        # …and the gate therefore still ACCEPTS this genuine differential.
        self.assertTrue(report_lib._has_captured_artifact(
            {"ref": "F1"}, {"observed_result": observed, "control_result": control}))

    def test_long_identical_values_are_still_non_differential(self) -> None:
        # The other direction: length must not make an identical pair look like a differential.
        same = "HTTP/1.1 200 OK\n" + ("<div>boilerplate</div>\n" * 400)
        self.assertTrue(report_lib.proof_is_non_differential(
            {"observed_result": same, "control_result": same}))


class ConfirmGateTests(unittest.TestCase):
    """report._has_captured_artifact — the single confirm authority for the whole engine."""

    def test_identical_pair_is_refused_as_an_artifact(self) -> None:
        proof = {"status": "confirmed", "observed_result": _SAME, "control_result": _SAME}
        self.assertFalse(report_lib._has_captured_artifact({"ref": "F1"}, proof))

    def test_whitespace_variant_pair_is_refused(self) -> None:
        proof = {"status": "confirmed", "observed_result": _SAME, "control_result": _SAME_VARIANT}
        self.assertFalse(report_lib._has_captured_artifact({"ref": "F1"}, proof))

    def test_differing_pair_is_accepted(self) -> None:
        proof = {"status": "confirmed", "observed_result": _OBSERVED, "control_result": _CONTROL}
        self.assertTrue(report_lib._has_captured_artifact({"ref": "F1"}, proof))

    def test_identical_pair_does_not_veto_the_secret_hits_route(self) -> None:
        # BRANCH ORDER IS LOAD-BEARING. The identical-pair check lives ONLY in the final
        # observed/control branch. A finding confirmed by an independent route (here a
        # value-free JWT secret hit) must stay confirmed even if a junk identical pair rides
        # alongside it — a top-of-function guard clause would have vetoed real confirmations.
        finding = {"ref": "F1", "secret_hits": [{"kind": "jwt-secret-claim", "claim": "password"}]}
        proof = {"status": "confirmed", "observed_result": _SAME, "control_result": _SAME}
        self.assertTrue(report_lib._has_captured_artifact(finding, proof))

    def test_cortex_delegates_rather_than_reimplementing(self) -> None:
        # has_confirming_artifact must return exactly what the gate returns for the canonical
        # proof, for BOTH verdicts — this is the invariant whose loss caused the original drift.
        for observed, control in ((_SAME, _SAME), (_OBSERVED, _CONTROL)):
            finding = {"ref": "F1"}
            plan = _plan(observed, control)
            gate = report_lib._has_captured_artifact(finding, plan["proof_of_impact"])
            self.assertEqual(investigator.has_confirming_artifact(finding, plan), gate, (observed, control))


class RenderedStatusTests(unittest.TestCase):
    """_proof_of_impact_detail — what the report, the sidecar and the submission package read."""

    def test_identical_pair_renders_candidate_not_confirmed(self) -> None:
        detail = report_lib._proof_of_impact_detail({"ref": "F1", "class_id": "access-control"}, _plan(_SAME, _SAME))
        self.assertEqual(detail["status"], "candidate")
        self.assertFalse(detail["ready"])

    def test_differing_pair_renders_confirmed(self) -> None:
        detail = report_lib._proof_of_impact_detail({"ref": "F1", "class_id": "access-control"}, _plan(_OBSERVED, _CONTROL))
        self.assertEqual(detail["status"], "confirmed")
        self.assertTrue(detail["ready"])


class CortexAgreementTests(unittest.TestCase):
    def test_identical_pair_is_contradicted_and_never_report_ready(self) -> None:
        finding = {"ref": "F1", "class_id": "access-control", "severity": "high", "confidence": "high"}
        graph = investigator.build_investigation([finding], {"F1": _plan(_SAME, _SAME)})
        row = graph["hypotheses"][0]
        codes = {c["code"] for c in graph["contradictions"]}
        self.assertEqual(row["status"], "contradicted")
        self.assertIn("non-differential-control", codes)
        self.assertIn("confirmation-without-artifact", codes)  # the gate agrees now
        self.assertFalse(row["report_ready"])
        self.assertNotIn("observed-control-differential", row["artifacts"])
        # Something WAS observed — it just proves nothing on its own. The inventory says so
        # honestly rather than advertising a differential the gate refused.
        self.assertEqual(row["decision"], "resolve-contradiction")

    def test_differing_pair_is_confirmed_and_report_ready(self) -> None:
        finding = {"ref": "F1", "class_id": "access-control", "severity": "high", "confidence": "high"}
        graph = investigator.build_investigation([finding], {"F1": _plan(_OBSERVED, _CONTROL)})
        row = graph["hypotheses"][0]
        self.assertEqual(row["status"], "confirmed")
        self.assertTrue(row["report_ready"])
        self.assertIn("observed-control-differential", row["artifacts"])
        self.assertEqual(graph["contradictions"], [])


class QaGateClaimIntegrityTests(unittest.TestCase):
    """Q5/Q6 — class-general, informational, and provably harmless to the static profile."""

    def _issues_for(self, res: dict, needle: str) -> list[dict]:
        return [i for i in res["issues"] if needle in str(i.get("question") or "")]

    def test_non_differential_is_recorded_without_moving_severity(self) -> None:
        finding = {"ref": "F1", "class_id": "access-control", "severity": "high", "confidence": "high"}
        plan = _plan(_SAME, _SAME)
        before = report_lib.resolve_severity(finding, plan)
        res = report_lib.qa_validate_report([finding], {"F1": plan})
        rows = self._issues_for(res, "actually differ")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "no")
        self.assertEqual(rows[0]["action"], "")                     # informational
        self.assertTrue(res["ok"])                                  # never flips ok
        self.assertEqual(report_lib.resolve_severity(finding, plan), before)  # never a cap

    def test_identical_pair_records_one_bullet_not_two(self) -> None:
        # The identical pair IS the reason there is no accepted artifact; Q5 must not be
        # stacked on top of Q6 for the same root cause.
        finding = {"ref": "F1", "class_id": "xss", "severity": "medium", "confidence": "high"}
        res = report_lib.qa_validate_report([finding], {"F1": _plan(_SAME, _SAME)})
        self.assertEqual(len(self._issues_for(res, "actually differ")), 1)
        self.assertEqual(len(self._issues_for(res, "captured artifact")), 0)

    def test_claimed_confirmed_without_artifact_is_recorded(self) -> None:
        # An explicit 'confirmed' with an observation but NO control: the status ladder already
        # renders it 'candidate' silently; Q5 makes that visible to the triager.
        finding = {"ref": "F1", "class_id": "xss", "severity": "medium", "confidence": "high"}
        plan = _plan(_OBSERVED, "")
        res = report_lib.qa_validate_report([finding], {"F1": plan})
        rows = self._issues_for(res, "captured artifact")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "unsupported")
        self.assertEqual(rows[0]["action"], "")
        self.assertTrue(res["ok"])
        self.assertEqual(report_lib._proof_of_impact_detail(finding, plan)["status"], "candidate")

    def test_a_real_differential_records_nothing(self) -> None:
        finding = {"ref": "F1", "class_id": "access-control", "severity": "high", "confidence": "high"}
        res = report_lib.qa_validate_report([finding], {"F1": _plan(_OBSERVED, _CONTROL)})
        self.assertEqual(res["issues"], [])
        self.assertTrue(res["ok"])

    def test_static_sqli_profile_is_untouched(self) -> None:
        # THE GUARDRAIL. A code-scanner SQLi carries no proof_evidence and an EMPTY observed/control
        # pair, and resolves to Critical from its class template alone. It claims nothing, so the
        # class-general checks must record nothing and move nothing. If this test ever fails, a
        # 'tighten the gate' change has just gutted the entire source-scanning profile.
        finding = {
            "ref": "F1", "rule_id": "py.sqli-fstring", "category": "sqli", "class_id": "sqli",
            "severity": "high", "confidence": "medium", "file_path": "app/db.py",
            "location": "app/db.py:42", "snippet": 'cur.execute(f"SELECT * FROM t WHERE id={uid}")',
        }
        plan = bounty._deterministic_attack_plan(finding, "sqli")
        poi = plan["proof_of_impact"]
        # Pin the precondition this guardrail rests on: the deterministic plan writes an EMPTY pair.
        self.assertEqual(str(poi.get("observed_result") or ""), "")
        self.assertEqual(str(poi.get("control_result") or ""), "")
        self.assertEqual(report_lib.resolve_severity(finding, plan), "critical")

        res = report_lib.qa_validate_report([finding], {"F1": plan})
        self.assertEqual(res["issues"], [])
        self.assertTrue(res["ok"])
        self.assertEqual(report_lib.resolve_severity(finding, plan), "critical")

    def test_any_static_shaped_plan_with_an_empty_pair_is_untouched(self) -> None:
        # Independent of bounty's class table: the empty-pair invariant itself, for a
        # high-severity static lead of another class.
        finding = {"ref": "F1", "rule_id": "py.subprocess-shell", "category": "rce", "class_id": "rce",
                   "severity": "critical", "confidence": "medium", "file_path": "svc/run.py",
                   "location": "svc/run.py:9"}
        plan = {"proof_of_impact": {"status": "missing", "observed_result": "", "control_result": ""},
                "cvss": {"vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "base_score": 9.8,
                         "base_severity": "Critical", "estimated": True, "justification": "class template"}}
        res = report_lib.qa_validate_report([finding], {"F1": plan})
        self.assertEqual(res["issues"], [])
        self.assertEqual(report_lib.resolve_severity(finding, plan), "critical")

    def test_qa_section_never_contradicts_its_own_bullet(self) -> None:
        """The closing line used to be derived from the CORRECTIONS list alone, so an informational
        claim-integrity issue (verdict 'unsupported', no severity change) printed
        "All claims matched the captured evidence" directly beneath a bullet saying the opposite —
        in the one section whose purpose is showing a triager that GreyIQ audits its own claims."""
        finding = {"ref": "F1", "class_id": "xss", "severity": "medium", "confidence": "high"}
        plan = _plan(_OBSERVED, "")  # claims confirmed, no control -> Q5 fires, no correction
        ctx = {"qa": report_lib.qa_validate_report([finding], {"F1": plan})}
        out: list[str] = []
        report_lib._append_qa(out, ctx)
        rendered = "\n".join(out)
        self.assertIn("unsupported", rendered)
        self.assertNotIn("All claims matched the captured evidence", rendered)
        self.assertIn("not backed by the captured evidence", rendered)

    def test_qa_section_still_reports_a_clean_run_cleanly(self) -> None:
        finding = {"ref": "F1", "class_id": "access-control", "severity": "high", "confidence": "high"}
        ctx = {"qa": report_lib.qa_validate_report([finding], {"F1": _plan(_OBSERVED, _CONTROL)})}
        out: list[str] = []
        report_lib._append_qa(out, ctx)
        self.assertEqual(out, [])  # no issues at all -> the section is omitted entirely

    def test_issue_carries_the_live_finding_for_ref_resync(self) -> None:
        # Every new issue must go through _record so the private ``_finding`` carrier rides
        # along — bounty renumbers findings AFTER QA, and a bare ref string would misattribute.
        finding = {"ref": "F1", "class_id": "xss", "severity": "medium", "confidence": "high"}
        res = report_lib.qa_validate_report([finding], {"F1": _plan(_SAME, _SAME)})
        self.assertIs(res["issues"][0]["_finding"], finding)
        finding["ref"] = "F7"                                        # simulate the post-QA renumber
        report_lib._resync_qa_refs(res)
        self.assertEqual(res["issues"][0]["ref"], "F7")
        self.assertNotIn("_finding", res["issues"][0])


def _submission_ctx(proof: dict) -> tuple[dict, dict]:
    finding = {
        "ref": "F1", "title": "IDOR on account export", "severity": "high", "confidence": "high",
        "class_id": "access-control", "class_name": "Broken access control", "cwe": "CWE-639",
        "location": "https://app.example.com/api/account/1001/export", "rule_id": "active.idor",
    }
    plan = {"impact": "Read another tenant's export.", "steps": ["..."], "proof_of_impact": proof}
    ctx = {
        "tool": "GreyIQ BugHunter", "version": "9.9.9", "generated_at": "now",
        "target": "https://app.example.com", "scope": "*.example.com",
        "attack_plans": {"F1": plan},
    }
    return ctx, finding


class SubmitGateEndToEndTests(unittest.TestCase):
    """The reason this matters: the auto-submit gate keys on the rendered proof_status."""

    @staticmethod
    def _network_must_not_be_touched(*_args, **_kwargs):
        raise AssertionError("submit_to_hackerone reached the network for an unproven finding")

    def test_non_differential_package_is_refused_by_the_submit_gate(self) -> None:
        ctx, finding = _submission_ctx({"status": "confirmed", "observed_result": _SAME, "control_result": _SAME})
        pkg = submission.build_submission(ctx, finding, "hackerone")
        self.assertIsNotNone(pkg)
        assert pkg is not None
        # Before this fix the package read 'confirmed' here and the gate below let it through.
        self.assertEqual(pkg["proof_status"], "candidate")
        self.assertFalse(submission.preflight(pkg)["ready"])
        with self.assertRaises(submission.SubmissionError) as cm:
            submission.submit_to_hackerone(
                pkg, team_handle="acme", api_username="u", api_token="k", confirm=True,
                _urlopen=self._network_must_not_be_touched,
            )
        self.assertIn("only CONFIRMED", str(cm.exception))

    def test_differing_pair_package_reaches_confirmed(self) -> None:
        # The control: a genuine differential still flows through to a submittable package.
        ctx, finding = _submission_ctx({"status": "confirmed", "observed_result": _OBSERVED, "control_result": _CONTROL})
        pkg = submission.build_submission(ctx, finding, "hackerone")
        assert pkg is not None
        self.assertEqual(pkg["proof_status"], "confirmed")
        self.assertTrue(submission.preflight(pkg)["checklist"][-1]["present"])


if __name__ == "__main__":
    unittest.main()
