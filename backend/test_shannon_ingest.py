"""The Shannon bridge (bughunter.shannon): an external pentest engine's output, imported
as candidates that can never reach a live submission on the external engine's word.

These tests pin four things, in descending order of how much damage getting them wrong does:

  1. THE CONFIRM VETO. ``report._has_captured_artifact`` is GreyIQ's single confirm
     authority, and its distinguishing signal is a populated observed/control differential.
     Shannon supplies exactly that shape and asserts its own findings are exploited, so the
     veto is the only thing standing between an imported candidate and the auto-submit
     gate. The test proves the veto is what does the work by feeding the SAME proof dict
     twice — once marked external, once not — and asserting the verdict flips.
  2. THE CANDIDATE INVARIANT. No imported finding may carry any field the confirm gate or
     ``_explicit_proof_status`` reads as proof: observed_result, control_result,
     proof_of_impact, impact_confirmed, replay_authenticated, or a bare ``status``.
  3. NO INVENTED PRECISION. SARIF cannot distinguish critical from high, so a candidate is
     stamped at the band floor. A CWE is taken only from Shannon's validated SAST rule id;
     Shannon's coarse ``injection`` class must NEVER become GreyIQ's ``rce`` class, which is
     what the cortex's own ``"injection": "rce"`` alias would do and what would turn a SQLi
     candidate into a remote-code-execution claim.
  4. FAIL-SOFT. Malformed, truncated, empty and duplicate-id input degrades to an empty or
     partial result with a warning, never a raise — a half-written SARIF from a crashed
     scan must not take a hunt down.

The fixture is SYNTHETIC and uses RFC 2606 example hosts. It is not copied from Shannon's
tree: Shannon is AGPL-3.0 and GreyIQ is not, so no Shannon file is vendored here. Its shape
was validated against the three real generated SARIFs committed under Shannon's
``benchmark/`` at pinned commit 2468b67d9e40d70d0b189462c5041c24e1dc886c — 52 results, all
of which parse with zero drops. ``test_conformance_against_real_shannon_output`` re-runs
that check against the real files and is skipped unless GREYIQ_SHANNON_DIR points at a
Shannon checkout, so CI stays hermetic while a developer with the clone gets the real check.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report as report_lib  # noqa: E402
from bughunter import submission  # noqa: E402
from bughunter.shannon import ingest, sarif, workspace  # noqa: E402

# A live-looking GitHub token shape, used to prove redaction reaches Shannon's prose.
PLANTED_SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

# Fields that would let an imported finding promote itself through the confirm gate
# (report._has_captured_artifact) or the explicit-status reader
# (report._explicit_proof_status). None may ever appear on an imported finding.
FORBIDDEN_FIELDS = (
    "observed_result",
    "control_result",
    "impact_proof",
    "impact_evidence",
    "impact_confirmed",
    "proof_confirmed",
    "replay_authenticated",
    "status",
    "secret_hits",
    "_credential_proof",
)

# An imported finding DOES carry a ``proof_of_impact`` dict — it has to, or
# report._proof_of_impact_detail returns early at 'missing' and the lead reaches the queue
# with no stated proof obligation. These are the keys inside it that drive promotion
# through _has_captured_artifact, and every one must be empty.
FORBIDDEN_PROOF_KEYS = ("evidence", "observed_result", "control_result")


def _result(
    finding_id: str,
    rule_id: str,
    *,
    level: str = "warning",
    taxon: str = "A01:2025",
    sast_rule: str | None = None,
    method: str = "POST",
    target: str = "https://app.example.com/api/graphql",
    parameter: str | None = "rootPath",
    title: str = "Example Candidate Title",
    narrative: str = "A finding narrative long enough to look like real prose.",
) -> dict:
    """One synthetic SARIF result, shaped like Shannon's renderer emits them."""
    properties: dict = {"findingId": finding_id, "status": "exploited"}
    if parameter:
        properties["parameter"] = parameter
    if sast_rule:
        properties["sastRuleId"] = sast_rule
    properties["authState"] = "Authenticated administrator"
    properties["prerequisites"] = f"An admin session, token {PLANTED_SECRET}"

    locations = [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "api/resolvers/user.go"},
                "region": {"startLine": 266, "endLine": 282},
            },
            "logicalLocations": [{"name": "UserAddRootPath", "kind": "function"}],
            "message": {"text": "sink"},
        }
    ]
    if sast_rule:
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "api/scanner/album.go"},
                    "region": {"startLine": 20, "endLine": 33},
                },
                "message": {"text": f"Validated SAST source location ({sast_rule})"},
            }
        )
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": f"{title}. {narrative}", "markdown": f"**{title}**\n\n{narrative}"},
        "locations": locations,
        "webRequest": {"method": method, "target": target},
        "taxa": [{"id": taxon, "toolComponent": {"name": "OWASP Top Ten 2025"}}],
        "properties": properties,
        "ruleIndex": 0,
    }


def _sarif(results: list[dict], *, execution_successful: bool = True) -> str:
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Shannon", "informationUri": "https://example.com/s"}},
                    "automationDetails": {"id": "shannon/exploit/example-com_shannon-1"},
                    "invocations": [{"executionSuccessful": execution_successful}],
                    "results": results,
                    "properties": {
                        "target": "https://app.example.com",
                        "assessmentDate": "2026-10-11",
                        "model": "claude-opus-5",
                    },
                }
            ],
        }
    )


class ConfirmVetoTests(unittest.TestCase):
    """The one test that matters most: an external finding cannot reach 'confirmed'."""

    #: A proof dict with a real observed-vs-control differential — the exact shape that
    #: satisfies report._has_captured_artifact's final branch.
    DIFFERENTIAL = {
        "observed_result": "HTTP 200 and the victim's record was returned in the body",
        "control_result": "HTTP 403 for the same request without the manipulated id",
    }

    def test_differential_confirms_a_native_finding(self) -> None:
        """Control case. Without this passing, the veto test below proves nothing."""
        native = {"title": "native finding"}
        self.assertTrue(report_lib._has_captured_artifact(native, self.DIFFERENTIAL))

    def test_same_differential_is_vetoed_for_an_external_finding(self) -> None:
        external = {"title": "imported finding", "source": ingest.SOURCE}
        self.assertFalse(report_lib._has_captured_artifact(external, self.DIFFERENTIAL))

    def test_veto_lifts_once_greyiq_proves_it(self) -> None:
        """The documented re-prove hook. Nothing sets this today, but it must work."""
        proved = {"title": "imported then proved", "source": ingest.SOURCE, "_greyiq_proved": True}
        self.assertTrue(report_lib._has_captured_artifact(proved, self.DIFFERENTIAL))

    def test_unknown_external_engine_is_also_vetoed(self) -> None:
        """The veto keys on 'not ours', not on a list of known engines."""
        other = {"title": "some other tool", "source": "some-future-engine"}
        self.assertFalse(report_lib._has_captured_artifact(other, self.DIFFERENTIAL))

    def test_blank_and_native_sources_are_not_external(self) -> None:
        """Every pre-existing finding carries no 'source' and must be unaffected."""
        for value in ("", None, "greyiq", "bughunter", "GreyIQ"):
            with self.subTest(source=value):
                self.assertTrue(
                    report_lib._has_captured_artifact(
                        {"title": "t", "source": value}, self.DIFFERENTIAL
                    )
                )

    def test_imported_finding_resolves_to_candidate_end_to_end(self) -> None:
        """Through the real proof-detail path, not just the gate predicate."""
        run = sarif.parse_sarif_text(_sarif([_result("AUTHZ-01", "shannon/authz")]))
        finding = ingest.findings_from_run(run)[0]
        detail = report_lib._proof_of_impact_detail(finding, {})
        self.assertEqual(detail["status"], "candidate")
        self.assertFalse(detail["ready"])


class CandidateInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run = sarif.parse_sarif_text(
            _sarif(
                [
                    _result("INJ-01", "shannon/injection", level="error", sast_rule="CWE-89"),
                    _result("AUTHZ-02", "shannon/authz", level="warning"),
                    _result("AUTH-03", "shannon/auth", level="note", taxon="A07:2025"),
                    _result("MISC-04", "shannon/miscellaneous", level="note", taxon="A10:2025"),
                ]
            )
        )
        self.findings = ingest.findings_from_run(self.run)

    def test_every_finding_is_a_candidate_from_shannon(self) -> None:
        self.assertEqual(len(self.findings), 4)
        for finding in self.findings:
            with self.subTest(rule_id=finding["rule_id"]):
                self.assertEqual(finding["proof_status"], "candidate")
                self.assertEqual(finding["source"], ingest.SOURCE)
                self.assertTrue(ingest.is_external(finding))
                self.assertFalse(ingest.greyiq_proved(finding))

    def test_no_finding_carries_a_proof_field(self) -> None:
        for finding in self.findings:
            for field in FORBIDDEN_FIELDS:
                with self.subTest(rule_id=finding["rule_id"], field=field):
                    self.assertNotIn(field, finding)

    def test_the_proof_dict_carries_no_differential(self) -> None:
        """The proof dict exists to hold an obligation, never evidence. A populated
        observed+control pair that differs is precisely what the confirm gate accepts."""
        for finding in self.findings:
            proof = finding["proof_of_impact"]
            self.assertEqual(proof["status"], "candidate")
            for key in FORBIDDEN_PROOF_KEYS:
                with self.subTest(rule_id=finding["rule_id"], key=key):
                    self.assertEqual(proof[key], "")

    def test_every_finding_states_a_proof_obligation(self) -> None:
        for finding in self.findings:
            obligation = finding["proof_of_impact"]["proof_obligation"]
            self.assertTrue(obligation.strip(), "a lead with no obligation is a dead end")

    def test_obligation_never_promises_a_confirm_the_prover_cannot_reach(self) -> None:
        """ssrf / auth / access-control are absent from PROVER_CLASSES, so an obligation
        saying 'run --active' for them would be undischargeable."""
        from bughunter import prover_classes

        for rule_id, class_id in (
            ("shannon/ssrf", "ssrf"),
            ("shannon/auth", "auth"),
            ("shannon/authz", "access-control"),
        ):
            with self.subTest(rule_id=rule_id):
                self.assertNotIn(class_id, prover_classes.PROVER_CLASSES)
                run = sarif.parse_sarif_text(_sarif([_result("F-1", rule_id)]))
                obligation = ingest.findings_from_run(run)[0]["proof_of_impact"]["proof_obligation"]
                self.assertIn("cannot confirm", obligation)
                self.assertNotIn("Re-run GreyIQ's active prover", obligation)

    def test_shannon_verdict_is_kept_only_as_provenance(self) -> None:
        """Shannon says 'exploited'. That must survive as a fact, under a key no gate reads."""
        detail = self.findings[0]["source_detail"]
        self.assertEqual(detail["shannon_status"], "exploited")
        self.assertIs(detail["greyiq_proved"], False)
        self.assertEqual(detail["engine"], "shannon")
        self.assertEqual(detail["shannon_finding_id"], "INJ-01")

    def test_confidence_never_seeded_high_by_an_external_engine(self) -> None:
        """Confidence feeds the cortex ranking base; an external engine may not top it."""
        for finding in self.findings:
            self.assertEqual(finding["confidence"], "medium")

    def test_rule_id_is_namespaced_so_origin_is_readable_anywhere(self) -> None:
        self.assertEqual(self.findings[0]["rule_id"], "shannon.injection.inj-01")


class NoInventedPrecisionTests(unittest.TestCase):
    def test_error_level_stamps_the_band_floor_and_records_the_ambiguity(self) -> None:
        """SARIF cannot separate critical from high. Claiming critical would be fabrication."""
        run = sarif.parse_sarif_text(_sarif([_result("INJ-01", "shannon/injection", level="error")]))
        finding = ingest.findings_from_run(run)[0]
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["source_detail"]["shannon_severity_band"], "critical-or-high")
        self.assertIn("critical", finding["source_detail"]["severity_note"])

    def test_level_mapping(self) -> None:
        for level, severity in (("error", "high"), ("warning", "medium"), ("note", "low")):
            with self.subTest(level=level):
                run = sarif.parse_sarif_text(
                    _sarif([_result("X-1", "shannon/xss", level=level)])
                )
                self.assertEqual(ingest.findings_from_run(run)[0]["severity"], severity)

    def test_bare_injection_never_becomes_rce(self) -> None:
        """The cortex aliases "injection" to rce. Honouring that would inflate a SQLi
        candidate into a remote-code-execution claim, so an unresolvable injection
        abstains and lets bounty._classify decide."""
        run = sarif.parse_sarif_text(_sarif([_result("INJ-01", "shannon/injection")]))
        finding = ingest.findings_from_run(run)[0]
        self.assertNotIn("_active_class_hint", finding)

    def test_miscellaneous_abstains(self) -> None:
        run = sarif.parse_sarif_text(_sarif([_result("MISC-01", "shannon/miscellaneous")]))
        self.assertNotIn("_active_class_hint", ingest.findings_from_run(run)[0])

    def test_the_annotation_pass_also_never_produces_rce(self) -> None:
        """Abstaining on _active_class_hint is NOT sufficient on its own. bounty._classify
        matches the `category` field against each class's scanner-category set, and `rce`'s
        set contains the literal string "injection" — so emitting Shannon's own class word as
        `category` would classify an abstaining injection candidate as remote code execution
        through the fallback path instead. Pin the real downstream result, not just the hint."""
        from bughunter import bounty

        self.assertIn("injection", bounty.VULN_CLASSES["rce"]["categories"])  # the hazard
        for rule_id in ("shannon/injection", "shannon/miscellaneous"):
            with self.subTest(rule_id=rule_id):
                run = sarif.parse_sarif_text(_sarif([_result("F-1", rule_id)]))
                finding = ingest.findings_from_run(run)[0]
                class_id, _name, _cwe, _owasp = bounty._classify(finding)
                self.assertNotEqual(class_id, "rce")

    def test_resolved_classes_survive_the_annotation_pass(self) -> None:
        """A resolved class must reach the report as itself, with its CWE."""
        from bughunter import bounty

        run = sarif.parse_sarif_text(
            _sarif([_result("INJ-01", "shannon/injection", sast_rule="CWE-89")])
        )
        finding = ingest.findings_from_run(run)[0]
        meta = bounty.VULN_CLASSES[finding["_active_class_hint"]]
        self.assertEqual(finding["_active_class_hint"], "sqli")
        self.assertEqual(meta["cwe"], "CWE-89")

    def test_validated_sast_cwe_resolves_the_class_exactly(self) -> None:
        run = sarif.parse_sarif_text(
            _sarif([_result("INJ-01", "shannon/injection", sast_rule="CWE-89")])
        )
        finding = ingest.findings_from_run(run)[0]
        self.assertEqual(finding["_active_class_hint"], "sqli")
        self.assertEqual(finding["source_detail"]["cwe"], "CWE-89")
        self.assertEqual(finding["source_detail"]["cwe_source"], "shannon-sast-rule")
        self.assertEqual(finding["source_detail"]["class_resolved_by"], "cwe:89:shannon-sast-rule")

    def test_unmapped_sast_cwe_keeps_the_weakness_but_abstains_on_class(self) -> None:
        """CWE-476 is real and appears in Shannon's own benchmark output, but GreyIQ has no
        class for it. The weakness must survive as provenance rather than be discarded."""
        run = sarif.parse_sarif_text(
            _sarif([_result("MISC-01", "shannon/miscellaneous", sast_rule="CWE-476")])
        )
        finding = ingest.findings_from_run(run)[0]
        self.assertNotIn("_active_class_hint", finding)
        self.assertEqual(finding["source_detail"]["cwe"], "CWE-476")

    def test_class_fallback_for_the_unambiguous_classes(self) -> None:
        for rule_id, class_id in (
            ("shannon/xss", "xss"),
            ("shannon/ssrf", "ssrf"),
            ("shannon/auth", "auth"),
            ("shannon/authz", "access-control"),
        ):
            with self.subTest(rule_id=rule_id):
                run = sarif.parse_sarif_text(_sarif([_result("F-1", rule_id)]))
                finding = ingest.findings_from_run(run)[0]
                self.assertEqual(finding["_active_class_hint"], class_id)

    def test_cwe_200_never_routes_to_the_secrets_class(self) -> None:
        """GreyIQ's CWE-200 means 'exposed secret/credential' and clamps severity through
        secret_classification. Shannon's CWE-200 is ordinary information disclosure, and
        filing one as the other would report a disclosure as a leaked credential."""
        run = sarif.parse_sarif_text(
            _sarif([_result("MISC-01", "shannon/miscellaneous", sast_rule="CWE-200")])
        )
        finding = ingest.findings_from_run(run)[0]
        self.assertNotEqual(finding.get("_active_class_hint"), "secrets")


class RedactionTests(unittest.TestCase):
    def test_planted_secret_does_not_survive_into_a_finding(self) -> None:
        """Shannon keeps captured tokens in its prose BY DESIGN — its own rule redacts only
        the credentials it was configured with. Everything it writes is therefore untrusted
        text and must go through GreyIQ's shared redactor."""
        run = sarif.parse_sarif_text(
            _sarif([_result("AUTH-01", "shannon/auth", narrative=f"Leaked {PLANTED_SECRET} here.")])
        )
        finding = ingest.findings_from_run(run)[0]
        blob = json.dumps(finding)
        self.assertNotIn(PLANTED_SECRET, blob)
        self.assertTrue(finding["redacted"])

    def test_planted_secret_does_not_survive_in_prerequisites(self) -> None:
        run = sarif.parse_sarif_text(_sarif([_result("AUTH-01", "shannon/auth")]))
        finding = ingest.findings_from_run(run)[0]
        self.assertNotIn(PLANTED_SECRET, json.dumps(finding["source_detail"]))


class SubmitGateTests(unittest.TestCase):
    def test_submit_refuses_an_external_package_and_names_the_engine(self) -> None:
        package = {
            "title": "t",
            "vulnerability_information": "body",
            "proof_status": "confirmed",  # forced, to prove the source check is independent
            "source": "shannon",
        }
        with self.assertRaises(submission.SubmissionError) as caught:
            submission.submit_to_hackerone(
                package, team_handle="team", api_username="u", api_token="t", confirm=True
            )
        message = str(caught.exception)
        self.assertIn("shannon", message)
        self.assertIn("external engine", message)

    def test_preflight_is_not_ready_and_says_why(self) -> None:
        package = {
            "title": "t",
            "vulnerability_information": "body",
            "location": "https://app.example.com/x",
            "proof_status": "confirmed",
            "source": "shannon",
        }
        result = submission.preflight(package, "hackerone")
        self.assertFalse(result["ready"])
        labels = [row["label"] for row in result["checklist"] if not row["present"]]
        self.assertIn("Proved by GreyIQ's own prover", labels)
        self.assertTrue(any("shannon" in warning for warning in result["warnings"]))

    def test_preflight_unaffected_for_a_native_package(self) -> None:
        """The source check must not change the verdict for GreyIQ's own work."""
        package = {
            "title": "t",
            "vulnerability_information": "body",
            "location": "https://app.example.com/x",
            "severity_rating": "high",
            "weakness": 79,
            "proof_status": "confirmed",
        }
        result = submission.preflight(package, "hackerone")
        self.assertEqual(result["missing"], [])
        self.assertTrue(result["ready"])


class FailSoftTests(unittest.TestCase):
    def test_malformed_json(self) -> None:
        run = sarif.parse_sarif_text("{not json")
        self.assertEqual(run.candidates, ())
        self.assertTrue(any("not valid JSON" in w for w in run.warnings))

    def test_empty_and_non_object_input(self) -> None:
        for text in ("", "[]", "null", "123"):
            with self.subTest(text=text):
                run = sarif.parse_sarif_text(text)
                self.assertEqual(run.candidates, ())
                self.assertTrue(run.warnings)

    def test_no_runs(self) -> None:
        run = sarif.parse_sarif_text(json.dumps({"version": "2.1.0", "runs": []}))
        self.assertEqual(run.candidates, ())
        self.assertTrue(any("no runs" in w for w in run.warnings))

    def test_result_without_finding_id_is_dropped_not_guessed(self) -> None:
        bad = _result("X-1", "shannon/xss")
        bad["properties"].pop("findingId")
        run = sarif.parse_sarif_text(_sarif([bad, _result("X-2", "shannon/xss")]))
        self.assertEqual(len(run.candidates), 1)
        self.assertEqual(run.dropped, 1)
        self.assertTrue(any("findingId" in w for w in run.warnings))

    def test_duplicate_finding_id_keeps_the_first_and_warns(self) -> None:
        run = sarif.parse_sarif_text(
            _sarif([_result("X-1", "shannon/xss", title="First"), _result("X-1", "shannon/xss", title="Second")])
        )
        self.assertEqual(len(run.candidates), 1)
        self.assertEqual(run.candidates[0].title, "First")
        self.assertTrue(any("duplicate" in w for w in run.warnings))

    def test_partial_run_is_flagged_so_it_is_not_read_as_clean(self) -> None:
        """An un-assessed vuln class is not a clean result."""
        run = sarif.parse_sarif_text(
            _sarif([_result("X-1", "shannon/xss")], execution_successful=False)
        )
        self.assertFalse(run.execution_successful)
        self.assertTrue(any("partial run" in w for w in run.warnings))
        finding = ingest.findings_from_run(run)[0]
        self.assertTrue(finding["source_detail"]["partial_run"])

    def test_missing_file(self) -> None:
        run = sarif.parse_sarif_file(BACKEND_DIR / "no-such-shannon-report.sarif")
        self.assertEqual(run.candidates, ())
        self.assertTrue(run.warnings)

    def test_unexpected_version_is_recorded_not_fatal(self) -> None:
        payload = json.loads(_sarif([_result("X-1", "shannon/xss")]))
        payload["version"] = "2.2.0"
        run = sarif.parse_sarif_text(json.dumps(payload))
        self.assertEqual(len(run.candidates), 1)
        self.assertTrue(any("2.2.0" in w for w in run.warnings))


class TitleAndLocationTests(unittest.TestCase):
    def test_title_comes_from_the_markdown_bold_span(self) -> None:
        run = sarif.parse_sarif_text(
            _sarif([_result("X-1", "shannon/xss", title="SQL Injection. Nested. Dots")])
        )
        self.assertEqual(run.candidates[0].title, "SQL Injection. Nested. Dots")

    def test_http_location_is_carried(self) -> None:
        run = sarif.parse_sarif_text(_sarif([_result("X-1", "shannon/xss")]))
        candidate = run.candidates[0]
        self.assertEqual(candidate.http_method, "POST")
        self.assertEqual(candidate.http_target, "https://app.example.com/api/graphql")
        self.assertEqual(candidate.parameter, "rootPath")

    def test_code_locations_normalize_the_sast_prose_role(self) -> None:
        run = sarif.parse_sarif_text(
            _sarif([_result("X-1", "shannon/injection", sast_rule="CWE-89")])
        )
        roles = [loc.role for loc in run.candidates[0].locations]
        self.assertIn("sink", roles)
        self.assertIn("sast-source", roles)

    def test_sast_prose_is_preserved_so_the_cwe_stays_recoverable(self) -> None:
        """Normalizing the role must not destroy the only copy of the CWE.

        ``message.text`` is the single place the location-level CWE appears. The role is
        normalized off it, so if the prose is not kept the CWE is simply gone.
        """
        run = sarif.parse_sarif_text(
            _sarif([_result("X-1", "shannon/injection", sast_rule="CWE-89")])
        )
        sast = [loc for loc in run.candidates[0].locations if loc.role == "sast-source"]
        self.assertEqual(len(sast), 1)
        self.assertEqual(sast[0].message, "Validated SAST source location (CWE-89)")

    def test_cwe_is_mined_from_the_location_when_no_sast_rule_id_is_set(self) -> None:
        """The 'shannon-sast-location' branch, which was unreachable.

        It mined ``loc.file`` — an artifact URI like "api/scanner/album.go", which carries
        no CWE — so the branch could never fire and the CWE in the prose was dropped.
        ``injection`` has no class-level CWE, so with the prose as the only source this
        either mines it or abstains; abstaining is the regression.
        """
        result = _result("X-1", "shannon/injection", sast_rule="CWE-89")
        # The prose location stays; the properties-level id that short-circuits the
        # resolver ahead of it does not.
        result["properties"].pop("sastRuleId")
        run = sarif.parse_sarif_text(_sarif([result]))
        candidate = run.candidates[0]
        self.assertEqual(candidate.cwe, "89")
        self.assertEqual(candidate.cwe_source, "shannon-sast-location")

    def test_code_locations_reach_the_finding(self) -> None:
        run = sarif.parse_sarif_text(_sarif([_result("X-1", "shannon/xss")]))
        finding = ingest.findings_from_run(run)[0]
        self.assertEqual(finding["code_locations"][0]["file"], "api/resolvers/user.go")
        self.assertEqual(finding["code_locations"][0]["start_line"], 266)
        self.assertEqual(finding["code_locations"][0]["symbol"], "UserAddRootPath")


class WorkspaceResolutionTests(unittest.TestCase):
    """Finding a finished run on disk. ``-o`` REPLACES the workspace root rather than adding
    to it, and the internal copy survives a failed surface, so there is no single location
    and a caller must not have to know which flags the operator used."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.payload = _sarif([_result("X-1", "shannon/xss")])

    def _write(self, relative: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.payload, encoding="utf-8")
        return path

    def test_run_root(self) -> None:
        expected = self._write("report.sarif")
        found, notes = workspace.find_sarif(self.root)
        self.assertEqual(found, expected)
        self.assertEqual(notes, [])

    def test_internal_deliverables_copy(self) -> None:
        expected = self._write(".shannon/deliverables/report.sarif")
        found, _ = workspace.find_sarif(self.root)
        self.assertEqual(found, expected)

    def test_run_root_wins_over_the_internal_copy(self) -> None:
        expected = self._write("report.sarif")
        self._write(".shannon/deliverables/report.sarif")
        found, _ = workspace.find_sarif(self.root)
        self.assertEqual(found, expected)

    def test_workspaces_parent_picks_the_most_recent_and_says_so(self) -> None:
        older = self._write("example-com_shannon-1/report.sarif")
        newer = self._write("example-com_shannon-2/report.sarif")
        os.utime(older, (1_000_000, 1_000_000))
        os.utime(newer, (2_000_000, 2_000_000))
        found, notes = workspace.find_sarif(self.root)
        self.assertEqual(found, newer)
        self.assertTrue(any("2 Shannon runs" in note for note in notes))

    def test_a_direct_sarif_file_is_accepted(self) -> None:
        expected = self._write("somewhere/custom-name.sarif")
        found, _ = workspace.find_sarif(expected)
        self.assertEqual(found, expected)

    def test_a_non_sarif_file_is_refused(self) -> None:
        path = self.root / "report.json"
        path.write_text("{}", encoding="utf-8")
        found, notes = workspace.find_sarif(path)
        self.assertIsNone(found)
        self.assertTrue(any("not a .sarif" in note for note in notes))

    def test_missing_path(self) -> None:
        found, notes = workspace.find_sarif(self.root / "nope")
        self.assertIsNone(found)
        self.assertTrue(notes)

    def test_empty_directory_explains_why_a_sarif_may_be_absent(self) -> None:
        found, notes = workspace.find_sarif(self.root)
        self.assertIsNone(found)
        self.assertTrue(any('exploit="false"' in note for note in notes))

    def test_ingest_workspace_returns_candidates(self) -> None:
        self._write("report.sarif")
        result = workspace.ingest_workspace(self.root)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["source"], ingest.SOURCE)
        self.assertEqual(result["findings"][0]["proof_status"], "candidate")

    def test_ingest_warns_when_live_session_state_was_left_behind(self) -> None:
        """auth-state.json is Playwright storage state — live cookies for the target. The
        operator is about to have a directory they may bundle or let OneDrive sync."""
        self._write("report.sarif")
        state = self.root / ".shannon" / "auth-state.json"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text("{}", encoding="utf-8")
        result = workspace.ingest_workspace(self.root)
        self.assertTrue(result["ok"])
        self.assertTrue(any("LIVE session cookies" in w for w in result["warnings"]))

    def test_ingest_fails_soft_on_a_sarif_with_no_usable_results(self) -> None:
        path = self.root / "report.sarif"
        path.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")
        result = workspace.ingest_workspace(self.root)
        self.assertFalse(result["ok"])
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["error"])

    def test_ingest_never_raises_on_junk_input(self) -> None:
        for value in ("", "   ", "\x00bad", str(self.root / ("a" * 50))):
            with self.subTest(value=value[:20]):
                result = workspace.ingest_workspace(value)
                self.assertFalse(result["ok"])
                self.assertEqual(result["findings"], [])

    @unittest.skipUnless(os.name == "nt", "MAX_PATH is a Windows behaviour")
    def test_long_path_is_diagnosed_rather_than_reported_as_absent(self) -> None:
        """Past MAX_PATH, Windows reports an existing file as absent instead of raising, so
        a bare 'not found' sends the diagnosis in the wrong direction. Hit for real while
        testing this module from a deeply nested temp directory."""
        deep = self.root / ("x" * 120) / ("y" * 120)
        found, notes = workspace.find_sarif(deep)
        self.assertIsNone(found)
        self.assertTrue(any("silently reports files past" in note for note in notes))


class ConformanceTests(unittest.TestCase):
    """Run the parser against Shannon's own committed generated SARIFs.

    Skipped unless GREYIQ_SHANNON_DIR points at a Shannon checkout, so CI needs no clone.
    """

    def test_conformance_against_real_shannon_output(self) -> None:
        root = os.environ.get("GREYIQ_SHANNON_DIR", "").strip()
        if not root:
            self.skipTest("GREYIQ_SHANNON_DIR not set — no Shannon checkout to conform against")
        benchmark = Path(root) / "benchmark"
        files = sorted(benchmark.glob("*.sarif")) if benchmark.is_dir() else []
        if not files:
            self.skipTest(f"no benchmark SARIFs under {benchmark}")

        total = 0
        for path in files:
            with self.subTest(path=path.name):
                run = sarif.parse_sarif_file(path)
                self.assertEqual(run.tool_name, "Shannon")
                self.assertEqual(run.dropped, 0, f"{path.name}: results were dropped")
                self.assertTrue(run.candidates, f"{path.name}: nothing parsed")
                total += len(run.candidates)
                from bughunter import bounty

                for finding in ingest.findings_from_run(run):
                    self.assertEqual(finding["proof_status"], "candidate")
                    self.assertEqual(finding["source"], ingest.SOURCE)
                    # The inflation this bridge exists to prevent — checked on BOTH paths:
                    # the hint, and the _classify fallback an abstaining finding takes.
                    self.assertNotEqual(finding.get("_active_class_hint"), "rce")
                    self.assertNotEqual(bounty._classify(finding)[0], "rce")
                    for field in FORBIDDEN_FIELDS:
                        self.assertNotIn(field, finding)
                    for key in FORBIDDEN_PROOF_KEYS:
                        self.assertEqual(finding["proof_of_impact"][key], "")
        self.assertGreaterEqual(total, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
