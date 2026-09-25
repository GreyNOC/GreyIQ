from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty as bounty_lib  # noqa: E402
from bughunter import next_steps as next_steps_lib  # noqa: E402
from bughunter import report as report_lib  # noqa: E402
from bughunter.bounty import _capture_direct_proof_artifacts, list_profiles  # noqa: E402


class BountyReportTests(unittest.TestCase):
    def test_https_repository_roots_are_git_targets_before_generic_urls(self) -> None:
        self.assertEqual(bounty_lib._infer_kind("https://github.com/acme/widget"), "git")
        self.assertEqual(bounty_lib._infer_kind("https://gitlab.com/acme/platform/widget.git"), "git")

    def test_forge_pages_remain_web_targets(self) -> None:
        self.assertEqual(bounty_lib._infer_kind("https://github.com/acme/widget/issues/12"), "url")
        self.assertEqual(bounty_lib._infer_kind("https://github.com/acme/widget/blob/main/app.py"), "url")

    def test_full_sweep_routes_https_repository_to_remote_clone_scanner(self) -> None:
        calls = []
        original = bounty_lib.run_code_scan
        bounty_lib.run_code_scan = lambda target, target_type, max_files=5000: (
            calls.append((target, target_type, max_files))
            or {"ok": True, "findings": [], "risk": "low", "score": 0,
                "files_scanned": 4, "finding_count": 0, "git_metadata": {"clone_depth": "1"}}
        )
        try:
            target = "https://github.com/acme/widget"
            kind = bounty_lib._infer_kind(target)
            _findings, scanners, meta, _risk, _score, _signals = bounty_lib._run_scanners(
                bounty_lib.BOUNTY_PROFILES["full-sweep"], kind, target, 123, False,
            )
        finally:
            bounty_lib.run_code_scan = original
        self.assertEqual(calls, [(target, "git_remote", 123)])
        self.assertEqual(scanners, ["code"])
        self.assertEqual(meta["code"]["git_metadata"]["clone_depth"], "1")

    def test_markdown_adds_bounty_submission_sections(self) -> None:
        ctx = {
            "tool": "GreyIQ BugHunter",
            "version": "test",
            "generated_at": "2026-06-19 12:00 UTC",
            "target": "https://example.test",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "vuln_class": None,
            "scope": "Example program - *.example.test",
            "authorized": True,
            "scanners_run": ["web", "live"],
            "run_live_requested": True,
            "risk": "high",
            "score": 0.8,
            "findings": [
                {
                    "ref": "F1",
                    "severity": "high",
                    "confidence": "high",
                    "class_id": "access-control",
                    "class_name": "Broken access control / IDOR",
                    "title": "Object can be read by another account",
                    "location": "https://example.test/api/orders/123",
                    "rule_id": "manual.idor",
                    "description": "A lower-privileged account can read another user's order.",
                    "snippet": "GET /api/orders/123",
                    "remediation": "Check object ownership server-side.",
                }
            ],
            "attack_plans": {
                "F1": {
                    "steps": ["Log in as account A.", "Replay the request with account B."],
                    "impact": "Cross-tenant order disclosure.",
                    "proof_of_impact": {
                        "status": "confirmed",
                        "method": "Replay account A's order request with account B's session.",
                        "actor": "Account B",
                        "affected_asset": "Order 123 owned by account A",
                        "observed_result": "HTTP 200 returned order 123 to account B.",
                        "control_result": "Account B should receive 403 or an empty result for account A's order.",
                        "evidence": "The replay as account B returned order 123 owned by account A.",
                        "limitations": "Only a single order id was tested.",
                    },
                }
            },
            "manual_checklist": ["Replay as a lower-privileged account."],
            "recommended_tools": [],
            "brain": {"used": False},
        }

        markdown = report_lib.build_markdown(ctx)
        json_doc = report_lib.build_json(ctx)

        self.assertIn("## Bounty triage", markdown)
        self.assertIn("**Proof of impact:**", markdown)
        self.assertIn("**Status:** Confirmed", markdown)
        self.assertIn("**Observed result:** HTTP 200 returned order 123 to account B.", markdown)
        self.assertIn("**Control / expected result:** Account B should receive 403", markdown)
        self.assertIn("The replay as account B returned order 123 owned by account A.", markdown)
        self.assertIn("### Submission preflight", markdown)
        self.assertIn("**Submission readiness**", markdown)
        self.assertIn("[x] Confirmed proof of impact is captured as concrete evidence.", markdown)
        self.assertIn("### Retest after fix", markdown)
        self.assertEqual(json_doc["class_counts"]["Broken access control / IDOR"], 1)
        self.assertEqual(
            json_doc["attack_plans"]["F1"]["proof_of_impact"]["evidence"],
            "The replay as account B returned order 123 owned by account A.",
        )
        self.assertEqual(json_doc["proof_of_impact"]["F1"]["status"], "confirmed")
        self.assertTrue(json_doc["proof_of_impact"]["F1"]["ready"])
        self.assertTrue(json_doc["run_live_requested"])
        self.assertIn("submission_checklist", json_doc)

        single = report_lib.build_finding_markdown(ctx, ctx["findings"][0])
        self.assertIn("## Proof of impact", single)
        self.assertIn("The replay as account B returned order 123 owned by account A.", single)

    def test_report_marks_missing_proof_of_impact_not_ready(self) -> None:
        ctx = {
            "tool": "GreyIQ BugHunter",
            "target": "https://example.test",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "findings": [
                {
                    "ref": "F1",
                    "severity": "medium",
                    "confidence": "medium",
                    "category": "secret",
                    "title": "Candidate issue",
                    "location": "app.js",
                    "rule_id": "manual.candidate",
                    "description": "A candidate issue was detected.",
                    "snippet": "candidate evidence",
                }
            ],
            "attack_plans": {
                "F1": {
                    "steps": ["Open the target.", "Replay the request."],
                    "impact": "Potential sensitive data exposure.",
                }
            },
            "recommended_tools": [],
            "brain": {"used": False},
        }

        markdown = report_lib.build_markdown(ctx)

        self.assertIn("**Proof of impact:**", markdown)
        self.assertIn("Not captured yet", markdown)
        self.assertIn("[ ] Confirmed proof of impact is captured as concrete evidence.", markdown)

    def test_report_marks_generic_proof_as_candidate_not_ready(self) -> None:
        ctx = {
            "tool": "GreyIQ BugHunter",
            "target": "https://example.test",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "findings": [
                {
                    "ref": "F1",
                    "severity": "medium",
                    "confidence": "medium",
                    "category": "access-control",
                    "title": "Candidate issue",
                    "location": "app.js",
                    "rule_id": "manual.candidate",
                    "description": "A candidate issue was detected.",
                    "snippet": "candidate evidence",
                }
            ],
            "attack_plans": {
                "F1": {
                    "steps": ["Open the target.", "Replay the request."],
                    "impact": "Potential sensitive data exposure.",
                    "proof_of_impact": "Needs confirmation.",
                }
            },
            "recommended_tools": [],
            "brain": {"used": False},
        }

        markdown = report_lib.build_markdown(ctx)
        json_doc = report_lib.build_json(ctx)

        self.assertIn("**Status:** Candidate / unverified", markdown)
        self.assertIn("**Gap:** Treat this as a lead", markdown)
        self.assertIn("[ ] Confirmed proof of impact is captured as concrete evidence.", markdown)
        self.assertEqual(json_doc["proof_of_impact"]["F1"]["status"], "candidate")
        self.assertFalse(json_doc["proof_of_impact"]["F1"]["ready"])

    def test_active_proof_renders_request_header_and_http_block(self) -> None:
        # A confirmed active finding carries request_line + request_header (the crafted
        # Origin:/Host:) — both must render, plus a copy-pasteable raw ```http block.
        ctx = {
            "tool": "GreyIQ BugHunter", "target": "https://example.test",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "findings": [{
                "ref": "F1", "severity": "high", "confidence": "high", "category": "headers",
                "class_id": "cors", "class_name": "CORS misconfiguration",
                "title": "Credentialed CORS reflection", "location": "https://example.test/api",
                "rule_id": "active.cors", "description": "Origin reflected with credentials.",
                "proof_evidence": {
                    "request_line": "GET https://example.test/api",
                    "request_header": "Origin: https://greyiq-marker.example",
                    "response_status": "HTTP 200",
                    "matched_value": "Access-Control-Allow-Origin: https://greyiq-marker.example; Access-Control-Allow-Credentials: true",
                },
            }],
            "attack_plans": {"F1": {"steps": ["Send a cross-origin request."], "impact": "Cross-origin theft."}},
            "recommended_tools": [], "brain": {"used": False},
        }
        single = report_lib.build_finding_markdown(ctx, ctx["findings"][0])
        self.assertIn("**Request header:**", single)
        self.assertIn("Origin: https://greyiq-marker.example", single)
        self.assertIn("```http", single)
        # The block reconstructs request -> response from the captured fields.
        self.assertIn("GET https://example.test/api", single)
        self.assertIn("HTTP 200", single)

    def test_captured_screenshot_embeds_on_both_default_report_paths(self) -> None:
        # A captured PoC screenshot must embed on the DEFAULT report (build_markdown +
        # build_finding_markdown), not only the per-platform package. It's referenced by
        # basename (the .png is bundled alongside the .md) and carries the not-redacted caveat.
        ctx = {
            "tool": "GreyIQ BugHunter", "target": "https://example.test",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "findings": [{
                "ref": "F1", "severity": "high", "confidence": "high", "category": "xss",
                "class_id": "xss", "class_name": "Reflected XSS", "title": "Reflected XSS",
                "location": "https://example.test/?q=", "rule_id": "active.xss",
                "description": "Reflected script executes.",
                "proof_of_impact": {"status": "confirmed"},
                "screenshot_path": "C:\\\\runtime\\\\screenshots\\\\poc-example-20260629.png",
            }],
            "attack_plans": {"F1": {"steps": ["Open the URL."], "impact": "Account takeover."}},
            "recommended_tools": [], "brain": {"used": False},
        }
        single = report_lib.build_finding_markdown(ctx, ctx["findings"][0])
        multi = report_lib.build_markdown(ctx)
        for md in (single, multi):
            self.assertIn("## Screenshot evidence", md)
            self.assertIn("![Proof-of-concept screenshot](poc-example-20260629.png)", md)  # basename only
            self.assertNotIn("C:\\\\runtime", md)  # never leak the absolute capture path
            self.assertIn("NOT auto-redacted", md)

    def test_direct_proof_capture_attaches_screenshot_and_source_text(self) -> None:
        finding = {
            "ref": "F1", "severity": "high", "confidence": "high", "category": "xss",
            "class_id": "xss", "class_name": "Reflected XSS", "title": "Reflected XSS",
            "location": "https://example.test/?q=1", "rule_id": "active.reflected-xss",
            "proof_evidence": {
                "request_line": "GET https://example.test/?q=<svg/onload=1>",
                "response_status": "HTTP 200",
                "matched_value": "<svg/onload=1>",
                "read_data": "<body><svg/onload=1></body>",
            },
        }
        plan = {"proof_of_impact": {
            "status": "confirmed",
            "observed_result": "payload reflected unescaped",
            "control_result": "plain marker did not execute",
            "evidence": "payload reflected unescaped",
        }}

        def fake_poc_url(_finding: dict, _ctx: dict) -> str:
            return "https://example.test/?q=<svg/onload=1>"

        def fake_capture(*_args: object, **_kwargs: object) -> dict:
            return {
                "ok": True,
                "path": "C:\\tmp\\proof-source.png",
                "source_text_path": "C:\\tmp\\proof-source.txt",
                "source_text": "REQUEST\nGET https://example.test/?q=<svg/onload=1>\nRESPONSE\nHTTP 200",
                "url": "https://example.test/?q=<svg/onload=1>",
                "final_url": "https://example.test/?q=<svg/onload=1>",
                "warning": "review before submit",
                "highlighted": True,
            }

        old_poc = bounty_lib.screenshot_service.poc_url_for_finding
        old_capture = bounty_lib.screenshot_service.capture_screenshot
        try:
            bounty_lib.screenshot_service.poc_url_for_finding = fake_poc_url
            bounty_lib.screenshot_service.capture_screenshot = fake_capture
            with tempfile.TemporaryDirectory() as tmp:
                count = _capture_direct_proof_artifacts(
                    [finding],
                    {"F1": plan},
                    Path(tmp),
                    "https://example.test",
                    "example.test",
                )
        finally:
            bounty_lib.screenshot_service.poc_url_for_finding = old_poc
            bounty_lib.screenshot_service.capture_screenshot = old_capture

        self.assertEqual(count, 1)
        self.assertEqual(finding["screenshot_path"], "C:\\tmp\\proof-source.png")
        self.assertIn("REQUEST", finding["source_text"])
        self.assertEqual(finding["proof_capture"]["status"], "captured")

    def test_passive_web_finding_gets_curl_repro_step(self) -> None:
        from bughunter.bounty import _deterministic_attack_plan
        finding = {
            "location": "https://example.test/?q=1", "rule_id": "web.missing-header.csp",
            "proof_evidence": {"request_line": "GET https://example.test/?q=1"},
        }
        plan = _deterministic_attack_plan(finding, "headers")
        self.assertTrue(any("curl -sSiL" in step for step in plan["steps"]))
        # A source-code finding (no URL) must NOT get a curl step.
        src_plan = _deterministic_attack_plan({"location": "app.py", "rule_id": "py.os-system"}, "rce")
        self.assertFalse(any("curl" in step for step in src_plan["steps"]))

    def test_report_polish_links_vrt_and_completeness(self) -> None:
        from bughunter import impact_model
        ctx = {
            "tool": "GreyIQ BugHunter", "target": "https://example.test",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "findings": [{
                "ref": "F1", "severity": "high", "confidence": "high", "category": "ssrf",
                "class_id": "ssrf", "class_name": "Server-side request forgery (SSRF)",
                "cwe": "CWE-918", "owasp": "A10:2021 SSRF", "vrt": impact_model.bugcrowd_vrt("ssrf"),
                "title": "SSRF", "location": "https://example.test/fetch?url=", "rule_id": "active.ssrf",
                "description": "The url parameter is fetched server-side.",
                "proof_evidence": {"request_line": "GET https://example.test/fetch?url=...", "response_status": "HTTP 200"},
                "references": impact_model.references_for_class("ssrf"),
            }],
            "attack_plans": {"F1": {"steps": ["a", "b"], "impact": "internal recon",
                                    "proof_of_impact": {"status": "confirmed", "observed_result": "o", "control_result": "c", "evidence": "e"},
                                    "remediation": "allowlist hosts"}},
            "recommended_tools": [], "brain": {"used": False},
        }
        single = report_lib.build_finding_markdown(ctx, ctx["findings"][0])
        self.assertIn("cwe.mitre.org/data/definitions/918.html", single)  # CWE deep link
        self.assertIn("owasp.org/Top10/", single)                          # OWASP deep link
        self.assertIn("Bugcrowd VRT", single)
        self.assertIn("server_side_request_forgery_ssrf", single)
        # build_json carries the per-finding completeness score (advisory).
        json_doc = report_lib.build_json(ctx)
        comp = json_doc["completeness"]["F1"]
        self.assertEqual(comp["score"], comp["max"])  # fully documented
        self.assertEqual(comp["missing"], [])

    def test_profiles_expose_expanded_focus_classes(self) -> None:
        payload = list_profiles()
        classes = {item["id"] for item in payload["classes"]}
        web_profile = next(profile for profile in payload["profiles"] if profile["id"] == "web-app")

        self.assertTrue({"csrf", "cors", "redirect", "file-upload", "business-logic", "supply-chain"} <= classes)
        self.assertIn("business-logic", web_profile["classes"])

    def test_modern_vuln_classes_present_and_well_formed(self) -> None:
        payload = list_profiles()
        classes = {item["id"]: item["name"] for item in payload["classes"]}
        modern = {"ssti", "xxe", "nosqli", "jwt", "graphql", "prototype-pollution",
                  "race-condition", "request-smuggling", "subdomain-takeover", "cloud-exposure"}
        self.assertTrue(modern <= set(classes), f"missing: {modern - set(classes)}")
        # Every modern class carries a CWE and a non-trivial checklist (3 steps).
        from bughunter.bounty import VULN_CLASSES
        for cid in modern:
            meta = VULN_CLASSES[cid]
            self.assertTrue(meta["cwe"], f"{cid} missing CWE")
            self.assertGreaterEqual(len(meta["checklist"]), 3, f"{cid} thin checklist")
        web = next(p for p in payload["profiles"] if p["id"] == "web-app")
        self.assertTrue({"ssti", "jwt", "graphql", "request-smuggling"} <= set(web["classes"]))
        source = next(p for p in payload["profiles"] if p["id"] == "source-code")
        self.assertIn("access-control", source["classes"])

    def test_class_value_floats_high_value_class_within_severity_band(self) -> None:
        ctx = {
            "kind": "url", "scanners_run": ["web"], "profile": {"id": "web-app"},
            "vuln_class": None, "manual_checklist": [], "recommended_tools": [], "attack_plans": {},
            "findings": [
                {"ref": "Fheaders", "severity": "high", "confidence": "high", "class_id": "headers", "title": "weak headers"},
                {"ref": "Fssti", "severity": "high", "confidence": "high", "class_id": "ssti", "title": "template injection"},
            ],
        }
        steps = next_steps_lib.build_next_steps(ctx)
        confirms = [s["ref"] for s in steps if s["phase"] == "Confirm findings"]
        # Same severity + confidence → the higher-value class (SSTI) is acted on first.
        self.assertLess(confirms.index("Fssti"), confirms.index("Fheaders"))

    def test_guided_next_steps_render_in_markdown_and_json(self) -> None:
        ctx = {
            "tool": "GreyIQ BugHunter", "version": "t", "generated_at": "now",
            "target": "https://example.test", "kind": "url",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "vuln_class": None, "scope": "acme", "authorized": True,
            "scanners_run": ["web"], "run_live_requested": False, "risk": "high", "score": 0.8,
            "findings": [
                {"ref": "F1", "severity": "high", "confidence": "high", "class_id": "access-control",
                 "class_name": "Broken access control / IDOR", "title": "IDOR", "location": "/api/orders/1"},
                {"ref": "F2", "severity": "low", "confidence": "medium", "class_id": "disclosure",
                 "class_name": "Information disclosure", "title": "Stack trace", "location": "/err"},
            ],
            "attack_plans": {"F1": {"steps": ["Locate the issue at /api/orders/1.", "Replay as account B."]}},
            "manual_checklist": ["Replay as a lower-privileged account."],
            "recommended_tools": [{"name": "Burp Suite", "url": "x", "maps_to": ["access-control"], "description": "p"}],
            "brain": {"used": False},
        }
        ctx["next_steps"] = next_steps_lib.build_next_steps(ctx, ["Probe /api/orders with account B."])
        ctx["coverage"] = next_steps_lib.coverage_summary(ctx)

        markdown = report_lib.build_markdown(ctx)
        json_doc = report_lib.build_json(ctx)

        self.assertIn("## Guided next steps", markdown)
        self.assertIn("### Coverage & gaps", markdown)
        self.assertIn("Confirm F1", markdown)
        self.assertTrue(json_doc["next_steps"])
        # Steps are numbered 1..N with no gaps, highest-impact confirm before submission.
        orders = [s["order"] for s in json_doc["next_steps"]]
        self.assertEqual(orders, list(range(1, len(orders) + 1)))
        phases = [s["phase"] for s in json_doc["next_steps"]]
        self.assertLess(phases.index("Confirm findings"), phases.index("Prepare submission"))

    def test_next_steps_high_confidence_medium_outranks_low_confidence_high(self) -> None:
        ctx = {
            "kind": "path", "scanners_run": ["code"], "profile": {"id": "source-code"},
            "vuln_class": None, "manual_checklist": [], "recommended_tools": [], "attack_plans": {},
            "findings": [
                {"ref": "Fhigh", "severity": "high", "confidence": "low", "class_id": "rce", "title": "maybe-rce"},
                {"ref": "Fmed", "severity": "medium", "confidence": "high", "class_id": "secrets", "title": "live-key"},
            ],
        }
        steps = next_steps_lib.build_next_steps(ctx)
        confirms = [s for s in steps if s["phase"] == "Confirm findings"]
        # Severity still dominates: the high (even low-confidence) confirms before the medium.
        self.assertEqual(confirms[0]["ref"], "Fhigh")
        # But the medium with a live, high-confidence secret is not buried — it has its own step.
        self.assertIn("Fmed", [s["ref"] for s in confirms])

    def test_next_steps_focus_unmatched_leads_with_manual_hunt(self) -> None:
        ctx = {
            "kind": "url", "scanners_run": ["web"], "profile": {"id": "web-app"},
            "vuln_class": {"id": "ssrf", "name": "Server-side request forgery (SSRF)"},
            "focus_unmatched": True, "other_findings_count": 3,
            "findings": [], "manual_checklist": [], "recommended_tools": [], "attack_plans": {},
        }
        steps = next_steps_lib.build_next_steps(ctx)
        hunt = next(s for s in steps if s["phase"] == "Hunt by hand")
        self.assertIn("SSRF", hunt["action"])
        self.assertIn("3 finding(s)", hunt["detail"])

    def test_coverage_flags_missing_dynamic_pass(self) -> None:
        cov = next_steps_lib.coverage_summary({"kind": "url", "scanners_run": ["web"]})
        self.assertTrue(any("dynamic" in g.lower() for g in cov["gaps"]))
        self.assertTrue(any("Passive web review" in c for c in cov["covered"]))


class ReproductionStepsTests(unittest.TestCase):
    """A triager's first act is to replay the bug, so every surface that delivers a repro must
    deliver it as an ORDERED, NUMBERED procedure — and everything that counts steps has to count
    the same steps the reader sees."""

    # The two shapes a brain (or a cached/imported ctx) really hands over.
    AS_STRING = "Send a GET to /search?q=marker\nObserve the marker reflected unencoded\nConfirm it executes"
    AS_BLOB = ["1. Send a GET to /search?q=marker\n2. Observe reflection\n3. Confirm execution"]
    AS_LIST = ["Send a GET to /search?q=marker", "Observe reflection", "Confirm execution"]

    def test_every_shape_normalizes_to_the_same_numbered_procedure(self) -> None:
        for label, raw in (("string", self.AS_STRING), ("blob", self.AS_BLOB), ("list", self.AS_LIST)):
            with self.subTest(shape=label):
                steps = report_lib.normalize_steps(raw)
                self.assertEqual(len(steps), 3, f"{label} must yield three steps: {steps}")
                for step in steps:
                    self.assertNotRegex(step, r"^\s*(?:\d+[.)]|[-*•])\s",
                                        "the renderer owns the numbering, not the source")
                    self.assertNotIn("\n", step, "a step must be one line so numbering stays 1:1")

    def test_a_bare_string_is_never_walked_character_by_character(self) -> None:
        """The failure this guards: iterating a string yields 'S', 'e', 'n'… which reached the
        operator's action plan as the literal opening move "S e"."""
        self.assertEqual(report_lib.normalize_steps("Send the request")[0], "Send the request")

    def test_the_readiness_check_counts_what_the_reader_sees(self) -> None:
        """Reading the raw field measured a CHARACTER count for a string (so any prose passed on
        length alone) and a single item for a multi-line blob (so a full procedure read as
        'not specific enough'). Both must agree with the rendered step count."""
        for label, raw in (("string", self.AS_STRING), ("blob", self.AS_BLOB), ("list", self.AS_LIST)):
            with self.subTest(shape=label):
                plan = {"steps": raw}
                rendered = len(report_lib.normalize_steps(raw))
                row = next(ok for ok, text in report_lib._finding_check_results({"ref": "F1"}, plan)
                           if "Reproduction steps" in text)
                self.assertEqual(row, rendered >= 2, f"{label}: checklist disagrees with the render")

    def test_one_real_step_is_not_advertised_as_replayable(self) -> None:
        plan = {"steps": ["Look at the page"]}
        self.assertFalse(next(ok for ok, text in report_lib._finding_check_results({"ref": "F1"}, plan)
                              if "Reproduction steps" in text))

    def test_the_operator_action_plan_quotes_real_steps(self) -> None:
        for label, raw in (("string", self.AS_STRING), ("blob", self.AS_BLOB)):
            with self.subTest(shape=label):
                opening = next_steps_lib._first_actions("F1", {"F1": {"steps": raw}}, [])
                self.assertIn("Send a GET", opening)
                self.assertNotRegex(opening, r"^\w \w$", "char-by-char garbling returned")

    def test_the_main_report_numbers_the_steps(self) -> None:
        ctx = _ctx_with_finding(steps=self.AS_LIST)
        markdown = report_lib.build_markdown(ctx)
        self.assertIn("1. Send a GET to /search?q=marker", markdown)
        self.assertIn("2. Observe reflection", markdown)
        self.assertIn("3. Confirm execution", markdown)

    def test_every_platform_export_numbers_the_steps(self) -> None:
        """render_finding is the one renderer behind all five platforms, so the numbered procedure
        must survive each reshaping."""
        from bughunter import report_formats

        ctx = _ctx_with_finding(steps=self.AS_LIST)
        finding = ctx["findings"][0]
        for platform in ("hackerone", "yeswehack", "bugcrowd", "intigriti", "hackenproof"):
            with self.subTest(platform=platform):
                body = report_formats.render_finding(ctx, finding, platform)
                self.assertIn("## Steps to reproduce", body)
                self.assertIn("1. Send a GET to /search?q=marker", body)
                self.assertIn("3. Confirm execution", body)


def _ctx_with_finding(*, steps: list[str]) -> dict:
    """A minimal reportable, confirmed finding plus the plan carrying its repro steps."""
    finding = {
        "ref": "F1", "rule_id": "active.reflected-xss", "title": "Reflected XSS",
        "class_id": "xss", "class_name": "Reflected XSS", "severity": "medium",
        "confidence": "high", "location": "https://app.example/search",
        "proof_evidence": {"request_line": "GET https://app.example/search?q=marker",
                           "response_status": "HTTP 200"},
    }
    plans = {"F1": {"steps": steps, "impact": "Script executes in a victim session.",
                    "proof_of_impact": {"status": "confirmed", "method": "differential",
                                        "observed_result": "marker executed",
                                        "control_result": "encoded, inert"}}}
    return {
        "tool": "GreyIQ BugHunter", "version": "test", "target": "https://app.example",
        "profile": {"name": "Web app"}, "risk": "medium", "score": 0.5,
        "findings": [finding], "attack_plans": plans, "scanners_run": ["active"],
        "authorized": True, "brain": {}, "next_steps": [], "coverage": {},
    }


class SeverityOrderingTests(unittest.TestCase):
    def test_order_by_resolved_severity_renumbers_and_rekeys(self) -> None:
        from bughunter.bounty import _order_by_resolved_severity
        # F1 reads high on the raw label but its CVSS is low; F2 is the reverse. The final
        # resolved severity (CVSS) must drive the order AND the ref numbers.
        display = [
            {"ref": "F1", "severity": "high", "title": "raw-high-cvss-low"},
            {"ref": "F2", "severity": "low", "title": "raw-low-cvss-critical"},
        ]
        plans = {"F1": {"cvss": {"base_severity": "low"}}, "F2": {"cvss": {"base_severity": "critical"}}}
        new_plans = _order_by_resolved_severity(display, plans)
        self.assertEqual(display[0]["title"], "raw-low-cvss-critical")
        self.assertEqual(display[0]["ref"], "F1")  # renumbered: critical is now F1
        self.assertEqual(display[1]["title"], "raw-high-cvss-low")
        self.assertEqual(display[1]["ref"], "F2")
        # Plans follow their finding to the new ref.
        self.assertEqual(new_plans["F1"]["cvss"]["base_severity"], "critical")
        self.assertEqual(new_plans["F2"]["cvss"]["base_severity"], "low")

    def test_order_is_stable_within_a_resolved_tier(self) -> None:
        from bughunter.bounty import _order_by_resolved_severity
        display = [
            {"ref": "F1", "severity": "high", "title": "first-high"},
            {"ref": "F2", "severity": "high", "title": "second-high"},
        ]
        _order_by_resolved_severity(display, {"F1": {}, "F2": {}})
        self.assertEqual([f["title"] for f in display], ["first-high", "second-high"])


class GroupDuplicateLeadsTests(unittest.TestCase):
    def test_collapses_same_rule_title_leads_across_locations(self) -> None:
        from bughunter.bounty import _group_duplicate_leads
        findings = [
            {"severity": "low", "class_id": "headers", "rule_id": "web.missing-header.csp", "title": "Missing CSP", "location": f"https://a.example/{i}"}
            for i in range(1, 4)
        ]
        grouped = _group_duplicate_leads(findings)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["group_count"], 3)
        self.assertEqual(grouped[0]["grouped_locations"], ["https://a.example/1", "https://a.example/2", "https://a.example/3"])

    def test_distinct_artifact_findings_never_collapse(self) -> None:
        from bughunter.bounty import _group_duplicate_leads
        # A captured VALUE (matched_value) or an active proof keeps a finding standalone;
        # a bare passive template (request_line only) is still groupable spam.
        findings = [
            {"class_id": "cors", "rule_id": "r", "title": "T", "location": "l1", "_active_proof": {"status": "confirmed"}},
            {"class_id": "cors", "rule_id": "r", "title": "T", "location": "l2", "proof_evidence": {"matched_value": "ACAO: *"}},
        ]
        grouped = _group_duplicate_leads(findings)
        self.assertEqual(len(grouped), 2)  # both carry distinct proof -> each stands alone
        for f in grouped:
            self.assertNotIn("group_count", f)

    def test_bare_passive_template_leads_are_grouped(self) -> None:
        from bughunter.bounty import _group_duplicate_leads
        # Identical missing-header leads whose only 'proof' is the GET template collapse.
        findings = [
            {"class_id": "headers", "rule_id": "web.missing-header.csp", "title": "Missing CSP",
             "location": f"https://a.example/{i}", "proof_evidence": {"request_line": f"GET https://a.example/{i}", "response_status": "HTTP 200"}}
            for i in range(1, 4)
        ]
        grouped = _group_duplicate_leads(findings)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["group_count"], 3)

    def test_unique_findings_are_untouched(self) -> None:
        from bughunter.bounty import _group_duplicate_leads
        findings = [
            {"class_id": "headers", "rule_id": "r1", "title": "A", "location": "l1"},
            {"class_id": "headers", "rule_id": "r2", "title": "B", "location": "l2"},
        ]
        grouped = _group_duplicate_leads(findings)
        self.assertEqual(len(grouped), 2)
        for f in grouped:
            self.assertNotIn("grouped_locations", f)
            self.assertNotIn("group_count", f)

    def test_grouped_finding_renders_instances_and_hint(self) -> None:
        ctx = {
            "tool": "GreyIQ BugHunter", "target": "https://a.example",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "findings": [{
                "ref": "F1", "severity": "low", "confidence": "low", "class_id": "headers",
                "class_name": "Security hardening (headers)", "title": "Missing CSP",
                "location": "https://a.example/1", "rule_id": "web.missing-header.csp",
                "group_count": 3, "grouped_locations": ["https://a.example/1", "https://a.example/2", "https://a.example/3"],
            }],
            "attack_plans": {"F1": {"steps": ["Add a CSP header."]}},
            "recommended_tools": [], "brain": {"used": False},
        }
        md = report_lib.build_markdown(ctx)
        self.assertIn("(+2 more)", md)          # findings-table hint
        self.assertIn("**Instances:**", md)     # detail list
        self.assertIn("https://a.example/3", md)
        single = report_lib.build_finding_markdown(ctx, ctx["findings"][0])
        self.assertIn("## Affected locations", single)
        self.assertIn("https://a.example/2", single)


class ExecutiveSummaryTests(unittest.TestCase):
    def _ctx(self, brain: dict) -> dict:
        return {
            "tool": "GreyIQ BugHunter", "target": "https://a.example",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "findings": [{"ref": "F1", "severity": "high", "confidence": "high", "class_id": "ssrf",
                          "class_name": "SSRF", "title": "SSRF", "location": "https://a.example/fetch", "rule_id": "active.ssrf"}],
            "attack_plans": {"F1": {"steps": ["a", "b"]}},
            "recommended_tools": [], "brain": brain,
        }

    def test_generic_summary_suppressed_when_brain_summary_present(self) -> None:
        md = report_lib.build_markdown(self._ctx({"used": True, "summary": "Analyst-written executive summary."}))
        self.assertIn("Analyst-written executive summary.", md)
        # The generic deterministic summary must NOT also print alongside it.
        self.assertNotIn("warrant immediate review", md)

    def test_default_summary_still_prints_without_a_brain(self) -> None:
        md = report_lib.build_markdown(self._ctx({"used": False}))
        self.assertIn("warrant immediate review", md)  # the high-impact default summary

    def test_tldr_and_report_title_render(self) -> None:
        md = report_lib.build_markdown(self._ctx({
            "used": True, "tldr": "One critical SSRF reaches cloud metadata.",
            "report_title": "SSRF in /fetch via the url parameter", "summary": "Details.",
        }))
        self.assertIn("TL;DR", md)
        self.assertIn("One critical SSRF reaches cloud metadata.", md)
        self.assertIn("Suggested report title:", md)
        self.assertIn("SSRF in /fetch via the url parameter", md)


class ChainRoleTests(unittest.TestCase):
    """The chain-role line must price THIS finding's step, not the chain's roll-up: the chain status
    is derived from the strongest evidence in the chain, so a purely projected step printed under a
    'confirmed' chain borrowed another finding's credibility."""

    def _ctx(self, step_state: str, chain_status: str = "confirmed") -> tuple[dict, dict]:
        finding = {"ref": "F2", "severity": "low", "confidence": "medium", "class_id": "cookies",
                   "class_name": "Cookie flags", "title": "Session cookie without HttpOnly",
                   "location": "https://a.example/login", "rule_id": "web.cookie-httponly"}
        ctx = {
            "tool": "GreyIQ BugHunter", "target": "https://a.example",
            "profile": {"id": "web-app", "name": "Web application", "description": ""},
            "findings": [finding], "attack_plans": {"F2": {"steps": ["a"]}},
            "recommended_tools": [], "brain": {"used": False},
            "investigation": {"attack_chains": [{
                "id": "C1", "title": "Session theft to account takeover", "status": chain_status,
                "projected_impact": "full account takeover", "refs": ["F1", "F2"],
                "steps": [{"n": 2, "title": "Read the session cookie", "evidence_ref": "F2",
                           "state": step_state}],
            }]},
        }
        return ctx, finding

    def test_a_projected_step_prints_its_own_state(self) -> None:
        ctx, finding = self._ctx("projected")
        md = report_lib.build_finding_markdown(ctx, finding)
        self.assertIn("this step is *projected*", md)
        self.assertIn("the chain is confirmed", md)          # ...attributed to the CHAIN, not the step
        self.assertIn("its projected impact is full account takeover", md)
        # the old wording put the chain's status where the step's belonged
        self.assertNotIn("(confirmed) — reaching", md)

    def test_a_proven_step_prints_proven(self) -> None:
        ctx, finding = self._ctx("proven", chain_status="candidate")
        md = report_lib.build_finding_markdown(ctx, finding)
        self.assertIn("this step is *proven*", md)
        self.assertIn("the chain is candidate", md)

    def test_a_stateless_step_defaults_to_projected(self) -> None:
        ctx, finding = self._ctx("")
        md = report_lib.build_finding_markdown(ctx, finding)
        self.assertIn("this step is *projected*", md)

    def test_the_standalone_file_defines_proven_and_projected(self) -> None:
        # The per-finding file carries no chain table, so the legend has to travel with the line.
        ctx, finding = self._ctx("projected")
        md = report_lib.build_finding_markdown(ctx, finding)
        self.assertIn("**Chain role:**", md)
        self.assertIn("a captured artifact the confirm gate accepted", md)
        self.assertIn("*projected* step is the next thing to prove", md)

    def test_the_full_report_body_carries_the_same_wording(self) -> None:
        ctx, _finding = self._ctx("projected")
        md = report_lib.build_markdown(ctx)
        self.assertIn("this step is *projected*", md)


class ConfirmedPlanProofStatusTests(unittest.TestCase):
    """A confirmation reached WITHOUT an ``_active_proof`` — the live-credential / JWT-replay /
    secret_hits routes — must land on the attack PLAN, not only on its CVSS. The plan's
    ``proof_of_impact.status`` comes from ``_deterministic_proof_status``, which never consults
    those carriers and so leaves 'candidate' behind; ``investigator._proof_status`` reads exactly
    that field as the finding's CLAIM. Left stale, the cortex called a report-confirmed finding an
    unproven lead ('gather-proof', not report-ready) in the same JSON document that confirmed it."""

    def _hunt(self, finding: dict) -> dict:
        """One real hunt over a stubbed code scan. The credential carrier is pre-set, so the
        hunt's liveness loop skips this finding and no request leaves the process."""
        original = bounty_lib.run_code_scan
        bounty_lib.run_code_scan = lambda target, target_type, max_files=5000: {
            "ok": True, "findings": [finding], "risk": "high", "score": 0.7,
            "files_scanned": 1, "finding_count": 1,
        }
        try:
            with tempfile.TemporaryDirectory() as tmp:
                return bounty_lib.run_bounty_hunt(
                    tmp, "secrets", None, tmp, "local QA fixture", True, {},
                    default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed", runtime_dir=None,
                )
        finally:
            bounty_lib.run_code_scan = original

    @staticmethod
    def _live_credential_finding() -> dict:
        # secret.github-pat is in secret_classification._CONFIRMED_VIA_LIVENESS, so a live
        # validator result makes this a confirmed_secret — the one confirm route that returns
        # early from report._proof_of_impact_detail, never touching the plan's own status.
        return {
            "rule_id": "secret.github-pat", "title": "GitHub personal access token in source",
            "severity": "high", "confidence": "high", "category": "secret",
            "file_path": "app/config.py", "line_start": 1, "line_end": 1,
            "snippet": "GITHUB_TOKEN = <token>", "secret_value": "ghp_" + "A" * 36,
            "_credential_proof": {
                "live": True, "principal": "acme-bot", "scopes": "repo",
                "http_status": 200, "endpoint": "https://api.github.com/user",
                "detail": "GitHub authenticated the token as acme-bot (scopes: repo)",
                "poc": "curl -s -H 'Authorization: token <redacted>' https://api.github.com/user",
                "response_excerpt": '{"login": "acme-bot"}',
            },
        }

    def test_confirmed_credential_route_syncs_the_plan_and_leaves_no_contradiction(self) -> None:
        result = self._hunt(self._live_credential_finding())
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["proof_of_impact"]["F1"]["status"], "confirmed")
        # The plan is the cortex's input; it must carry the same status the report granted.
        self.assertEqual(result["attack_plans"]["F1"]["proof_of_impact"]["status"], "confirmed")
        hypothesis = next(h for h in result["investigation"]["hypotheses"] if h["ref"] == "F1")
        self.assertEqual(hypothesis["claimed_proof_status"], "confirmed")
        self.assertEqual(hypothesis["status"], "confirmed")
        self.assertTrue(hypothesis["report_ready"])
        self.assertEqual(hypothesis["decision"], "report-now")
        self.assertEqual(result["investigation"]["contradictions"], [])
        self.assertEqual(result["investigation"]["metrics"]["contradictions"], 0)

    def test_an_unproven_secret_is_never_promoted_by_the_sync(self) -> None:
        # The sync only ECHOES the confirm authority: with the credential dead, classification
        # marks the finding false_positive/candidate, the report stays unconfirmed, and the plan
        # must NOT read 'confirmed'. (A dead credential is dropped from the report entirely.)
        dead = self._live_credential_finding()
        dead["_credential_proof"] = {"live": False, "http_status": 401, "detail": "token rejected"}
        result = self._hunt(dead)
        self.assertTrue(result["ok"], result.get("error"))
        for ref, detail in (result["proof_of_impact"] or {}).items():
            self.assertNotEqual(detail["status"], "confirmed", ref)
        for ref, plan in (result["attack_plans"] or {}).items():
            poi = plan.get("proof_of_impact")
            if isinstance(poi, dict):
                self.assertNotEqual(poi.get("status"), "confirmed", ref)


if __name__ == "__main__":
    unittest.main()
