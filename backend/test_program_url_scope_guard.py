"""Saved URL scope must not become a host-wide manual hunt authorization."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402
from bughunter import portfolio  # noqa: E402


def _program(identifier: str, *, extra_rows: list[dict] | None = None) -> dict:
    rows = [{"identifier": identifier, "eligible_for_submission": True}, *(extra_rows or [])]
    return {"id": "p1", "name": "Reviewed program", "platform": "intigriti",
            "structured_scope": rows, "scope_text": " ".join(
                row["identifier"] for row in rows if row.get("eligible_for_submission", True))}


class UrlScopeClassificationTests(unittest.TestCase):
    def test_path_scheme_query_and_port_require_independent_host_scope(self) -> None:
        for identifier in ("https://app.example.test/allowed", "https://app.example.test",
                           "app.example.test/allowed", "https://app.example.test:8443/",
                           "https://app.example.test/?only=one"):
            with self.subTest(identifier=identifier):
                self.assertIn("host-only", portfolio.manual_web_scope_error(_program(identifier)))

    def test_explicit_host_or_wildcard_row_authorizes_wider_host(self) -> None:
        url = "https://app.example.test/allowed"
        for explicit in ("app.example.test", "*.example.test"):
            with self.subTest(explicit=explicit):
                self.assertEqual(portfolio.manual_web_scope_error(_program(url, extra_rows=[
                    {"identifier": explicit, "eligible_for_submission": True}])), "")

    def test_bare_host_does_not_authorize_a_different_subdomain(self) -> None:
        program = _program("https://bar.foo.example.test/allowed", extra_rows=[
            {"identifier": "foo.example.test", "eligible_for_submission": True}])
        self.assertTrue(portfolio.manual_web_scope_error(program))

    def test_stale_derived_host_list_does_not_override_url_limit(self) -> None:
        program = _program("https://app.example.test/allowed")
        program["in_scope_hosts"] = ["app.example.test"]
        self.assertTrue(portfolio.manual_web_scope_error(program))

    def test_exclusion_does_not_grant_host_scope_and_repo_root_is_not_web_scope(self) -> None:
        url = "https://app.example.test/allowed"
        self.assertTrue(portfolio.manual_web_scope_error(_program(url, extra_rows=[
            {"identifier": "app.example.test", "eligible_for_submission": False}])))
        repo = _program("https://github.com/acme/repository")
        self.assertTrue(portfolio.manual_web_scope_error(repo))
        repo["clone_repositories"] = True
        repo["repository_urls"] = ["https://github.com/acme/repository"]
        self.assertEqual(portfolio.manual_web_scope_error(repo), "")


class RuntimeUrlScopeGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
        self.program = _program("https://app.example.test/allowed")

    def test_single_and_whole_program_campaign_refuse_before_dispatch(self) -> None:
        with (patch.object(api.bounty_portfolio, "get_program", return_value=self.program),
              patch.object(api.bounty_campaign, "run_campaign", side_effect=AssertionError("network")),
              patch.object(api.bounty_campaign, "run_campaign_over_targets", side_effect=AssertionError("network"))):
            single = self.rt.run_campaign(api.CampaignRequest(
                target="https://app.example.test/allowed", scope=self.program["scope_text"],
                active_program_id="p1", authorized=True, active=True))
            whole = self.rt.run_campaign(api.CampaignRequest(
                program_id="p1", authorized=True, active=True))
        self.assertFalse(single["ok"])
        self.assertFalse(whole["ok"])
        self.assertIn("host-only", single["error"])

    def test_portfolio_rejects_before_any_selected_program_runs(self) -> None:
        with (patch.object(api.bounty_portfolio, "list_programs", return_value=[self.program]),
              patch.object(api.bounty_campaign, "run_portfolio_campaign", side_effect=AssertionError("network"))):
            result = self.rt.run_portfolio(api.PortfolioRequest(all_programs=True, authorized=True))
        self.assertFalse(result["ok"])
        self.assertIn("Reviewed program", result["error"])

    def test_active_prove_and_reverify_refuse_before_probe(self) -> None:
        with (patch.object(api.bounty_portfolio, "get_program", return_value=self.program),
              patch.object(api.bounty_active_verify, "verify_active", side_effect=AssertionError("network"))):
            prove = self.rt.prove_finding(api.ProveRequest(
                url="https://app.example.test/allowed", program_id="p1", authorized=True))
            reverify = self.rt.reverify_finding(api.ReverifyRequest(
                url="https://app.example.test/allowed", program_id="p1", authorized=True))
        self.assertFalse(prove["ok"])
        self.assertFalse(reverify["ok"])

    def test_run_backed_screenshot_refuses_before_browser_navigation(self) -> None:
        self.rt._resolve_run_finding = lambda run_id, ref: (
            {"scope": self.program["scope_text"]}, {"title": "Finding", "location": "https://app.example.test/allowed"},
            {"program_id": "p1"})
        with (patch.object(api.bounty_portfolio, "get_program", return_value=self.program),
              patch.object(api.bounty_screenshot, "poc_url_for_finding",
                           return_value="https://app.example.test/allowed"),
              patch.object(api.bounty_screenshot, "capture_screenshot",
                           side_effect=AssertionError("browser navigation"))):
            result = self.rt.capture_screenshot(api.ScreenshotRequest(run_id="r1", ref="F1"))
        self.assertFalse(result["ok"])


class ExclusionResyncTests(unittest.TestCase):
    def test_missing_old_exclusion_is_preserved_and_new_exclusions_are_added(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = portfolio.upsert_program(directory, {"name": "Acme", "structured_scope": [
                {"identifier": "*.example.test", "eligible_for_submission": True},
                {"identifier": "https://admin.example.test/private", "eligible_for_submission": False},
            ]})
            updated = portfolio.upsert_program(directory, {"id": first["id"], "name": "Acme",
                "resync_scope": True, "structured_scope": [
                    {"identifier": "*.example.test", "eligible_for_submission": True},
                    {"identifier": "billing.example.test", "eligible_for_submission": False},
                ]})
            self.assertEqual(updated["out_of_scope_hosts"],
                             ["admin.example.test", "billing.example.test"])

    def test_explicit_removal_is_transient_and_does_not_remove_new_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = portfolio.upsert_program(directory, {"name": "Acme", "structured_scope": [
                {"identifier": "*.example.test", "eligible_for_submission": True},
                {"identifier": "https://admin.example.test/private", "eligible_for_submission": False},
            ]})
            updated = portfolio.upsert_program(directory, {"id": first["id"], "name": "Acme",
                "resync_scope": True,
                "remove_out_of_scope_hosts": ["https://admin.example.test/private"],
                "structured_scope": [{"identifier": "*.example.test", "eligible_for_submission": True}]})
            self.assertEqual(updated["out_of_scope_hosts"], [])
            self.assertNotIn("remove_out_of_scope_hosts", updated)
            self.assertEqual(portfolio.get_program(directory, first["id"])["out_of_scope_hosts"], [])

    def test_deleting_all_structured_rows_clears_prior_derived_positive_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = portfolio.upsert_program(directory, {"name": "Acme", "active": True,
                "structured_scope": [{"identifier": "app.example.test", "eligible_for_submission": True}]})
            updated = portfolio.upsert_program(directory, {"id": first["id"], "name": "Acme",
                "resync_scope": True, "structured_scope": []})
            self.assertEqual(updated["scope_text"], "")
            self.assertFalse(updated["active"])


if __name__ == "__main__":
    unittest.main()
