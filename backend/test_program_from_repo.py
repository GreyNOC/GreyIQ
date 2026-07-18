"""Repo-link program onboarding stays passive, bounded, and operator-confirmed."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402
from bughunter import forge_metadata, portfolio  # noqa: E402


class ProgramFromRepoTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = api.RUNTIME_DIR
        self._orig_enrich = api.bounty_forge_metadata.enrich_repositories
        api.RUNTIME_DIR = Path(self._tmp.name)
        self.runtime = api.GreyIQRuntime.__new__(api.GreyIQRuntime)

    def tearDown(self) -> None:
        api.RUNTIME_DIR = self._orig_runtime_dir
        api.bounty_forge_metadata.enrich_repositories = self._orig_enrich
        self._tmp.cleanup()

    def create(self, urls: list[str], *, enrich: bool = False) -> dict:
        request = api.ProgramFromRepoRequest(repository_urls=urls, enrich=enrich)
        return api.GreyIQRuntime.program_from_repo(self.runtime, request)

    def test_tier_one_creates_empty_scope_inactive_draft_from_supported_roots(self) -> None:
        result = self.create([
            "https://github.com/acme/webapp/",
            "https://gitlab.com/acme/api",
            "https://github.com/acme/webapp",
        ])
        self.assertTrue(result["ok"])
        program = result["program"]
        self.assertEqual(program["name"], "Acme")
        self.assertEqual(program["repository_urls"], [
            "https://github.com/acme/webapp",
            "https://gitlab.com/acme/api",
        ])
        self.assertTrue(program["clone_repositories"])
        self.assertEqual(program["scope_text"], "")
        self.assertEqual(program["structured_scope"], [])
        self.assertEqual(program["in_scope_hosts"], [])
        self.assertEqual(program["seed_targets"], [])
        self.assertFalse(program["active"])
        self.assertFalse(program["live"])
        self.assertFalse(program["deep"])
        self.assertFalse(program["auto_submit"])
        self.assertFalse(program["enabled"])  # cannot be picked up by a running Operator before review
        self.assertNotIn("repo_draft_pending", program)  # internal marker is never exposed
        self.assertIn("scope is source-only", program["notes"])

        stored = portfolio.get_program(api.RUNTIME_DIR, program["id"])
        self.assertEqual(stored["scope_text"], "")
        self.assertTrue(stored["repo_draft_pending"])

    def test_owner_names_preserve_acronyms_and_mixed_case(self) -> None:
        # Plain words are Titlecased; acronyms and mixed-case handles are kept verbatim
        # (was mangled by str.title: OWASP -> "Owasp", GitLab -> "Gitlab").
        self.assertEqual(self.create(["https://github.com/OWASP/NodeGoat"])["program"]["name"], "OWASP")
        self.assertEqual(self.create(["https://github.com/GitLab/app"])["program"]["name"], "GitLab")
        self.assertEqual(self.create(["https://github.com/acme-corp/api"])["program"]["name"], "Acme Corp")
        multi = self.create(["https://github.com/OWASP/a", "https://gitlab.com/PortSwigger/b"])["program"]
        self.assertEqual(multi["name"], "OWASP + PortSwigger")

    def test_first_program_form_save_finalizes_only_the_repository_scope(self) -> None:
        draft = self.create(["https://github.com/acme/webapp"])["program"]
        saved = self.runtime.upsert_program(api.ProgramUpsertRequest(
            id=draft["id"],
            name=draft["name"],
            repository_urls=draft["repository_urls"],
            clone_repositories=True,
            structured_scope=[],
            resync_scope=True,
            enabled=False,
        ))["program"]
        self.assertEqual(saved["scope_text"], "https://github.com/acme/webapp")
        self.assertEqual(saved["structured_scope"], [])
        self.assertFalse(saved["active"])

    def test_all_invalid_inputs_are_rejected_without_writing_a_program(self) -> None:
        invalid_inputs = [
            [],
            ["https://github.com/acme/webapp/issues"],
            ["https://github.com/acme/webapp/blob/main/app.py"],
            ["https://gitlab.com/acme/webapp/-/tree/main"],
            ["https://example.com/acme/webapp"],
            ["https://user:secret@github.com/acme/webapp"],
        ]
        for urls in invalid_inputs:
            with self.subTest(urls=urls):
                result = self.create(urls)
                self.assertFalse(result["ok"])
                self.assertIn("repository-root", result["error"])
                self.assertIn("supported forge", result["error"])
                self.assertEqual(portfolio.list_programs(api.RUNTIME_DIR), [])

    def test_enrich_false_never_invokes_forge_fetch(self) -> None:
        def forbidden(*args, **kwargs):  # noqa: ANN002, ANN003
            raise AssertionError("enrichment fetch must stay off by default")

        api.bounty_forge_metadata.enrich_repositories = forbidden
        result = self.create(["https://github.com/acme/webapp"], enrich=False)
        self.assertTrue(result["ok"])
        self.assertEqual(result["candidate_hosts"], [])

    def test_enrichment_returns_candidates_without_authorizing_or_persisting_them(self) -> None:
        calls: list[tuple[list[str], float]] = []

        def fake_enrich(urls, *, timeout):  # noqa: ANN001
            calls.append((list(urls), timeout))
            return {
                "descriptions": [{
                    "repository_url": urls[0],
                    "description": "Public application source",
                }],
                "candidate_hosts": ["app.acme.test"],
            }

        api.bounty_forge_metadata.enrich_repositories = fake_enrich
        result = self.create(["https://github.com/acme/webapp"], enrich=True)
        self.assertEqual(calls, [(["https://github.com/acme/webapp"], 10.0)])
        self.assertEqual(result["candidate_hosts"], ["app.acme.test"])
        self.assertIn("Public application source", result["program"]["notes"])
        for field in ("scope_text", "in_scope_hosts", "out_of_scope_hosts", "seed_targets"):
            self.assertNotIn("app.acme.test", result["program"].get(field) or [])
        self.assertEqual(result["program"]["structured_scope"], [])
        stored = portfolio.get_program(api.RUNTIME_DIR, result["program"]["id"])
        self.assertEqual(stored["structured_scope"], [])
        self.assertNotIn("app.acme.test", json.dumps(stored))

    def test_enrichment_failure_never_blocks_local_draft_creation(self) -> None:
        def failed_enrich(*args, **kwargs):  # noqa: ANN002, ANN003
            raise OSError("forge unavailable")

        api.bounty_forge_metadata.enrich_repositories = failed_enrich
        result = self.create(["https://github.com/acme/webapp"], enrich=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["candidate_hosts"], [])
        self.assertEqual(result["program"]["scope_text"], "")

    def test_repeat_is_idempotent_and_preserves_existing_program_choices(self) -> None:
        first = self.create(["https://github.com/acme/webapp"])["program"]
        portfolio.upsert_program(api.RUNTIME_DIR, {
            "id": first["id"],
            "name": first["name"],
            "repo_draft_pending": False,
            "scope_text": "app.acme.test",
            "in_scope_hosts": ["app.acme.test"],
            "repository_urls": first["repository_urls"],
            "clone_repositories": True,
            "active": True,
            "enabled": True,
            "account_access": {"email": "researcher@acme.test", "password": "secret"},
            "notes": first["notes"] + "\nOperator note.",
        })

        second = self.create([
            "https://github.com/acme/webapp",
            "https://gitlab.com/acme/api",
        ])["program"]
        self.assertEqual(second["id"], first["id"])
        self.assertEqual(len(portfolio.list_programs(api.RUNTIME_DIR)), 1)
        self.assertEqual(second["scope_text"], "app.acme.test")
        self.assertTrue(second["active"])
        self.assertTrue(second["enabled"])
        self.assertEqual(second["repository_urls"], [
            "https://github.com/acme/webapp",
            "https://gitlab.com/acme/api",
        ])
        self.assertEqual(second["notes"].count(api._REPO_DRAFT_PROVENANCE), 1)
        stored = portfolio.get_program(api.RUNTIME_DIR, first["id"])
        self.assertEqual(stored["account_access"]["password"], "secret")


class ForgeMetadataTests(unittest.TestCase):
    def test_one_get_per_supported_api_repo_and_candidates_are_domains(self) -> None:
        calls: list[tuple[str, float]] = []

        def fake_fetch(url, *, timeout):  # noqa: ANN001
            calls.append((url, timeout))
            if "api.github.com" in url:
                return {"description": "Web app", "homepage": "https://App.Acme.Test/path"}
            return {"description": "API", "web_url": "https://gitlab.com/acme/api"}

        result = forge_metadata.enrich_repositories([
            "https://github.com/acme/webapp",
            "https://gitlab.com/acme/api",
            "https://bitbucket.org/acme/worker",
        ], fetch=fake_fetch)
        self.assertEqual(calls, [
            ("https://api.github.com/repos/acme/webapp", 10.0),
            ("https://gitlab.com/api/v4/projects/acme%2Fapi", 10.0),
        ])
        self.assertEqual(result["candidate_hosts"], ["app.acme.test", "gitlab.com"])
        self.assertEqual(len(result["descriptions"]), 2)

    def test_fetch_failure_is_swallowed(self) -> None:
        result = forge_metadata.enrich_repositories(
            ["https://github.com/acme/webapp"],
            fetch=lambda *args, **kwargs: (_ for _ in ()).throw(OSError("offline")),
        )
        self.assertEqual(result, {"descriptions": [], "candidate_hosts": []})

    def test_ip_and_localhost_homepages_are_not_domain_suggestions(self) -> None:
        for homepage in ("http://127.0.0.1/admin", "http://localhost:8080/"):
            with self.subTest(homepage=homepage):
                result = forge_metadata.enrich_repositories(
                    ["https://github.com/acme/webapp"],
                    fetch=lambda *args, **kwargs: {"homepage": homepage},
                )
                self.assertEqual(result["candidate_hosts"], [])


def _receive_once(body: bytes):
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


class _Capture:
    def __init__(self) -> None:
        self.status: int | None = None
        self.body = b""

    async def send(self, message: dict) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
        elif message["type"] == "http.response.body":
            self.body += message.get("body", b"")


class ProgramFromRepoRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = api.RUNTIME_DIR
        api.RUNTIME_DIR = Path(self._tmp.name)

    def tearDown(self) -> None:
        api.RUNTIME_DIR = self._orig_runtime_dir
        self._tmp.cleanup()

    def test_post_route_validates_and_dispatches(self) -> None:
        body = json.dumps({
            "repository_urls": ["https://github.com/acme/webapp"],
            "enrich": False,
        }).encode()
        capture = _Capture()
        scope = {
            "method": "POST",
            "path": "/api/programs/from-repo",
            "scheme": "http",
            "query_string": b"",
            "headers": [
                (b"host", b"127.0.0.1:8766"),
                (b"content-type", b"application/json"),
                (b"x-greyiq-token", api.SESSION_TOKEN.encode("ascii")),
            ],
        }
        asyncio.run(api.route_http(scope, _receive_once(body), capture.send))
        self.assertEqual(capture.status, 200)
        result = json.loads(capture.body)
        self.assertTrue(result["ok"])
        self.assertEqual(result["program"]["name"], "Acme")


if __name__ == "__main__":
    unittest.main()
