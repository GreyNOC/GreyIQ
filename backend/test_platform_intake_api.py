"""Offline contracts for credentialed, read-only platform program intake.

All platform adapters are mocked here. A discovered program or scope preview is
information for operator review and must never persist a program or grant tests.
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402


def _call_route(method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    body = json.dumps(payload or {}).encode("utf-8") if method == "POST" else b""
    sent_body = False
    status = 0
    response = bytearray()

    async def receive():
        nonlocal sent_body
        if sent_body:
            return {"type": "http.disconnect"}
        sent_body = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
        elif message["type"] == "http.response.body":
            response.extend(message.get("body", b""))

    headers = [(b"host", b"127.0.0.1:8791"),
               (b"x-greyiq-token", api.SESSION_TOKEN.encode("ascii"))]
    if method == "POST":
        headers.append((b"content-type", b"application/json"))
    scope = {"method": method, "path": path, "headers": headers,
             "scheme": "http", "query_string": b""}
    asyncio.run(api.route_http(scope, receive, send))
    return status, json.loads(response)


class PlatformIntakeRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.secrets_path = Path(self.temp.name) / "secrets.json"
        secret_patch = patch.object(api, "SECRETS_PATH", self.secrets_path)
        secret_patch.start()
        self.addCleanup(secret_patch.stop)
        # The intake methods do not need to initialize the model, store, or API
        # server. Skipping __init__ also prevents writes to the real runtime.
        self.runtime = object.__new__(api.GreyIQRuntime)

    def test_credential_status_returns_presence_never_secret_values(self) -> None:
        secrets = {
            "hackerone.team_handle": "example", "hackerone.api_username": "api-id",
            "hackerone.api_token": "H1-SECRET-123",
            "yeswehack.email": "hunter@example.test", "yeswehack.token_kind": "jwt",
            "yeswehack.api_token": "YWH-SECRET-123",
            "platform.bugcrowd.credential": "bc-id:BC-SECRET-123",
            "platform.intigriti.credential": "INT-SECRET-123",
        }
        self.secrets_path.write_text(json.dumps(secrets), encoding="utf-8")

        result = self.runtime.platform_credentials_status()

        self.assertTrue(result["ok"])
        self.assertEqual(set(result["platforms"]),
                         {"hackerone", "yeswehack", "bugcrowd", "intigriti"})
        self.assertTrue(all(p["has_token"] for p in result["platforms"].values()))
        serialized = json.dumps(result)
        for secret in ("H1-SECRET-123", "YWH-SECRET-123", "BC-SECRET-123", "INT-SECRET-123"):
            self.assertNotIn(secret, serialized)

    def test_save_clear_and_reject_invalid_credentials_without_echo(self) -> None:
        bc = self.runtime.save_platform_credential(
            api.PlatformCredentialRequest(platform=" BUGCROWD ", credential="bc-id:bc-secret"))
        self.assertEqual(bc, {"ok": True, "platform": "bugcrowd", "has_token": True})
        self.assertEqual(api._load_secrets()["platform.bugcrowd.credential"], "bc-id:bc-secret")

        invalid = self.runtime.save_platform_credential(
            api.PlatformCredentialRequest(platform="bugcrowd", credential="bad\nsecret"))
        self.assertFalse(invalid["ok"])
        self.assertNotIn("bad\nsecret", json.dumps(invalid))
        self.assertEqual(api._load_secrets()["platform.bugcrowd.credential"], "bc-id:bc-secret")

        it = self.runtime.save_platform_credential(
            api.PlatformCredentialRequest(platform="intigriti", credential="bearer-secret"))
        self.assertTrue(it["has_token"])
        cleared = self.runtime.save_platform_credential(
            api.PlatformCredentialRequest(platform="bugcrowd", clear_token=True))
        self.assertFalse(cleared["has_token"])
        self.assertNotIn("platform.bugcrowd.credential", api._load_secrets())
        self.assertEqual(api._load_secrets()["platform.intigriti.credential"], "bearer-secret")
        self.assertFalse(self.runtime.save_platform_credential(
            api.PlatformCredentialRequest(platform="hackerone", credential="irrelevant"))["ok"])

    def test_discovery_delegates_each_platform_and_never_saves_program(self) -> None:
        secrets = {
            "hackerone.api_username": "h1-id", "hackerone.api_token": "h1-token",
            "yeswehack.api_token": "ywh-token", "yeswehack.token_kind": "jwt",
            "platform.bugcrowd.credential": "bc-id:bc-token",
            "platform.intigriti.credential": "int-token",
        }
        self.secrets_path.write_text(json.dumps(secrets), encoding="utf-8")
        h1_result = {"ok": True, "programs": [
            {"handle": "alpha", "name": "Alpha", "submission_state": "open", "source_url": "https://hackerone.com/alpha"},
            {"handle": "beta", "name": "Beta", "submission_state": "closed", "source_url": "https://hackerone.com/beta"}]}
        ywh_result = {"ok": True, "programs": [{"slug": "alpha", "title": "Alpha", "disabled": False}]}
        generic_result = {"ok": True, "programs": [{"id": "uuid", "handle": "alpha", "name": "Alpha", "status": "open"}]}
        with (patch.object(api.bounty_h1_import, "list_programs", return_value=h1_result) as h1,
              patch.object(api.bounty_ywh_import, "list_programs", return_value=ywh_result) as ywh,
              patch.object(api.bounty_platform_programs, "list_programs", return_value=generic_result) as generic,
              patch.object(api.bounty_portfolio, "upsert_program") as upsert):
            h1_rows = self.runtime.discover_platform_programs(
                api.PlatformProgramsRequest(platform="HACKERONE", query="Alp", limit=12))
            ywh_rows = self.runtime.discover_platform_programs(
                api.PlatformProgramsRequest(platform="yeswehack", query="Alp", limit=12))
            bc_rows = self.runtime.discover_platform_programs(
                api.PlatformProgramsRequest(platform="bugcrowd", query="alp", limit=12))
            int_rows = self.runtime.discover_platform_programs(
                api.PlatformProgramsRequest(platform="intigriti", query="alp", limit=12))
            upsert.assert_not_called()

        h1.assert_called_once_with("h1-id", "h1-token", max_entries=12)
        ywh.assert_called_once_with(token="ywh-token", token_kind="jwt", query="Alp", max_entries=12)
        self.assertEqual(generic.call_args_list[0].args, ("bugcrowd", "bc-id:bc-token"))
        self.assertEqual(generic.call_args_list[1].args, ("intigriti", "int-token"))
        self.assertTrue(all(call.kwargs == {"limit": 12} for call in generic.call_args_list))
        for result in (h1_rows, ywh_rows, bc_rows, int_rows):
            self.assertTrue(result["ok"])
            self.assertEqual(result["count"], 1)
            self.assertEqual(result["programs"][0]["name"], "Alpha")
            self.assertNotIn("authorized", result["programs"][0])
        self.assertEqual(h1_rows["programs"][0]["status"], "open")
        self.assertEqual(ywh_rows["programs"][0]["status"], "visible")

    def test_failed_discovery_returns_no_partial_candidates(self) -> None:
        failure = {"ok": False, "error": "API unavailable", "programs": [{"name": "stale"}]}
        with patch.object(api.bounty_platform_programs, "list_programs", return_value=failure):
            result = self.runtime.discover_platform_programs(
                api.PlatformProgramsRequest(platform="bugcrowd"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["programs"], [])
        self.assertEqual(result["error"], "API unavailable")

    def test_preview_delegates_all_platforms_and_stays_review_only(self) -> None:
        self.secrets_path.write_text(json.dumps({
            "platform.bugcrowd.credential": "bc-id:bc-token",
            "platform.intigriti.credential": "int-token"}), encoding="utf-8")
        adapter_result = {"ok": True, "name": "Example", "scope_complete": True,
                          "authorized": True, "enabled": True, "warnings": ["partial API record"]}
        with (patch.object(self.runtime, "import_hackerone_scope", return_value=adapter_result) as h1,
              patch.object(self.runtime, "import_yeswehack_scope", return_value=adapter_result) as ywh,
              patch.object(api.bounty_platform_programs, "preview_program", return_value=adapter_result) as generic,
              patch.object(api.bounty_portfolio, "upsert_program") as upsert):
            previews = [self.runtime.preview_platform_program(
                api.PlatformPreviewRequest(platform=p, program_id="example"))
                for p in ("hackerone", "yeswehack", "bugcrowd", "intigriti")]
            upsert.assert_not_called()

        self.assertEqual(h1.call_args.args[0].handle, "example")
        self.assertEqual(ywh.call_args.args[0].slug, "example")
        self.assertEqual(generic.call_args_list[0].args, ("bugcrowd", "example", "bc-id:bc-token"))
        self.assertEqual(generic.call_args_list[1].args, ("intigriti", "example", "int-token"))
        for platform, preview in zip(("hackerone", "yeswehack", "bugcrowd", "intigriti"), previews):
            self.assertTrue(preview["ok"])
            self.assertEqual(preview["platform"], platform)
            self.assertEqual(preview["program_id"], "example")
            self.assertFalse(preview["scope_complete"])
            self.assertFalse(preview.get("authorized", False))
            self.assertFalse(preview.get("enabled", False))
            self.assertIn("partial API record", preview["warnings"])
            self.assertTrue(any("authorization" in warning for warning in preview["warnings"]))
            self.assertTrue(preview["fetched_at"])

    def test_unsupported_platform_does_not_call_any_adapter(self) -> None:
        with (patch.object(api.bounty_platform_programs, "list_programs") as listing,
              patch.object(api.bounty_platform_programs, "preview_program") as preview):
            self.assertFalse(self.runtime.discover_platform_programs(
                api.PlatformProgramsRequest(platform="unknown"))["ok"])
            self.assertFalse(self.runtime.preview_platform_program(
                api.PlatformPreviewRequest(platform="unknown", program_id="x"))["ok"])
        listing.assert_not_called()
        preview.assert_not_called()


class PlatformIntakeRouteTests(unittest.TestCase):
    def test_credentials_routes_delegate_and_validate(self) -> None:
        with (patch.object(api.runtime, "platform_credentials_status", return_value={"ok": True, "platforms": {}}) as status_fn,
              patch.object(api.runtime, "save_platform_credential", return_value={"ok": True, "has_token": True}) as save_fn):
            status, body = _call_route("GET", "/api/platforms/credentials")
            self.assertEqual((status, body), (200, {"ok": True, "platforms": {}}))
            status_fn.assert_called_once_with()
            status, body = _call_route("POST", "/api/platforms/credentials",
                                       {"platform": "bugcrowd", "credential": "id:secret"})
            self.assertEqual(status, 200)
            self.assertTrue(body["has_token"])
            self.assertEqual(save_fn.call_args.args[0].platform, "bugcrowd")
            self.assertEqual(save_fn.call_args.args[0].credential, "id:secret")

            status, _ = _call_route("POST", "/api/platforms/credentials", {"platform": ""})
            self.assertEqual(status, 422)
            self.assertEqual(save_fn.call_count, 1)

    def test_discovery_and_preview_routes_delegate_typed_requests(self) -> None:
        with (patch.object(api.runtime, "discover_platform_programs", return_value={"ok": True, "programs": []}) as discover,
              patch.object(api.runtime, "preview_platform_program", return_value={"ok": True, "scope_complete": False}) as preview):
            status, body = _call_route("POST", "/api/platforms/programs",
                                       {"platform": "intigriti", "query": "acme", "limit": 7})
            self.assertEqual(status, 200)
            self.assertEqual(body["programs"], [])
            self.assertEqual(discover.call_args.args[0].platform, "intigriti")
            self.assertEqual(discover.call_args.args[0].limit, 7)
            status, body = _call_route("POST", "/api/platforms/preview",
                                       {"platform": "intigriti", "program_id": "program-1"})
            self.assertEqual(status, 200)
            self.assertFalse(body["scope_complete"])
            self.assertEqual(preview.call_args.args[0].program_id, "program-1")

            status, _ = _call_route("POST", "/api/platforms/programs",
                                    {"platform": "intigriti", "limit": 101})
            self.assertEqual(status, 422)
            self.assertEqual(discover.call_count, 1)


if __name__ == "__main__":
    unittest.main()
