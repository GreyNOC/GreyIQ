"""Tests for greyiq_api's request-body parsing, payload validation, and the cached
run-state locking around concurrent /api/* calls.

read_json_body / validate_payload had no dedicated tests at all -- both are now covered:
an invalid-UTF-8 body must produce a clean 400 (not an unhandled 500), and a pydantic
validation error must never reflect the submitted values back to the client.
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402
from bughunter import ledger as bounty_ledger  # noqa: E402
from bughunter import learning as bounty_learning  # noqa: E402


def _receive_once(body: bytes):
    sent = {"v": False}

    async def receive():
        if sent["v"]:
            return {"type": "http.disconnect"}
        sent["v"] = True
        return {"type": "http.request", "body": body, "more_body": False}
    return receive


class _Capture:
    """Minimal in-process ASGI response sink (mirrors test_api_auth_cors.py's harness)."""

    def __init__(self) -> None:
        self.status: int | None = None
        self.body = b""

    async def send(self, message: dict) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
        elif message["type"] == "http.response.body":
            self.body += message.get("body", b"")


def _run_post_route(path: str, payload: dict) -> _Capture:
    """POST `payload` as a JSON body through the real ASGI entry point (g.route_http) --
    unlike test_api_auth_cors.py's GET-only `_run_route`, this actually carries a body."""
    cap = _Capture()
    body = json.dumps(payload).encode("utf-8")
    headers = [
        (b"host", b"127.0.0.1:8791"),
        (b"x-greyiq-token", g.SESSION_TOKEN.encode("ascii")),
        (b"content-type", b"application/json"),
    ]
    scope = {"method": "POST", "path": path, "headers": headers, "scheme": "http", "query_string": b""}
    asyncio.run(g.route_http(scope, _receive_once(body), cap.send))
    return cap


class OperatorStartGateTests(unittest.TestCase):
    def test_legacy_allow_submit_payload_is_rejected_without_starting(self) -> None:
        with patch.object(g.runtime, "_get_operator") as get_operator:
            response = _run_post_route("/api/operator/start", {"authorized": True, "allow_submit": True})
        self.assertEqual(response.status, 200)
        body = json.loads(response.body)
        self.assertFalse(body["ok"])
        self.assertFalse(body["started"])
        self.assertFalse(body["allow_submit"])
        self.assertIn("disabled", body["error"].lower())
        get_operator.assert_not_called()

    def test_authorized_flag_without_program_grants_is_rejected(self) -> None:
        response = _run_post_route("/api/operator/start", {"authorized": True})
        self.assertEqual(response.status, 200)
        body = json.loads(response.body)
        self.assertFalse(body["ok"])
        self.assertFalse(body["started"])

    def test_start_passes_program_grants_to_operator(self) -> None:
        grant = {"program_id": "program-1", "authorization_ref": "engagement-1",
                 "policy_source": "policy-1", "policy_checked_at": "2026-10-06T12:00:00Z",
                 "expires_at": "2026-10-07T12:00:00Z"}
        with patch.object(g.runtime, "_get_operator") as get_operator:
            get_operator.return_value.start.return_value = True
            response = _run_post_route("/api/operator/start", {"authorized": True, "grants": [grant]})
        self.assertEqual(response.status, 200)
        self.assertTrue(json.loads(response.body)["started"])
        get_operator.return_value.start.assert_called_once_with(grants=[grant])


class ReadJsonBodyTests(unittest.TestCase):
    def test_valid_json_parses(self) -> None:
        result = asyncio.run(g.read_json_body(_receive_once(b'{"a": 1}')))
        self.assertEqual(result, {"a": 1})

    def test_empty_body_returns_empty_dict(self) -> None:
        result = asyncio.run(g.read_json_body(_receive_once(b"")))
        self.assertEqual(result, {})

    def test_malformed_json_raises_400(self) -> None:
        with self.assertRaises(g.HTTPError) as ctx:
            asyncio.run(g.read_json_body(_receive_once(b"{not json")))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_invalid_utf8_body_raises_400_not_500(self) -> None:
        # Before the fix, UnicodeDecodeError (a ValueError, but NOT a json.JSONDecodeError)
        # escaped read_json_body entirely and surfaced as a generic 500 to the client.
        with self.assertRaises(g.HTTPError) as ctx:
            asyncio.run(g.read_json_body(_receive_once(b"\xff\xfe{")))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_non_object_json_raises_422(self) -> None:
        with self.assertRaises(g.HTTPError) as ctx:
            asyncio.run(g.read_json_body(_receive_once(b"[1, 2, 3]")))
        self.assertEqual(ctx.exception.status_code, 422)

    def test_oversized_body_raises_413(self) -> None:
        orig = g.MAX_REQUEST_BYTES
        g.MAX_REQUEST_BYTES = 10
        try:
            with self.assertRaises(g.HTTPError) as ctx:
                asyncio.run(g.read_json_body(_receive_once(b'{"a": "way too long for the cap"}')))
            self.assertEqual(ctx.exception.status_code, 413)
        finally:
            g.MAX_REQUEST_BYTES = orig


class ValidatePayloadTests(unittest.TestCase):
    def test_valid_payload_passes(self) -> None:
        req = g.validate_payload(g.ScreenshotRequest, {"run_id": "r1", "ref": "F1"})
        self.assertEqual(req.run_id, "r1")

    def test_invalid_payload_raises_422_with_field_name_not_value(self) -> None:
        # run_id has max_length=64 -- an over-long value fails validation. The 422 detail
        # must name the field but NEVER echo the submitted value back to the client.
        secret_value = "TOP-SECRET-MARKER-XYZ"
        with self.assertRaises(g.HTTPError) as ctx:
            g.validate_payload(g.ScreenshotRequest, {"run_id": secret_value * 4})  # 84 > 64
        self.assertEqual(ctx.exception.status_code, 422)
        detail = str(ctx.exception.detail)
        self.assertIn("run_id", detail)            # names the failing field
        self.assertNotIn(secret_value, detail)      # never echoes a submitted value
        self.assertNotIn("pydantic.dev", detail)     # never leaks pydantic's internal error-doc URL

    def test_multiple_invalid_fields_named_in_safe_message(self) -> None:
        # Two fields exceed their max_length; the safe 422 detail names each failing field.
        with self.assertRaises(g.HTTPError) as ctx:
            g.validate_payload(g.ScreenshotRequest, {"run_id": "a" * 100, "ref": "b" * 100})
        detail = str(ctx.exception.detail)
        self.assertIn("run_id", detail)
        self.assertIn("ref", detail)

    def test_ingest_targets_kind_accepts_hackerone_scope(self) -> None:
        # Regression: kind's max_length must fit "hackerone_scope" (15 chars) — a live
        # browser check caught this rejecting with a 422 before the field was widened.
        req = g.validate_payload(g.IngestTargetsRequest, {"content": "x", "kind": "hackerone_scope"})
        self.assertEqual(req.kind, "hackerone_scope")


class ProgramUpsertExcludeUnsetTests(unittest.TestCase):
    """The Operator tab's compact edit form doesn't know about structured_scope/oob_allowed/
    notes -- it simply never puts those keys in the request body. Regression: RuntimeApi.
    upsert_program used to model_dump every ProgramUpsertRequest field (Pydantic fills
    omitted fields with their bare default), so an edit via that form silently wiped a
    program's structured scope table back to empty. Verified end-to-end through the real
    HTTP-layer path (Pydantic validation -> RuntimeApi.upsert_program -> portfolio merge),
    not just portfolio.py's already-correct dict-merge in isolation."""

    def setUp(self) -> None:
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = g.RUNTIME_DIR
        g.RUNTIME_DIR = Path(self._tmp.name)

    def tearDown(self) -> None:
        g.RUNTIME_DIR = self._orig_runtime_dir
        self._tmp.cleanup()

    def test_edit_omitting_new_fields_preserves_them(self) -> None:
        created = g.validate_payload(g.ProgramUpsertRequest, {
            "name": "Acme", "oob_allowed": True, "notes": "policy allows OOB",
            "structured_scope": [{"identifier": "a.acme.com"}],
        })
        first = self.rt.upsert_program(created)["program"]

        # Simulate the Operator tab's compact form: a real request body that never
        # mentions structured_scope/oob_allowed/notes at all (not even as null/false).
        edit = g.validate_payload(g.ProgramUpsertRequest, {"id": first["id"], "name": "Acme", "interval_minutes": 60})
        second = self.rt.upsert_program(edit)["program"]

        self.assertTrue(second["oob_allowed"])
        self.assertEqual(second["notes"], "policy allows OOB")
        self.assertEqual(len(second["structured_scope"]), 1)
        self.assertEqual(second["interval_minutes"], 60)

    def test_explicit_false_still_applies(self) -> None:
        # exclude_unset must only skip OMITTED fields -- a field explicitly sent as false
        # (present in the JSON body) still has to take effect.
        created = g.validate_payload(g.ProgramUpsertRequest, {"name": "Acme", "oob_allowed": True})
        first = self.rt.upsert_program(created)["program"]
        edit = g.validate_payload(g.ProgramUpsertRequest, {"id": first["id"], "name": "Acme", "oob_allowed": False})
        second = self.rt.upsert_program(edit)["program"]
        self.assertFalse(second["oob_allowed"])


class ImportScopeRouteTests(unittest.TestCase):
    """POST /api/hackerone/import-scope had zero coverage through the real ASGI dispatch
    (route match, session-token gate, JSON parsing, credential lookup) -- only the
    underlying hackerone_import.fetch_structured_scope function was tested directly.
    Drives the real g.route_http entry point, same as test_api_auth_cors.py's harness,
    but with an actual JSON body (that harness is GET-only)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_secrets = g.SECRETS_PATH
        g.SECRETS_PATH = Path(self._tmp.name) / "secrets.json"
        self._orig_fetch = g.bounty_h1_import.fetch_structured_scope

    def tearDown(self) -> None:
        g.SECRETS_PATH = self._orig_secrets
        g.bounty_h1_import.fetch_structured_scope = self._orig_fetch
        self._tmp.cleanup()

    def test_no_creds_saved_degrades_gracefully_not_500(self) -> None:
        cap = _run_post_route("/api/hackerone/import-scope", {"handle": "acme"})
        self.assertEqual(cap.status, 200)   # the handler itself never raises -- {"ok": false, "error": ...}
        data = json.loads(cap.body)
        self.assertFalse(data["ok"])
        self.assertIn("api username", data["error"].lower())

    def test_missing_handle_is_a_clean_422_not_500(self) -> None:
        cap = _run_post_route("/api/hackerone/import-scope", {})
        self.assertEqual(cap.status, 422)

    def test_success_path_reaches_the_real_fetch_function_and_returns_its_result(self) -> None:
        g._store_secret("hackerone.api_username", "me")
        g._store_secret("hackerone.api_token", "tok")
        calls = []

        def fake_fetch(handle, api_username, api_token, **kw):
            calls.append((handle, api_username, api_token))
            return {"ok": True, "handle": handle, "program_name": "Acme Corp", "policy_excerpt": "",
                    "offers_bounty": True, "structured_scope": [{"identifier": "a.acme.com"}], "warnings": []}

        g.bounty_h1_import.fetch_structured_scope = fake_fetch
        cap = _run_post_route("/api/hackerone/import-scope", {"handle": "acme"})
        self.assertEqual(cap.status, 200)
        data = json.loads(cap.body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["program_name"], "Acme Corp")
        self.assertEqual(calls, [("acme", "me", "tok")])   # the saved creds actually reached the fetch call

    def test_token_is_never_echoed_in_the_response(self) -> None:
        g._store_secret("hackerone.api_username", "me")
        g._store_secret("hackerone.api_token", "TOP-SECRET-TOKEN-XYZ")
        g.bounty_h1_import.fetch_structured_scope = lambda *a, **k: {"ok": True, "handle": "acme", "program_name": "Acme",
                                                                        "policy_excerpt": "", "offers_bounty": False,
                                                                        "structured_scope": [], "warnings": []}
        cap = _run_post_route("/api/hackerone/import-scope", {"handle": "acme"})
        self.assertNotIn(b"TOP-SECRET-TOKEN-XYZ", cap.body)

    def test_wrong_method_falls_through_to_404_not_matched(self) -> None:
        cap = _Capture()
        headers = [(b"host", b"127.0.0.1:8791"), (b"x-greyiq-token", g.SESSION_TOKEN.encode("ascii"))]
        scope = {"method": "GET", "path": "/api/hackerone/import-scope", "headers": headers, "scheme": "http", "query_string": b""}
        asyncio.run(g.route_http(scope, _receive_once(b""), cap.send))
        self.assertEqual(cap.status, 404)


class YesWeHackRouteTests(unittest.TestCase):
    """The YesWeHack routes through the real ASGI dispatch. Mirrors ImportScopeRouteTests,
    with the differences that matter for this platform: a credential is OPTIONAL (public
    programs import anonymously), and the creds save is partial-field."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_secrets = g.SECRETS_PATH
        g.SECRETS_PATH = Path(self._tmp.name) / "secrets.json"
        self._orig_fetch = g.bounty_ywh_import.fetch_program_scope
        self._orig_login = g.bounty_ywh_import.login

    def tearDown(self) -> None:
        g.SECRETS_PATH = self._orig_secrets
        g.bounty_ywh_import.fetch_program_scope = self._orig_fetch
        g.bounty_ywh_import.login = self._orig_login
        self._tmp.cleanup()

    def test_import_scope_works_with_no_credential_saved(self) -> None:
        # The whole point of the anonymous path: no secret, still a real import.
        seen = {}

        def fake(slug, **kw):
            seen["slug"] = slug
            seen["token"] = kw.get("token")
            return {"ok": True, "slug": slug, "program_name": "Acme", "structured_scope": [], "warnings": []}

        g.bounty_ywh_import.fetch_program_scope = fake
        cap = _run_post_route("/api/yeswehack/import-scope", {"slug": "acme"})
        self.assertEqual(cap.status, 200)
        self.assertTrue(json.loads(cap.body)["ok"])
        self.assertEqual(seen["slug"], "acme")
        self.assertEqual(seen["token"], "")

    def test_missing_slug_is_a_clean_422_not_500(self) -> None:
        self.assertEqual(_run_post_route("/api/yeswehack/import-scope", {}).status, 422)

    def test_saved_token_reaches_the_fetch_with_its_kind(self) -> None:
        g._store_secret("yeswehack.api_token", "pat-123")
        g._store_secret("yeswehack.token_kind", "pat")
        seen = {}

        def fake(slug, **kw):
            seen.update(kw)
            return {"ok": True, "slug": slug, "program_name": "Acme", "structured_scope": [], "warnings": []}

        g.bounty_ywh_import.fetch_program_scope = fake
        _run_post_route("/api/yeswehack/import-scope", {"slug": "acme"})
        self.assertEqual(seen["token"], "pat-123")
        self.assertEqual(seen["token_kind"], "pat")

    def test_token_is_never_echoed_in_the_response(self) -> None:
        g._store_secret("yeswehack.api_token", "TOP-SECRET-YWH-XYZ")
        g.bounty_ywh_import.fetch_program_scope = lambda *a, **k: {
            "ok": True, "slug": "acme", "program_name": "Acme", "structured_scope": [], "warnings": []}
        cap = _run_post_route("/api/yeswehack/import-scope", {"slug": "acme"})
        self.assertNotIn(b"TOP-SECRET-YWH-XYZ", cap.body)

    def test_creds_status_never_returns_the_token(self) -> None:
        g._store_secret("yeswehack.api_token", "TOP-SECRET-YWH-XYZ")
        cap = _Capture()
        headers = [(b"host", b"127.0.0.1:8791"), (b"x-greyiq-token", g.SESSION_TOKEN.encode("ascii"))]
        scope = {"method": "GET", "path": "/api/bounty/yeswehack/creds", "headers": headers,
                 "scheme": "http", "query_string": b""}
        asyncio.run(g.route_http(scope, _receive_once(b""), cap.send))
        self.assertEqual(cap.status, 200)
        self.assertNotIn(b"TOP-SECRET-YWH-XYZ", cap.body)
        self.assertTrue(json.loads(cap.body)["has_token"])

    def test_a_partial_save_does_not_wipe_the_other_stored_fields(self) -> None:
        # The PAT box posts no email, and sign-out posts only clear_token -- neither may
        # clear the saved email, since _store_secret("") is a delete.
        _run_post_route("/api/bounty/yeswehack/creds",
                        {"email": "me@example.test", "api_token": "jwt-1", "token_kind": "jwt"})
        _run_post_route("/api/bounty/yeswehack/creds", {"api_token": "pat-2", "token_kind": "pat"})
        stored = g._load_secrets()
        self.assertEqual(stored.get("yeswehack.email"), "me@example.test")
        self.assertEqual(stored.get("yeswehack.api_token"), "pat-2")
        self.assertEqual(stored.get("yeswehack.token_kind"), "pat")

    def test_sign_out_clears_the_token_but_keeps_the_email(self) -> None:
        _run_post_route("/api/bounty/yeswehack/creds", {"email": "me@example.test", "api_token": "jwt-1"})
        cap = _run_post_route("/api/bounty/yeswehack/creds", {"clear_token": True})
        data = json.loads(cap.body)
        self.assertFalse(data["has_token"])
        self.assertEqual(data["email"], "me@example.test")
        self.assertNotIn("yeswehack.api_token", g._load_secrets())

    def test_an_empty_token_field_never_clears_a_saved_one(self) -> None:
        _run_post_route("/api/bounty/yeswehack/creds", {"api_token": "jwt-1"})
        _run_post_route("/api/bounty/yeswehack/creds", {"email": "me@example.test", "api_token": ""})
        self.assertEqual(g._load_secrets().get("yeswehack.api_token"), "jwt-1")

    def test_login_stores_only_the_returned_token_never_the_password(self) -> None:
        g.bounty_ywh_import.login = lambda email, password, **kw: {
            "ok": True, "token": "jwt-from-ywh", "token_kind": "jwt", "message": "Signed in."}
        cap = _run_post_route("/api/bounty/yeswehack/login",
                              {"email": "me@example.test", "password": "hunter2-SECRET"})
        self.assertEqual(cap.status, 200)
        self.assertNotIn(b"hunter2-SECRET", cap.body)
        self.assertNotIn(b"jwt-from-ywh", cap.body)      # the token isn't echoed either
        stored = g._load_secrets()
        self.assertEqual(stored.get("yeswehack.api_token"), "jwt-from-ywh")
        self.assertNotIn("hunter2-SECRET", json.dumps(stored))

    def test_login_totp_required_is_carried_through_without_storing_anything(self) -> None:
        g.bounty_ywh_import.login = lambda email, password, **kw: {
            "ok": False, "totp_required": True, "error": "2FA needed"}
        cap = _run_post_route("/api/bounty/yeswehack/login",
                              {"email": "me@example.test", "password": "pw"})
        data = json.loads(cap.body)
        self.assertFalse(data["ok"])
        self.assertTrue(data["totp_required"])
        self.assertNotIn("yeswehack.api_token", g._load_secrets())


class HackerOneActivityRouteTests(unittest.TestCase):
    """The new hacktivity/my-reports/report-status/earnings/sync-submitted routes each
    reach the real g.route_http dispatch (route match, session-token gate, JSON parsing,
    credential lookup) -- mirrors ImportScopeRouteTests' pattern above."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_secrets = g.SECRETS_PATH
        self._orig_runtime_dir = g.RUNTIME_DIR
        g.SECRETS_PATH = Path(self._tmp.name) / "secrets.json"
        g.RUNTIME_DIR = Path(self._tmp.name)
        g._store_secret("hackerone.api_username", "me")
        g._store_secret("hackerone.api_token", "tok")
        self._orig_hacktivity = g.bounty_h1_activity.fetch_hacktivity
        self._orig_my_reports = g.bounty_h1_activity.fetch_my_reports
        self._orig_report_status = g.bounty_h1_activity.fetch_report_status
        self._orig_earnings = g.bounty_h1_activity.fetch_earnings
        self._orig_balance = g.bounty_h1_activity.fetch_balance

    def tearDown(self) -> None:
        g.SECRETS_PATH = self._orig_secrets
        g.RUNTIME_DIR = self._orig_runtime_dir
        g.bounty_h1_activity.fetch_hacktivity = self._orig_hacktivity
        g.bounty_h1_activity.fetch_my_reports = self._orig_my_reports
        g.bounty_h1_activity.fetch_report_status = self._orig_report_status
        g.bounty_h1_activity.fetch_earnings = self._orig_earnings
        g.bounty_h1_activity.fetch_balance = self._orig_balance
        self._tmp.cleanup()

    def test_hacktivity_route_reaches_the_real_function(self) -> None:
        calls = []
        g.bounty_h1_activity.fetch_hacktivity = lambda handle, u, t, **kw: calls.append(handle) or {"ok": True, "handle": handle, "items": []}
        cap = _run_post_route("/api/hackerone/hacktivity", {"team_handle": "acme"})
        self.assertEqual(cap.status, 200)
        self.assertEqual(calls, ["acme"])

    def test_hacktivity_missing_handle_is_422(self) -> None:
        cap = _run_post_route("/api/hackerone/hacktivity", {})
        self.assertEqual(cap.status, 422)

    def test_my_reports_route_defaults_page_to_one(self) -> None:
        calls = []
        g.bounty_h1_activity.fetch_my_reports = lambda u, t, **kw: calls.append(kw.get("page")) or {"ok": True, "page": 1, "items": []}
        cap = _run_post_route("/api/hackerone/my-reports", {})
        self.assertEqual(cap.status, 200)
        self.assertEqual(calls, [1])

    def test_report_status_route_reaches_the_real_function(self) -> None:
        calls = []
        g.bounty_h1_activity.fetch_report_status = lambda rid, u, t, **kw: calls.append(rid) or {"ok": True, "id": rid, "state": "triaged"}
        cap = _run_post_route("/api/hackerone/report-status", {"report_id": "42"})
        self.assertEqual(cap.status, 200)
        data = json.loads(cap.body)
        self.assertEqual(data["state"], "triaged")
        self.assertEqual(calls, ["42"])

    def test_earnings_route_bundles_balance_in_one_response(self) -> None:
        g.bounty_h1_activity.fetch_earnings = lambda u, t, **kw: {"ok": True, "page": 1, "items": [{"amount": 500}]}
        g.bounty_h1_activity.fetch_balance = lambda u, t, **kw: {"ok": True, "balance": {"amount": 100}}
        cap = _run_post_route("/api/hackerone/earnings", {})
        data = json.loads(cap.body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["items"], [{"amount": 500}])
        self.assertEqual(data["balance"], {"amount": 100})

    def test_earnings_route_skips_balance_call_on_earnings_failure(self) -> None:
        calls = []
        g.bounty_h1_activity.fetch_earnings = lambda u, t, **kw: {"ok": False, "error": "401"}
        g.bounty_h1_activity.fetch_balance = lambda u, t, **kw: calls.append(1) or {"ok": True, "balance": {}}
        cap = _run_post_route("/api/hackerone/earnings", {})
        data = json.loads(cap.body)
        self.assertFalse(data["ok"])
        self.assertEqual(calls, [])

    def test_sync_submitted_route_reaches_the_real_orchestration(self) -> None:
        g.bounty_h1_activity.fetch_report_status = lambda rid, u, t, **kw: {"ok": True, "state": "resolved", "bounty_awarded_at": "2026-01-01"}
        cap = _run_post_route("/api/hackerone/sync-submitted", {})
        self.assertEqual(cap.status, 200)
        data = json.loads(cap.body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["checked"], 0)  # no submitted findings in this empty ledger -- still a clean 200

    def test_sync_advances_to_paid_on_a_reward_even_when_state_is_unchanged(self) -> None:
        # Regression: a report can pick up bounty_awarded_at/swag_awarded_at before (or
        # without) its state changing -- e.g. still 'triaged'. The sync must not skip a
        # record just because state matches the last-seen h1_state; the reward signal
        # alone is new information and must still advance the ledger to 'paid'.
        finding = {"ref": "F1", "class_id": "xss", "rule_id": "active.reflected-xss", "location": "https://x/a"}
        bounty_ledger.upsert_findings(g.RUNTIME_DIR, "acme", "https://x", [{"finding": finding, "proof_status": "confirmed"}])
        key = bounty_ledger.dedup_key(finding)
        pid = bounty_ledger.program_key("acme", "https://x")
        bounty_ledger.record_submission(g.RUNTIME_DIR, "acme", "https://x", key, "555", "u")
        bounty_ledger.record_h1_sync(g.RUNTIME_DIR, pid, key, state="triaged", resolved_with_reward=False)
        bounty_learning.record_outcome(g.RUNTIME_DIR, program="acme", class_id="xss",
                                       status="submitted", finding_id=f"ledger:{key}")

        g.bounty_h1_activity.fetch_report_status = lambda rid, u, t, **kw: {
            "ok": True, "state": "triaged", "bounty_awarded_at": "2026-02-01T00:00:00Z",
            "total_awarded_amount": 300,
        }
        cap = _run_post_route("/api/hackerone/sync-submitted", {})
        self.assertEqual(cap.status, 200)
        data = json.loads(cap.body)
        self.assertEqual(data["updated"], 1)
        stored = bounty_ledger._load(g.RUNTIME_DIR)["programs"][pid]["findings"][key]
        self.assertEqual(stored["stage"], "paid")
        self.assertEqual(stored["h1_state"], "triaged")
        learned = bounty_learning.program_summary(g.RUNTIME_DIR, "acme")
        self.assertEqual(learned["findings"], 1)
        self.assertEqual(learned["rewarded"], 1)
        self.assertEqual(learned["bounty_total"], 300)
        self.assertEqual(bounty_learning._load(g.RUNTIME_DIR)["programs"]["acme"]["findings"][0]["status"],
                         "accepted")
        again = _run_post_route("/api/hackerone/sync-submitted", {})
        self.assertEqual(json.loads(again.body)["checked"], 0)
        self.assertEqual(bounty_learning.program_summary(g.RUNTIME_DIR, "acme")["findings"], 1)

    def test_sync_terminal_outcome_updates_existing_learning_report(self) -> None:
        finding = {"ref": "F1", "class_id": "xss", "rule_id": "active.reflected-xss",
                   "location": "https://x/a"}
        bounty_ledger.upsert_findings(g.RUNTIME_DIR, "acme", "https://x",
                                      [{"finding": finding, "proof_status": "confirmed"}])
        key = bounty_ledger.dedup_key(finding)
        bounty_ledger.record_submission(g.RUNTIME_DIR, "acme", "https://x", key, "555", "u")
        bounty_learning.record_outcome(g.RUNTIME_DIR, program="acme", class_id="xss",
                                       status="submitted", finding_id=f"ledger:{key}")
        g.bounty_h1_activity.fetch_report_status = lambda rid, u, t, **kw: {
            "ok": True, "state": "resolved", "bounty_awarded_at": "2026-02-01T00:00:00Z",
            "total_awarded_amount": 500,
        }
        cap = _run_post_route("/api/hackerone/sync-submitted", {})
        self.assertTrue(json.loads(cap.body)["ok"])
        learned = bounty_learning.program_summary(g.RUNTIME_DIR, "acme")
        self.assertEqual(learned["findings"], 1)
        self.assertEqual(learned["rewarded"], 1)
        self.assertEqual(learned["bounty_total"], 500)

    def test_token_never_echoed_by_any_new_route(self) -> None:
        g._store_secret("hackerone.api_token", "TOP-SECRET-TOKEN-XYZ")
        g.bounty_h1_activity.fetch_hacktivity = lambda *a, **k: {"ok": True, "handle": "acme", "items": []}
        cap = _run_post_route("/api/hackerone/hacktivity", {"team_handle": "acme"})
        self.assertNotIn(b"TOP-SECRET-TOKEN-XYZ", cap.body)


class CampaignProgramIdTests(unittest.TestCase):
    """POST /api/bounty/campaign with program_id -- "span this program's whole scope"
    mode. Drives the real route (CampaignRequest validation, program lookup, target
    derivation) with bounty_campaign.run_campaign_over_targets mocked out (its own real
    behavior is covered end-to-end by test_campaign.py)."""

    def setUp(self) -> None:
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = g.RUNTIME_DIR
        g.RUNTIME_DIR = Path(self._tmp.name)
        self._orig_span = g.bounty_campaign.run_campaign_over_targets
        self._orig_single = g.bounty_campaign.run_campaign

    def tearDown(self) -> None:
        g.RUNTIME_DIR = self._orig_runtime_dir
        g.bounty_campaign.run_campaign_over_targets = self._orig_span
        g.bounty_campaign.run_campaign = self._orig_single
        self._tmp.cleanup()

    def _seed_program(self, **kw):
        record = {"name": "Acme", "scope_text": "*.acme.com",
                  "structured_scope": [{"identifier": "a.acme.com", "eligible_for_submission": True},
                                        {"identifier": "b.acme.com", "eligible_for_submission": True}]}
        record.update(kw)
        return g.bounty_portfolio.upsert_program(g.RUNTIME_DIR, record)

    def test_spans_every_derived_target(self) -> None:
        program = self._seed_program()
        calls = []

        def fake_span(targets, *, scope, program, **kw):
            calls.append((tuple(targets), scope, program))
            return {"ok": True, "targets_total": len(targets), "targets_hunted": len(targets),
                    "findings": [], "proof_of_impact": {}, "cvss": {}, "attack_plans": {},
                    "surface": {"urls": [], "sources": {}, "notes": [], "tech": []},
                    "severity_counts": {}, "risk": "clean", "per_target": [], "errors": [],
                    "submission_paths": [], "finding_count": 0, "confirmed_count": 0}
        g.bounty_campaign.run_campaign_over_targets = fake_span

        cap = _run_post_route("/api/bounty/campaign", {"program_id": program["id"], "authorized": True})
        self.assertEqual(cap.status, 200)
        data = json.loads(cap.body)
        self.assertTrue(data["ok"])
        self.assertEqual(len(calls), 1)
        targets, scope, program_label = calls[0]
        self.assertEqual(set(targets), {"https://a.acme.com", "https://b.acme.com"})
        self.assertEqual(scope, "*.acme.com")   # the program's OWN scope_text, not a client-sent one
        self.assertEqual(program_label, "Acme")

    def test_unknown_program_id_is_a_clean_error_not_500(self) -> None:
        cap = _run_post_route("/api/bounty/campaign", {"program_id": "does-not-exist", "authorized": True})
        self.assertEqual(cap.status, 200)
        data = json.loads(cap.body)
        self.assertFalse(data["ok"])
        self.assertIn("not found", data["error"].lower())

    def test_program_with_no_huntable_targets_is_a_clean_error(self) -> None:
        program = self._seed_program(structured_scope=[])
        cap = _run_post_route("/api/bounty/campaign", {"program_id": program["id"], "authorized": True})
        data = json.loads(cap.body)
        self.assertFalse(data["ok"])
        self.assertIn("no huntable targets", data["error"].lower())

    def test_program_id_absent_falls_back_to_single_target_unchanged(self) -> None:
        calls = []
        g.bounty_campaign.run_campaign = lambda target, **kw: (calls.append(target), {"ok": True, "findings": []})[1]
        cap = _run_post_route("/api/bounty/campaign", {"target": "https://solo.example.com", "authorized": True})
        self.assertEqual(cap.status, 200)
        self.assertEqual(calls, ["https://solo.example.com"])

    def test_no_target_and_no_program_id_is_a_clean_error(self) -> None:
        cap = _run_post_route("/api/bounty/campaign", {"authorized": True})
        data = json.loads(cap.body)
        self.assertFalse(data["ok"])
        self.assertIn("no target", data["error"].lower())


class ConcurrentRunMutationTests(unittest.TestCase):
    """Two /api/* calls against the SAME run_id+ref (e.g. screenshot + research) run on
    different asyncio.to_thread worker threads and mutate the same cached finding/run
    dicts -- this must not corrupt the run cache under concurrent access."""

    def setUp(self) -> None:
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = g.RUNTIME_DIR
        g.RUNTIME_DIR = Path(self._tmp.name)

    def tearDown(self) -> None:
        g.RUNTIME_DIR = self._orig_runtime_dir
        self._tmp.cleanup()

    def test_concurrent_screenshot_and_research_do_not_corrupt_run_state(self) -> None:
        result = {
            "ok": True,
            "findings": [{"ref": f"F{i}", "title": f"Finding {i}", "severity": "low",
                          "class_id": "x", "rule_id": "x"} for i in range(20)],
            "attack_plans": {},
        }
        self.rt._cache_bounty_run(result, target="https://app.example.com", scope="app.example.com", program=None)
        run_id = result["run_id"]

        # Monkeypatch the heavy I/O each handler does so this stays a pure concurrency
        # test of the shared-dict mutation, not a real screenshot/brain call.
        orig_capture = g.bounty_screenshot.capture_screenshot
        orig_dossier = g.bounty_research.build_dossier
        g.bounty_screenshot.capture_screenshot = lambda *a, **k: {"ok": True, "path": "/x.png", "url": "x", "warning": ""}
        g.bounty_research.build_dossier = lambda finding, ctx, cfg: {"markdown": "# x", "used_brain": False, "model": ""}
        try:
            errors: list[Exception] = []

            def worker(ref: str) -> None:
                try:
                    self.rt.capture_screenshot(g.ScreenshotRequest(run_id=run_id, ref=ref))
                    self.rt.research_finding(g.ResearchRequest(run_id=run_id, ref=ref))
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(f"F{i}",)) for i in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
            self.assertEqual(errors, [])
            run = self.rt.bounty_runs[run_id]
            self.assertEqual(len(run.get("screenshots", {})), 20)
            self.assertEqual(len(run.get("research_paths", {})), 20)
        finally:
            g.bounty_screenshot.capture_screenshot = orig_capture
            g.bounty_research.build_dossier = orig_dossier


if __name__ == "__main__":
    unittest.main()
