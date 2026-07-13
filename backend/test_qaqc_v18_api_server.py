"""Regression tests for QA/QC v1.8 fixes in greyiq_api.py (group: api-server).

Each test fails before its corresponding fix and passes after. Offline/deterministic:
no network, no real ledger writes (module-level collaborators are monkeypatched).
"""
import asyncio
import sys
import types
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api  # noqa: E402


def _drive_route(scope, body=b""):
    """Run route_http against a minimal ASGI scope, returning the sent messages."""
    sent = []

    async def receive():
        return {"body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(greyiq_api.route_http(scope, receive, send))
    return sent


def _status(sent):
    for message in sent:
        if message.get("type") == "http.response.start":
            return message.get("status")
    return None


# --- read_json_body: deeply-nested JSON -> 400, not RecursionError/500 ---------

def test_read_json_body_deeply_nested_maps_to_400():
    async def receive():
        # 60000 open brackets: json.loads raises RecursionError (NOT a ValueError
        # subclass). Before the fix it escaped read_json_body and surfaced as a 500.
        return {"body": b"[" * 60000, "more_body": False}

    async def run():
        try:
            await greyiq_api.read_json_body(receive)
        except greyiq_api.HTTPError as exc:
            return exc.status_code
        return None

    assert asyncio.run(run()) == 400


# --- static-file fallback: null-byte path -> 404, not 500 ----------------------

def test_null_byte_path_returns_404_not_500():
    greyiq_api.GREYIQ_ACCESS_KEY = ""  # default keyless loopback deployment
    scope = {
        "type": "http", "method": "GET", "path": "/\x00", "scheme": "http",
        "headers": [(b"host", b"127.0.0.1:8766")],
    }
    sent = _drive_route(scope)
    # Before the fix, .resolve() on the null byte raised ValueError outside the guard
    # and the generic handler returned 500. The guard now yields a clean 404.
    assert _status(sent) == 404


# --- Host-header allowlist: DNS rebinding refused ------------------------------

def test_host_header_allowed_matrix():
    greyiq_api.GREYIQ_ACCESS_KEY = ""
    allowed = greyiq_api._host_header_allowed
    assert allowed({"headers": [(b"host", b"127.0.0.1:8766")]}) is True
    assert allowed({"headers": [(b"host", b"localhost")]}) is True
    assert allowed({"headers": [(b"host", b"[::1]:8766")]}) is True
    # The rebinding host is neither loopback nor a configured origin -> refused.
    assert allowed({"headers": [(b"host", b"evil.com:8766")]}) is False
    assert allowed({"headers": [(b"host", b"evil.com")]}) is False


def test_configured_origin_host_allowed(monkeypatch):
    greyiq_api.GREYIQ_ACCESS_KEY = ""
    monkeypatch.setenv("GREYIQ_ALLOWED_ORIGINS", "https://app.example.com:8766")
    assert greyiq_api._host_header_allowed(
        {"headers": [(b"host", b"app.example.com:8766")]}) is True


def test_route_rejects_rebinding_host_403():
    greyiq_api.GREYIQ_ACCESS_KEY = ""
    scope = {
        "type": "http", "method": "GET", "path": "/", "scheme": "http",
        "headers": [(b"host", b"evil.com")],
    }
    sent = _drive_route(scope)
    # Before the fix the rebound Host was trusted verbatim and the index (200, with the
    # SESSION_TOKEN) was served. Now the Host allowlist refuses it before anything is served.
    assert _status(sent) == 403


# --- get_report_ready: no "ready" signal when the durable write fails ----------

def test_get_report_ready_not_persisted_returns_not_ok_and_no_event(monkeypatch):
    events = []
    monkeypatch.setattr(greyiq_api.bounty_progress, "global_log",
                        lambda *a, **k: events.append((a, k)))
    # Both the initial mark and the fallback mark fail to locate the record.
    monkeypatch.setattr(greyiq_api.bounty_ledger, "mark_report_ready",
                        lambda *a, **k: False)
    monkeypatch.setattr(greyiq_api.bounty_ledger, "upsert_findings",
                        lambda *a, **k: None)
    monkeypatch.setattr(greyiq_api, "bounty_build_replay", lambda items: ("", 0))
    monkeypatch.setattr(greyiq_api, "bounty_build_har", lambda items, version=None: (None, 0))

    fake_self = types.SimpleNamespace(
        build_finding_report=lambda request: {
            "ok": True, "package": {"body": "x"},
            "platform": "hackerone", "proof_status": "candidate",
        }
    )
    request = types.SimpleNamespace(
        program="acme", target="https://acme.com/x", platform="hackerone",
        location="https://acme.com/x", proof_evidence=None, screenshot_path="",
        proof=None, title="Outdated component", class_id="cve", rule_id="cve-x",
        severity="medium", poc="", dedup_key="deadbeef",
    )

    result = greyiq_api.GreyIQRuntime.get_report_ready(fake_self, request)
    # Persistence failed -> the response must NOT claim ok/ready and must NOT fire the
    # app-wide report_ready event (which the client badges as "Report ready").
    assert result["persisted"] is False
    assert result["ok"] is False
    assert events == []


def test_get_report_ready_persisted_returns_ok_and_fires_event(monkeypatch):
    events = []
    monkeypatch.setattr(greyiq_api.bounty_progress, "global_log",
                        lambda *a, **k: events.append((a, k)))
    monkeypatch.setattr(greyiq_api.bounty_ledger, "mark_report_ready",
                        lambda *a, **k: True)
    monkeypatch.setattr(greyiq_api, "bounty_build_replay", lambda items: ("", 0))
    monkeypatch.setattr(greyiq_api, "bounty_build_har", lambda items, version=None: (None, 0))

    fake_self = types.SimpleNamespace(
        build_finding_report=lambda request: {
            "ok": True, "package": {"body": "x"},
            "platform": "hackerone", "proof_status": "candidate",
        }
    )
    request = types.SimpleNamespace(
        program="acme", target="https://acme.com/x", platform="hackerone",
        location="https://acme.com/x", proof_evidence=None, screenshot_path="",
        proof=None, title="t", class_id="c", rule_id="r",
        severity="medium", poc="", dedup_key="deadbeef",
    )

    result = greyiq_api.GreyIQRuntime.get_report_ready(fake_self, request)
    assert result["persisted"] is True
    assert result["ok"] is True
    assert len(events) == 1
