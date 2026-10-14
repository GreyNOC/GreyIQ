"""Exercise the Defense monitor through GreyIQ's authenticated ASGI routes."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import greyiq_api as api  # noqa: E402
from defense_log_monitor import DefenseLogMonitor  # noqa: E402
from defense_monitor_lease import MonitorLease, MonitorLeaseBusy  # noqa: E402


class _Monitor:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def status(self) -> dict:
        self.calls.append(("status",))
        return {"ok": True, "sources": [], "alerts": []}

    def add_source(self, body: dict) -> dict:
        self.calls.append(("add", body))
        return {"ok": True, "source": {"id": "s1", "name": body["name"]}}

    def set_enabled(self, source_id: str, enabled: bool) -> dict:
        self.calls.append(("enabled", source_id, enabled))
        return {"ok": True}

    def remove_source(self, source_id: str) -> dict:
        self.calls.append(("remove", source_id))
        return {"ok": True}


def test_defense_monitor_lease_follows_asgi_lifespan(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    monitor = DefenseLogMonitor(runtime_dir, autostart=False)
    assert not (runtime_dir / "data" / "defense_monitor.lock").exists()
    for _ in range(2):
        messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
        sent: list[str] = []

        async def receive() -> dict:
            return next(messages)

        async def send(message: dict) -> None:
            sent.append(message["type"])
            if message["type"] == "lifespan.startup.complete":
                with pytest.raises(MonitorLeaseBusy):
                    MonitorLease(runtime_dir).acquire()

        with patch.object(api.runtime, "defense_monitor", monitor):
            asyncio.run(api.route_lifespan(receive, send))
        assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
        with MonitorLease(runtime_dir):
            pass


def _route(method: str, path: str, body: dict | None = None, *, authenticated: bool = True) -> tuple[int, dict]:
    payload = json.dumps(body or {}).encode("utf-8")
    headers = [(b"host", b"127.0.0.1:8766")]
    if authenticated:
        headers.append((b"x-greyiq-token", api.SESSION_TOKEN.encode("ascii")))
    scope = {"type": "http", "method": method, "path": path, "headers": headers,
             "scheme": "http", "query_string": b""}
    result = {"status": 0, "body": b""}

    async def receive() -> dict:
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            result["status"] = message["status"]
        elif message["type"] == "http.response.body":
            result["body"] += message.get("body", b"")

    asyncio.run(api.route_http(scope, receive, send))
    return result["status"], json.loads(result["body"])


def test_defense_routes_require_session_token() -> None:
    monitor = _Monitor()
    with patch.object(api.runtime, "defense_monitor", monitor):
        status, body = _route("GET", "/api/defense/status", authenticated=False)
        assert status == 403
        assert "token" in body["error"]
        assert monitor.calls == []


def test_defense_source_lifecycle_routes() -> None:
    monitor = _Monitor()
    with patch.object(api.runtime, "defense_monitor", monitor):
        assert _route("GET", "/api/defense/status") == (200, {"ok": True, "sources": [], "alerts": []})
        status, body = _route("POST", "/api/defense/sources", {"kind": "file", "name": "Test", "path": "/tmp/app.log", "authorized": True})
        assert status == 200 and body["source"]["id"] == "s1"
        assert _route("POST", "/api/defense/sources/s1/stop")[0] == 200
        assert _route("POST", "/api/defense/sources/s1/start")[0] == 200
        assert _route("DELETE", "/api/defense/sources/s1")[0] == 200
    assert monitor.calls == [
        ("status",),
        ("add", {"kind": "file", "name": "Test", "path": "/tmp/app.log", "authorized": True}),
        ("enabled", "s1", False),
        ("enabled", "s1", True),
        ("remove", "s1"),
    ]


def test_defense_route_rejects_non_resource_path() -> None:
    monitor = _Monitor()
    with patch.object(api.runtime, "defense_monitor", monitor):
        assert _route("DELETE", "/api/defense/sources/s1/extra")[0] == 404
        assert _route("POST", "/api/defense/status")[0] == 405
        assert _route("GET", "/api/defense/sources")[0] == 405
    assert monitor.calls == []


def test_defense_mutation_reports_busy_collector() -> None:
    monitor = _Monitor()
    with patch.object(api.runtime, "defense_monitor", monitor), patch.object(
        monitor, "add_source", side_effect=MonitorLeaseBusy("Another defense monitor is using this runtime.")
    ):
        status, body = _route("POST", "/api/defense/sources", {
            "kind": "file", "name": "App", "path": "/tmp/app.log", "authorized": True,
        })
    assert status == 409
    assert "Another defense monitor" in body["detail"]


def test_file_alert_reaches_authenticated_status_api(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    monitor = DefenseLogMonitor(tmp_path / "state", autostart=False)
    try:
        with patch.object(api.runtime, "defense_monitor", monitor):
            rejected, _ = _route("POST", "/api/defense/sources", {
                "kind": "file", "name": "Authentication", "path": str(log),
            })
            assert rejected == 422
            status, body = _route("POST", "/api/defense/sources", {
                "kind": "file", "name": "Authentication", "path": str(log), "authorized": True,
            })
            assert status == 200 and body["ok"]
            with log.open("a", encoding="utf-8") as handle:
                handle.write("authentication failure for test-account\n")
            monitor.poll_once()
            status, body = _route("GET", "/api/defense/status")
            assert status == 200
            assert body["sources"][0]["events_seen"] == 1
            assert body["alerts"][0]["severity"] == "high"
            assert "authentication failure" in body["alerts"][0]["message"]
    finally:
        monitor.close()
