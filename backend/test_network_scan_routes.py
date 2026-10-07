"""Legacy network scan API routes refuse unscoped calls before scanner dispatch."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402


def _post(path: str, payload: dict) -> dict:
    encoded = json.dumps(payload).encode()
    messages: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": encoded, "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    scope = {"method": "POST", "path": path, "headers": [
        (b"host", b"127.0.0.1:8791"),
        (b"x-greyiq-token", api.SESSION_TOKEN.encode("ascii")),
        (b"content-type", b"application/json"),
    ], "scheme": "http", "query_string": b""}
    asyncio.run(api.route_http(scope, receive, send))
    return json.loads(b"".join(message.get("body", b"") for message in messages).decode())


def test_web_route_rejects_unscoped_and_cross_host_before_scanning() -> None:
    with patch.object(api, "run_web_scan") as scanner:
        missing = _post("/api/scan/web", {"url": "https://app.example.test/"})
        cross = _post("/api/scan/web", {
            "url": "https://app.example.test/", "authorized": True, "scope_host": "other.example.test",
        })
    assert not missing["ok"] and "authorization" in missing["error"]
    assert not cross["ok"] and "outside" in cross["error"]
    scanner.assert_not_called()


def test_web_and_live_routes_forward_exact_scope() -> None:
    payload = {"url": "https://app.example.test/", "authorized": True, "scope_host": "app.example.test"}
    with patch.object(api, "run_web_scan", return_value={"ok": True}) as web:
        assert _post("/api/scan/web", payload)["ok"]
    web.assert_called_once_with("https://app.example.test/", scope_host="app.example.test")
    with patch.object(api, "run_live_scan", return_value={"ok": True}) as live:
        assert _post("/api/scan/live", payload)["ok"]
    live.assert_called_once_with("https://app.example.test/", 6.0, scope_host="app.example.test")


def test_remote_code_route_requires_scope_but_local_code_does_not() -> None:
    with patch.object(api, "run_code_scan", return_value={"ok": True}) as scanner:
        remote = _post("/api/scan/code", {
            "target": "https://github.com/acme/widget", "target_type": "GIT_REMOTE",
        })
        assert not remote["ok"]
        wrong = _post("/api/scan/code", {
            "target": "https://github.com/acme/widget", "target_type": "git_remote",
            "authorized": True, "scope_repository": "https://github.com/acme/other",
        })
        assert not wrong["ok"]
        scanner.assert_not_called()
        granted = _post("/api/scan/code", {
            "target": "https://github.com/acme/widget", "target_type": "git_remote",
            "authorized": True, "scope_repository": "https://github.com/acme/widget",
        })
        assert granted["ok"]
        local = _post("/api/scan/code", {"target": "C:/work/src", "target_type": "path"})
        assert local["ok"]
        assert scanner.call_count == 2
