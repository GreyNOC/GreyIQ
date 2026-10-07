"""MCP chat and API routing require deliberate operator actions.

The manager is mocked here: these tests must never launch a server or contact a
network endpoint. Transport and persistence behavior belongs to the manager's
own tests.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402


def _runtime() -> tuple[api.GreyIQRuntime, Mock]:
    runtime = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
    runtime.store = Mock(load=lambda: {})
    manager = Mock()
    runtime.mcp_servers = manager
    return runtime, manager


def _request(method: str, path: str, payload: dict | None = None, *,
             token: bool = True, origin: str = "") -> tuple[int, dict]:
    encoded = json.dumps(payload or {}).encode("utf-8")
    messages: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": encoded, "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    headers = [(b"host", b"127.0.0.1:8791"), (b"content-type", b"application/json")]
    if token:
        headers.append((b"x-greyiq-token", api.SESSION_TOKEN.encode("ascii")))
    if origin:
        headers.append((b"origin", origin.encode("ascii")))
    scope = {"method": method, "path": path, "headers": headers,
             "scheme": "http", "query_string": b""}
    asyncio.run(api.route_http(scope, receive, send))
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in messages).decode("utf-8")
    return status, json.loads(body)


def test_incidental_mcp_mention_stays_ordinary_chat() -> None:
    runtime, manager = _runtime()
    ordinary = {"message": "MCP is a protocol."}
    with patch.object(runtime, "_coder_reply", return_value=ordinary) as brain:
        reply = runtime.chat(api.ChatRequest(message="How do MCP servers work?"))
    assert reply is ordinary
    brain.assert_called_once()
    manager.list_servers.assert_not_called()
    manager.list_tools.assert_not_called()
    manager.call_tool.assert_not_called()


def test_mcp_listing_is_inert_and_explicit_tools_need_authorization() -> None:
    runtime, manager = _runtime()
    manager.list_servers.return_value = {"ok": True, "servers": [{
        "name": "local", "transport": "stdio", "enabled": False, "status": "untested",
    }]}
    listed = runtime.chat(api.ChatRequest(message="mcp list"))
    assert "local" in listed["message"]
    manager.list_servers.assert_called_once_with()
    manager.list_tools.assert_not_called()
    manager.call_tool.assert_not_called()

    for command in ("mcp tools local", "mcp call local read {}", "mcp tools -y", "mcp call -y local"):
        refused = runtime.chat(api.ChatRequest(message=command))
        assert refused["mcp_result"]["ok"] is False
        assert "-y" in refused["message"]
    manager.list_tools.assert_not_called()
    manager.call_tool.assert_not_called()


def test_explicit_tools_and_call_dispatch_only_named_server_and_arguments() -> None:
    runtime, manager = _runtime()
    manager.list_tools.return_value = {"ok": True, "tools": [
        {"name": "read_summary", "description": "Read an existing summary"},
    ]}
    manager.call_tool.return_value = {"ok": True, "content": [
        {"type": "text", "text": "Observed: one record; control: none."},
    ], "is_error": False}

    tools = runtime.chat(api.ChatRequest(message="mcp tools -y local"))
    assert "read_summary" in tools["message"]
    manager.list_tools.assert_called_once_with("local")

    result = runtime.chat(api.ChatRequest(
        message='mcp call -y local read_summary {"record":"case-1","limit":2}'
    ))
    assert result["mcp_result"]["ok"] is True
    assert "untrusted server data" in result["message"]
    assert "Observed: one record" in result["message"]
    manager.call_tool.assert_called_once_with("local", "read_summary", {"record": "case-1", "limit": 2})


def test_malformed_call_json_fails_before_manager_dispatch() -> None:
    runtime, manager = _runtime()
    for arguments in ('{"record":}', '[]', '{"record": 1} trailing'):
        reply = runtime.chat(api.ChatRequest(message=f"mcp call -y local read_summary {arguments}"))
        assert reply["mcp_result"]["ok"] is False
    manager.call_tool.assert_not_called()


def test_tool_output_is_redacted_bounded_and_server_error_is_displayed() -> None:
    runtime, manager = _runtime()
    secret = "ghp_" + "A" * 36
    manager.call_tool.return_value = {"ok": True, "content": [
        {"type": "text", "text": f"token={secret}\n" + "x" * 30_000},
    ], "is_error": True}
    reply = runtime.chat(api.ChatRequest(message="mcp call -y local read_summary {}"))
    assert secret not in reply["message"]
    assert "REDACTED_SECRET" in reply["message"]
    assert "server marked this tool result as an error" in reply["message"]
    assert len(reply["message"]) <= 12_000

    manager.call_tool.return_value = {"ok": False, "error": "Enable this MCP server before using its tools."}
    disabled = runtime.chat(api.ChatRequest(message="mcp call -y local read_summary {}"))
    assert disabled["mcp_result"]["ok"] is False
    assert "Enable this MCP server" in disabled["message"]


def test_mcp_routes_reject_missing_token_and_foreign_origin_before_manager() -> None:
    manager = Mock()
    with patch.object(api.runtime, "mcp_servers", manager), patch.object(api, "GREYIQ_ACCESS_KEY", ""):
        no_token = _request("POST", "/api/mcp/servers", {"name": "local"}, token=False)
        foreign_origin = _request("POST", "/api/mcp/servers", {"name": "local"},
                                  origin="https://foreign.example.test")
    assert no_token[0] == 403
    assert foreign_origin[0] == 403
    manager.add_server.assert_not_called()


def test_mcp_routes_dispatch_explicit_crud_and_test_operations() -> None:
    manager = Mock()
    manager.list_servers.return_value = {"ok": True, "servers": []}
    manager.add_server.return_value = {"ok": True, "server": {"name": "local"}}
    manager.update_server.return_value = {"ok": True, "server": {"name": "local", "enabled": True}}
    manager.test_server.return_value = {"ok": True, "server": "local", "status": "available"}
    manager.delete_server.return_value = {"ok": True, "deleted": "local"}
    with patch.object(api.runtime, "mcp_servers", manager), patch.object(api, "GREYIQ_ACCESS_KEY", ""):
        assert _request("GET", "/api/mcp/servers")[1]["ok"]
        assert _request("POST", "/api/mcp/servers", {"name": "local"})[1]["ok"]
        assert _request("PUT", "/api/mcp/servers/local", {"enabled": True})[1]["ok"]
        assert _request("POST", "/api/mcp/servers/local/test")[1]["ok"]
        assert _request("DELETE", "/api/mcp/servers/local")[1]["ok"]
    manager.list_servers.assert_called_once_with()
    manager.add_server.assert_called_once_with({"name": "local"})
    manager.update_server.assert_called_once_with("local", {"enabled": True})
    manager.test_server.assert_called_once_with("local")
    manager.delete_server.assert_called_once_with("local")


def test_hunt_approval_routes_require_exact_operator_action() -> None:
    manager = Mock()
    manager.list_hunt_approvals.return_value = {"ok": True, "approvals": []}
    manager.approve_hunt_tool.return_value = {"ok": True, "approval": {
        "server": "local", "tool": "review_evidence", "valid": True,
    }}
    manager.revoke_hunt_tool.return_value = {"ok": True, "revoked": True}
    with patch.object(api.runtime, "mcp_servers", manager), patch.object(api, "GREYIQ_ACCESS_KEY", ""):
        assert _request("GET", "/api/mcp/hunt-approvals")[1]["approvals"] == []
        rejected = _request("POST", "/api/mcp/hunt-approvals", {
            "server": "local", "tool": "review_evidence",
        })
        assert rejected[0] == 400
        assert _request("POST", "/api/mcp/hunt-approvals", {
            "server": "local", "tool": "review_evidence", "evidence_only": True,
        })[1]["ok"]
        assert _request("DELETE", "/api/mcp/hunt-approvals/local/review_evidence")[1]["revoked"]
    manager.approve_hunt_tool.assert_called_once_with(
        "local", "review_evidence", evidence_only=True)
    manager.revoke_hunt_tool.assert_called_once_with("local", "review_evidence")
