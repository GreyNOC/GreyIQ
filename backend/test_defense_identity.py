"""The pre-auth CLI identity proof must be local and bound to the server socket."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from unittest.mock import patch

from backend import greyiq_api as api


def _route(*, port: int = 8766, host_port: int | None = None,
           client: str = "127.0.0.1",
           query: bytes | None = None, path: str = "/api/internal/defense-identity",
           method: str = "GET") -> tuple[int, dict]:
    nonce = "a" * 64
    scope = {
        "type": "http", "method": method, "path": path,
        "client": (client, 50000), "server": ("127.0.0.1", port),
        "headers": [(b"host", f"127.0.0.1:{host_port or port}".encode("ascii"))],
        "scheme": "http", "query_string": query if query is not None else f"nonce={nonce}".encode("ascii"),
    }
    result: dict = {"status": 0, "body": b""}

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            result["status"] = message["status"]
        elif message["type"] == "http.response.body":
            result["body"] += message.get("body", b"")

    asyncio.run(api.route_http(scope, receive, send))
    return result["status"], json.loads(result["body"])


def test_identity_proof_precedes_access_key_and_binds_actual_port() -> None:
    nonce = "a" * 64
    with patch.object(api, "GREYIQ_ACCESS_KEY", "private-access-key"):
        status, payload = _route(port=8766)
        assert status == 200
        message = f"GreyIQ defense identity v1\n127.0.0.1:8766\n{nonce}".encode("ascii")
        expected = hmac.new(api.DEFENSE_IDENTITY_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()
        assert payload == {"version": 1, "proof": expected}
        other_port_proof = _route(port=8767, host_port=8766)[1]["proof"]
        assert other_port_proof != expected
        # All ordinary API routes still require the configured access key.
        assert _route(path="/api/defense/status")[0] == 401


def test_identity_proof_refuses_remote_peer_and_invalid_challenge() -> None:
    assert _route(client="192.0.2.1")[0] == 404
    assert _route(query=b"nonce=bad")[0] == 400
    assert _route(method="POST")[0] == 404
