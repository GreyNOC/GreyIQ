"""Built-in MCP hunt review stays local, bounded, and advisory."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bughunter import mcp_hunt  # noqa: E402
from bughunter.prover_classes import PROVER_CLASSES  # noqa: E402


def test_real_in_memory_mcp_web_review_never_uses_target_network(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("mcp")  # import before patching Popen (SDK annotates that class)
    def unexpected(*_args, **_kwargs):
        raise AssertionError("Built-in MCP review must not open a socket or child process")

    monkeypatch.setattr(socket, "create_connection", unexpected)
    monkeypatch.setattr(subprocess, "Popen", unexpected)
    result = mcp_hunt.run_builtin_hunt_review(
        "url", "https://app.example.test/?token=target-secret", "app.example.test",
        {"endpoints": [
            "https://app.example.test/api/search?q=query-secret",
            "https://app.example.test/download?file=private-secret",
            "https://elsewhere.test/admin",
        ], "params": ["file", "redirect_url"]},
        [{"rule_id": "xss.reflected", "severity": "high", "snippet": "finding-secret"}],
    )
    assert result["ok"], result
    assert result["source"] == "builtin-mcp"
    assert result["advisory"] is True
    assert result["reviewed"] == {"endpoints": 3, "findings": 1}
    assert result["web_priorities"][0]["endpoint_index"] == 0
    assert "xss" in result["web_priorities"][0]["classes"]
    assert all(set(row["classes"]) <= PROVER_CLASSES for row in result["web_priorities"])
    assert result["finding_priorities"] == [
        {"finding_index": 0, "reason": "scanner lead review priority"},
    ]
    encoded = json.dumps(result)
    for secret in ("target-secret", "query-secret", "private-secret", "finding-secret", "elsewhere.test"):
        assert secret not in encoded
    assert "confirmed" not in encoded.lower()


def test_real_in_memory_mcp_source_review_accepts_local_path_without_scope() -> None:
    result = mcp_hunt.run_builtin_hunt_review(
        "path", r"C:\repo\internal", "", {},
        [{"rule_id": "deps.outdated", "severity": "medium"},
         {"rule_id": "secret.api-key", "severity": "high"},
         {"rule_id": "style.todo", "severity": "info"}],
    )
    assert result["ok"], result
    assert result["web_priorities"] == []
    assert [row["finding_index"] for row in result["finding_priorities"]] == [1, 0, 2]
    assert result["reviewed"] == {"endpoints": 0, "findings": 3}


def test_snapshot_contains_only_categories_and_indexes(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    async def fake_call(snapshot):
        captured.update(snapshot)
        return mcp_hunt._review_snapshot(snapshot)

    monkeypatch.setattr(mcp_hunt, "_call_tool", fake_call)
    result = mcp_hunt.run_builtin_hunt_review(
        "url", "https://target.test/password=target-secret", "target.test",
        {"endpoints": ["https://target.test/api/search?token=query-secret"] * 35,
         "params": ["q", "password=param-secret"]},
        [{"rule_id": "secret.api-key", "severity": "high", "snippet": "snippet-secret"}] * 55,
    )
    assert result["ok"]
    assert result["reviewed"] == {"endpoints": 24, "findings": 40}
    assert set(captured) == {"kind", "endpoints", "global_features", "findings"}
    encoded = json.dumps(captured)
    for secret in ("target-secret", "query-secret", "param-secret", "snippet-secret", "target.test"):
        assert secret not in encoded


@pytest.mark.parametrize("kind,target,scope", [
    ("url", "https://target.test/", ""), ("git", "https://forge.test/org/repo", ""),
    ("unknown", "x", "x"), ("url", "", "target.test"),
])
def test_invalid_target_or_missing_remote_scope_never_calls_mcp(
    monkeypatch: pytest.MonkeyPatch, kind: str, target: str, scope: str,
) -> None:
    async def unexpected(_snapshot):
        raise AssertionError("MCP call must be rejected before dispatch")

    monkeypatch.setattr(mcp_hunt, "_call_tool", unexpected)
    assert mcp_hunt.run_builtin_hunt_review(kind, target, scope, {}, [])["ok"] is False


@pytest.mark.parametrize("bad", [
    {"kind": "url", "web_priorities": [{"endpoint_index": 3, "classes": ["xss"]}]},
    {"kind": "url", "web_priorities": [{"endpoint_index": 0, "classes": ["invented"]}]},
    {"kind": "url", "web_priorities": [{"endpoint_index": True, "classes": ["xss"]}]},
    {"kind": "url", "finding_priorities": [{"finding_index": 9}]},
    {"kind": "url", "web_priorities": "x" * 9000},
    {"kind": "path", "web_priorities": []},
])
def test_mcp_output_cannot_invent_targets_classes_or_oversized_advice(
    monkeypatch: pytest.MonkeyPatch, bad: dict,
) -> None:
    async def fake_call(_snapshot):
        return bad

    monkeypatch.setattr(mcp_hunt, "_call_tool", fake_call)
    result = mcp_hunt.run_builtin_hunt_review(
        "url", "https://target.test/", "target.test",
        {"endpoints": ["https://target.test/search"]}, [{"severity": "low"}],
    )
    assert result["ok"] is False
    assert result["advisory"] is True


def test_mcp_timeout_returns_bounded_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    async def stall(_snapshot):
        await asyncio.sleep(1)
        return {}

    monkeypatch.setattr(mcp_hunt, "_call_tool", stall)
    monkeypatch.setattr(mcp_hunt, "_TIMEOUT_SECONDS", 0.01)
    result = mcp_hunt.run_builtin_hunt_review("path", "C:/repo", "", {}, [])
    assert result["ok"] is False
    assert result["reason"] == "Built-in MCP review is unavailable."
