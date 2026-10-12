"""Chat active verification is authorized, bounded, asynchronous, and evidence-calibrated."""

from __future__ import annotations

import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path
from unittest.mock import Mock, patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402
from bughunter.chat_commands import parse_active_chat_command  # noqa: E402


def _runtime() -> api.GreyIQRuntime:
    runtime = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
    runtime.lock = threading.RLock()
    runtime._active_chat_runs = OrderedDict()
    runtime._active_chat_running_id = ""
    runtime.store = Mock(load=lambda: {})
    runtime.log = Mock()
    return runtime


def _await_result(runtime: api.GreyIQRuntime, run_id: str) -> dict:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        result = runtime.active_chat_status(run_id)
        if result.get("status") != "running":
            return result
        time.sleep(0.01)
    raise AssertionError("active worker did not finish")


def test_active_command_requires_authorization_and_one_exact_matching_host() -> None:
    assert parse_active_chat_command("How does an active scan work?") is None
    for command in (
        "scan active https://app.example.test/",
        "scan active -y https://app.example.test/",
        "scan active -y --scope *.example.test https://app.example.test/",
        "scan active -y --scope example.test https://app.example.test/",
        "scan active -y --scope app.example.test --scope other.example.test https://app.example.test/",
        "scan active -y --scope app.example.test https://app.example.test/ --time-based",
        "scan active -y --scope app.example.test https://user:pass@app.example.test/",
    ):
        result = parse_active_chat_command(command)
        assert result is not None and not result["ok"], command
    assert parse_active_chat_command(
        "scan active -y --scope app.example.test https://app.example.test/search?q=1"
    ) == {"ok": True, "target": "https://app.example.test/search?q=1", "scope_host": "app.example.test"}


def test_active_chat_is_background_single_flight_and_reports_control() -> None:
    runtime = _runtime()
    started = threading.Event()
    release = threading.Event()

    def verify(*args, **kwargs):
        started.set()
        assert release.wait(2)
        return ([{
            "title": "Control-backed observation", "severity": "medium",
            "_active_proof": {"status": "confirmed", "observed_result": "marker reflected",
                              "control_result": "control marker absent", "limitations": "one endpoint"},
        }], {"in_scope": True, "host": "app.example.test", "requests_used": 4, "rate_limited": False})

    command = "scan active -y --scope app.example.test https://app.example.test/"
    with patch.object(api.bounty_active_verify, "verify_active", side_effect=verify) as scanner:
        reply = runtime.chat(api.ChatRequest(message=command))
        run_id = reply["active_scan"]["run_id"]
        assert run_id.startswith("active-")
        assert started.wait(1)
        assert runtime.active_chat_status(run_id)["status"] == "running"
        busy = runtime.chat(api.ChatRequest(message=command))
        assert "already running" in busy["message"]
        release.set()
        finished = _await_result(runtime, run_id)
    assert scanner.call_count == 1
    assert scanner.call_args.kwargs["scope_host"] == "app.example.test"
    assert scanner.call_args.kwargs["requests_budget"] == 16
    assert scanner.call_args.kwargs["time_based"] is False
    assert finished["status"] == "done"
    assert "4/16" in finished["message"]
    assert "Observed: marker reflected" in finished["message"]
    assert "Control: control marker absent" in finished["message"]


def test_unscoped_active_chat_never_calls_verifier() -> None:
    runtime = _runtime()
    with patch.object(api.bounty_active_verify, "verify_active") as scanner:
        reply = runtime.chat(api.ChatRequest(message="scan active https://app.example.test/"))
    assert "requires -y" in reply["message"]
    scanner.assert_not_called()


def test_active_chat_reports_preflight_stop_without_claiming_a_finding() -> None:
    runtime = _runtime()
    with patch.object(api.bounty_active_verify, "verify_active", return_value=([], {
        "in_scope": False, "skipped_reason": "scope refused", "requests_used": 0,
    })):
        reply = runtime.chat(api.ChatRequest(message=(
            "scan active -y --scope app.example.test https://app.example.test/"
        )))
        result = _await_result(runtime, reply["active_scan"]["run_id"])
    assert result["status"] == "error"
    assert "stopped before proof" in result["message"]
    assert "confirmed" not in result["message"]
