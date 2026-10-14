"""Security and durability contracts for operator-configured log sources."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.defense_log_monitor import DefenseLogMonitor, _safe_excerpt


@pytest.mark.parametrize("line,secret", [
    ("Cookie: sessionid=abc123", "abc123"),
    ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ("client_secret=topsecret", "topsecret"),
    ("private_key: BEGINKEY", "BEGINKEY"),
    ("https://user:password@host.test/log", "password"),
    ('{"password": "jsonsecret"}', "jsonsecret"),
])
def test_alert_excerpt_redacts_common_credentials(line: str, secret: str) -> None:
    excerpt = _safe_excerpt(line)
    assert secret not in excerpt
    assert "[REDACTED]" in excerpt


def test_authorization_required_and_credentials_outside_state(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    credentials_path = tmp_path / "local-profile" / "credentials.json"
    monitor = DefenseLogMonitor(runtime, credentials_path=credentials_path, autostart=False)
    source = {
        "kind": "elasticsearch", "name": "Search logs",
        "url": "https://search.example:9200", "api_key": "private-api-key",
        "table": "security-logs", "cursor_column": "event.sequence",
        "message_column": "message", "severity_column": "log.level",
    }
    with pytest.raises(ValueError, match="authorized"):
        monitor.add_source(source)
    created = monitor.add_source({**source, "authorized": True})
    source_id = created["source"]["id"]
    assert created["source"]["authorized_at"]
    assert "private-api-key" not in json.dumps(monitor.status())
    state_file = runtime / "data" / "defense_log_monitor.json"
    state = state_file.read_text(encoding="utf-8")
    assert "private-api-key" not in state
    assert "search.example" not in state
    assert "private-api-key" in credentials_path.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="credential file"):
        monitor.add_source({"kind": "file", "name": "Private data",
                            "path": str(credentials_path), "authorized": True})
    monitor.close()

    resumed = DefenseLogMonitor(runtime, credentials_path=credentials_path, autostart=False)
    assert resumed._sources[source_id]["api_key"] == "private-api-key"
    assert resumed._sources[source_id]["url"] == "https://search.example:9200"
    assert "private-api-key" not in json.dumps(resumed.status())
    resumed.close()


def test_corrupt_state_does_not_stop_api_or_get_overwritten(tmp_path: Path) -> None:
    state_file = tmp_path / "data" / "defense_log_monitor.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text("{corrupt", encoding="utf-8")
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    assert "could not be read" in monitor.status()["warning"]
    with pytest.raises(ValueError, match="repaired"):
        monitor.add_source({"kind": "file", "name": "App", "path": str(tmp_path / "app.log"),
                            "authorized": True})
    assert state_file.read_text(encoding="utf-8") == "{corrupt"
    monitor.close()


def test_elasticsearch_source_reaches_alert_pipeline(tmp_path: Path) -> None:
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    added = monitor.add_source({
        "kind": "elasticsearch", "name": "Search", "url": "https://search.example:9200",
        "table": "security-logs", "cursor_column": "event.sequence",
        "message_column": "message", "authorized": True,
    })
    with patch("backend.defense_log_monitor.read_elasticsearch", return_value=(
        [("{\"type\":\"integer\",\"value\":\"1\"}", "failed login", "warning")],
        {"initialized": True, "cursor": {"type": "integer", "value": "1"}},
    )) as reader:
        monitor.poll_once()
    assert reader.call_count == 1
    assert monitor.status()["sources"][0]["events_seen"] == 1
    assert monitor.status()["alerts"][0]["severity"] == "high"
    assert monitor.status()["alerts"][0]["source_id"] == added["source"]["id"]
    monitor.close()


def test_worker_recovers_after_poll_failure(tmp_path: Path) -> None:
    monitor = DefenseLogMonitor(tmp_path, poll_interval=0.05, autostart=False)
    recovered = threading.Event()
    calls = 0

    def poll() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("temporary storage failure")
        recovered.set()

    monitor.poll_once = poll  # type: ignore[method-assign]
    worker = threading.Thread(target=monitor._run, daemon=True)
    worker.start()
    assert recovered.wait(1)
    monitor._stop.set()
    worker.join(timeout=1)
    assert not worker.is_alive()
