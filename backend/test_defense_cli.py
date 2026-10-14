"""End-to-end contracts for the terminal Defense log monitor."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest import mock

from backend.defense_log_monitor import defense_credentials_path


ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "backend" / "gn_cli.py"


def _run(runtime: Path, *argv: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["GREYIQ_RUNTIME_DIR"] = str(runtime)
    env["LOCALAPPDATA"] = str(runtime.parent / "local-profile")
    env["XDG_STATE_HOME"] = str(runtime.parent / "local-profile")
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(CLI), "defense", *argv],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=20, env=env,
    )


def _json_result(process: subprocess.CompletedProcess[str]) -> dict:
    assert process.returncode == 0, process.stderr
    return json.loads(process.stdout)


def test_defense_is_registered_and_help_works_without_third_party_imports() -> None:
    from backend import gn_cli
    from backend.test_gn_cli_stdlib_boot import _run_cli as guarded_run

    assert "defense" in gn_cli.CLI_COMMANDS
    proc = guarded_run(["defense", "--help"])
    assert proc.returncode == 0, proc.stderr
    assert "add" in proc.stdout and "watch" in proc.stdout


def test_file_source_requires_explicit_authorization(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    log = tmp_path / "events.log"
    log.write_text("", encoding="utf-8")
    proc = _run(runtime, "add", "--kind", "file", "--name", "App", "--path", str(log), "--json")
    assert proc.returncode == 2
    assert "authoriz" in json.loads(proc.stdout)["error"].lower()
    assert _json_result(_run(runtime, "status", "--json"))["sources"] == []


def test_file_add_watch_once_and_lifecycle_share_saved_state(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    log = tmp_path / "events.log"
    log.write_text("old authentication failure\n", encoding="utf-8")
    added = _json_result(_run(
        runtime, "add", "--kind", "file", "--name", "App", "--path", str(log), "-y", "--json",
    ))
    source_id = added["source"]["id"]
    assert added["source"]["watch_mode"] == "new events only"

    with log.open("a", encoding="utf-8") as handle:
        handle.write("authentication failure for alice password=hunter2\n")
    watched = _run(runtime, "watch", "--once", "--json")
    assert watched.returncode == 0, watched.stderr
    status = _json_result(_run(runtime, "status", "--json"))
    assert status["sources"][0]["id"] == source_id
    assert status["sources"][0]["events_seen"] == 1
    assert len(status["alerts"]) == 1
    assert status["alerts"][0]["severity"] == "high"
    assert "authentication failure" in status["alerts"][0]["message"]
    assert "hunter2" not in watched.stdout + json.dumps(status)

    assert _run(runtime, "stop", source_id, "--json").returncode == 0
    assert _json_result(_run(runtime, "status", "--json"))["sources"][0]["enabled"] is False
    assert _run(runtime, "start", source_id, "--json").returncode == 0
    assert _json_result(_run(runtime, "status", "--json"))["sources"][0]["enabled"] is True
    assert _run(runtime, "remove", source_id, "--json").returncode == 0
    assert _json_result(_run(runtime, "status", "--json"))["sources"] == []


def test_database_url_env_is_secret_safe_and_credentials_match_desktop_path(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    url = "postgresql+psycopg://reader:db-password@db.example.invalid/logs"
    key = "GREYIQ_DEFENSE_TEST_URL"
    proc = _run(
        runtime, "add", "--kind", "database", "--name", "Database logs",
        "--url-env", key, "--table", "events", "--cursor", "id",
        "--message", "message", "--severity", "level", "-y", "--json",
        extra_env={key: url},
    )
    added = _json_result(proc)
    assert added["source"]["kind"] == "database"
    status = _json_result(_run(runtime, "status", "--json"))
    assert len(status["sources"]) == 1
    for text in (proc.stdout, proc.stderr, json.dumps(status)):
        assert "db-password" not in text
        assert url not in text

    profile = tmp_path / "local-profile"
    with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(profile), "XDG_STATE_HOME": str(profile)}):
        credentials_path = defense_credentials_path(runtime)
    assert credentials_path.exists()
    assert url in credentials_path.read_text(encoding="utf-8")
    state_path = runtime / "data" / "defense_log_monitor.json"
    assert "db-password" not in state_path.read_text(encoding="utf-8")


def test_sqlite_source_collects_new_row_through_cli(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    database = tmp_path / "audit.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, message TEXT, severity TEXT)")
    added = _json_result(_run(
        runtime, "add", "--kind", "database", "--name", "SQLite audit",
        "--url", f"sqlite:///{database.as_posix()}", "--table", "events",
        "--cursor", "id", "--message", "message", "--severity", "severity",
        "-y", "--json",
    ))
    assert added["source"]["kind"] == "database"
    assert _run(runtime, "watch", "--once", "--json").returncode == 0
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO events (message, severity) VALUES (?, ?)", ("failed login", "high"))
    watched = _json_result(_run(runtime, "watch", "--once", "--json"))
    assert watched["sources"][0]["events_seen"] == 1
    assert watched["alerts"][0]["severity"] == "high"


def test_credential_bearing_command_line_url_is_refused_without_echo(tmp_path: Path) -> None:
    url = "postgresql+psycopg://reader:command-line-secret@db.example.invalid/logs"
    proc = _run(
        tmp_path / "runtime", "add", "--kind", "database", "--name", "Database logs",
        "--url", url, "--table", "events", "--cursor", "id",
        "--message", "message", "-y", "--json",
    )
    assert proc.returncode == 2
    assert "command-line-secret" not in proc.stdout + proc.stderr
    assert "--url-env" in json.loads(proc.stdout)["error"]


def test_elasticsearch_api_key_from_env_stays_out_of_output(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    key = "GREYIQ_DEFENSE_TEST_API_KEY"
    proc = _run(
        runtime, "add", "--kind", "elasticsearch", "--name", "Search logs",
        "--url", "https://search.example.invalid:9200", "--table", "security-logs",
        "--cursor", "event.sequence", "--message", "message", "--severity", "log.level",
        "--api-key-env", key, "-y", "--json",
        extra_env={key: "sensitive-api-key"},
    )
    assert proc.returncode == 0, proc.stderr
    assert "sensitive-api-key" not in proc.stdout + proc.stderr
    assert "sensitive-api-key" not in json.dumps(_json_result(_run(runtime, "status", "--json")))


def test_mongodb_collection_can_be_registered_without_connecting(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    added = _json_result(_run(
        runtime, "add", "--kind", "mongodb", "--name", "Mongo logs",
        "--url", "mongodb://127.0.0.1:27017/logs", "--table", "events",
        "--cursor", "_id", "--message", "event.message", "--severity", "log.level",
        "-y", "--json",
    ))
    assert added["source"]["kind"] == "mongodb"
    status = _json_result(_run(runtime, "status", "--json"))
    assert status["sources"][0]["kind"] == "mongodb"
    assert status["sources"][0]["table"] == "events"


def test_continuous_watch_emits_new_alert_as_ndjson() -> None:
    from backend import defense_cli

    alert = {"id": "alert-1", "severity": "high", "message": "failed login"}
    snapshots = iter([
        {"ok": True, "sources": [], "alerts": []},
        {"ok": True, "sources": [], "alerts": [alert]},
    ])

    def poll() -> dict:
        try:
            return next(snapshots)
        except StopIteration:
            raise KeyboardInterrupt from None

    output = io.StringIO()
    args = argparse.Namespace(json=True, once=False, interval=0.5)
    with mock.patch.object(defense_cli.time, "sleep"), contextlib.redirect_stdout(output):
        assert defense_cli._watch(args, poll, attached=False) == 0
    lines = [json.loads(line) for line in output.getvalue().splitlines()]
    assert lines[0]["type"] == "status"
    assert [line["alert"]["id"] for line in lines if line["type"] == "alert"] == ["alert-1"]
