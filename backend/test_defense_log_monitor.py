"""Focused contract tests for local Defense log collection."""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

import pytest

from backend.defense_log_monitor import DefenseLogMonitor, _database_query
from backend.defense_monitor_lease import MonitorLease, MonitorLeaseBusy


def _source(monitor: DefenseLogMonitor, kind: str, **options: object) -> dict[str, object]:
    return monitor.add_source({"kind": kind, "name": "test source", "authorized": True, **options})["source"]


def test_desktop_monitor_pauses_while_cli_owns_runtime(tmp_path: Path) -> None:
    with MonitorLease(tmp_path):
        monitor = DefenseLogMonitor(tmp_path)
        try:
            assert "Another defense log monitor" in monitor.status()["warning"]
            with pytest.raises(MonitorLeaseBusy):
                _source(monitor, "file", path=str(tmp_path / "events.log"))
            with pytest.raises(MonitorLeaseBusy):
                monitor.poll_once()
        finally:
            monitor.close()


def test_desktop_monitor_resumes_after_cli_releases_runtime(tmp_path: Path) -> None:
    log = tmp_path / "events.log"
    log.write_text("", encoding="utf-8")
    with MonitorLease(tmp_path):
        local = DefenseLogMonitor(tmp_path, autostart=False)
        try:
            _source(local, "file", path=str(log))
        finally:
            local.close()
        desktop = DefenseLogMonitor(tmp_path, poll_interval=0.05)
        assert "Waiting for it to stop" in desktop.status()["warning"]
    try:
        deadline = time.monotonic() + 3
        while desktop.status()["warning"] and time.monotonic() < deadline:
            time.sleep(0.02)
        assert desktop.status()["warning"] == ""
        with log.open("a", encoding="utf-8") as handle:
            handle.write("authentication failure\n")
        while not desktop.status()["alerts"] and time.monotonic() < deadline:
            time.sleep(0.02)
        assert desktop.status()["alerts"][0]["severity"] == "high"
    finally:
        desktop.close()


def test_file_tails_only_new_lines_and_resumes_without_duplicate(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("old authentication failure\n", encoding="utf-8")
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    source = _source(monitor, "file", path=str(log))
    assert source["watch_mode"] == "new events only"
    monitor.poll_once()
    assert monitor.status()["alerts"] == []

    with log.open("a", encoding="utf-8") as handle:
        handle.write("authentication failure for alice password=hunter2\n")
    monitor.poll_once()
    status = monitor.status()
    assert len(status["alerts"]) == 1
    assert status["alerts"][0]["severity"] == "high"
    assert "hunter2" not in status["alerts"][0]["message"]
    assert "authentication failure" in status["alerts"][0]["message"]
    assert status["sources"][0]["events_seen"] == 1
    monitor.close()

    resumed = DefenseLogMonitor(tmp_path, autostart=False)
    resumed.poll_once()
    assert len(resumed.status()["alerts"]) == 1
    with log.open("a", encoding="utf-8") as handle:
        handle.write("access denied for bob\n")
    resumed.poll_once()
    assert len(resumed.status()["alerts"]) == 2
    resumed.close()


def test_file_partial_line_truncation_rotation_and_bounded_backfill(tmp_path: Path) -> None:
    log = tmp_path / "events.log"
    log.write_text("", encoding="utf-8")
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    _source(monitor, "file", path=str(log))
    with log.open("ab") as handle:
        handle.write(b"access denied")
    monitor.poll_once()
    assert monitor.status()["alerts"] == []
    with log.open("ab") as handle:
        handle.write(b" for user\n")
    monitor.poll_once()
    assert len(monitor.status()["alerts"]) == 1

    log.write_text("malware detected\n", encoding="utf-8")
    monitor.poll_once()
    assert len(monitor.status()["alerts"]) == 2

    rotated = tmp_path / "events.log.1"
    log.rename(rotated)
    log.write_text("failed login\n", encoding="utf-8")
    monitor.poll_once()
    assert len(monitor.status()["alerts"]) == 3
    monitor.close()

    backfill = DefenseLogMonitor(tmp_path / "backfill", autostart=False)
    _source(backfill, "file", path=str(log), backfill=True)
    backfill.poll_once()
    assert len(backfill.status()["alerts"]) == 1
    backfill.close()


def test_file_rewrite_with_same_size_and_prefix_is_detected(tmp_path: Path) -> None:
    log = tmp_path / "copytruncate.log"
    prefix = "x" * 64 + " "
    log.write_text(prefix + "normal\n", encoding="utf-8")
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    _source(monitor, "file", path=str(log))
    monitor.poll_once()
    assert monitor.status()["alerts"] == []
    log.write_text(prefix + "ERROR!\n", encoding="utf-8")
    monitor.poll_once()
    alerts = monitor.status()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "medium"
    monitor.close()


def test_file_source_follows_symlink_rotation(tmp_path: Path) -> None:
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    link = tmp_path / "current.log"
    first.write_text("old event\n", encoding="utf-8")
    second.write_text("malware detected\n", encoding="utf-8")
    try:
        link.symlink_to(first)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")
    monitor = DefenseLogMonitor(tmp_path / "runtime", autostart=False)
    source = _source(monitor, "file", path=str(link))
    assert source["path"] == str(link)
    with first.open("a", encoding="utf-8") as handle:
        handle.write("access denied\n")
    monitor.poll_once()
    assert len(monitor.status()["alerts"]) == 1
    link.unlink()
    link.symlink_to(second)
    monitor.poll_once()
    assert len(monitor.status()["alerts"]) == 2
    monitor.close()


def test_symlink_retarget_to_private_state_is_rejected(tmp_path: Path) -> None:
    log = tmp_path / "events.log"
    link = tmp_path / "current.log"
    log.write_text("", encoding="utf-8")
    try:
        link.symlink_to(log)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")
    monitor = DefenseLogMonitor(tmp_path / "runtime", autostart=False)
    _source(monitor, "file", path=str(link))
    link.unlink()
    link.symlink_to(tmp_path / "runtime" / "data" / "defense_log_monitor.json")
    monitor.poll_once()
    assert monitor.status()["sources"][0]["state"] == "error"
    assert monitor.status()["alerts"] == []
    monitor.close()


def test_sqlite_monitors_new_rows_and_never_exposes_url(tmp_path: Path) -> None:
    db_path = tmp_path / "source.db"
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, message TEXT, severity TEXT)")
        db.execute("INSERT INTO events(message,severity) VALUES ('old error','error')")
    url = f"sqlite:///{db_path.as_posix()}"
    monitor = DefenseLogMonitor(tmp_path / "runtime", autostart=False)
    source = _source(monitor, "database", url=url, table="events", cursor_column="id",
                     message_column="message", severity_column="severity")
    assert "url" not in source
    monitor.poll_once()  # Initial max-cursor checkpoint; existing row is skipped.
    assert monitor.status()["alerts"] == []

    with sqlite3.connect(db_path) as db:
        db.execute("INSERT INTO events(message,severity) VALUES ('new failure','error')")
    monitor.poll_once()
    status = monitor.status()
    assert len(status["alerts"]) == 1
    assert status["alerts"][0]["message"] == "new failure"
    assert status["sources"][0]["events_seen"] == 1
    assert "url" not in status["sources"][0]
    monitor.close()

    resumed = DefenseLogMonitor(tmp_path / "runtime", autostart=False)
    resumed.poll_once()
    assert len(resumed.status()["alerts"]) == 1
    resumed.close()


def test_database_errors_and_credentials_are_not_exposed(tmp_path: Path) -> None:
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    secret = "especially-secret-password"
    url = f"postgresql+psycopg://nobody:{secret}@127.0.0.1:1/missing"
    source = _source(monitor, "database", url=url, table="events", cursor_column="id",
                     message_column="message")
    assert secret not in str(source)
    monitor.poll_once()
    status = monitor.status()
    assert status["sources"][0]["state"] == "error"
    assert secret not in str(status)
    assert "127.0.0.1" not in str(status["sources"][0]["error"])
    monitor.close()


def test_enable_remove_and_private_storage(tmp_path: Path) -> None:
    log = tmp_path / "test.log"
    log.write_text("", encoding="utf-8")
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    source = _source(monitor, "file", path=str(log))
    source_id = str(source["id"])
    assert monitor.set_enabled(source_id, False)["source"]["state"] == "stopped"
    log.write_text("malware detected\n", encoding="utf-8")
    monitor.poll_once()
    assert monitor.status()["alerts"] == []
    monitor.set_enabled(source_id, True)
    monitor.poll_once()
    assert len(monitor.status()["alerts"]) == 1
    state_path = tmp_path / "data" / "defense_log_monitor.json"
    assert state_path.exists()
    if os.name != "nt":
        assert state_path.stat().st_mode & 0o077 == 0
    assert monitor.remove_source(source_id) == {"ok": True}
    assert monitor.status()["sources"] == []
    monitor.close()


def test_invalid_input_does_not_echo_database_secret(tmp_path: Path) -> None:
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    secret = "password-in-bad-url"
    with pytest.raises(ValueError) as exc:
        _source(monitor, "database", url=f"not a url {secret}", table="events",
                cursor_column="id", message_column="message")
    assert secret not in str(exc.value)
    monitor.close()


def test_monitor_cannot_read_its_own_private_state(tmp_path: Path) -> None:
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    state_path = tmp_path / "data" / "defense_log_monitor.json"
    with pytest.raises(ValueError, match="own state"):
        _source(monitor, "file", path=str(state_path))
    monitor.close()


def test_database_query_compiles_for_major_sqlalchemy_dialects() -> None:
    from sqlalchemy import Column, Integer, MetaData, String, Table
    from sqlalchemy.dialects import mssql, mysql, oracle, postgresql, sqlite

    table = Table("events", MetaData(), Column("id", Integer, primary_key=True),
                  Column("message", String), Column("severity", String))
    for dialect in (sqlite.dialect(), postgresql.dialect(), mysql.dialect(),
                    mssql.dialect(), oracle.dialect()):
        query = _database_query(table, "id", "message", "severity", dialect.name, 12)
        sql = str(query.compile(dialect=dialect, compile_kwargs={"literal_binds": True})).upper()
        assert "SELECT" in sql and "EVENTS" in sql and "ID > 12" in sql
        assert "SUBSTR(" in sql if dialect.name in {"sqlite", "oracle"} else "SUBSTRING(" in sql
        assert any(marker in sql for marker in ("LIMIT 100", "TOP 100", "FETCH FIRST 100", "FETCH FIRST"))


def test_composite_key_is_not_a_safe_cursor(tmp_path: Path) -> None:
    db_path = tmp_path / "composite.db"
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE events (id INTEGER, tenant INTEGER, message TEXT, PRIMARY KEY(id, tenant))")
    monitor = DefenseLogMonitor(tmp_path / "runtime", autostart=False)
    _source(monitor, "database", url=f"sqlite:///{db_path.as_posix()}", table="events",
            cursor_column="id", message_column="message")
    monitor.poll_once()
    assert monitor.status()["sources"][0]["state"] == "error"
    monitor.close()


def test_database_cursor_resets_after_table_is_truncated(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, message TEXT)")
        db.execute("INSERT INTO events(id,message) VALUES (10,'old event')")
    monitor = DefenseLogMonitor(tmp_path / "runtime", autostart=False)
    _source(monitor, "database", url=f"sqlite:///{db_path.as_posix()}", table="events",
            cursor_column="id", message_column="message")
    monitor.poll_once()  # Baseline at id 10.
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM events")
        db.execute("INSERT INTO events(id,message) VALUES (1,'failed login')")
    monitor.poll_once()  # Recognize reset; checkpoint is saved before reading id 1.
    assert monitor.status()["sources"][0]["cursor_reset_at"]
    monitor.close()

    resumed = DefenseLogMonitor(tmp_path / "runtime", autostart=False)
    resumed.poll_once()
    assert len(resumed.status()["alerts"]) == 1
    assert resumed.status()["sources"][0]["state"] == "monitoring"
    resumed.close()


class _FakeMongoCursor:
    def __init__(self, docs: list[dict[str, object]]) -> None:
        self.docs = docs
        self.batch_size_value = None

    def sort(self, key: str, direction: int) -> "_FakeMongoCursor":
        self.docs.sort(key=lambda item: _fake_mongo_value(item, key), reverse=direction < 0)
        return self

    def limit(self, count: int) -> "_FakeMongoCursor":
        self.docs = self.docs[:count]
        return self

    def max_time_ms(self, _milliseconds: int) -> "_FakeMongoCursor":
        return self

    def batch_size(self, count: int) -> "_FakeMongoCursor":
        self.batch_size_value = count
        return self

    def __iter__(self):
        return iter(self.docs)


def _fake_mongo_value(document: dict[str, object], path: str) -> object:
    value: object = document
    for segment in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(segment)
    return value


def _fake_mongo_project(document: dict[str, object], projection: dict[str, int]) -> dict[str, object]:
    result: dict[str, object] = {}
    for path in projection:
        value = _fake_mongo_value(document, path)
        if value is None:
            continue
        target = result
        segments = path.split(".")
        for segment in segments[:-1]:
            target = target.setdefault(segment, {})  # type: ignore[assignment]
        target[segments[-1]] = value
    return result


class _FakeMongoCollection:
    def __init__(self, docs: list[dict[str, object]], indexes: dict[str, object] | None = None) -> None:
        self.docs = docs
        self.cursors: list[_FakeMongoCursor] = []
        self.projections: list[dict[str, int]] = []
        self.indexes = indexes or {"_id_": {"key": [("_id", 1)], "unique": True}}

    def find(self, filter_: dict[str, object], projection: dict[str, int]) -> _FakeMongoCursor:
        key, condition = next(iter(filter_.items()))
        if "$gt" in condition:
            rows = [doc for doc in self.docs if _fake_mongo_value(doc, key) is not None and
                    _fake_mongo_value(doc, key) > condition["$gt"]]
        else:
            rows = [doc for doc in self.docs if _fake_mongo_value(doc, key) is not None]
        cursor = _FakeMongoCursor([_fake_mongo_project(doc, projection) for doc in rows])
        self.cursors.append(cursor)
        self.projections.append(projection)
        return cursor

    def index_information(self) -> dict[str, object]:
        return self.indexes


class _FakeMongoClient:
    def __init__(self, collection: _FakeMongoCollection) -> None:
        self.collection = collection

    def __getitem__(self, name: str):
        return self.collection if name == "events" else self

    def close(self) -> None:
        pass


def test_mongodb_objectid_cursor_resume_and_redacted_status(tmp_path: Path) -> None:
    from bson.objectid import ObjectId

    docs = [{"_id": ObjectId(), "message": "old failure", "severity": "error"}]
    collection = _FakeMongoCollection(docs)
    fake = _FakeMongoClient(collection)
    runtime = tmp_path / "runtime"
    monitor = DefenseLogMonitor(runtime, autostart=False)
    secret = "mongodb-password-secret"
    source = _source(monitor, "mongodb", url=f"mongodb://operator:{secret}@localhost:27017/security",
                     table="events", message_column="message", severity_column="severity")
    assert source["cursor_column"] == "_id"
    assert secret not in str(source)
    monitor._mongo_for = lambda _source: fake
    monitor.poll_once()
    assert monitor.status()["alerts"] == []
    docs.append({"_id": ObjectId(), "message": "failed login", "severity": "warning"})
    monitor.poll_once()
    assert len(monitor.status()["alerts"]) == 1
    assert secret not in str(monitor.status())
    assert collection.cursors and all(cursor.batch_size_value == 1 for cursor in collection.cursors)
    monitor.close()

    resumed = DefenseLogMonitor(runtime, autostart=False)
    resumed._mongo_for = lambda _source: fake
    resumed.poll_once()
    assert len(resumed.status()["alerts"]) == 1
    resumed.close()


def test_mongodb_cursor_reset_after_collection_recreation(tmp_path: Path) -> None:
    collection = _FakeMongoCollection([{"_id": 10, "message": "old"}])
    fake = _FakeMongoClient(collection)
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    _source(monitor, "mongodb", url="mongodb://localhost:27017/security", table="events")
    monitor._mongo_for = lambda _source: fake
    monitor.poll_once()
    collection.docs[:] = [{"_id": 1, "message": "malware detected"}]
    monitor.poll_once()
    assert monitor.status()["sources"][0]["cursor_reset_at"]
    monitor.poll_once()
    assert len(monitor.status()["alerts"]) == 1
    monitor.close()


def test_mongodb_dotted_cursor_message_and_severity_fields(tmp_path: Path) -> None:
    docs = [{"_id": 1, "event": {"sequence": 10, "message": "old"},
             "log": {"level": "error"}}]
    collection = _FakeMongoCollection(
        docs, {"sequence_1": {"key": [("event.sequence", 1)], "unique": True}})
    fake = _FakeMongoClient(collection)
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    _source(monitor, "mongodb", url="mongodb://localhost:27017/security", table="events",
            cursor_column="event.sequence", message_column="event.message",
            severity_column="log.level")
    monitor._mongo_for = lambda _source: fake
    monitor.poll_once()
    assert monitor.status()["alerts"] == []
    docs.append({"_id": 2, "event": {"sequence": 11, "message": "new error"},
                 "log": {"level": "error"}})
    monitor.poll_once()
    assert monitor.status()["alerts"][0]["message"] == "new error"
    assert monitor.status()["alerts"][0]["severity"] == "medium"
    assert collection.projections[-1] == {
        "event.sequence": 1, "event.message": 1, "log.level": 1}
    monitor.poll_once()
    assert len(monitor.status()["alerts"]) == 1
    monitor.close()


@pytest.mark.parametrize(("field", "invalid"), [
    ("cursor_column", "event..sequence"),
    ("message_column", "event.$where"),
    ("severity_column", "log.level."),
])
def test_mongodb_rejects_unsafe_dotted_fields(tmp_path: Path, field: str, invalid: str) -> None:
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    with pytest.raises(ValueError, match="safe dotted identifier"):
        _source(monitor, "mongodb", url="mongodb://localhost:27017/security",
                table="events", **{field: invalid})
    monitor.close()


def test_mongodb_requires_database_in_url(tmp_path: Path) -> None:
    monitor = DefenseLogMonitor(tmp_path, autostart=False)
    with pytest.raises(ValueError, match="MongoDB URL"):
        _source(monitor, "mongodb", url="mongodb://user:secret@localhost:27017", table="events")
    monitor.close()
