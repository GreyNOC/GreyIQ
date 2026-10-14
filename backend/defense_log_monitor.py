"""Local, read-only log collectors for GreyIQ's Defense panel.

Sources watch *new* records by default.  A source can opt into bounded backfill.
Collection state and brief, redacted alerts are committed together so a restart
does not replay already processed records or silently lose an emitted alert.
Relational adapters are supplied by SQLAlchemy and the operator-installed
driver; MongoDB uses PyMongo. Configure a read-only account for either source.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import uuid4

if __package__:
    from .defense_elasticsearch import _connection as _elasticsearch_connection
    from .defense_elasticsearch import _source_fields as _elasticsearch_fields
    from .defense_elasticsearch import read_elasticsearch
    from .defense_monitor_lease import MonitorLease, MonitorLeaseBusy
else:
    from defense_elasticsearch import _connection as _elasticsearch_connection
    from defense_elasticsearch import _source_fields as _elasticsearch_fields
    from defense_elasticsearch import read_elasticsearch
    from defense_monitor_lease import MonitorLease, MonitorLeaseBusy


_POLL_SECONDS = 2.0
_MAX_FILE_BYTES = 256 * 1024
_MAX_FILE_LINES = 100
_MAX_LINE_BYTES = 16 * 1024
_MAX_DB_ROWS = 100
_MAX_DB_MESSAGE = 2048
_MAX_ALERTS = 300
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MONGO_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_COLLECTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|client[_-]?secret|"
    r"private[_-]?key|sessionid|session[_-]?token|access[_-]?key|refresh[_-]?token|"
    r"authorization)\b"
    r"(\s*[\"']?\s*[:=]\s*[\"']?)([^\s,;\"'}]+)"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+")
_SENSITIVE_HEADER = re.compile(r"(?im)\b(?:proxy-authorization|authorization|set-cookie|cookie|x-api-key)\s*:\s*[^\r\n]*")
_URL_USERINFO = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s@]+@")
_RULES = (
    (re.compile(r"(?i)\b(ransomware|malware detected|intrusion detected)\b"), "critical", "Security threat detected"),
    (re.compile(r"(?i)\b(failed (?:log.?in|authentication|password)|log.?in failed|"
                r"account failed to log on|authentication fail(?:ed|ure)|"
                r"brute.?force|unauthorized access|privilege escalation|access denied|permission denied)\b"),
     "high", "Access or authentication event"),
    (re.compile(r"(?i)\b(suspicious activity|firewall block(?:ed)?|account lock(?:ed|out))\b"),
     "medium", "Security event"),
)
_SEVERITY = {
    "emergency": "critical", "fatal": "critical", "critical": "critical", "crit": "critical",
    "error": "medium", "err": "medium", "high": "high",
    "warning": "low", "warn": "low", "medium": "medium",
    "low": "low", "notice": "low",
}
_LINE_LEVEL = re.compile(r"(?i)(?:^|[\s\[])\b(CRITICAL|FATAL|ERROR|ERR|WARN(?:ING)?|NOTICE)\b")


def defense_credentials_path(runtime_dir: str | os.PathLike[str]) -> Path:
    """Credential store shared by the desktop API and headless CLI."""
    if sys.platform == "win32":
        base = Path(os.getenv("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.getenv("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
    if not base.is_absolute():
        base = Path.home() / ("AppData/Local" if sys.platform == "win32" else ".local/state")
    key = hashlib.sha256(str(Path(runtime_dir).resolve()).encode("utf-8")).hexdigest()[:16]
    return base / "GreyIQ" / f"defense_credentials_{key}.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _private_json_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _safe_excerpt(value: Any) -> str:
    # Limit before regex work so one hostile row cannot consume unbounded CPU.
    text = str(value or "")[:_MAX_DB_MESSAGE]
    text = _SENSITIVE_HEADER.sub(lambda m: m.group(0).split(":", 1)[0] + ": [REDACTED]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _BASIC.sub("Basic [REDACTED]", text)
    text = _URL_USERINFO.sub(lambda m: m.group(1) + "[REDACTED]@", text)
    text = _SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", text)
    text = " ".join(text.split())
    return text[:240]


def _classification(message: str, severity: Any) -> tuple[str, str] | None:
    for pattern, level, title in _RULES:
        if pattern.search(message):
            return level, title
    raw = str(severity or "").strip().lower()
    if not raw:
        match = _LINE_LEVEL.search(message[:120])
        raw = match.group(1).lower() if match else ""
    level = _SEVERITY.get(raw)
    return (level, f"Log severity: {raw.title()}") if level else None


def _parse_line(text: str) -> tuple[str, str]:
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            obj = None
        if isinstance(obj, dict):
            message = next((obj[key] for key in ("message", "msg", "event") if isinstance(obj.get(key), str)), text)
            severity = next((obj[key] for key in ("severity", "level", "lvl") if isinstance(obj.get(key), str)), "")
            return str(message)[:_MAX_DB_MESSAGE], str(severity)[:64]
    return text[:_MAX_DB_MESSAGE], ""


def _mongo_value(document: dict[str, Any] | None, dotted_field: str) -> Any:
    """Read a projected MongoDB field, including nested dotted paths."""
    value: Any = document
    for part in dotted_field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _encode_cursor(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    try:
        from bson.objectid import ObjectId
    except ImportError:
        ObjectId = ()  # type: ignore[assignment,misc]
    if isinstance(value, datetime):
        kind, text = "datetime", value.isoformat()
    elif isinstance(value, date):
        kind, text = "date", value.isoformat()
    elif isinstance(value, Decimal):
        kind, text = "decimal", str(value)
    elif isinstance(value, bool):
        raise ValueError("Database cursor type is unsupported.")
    elif isinstance(value, int):
        kind, text = "integer", str(value)
    elif isinstance(value, float):
        kind, text = "float", repr(value)
    elif isinstance(value, str):
        kind, text = "string", value
    elif isinstance(value, ObjectId):
        kind, text = "objectid", str(value)
    else:
        raise ValueError("Database cursor type is unsupported.")
    if len(text) > 512:
        raise ValueError("Database cursor value is too large.")
    return {"type": kind, "value": text}


def _decode_cursor(cursor: dict[str, str] | None) -> Any:
    if cursor is None:
        return None
    kind, value = cursor["type"], cursor["value"]
    if kind == "objectid":
        from bson.objectid import ObjectId
        return ObjectId(value)
    decoders = {
        "datetime": datetime.fromisoformat, "date": date.fromisoformat,
        "decimal": Decimal, "integer": int, "float": float, "string": str,
    }
    if kind not in decoders:
        raise ValueError("Saved database cursor type is unsupported.")
    return decoders[kind](value)


def _head_digest(path: Path, length: int) -> str:
    with path.open("rb") as handle:
        return hashlib.sha256(handle.read(length)).hexdigest()


def _tail_digest(path: Path, offset: int) -> str:
    with path.open("rb") as handle:
        handle.seek(max(0, offset - 64))
        return hashlib.sha256(handle.read(min(offset, 64))).hexdigest()


def _database_query(table: Any, cursor_name: str, message_name: str,
                    severity_name: str, dialect_name: str, saved_cursor: Any) -> Any:
    """Build a bounded SELECT; identifiers come only from reflected columns."""
    from sqlalchemy import func, select

    cursor_col = table.c[cursor_name]
    clip = func.substr if dialect_name in {"oracle", "sqlite"} else func.substring
    columns = [cursor_col.label("cursor"), clip(table.c[message_name], 1, _MAX_DB_MESSAGE).label("message")]
    if severity_name:
        columns.append(clip(table.c[severity_name], 1, 64).label("severity"))
    query = select(*columns).order_by(cursor_col.asc()).limit(_MAX_DB_ROWS)
    if saved_cursor is not None:
        query = query.where(cursor_col > saved_cursor)
    return query


class DefenseLogMonitor:
    """Monitor operator-chosen files, SQL/MongoDB databases, and Elasticsearch indexes."""

    def __init__(self, runtime_dir: str | os.PathLike[str], *, poll_interval: float = _POLL_SECONDS,
                 autostart: bool = True,
                 credentials_path: str | os.PathLike[str] | None = None) -> None:
        self._runtime_dir = Path(runtime_dir)
        self._path = Path(runtime_dir) / "data" / "defense_log_monitor.json"
        self._credentials_path = (Path(credentials_path) if credentials_path is not None
                                  else self._path.with_name("defense_log_credentials.json"))
        self._worker: threading.Thread | None = None
        self._lease: MonitorLease | None = None
        self._lease_busy = False
        self._lock = threading.RLock()
        self._poll_lock = threading.Lock()
        self._stop = threading.Event()
        self._interval = max(0.05, float(poll_interval))
        self._engines: dict[str, Any] = {}
        self._mongo_clients: dict[str, Any] = {}
        self._tables: dict[str, Any] = {}
        self._last_persist = 0.0
        self._sources: dict[str, dict[str, Any]] = {}
        self._alerts: list[dict[str, Any]] = []
        self._load_warning = ""
        credentials: dict[str, Any] = {}
        if self._credentials_path.exists():
            try:
                raw_credentials = json.loads(self._credentials_path.read_text(encoding="utf-8"))
                credentials = raw_credentials.get("sources", {})
                if not isinstance(credentials, dict):
                    raise ValueError("Invalid credentials file.")
            except (OSError, ValueError, TypeError, AttributeError):
                self._load_warning = "Saved log source credentials could not be read. Affected database sources are paused."
        self._stored_credentials = credentials
        if self._path.exists():
            try:
                saved = json.loads(self._path.read_text(encoding="utf-8"))
                self._sources = {s["id"]: s for s in saved.get("sources", []) if isinstance(s, dict) and s.get("id")}
                self._alerts = [a for a in saved.get("alerts", []) if isinstance(a, dict)][-_MAX_ALERTS:]
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                self._load_warning = "Saved log monitor state could not be read; the monitor is paused to preserve it."
                self._sources = {}
                self._alerts = []
                self._state_unreadable = True
            else:
                self._state_unreadable = False
        else:
            self._state_unreadable = False
        for source in self._sources.values():
            if source.get("kind") == "file":
                continue
            stored = credentials.get(source["id"], {})
            if not isinstance(stored, dict):
                stored = {}
            # Legacy state may contain credentials. The next save migrates them
            # out of the workspace state file.
            source["url"] = stored.get("url") or source.get("url", "")
            source["api_key"] = stored.get("api_key") or source.get("api_key", "")
            if not source["url"]:
                source["enabled"] = False
                source["state"] = "error"
                source["error"] = "Saved connection credentials are unavailable; add this source again."
        if autostart:
            self.start()

    def start(self) -> None:
        """Start collection after the host application has entered its lifecycle.

        Reload state after taking the lease: a dormant monitor may have been
        constructed while another process was still collecting this runtime.
        """
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                if self._stop.is_set():
                    raise RuntimeError("The defense log monitor is still stopping.")
                return
            # ASGI test clients can run multiple startup/shutdown lifespans in
            # one process. A completed shutdown may start a fresh worker.
            self._worker = None
            self._stop.clear()
            self._lease_busy = True
            if not self._resume_after_lease():
                warning = "Another defense log monitor is using this runtime. Waiting for it to stop."
                self._load_warning = f"{self._load_warning} {warning}".strip()
                for source in self._sources.values():
                    if source.get("enabled"):
                        source["state"] = "paused"
                        source["error"] = warning
            self._worker = threading.Thread(target=self._run, name="greyiq-defense-logs", daemon=True)
            self._worker.start()

    def _ensure_available(self) -> None:
        if self._lease_busy:
            raise MonitorLeaseBusy("Another defense log monitor is using this runtime. Try again when it stops.")

    def _resume_after_lease(self) -> bool:
        """Reload the latest checkpoints after the other collector releases them."""
        if not self._lease_busy:
            return True
        lease = MonitorLease(self._runtime_dir)
        try:
            lease.acquire()
        except MonitorLeaseBusy:
            return False
        try:
            fresh = DefenseLogMonitor(
                self._runtime_dir, poll_interval=self._interval, autostart=False,
                credentials_path=self._credentials_path,
            )
            with self._lock:
                self._sources = fresh._sources
                self._alerts = fresh._alerts
                self._stored_credentials = fresh._stored_credentials
                self._state_unreadable = fresh._state_unreadable
                self._load_warning = fresh._load_warning
                self._lease = lease
                self._lease_busy = False
            return True
        except Exception:
            lease.release()
            raise

    def _save(self) -> None:
        if self._state_unreadable:
            raise OSError("Saved log monitor state is unreadable; no data was overwritten.")
        credentials = {
            source["id"]: {"url": source.get("url", ""), "api_key": source.get("api_key", "")}
            for source in self._sources.values() if source.get("kind") != "file"
        }
        public_sources = [
            {key: value for key, value in source.items() if key not in {"url", "api_key"}}
            for source in self._sources.values()
        ]
        # Write credentials first so a crash cannot leave a newly saved source
        # without its connection settings. The workspace state never holds them.
        if credentials != self._stored_credentials or (credentials and not self._credentials_path.exists()):
            _private_json_write(self._credentials_path, {"version": 1, "sources": credentials})
        _private_json_write(self._path, {"version": 2, "sources": public_sources, "alerts": self._alerts})
        self._stored_credentials = credentials

    @staticmethod
    def _public_source(source: dict[str, Any]) -> dict[str, Any]:
        public = {k: source.get(k) for k in (
            "id", "name", "kind", "enabled", "state", "error", "events_seen", "last_checked_at", "backfill",
            "authorized_at",
        )}
        public["watch_mode"] = "backfill then new events" if source.get("backfill") else "new events only"
        if source.get("kind") == "file":
            public["path"] = source.get("path", "")
        else:
            public.update({k: source.get(k, "") for k in (
                "database_type", "table", "cursor_column", "message_column", "severity_column"
            )})
            db_label = source.get("database_type", "database")
            if source.get("kind") == "mongodb":
                db_label = f"mongodb / {source.get('database_name', '')}"
            elif source.get("kind") == "elasticsearch":
                db_label = "elasticsearch"
            public["display_target"] = f"{db_label} / {source.get('table', '')}"
            public["cursor_reset_at"] = (source.get("checkpoint") or {}).get("reset_at")
        if source.get("kind") == "file":
            public["display_target"] = source.get("path", "")
        return public

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {"ok": True, "sources": [self._public_source(s) for s in self._sources.values()],
                    "alerts": [dict(a) for a in reversed(self._alerts)], "warning": self._load_warning}

    def add_source(self, config: dict[str, Any]) -> dict[str, Any]:
        self._ensure_available()
        if self._state_unreadable:
            raise ValueError("Saved log monitor state must be repaired before adding sources.")
        if not isinstance(config, dict):
            raise ValueError("Log source configuration must be an object.")
        if config.get("authorized") is not True:
            raise ValueError("Confirm that you are authorized to read this log source.")
        kind = str(config.get("kind") or "").strip().lower()
        if kind not in {"file", "database", "mongodb", "elasticsearch"}:
            raise ValueError("Log source kind must be file, database, mongodb, or elasticsearch.")
        name = str(config.get("name") or "").strip()
        if not name or len(name) > 120:
            raise ValueError("Log source name must be 1 to 120 characters.")
        backfill = config.get("backfill", False)
        if not isinstance(backfill, bool):
            raise ValueError("Backfill must be true or false.")
        source: dict[str, Any] = {
            "id": f"log_{uuid4().hex[:16]}", "name": name, "kind": kind,
            "enabled": True, "state": "starting", "error": "", "events_seen": 0,
            "last_checked_at": None, "backfill": backfill, "authorized_at": _now(),
        }
        if kind == "file":
            raw_path = str(config.get("path") or "").strip()
            if not raw_path:
                raise ValueError("A file path is required.")
            # Preserve the named path: operators commonly tail a stable symlink
            # that is repointed to a new file during rotation.
            path = Path(os.path.abspath(Path(raw_path).expanduser()))
            target = path.resolve()
            if (target in {self._path.resolve(), self._credentials_path.resolve()} or
                    (target.parent == self._path.parent.resolve() and target.name.startswith(self._path.name + ".")) or
                    (target.parent == self._credentials_path.parent.resolve() and
                     target.name.startswith(self._credentials_path.name + "."))):
                raise ValueError("The monitor's own state or credential file cannot be a log source.")
            if path.exists() and not path.is_file():
                raise ValueError("The log path must point to a regular file.")
            stat = path.stat() if path.exists() else None
            source["path"] = str(path)
            source["checkpoint"] = {
                "offset": stat.st_size if stat and not backfill else 0,
                "dev": stat.st_dev if stat else None,
                "ino": stat.st_ino if stat else None,
                "head_len": min(stat.st_size, 64) if stat else 0,
                "head": _head_digest(path, min(stat.st_size, 64)) if stat else None,
                "tail": _tail_digest(path, stat.st_size if not backfill else 0) if stat else None,
                "skip_line": False,
            }
        elif kind == "mongodb":
            raw_url = str(config.get("url") or "").strip()
            try:
                parsed = urlsplit(raw_url)
                database_name = unquote(parsed.path.lstrip("/"))
            except (ValueError, TypeError) as exc:
                raise ValueError("A valid MongoDB URL with a database name is required.") from exc
            if (parsed.scheme not in {"mongodb", "mongodb+srv"} or not parsed.netloc or
                    not database_name or "/" in database_name or parsed.fragment):
                raise ValueError("A valid MongoDB URL with a database name is required.")
            collection = str(config.get("table") or "").strip()
            cursor_col = str(config.get("cursor_column") or "_id").strip()
            message_col = str(config.get("message_column") or "message").strip()
            severity_col = str(config.get("severity_column") or "").strip()
            if not _COLLECTION.fullmatch(collection) or ".." in collection or collection.endswith("."):
                raise ValueError("MongoDB collection name is invalid.")
            if (len(cursor_col) > 160 or len(message_col) > 160 or
                    not _MONGO_FIELD.fullmatch(cursor_col) or not _MONGO_FIELD.fullmatch(message_col)):
                raise ValueError("Cursor and message fields must be safe dotted identifiers.")
            if severity_col and (len(severity_col) > 160 or not _MONGO_FIELD.fullmatch(severity_col)):
                raise ValueError("Severity field must be a safe dotted identifier.")
            source.update({
                "url": raw_url, "database_type": "mongodb", "database_name": database_name,
                "table": collection, "cursor_column": cursor_col,
                "message_column": message_col, "severity_column": severity_col,
                "checkpoint": {"initialized": bool(backfill), "cursor": None},
            })
        elif kind == "elasticsearch":
            raw_url = str(config.get("url") or "").strip()
            table = str(config.get("table") or "").strip()
            cursor_col = str(config.get("cursor_column") or "").strip()
            message_col = str(config.get("message_column") or "").strip()
            severity_col = str(config.get("severity_column") or "").strip()
            api_key = str(config.get("api_key") or "").strip()
            candidate = {
                "url": raw_url, "api_key": api_key, "table": table,
                "cursor_column": cursor_col, "message_column": message_col,
                "severity_column": severity_col,
            }
            _elasticsearch_fields(candidate)
            _elasticsearch_connection(candidate)
            source.update({
                **candidate, "database_type": "elasticsearch",
                "checkpoint": {"initialized": bool(backfill), "cursor": None},
            })
        else:
            try:
                from sqlalchemy.engine import make_url
                url = make_url(str(config.get("url") or ""))
            except Exception as exc:
                raise ValueError("A valid SQLAlchemy database URL is required.") from exc
            if not url.drivername or not (url.database or url.host or url.query):
                raise ValueError("A database target is required in the URL.")
            table = str(config.get("table") or "").strip()
            cursor_col = str(config.get("cursor_column") or "").strip()
            message_col = str(config.get("message_column") or "").strip()
            severity_col = str(config.get("severity_column") or "").strip()
            if not table or len(table.split(".")) > 2 or not all(_IDENTIFIER.fullmatch(p) for p in table.split(".")):
                raise ValueError("Table must be a simple name or schema.table.")
            if not _IDENTIFIER.fullmatch(cursor_col) or not _IDENTIFIER.fullmatch(message_col):
                raise ValueError("Cursor and message columns must be simple identifiers.")
            if severity_col and not _IDENTIFIER.fullmatch(severity_col):
                raise ValueError("Severity column must be a simple identifier.")
            source.update({
                "url": str(config["url"]), "database_type": url.drivername,
                "table": table, "cursor_column": cursor_col,
                "message_column": message_col, "severity_column": severity_col,
                "checkpoint": {"initialized": bool(backfill), "cursor": None},
            })
        with self._lock:
            self._sources[source["id"]] = source
            try:
                self._save()
            except Exception:
                del self._sources[source["id"]]
                raise
            return {"ok": True, "source": self._public_source(source)}

    def set_enabled(self, source_id: str, enabled: bool) -> dict[str, Any]:
        self._ensure_available()
        if not isinstance(enabled, bool):
            raise ValueError("Enabled must be true or false.")
        with self._lock:
            source = self._sources.get(source_id)
            if source is None:
                raise ValueError("Unknown log source.")
            previous = dict(source)
            source["enabled"] = enabled
            source["state"] = "starting" if enabled else "stopped"
            source["error"] = ""
            try:
                self._save()
            except Exception:
                self._sources[source_id] = previous
                raise
            return {"ok": True, "source": self._public_source(source)}

    def remove_source(self, source_id: str) -> dict[str, Any]:
        self._ensure_available()
        with self._lock:
            if source_id not in self._sources:
                raise ValueError("Unknown log source.")
            removed = self._sources.pop(source_id)
            try:
                self._save()
            except Exception:
                self._sources[source_id] = removed
                raise
            engine = self._engines.pop(source_id, None)
            mongo_client = self._mongo_clients.pop(source_id, None)
            self._tables.pop(source_id, None)
        if engine is not None:
            engine.dispose()
        if mongo_client is not None:
            mongo_client.close()
        return {"ok": True}

    def close(self) -> None:
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=3)
        with self._lock:
            engines = list(self._engines.values())
            self._engines.clear()
            mongo_clients = list(self._mongo_clients.values())
            self._mongo_clients.clear()
        for engine in engines:
            engine.dispose()
        for client in mongo_clients:
            client.close()
        if self._lease is not None and (self._worker is None or not self._worker.is_alive()):
            self._release_lease()

    def _release_lease(self) -> None:
        with self._lock:
            lease, self._lease = self._lease, None
        if lease is not None:
            lease.release()

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                if self._lease_busy:
                    try:
                        if not self._resume_after_lease():
                            self._stop.wait(self._interval)
                            continue
                    except Exception:
                        self._stop.wait(self._interval)
                        continue
                    if self._stop.is_set():
                        break
                try:
                    self.poll_once()
                except Exception:
                    # In particular, a temporary state-file write failure must not
                    # permanently kill the collector thread.
                    with self._lock:
                        for source in self._sources.values():
                            if source.get("enabled"):
                                source["state"] = "error"
                                source["error"] = "Monitor state could not be saved; check local storage."
                self._stop.wait(self._interval)
        finally:
            if self._stop.is_set():
                self._release_lease()

    def poll_once(self) -> None:
        """Run one bounded pass; public for deterministic tests and manual diagnostics."""
        self._ensure_available()
        with self._poll_lock:
            with self._lock:
                sources = [dict(s) for s in self._sources.values() if s.get("enabled")]
                sources.sort(key=lambda item: item.get("kind") != "file")
            for source in sources:
                source_id = source["id"]
                try:
                    if source["kind"] == "file":
                        events, checkpoint = self._read_file(source)
                    elif source["kind"] == "mongodb":
                        events, checkpoint = self._read_mongodb(source)
                    elif source["kind"] == "elasticsearch":
                        events, checkpoint = read_elasticsearch(source, dict(source.get("checkpoint") or {}))
                    elif source["kind"] == "database":
                        events, checkpoint = self._read_database(source)
                    else:
                        raise ValueError("Unsupported log source kind.")
                    alert_rows = []
                    for locator, message, severity in events:
                        classified = _classification(message, severity)
                        if classified is None:
                            continue
                        level, title = classified
                        alert_rows.append({
                            "id": "al_" + hashlib.sha256(f"{source_id}:{locator}:{title}".encode()).hexdigest()[:20],
                            "source_id": source_id, "source_name": source["name"],
                            "severity": level, "title": title, "message": _safe_excerpt(message), "timestamp": _now(),
                        })
                    with self._lock:
                        current = self._sources.get(source_id)
                        if current is None or not current.get("enabled"):
                            continue
                        current["checkpoint"] = checkpoint
                        current["events_seen"] = int(current.get("events_seen", 0)) + len(events)
                        current["state"] = "monitoring"
                        current["error"] = ""
                        current["last_checked_at"] = _now()
                        self._alerts.extend(alert_rows)
                        self._alerts = self._alerts[-_MAX_ALERTS:]
                        if (events or alert_rows or checkpoint != source.get("checkpoint") or
                                source.get("state") != "monitoring" or time.monotonic() - self._last_persist > 60):
                            self._save()
                            self._last_persist = time.monotonic()
                except Exception as exc:  # One failed source must not stop the others.
                    with self._lock:
                        self._tables.pop(source_id, None)
                        current = self._sources.get(source_id)
                        if current is not None and current.get("enabled"):
                            current["state"] = "error"
                            # Driver exceptions commonly include full URLs and SQL. Never echo them.
                            current["error"] = f"Source unavailable ({type(exc).__name__}). Check path, driver, permissions, and schema."
                            current["last_checked_at"] = _now()
                            self._save()

    def _read_file(self, source: dict[str, Any]) -> tuple[list[tuple[str, str, str]], dict[str, Any]]:
        path = Path(source["path"])
        # A symlink may be repointed after registration; keep the private-state
        # guard at the read boundary as well as at add_source.
        target = path.resolve()
        if (target in {self._path.resolve(), self._credentials_path.resolve()} or
                (target.parent == self._path.parent.resolve() and target.name.startswith(self._path.name + ".")) or
                (target.parent == self._credentials_path.parent.resolve() and
                 target.name.startswith(self._credentials_path.name + "."))):
            raise ValueError("The monitor's own state or credential file cannot be a log source.")
        stat = path.stat()
        if not path.is_file():
            raise ValueError("Log path is not a regular file.")
        old = dict(source.get("checkpoint") or {})
        old_head_len = min(max(0, int(old.get("head_len", 0))), 64)
        comparison_head = _head_digest(path, old_head_len)
        rotated = (old.get("dev") is not None and
                   (old.get("dev") != stat.st_dev or old.get("ino") != stat.st_ino))
        rewritten = old.get("head") is not None and old.get("head") != comparison_head
        old_offset = int(old.get("offset", 0))
        if old.get("tail") is not None and stat.st_size >= old_offset:
            rewritten = rewritten or old["tail"] != _tail_digest(path, old_offset)
        offset = 0 if rotated or rewritten or stat.st_size < old_offset else old_offset
        skip_line = bool(old.get("skip_line")) and not (rotated or rewritten or stat.st_size < old_offset)
        events: list[tuple[str, str, str]] = []
        consumed = 0
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (stat.st_dev, stat.st_ino):
                raise OSError("Log target changed during polling.")
            for private_path in (self._path, self._credentials_path):
                try:
                    private = private_path.stat()
                except FileNotFoundError:
                    continue
                if (opened.st_ino and private.st_ino and
                        (opened.st_dev, opened.st_ino) == (private.st_dev, private.st_ino)):
                    raise ValueError("The monitor's own state or credential file cannot be a log source.")
            handle.seek(offset)
            while len(events) < _MAX_FILE_LINES and consumed < _MAX_FILE_BYTES:
                start = handle.tell()
                chunk = handle.readline(min(_MAX_LINE_BYTES + 1, _MAX_FILE_BYTES - consumed))
                if not chunk:
                    break
                consumed += len(chunk)
                if not chunk.endswith(b"\n"):
                    if len(chunk) >= _MAX_LINE_BYTES or skip_line:
                        skip_line = True
                        offset = handle.tell()
                    # An ordinary partial line stays unconsumed until completed.
                    break
                offset = handle.tell()
                if skip_line or len(chunk) > _MAX_LINE_BYTES:
                    skip_line = False
                    continue
                message = chunk.decode("utf-8", errors="replace").strip()
                if message:
                    parsed_message, severity = _parse_line(message)
                    events.append((f"byte:{start}", parsed_message, severity))
        new_head_len = min(stat.st_size, 64)
        return events, {"offset": offset, "dev": stat.st_dev, "ino": stat.st_ino,
                        "head_len": new_head_len, "head": _head_digest(path, new_head_len),
                        "tail": _tail_digest(path, offset),
                        "skip_line": skip_line}

    def _engine_for(self, source: dict[str, Any]) -> Any:
        with self._lock:
            cached = self._engines.get(source["id"])
            if cached is not None:
                return cached
        from sqlalchemy import create_engine, event
        from sqlalchemy.engine import make_url
        from sqlalchemy.pool import NullPool

        url = make_url(source["url"])
        backend = url.get_backend_name()
        if backend == "sqlite":
            # A SQLite source must already exist. URI mode=ro protects it even if
            # future code accidentally tries to write through this connection.
            location = url.database
            if not location or location == ":memory:":
                raise ValueError("A persistent SQLite database file is required.")
            path = Path(location).expanduser().resolve()
            if not path.is_file():
                raise FileNotFoundError("SQLite database file is unavailable.")
            from urllib.parse import quote
            uri_path = quote(path.as_posix(), safe="/:")
            engine = create_engine(f"sqlite+pysqlite:///file:{uri_path}?mode=ro&uri=true", poolclass=NullPool)

            @event.listens_for(engine, "connect")
            def _query_only(dbapi_connection: Any, _record: Any) -> None:
                dbapi_connection.execute("PRAGMA query_only=ON")
        else:
            # Only common driver families have a portable connect timeout
            # keyword. Other dialects may set it in their connection URL.
            connect_args: dict[str, Any] = {}
            if backend in {"postgresql", "mysql", "mariadb"}:
                connect_args["connect_timeout"] = 5
            elif url.drivername == "mssql+pyodbc":
                connect_args["timeout"] = 5
            engine = create_engine(url, pool_pre_ping=True, poolclass=NullPool, connect_args=connect_args)
        with self._lock:
            existing = self._engines.get(source["id"])
            if existing is not None:
                engine.dispose()
                return existing
            self._engines[source["id"]] = engine
        return engine

    def _mongo_for(self, source: dict[str, Any]) -> Any:
        with self._lock:
            cached = self._mongo_clients.get(source["id"])
            if cached is not None:
                return cached
        from pymongo import MongoClient

        client = MongoClient(source["url"], serverSelectionTimeoutMS=5000,
                             connectTimeoutMS=5000, socketTimeoutMS=5000, retryReads=False)
        with self._lock:
            existing = self._mongo_clients.get(source["id"])
            if existing is not None:
                client.close()
                return existing
            self._mongo_clients[source["id"]] = client
        return client

    def _read_mongodb(self, source: dict[str, Any]) -> tuple[list[tuple[str, str, str]], dict[str, Any]]:
        from pymongo import ASCENDING, DESCENDING

        client = self._mongo_for(source)
        collection = client[source["database_name"]][source["table"]]
        cursor_name = source["cursor_column"]
        if cursor_name != "_id":
            unique = any(
                item.get("unique") and item.get("key") == [(cursor_name, ASCENDING)]
                for item in collection.index_information().values()
            )
            if not unique:
                raise ValueError("MongoDB cursor field must have a single-field unique ascending index.")
        checkpoint = dict(source.get("checkpoint") or {})
        base_filter = {cursor_name: {"$exists": True, "$ne": None}}
        if not checkpoint.get("initialized"):
            newest = collection.find(base_filter, {cursor_name: 1}).sort(
                cursor_name, DESCENDING).limit(1).batch_size(1).max_time_ms(5000)
            latest_row = next(iter(newest), None)
            latest = _mongo_value(latest_row, cursor_name)
            return [], {"initialized": True, "cursor": _encode_cursor(latest)}
        saved_cursor = _decode_cursor(checkpoint.get("cursor"))
        row_filter = {cursor_name: {"$gt": saved_cursor}} if saved_cursor is not None else base_filter
        projection: dict[str, int] = {}
        for field in (cursor_name, source["message_column"], source.get("severity_column") or ""):
            if not field or any(field.startswith(parent + ".") for parent in projection):
                continue
            for child in tuple(projection):
                if child.startswith(field + "."):
                    del projection[child]
            projection[field] = 1
        rows = collection.find(row_filter, projection).sort(
            cursor_name, ASCENDING).limit(_MAX_DB_ROWS).batch_size(1).max_time_ms(5000)
        events: list[tuple[str, str, str]] = []
        last_cursor: dict[str, str] | None = None
        for row in rows:
            encoded = _encode_cursor(_mongo_value(row, cursor_name))
            if encoded is None:
                continue
            locator = json.dumps(encoded, sort_keys=True)
            raw_message = _mongo_value(row, source["message_column"])
            message = raw_message[:_MAX_DB_MESSAGE] if isinstance(raw_message, str) else ""
            raw_severity = _mongo_value(row, source.get("severity_column") or "")
            severity = raw_severity[:64] if isinstance(raw_severity, str) else ""
            events.append((locator, message, severity))
            last_cursor = encoded
        if not events and saved_cursor is not None:
            newest = collection.find(base_filter, {cursor_name: 1}).sort(
                cursor_name, DESCENDING).limit(1).batch_size(1).max_time_ms(5000)
            latest_row = next(iter(newest), None)
            latest = _mongo_value(latest_row, cursor_name)
            try:
                reset = latest is None or latest < saved_cursor
            except TypeError:
                reset = False
            if reset:
                checkpoint["cursor"] = None
                checkpoint["reset_at"] = _now()
        if last_cursor is not None:
            checkpoint["cursor"] = last_cursor
        checkpoint["initialized"] = True
        return events, checkpoint

    def _read_database(self, source: dict[str, Any]) -> tuple[list[tuple[str, str, str]], dict[str, Any]]:
        from sqlalchemy import MetaData, Table, func, inspect, select
        engine = self._engine_for(source)
        pieces = source["table"].split(".")
        schema, table_name = (pieces[0], pieces[1]) if len(pieces) == 2 else (None, pieces[0])
        checkpoint = dict(source.get("checkpoint") or {})
        with engine.connect() as conn:
            table = self._tables.get(source["id"])
            if table is None:
                table = Table(table_name, MetaData(), schema=schema, autoload_with=conn)
                self._tables[source["id"]] = table
            cursor_col = table.c[source["cursor_column"]]
            message_col = table.c[source["message_column"]]
            severity_col = table.c[source["severity_column"]] if source.get("severity_column") else None
            # A nonunique cursor could skip tied rows at a batch boundary.
            unique = (len(table.primary_key.columns) == 1 and
                      source["cursor_column"] in table.primary_key.columns) or any(
                len(c.columns) == 1 and source["cursor_column"] in c.columns
                for c in table.constraints if type(c).__name__ == "UniqueConstraint"
            )
            if not unique:
                unique = any(
                    index.get("unique") and index.get("column_names") == [source["cursor_column"]]
                    for index in inspect(conn).get_indexes(table_name, schema=schema)
                )
            if not unique:
                raise ValueError("Cursor column must be unique and increasing.")
            if not checkpoint.get("initialized"):
                latest = conn.execute(select(func.max(cursor_col))).scalar_one()
                return [], {"initialized": True, "cursor": _encode_cursor(latest)}
            saved_cursor = _decode_cursor(checkpoint.get("cursor"))
            query = _database_query(table, source["cursor_column"], source["message_column"],
                                    source.get("severity_column") or "", engine.dialect.name, saved_cursor)
            rows = conn.execute(query).mappings().all()
            if not rows and saved_cursor is not None:
                # A log table can be truncated/recreated with its sequence reset.
                # Without this check `cursor > old_cursor` would stay quiet forever.
                latest = conn.execute(select(func.max(cursor_col))).scalar_one()
                try:
                    reset = latest is None or latest < saved_cursor
                except TypeError:
                    reset = False
                if reset:
                    checkpoint["cursor"] = None
                    checkpoint["reset_at"] = _now()
        events: list[tuple[str, str, str]] = []
        for row in rows:
            encoded = _encode_cursor(row["cursor"])
            locator = json.dumps(encoded, sort_keys=True)
            events.append((locator, str(row["message"] or "")[:_MAX_DB_MESSAGE],
                           str(row.get("severity") or "")[:64]))
        if rows:
            checkpoint["cursor"] = _encode_cursor(rows[-1]["cursor"])
        checkpoint["initialized"] = True
        return events, checkpoint
