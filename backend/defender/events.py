"""Append-only, bounded local defender event journal.

Each JSONL record has a sequence number and SHA-256 link to the previous
record. A separate head checkpoint detects accidental tail truncation. The
chain detects corruption, not a deliberate attacker who can rewrite both the
journal and checkpoint. No packet bytes, command lines, or secrets are stored.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import uuid
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping
from urllib.parse import urlsplit, urlunsplit


_GENESIS = "0" * 64
_MAX_EVENT_BYTES = 16_384
_MAX_FIELD_CHARS = 512
_MAX_EVIDENCE_FIELDS = 40
_MAX_READ_LIMIT = 10_000
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|authorization|cookie)\s*[:=]\s*([^\s,;]+)"
)
_BEARER_VALUE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_ALLOWED_EVIDENCE = {
    "pid", "ppid", "process_name", "exe", "old_exe", "new_exe", "sha256",
    "protocol", "local_address", "local_port", "remote_address", "remote_port",
    "state", "service", "port", "name", "location", "start_type", "status",
    "interface", "indicator_type", "indicator_value", "source", "url",
    "retrieved_at", "expires_at", "category", "count", "host", "scan_id",
    "rule_id", "coverage", "error_code", "tool", "exit_code", "duration_ms",
    "artifact_path", "artifact_relpath", "artifact_sha256", "artifact_bytes", "process_count",
    "connection_count", "interface_count", "route_count", "service_count",
    "startup_count", "package_count", "file_count", "finding_count",
    "error_count", "changed_count", "removed_count", "added_count",
    "affected_count", "baseline_file_count", "watched_root_count",
    "loopback_only", "baseline_path", "baseline_sha256",
    "archive_path", "archive_relpath", "archive_sha256", "prior_baseline_sha256",
    "observation_source", "observed_endpoint", "source_ip", "destination_ip",
    "source_port", "destination_port", "packet_count",
}


class EventLogIntegrityError(RuntimeError):
    """The event journal or its head checkpoint is inconsistent."""


def _paths(runtime_dir: str | Path) -> tuple[Path, Path, Path]:
    directory = Path(runtime_dir) / "defender"
    return directory / "events.jsonl", directory / "events.head.json", directory / "events.lock"


def _private(path: Path) -> None:
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


@contextmanager
def _journal_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    _private(path)
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _clean_text(value: Any, *, limit: int = _MAX_FIELD_CHARS) -> str:
    if value is None:
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    text = "".join(char for char in text if char.isprintable())
    text = _BEARER_VALUE.sub("Bearer <redacted>", text)
    text = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    return text[:limit]


def _clean_url(value: Any) -> str:
    text = _clean_text(value, limit=1000)
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return ""
    # Remove embedded credentials, query strings, and fragments.
    netloc = parts.hostname
    try:
        if parts.port:
            netloc += f":{parts.port}"
    except ValueError:
        return ""
    return urlunsplit((parts.scheme, netloc, parts.path[:256], "", ""))


def _clean_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    clean: dict[str, Any] = {}
    for key, raw in value.items():
        if len(clean) >= _MAX_EVIDENCE_FIELDS:
            break
        if not isinstance(key, str) or key not in _ALLOWED_EVIDENCE:
            continue
        if isinstance(raw, bool):
            clean[key] = raw
        elif isinstance(raw, (int, float)) and not isinstance(raw, bool):
            if isinstance(raw, int) or math.isfinite(raw):
                clean[key] = raw
        elif isinstance(raw, str):
            clean[key] = _clean_url(raw) if key == "url" else _clean_text(raw)
        elif raw is None:
            clean[key] = None
        # Arrays and nested objects could carry packet or process content.
    return clean


def _normalize_event(event: Mapping[str, Any]) -> dict[str, Any]:
    event_type = _clean_text(event.get("type") or event.get("kind") or event.get("event_type"), limit=80)
    if not event_type or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,79}", event_type):
        raise ValueError("event type must be a short identifier")
    severity = _clean_text(event.get("severity") or "info", limit=16).lower()
    if severity not in {"info", "low", "medium", "high", "critical"}:
        raise ValueError("event severity must be info, low, medium, high, or critical")
    evidence = _clean_evidence(event.get("evidence") or event.get("details"))
    return {
        "type": event_type,
        "severity": severity,
        "title": _clean_text(event.get("title"), limit=200),
        "message": _clean_text(event.get("message"), limit=1000),
        "source": _clean_text(event.get("source"), limit=100),
        "rule_id": _clean_text(event.get("rule_id"), limit=100),
        "subject": _clean_text(event.get("subject"), limit=256),
        "status": _clean_text(event.get("status"), limit=40),
        "scan_id": _clean_text(event.get("scan_id"), limit=100),
        "evidence": evidence,
    }


def _canonical(record: Mapping[str, Any]) -> bytes:
    material = {key: value for key, value in record.items() if key != "hash"}
    return json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


def _last_record(path: Path) -> tuple[dict[str, Any] | None, int]:
    if not path.exists():
        return None, 0
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        if size == 0:
            return None, 0
        stream.seek(max(0, size - _MAX_EVENT_BYTES - 2))
        tail = stream.read()
    if not tail.endswith(b"\n"):
        raise EventLogIntegrityError("event journal ends with an incomplete record")
    lines = tail.rstrip(b"\n").split(b"\n")
    if not lines or len(lines[-1]) > _MAX_EVENT_BYTES:
        raise EventLogIntegrityError("last event record is missing or oversized")
    try:
        record = json.loads(lines[-1].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EventLogIntegrityError("last event record is not valid JSON") from exc
    if not isinstance(record, dict) or record.get("hash") != _digest(record):
        raise EventLogIntegrityError("last event record failed integrity check")
    if not isinstance(record.get("sequence"), int) or record["sequence"] < 1:
        raise EventLogIntegrityError("last event sequence is invalid")
    return record, size


def _head(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EventLogIntegrityError("event head checkpoint is invalid") from exc
    if not isinstance(value, dict):
        raise EventLogIntegrityError("event head checkpoint is invalid")
    return value


def _write_head(path: Path, *, sequence: int, digest: str, size: int) -> None:
    value = {"sequence": sequence, "hash": digest, "size": size}
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, path)
        _private(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def append_event(runtime_dir: str | Path, event: Mapping[str, Any]) -> dict[str, Any]:
    """Append one redacted event; return the persisted record.

    Unknown fields, command lines, packet payloads, and nested objects are not
    copied. The caller's mapping is never modified. If the journal checkpoint
    shows a truncated or replaced file, this raises instead of hiding it.
    """

    if not isinstance(event, Mapping):
        raise TypeError("event must be a mapping")
    normalized = _normalize_event(event)
    path, head_path, lock_path = _paths(runtime_dir)
    with _journal_lock(lock_path):
        previous, size = _last_record(path)
        checkpoint = _head(head_path)
        if checkpoint is not None and (
            checkpoint.get("sequence") != (previous or {}).get("sequence", 0)
            or checkpoint.get("hash") != (previous or {}).get("hash", _GENESIS)
            or checkpoint.get("size") != size
        ):
            raise EventLogIntegrityError("event journal differs from its head checkpoint")
        if checkpoint is None and previous is not None:
            # A crash may leave a complete journal line before the checkpoint
            # rename. Verify the entire chain before accepting a new append.
            result = _verify_unlocked(path, None)
            if not result["ok"]:
                raise EventLogIntegrityError(result["error"])
        record = {
            "schema_version": "1",
            "sequence": int(previous["sequence"]) + 1 if previous else 1,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "event_id": uuid.uuid4().hex,
            **normalized,
            "prev_hash": previous["hash"] if previous else _GENESIS,
        }
        record["hash"] = _digest(record)
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        if len(line) > _MAX_EVENT_BYTES:
            raise ValueError("event exceeds the 16 KB journal record limit")
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
        try:
            written = os.write(fd, line)
            if written != len(line):
                raise OSError("short write to event journal")
            os.fsync(fd)
        finally:
            os.close(fd)
        _private(path)
        _write_head(head_path, sequence=record["sequence"], digest=record["hash"], size=size + len(line))
    return record


def _verify_unlocked(path: Path, head_path: Path | None) -> dict[str, Any]:
    expected_sequence = 1
    expected_prev = _GENESIS
    size = 0
    if path.exists():
        with path.open("rb") as stream:
            for line in stream:
                size += len(line)
                if not line.endswith(b"\n") or len(line) > _MAX_EVENT_BYTES:
                    return {"ok": False, "event_count": expected_sequence - 1, "error": "incomplete or oversized event record"}
                try:
                    record = json.loads(line.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError):
                    return {"ok": False, "event_count": expected_sequence - 1, "error": "invalid event JSON"}
                if not isinstance(record, dict) or record.get("sequence") != expected_sequence:
                    return {"ok": False, "event_count": expected_sequence - 1, "error": "event sequence gap or invalid record"}
                if record.get("prev_hash") != expected_prev or record.get("hash") != _digest(record):
                    return {"ok": False, "event_count": expected_sequence - 1, "error": "event hash chain mismatch"}
                expected_prev = record["hash"]
                expected_sequence += 1
    count = expected_sequence - 1
    if head_path is not None:
        try:
            checkpoint = _head(head_path)
        except EventLogIntegrityError as exc:
            return {"ok": False, "event_count": count, "error": str(exc)}
        if checkpoint is None and count:
            return {"ok": False, "event_count": count, "error": "event head checkpoint is missing"}
        if checkpoint is not None and (
            checkpoint.get("sequence") != count or checkpoint.get("hash") != expected_prev
            or checkpoint.get("size") != size
        ):
            return {"ok": False, "event_count": count, "error": "event head checkpoint mismatch or tail truncation"}
    return {"ok": True, "event_count": count, "last_hash": expected_prev, "error": ""}


def verify_events(runtime_dir: str | Path) -> dict[str, Any]:
    """Verify every link and the external head checkpoint."""

    path, head_path, lock_path = _paths(runtime_dir)
    with _journal_lock(lock_path):
        return _verify_unlocked(path, head_path)


def verify_artifacts(runtime_dir: str | Path) -> dict[str, Any]:
    """Verify every journal-linked run artifact without reading outside runs/.

    The journal is verified before its references are trusted. Artifact paths
    must name direct, regular children of this runtime's ``defender/runs``
    directory. This checks saved evidence for accidental loss or alteration;
    it cannot authenticate against an attacker able to rewrite the journal.
    """

    path, head_path, lock_path = _paths(runtime_dir)
    runs = (Path(runtime_dir) / "defender" / "runs").resolve()
    references: list[tuple[str, str, str | None]] = []
    with _journal_lock(lock_path):
        journal = _verify_unlocked(path, head_path)
        if not journal["ok"]:
            return {"ok": False, "referenced": 0, "verified": 0,
                    "error": f"journal: {journal['error']}"}
        if path.exists():
            with path.open("rb") as stream:
                for line in stream:
                    event = json.loads(line)
                    evidence = event.get("evidence") or {}
                    if not isinstance(evidence, dict):
                        continue
                    artifact_path = evidence.get("artifact_path")
                    artifact_relpath = evidence.get("artifact_relpath")
                    artifact_hash = evidence.get("artifact_sha256")
                    if artifact_path is None and artifact_hash is None and artifact_relpath is None:
                        continue
                    if (not isinstance(artifact_path, str) or not isinstance(artifact_hash, str)
                            or artifact_relpath is not None and not isinstance(artifact_relpath, str)):
                        return {"ok": False, "referenced": len(references) + 1,
                                "verified": 0, "error": "incomplete artifact reference"}
                    references.append((artifact_path, artifact_hash, artifact_relpath))

    verified = 0
    for raw_path, expected, relpath in references:
        if relpath is not None:
            if (not re.fullmatch(r"runs/[A-Za-z0-9._-]+\.json\.gz", relpath)
                    or Path(raw_path).name != relpath.split("/", 1)[1]):
                return {"ok": False, "referenced": len(references), "verified": verified,
                        "error": "artifact relative reference is invalid"}
            target = runs / relpath.split("/", 1)[1]
        else:
            target = Path(raw_path)
        if (not target.is_absolute() or target.name in {"", ".", ".."}
                or target.suffixes[-2:] != [".json", ".gz"]
                or target.parent.resolve() != runs
                or target.is_symlink()
                or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            return {"ok": False, "referenced": len(references), "verified": verified,
                    "error": "artifact reference is outside this runtime or invalid"}
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target, flags)
            try:
                file_stat = os.fstat(fd)
                if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > 34 * 1024 * 1024:
                    raise OSError("artifact is not a regular file")
                digest = hashlib.sha256()
                with os.fdopen(fd, "rb", closefd=False) as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
            finally:
                os.close(fd)
        except OSError:
            return {"ok": False, "referenced": len(references), "verified": verified,
                    "error": f"artifact missing or unreadable: {target.name}"}
        if digest.hexdigest() != expected:
            return {"ok": False, "referenced": len(references), "verified": verified,
                    "error": f"artifact digest mismatch: {target.name}"}
        verified += 1
    return {"ok": True, "referenced": len(references), "verified": verified, "error": ""}


def read_events(runtime_dir: str | Path, limit: int = 100) -> list[dict[str, Any]]:
    """Read the most recent events, newest first, without mutating the log."""

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise ValueError("limit must be a non-negative integer")
    if limit == 0:
        return []
    path, _, lock_path = _paths(runtime_dir)
    with _journal_lock(lock_path):
        if not path.exists():
            return []
        recent: deque[dict[str, Any]] = deque(maxlen=min(limit, _MAX_READ_LIMIT))
        with path.open("rb") as stream:
            for line in stream:
                if not line.endswith(b"\n") or len(line) > _MAX_EVENT_BYTES:
                    raise EventLogIntegrityError("incomplete or oversized event record")
                try:
                    value = json.loads(line.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise EventLogIntegrityError("invalid event JSON") from exc
                if not isinstance(value, dict):
                    raise EventLogIntegrityError("invalid event record")
                recent.append(value)
        return list(reversed(recent))
