"""Explicit local snapshots and conservative drift comparison.

A baseline means only "the operator chose this reference snapshot". It does not
certify that the reference host was clean. Partial collections never generate
removal claims, and transient outbound connections are not compared.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

BASELINE_KIND = "greyiq_defender_baseline"
SCHEMA_VERSION = 1
SECTIONS = ("processes", "listeners", "interfaces", "routes", "services", "startup", "packages", "files")
_MAX_BASELINE_BYTES = 64 * 1024 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _validate_inventory(inventory: Any) -> dict[str, Any]:
    if not isinstance(inventory, dict) or inventory.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported defender inventory schema")
    if not isinstance(inventory.get("host"), dict):
        raise ValueError("inventory host is missing")
    if not isinstance(inventory.get("coverage"), dict):
        raise ValueError("inventory coverage is missing")
    for section in ("processes", "connections", "interfaces", "routes", "services", "startup", "packages", "files"):
        if not isinstance(inventory.get(section), list):
            raise ValueError(f"inventory {section} is missing")
    if not isinstance(inventory.get("file_roots"), list):
        raise ValueError("inventory file_roots is missing")
    return inventory


def _validate_baseline(baseline: Any) -> dict[str, Any]:
    if not isinstance(baseline, dict) or baseline.get("kind") != BASELINE_KIND:
        raise ValueError("not a GreyIQ defender baseline")
    if baseline.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported defender baseline schema")
    inventory = _validate_inventory(baseline.get("inventory"))
    expected = hashlib.sha256(_canonical(inventory)).hexdigest()
    if baseline.get("sha256") != expected:
        raise ValueError("defender baseline integrity check failed")
    return baseline


def _read_baseline_bytes(path: Path) -> bytes:
    """Read one regular file within the size cap without following symlinks."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("baseline path must be a regular file, not a symlink")
    if before.st_size > _MAX_BASELINE_BYTES:
        raise ValueError("defender baseline exceeds size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("baseline changed during open")
        content = handle.read(_MAX_BASELINE_BYTES + 1)
        after = os.fstat(handle.fileno())
    if len(content) > _MAX_BASELINE_BYTES:
        raise ValueError("defender baseline exceeds size limit")
    if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("baseline changed during read")
    return content


def _parse_baseline_bytes(content: bytes) -> dict[str, Any]:
    try:
        baseline = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("defender baseline is not valid JSON") from exc
    return _validate_baseline(baseline)


def _sync_directory(path: Path) -> None:
    """Persist a directory entry where the host supports directory fsync."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        # Windows does not generally allow fsync on directory handles. On
        # POSIX, a failed sync means archival durability is unconfirmed.
        if os.name != "nt":
            raise


def _archive_baseline(target: Path, content: bytes, previous: dict[str, Any]) -> dict[str, str]:
    """Publish an immutable copy before replacement, reusing only exact copies."""
    content_sha256 = hashlib.sha256(content).hexdigest()
    archive = target.with_name(f".{target.name[:48]}.archive.{content_sha256}.json")
    fd, temporary = tempfile.mkstemp(prefix=".defender-archive-", suffix=".tmp", dir=target.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, archive)
        except FileExistsError:
            if _read_baseline_bytes(archive) != content:
                raise ValueError("baseline archive collision contains different content")
            if os.name != "nt" and stat.S_IMODE(archive.stat().st_mode) & 0o077:
                raise ValueError("existing baseline archive is not private")
        _sync_directory(target.parent)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return {"path": str(archive), "sha256": content_sha256,
            "baseline_sha256": str(previous["sha256"])}


def save_baseline(inventory: dict[str, Any], path: str | Path, *, replace: bool = False) -> dict[str, Any]:
    """Save an operator-selected reference; never overwrite unless ``replace`` is true.

    The return value is the verified baseline document. Replacement adds an
    ``archive`` object with the previous file's path and digests. A temporary
    file and atomic publish prevent a partial write becoming a valid reference.
    """
    _validate_inventory(inventory)
    inventory = json.loads(_canonical(inventory))  # a detached, JSON-safe copy
    target = Path(path).absolute()
    if target.is_symlink():
        raise ValueError("baseline path must not be a symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    baseline = {
        "kind": BASELINE_KIND,
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "sha256": hashlib.sha256(_canonical(inventory)).hexdigest(),
        "inventory": inventory,
    }
    encoded = json.dumps(baseline, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if len(encoded.encode("utf-8")) > _MAX_BASELINE_BYTES:
        raise ValueError("defender baseline exceeds size limit")
    fd, temporary = tempfile.mkstemp(prefix=".defender-baseline-", suffix=".tmp", dir=target.parent)
    archive_info = None
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            try:
                previous_content = _read_baseline_bytes(target)
            except FileNotFoundError:
                previous_content = None
            if previous_content is None:
                # Preserve create-only behavior if another writer has since
                # created a baseline at this path.
                os.link(temporary, target)
            else:
                previous = _parse_baseline_bytes(previous_content)
                archive_info = _archive_baseline(target, previous_content, previous)
                if _read_baseline_bytes(target) != previous_content:
                    raise ValueError("baseline changed before replacement")
                os.replace(temporary, target)
                _sync_directory(target.parent)
        else:
            # Hard-link publication is atomic and fails if the destination
            # already exists, including a race after the initial symlink check.
            os.link(temporary, target)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    result = _validate_baseline(baseline)
    if archive_info is not None:
        result["archive"] = archive_info
    return result


def load_baseline(path: str | Path) -> dict[str, Any]:
    """Load a snapshot only after validating its schema and SHA-256 digest."""
    return _parse_baseline_bytes(_read_baseline_bytes(Path(path)))


def _processes(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    windows = str(inventory.get("host", {}).get("platform") or "").lower().startswith("win")
    for row in inventory.get("processes", []):
        if not isinstance(row, dict):
            continue
        name, exe = str(row.get("name") or ""), str(row.get("exe") or "")
        if not name and not exe:
            continue
        # Name is the stable key across launches and executable replacement.
        # A path change then appears as a changed record, not unrelated add and
        # remove events. The full path set preserves distinct same-name binaries.
        group = groups.setdefault(name.casefold(), {
            "name": name, "exes": {}, "sha256_by_exe": {}, "count": 0,
        })
        group["count"] += 1
        if exe:
            path_key = ntpath.normcase(ntpath.normpath(exe)) if windows else exe
            group["exes"].setdefault(path_key, exe)
            digest = str(row.get("sha256") or "")
            if digest:
                group["sha256_by_exe"][path_key] = digest
    output = []
    for group in groups.values():
        exes = sorted(group["exes"].values(), key=str.casefold)
        output.append({"name": group["name"], "exe": exes[0] if len(exes) == 1 else "",
                       "exes": exes, "count": group["count"],
                       "sha256_by_exe": dict(sorted(group["sha256_by_exe"].items()))})
    return output


def _rows_differ(section: str, before: dict[str, Any], after: dict[str, Any],
                 *, windows: bool = False) -> bool:
    if section in {"services", "startup"}:
        old, new = dict(before), dict(after)
        if old.get("definition_status") != "hashed" or new.get("definition_status") != "hashed":
            # Missing definition bytes are a coverage gap, not evidence that
            # the unit or autorun target changed.
            for field in ("definition_sha256", "definition_status", "config_path", "target_path"):
                old.pop(field, None)
                new.pop(field, None)
        return old != new
    if section != "processes":
        return before != after
    old, new = dict(before), dict(after)
    old_hashes = old.pop("sha256_by_exe", {})
    new_hashes = new.pop("sha256_by_exe", {})
    if windows:
        for row in (old, new):
            row["exe"] = ntpath.normcase(ntpath.normpath(row["exe"])) if row["exe"] else ""
            row["exes"] = sorted(ntpath.normcase(ntpath.normpath(path))
                                 for path in row["exes"])
    if old != new:
        return True
    # One-sided opt-in or a temporarily unreadable executable cannot establish
    # binary drift. Only compare hashes observed for the same path in both runs.
    return any(old_hashes[path] != new_hashes[path]
               for path in old_hashes.keys() & new_hashes.keys())


def _listeners(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    process_by_pid = {
        row.get("pid"): row for row in inventory.get("processes", [])
        if isinstance(row, dict) and isinstance(row.get("pid"), int)
    }
    listeners = []
    for row in inventory.get("connections", []):
        if not isinstance(row, dict):
            continue
        # UDP BOUND rows do not establish that a process is offering a service.
        # Outbound clients commonly bind a new ephemeral UDP port each cycle,
        # so comparing them as listeners creates false intrusion alerts. The
        # raw UDP sockets remain in inventory and PID trace for investigation.
        if (str(row.get("protocol") or "").lower() != "tcp"
                or str(row.get("state") or "").upper() not in {"LISTEN", "LISTENING"}):
            continue
        process = process_by_pid.get(row.get("pid"), {})
        listeners.append({
            "protocol": row.get("protocol"), "family": row.get("family"),
            "local_address": row.get("local_address"), "local_port": row.get("local_port"),
            "process_name": process.get("name", ""), "process_exe": process.get("exe", ""),
        })
    return listeners


def _key(section: str, row: dict[str, Any]) -> str:
    if section == "processes":
        parts = (str(row.get("name") or "").casefold(),)
    elif section == "listeners":
        parts = (row.get("protocol"), row.get("family"), row.get("local_address"),
                 row.get("local_port"), row.get("process_name"))
    elif section == "interfaces":
        parts = (row.get("mac") or row.get("name"),)
    elif section == "routes":
        parts = (row.get("family"), row.get("destination"), row.get("interface"))
    elif section == "services":
        parts = (row.get("name"),)
    elif section == "startup":
        parts = (row.get("name"), row.get("location"))
    elif section == "packages":
        parts = (row.get("name"), row.get("publisher"))
    else:
        parts = (row.get("path"),)
    return json.dumps(parts, sort_keys=True, default=str)


def _section_rows(inventory: dict[str, Any], section: str) -> list[dict[str, Any]]:
    if section == "processes":
        return _processes(inventory)
    if section == "listeners":
        return _listeners(inventory)
    return [row for row in inventory.get(section, []) if isinstance(row, dict)]


def _coverage(inventory: dict[str, Any], section: str) -> str:
    source = "connections" if section == "listeners" else section
    if section == "listeners":
        # Listener ownership depends on both collections.
        if inventory.get("coverage", {}).get("processes") != "ok":
            return "partial"
    return str(inventory.get("coverage", {}).get(source) or "unavailable")


def compare_baseline(inventory: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Return evidence of local drift without labeling it malicious.

    PID churn and ephemeral outbound connections are ignored. A partial source
    can support comparisons of records it observed, but cannot support claims
    about missing records.
    """
    current = _validate_inventory(inventory)
    reference = _validate_baseline(baseline)["inventory"]
    for field in ("hostname", "platform", "machine"):
        if str(current["host"].get(field) or "").casefold() != str(reference["host"].get(field) or "").casefold():
            raise ValueError(f"baseline belongs to a different host ({field} mismatch)")
    old_roots = {os.path.normcase(os.path.normpath(str(path))) for path in reference.get("file_roots", [])}
    new_roots = {os.path.normcase(os.path.normpath(str(path))) for path in current.get("file_roots", [])}
    if old_roots != new_roots:
        raise ValueError("file roots differ from baseline; compare the same paths or create a new reference")
    sections: dict[str, Any] = {}
    summary = {"added": 0, "removed": 0, "changed": 0}
    windows = str(current["host"].get("platform") or "").lower().startswith("win")
    for section in SECTIONS:
        old_coverage = _coverage(reference, section)
        new_coverage = _coverage(current, section)
        old_rows = {_key(section, row): row for row in _section_rows(reference, section)}
        new_rows = {_key(section, row): row for row in _section_rows(current, section)}
        observed_old = old_coverage in {"ok", "partial"}
        observed_new = new_coverage in {"ok", "partial"}
        added = [new_rows[key] for key in sorted(new_rows.keys() - old_rows.keys())] if old_coverage == "ok" and observed_new else []
        removed = [old_rows[key] for key in sorted(old_rows.keys() - new_rows.keys())] if new_coverage == "ok" and observed_old else []
        changed = [
            {"before": old_rows[key], "after": new_rows[key]}
            for key in sorted(old_rows.keys() & new_rows.keys())
            if _rows_differ(section, old_rows[key], new_rows[key], windows=windows)
        ] if observed_old and observed_new else []
        status = "compared" if old_coverage == new_coverage == "ok" else "partial" if observed_old and observed_new else "unavailable"
        sections[section] = {
            "status": status, "baseline_coverage": old_coverage, "current_coverage": new_coverage,
            "added": added, "removed": removed, "changed": changed,
        }
        for change in summary:
            summary[change] += len(sections[section][change])
    return {
        "schema_version": SCHEMA_VERSION, "baseline_created_at": baseline["created_at"],
        "current_collected_at": current.get("collected_at"), "host": current["host"],
        "file_roots": reference.get("file_roots", []), "sections": sections,
        "summary": summary,
        "note": "Changes are observations requiring review, not confirmed threats or proof the baseline was clean.",
    }
