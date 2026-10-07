"""Read-only terminal dashboard for the local GreyIQ operator workspace.

The dashboard reads the portfolio, finding ledger, hunt trace, and report file
names from ``GREYIQ_RUNTIME_DIR``. Its only socket request is a short health
probe to 127.0.0.1; it never starts a scan or changes the runtime store.
"""

from __future__ import annotations

import http.client
import json
import math
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
_STAGES = ("discovered", "confirmed", "reported", "submitted", "paid")
_MAX_STORE_BYTES = 64 * 1024 * 1024


def _text(value: Any, limit: int = 100) -> str:
    """Make stored, possibly target-controlled text inert in a terminal."""
    cleaned = _CONTROL.sub(" ", str(value or ""))
    cleaned = " ".join(cleaned.split())
    return cleaned[:limit]


def _timestamp(value: Any) -> float:
    try:
        if isinstance(value, (int, float)):
            return float(value)
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError, OverflowError):
        return 0.0


def _clock(value: float) -> str:
    return datetime.fromtimestamp(value).strftime("%m-%d %H:%M") if value > 0 else "--"


def _read_json(path: Path, errors: list[str]) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        if path.is_symlink():
            raise ValueError("symlinked store refused")
        if path.stat().st_size > _MAX_STORE_BYTES:
            raise ValueError("store too large for dashboard")
        result = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(result, dict):
            raise ValueError("expected a JSON object")
        return result
    except (OSError, ValueError, RecursionError) as exc:
        errors.append(f"{path.name}: {_text(exc, 80)}")
        return {}


def _api_health(port: int) -> str:
    """Probe only the local API; HTTP redirects are deliberately not followed."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.35)
    try:
        conn.request("GET", "/api/health", headers={"Accept": "application/json"})
        response = conn.getresponse()
        if response.status == 401:
            return "protected"
        if response.status != 200:
            return f"HTTP {response.status}"
        payload = json.loads(response.read(256).decode("utf-8"))
        return "online" if isinstance(payload, dict) and payload.get("status") == "ok" else "unexpected reply"
    except (OSError, ValueError, json.JSONDecodeError, http.client.HTTPException):
        return "offline"
    finally:
        conn.close()


def _report_files(runtime_dir: Path, limit: int = 8) -> list[tuple[float, str]]:
    """Inspect names and mtimes only, with bounded traversal and no symlink follow."""
    root = runtime_dir / "reports"
    if not root.is_dir() or root.is_symlink():
        return []
    found: list[tuple[float, str]] = []
    pending: list[tuple[Path, int]] = [(root, 0)]
    visited = 0
    while pending and visited < 3000:
        folder, depth = pending.pop()
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    visited += 1
                    if visited > 3000:
                        break
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False) and depth < 2:
                        pending.append((Path(entry.path), depth + 1))
                    elif entry.is_file(follow_symlinks=False) and entry.name.lower().endswith(".md"):
                        stamp = entry.stat(follow_symlinks=False).st_mtime
                        found.append((stamp, _text(Path(entry.path).relative_to(root), 120)))
        except OSError:
            continue
    found.sort(key=lambda item: item[0], reverse=True)
    return found[:limit]


def _recent_traces(runtime_dir: Path, limit: int = 8) -> list[tuple[float, str]]:
    path = runtime_dir / "hunt_traces.jsonl"
    try:
        if path.is_symlink():
            return []
        with path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            start = max(0, size - 256 * 1024)
            handle.seek(start)
            if start:
                handle.readline()  # discard a partial record
            lines = handle.readlines()[-limit:]
    except OSError:
        return []
    events: list[tuple[float, str]] = []
    for line in lines:
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(row, dict):
            continue
        outcomes = row.get("outcomes")
        count = len(outcomes) if isinstance(outcomes, list) else 0
        program = _text(row.get("program") or "unknown", 40)
        events.append((_timestamp(row.get("ts")), f"Hunt {program}: {count} outcome(s)"))
    return events


def _cpu_ticks(proc_root: Path = Path("/proc")) -> tuple[int, int] | None:
    """Return Linux busy/total CPU ticks; the caller computes a later delta."""
    try:
        with (proc_root / "stat").open(encoding="ascii") as handle:
            first = handle.readline().split()
        if first[0] != "cpu" or len(first) < 5:
            return None
        # guest/guest_nice are already included in user/nice; use the first eight.
        ticks = [int(value) for value in first[1:9]]
        total = sum(ticks)
        idle = ticks[3] + (ticks[4] if len(ticks) > 4 else 0)
        return total - idle, total
    except (OSError, ValueError, IndexError):
        return None


def _cpu_percent(previous: tuple[int, int] | None, current: tuple[int, int] | None) -> float | None:
    if previous is None or current is None:
        return None
    busy_delta = current[0] - previous[0]
    total_delta = current[1] - previous[1]
    if total_delta <= 0 or busy_delta < 0:
        return None
    return max(0.0, min(100.0, 100.0 * busy_delta / total_delta))


def _system_health() -> tuple[str, float | None, str]:
    try:
        load = os.getloadavg()
        load_text = f"{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}"
    except (AttributeError, OSError):
        load_text = "unavailable"
    memory_percent: float | None = None
    memory_text = "unavailable"
    try:
        values: dict[str, int] = {}
        with Path("/proc/meminfo").open(encoding="ascii") as handle:
            for line in handle:
                key, _, raw = line.partition(":")
                if key in ("MemTotal", "MemAvailable"):
                    values[key] = int(raw.strip().split()[0])
        total, available = values["MemTotal"], values["MemAvailable"]
        if total:
            used = max(0, min(total, total - available))
            memory_percent = 100.0 * used / total
            memory_text = f"{used / (1024 * 1024):.1f}/{total / (1024 * 1024):.1f} GiB"
    except (OSError, KeyError, ValueError):
        pass
    return load_text, memory_percent, memory_text


def _local_processes(proc_root: Path = Path("/proc"), *, uid: int | None = None, limit: int = 6) -> list[dict[str, Any]]:
    """List only same-user GreyIQ processes, never exposing their arguments."""
    if uid is None:
        if not hasattr(os, "getuid"):
            return []
        uid = os.getuid()
    found: list[dict[str, Any]] = []
    try:
        with os.scandir(proc_root) as entries:
            for index, entry in enumerate(entries):
                if index >= 4096:
                    break
                if not entry.name.isdecimal():
                    continue
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    base = Path(entry.path)
                    comm = (base / "comm").read_text(encoding="ascii", errors="replace").strip().lower()
                    if not (comm.startswith("greyiq") or comm in ("electron", "python", "python3") or comm.startswith("python3.")):
                        continue
                    status = (base / "status").read_text(encoding="ascii", errors="replace")
                    uid_line = next((line for line in status.splitlines() if line.startswith("Uid:")), "")
                    if not uid_line or int(uid_line.split()[1]) != uid:
                        continue
                    role = ""
                    if comm == "greyiq-backend":
                        role = "Backend"
                    elif comm.startswith("greyiq"):
                        role = "Desktop"
                    else:
                        # Used only to identify the process. Never display cmdline:
                        # CLI arguments may contain cookies or authorization headers.
                        command = (base / "cmdline").read_bytes()[:4096].lower()
                        if comm.startswith("python") and b"backend.greyiq_api" in command:
                            role = "Backend (dev)"
                        elif comm == "electron" and b"greyiq" in command:
                            role = "Desktop (dev)"
                    if not role:
                        continue
                    rss_line = next((line for line in status.splitlines() if line.startswith("VmRSS:")), "")
                    rss_mib = round(int(rss_line.split()[1]) / 1024) if rss_line else 0
                    found.append({"pid": int(entry.name), "role": role, "rss_mib": rss_mib})
                except (OSError, ValueError, IndexError):
                    continue  # a process exited or its details are not readable
    except OSError:
        return []
    found.sort(key=lambda row: (-row["rss_mib"], row["pid"]))
    return found[: max(0, limit)]


def collect_snapshot(runtime_dir: str | Path, *, port: int = 8766,
                     previous_cpu: tuple[int, int] | None = None) -> dict[str, Any]:
    """Return a small, display-safe snapshot. All store access is read-only."""
    runtime = Path(runtime_dir)
    errors: list[str] = []
    portfolio = _read_json(runtime / "portfolio.json", errors)
    ledger = _read_json(runtime / "bughunter_ledger.json", errors)

    raw_programs = portfolio.get("programs")
    raw_programs = raw_programs if isinstance(raw_programs, dict) else {}
    programs = []
    for key, value in raw_programs.items():
        if not isinstance(value, dict):
            continue
        programs.append({
            "name": _text(value.get("name") or key, 60),
            "enabled": bool(value.get("enabled", True)),
            "last_run": _timestamp(value.get("last_run_at")),
        })
    programs.sort(key=lambda item: (not item["enabled"], item["name"].lower()))

    counts = dict.fromkeys(_STAGES, 0)
    ready = 0
    total = 0
    bounty = 0.0
    finding_events: list[tuple[float, str]] = []
    dismissed = ledger.get("dismissed")
    dismissed = dismissed if isinstance(dismissed, dict) else {}
    buckets = ledger.get("programs")
    buckets = buckets if isinstance(buckets, dict) else {}
    for bucket in buckets.values():
        if not isinstance(bucket, dict):
            continue
        findings = bucket.get("findings")
        if not isinstance(findings, dict):
            continue
        for key, record in findings.items():
            if not isinstance(record, dict) or key in dismissed or record.get("dismissed"):
                continue
            total += 1
            stage = record.get("stage")
            if isinstance(stage, str) and stage in counts:
                counts[stage] += 1
            if record.get("report_ready"):
                ready += 1
            try:
                amount = float(record.get("bounty") or 0)
                if math.isfinite(amount):
                    bounty += amount
            except (TypeError, ValueError):
                pass
            stamp = _timestamp(record.get("updated_at") or record.get("last_seen"))
            if stamp:
                title = _text(record.get("title") or "finding", 70)
                finding_events.append((stamp, f"{_text(stage, 12)}: {title}"))

    reports = _report_files(runtime)
    events = finding_events + _recent_traces(runtime)
    events.extend((stamp, f"Report saved: {name}") for stamp, name in reports)
    events.sort(key=lambda item: item[0], reverse=True)
    load, memory_percent, memory = _system_health()
    cpu_ticks = _cpu_ticks()
    return {
        "as_of": time.time(),
        "runtime": _text(runtime, 160),
        "api": _api_health(port),
        "port": port,
        "load": load,
        "memory": memory,
        "memory_percent": memory_percent,
        "cpu_percent": _cpu_percent(previous_cpu, cpu_ticks),
        "cpu_ticks": cpu_ticks,
        "processes": _local_processes(),
        "programs": programs,
        "enabled": sum(bool(row["enabled"]) for row in programs),
        "total": total,
        "stages": counts,
        "ready": ready,
        "bounty": round(bounty, 2),
        "reports": reports,
        "activity": events[:12],
        "errors": errors,
    }


def _write(screen: Any, y: int, x: int, width: int, value: str, style: int = 0) -> None:
    import curses

    if width <= 0:
        return
    try:
        screen.addnstr(y, x, _text(value, max(1, width * 2)), width, style)
    except curses.error:
        pass  # lower-right terminal cell and concurrent resize are harmless


def _box(screen: Any, y: int, x: int, height: int, width: int, title: str, style: int) -> None:
    if height < 3 or width < 4:
        return
    _write(screen, y, x, width, "+" + "-" * (width - 2) + "+", style)
    for row in range(y + 1, y + height - 1):
        _write(screen, row, x, 1, "|", style)
        _write(screen, row, x + width - 1, 1, "|", style)
    _write(screen, y + height - 1, x, width, "+" + "-" * (width - 2) + "+", style)
    _write(screen, y, x + 2, width - 4, f" {title} ", style)


def _rows(screen: Any, y: int, x: int, height: int, width: int, rows: list[str], offset: int = 0) -> None:
    for index, line in enumerate(rows[offset:offset + max(0, height - 2)]):
        _write(screen, y + 1 + index, x + 2, width - 4, line)


def _gauge(label: str, percent: float | None, width: int = 16) -> str:
    if percent is None:
        return f"{label:<4} [{'?' * width}]   --"
    bounded = max(0.0, min(100.0, percent))
    filled = round(width * bounded / 100)
    return f"{label:<4} [{'#' * filled}{'.' * (width - filled)}] {bounded:3.0f}%"


def _process_row(row: dict[str, Any]) -> str:
    return f"PID {row['pid']:<7} {row['role']:<14} {row['rss_mib']:>5} MiB"


def _render(screen: Any, snapshot: dict[str, Any], focus: int, offsets: list[int], version: str) -> None:
    import curses

    screen.erase()
    height, width = screen.getmaxyx()
    if height < 23 or width < 60:
        _write(screen, 0, 0, max(0, width - 1), "GreyIQ dashboard: enlarge terminal to at least 60 x 23; q to quit")
        screen.refresh()
        return
    accent = curses.color_pair(1) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD
    warn = curses.color_pair(2) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD
    _write(screen, 0, 1, width - 2, f"GREYIQ  /  OPERATOR DASHBOARD  v{version}", accent)
    _write(screen, 1, 1, width - 2, f"Local status   {datetime.fromtimestamp(snapshot['as_of']).strftime('%Y-%m-%d %H:%M:%S')}")

    wide = width >= 104
    top_y, top_h = 2, 9 if wide else 8
    processes = snapshot["processes"]
    stages = snapshot["stages"]
    if wide:
        split = width // 2
        _box(screen, top_y, 0, top_h, split, "SYSTEM / ENGINE", accent)
        _rows(screen, top_y, 0, top_h, split, [
            f"API  {snapshot['api']}  /  127.0.0.1:{snapshot['port']}",
            _gauge("CPU", snapshot["cpu_percent"]),
            _gauge("MEM", snapshot["memory_percent"]) + f"  {snapshot['memory']}",
            f"Load  {snapshot['load']}",
            f"GreyIQ processes: {len(processes)} detected",
            *([_process_row(row) for row in processes[:2]] or ["No local GreyIQ process found"]),
        ])
        _box(screen, top_y, split, top_h, width - split, "FINDING PIPELINE", accent)
        _rows(screen, top_y, split, top_h, width - split, [
            f"Findings {snapshot['total']}    Ready {snapshot['ready']}    Bounty ${snapshot['bounty']:,.2f}",
            *[f"{stage.title():<11} {stages[stage]:>4}  "
              + _gauge("", 100 * stages[stage] / snapshot["total"] if snapshot["total"] else 0, 12)
              for stage in _STAGES],
            f"Runtime: {snapshot['runtime']}",
        ])
        mid_y = top_y + top_h
        activity_h = 6
        mid_h = height - 1 - mid_y - activity_h
        panels = [(mid_y, 0, mid_h, split), (mid_y, split, mid_h, width - split)]
        activity_y = mid_y + mid_h
    else:
        _box(screen, top_y, 0, top_h, width, "SYSTEM / PIPELINE", accent)
        process_line = _process_row(processes[0]) + (f"  (+{len(processes) - 1} more)" if len(processes) > 1 else "") if processes else "No local GreyIQ process found"
        _rows(screen, top_y, 0, top_h, width, [
            f"API {snapshot['api']} / 127.0.0.1:{snapshot['port']}    Load {snapshot['load']}",
            _gauge("CPU", snapshot["cpu_percent"], 20),
            _gauge("MEM", snapshot["memory_percent"], 20) + f"  {snapshot['memory']}",
            f"Programs {len(snapshot['programs'])} / enabled {snapshot['enabled']}    Findings {snapshot['total']} / ready {snapshot['ready']}    ${snapshot['bounty']:,.2f}",
            f"D {stages['discovered']}  C {stages['confirmed']}  R {stages['reported']}  S {stages['submitted']}  P {stages['paid']}",
            f"Processes {len(processes)} detected: {process_line}",
        ])
        mid_y = top_y + top_h
        activity_h = 5
        mid_h = height - 1 - mid_y - activity_h
        first_h = max(4, mid_h // 2)
        panels = [(mid_y, 0, first_h, width), (mid_y + first_h, 0, mid_h - first_h, width)]
        activity_y = mid_y + mid_h

    programs = snapshot["programs"]
    reports = snapshot["reports"]
    py, px, ph, pw = panels[0]
    _box(screen, py, px, ph, pw, f"PORTFOLIO  {len(programs)} programs" + (" *" if focus == 0 else ""), accent if focus == 0 else 0)
    program_rows = [f"{'ON ' if row['enabled'] else 'OFF'}  {row['name']}    last {_clock(row['last_run'])}" for row in programs]
    _rows(screen, py, px, ph, pw, program_rows or ["No saved programs"], offsets[0])

    ry, rx, rh, rw = panels[1]
    _box(screen, ry, rx, rh, rw, f"RECENT REPORTS  {len(reports)} shown" + (" *" if focus == 1 else ""), accent if focus == 1 else 0)
    report_rows = [f"{_clock(stamp)}  {name}" for stamp, name in reports]
    _rows(screen, ry, rx, rh, rw, report_rows or ["No report files"], offsets[1])

    _box(screen, activity_y, 0, activity_h, width, "RECENT ACTIVITY" + (" *" if focus == 2 else ""), accent if focus == 2 else 0)
    activity_rows = [f"{_clock(stamp)}  {message}" for stamp, message in snapshot["activity"]]
    _rows(screen, activity_y, 0, activity_h, width, activity_rows or ["No recent activity"], offsets[2])
    if snapshot["errors"]:
        _write(screen, height - 1, 1, width - 2, "Store warning: " + snapshot["errors"][0], warn)
    else:
        _write(screen, height - 1, 1, width - 2, "Tab: panel   Up/Down: scroll   r: refresh   q: quit   Read-only", accent)
    screen.refresh()


def _tui(screen: Any, runtime_dir: Path, port: int, interval: float, version: str) -> None:
    import curses

    try:
        curses.curs_set(0)
    except curses.error:
        pass
    if curses.has_colors():
        curses.start_color()
        try:
            curses.use_default_colors()
            background = -1
        except curses.error:
            background = curses.COLOR_BLACK
        curses.init_pair(1, curses.COLOR_CYAN, background)
        curses.init_pair(2, curses.COLOR_YELLOW, background)
    screen.keypad(True)
    screen.timeout(200)
    snapshot: dict[str, Any] | None = None
    next_refresh = 0.0
    focus = 0
    offsets = [0, 0, 0]
    while True:
        now = time.monotonic()
        if snapshot is None or now >= next_refresh:
            previous_cpu = snapshot.get("cpu_ticks") if snapshot else None
            snapshot = collect_snapshot(runtime_dir, port=port, previous_cpu=previous_cpu)
            next_refresh = now + interval
        _render(screen, snapshot, focus, offsets, version)
        key = screen.getch()
        if key in (ord("q"), ord("Q"), 27):
            return
        if key in (ord("r"), ord("R")):
            next_refresh = 0.0
        elif key in (9, curses.KEY_RIGHT):
            focus = (focus + 1) % 3
        elif key == curses.KEY_LEFT:
            focus = (focus - 1) % 3
        elif key in (curses.KEY_DOWN, ord("j")):
            lengths = (len(snapshot["programs"]), len(snapshot["reports"]), len(snapshot["activity"]))
            offsets[focus] = min(offsets[focus] + 1, max(0, lengths[focus] - 1))
        elif key in (curses.KEY_UP, ord("k")):
            offsets[focus] = max(0, offsets[focus] - 1)


def run_dashboard(runtime_dir: str | Path, *, port: int = 8766, interval: float = 2.0, version: str = "") -> int:
    """Run the interactive dashboard; return 2 with a clear message without a TTY."""
    if not sys.stdin.isatty() or not sys.stdout.isatty() or os.getenv("TERM", "").lower() in ("", "dumb"):
        print("gn: dashboard requires an interactive terminal (stdin/stdout TTY and TERM).", file=sys.stderr)
        return 2
    if not 1 <= port <= 65535 or not 0.2 <= interval <= 60:
        print("gn: dashboard requires --port 1..65535 and --interval 0.2..60 seconds.", file=sys.stderr)
        return 2
    try:
        import curses
    except ImportError:
        print("gn: this terminal does not provide Python curses support.", file=sys.stderr)
        return 2
    try:
        curses.wrapper(_tui, Path(runtime_dir), port, interval, version)
    except (curses.error, OSError) as exc:
        print(f"gn: could not start terminal dashboard: {_text(exc, 120)}", file=sys.stderr)
        return 2
    return 0
