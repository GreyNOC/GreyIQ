"""Bounded, passive host inventory for ``gn defender``.

No network probe is sent. Command lines, process environments, packet payloads,
and file contents are deliberately absent from the snapshot. Unavailable sources
are recorded as coverage gaps; an empty list alone never means a clean host.
"""

from __future__ import annotations

import ipaddress
import hashlib
import json
import ntpath
import os
import platform
import posixpath
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
LIMITS = {
    "processes": 4096,
    "connections": 8192,
    "interfaces": 256,
    "routes": 2048,
    "proxies": 32,
    "services": 4096,
    "startup": 1024,
    "packages": 8192,
    "files": 1000,
}
_MAX_COMMAND_OUTPUT = 4_000_000
_COMMAND_TIMEOUT = 20
_MAX_FILE_ROOTS = 16
_MAX_TOTAL_HASH_BYTES = 256 * 1024 * 1024
_MAX_WINDOWS_ADDRESSES = 4096
_MAX_DEFINITION_BYTES = 256 * 1024
_MAX_DEFINITION_TOTAL_BYTES = 16 * 1024 * 1024
_SOCKET_RE = re.compile(r"^socket:\[(\d+)\]$")
_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}
_WINDOWS_TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECV",
    5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2",
    8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
    11: "TIME_WAIT", 12: "DELETE_TCB", 100: "BOUND",
}
_WINDOWS_TCP_NAMES = {
    "closed": "CLOSED", "listen": "LISTEN", "synsent": "SYN_SENT",
    "synreceived": "SYN_RECV", "established": "ESTABLISHED",
    "finwait1": "FIN_WAIT1", "finwait2": "FIN_WAIT2",
    "closewait": "CLOSE_WAIT", "closing": "CLOSING",
    "lastack": "LAST_ACK", "timewait": "TIME_WAIT",
    "deletetcb": "DELETE_TCB", "bound": "BOUND",
}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _clean(value: Any, limit: int = 512) -> str:
    return "".join(c if c.isprintable() else " " for c in str(value or ""))[:limit].strip()


def _integer(value: Any, default: int | None = None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _command(argv: list[str], *, timeout: int = _COMMAND_TIMEOUT) -> tuple[str, str]:
    """Run one fixed local OS inventory command without invoking a shell."""
    try:
        result = subprocess.run(
            argv, capture_output=True, timeout=timeout, check=False,
            text=True, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", _clean(f"{type(exc).__name__}: {exc}", 240)
    if result.returncode != 0:
        return "", _clean(result.stderr or f"exit {result.returncode}", 240)
    if len(result.stdout) > _MAX_COMMAND_OUTPUT:
        return "", "inventory command exceeded output cap"
    return result.stdout, ""


def _rows(value: Any, limit: int) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return []
    return [row for row in value[:limit] if isinstance(row, dict)]


def _limited_rows(value: Any, limit: int) -> tuple[list[dict[str, Any]], bool]:
    """Keep at most ``limit`` rows and detect a fetched N+1 sentinel."""
    fetched = _rows(value, limit + 1)
    return fetched[:limit], len(fetched) > limit


def _truncation_error(label: str, limit: int, truncated: bool) -> str:
    return f"{label} truncated at {limit} records" if truncated else ""


def _digest_command(raw: Any) -> tuple[str, str]:
    """Fingerprint a command in memory without copying it into a snapshot.

    SHA-256 supports change detection, not secrecy against someone who can
    guess a low-entropy command. It must not be described as encrypted data.
    """
    command = str(raw or "")
    if not command:
        return "", "unavailable"
    encoded = command.encode("utf-8", errors="replace")
    if len(encoded) > _MAX_DEFINITION_BYTES:
        return "", "too_large"
    return hashlib.sha256(encoded).hexdigest(), "hashed"


def _digest_service_command(path_name: Any, service_dll: Any) -> tuple[str, str]:
    path = str(path_name or "")
    dll = str(service_dll or "")
    if not path and not dll:
        return "", "unavailable"
    # Domain separators make pairs unambiguous without retaining either raw
    # value. For shared svchost services the ServiceDll is the key target.
    return _digest_command(f"PathName\0{path}\0ServiceDll\0{dll}")


def _windows_command_target(raw: Any) -> str:
    """Return only an unambiguous absolute executable path from a command."""
    command = str(raw or "").strip()
    if not command:
        return ""
    if command.startswith('"'):
        match = re.match(r'^"([^\"]+)"(?:\s|$)', command)
        if not match:
            return ""
        candidate = match.group(1)
    else:
        candidate = command.split(None, 1)[0]
    if not ntpath.isabs(candidate) or "%" in candidate or not candidate.lower().endswith((".exe", ".com", ".bat", ".cmd")):
        return ""
    return ntpath.normpath(candidate)


def _posix_command_target(raw: str) -> str:
    try:
        tokens = shlex.split(raw.strip(), posix=True)
    except ValueError:
        return ""
    if not tokens:
        return ""
    candidate = tokens[0].lstrip("-@+!")  # systemd ExecStart modifiers
    if not candidate.startswith("/") or "%" in candidate:
        return ""
    return posixpath.normpath(candidate)


def _digest_definition_files(paths: list[Path], budget: int) -> tuple[str, str, int, bytes]:
    """Hash bounded config bytes plus resolved paths, returning first file for parsing."""
    if not paths:
        return "", "unavailable", 0, b""
    digest = hashlib.sha256()
    used = 0
    first_content = b""
    for index, path in enumerate(paths):
        try:
            with path.open("rb") as handle:
                before = os.fstat(handle.fileno())
                if before.st_size > _MAX_DEFINITION_BYTES:
                    return "", "too_large", used, b""
                if before.st_size > budget - used:
                    return "", "budget_exceeded", used, b""
                content = handle.read(_MAX_DEFINITION_BYTES + 1)
                after = os.fstat(handle.fileno())
        except OSError:
            return "", "unreadable", used, b""
        if len(content) > _MAX_DEFINITION_BYTES:
            return "", "too_large", used, b""
        used += len(content)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            return "", "changed_during_read", used, b""
        if index == 0:
            first_content = content
        digest.update(str(path.resolve()).encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest(), "hashed", used, first_content


def _powershell_json(expression: str) -> tuple[Any, str]:
    binary = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("pwsh")
    if not binary:
        return None, "PowerShell is unavailable"
    # Every expression is a constant in this module, never operator text.
    script = "$ErrorActionPreference='Stop'; " + expression + " | ConvertTo-Json -Compress -Depth 6"
    output, error = _command([binary, "-NoProfile", "-NonInteractive", "-Command", script])
    if error:
        return None, error
    if not output.strip():
        return [], ""
    try:
        return json.loads(output), ""
    except (ValueError, TypeError):
        return None, "PowerShell returned invalid JSON"


def _windows_tcp_state(value: Any) -> tuple[str, bool]:
    """Normalize Win32 enum names and legacy numeric JSON values.

    PowerShell's ``ConvertTo-Json`` may emit the enum's number even when its
    table output shows the name. New collection calls ``ToString()`` before
    serialization; numeric handling keeps existing exports parseable.
    """
    raw = _clean(value, 40)
    if raw.isdecimal():
        normalized = _WINDOWS_TCP_STATES.get(int(raw))
    else:
        normalized = _WINDOWS_TCP_NAMES.get(raw.replace("_", "").replace("-", "").casefold())
    return (normalized, True) if normalized else (f"UNKNOWN({raw or 'empty'})", False)


def _record(snapshot: dict[str, Any], section: str, rows: list[dict[str, Any]],
            error: str = "", *, partial: bool = False) -> None:
    cap = LIMITS[section]
    snapshot[section] = rows[:cap]
    if error:
        snapshot["errors"].append({"section": section, "error": _clean(error, 240)})
    if len(rows) > cap:
        snapshot["errors"].append({"section": section, "error": f"truncated at {cap} records"})
    snapshot["coverage"][section] = (
        "unavailable" if error and not rows else "partial" if error or partial or len(rows) > cap else "ok"
    )


def _proxy_endpoint(raw: Any, *, kind: str, source: str) -> dict[str, Any] | None:
    """Keep only the endpoint; proxy URLs can carry user names and passwords."""
    value = str(raw or "").strip()
    if not value or len(value) > 4096:
        return None
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host, port = parsed.hostname, parsed.port
    except ValueError:
        return None
    if not host or len(host) > 255:
        return None
    normalized_kind = kind.strip().lower()
    if normalized_kind not in {"http", "https", "ftp", "socks", "socks5", "all", "pac", "system"}:
        normalized_kind = "system"
    scheme = parsed.scheme or (normalized_kind if normalized_kind.startswith("socks") else "http")
    return {"kind": normalized_kind, "host": _clean(host, 255), "port": port,
            "source": source, "scheme": _clean(scheme, 24).lower()}


def _collect_proxies() -> tuple[list[dict[str, Any]], str, bool]:
    """Observe this process's proxy environment and the current Windows user's settings.

    This is local configuration inventory, not a test of reachability or a claim
    that every process uses these settings. PAC scripts are never fetched.
    """
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    truncated = False
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        value = os.environ.get(name) or os.environ.get(name.lower())
        if value:
            row = _proxy_endpoint(value, kind=name.removesuffix("_PROXY").lower(),
                                  source=f"env:{name}")
            if row:
                rows.append(row)
            else:
                errors.append(f"invalid {name} endpoint")
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                def setting(name: str) -> Any:
                    try:
                        return winreg.QueryValueEx(key, name)[0]
                    except FileNotFoundError:
                        return None

                if setting("ProxyEnable"):
                    raw = str(setting("ProxyServer") or "")
                    entries = raw.split(";")
                    truncated = len(entries) > LIMITS["proxies"]
                    for entry in entries[:LIMITS["proxies"]]:
                        if not entry.strip():
                            continue
                        kind, sep, endpoint = entry.partition("=")
                        row = _proxy_endpoint(endpoint if sep else kind,
                                              kind=kind.lower() if sep else "system",
                                              source="windows:user")
                        if row:
                            rows.append(row)
                        else:
                            errors.append("invalid Windows user proxy endpoint")
                pac = setting("AutoConfigURL")
                if pac:
                    row = _proxy_endpoint(pac, kind="pac", source="windows:user")
                    if row:
                        rows.append(row)
                    else:
                        errors.append("invalid Windows user PAC endpoint")
        except (OSError, ValueError) as exc:
            errors.append(f"Windows user proxy settings unavailable: {type(exc).__name__}")
    deduped = list({(row["kind"], row["host"], row["port"], row["source"]): row
                    for row in rows}.values())
    return deduped, "; ".join(errors), truncated or len(deduped) > LIMITS["proxies"]


def _host() -> dict[str, Any]:
    host = {
        "hostname": _clean(socket.gethostname(), 255),
        "platform": sys.platform,
        "release": _clean(platform.release(), 100),
        "machine": _clean(platform.machine(), 100),
    }
    if sys.platform.startswith("linux"):
        try:
            host["boot_id"] = _clean(Path("/proc/sys/kernel/random/boot_id").read_text(), 80)
        except OSError:
            pass
    return host


def _linux_processes() -> tuple[list[dict[str, Any]], str, bool]:
    proc = Path("/proc")
    if not proc.is_dir():
        return [], "/proc is unavailable", False
    rows: list[dict[str, Any]] = []
    denied = 0
    for entry in sorted((p for p in proc.iterdir() if p.name.isdigit()), key=lambda p: int(p.name)):
        if len(rows) >= LIMITS["processes"]:
            return rows, "", True
        try:
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
            end = stat.rfind(")")
            if end < 0:
                continue
            name = stat[stat.find("(") + 1:end]
            fields = stat[end + 2:].split()
            ppid = int(fields[1])
            started = fields[19]
            try:
                exe = os.readlink(entry / "exe")
            except OSError:
                exe = ""
            rows.append({
                "pid": int(entry.name), "ppid": ppid, "name": _clean(name, 255),
                "exe": _clean(exe, 1024), "started": _clean(started, 64),
            })
        except PermissionError:
            denied += 1
        except (FileNotFoundError, ProcessLookupError, IndexError, ValueError, OSError):
            # Process exits during inventory are normal. A missing process is not
            # evidence of a threat and does not invalidate the remaining rows.
            continue
    return rows, f"{denied} process records denied" if denied else "", bool(denied)


def _linux_addr(value: str, family: str) -> tuple[str, int]:
    address, port = value.split(":", 1)
    raw = bytes.fromhex(address)
    if family == "ipv4":
        packed = raw[::-1]
    else:
        packed = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return str(ipaddress.ip_address(packed)), int(port, 16)


def _linux_socket_inodes(processes: list[dict[str, Any]], wanted: set[str]) -> tuple[dict[str, int], int]:
    owners: dict[str, int] = {}
    denied = 0
    if not wanted:
        return owners, denied
    for process in processes:
        pid = process["pid"]
        fd_dir = Path("/proc") / str(pid) / "fd"
        try:
            descriptors = list(fd_dir.iterdir())[:512]
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue
        for fd in descriptors:
            try:
                match = _SOCKET_RE.match(os.readlink(fd))
            except OSError:
                continue
            if match and match.group(1) in wanted:
                owners.setdefault(match.group(1), pid)
        if len(owners) == len(wanted):
            break
    return owners, denied


def _linux_connections(processes: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str, bool]:
    rows: list[dict[str, Any]] = []
    inode_for_row: list[str] = []
    available = 0
    partial = False
    for filename, protocol, family in (
        ("tcp", "tcp", "ipv4"), ("tcp6", "tcp", "ipv6"),
        ("udp", "udp", "ipv4"), ("udp6", "udp", "ipv6"),
    ):
        path = Path("/proc/net") / filename
        try:
            lines = path.read_text(encoding="ascii", errors="replace").splitlines()[1:]
        except OSError:
            partial = True
            continue
        available += 1
        for line in lines:
            if len(rows) >= LIMITS["connections"]:
                partial = True
                break
            cols = line.split()
            if len(cols) < 10:
                continue
            try:
                local_address, local_port = _linux_addr(cols[1], family)
                remote_address, remote_port = _linux_addr(cols[2], family)
            except (ValueError, IndexError):
                continue
            if remote_port == 0 and remote_address in {"0.0.0.0", "::"}:
                remote_address = ""
            rows.append({
                "protocol": protocol, "family": family,
                "local_address": local_address, "local_port": local_port,
                "remote_address": remote_address, "remote_port": remote_port,
                "state": _TCP_STATES.get(cols[3].upper(), cols[3].upper()) if protocol == "tcp" else "BOUND",
                "pid": None,
            })
            inode_for_row.append(cols[9])
    if available == 0:
        return [], "/proc/net socket tables are unavailable", False
    owners, denied = _linux_socket_inodes(processes, set(inode_for_row))
    for row, inode in zip(rows, inode_for_row):
        row["pid"] = owners.get(inode)
    return rows, f"PID attribution denied for {denied} processes" if denied else "", partial or bool(denied)


def _linux_interfaces() -> tuple[list[dict[str, Any]], str, bool]:
    try:
        names = socket.if_nameindex()[:LIMITS["interfaces"]]
    except OSError as exc:
        return [], str(exc), False
    by_name: dict[str, dict[str, Any]] = {}
    for index, name in names:
        sysfs = Path("/sys/class/net") / name
        try:
            mac = _clean((sysfs / "address").read_text(), 32)
        except OSError:
            mac = ""
        try:
            status = _clean((sysfs / "operstate").read_text(), 32)
        except OSError:
            status = "unknown"
        by_name[name] = {"name": name, "index": index, "mac": mac, "status": status, "addresses": []}
    binary = shutil.which("ip")
    if not binary:
        return list(by_name.values()), "ip utility unavailable; interface addresses omitted", True
    output, error = _command([binary, "-j", "address", "show"])
    if error:
        return list(by_name.values()), f"interface addresses: {error}", True
    try:
        for iface in json.loads(output):
            name = _clean(iface.get("ifname"), 255)
            if name not in by_name:
                continue
            addresses = []
            for item in iface.get("addr_info", [])[:64]:
                local = _clean(item.get("local"), 100)
                if local:
                    addresses.append(f"{local}/{_integer(item.get('prefixlen'), 0)}")
            by_name[name]["addresses"] = sorted(set(addresses))
    except (ValueError, TypeError, AttributeError):
        return list(by_name.values()), "ip utility returned invalid JSON", True
    return list(by_name.values()), "", len(names) >= LIMITS["interfaces"]


def _linux_routes() -> tuple[list[dict[str, Any]], str, bool]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        lines = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
        for line in lines:
            cols = line.split()
            if len(cols) < 8 or len(rows) >= LIMITS["routes"]:
                continue
            try:
                dst = ipaddress.IPv4Address(bytes.fromhex(cols[1])[::-1])
                gateway = ipaddress.IPv4Address(bytes.fromhex(cols[2])[::-1])
                mask = ipaddress.IPv4Address(bytes.fromhex(cols[7])[::-1])
                network = ipaddress.IPv4Network(f"{dst}/{mask}", strict=False)
                rows.append({"destination": str(network), "gateway": str(gateway),
                             "interface": _clean(cols[0], 255), "metric": int(cols[6]), "family": "ipv4"})
            except (ValueError, IndexError):
                continue
    except OSError:
        errors.append("/proc/net/route unavailable")
    try:
        lines = Path("/proc/net/ipv6_route").read_text(encoding="ascii").splitlines()
        for line in lines:
            cols = line.split()
            if len(cols) < 10 or len(rows) >= LIMITS["routes"]:
                continue
            try:
                dst = ipaddress.IPv6Address(bytes.fromhex(cols[0]))
                prefix = int(cols[1], 16)
                gateway = ipaddress.IPv6Address(bytes.fromhex(cols[4]))
                network = ipaddress.IPv6Network((dst, prefix), strict=False)
                rows.append({"destination": str(network), "gateway": str(gateway),
                             "interface": _clean(cols[-1], 255), "metric": int(cols[5], 16), "family": "ipv6"})
            except (ValueError, IndexError):
                continue
    except OSError:
        errors.append("/proc/net/ipv6_route unavailable")
    return rows, "; ".join(errors), bool(errors or len(rows) >= LIMITS["routes"])


def _systemd_unit_roots() -> tuple[Path, ...]:
    # Higher-priority local overrides first. These are filesystem observations,
    # not a claim that systemd has resolved every alias or transient unit.
    return tuple(Path(root) for root in (
        "/etc/systemd/system", "/run/systemd/system",
        "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ))


def _systemd_definition_files(name: str, roots: tuple[Path, ...]) -> tuple[list[Path], bool]:
    fragment = None
    discovery_partial = False
    for root in roots:
        candidate = root / name
        try:
            if stat.S_ISREG(candidate.stat().st_mode):
                fragment = candidate
                break
        except FileNotFoundError:
            continue
        except OSError:
            discovery_partial = True
    if fragment is None:
        return [], discovery_partial
    dropins: list[Path] = []
    for root in roots:
        try:
            folder = root / f"{name}.d"
            if stat.S_ISDIR(folder.stat().st_mode):
                dropins.extend(sorted(path for path in folder.iterdir() if path.suffix == ".conf"))
        except FileNotFoundError:
            continue
        except OSError:
            discovery_partial = True
    return [fragment, *dropins], discovery_partial


def _definition_exec(content: bytes, *, desktop: bool) -> str:
    key = "Exec=" if desktop else "ExecStart="
    for line in content.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if desktop and stripped.startswith("[Desktop Action"):
            break
        if stripped.startswith(key):
            return _posix_command_target(stripped[len(key):])
    return ""


def _linux_services(unit_roots: tuple[Path, ...] | None = None) -> tuple[list[dict[str, Any]], str, bool]:
    binary = shutil.which("systemctl")
    if not binary:
        return [], "systemctl unavailable", False
    output, error = _command([binary, "list-unit-files", "--type=service", "--all", "--no-legend", "--no-pager"])
    if error:
        return [], error, False
    roots = unit_roots if unit_roots is not None else _systemd_unit_roots()
    rows = []
    budget = _MAX_DEFINITION_TOTAL_BYTES
    digest_errors = 0
    for line in output.splitlines():
        cols = line.split()
        if len(cols) >= 2 and cols[0].endswith(".service"):
            name = _clean(cols[0], 255)
            files, discovery_partial = _systemd_definition_files(name, roots)
            digest, status, used, fragment = _digest_definition_files(files, budget)
            budget -= used
            if discovery_partial:
                digest, status, fragment = "", "discovery_partial", b""
            # The unit list can be complete while its executable/config
            # definition is not observable from these bounded local roots.
            digest_errors += status != "hashed"
            rows.append({
                "name": name, "status": "unknown", "start_type": _clean(cols[1], 40),
                "definition_sha256": digest, "definition_status": status,
                "config_path": str(files[0]) if files else "",
                "target_path": _definition_exec(fragment, desktop=False) if status == "hashed" and len(files) == 1 else "",
            })
        if len(rows) >= LIMITS["services"]:
            return rows, f"services truncated at {LIMITS['services']} records", True
    error = f"{digest_errors} service definition(s) unavailable or over limits" if digest_errors else ""
    return rows, error, bool(digest_errors)


def _linux_startup(roots: tuple[Path, ...] | None = None) -> tuple[list[dict[str, Any]], str, bool]:
    rows: list[dict[str, Any]] = []
    budget = _MAX_DEFINITION_TOTAL_BYTES
    digest_errors = 0
    search_roots = roots if roots is not None else (Path("/etc/xdg/autostart"), Path.home() / ".config" / "autostart")
    for root in search_roots:
        try:
            root.stat()
        except FileNotFoundError:
            # An optional autostart directory may legitimately not exist.
            continue
        except OSError:
            digest_errors += 1
            continue
        try:
            files = sorted(path for path in root.iterdir() if path.suffix == ".desktop")
        except OSError:
            digest_errors += 1
            continue
        for path in files:
            digest, status, used, content = _digest_definition_files([path], budget)
            budget -= used
            digest_errors += status in {"too_large", "unreadable", "changed_during_read", "budget_exceeded"}
            rows.append({
                "name": _clean(path.stem, 255), "location": str(root),
                "definition_sha256": digest, "definition_status": status,
                "config_path": str(path),
                "target_path": _definition_exec(content, desktop=True) if status == "hashed" else "",
            })
            if len(rows) >= LIMITS["startup"]:
                return rows, f"startup entries truncated at {LIMITS['startup']} records", True
    error = f"{digest_errors} startup definition(s) or root(s) unavailable or over limits" if digest_errors else ""
    return rows, error, bool(digest_errors)


def _linux_packages() -> tuple[list[dict[str, Any]], str, bool]:
    if binary := shutil.which("dpkg-query"):
        output, error = _command([binary, "-W", "-f=${Package}\t${Version}\n"])
        delimiter = "\t"
    elif binary := shutil.which("rpm"):
        output, error = _command([binary, "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
        delimiter = "\t"
    elif binary := shutil.which("pacman"):
        output, error = _command([binary, "-Q"])
        delimiter = " "
    else:
        return [], "supported package manager unavailable", False
    if error:
        return [], error, False
    rows = []
    for line in output.splitlines():
        name, sep, version = line.partition(delimiter)
        if sep and name.strip():
            rows.append({"name": _clean(name, 255), "version": _clean(version, 120), "publisher": ""})
        if len(rows) >= LIMITS["packages"]:
            return rows, "", True
    return rows, "", False


def _collect_linux(snapshot: dict[str, Any]) -> None:
    processes, error, partial = _linux_processes()
    _record(snapshot, "processes", processes, error, partial=partial)
    for section, collector in (
        ("connections", lambda: _linux_connections(processes)),
        ("interfaces", _linux_interfaces),
        ("routes", _linux_routes),
        ("services", _linux_services),
        ("startup", _linux_startup),
        ("packages", _linux_packages),
    ):
        rows, error, partial = collector()
        _record(snapshot, section, rows, error, partial=partial)


def _collect_windows(snapshot: dict[str, Any]) -> None:
    process_raw, error = _powershell_json(
        f"@(Get-CimInstance Win32_Process | Select-Object -First {LIMITS['processes'] + 1} "
        "ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate)"
    )
    process_rows, process_truncated = _limited_rows(process_raw, LIMITS["processes"])
    processes = [
        {"pid": _integer(r.get("ProcessId")), "ppid": _integer(r.get("ParentProcessId")),
         "name": _clean(r.get("Name"), 255), "exe": _clean(r.get("ExecutablePath"), 1024),
         "started": _clean(r.get("CreationDate"), 100)}
        for r in process_rows if _integer(r.get("ProcessId")) is not None
    ]
    process_error = "; ".join(x for x in (
        error, _truncation_error("processes", LIMITS["processes"], process_truncated)) if x)
    _record(snapshot, "processes", processes, process_error, partial=process_truncated)

    tcp_raw, tcp_error = _powershell_json(
        f"@(Get-NetTCPConnection | Select-Object -First {LIMITS['connections'] + 1} "
        "LocalAddress,LocalPort,RemoteAddress,RemotePort,"
        "@{Name='State';Expression={$_.State.ToString()}},OwningProcess)"
    )
    udp_raw, udp_error = _powershell_json(
        f"@(Get-NetUDPEndpoint | Select-Object -First {LIMITS['connections'] + 1} "
        "LocalAddress,LocalPort,OwningProcess)"
    )
    tcp_rows, tcp_truncated = _limited_rows(tcp_raw, LIMITS["connections"])
    udp_rows, udp_truncated = _limited_rows(udp_raw, LIMITS["connections"])
    cap = LIMITS["connections"]
    # Sample both protocols when their combined tables exceed the cap. A
    # TCP-first slice could consume the entire budget and silently hide UDP.
    tcp_take = min(len(tcp_rows), cap // 2)
    udp_take = min(len(udp_rows), cap // 2)
    remaining = cap - tcp_take - udp_take
    extra_tcp = min(remaining, len(tcp_rows) - tcp_take)
    tcp_take += extra_tcp
    remaining -= extra_tcp
    udp_take += min(remaining, len(udp_rows) - udp_take)
    combined_truncated = tcp_truncated or udp_truncated or len(tcp_rows) + len(udp_rows) > cap
    connections = []
    unknown_states: set[str] = set()
    for row in tcp_rows[:tcp_take]:
        local = _clean(row.get("LocalAddress"), 100)
        state, known = _windows_tcp_state(row.get("State"))
        if not known:
            unknown_states.add(state)
        connections.append({
            "protocol": "tcp", "family": "ipv6" if ":" in local else "ipv4",
            "local_address": local, "local_port": _integer(row.get("LocalPort"), 0),
            "remote_address": _clean(row.get("RemoteAddress"), 100),
            "remote_port": _integer(row.get("RemotePort"), 0),
            "state": state,
            "pid": _integer(row.get("OwningProcess")),
        })
    for row in udp_rows[:udp_take]:
        local = _clean(row.get("LocalAddress"), 100)
        connections.append({
            "protocol": "udp", "family": "ipv6" if ":" in local else "ipv4",
            "local_address": local, "local_port": _integer(row.get("LocalPort"), 0),
            "remote_address": "", "remote_port": 0, "state": "BOUND",
            "pid": _integer(row.get("OwningProcess")),
        })
    state_error = f"unknown TCP state value(s): {', '.join(sorted(unknown_states)[:10])}" if unknown_states else ""
    limit_error = _truncation_error("TCP/UDP connections", cap, combined_truncated)
    connection_error = "; ".join(x for x in (tcp_error, udp_error, state_error, limit_error) if x)
    _record(snapshot, "connections", connections, connection_error,
            partial=bool(connection_error or combined_truncated))

    adapter_raw, adapter_error = _powershell_json(
        f"@(Get-NetAdapter | Select-Object -First {LIMITS['interfaces'] + 1} "
        "Name,InterfaceIndex,MacAddress,Status)"
    )
    address_raw, address_error = _powershell_json(
        f"@(Get-NetIPAddress | Select-Object -First {_MAX_WINDOWS_ADDRESSES + 1} "
        "InterfaceIndex,IPAddress,PrefixLength)"
    )
    adapter_rows, adapter_truncated = _limited_rows(adapter_raw, LIMITS["interfaces"])
    address_rows, address_truncated = _limited_rows(address_raw, _MAX_WINDOWS_ADDRESSES)
    interfaces = {}
    for row in adapter_rows:
        index = _integer(row.get("InterfaceIndex"))
        if index is not None:
            interfaces[index] = {
                "name": _clean(row.get("Name"), 255), "index": index,
                "mac": _clean(row.get("MacAddress"), 32),
                "status": _clean(row.get("Status"), 40), "addresses": [],
            }
    for row in address_rows:
        index = _integer(row.get("InterfaceIndex"))
        if index in interfaces:
            address = _clean(row.get("IPAddress"), 100)
            if address:
                interfaces[index]["addresses"].append(f"{address}/{_integer(row.get('PrefixLength'), 0)}")
    for iface in interfaces.values():
        iface["addresses"] = sorted(set(iface["addresses"]))
    interface_error = "; ".join(x for x in (
        adapter_error, address_error,
        _truncation_error("network adapters", LIMITS["interfaces"], adapter_truncated),
        _truncation_error("interface addresses", _MAX_WINDOWS_ADDRESSES, address_truncated),
    ) if x)
    _record(snapshot, "interfaces", list(interfaces.values()), interface_error,
            partial=bool(interface_error))

    route_raw, error = _powershell_json(
        f"@(Get-NetRoute | Select-Object -First {LIMITS['routes'] + 1} "
        "DestinationPrefix,NextHop,InterfaceIndex,RouteMetric)"
    )
    route_rows, route_truncated = _limited_rows(route_raw, LIMITS["routes"])
    routes = []
    for row in route_rows:
        destination = _clean(row.get("DestinationPrefix"), 100)
        routes.append({"destination": destination, "gateway": _clean(row.get("NextHop"), 100),
                       "interface": _integer(row.get("InterfaceIndex")),
                       "metric": _integer(row.get("RouteMetric")),
                       "family": "ipv6" if ":" in destination else "ipv4"})
    route_error = "; ".join(x for x in (
        error, _truncation_error("routes", LIMITS["routes"], route_truncated)) if x)
    _record(snapshot, "routes", routes, route_error, partial=route_truncated)

    service_raw, error = _powershell_json(
        f"@(Get-CimInstance Win32_Service | Select-Object -First {LIMITS['services'] + 1} "
        "Name,State,StartMode,PathName,"
        "@{Name='ServiceDll';Expression={(Get-ItemProperty -LiteralPath "
        "('Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\' + $_.Name + "
        "'\\Parameters') -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll}})"
    )
    service_rows, service_truncated = _limited_rows(service_raw, LIMITS["services"])
    services = []
    service_digest_errors = 0
    for row in service_rows:
        digest, digest_status = _digest_service_command(row.get("PathName"), row.get("ServiceDll"))
        service_digest_errors += digest_status == "too_large"
        services.append({
            "name": _clean(row.get("Name"), 255),
            "status": _clean(row.get("State"), 40),
            "start_type": _clean(row.get("StartMode"), 40),
            "definition_sha256": digest, "definition_status": digest_status,
            "target_path": _windows_command_target(row.get("PathName")) if digest_status == "hashed" else "",
        })
    service_error = "; ".join(x for x in (
        error, _truncation_error("services", LIMITS["services"], service_truncated),
        f"{service_digest_errors} service definition(s) over size limit" if service_digest_errors else "",
    ) if x)
    _record(snapshot, "services", services, service_error,
            partial=service_truncated or bool(service_digest_errors))

    startup_raw, error = _powershell_json(
        f"@(Get-CimInstance Win32_StartupCommand | Select-Object -First {LIMITS['startup'] + 1} "
        "Name,Location,Command)"
    )
    startup_rows, startup_truncated = _limited_rows(startup_raw, LIMITS["startup"])
    startup = []
    startup_digest_errors = 0
    for row in startup_rows:
        digest, digest_status = _digest_command(row.get("Command"))
        startup_digest_errors += digest_status == "too_large"
        startup.append({
            "name": _clean(row.get("Name"), 255),
            "location": _clean(row.get("Location"), 512),
            "definition_sha256": digest, "definition_status": digest_status,
            "target_path": _windows_command_target(row.get("Command")) if digest_status == "hashed" else "",
        })
    startup_error = "; ".join(x for x in (
        error, _truncation_error("startup entries", LIMITS["startup"], startup_truncated),
        f"{startup_digest_errors} startup definition(s) over size limit" if startup_digest_errors else "",
    ) if x)
    _record(snapshot, "startup", startup, startup_error,
            partial=startup_truncated or bool(startup_digest_errors))

    package_raw, error = _powershell_json(
        "@((Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
        f"-ErrorAction SilentlyContinue) | Where-Object DisplayName | Select-Object -First {LIMITS['packages'] + 1} "
        "DisplayName,DisplayVersion,Publisher)"
    )
    package_rows, package_truncated = _limited_rows(package_raw, LIMITS["packages"])
    packages = [
        {"name": _clean(r.get("DisplayName"), 255), "version": _clean(r.get("DisplayVersion"), 120),
         "publisher": _clean(r.get("Publisher"), 255)}
        for r in package_rows
    ]
    package_error = "; ".join(x for x in (
        error, _truncation_error("packages", LIMITS["packages"], package_truncated)) if x)
    _record(snapshot, "packages", packages, package_error, partial=package_truncated)


def _collect_other(snapshot: dict[str, Any]) -> None:
    # The CLI remains honest on a platform with no collector: callers can still
    # inspect the host header and the explicit coverage gaps.
    for section in LIMITS:
        if section in ("files", "proxies"):
            continue
        _record(snapshot, section, [], f"{sys.platform} collector unavailable")


def _file_roots(paths: tuple[str, ...] | list[str]) -> list[str]:
    roots = []
    for raw in paths[:_MAX_FILE_ROOTS]:
        normalized = os.path.abspath(os.path.expanduser(str(raw)))
        if normalized not in roots:
            roots.append(normalized)
    return roots


def _hash_file(path: Path, *, max_file_bytes: int, bytes_left: int) -> tuple[dict[str, Any], int]:
    """Hash one regular file, refusing symlinks and records that exceed budgets."""
    row: dict[str, Any] = {"path": str(path), "size": None, "mtime_ns": None,
                           "sha256": "", "status": "unreadable"}
    try:
        info = path.lstat()
        if path.is_symlink():
            row["status"] = "skipped_symlink"
            return row, 0
        if not path.is_file():
            row["status"] = "skipped_special"
            return row, 0
        row["size"], row["mtime_ns"] = info.st_size, info.st_mtime_ns
        if info.st_size > max_file_bytes:
            row["status"] = "skipped_size"
            return row, 0
        if info.st_size > bytes_left:
            row["status"] = "skipped_budget"
            return row, 0
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as handle:
            before = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                row["status"] = "changed_during_open"
                return row, 0
            digest = hashlib.sha256()
            read = 0
            while chunk := handle.read(min(64 * 1024, max_file_bytes + 1 - read)):
                read += len(chunk)
                if read > max_file_bytes or read > bytes_left:
                    row["status"] = "skipped_budget"
                    return row, read
                digest.update(chunk)
            after = os.fstat(handle.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            row["status"] = "changed_during_read"
            return row, read
        row["sha256"] = digest.hexdigest()
        row["status"] = "hashed"
        return row, read
    except OSError:
        return row, 0


def _hash_process_executables(snapshot: dict[str, Any], *, max_hashes: int,
                              max_file_bytes: int, max_total_bytes: int) -> None:
    """Opt-in, bounded on-disk hashes for observed process executable paths.

    A hash here describes the file currently at the reported path. It is not
    proof that the in-memory image of a process is identical, especially on a
    system where executable files can be replaced while running.
    """
    max_hashes = max(1, min(1024, int(max_hashes)))
    max_file_bytes = max(1, min(128 * 1024 * 1024, int(max_file_bytes)))
    remaining = max(1, min(1024 * 1024 * 1024, int(max_total_bytes)))
    cache: dict[str, tuple[str, str]] = {}
    incomplete = 0
    for process in snapshot.get("processes", []):
        exe = str(process.get("exe") or "")
        process["sha256"] = ""
        process["hash_source"] = "executable_path_file"
        if not exe:
            process["hash_status"] = "path_unavailable"
            incomplete += 1
            continue
        cache_key = os.path.normcase(exe)
        if cache_key not in cache:
            if len(cache) >= max_hashes:
                cache[cache_key] = ("", "skipped_limit")
            else:
                file_row, consumed = _hash_file(Path(exe), max_file_bytes=max_file_bytes,
                                                bytes_left=remaining)
                remaining = max(0, remaining - consumed)
                cache[cache_key] = (str(file_row.get("sha256") or ""),
                                    str(file_row.get("status") or "unreadable"))
        process["sha256"], process["hash_status"] = cache[cache_key]
        if process["hash_status"] != "hashed":
            incomplete += 1
    snapshot["coverage"]["process_binaries"] = "partial" if incomplete else "ok"
    if incomplete:
        snapshot["errors"].append({
            "section": "process_binaries",
            "error": f"{incomplete} process executable hash(es) unavailable or over limits",
        })


def _collect_files(snapshot: dict[str, Any], roots: list[str], *, max_files: int,
                   max_file_bytes: int, roots_truncated: bool = False) -> None:
    if not roots:
        snapshot["coverage"]["files"] = "not_requested"
        return
    max_files = max(1, min(10_000, int(max_files)))
    max_file_bytes = max(1, min(100 * 1024 * 1024, int(max_file_bytes)))
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    partial = roots_truncated
    limit_hit = False
    remaining = _MAX_TOTAL_HASH_BYTES
    for root_text in roots:
        root = Path(root_text)
        if len(rows) >= max_files:
            partial = True
            limit_hit = True
            break
        if root.is_symlink():
            errors.append(f"symlink root skipped: {root}")
            partial = True
            continue
        if not root.exists():
            errors.append(f"root unavailable: {root}")
            partial = True
            continue
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            candidates = None
        else:
            errors.append(f"non-file root skipped: {root}")
            partial = True
            continue
        if candidates is not None:
            paths_iter = iter(candidates)
        else:
            def walk() -> Any:
                nonlocal partial
                def onerror(exc: OSError) -> None:
                    nonlocal partial
                    partial = True
                    errors.append(f"directory unavailable: {exc.filename or root}")
                for current, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
                    retained = []
                    for directory in sorted(dirs):
                        if (Path(current) / directory).is_symlink():
                            partial = True
                            if len(errors) < 20:
                                errors.append(f"symlink directory skipped: {Path(current) / directory}")
                        else:
                            retained.append(directory)
                    dirs[:] = retained
                    for name in sorted(files):
                        yield Path(current) / name
            paths_iter = walk()
        for path in paths_iter:
            if len(rows) >= max_files:
                partial = True
                limit_hit = True
                break
            row, read = _hash_file(path, max_file_bytes=max_file_bytes, bytes_left=remaining)
            remaining = max(0, remaining - read)
            rows.append(row)
            if row["status"] != "hashed":
                partial = True
    snapshot["files"] = sorted(rows, key=lambda row: row["path"])
    snapshot["coverage"]["files"] = "partial" if partial or errors else "ok"
    snapshot["errors"].extend({"section": "files", "error": _clean(error, 240)} for error in errors[:20])
    if limit_hit:
        snapshot["errors"].append({"section": "files", "error": f"file limit reached ({max_files})"})


def collect_inventory(paths: tuple[str, ...] | list[str] = (), *, max_files: int = 1000,
                      max_file_bytes: int = 10 * 1024 * 1024,
                      hash_processes: bool = False, max_process_hashes: int = 256,
                      max_process_file_bytes: int = 32 * 1024 * 1024,
                      max_process_total_bytes: int = 256 * 1024 * 1024) -> dict[str, Any]:
    """Return a read-only local host snapshot with per-section coverage.

    This is an observation, never an assertion that the host is safe. A baseline
    is saved separately only when the operator explicitly requests it.
    """
    snapshot: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "collected_at": _now(), "host": _host(),
        **{section: [] for section in LIMITS}, "coverage": {}, "errors": [],
        "file_roots": _file_roots(paths),
    }
    if sys.platform.startswith("linux"):
        _collect_linux(snapshot)
    elif os.name == "nt":
        _collect_windows(snapshot)
    else:
        _collect_other(snapshot)
    proxies, proxy_error, proxy_partial = _collect_proxies()
    _record(snapshot, "proxies", proxies, proxy_error, partial=proxy_partial)
    if hash_processes:
        _hash_process_executables(snapshot, max_hashes=max_process_hashes,
                                  max_file_bytes=max_process_file_bytes,
                                  max_total_bytes=max_process_total_bytes)
    else:
        snapshot["coverage"]["process_binaries"] = "not_requested"
    _collect_files(snapshot, snapshot["file_roots"], max_files=max_files,
                   max_file_bytes=max_file_bytes, roots_truncated=len(paths) > _MAX_FILE_ROOTS)
    for section, rows in ((name, snapshot[name]) for name in LIMITS):
        rows.sort(key=lambda row: json.dumps(row, sort_keys=True, default=str))
        snapshot["coverage"].setdefault(section, "unavailable")
    return snapshot
