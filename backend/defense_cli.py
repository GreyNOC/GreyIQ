"""The ``gn defense`` commands for the local log monitor.

Registration is deliberately stdlib-only. Database drivers and the monitor are
loaded only when a command runs, so ordinary ``gn`` commands still boot on a
bare Python installation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote, urlsplit


_SOURCE_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_SECRET_FILE = 16 * 1024
_MAX_API_RESPONSE = 2 * 1024 * 1024


class _CliFailure(Exception):
    """An operator-facing error whose text contains no connection secret."""


class _ApiTokenRejected(_CliFailure):
    pass


class _LocalBusy(_CliFailure):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> None:
        return None


_HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def register_cli(sub: argparse._SubParsersAction) -> None:
    defense = sub.add_parser("defense", help="monitor authorized log files and databases")
    actions = defense.add_subparsers(dest="defense_action", metavar="<action>")

    add = actions.add_parser("add", help="add a file, SQL, MongoDB, or Elasticsearch log source")
    add.add_argument("--kind", required=True,
                     choices=("file", "database", "mongodb", "elasticsearch"))
    add.add_argument("--name", required=True, help="operator label for this source")
    add.add_argument("--path", help="log file path (file sources)")
    urls = add.add_mutually_exclusive_group()
    urls.add_argument("--url", help="database/cluster URL without embedded credentials")
    urls.add_argument("--url-env", metavar="ENV", help="read database/cluster URL from an environment variable")
    urls.add_argument("--url-file", metavar="FILE", help="read database/cluster URL from a private file")
    add.add_argument("--table", help="SQL table, MongoDB collection, or Elasticsearch index")
    add.add_argument("--cursor", help="unique increasing cursor column or field")
    add.add_argument("--message", help="message column or field")
    add.add_argument("--severity", help="optional severity column or field")
    keys = add.add_mutually_exclusive_group()
    keys.add_argument("--api-key-env", metavar="ENV", help="read Elasticsearch API key from an environment variable")
    keys.add_argument("--api-key-file", metavar="FILE", help="read Elasticsearch API key from a private file")
    add.add_argument("--backfill", action="store_true", help="process existing entries in bounded batches")
    add.add_argument("-y", "--authorize", action="store_true",
                     help="confirm you are authorized to read this log source (required)")
    add.add_argument("--json", action="store_true", help="print one JSON result")
    add.set_defaults(func=_command)

    status = actions.add_parser("status", help="list sources and recent alerts")
    status.add_argument("--json", action="store_true", help="print one JSON result")
    status.set_defaults(func=_command)

    watch = actions.add_parser("watch", help="monitor continuously in this terminal")
    watch.add_argument("--once", action="store_true", help="poll once and exit (headless mode)")
    watch.add_argument("--interval", type=float, default=2.0, metavar="SEC",
                       help="seconds between polls, 0.5-3600 (default: 2)")
    watch.add_argument("--json", action="store_true",
                       help="one JSON object with --once; newline-delimited JSON while watching")
    watch.set_defaults(func=_command)

    for action in ("start", "stop", "remove"):
        parser = actions.add_parser(action, help=f"{action} a saved log source")
        parser.add_argument("source_id", metavar="SOURCE_ID")
        parser.add_argument("--json", action="store_true", help="print one JSON result")
        parser.set_defaults(func=_command)

    defense.set_defaults(func=_command)


def _fail(args: argparse.Namespace, message: str) -> int:
    if getattr(args, "json", False):
        print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
    else:
        print(f"gn: {message}", file=sys.stderr)
    return 2


def _plain(value: Any, limit: int = 300) -> str:
    """Terminal-safe text for names, paths, and attacker-influenced log lines."""
    text = str(value or "")[:limit]
    return " ".join("".join(" " if ord(char) < 32 or ord(char) == 127 else char
                            for char in text).split())[:limit]


def _secret_env(name: str, label: str) -> str:
    if not _ENV_NAME.fullmatch(name):
        raise _CliFailure(f"{label} environment variable name is invalid.")
    value = os.getenv(name, "").strip()
    if not value:
        raise _CliFailure(f"{label} environment variable is empty or unset.")
    return value


def _secret_file(filename: str, label: str) -> str:
    try:
        with Path(filename).expanduser().open("rb") as handle:
            content = handle.read(_MAX_SECRET_FILE + 1)
    except OSError as exc:
        raise _CliFailure(f"Could not read {label} file ({type(exc).__name__}).") from None
    if len(content) > _MAX_SECRET_FILE:
        raise _CliFailure(f"{label} file is too large.")
    try:
        value = content.decode("utf-8").strip()
    except UnicodeError:
        raise _CliFailure(f"{label} file must be UTF-8 text.") from None
    if not value:
        raise _CliFailure(f"{label} file is empty.")
    return value


def _source_config(args: argparse.Namespace) -> dict[str, Any]:
    config: dict[str, Any] = {
        "authorized": True, "kind": args.kind, "name": args.name,
        "backfill": bool(args.backfill),
    }
    if args.kind == "file":
        if not args.path:
            raise _CliFailure("File sources require --path.")
        if args.url or args.url_env or args.url_file:
            raise _CliFailure("File sources use --path, not a database URL.")
        if args.table or args.cursor or args.message or args.severity or args.api_key_env or args.api_key_file:
            raise _CliFailure("File sources do not use database fields or API keys.")
        config["path"] = args.path
        return config
    if args.path:
        raise _CliFailure("Database and index sources use a URL, not --path.")
    if args.url_env:
        url = _secret_env(args.url_env, "URL")
    elif args.url_file:
        url = _secret_file(args.url_file, "URL")
    else:
        url = str(args.url or "").strip()
    if not url:
        raise _CliFailure("This source requires --url, --url-env, or --url-file.")
    if args.url:
        try:
            has_userinfo = "@" in urlsplit(url).netloc
        except ValueError:
            raise _CliFailure("URL is invalid; use --url-env or --url-file for a credential-bearing URL.") from None
        if has_userinfo:
            raise _CliFailure("Do not put URL credentials on the command line; use --url-env or --url-file.")
    config.update({
        "url": url, "table": str(args.table or ""),
        "cursor_column": str(args.cursor or ""),
        "message_column": str(args.message or ""),
        "severity_column": str(args.severity or ""),
    })
    if args.api_key_env or args.api_key_file:
        if args.kind != "elasticsearch":
            raise _CliFailure("API key options are for Elasticsearch sources only.")
        config["api_key"] = (_secret_env(args.api_key_env, "API key") if args.api_key_env
                             else _secret_file(args.api_key_file, "API key"))
    return config


def _ports() -> Iterator[int]:
    seen: set[int] = set()
    for value in (os.getenv("GREYIQ_PORT"), os.getenv("PORT")):
        if str(value or "").isdigit():
            port = int(value)
            if 1 <= port <= 65535 and port not in seen:
                seen.add(port)
                yield port
    for port in range(8766, 8846):
        if port not in seen:
            yield port


class _DefenseApi:
    def __init__(self, port: int, token: str) -> None:
        self.port = port
        self.token = token

    def request(self, method: str, path: str,
                payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers={"X-GreyIQ-Token": self.token, "Accept": "application/json"},
        )
        if payload is not None:
            request.add_header("Content-Type", "application/json")
        _apply_access_key(request)
        try:
            with _HTTP.open(request, timeout=5.0) as response:
                raw = response.read(_MAX_API_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                raise _ApiTokenRejected("GreyIQ rejected this runtime's session token.") from None
            if exc.code == 401:
                raise _CliFailure("GreyIQ requires GREYIQ_ACCESS_KEY for this session.") from None
            if exc.code in {409, 422}:
                try:
                    detail = json.loads(exc.read(4096).decode("utf-8", "replace"))
                    message = (detail.get("detail") or detail.get("error")) if isinstance(detail, dict) else ""
                except ValueError:
                    message = ""
                if isinstance(message, str) and message:
                    # Source validation text comes from the backend, but never
                    # echo a supplied URL or API key if a future validator does.
                    for secret in ((payload or {}).get("url"), (payload or {}).get("api_key")):
                        if secret:
                            message = message.replace(str(secret), "[REDACTED]")
                    if exc.code == 409:
                        raise _CliFailure(f"Defense monitor is busy: {message[:250]}") from None
                    raise _CliFailure(message[:300]) from None
                if exc.code == 409:
                    raise _CliFailure("Defense monitor is busy in another process; retry after it stops.") from None
            raise _CliFailure(f"GreyIQ defense API returned HTTP {exc.code}.") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise _CliFailure("Lost the GreyIQ API connection; no local state was changed.") from None
        if len(raw) > _MAX_API_RESPONSE:
            raise _CliFailure("GreyIQ defense API response is too large.")
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise _CliFailure("GreyIQ defense API returned invalid JSON.") from None
        if not isinstance(result, dict):
            raise _CliFailure("GreyIQ defense API returned an invalid result.")
        return result


def _api_for_runtime(runtime: Path) -> _DefenseApi | None:
    """Attach only after the listener proves possession of a private peer key."""
    token_path = runtime / "session.token"
    identity_path = runtime / "defense.identity"
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    try:
        identity_secret = identity_path.read_text(encoding="utf-8").strip()
    except OSError:
        identity_secret = ""
    if not token or not identity_secret:
        if token_path.exists() or identity_path.exists():
            raise _CliFailure(
                "This runtime is missing an API session token or private identity secret. "
                "Restart GreyIQ or select the correct runtime before changing local state."
            )
        return None
    # Windows can take about 100 ms to refuse each closed loopback port. Probe
    # ports concurrently, with no credentials, then run GreyIQ's full identity
    # checks only on listeners that accepted a TCP connection.
    from concurrent.futures import ThreadPoolExecutor
    ports = list(_ports())
    with ThreadPoolExecutor(max_workers=16) as executor:
        open_ports = [port for port, listening in zip(ports, executor.map(_port_open, ports)) if listening]
    unverified_backend = False
    proven_backend = False
    for port in open_ports:
        identity = _identity_probe(port, identity_secret)
        if identity != "verified":
            unverified_backend |= identity == "unverified"
            continue
        proven_backend = True
        client = _DefenseApi(port, token)
        try:
            client.request("GET", "/api/defense/status")
        except _ApiTokenRejected:
            continue
        return client
    if proven_backend:
        raise _CliFailure(
            "A GreyIQ API proved this runtime's private identity, but rejected its session token. "
            "Stop the API or select its runtime with GREYIQ_RUNTIME_DIR before changing local state."
        )
    if unverified_backend and token_path.exists():
        raise _CliFailure(
            "A local API could not prove this runtime's private identity. "
            "Stop the API or select its runtime with GREYIQ_RUNTIME_DIR before changing local state."
        )
    return None


def _port_open(port: int) -> bool:
    """Cheap, credential-free prefilter before HTTP identity probes."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
            return True
    except OSError:
        return False


def _apply_access_key(request: urllib.request.Request) -> None:
    access_key = os.getenv("GREYIQ_ACCESS_KEY", "")
    if access_key:
        encoded = base64.b64encode(f"gn:{access_key}".encode("utf-8")).decode("ascii")
        request.add_header("Authorization", "Basic " + encoded)


def _identity_probe(port: int, identity_secret: str) -> str:
    """Verify a nonce proof before sending either the token or the Basic key.

    The server signs its actual ASGI socket address, not a supplied Host header.
    A listener on another scanned port cannot relay a proof from the real API.
    """
    if not identity_secret:
        return "other"
    nonce = secrets.token_hex(32)
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/internal/defense-identity?nonce={nonce}",
        method="GET",
    )
    try:
        with _HTTP.open(request, timeout=1.0) as response:
            raw = response.read(1025)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        return "other"
    if len(raw) > 1024:
        return "other"
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        return "other"
    if not isinstance(result, dict) or result.get("version") != 1:
        return "other"
    proof = result.get("proof")
    if not isinstance(proof, str) or not re.fullmatch(r"[0-9a-f]{64}", proof):
        return "unverified"
    message = f"GreyIQ defense identity v1\n127.0.0.1:{port}\n{nonce}".encode("ascii")
    expected = hmac.new(identity_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return "verified" if hmac.compare_digest(proof, expected) else "unverified"


@contextmanager
def _local_monitor(runtime: Path, *, wait_seconds: float = 2.0) -> Iterator[Any]:
    from defense_log_monitor import DefenseLogMonitor, defense_credentials_path
    from defense_monitor_lease import MonitorLease, MonitorLeaseBusy

    lease = MonitorLease(runtime)
    deadline = time.monotonic() + max(0.0, wait_seconds)
    while True:
        try:
            lease.acquire()
            break
        except MonitorLeaseBusy:
            if time.monotonic() >= deadline:
                raise _LocalBusy("Another defense monitor is using this runtime. Use the running GreyIQ API or stop that monitor.") from None
            time.sleep(0.05)
    try:
        monitor = DefenseLogMonitor(
            runtime, autostart=False, credentials_path=defense_credentials_path(runtime)
        )
        try:
            yield monitor
        finally:
            monitor.close()
    finally:
        lease.release()


@contextmanager
def _local_status_monitor(runtime: Path) -> Iterator[Any]:
    """Read atomic saved state without taking the collector's writer lease."""
    from defense_log_monitor import DefenseLogMonitor, defense_credentials_path

    monitor = DefenseLogMonitor(
        runtime, autostart=False, credentials_path=defense_credentials_path(runtime)
    )
    try:
        yield monitor
    finally:
        monitor.close()


def _headless_watch_poll(runtime: Path) -> dict[str, Any]:
    """One bounded poll; let other CLI commands edit sources between passes."""
    api = _api_for_runtime(runtime)
    if api is not None:
        return api.request("GET", "/api/defense/status")
    try:
        with _local_monitor(runtime, wait_seconds=0.0) as monitor:
            monitor.poll_once()
            return monitor.status()
    except _LocalBusy:
        # A desktop API may have acquired the lease just after our identity
        # check. Try its authenticated API before showing saved state.
        api = _api_for_runtime(runtime)
        if api is not None:
            return api.request("GET", "/api/defense/status")
        with _local_status_monitor(runtime) as monitor:
            snapshot = monitor.status()
        prior = str(snapshot.get("warning") or "").strip()
        snapshot["warning"] = (prior + " " if prior else "") + "Another collector is active; showing saved state."
        return snapshot


def _source_id(args: argparse.Namespace) -> str:
    if not _SOURCE_ID.fullmatch(str(args.source_id or "")):
        raise _CliFailure("Source ID is invalid.")
    return args.source_id


def _render_status(snapshot: dict[str, Any]) -> None:
    sources = snapshot.get("sources") or []
    alerts = snapshot.get("alerts") or []
    print(f"Defense log monitoring: {len(sources)} source(s), {len(alerts)} recent alert(s)")
    for source in sources:
        if not isinstance(source, dict):
            continue
        label = _plain(source.get("name"), 120)
        target = _plain(source.get("display_target"), 180)
        state = _plain(source.get("state"), 40)
        print(f"  {_plain(source.get('id'), 80)}  {state:12}  {label}  {target}")
        if source.get("error"):
            print(f"    {_plain(source['error'], 240)}")
    if not sources:
        print("  No sources. Add one with `gn defense add`.")
    warning = snapshot.get("warning")
    if warning:
        print(f"  Warning: {_plain(warning, 240)}")
    if alerts:
        print("Recent alerts:")
        for alert in alerts[:20]:
            if isinstance(alert, dict):
                _render_alert(alert)


def _render_alert(alert: dict[str, Any]) -> None:
    print("  " + "  ".join((
        _plain(alert.get("timestamp"), 35),
        _plain(alert.get("severity"), 12).upper(),
        _plain(alert.get("source_name"), 100),
        _plain(alert.get("title"), 120),
        _plain(alert.get("message"), 240),
    )))


def _emit(args: argparse.Namespace, payload: dict[str, Any], action: str,
          *, attached: bool) -> None:
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        return
    if action in {"status", "watch"}:
        _render_status(payload)
        if not attached and action == "status":
            print("Run `gn defense watch` to collect events while the app is closed.")
        return
    if action == "add":
        source = payload.get("source") or {}
        print(f"Added log source: {_plain(source.get('name'), 120)} ({_plain(source.get('id'), 80)})")
        if not attached:
            print("Run `gn defense watch` to collect events continuously while the app is closed.")
    elif action == "remove":
        print("Removed log source.")
    else:
        source = payload.get("source") or {}
        verb = "Started" if action == "start" else "Stopped"
        print(f"{verb} log source: {_plain(source.get('name'), 120)} "
              f"({_plain(source.get('id'), 80)})")


def _watch(args: argparse.Namespace, poll: Any, *, attached: bool) -> int:
    if not 0.5 <= args.interval <= 3600:
        raise _CliFailure("--interval must be between 0.5 and 3600 seconds.")
    snapshot = poll()
    if args.once:
        _emit(args, snapshot, "watch", attached=attached)
        return 0
    if args.json:
        print(json.dumps({"type": "status", **snapshot}, ensure_ascii=False, separators=(",", ":")), flush=True)
    else:
        _render_status(snapshot)
        print("Watching for new alerts. Press Ctrl+C to stop.", flush=True)
    seen = {str(row.get("id")) for row in snapshot.get("alerts", []) if isinstance(row, dict)}
    previous_sources = _source_signature(snapshot.get("sources", []))
    previous_warning = snapshot.get("warning", "")
    try:
        while True:
            time.sleep(args.interval)
            snapshot = poll()
            sources = snapshot.get("sources", [])
            warning = snapshot.get("warning", "")
            signature = _source_signature(sources)
            if signature != previous_sources or warning != previous_warning:
                if args.json:
                    print(json.dumps({"type": "status", "sources": sources, "warning": warning},
                                     ensure_ascii=False, separators=(",", ":")), flush=True)
                else:
                    _render_status({"sources": sources, "alerts": [], "warning": warning})
                previous_sources, previous_warning = signature, warning
            for alert in reversed(snapshot.get("alerts", [])):
                if not isinstance(alert, dict):
                    continue
                alert_id = str(alert.get("id") or "")
                if alert_id in seen:
                    continue
                if args.json:
                    print(json.dumps({"type": "alert", "alert": alert},
                                     ensure_ascii=False, separators=(",", ":")), flush=True)
                else:
                    _render_alert(alert)
                seen.add(alert_id)
            if len(seen) > 1200:
                seen = {str(row.get("id")) for row in snapshot.get("alerts", []) if isinstance(row, dict)}
    except KeyboardInterrupt:
        if not args.json:
            print("\nStopped watching.")
        return 0


def _source_signature(sources: Any) -> str:
    """Ignore routine poll timestamps when deciding whether to redraw status."""
    compact = []
    for source in sources if isinstance(sources, list) else []:
        if isinstance(source, dict):
            compact.append({key: value for key, value in source.items() if key != "last_checked_at"})
    return json.dumps(compact, sort_keys=True, default=str)


def _command(args: argparse.Namespace) -> int:
    action = getattr(args, "defense_action", None)
    if action is None:
        return _fail(args, "choose a defense action: add, status, watch, start, stop, or remove.")
    if action == "add" and not args.authorize:
        return _fail(args, "pass -y/--authorize to confirm you may read this log source.")
    try:
        if action == "watch" and not 0.5 <= args.interval <= 3600:
            raise _CliFailure("--interval must be between 0.5 and 3600 seconds.")
        config = _source_config(args) if action == "add" else None
        source_id = _source_id(args) if action in {"start", "stop", "remove"} else ""
        from gn_cli import RUNTIME_DIR

        runtime = Path(RUNTIME_DIR).resolve()
        api = _api_for_runtime(runtime)
        if action == "watch":
            return _watch(args, lambda: _headless_watch_poll(runtime), attached=api is not None)
        if api is not None:
            if action == "status":
                poll = lambda: api.request("GET", "/api/defense/status")
                result = poll()
            elif action == "add":
                result = api.request("POST", "/api/defense/sources", config)
            elif action == "remove":
                result = api.request("DELETE", f"/api/defense/sources/{quote(source_id, safe='')}")
            else:
                result = api.request("POST", f"/api/defense/sources/{quote(source_id, safe='')}/{action}", {})
            _emit(args, result, action, attached=True)
            return 0
        if action == "status":
            with _local_status_monitor(runtime) as monitor:
                result = monitor.status()
        else:
            with _local_monitor(runtime) as monitor:
                if action == "add":
                    result = monitor.add_source(config)
                elif action == "start":
                    result = monitor.set_enabled(source_id, True)
                elif action == "stop":
                    result = monitor.set_enabled(source_id, False)
                else:
                    result = monitor.remove_source(source_id)
        _emit(args, result, action, attached=False)
        return 0
    except _CliFailure as exc:
        return _fail(args, str(exc))
    except ValueError as exc:
        # DefenseLogMonitor's validation messages are safe, but avoid adding
        # connection input to any parser failure a driver might raise.
        message = str(exc)
        if action == "add" and config:
            for secret in (config.get("url"), config.get("api_key")):
                if secret:
                    message = message.replace(str(secret), "[REDACTED]")
        return _fail(args, message[:300])
    except Exception as exc:  # Keep unexpected transport/driver text off the terminal.
        return _fail(args, f"Defense command failed ({type(exc).__name__}).")
