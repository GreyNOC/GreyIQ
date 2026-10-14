"""The CLI must use the running same-runtime API instead of a second collector."""
from __future__ import annotations

import json
import os
import hashlib
import hmac
import queue
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "backend" / "gn_cli.py"


class _DefenseServer(ThreadingHTTPServer):
    def __init__(self, *, busy: bool = False, access_key: str = "",
                 identity_port: int | None = None, identity_missing: bool = False,
                 identity_secret: str = "api-identity-secret") -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.busy = busy
        self.access_key = access_key
        self.identity_port = identity_port
        self.identity_missing = identity_missing
        self.sources: list[dict] = []
        self.requests: list[tuple[str, str]] = []
        self.credentials_seen: list[tuple[str, str]] = []
        self.all_headers: list[tuple[str, str, str]] = []
        self.expected_token = "api-session-token"
        self.identity_secret = identity_secret


class _Handler(BaseHTTPRequestHandler):
    server: _DefenseServer

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if status == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="GreyIQ"')
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        self.server.credentials_seen.append((
            self.headers.get("Authorization", ""), self.headers.get("X-GreyIQ-Token", "")))
        if self.server.access_key:
            import base64
            expected = "Basic " + base64.b64encode(
                f"gn:{self.server.access_key}".encode("utf-8")).decode("ascii")
            if self.headers.get("Authorization") != expected:
                self._send(401, {"error": "authentication required"})
                return False
        if self.headers.get("X-GreyIQ-Token") != self.server.expected_token:
            self._send(403, {"error": "missing or invalid session token"})
            return False
        return True

    def do_GET(self) -> None:
        self.server.all_headers.append((self.path, self.headers.get("Authorization", ""),
                                        self.headers.get("X-GreyIQ-Token", "")))
        parsed = urlsplit(self.path)
        if parsed.path == "/api/internal/defense-identity":
            if self.server.identity_missing:
                self._send(404, {"error": "not found"})
                return
            nonce = parse_qs(parsed.query).get("nonce", [""])[0]
            port = self.server.identity_port or self.server.server_address[1]
            message = f"GreyIQ defense identity v1\n127.0.0.1:{port}\n{nonce}".encode("ascii")
            proof = hmac.new(self.server.identity_secret.encode("utf-8"),
                             message, hashlib.sha256).hexdigest()
            self._send(200, {"version": 1, "proof": proof})
            return
        if self.path == "/api/health":
            if self.server.access_key and not self.headers.get("Authorization"):
                self._send(401, {"error": "authentication required"})
            else:
                self._send(200, {"status": "ok"})
            return
        if not self._authorized():
            return
        self.server.requests.append(("GET", self.path))
        if self.path == "/api/defense/status":
            self._send(200, {"ok": True, "sources": list(self.server.sources),
                             "alerts": [], "warning": ""})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        self.server.all_headers.append((self.path, self.headers.get("Authorization", ""),
                                        self.headers.get("X-GreyIQ-Token", "")))
        if not self._authorized():
            return
        self.server.requests.append(("POST", self.path))
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/api/defense/sources":
            if self.server.busy:
                self._send(409, {"detail": "Another defense log monitor is using this runtime."})
                return
            source = {"id": "log_api_1", "kind": body["kind"], "name": body["name"],
                      "enabled": True, "state": "monitoring", "display_target": body.get("path", "")}
            self.server.sources.append(source)
            self._send(200, {"ok": True, "source": source})
        else:
            self._send(404, {"error": "not found"})


@contextmanager
def _server(*, busy: bool = False, access_key: str = "",
            identity_port: int | None = None,
            identity_missing: bool = False,
            identity_secret: str = "api-identity-secret") -> Iterator[_DefenseServer]:
    server = _DefenseServer(busy=busy, access_key=access_key,
                            identity_port=identity_port, identity_missing=identity_missing,
                            identity_secret=identity_secret)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _run(runtime: Path, port: int, *args: str,
         access_key: str = "") -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    if access_key:
        env["GREYIQ_ACCESS_KEY"] = access_key
    else:
        env.pop("GREYIQ_ACCESS_KEY", None)
    env["GREYIQ_RUNTIME_DIR"] = str(runtime)
    env["GREYIQ_PORT"] = str(port)
    return subprocess.run(
        [sys.executable, str(CLI), "defense", *args],
        cwd=ROOT, capture_output=True, text=True, timeout=20, env=env,
    )


def _identity_file(runtime: Path) -> None:
    (runtime / "defense.identity").write_text("api-identity-secret", encoding="utf-8")


def test_cli_uses_same_runtime_api_for_add_status_and_watch_once(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "session.token").write_text("api-session-token", encoding="utf-8")
    _identity_file(runtime)
    log = tmp_path / "events.log"
    log.write_text("", encoding="utf-8")
    with _server() as server:
        port = server.server_address[1]
        added = _run(runtime, port, "add", "--kind", "file", "--name", "API logs",
                     "--path", str(log), "-y", "--json")
        assert added.returncode == 0, added.stderr
        assert json.loads(added.stdout)["source"]["id"] == "log_api_1"
        status = _run(runtime, port, "status", "--json")
        assert status.returncode == 0, status.stderr
        assert json.loads(status.stdout)["sources"][0]["name"] == "API logs"
        watched = _run(runtime, port, "watch", "--once", "--json")
        assert watched.returncode == 0, watched.stderr
        assert json.loads(watched.stdout)["sources"][0]["id"] == "log_api_1"
        assert ("POST", "/api/defense/sources") in server.requests
        assert sum(path == "/api/defense/status" for _, path in server.requests) >= 3
    assert not (runtime / "data" / "defense_log_monitor.json").exists()
    assert not (runtime / "data" / "defense_monitor.lock").exists()


def test_cli_rejects_wrong_runtime_token_without_local_write(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "session.token").write_text("wrong-token", encoding="utf-8")
    _identity_file(runtime)
    log = tmp_path / "events.log"
    log.write_text("", encoding="utf-8")
    with _server() as server:
        proc = _run(runtime, server.server_address[1], "add", "--kind", "file",
                    "--name", "API logs", "--path", str(log), "-y", "--json")
        assert proc.returncode == 2
        assert "session token" in json.loads(proc.stdout)["error"].lower()
        assert server.sources == []
    assert not (runtime / "data" / "defense_log_monitor.json").exists()


def test_cli_attaches_to_proven_api_with_access_key(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "session.token").write_text("api-session-token", encoding="utf-8")
    _identity_file(runtime)
    with _server(access_key="private-access-key") as server:
        proc = _run(runtime, server.server_address[1], "status", "--json",
                    access_key="private-access-key")
        assert proc.returncode == 0, proc.stderr
        assert json.loads(proc.stdout)["ok"] is True
        assert server.credentials_seen
        assert all(pair == ("Basic Z246cHJpdmF0ZS1hY2Nlc3Mta2V5", "api-session-token")
                   for pair in server.credentials_seen)


def test_spoofed_identity_cannot_steal_access_key_or_session_token(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "session.token").write_text("api-session-token", encoding="utf-8")
    _identity_file(runtime)
    # The listener signs a different socket port, as a relay to a real API
    # would. Its forged health and session-token errors are no proof of identity.
    with _server(access_key="private-access-key", identity_port=8766) as server:
        proc = _run(runtime, server.server_address[1], "status", "--json",
                    access_key="private-access-key")
        assert proc.returncode == 2
        assert "private identity" in json.loads(proc.stdout)["error"].lower()
        assert server.credentials_seen == []
        assert all(not authorization and not token
                   for _, authorization, token in server.all_headers)


def test_basic_auth_fingerprint_alone_never_receives_access_key(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "session.token").write_text("api-session-token", encoding="utf-8")
    _identity_file(runtime)
    with _server(access_key="private-access-key", identity_missing=True) as server:
        proc = _run(runtime, server.server_address[1], "status", "--json",
                    access_key="private-access-key")
        assert proc.returncode == 0
        assert server.credentials_seen == []
        assert all(not authorization and not token
                   for _, authorization, token in server.all_headers)


def test_keyless_spoof_with_public_session_token_cannot_attach(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "session.token").write_text("api-session-token", encoding="utf-8")
    _identity_file(runtime)
    # A local listener may know the keyless app's HTML-exposed session token.
    # That does not let it forge the separate owner-only identity proof.
    with _server(identity_secret="attacker-knows-only-session-token") as server:
        proc = _run(runtime, server.server_address[1], "status", "--json")
        assert proc.returncode == 2
        assert "private identity" in json.loads(proc.stdout)["error"].lower()
        assert all(not authorization and not token
                   for _, authorization, token in server.all_headers)


def test_missing_private_identity_file_never_sends_credentials(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "session.token").write_text("api-session-token", encoding="utf-8")
    with _server(access_key="private-access-key") as server:
        proc = _run(runtime, server.server_address[1], "status", "--json",
                    access_key="private-access-key")
        assert proc.returncode == 2
        assert "private identity secret" in json.loads(proc.stdout)["error"].lower()
        assert server.all_headers == []


def test_identity_and_actions_bypass_environment_proxy(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "session.token").write_text("api-session-token", encoding="utf-8")
    _identity_file(runtime)
    log = tmp_path / "events.log"
    log.write_text("", encoding="utf-8")
    with _server(access_key="private-access-key") as api_server, _server(
        identity_secret="proxy-attacker-secret"
    ) as proxy_server:
        env = dict(os.environ)
        env["GREYIQ_PORT"] = str(api_server.server_address[1])
        env["GREYIQ_ACCESS_KEY"] = "private-access-key"
        proxy_url = f"http://127.0.0.1:{proxy_server.server_address[1]}"
        env.update({"HTTP_PROXY": proxy_url, "http_proxy": proxy_url,
                    "ALL_PROXY": proxy_url, "all_proxy": proxy_url,
                    "NO_PROXY": "", "no_proxy": ""})
        # Force the normal urllib proxy bypass hook off, so this test detects
        # accidental use of its default opener even for 127.0.0.1.
        script = (
            "import sys, urllib.request\n"
            "from pathlib import Path\n"
            "urllib.request.proxy_bypass = lambda host: False\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from defense_cli import _api_for_runtime\n"
            "api = _api_for_runtime(Path(sys.argv[2]))\n"
            "assert api is not None\n"
            "api.request('POST', '/api/defense/sources', "
            "{'authorized': True, 'kind': 'file', 'name': 'Proxy safe', 'path': sys.argv[3]})\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script, str(ROOT / "backend"), str(runtime), str(log)],
            cwd=ROOT, capture_output=True, text=True, timeout=20, env=env,
        )
        assert proc.returncode == 0, proc.stderr
        assert ("POST", "/api/defense/sources") in api_server.requests
        assert all(not authorization and not token
                   for _, authorization, token in proxy_server.all_headers)


def test_cli_reports_api_monitor_busy_detail(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "session.token").write_text("api-session-token", encoding="utf-8")
    _identity_file(runtime)
    log = tmp_path / "events.log"
    log.write_text("", encoding="utf-8")
    with _server(busy=True) as server:
        proc = _run(runtime, server.server_address[1], "add", "--kind", "file",
                    "--name", "API logs", "--path", str(log), "-y", "--json")
        assert proc.returncode == 2
        error = json.loads(proc.stdout)["error"].lower()
        assert "busy" in error and "another defense log monitor" in error
        assert server.sources == []
    assert not (runtime / "data" / "defense_log_monitor.json").exists()


def test_headless_watch_allows_other_cli_commands_between_polls(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    log = tmp_path / "events.log"
    log.write_text("", encoding="utf-8")
    env = dict(os.environ)
    env.pop("GREYIQ_ACCESS_KEY", None)
    env["GREYIQ_RUNTIME_DIR"] = str(runtime)
    watcher = subprocess.Popen(
        [sys.executable, str(CLI), "defense", "watch", "--interval", "0.5", "--json"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", bufsize=1,
    )
    lines: queue.Queue[str] = queue.Queue()
    assert watcher.stdout is not None
    reader = threading.Thread(target=lambda: [lines.put(line) for line in watcher.stdout], daemon=True)
    reader.start()
    try:
        first = json.loads(lines.get(timeout=8))
        assert first["type"] == "status"
        added = _run(runtime, 8766, "add", "--kind", "file", "--name", "Shared logs",
                     "--path", str(log), "-y", "--json")
        assert added.returncode == 0, added.stderr
        source_id = json.loads(added.stdout)["source"]["id"]
        status = _run(runtime, 8766, "status", "--json")
        assert status.returncode == 0, status.stderr
        assert json.loads(status.stdout)["sources"][0]["id"] == source_id
        with log.open("a", encoding="utf-8") as handle:
            handle.write("failed login\n")
        deadline = time.monotonic() + 8
        found_alert = False
        while time.monotonic() < deadline:
            try:
                event = json.loads(lines.get(timeout=1))
            except queue.Empty:
                continue
            if event.get("type") == "alert":
                found_alert = True
                assert event["alert"]["severity"] == "high"
                break
        assert found_alert, "watch did not pick up a source added by a second CLI command"
        stopped = _run(runtime, 8766, "stop", source_id, "--json")
        assert stopped.returncode == 0, stopped.stderr
        assert json.loads(stopped.stdout)["source"]["enabled"] is False
        removed = _run(runtime, 8766, "remove", source_id, "--json")
        assert removed.returncode == 0, removed.stderr
    finally:
        watcher.terminate()
        try:
            watcher.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            watcher.kill()
            watcher.communicate(timeout=5)
        reader.join(timeout=1)
