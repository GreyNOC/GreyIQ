"""Operator-managed MCP servers for GreyIQ.

Saving a server is inert. A connection is opened only by an explicit test, tool
listing, or tool call. This module deliberately does not turn an MCP server into
authorization for target testing: callers must apply their own engagement gate.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from bughunter import sensitive_data
from bughunter.code_scanner.redaction import redact_text


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9_-]{1,100}\Z")
_HTTP_NETLOC = re.compile(r"(?:127\.0\.0\.1|\[::1\]):[0-9]{1,5}\Z")
_MAX_SERVERS = 20
_MAX_ARGS = 32
_MAX_ARG_CHARS = 2048
_MAX_CONFIG_BYTES = 256_000
_MAX_TOOLS = 64
_MAX_TOOL_DESCRIPTION = 1000
_MAX_TOOL_SCHEMA_BYTES = 8192
_MAX_RESULT_CHARS = 12_000
_MAX_ARGUMENT_BYTES = 16_384
_CONNECT_TIMEOUT_S = 12.0
_ALLOWED_FIELDS = frozenset({"name", "transport", "command", "args", "url", "enabled"})
_STORED_FIELDS = _ALLOWED_FIELDS | {"command_target"}
_MAX_HUNT_APPROVALS = 64
_MAX_HUNT_CALLS = 8
_HUNT_PERMIT_TTL_S = 60 * 60
_HUNT_FINDING_FIELDS = frozenset({
    "ref", "title", "category", "severity", "proof_status", "observation",
    "negative_control", "limitations",
})
_HUNT_SUMMARY_FIELDS = frozenset({
    "risk", "score", "finding_count", "severity_counts", "scanners_run",
})


class MCPServerManager:
    """A small, persistent MCP registry with bounded one-shot connections."""

    def __init__(self, config_path: str | Path) -> None:
        self.config_path = Path(config_path).expanduser().resolve()
        self.hunt_approvals_path = self.config_path.with_name("mcp_hunt_approvals.json")
        self._lock = threading.RLock()
        self._operation_lock = threading.Lock()
        self._status: dict[str, dict[str, Any]] = {}
        # Authorization is never restored after restart. A saved tool approval
        # only identifies a tool that the operator reviewed for evidence analysis.
        self._hunt_permits: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _error(message: str, *, status: str | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {"ok": False, "error": message}
        if status:
            result["status"] = status
        return result

    @staticmethod
    def _valid_name(name: Any) -> bool:
        return isinstance(name, str) and bool(_NAME.fullmatch(name))

    @staticmethod
    def _valid_text(value: Any, *, max_chars: int) -> bool:
        return (isinstance(value, str) and len(value) <= max_chars
                and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value))

    @staticmethod
    def _valid_scope_text(value: Any) -> bool:
        # Saved program scope is commonly one host per line. Preserve that
        # exact string for process-local permit matching; do not send it to MCP.
        return (isinstance(value, str) and 0 < len(value) <= 2000
                and not any((ord(ch) < 32 and ch not in "\t\r\n") or ord(ch) == 127
                            for ch in value))

    @classmethod
    def _normalize(cls, payload: dict[str, Any], *, check_executable: bool = True) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) - _STORED_FIELDS:
            raise ValueError("Unsupported MCP server settings.")
        name = payload.get("name")
        if not cls._valid_name(name):
            raise ValueError("Server name must start with a letter or digit and contain only letters, digits, _ or - (max 40).")
        transport = payload.get("transport")
        if transport not in {"stdio", "http"}:
            raise ValueError("Transport must be stdio or http.")
        enabled = payload.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ValueError("Enabled must be true or false.")
        record: dict[str, Any] = {"name": name, "transport": transport, "enabled": enabled}
        if transport == "stdio":
            if payload.get("url") not in (None, ""):
                raise ValueError("A stdio server cannot include a URL.")
            command = payload.get("command")
            if not cls._valid_text(command, max_chars=2048) or not command:
                raise ValueError("Command must be an absolute native executable path.")
            path = Path(command).expanduser()
            if not path.is_absolute() or (sys.platform == "win32" and str(path).startswith("\\\\")):
                raise ValueError("Command must be an absolute local executable path.")
            # Keep the launch path's symlink. Unix virtual environments commonly
            # use bin/python -> the system interpreter; executing the resolved
            # target loses pyvenv.cfg discovery and the environment's packages.
            launch_path = Path(os.path.abspath(path))
            try:
                resolved = launch_path.resolve(strict=check_executable)
                mode = resolved.stat().st_mode if check_executable else None
            except (OSError, RuntimeError):
                raise ValueError("Command executable does not exist.") from None
            if sys.platform == "win32" and str(resolved).startswith("\\\\"):
                raise ValueError("Command must be an absolute local executable path.")
            if check_executable and not stat.S_ISREG(mode):
                raise ValueError("Command must be a regular executable file.")
            if sys.platform == "win32":
                if resolved.suffix.lower() not in {".exe", ".com"}:
                    raise ValueError("Windows stdio commands must be .exe or .com files.")
            elif check_executable and not os.access(resolved, os.X_OK):
                raise ValueError("Command file is not executable.")
            args = payload.get("args", [])
            if (not isinstance(args, list) or len(args) > _MAX_ARGS
                    or any(not cls._valid_text(arg, max_chars=_MAX_ARG_CHARS) for arg in args)):
                raise ValueError("Arguments must be an array of at most 32 bounded strings.")
            target = str(resolved)
            bound_target = payload.get("command_target", target)
            if (not isinstance(bound_target, str) or not Path(bound_target).is_absolute()
                    or len(bound_target) > 2048):
                raise ValueError("Saved MCP server command target is invalid.")
            if check_executable and bound_target != target:
                raise ValueError("MCP server command target changed since registration.")
            record.update(command=str(launch_path), command_target=bound_target, args=list(args))
        else:
            if (payload.get("command") not in (None, "") or payload.get("args") not in (None, [])
                    or payload.get("command_target") is not None):
                raise ValueError("An HTTP server cannot include a command or arguments.")
            url = payload.get("url")
            if not cls._valid_text(url, max_chars=2048) or not url or "?" in url or "#" in url or "\\" in url:
                raise ValueError("HTTP URL must be a literal loopback address with an explicit port.")
            try:
                parsed = urlsplit(url)
                port = parsed.port
            except ValueError:
                raise ValueError("HTTP URL has an invalid port or host.") from None
            if (parsed.scheme != "http" or not _HTTP_NETLOC.fullmatch(parsed.netloc)
                    or parsed.hostname not in {"127.0.0.1", "::1"}
                    or port is None or not 1 <= port <= 65535
                    or parsed.username or parsed.password):
                raise ValueError("HTTP URL must be http://127.0.0.1:<port> or http://[::1]:<port>.")
            record["url"] = url
        return record

    def _load(self) -> list[dict[str, Any]]:
        if not self.config_path.exists():
            return []
        if self.config_path.stat().st_size > _MAX_CONFIG_BYTES:
            raise ValueError("MCP server configuration is too large.")
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ValueError("MCP server configuration could not be read.") from None
        if (not isinstance(data, dict) or data.get("version") != 1
                or not isinstance(data.get("servers"), list)
                or len(data["servers"]) > _MAX_SERVERS):
            raise ValueError("MCP server configuration has an invalid format.")
        # A previously configured executable can disappear. The operator still
        # needs to list, repair, or remove that server without touching the file.
        servers = [self._normalize(item, check_executable=False) for item in data["servers"]]
        if len({item["name"].casefold() for item in servers}) != len(servers):
            raise ValueError("MCP server configuration has duplicate names.")
        return servers

    def _save(self, servers: list[dict[str, Any]]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        contents = json.dumps({"version": 1, "servers": servers}, ensure_ascii=True, separators=(",", ":"))
        if len(contents.encode("utf-8")) > _MAX_CONFIG_BYTES:
            raise ValueError("MCP server configuration is too large.")
        tmp = self.config_path.with_name(f".{self.config_path.name}.{uuid4().hex}.tmp")
        replaced = False
        try:
            descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(contents)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.config_path)
            replaced = True
        finally:
            if not replaced:
                try:
                    tmp.unlink()
                except OSError:
                    pass

    @staticmethod
    def _server_fingerprint(record: dict[str, Any]) -> str:
        # Include enablement so toggling a server requires a fresh approval.
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @classmethod
    def _launch_target_is_current(cls, record: dict[str, Any]) -> bool:
        if record["transport"] != "stdio":
            return True
        try:
            cls._normalize(record, check_executable=True)
        except ValueError:
            return False
        return True

    @staticmethod
    def _valid_tool_name(name: Any) -> bool:
        return (isinstance(name, str) and bool(name) and len(name) <= 128
                and name == name.strip()
                and not any(ord(ch) < 32 or ord(ch) == 127 for ch in name))

    def _load_hunt_approvals(self) -> list[dict[str, Any]]:
        if not self.hunt_approvals_path.exists():
            return []
        if self.hunt_approvals_path.stat().st_size > _MAX_CONFIG_BYTES:
            raise ValueError("MCP hunt approvals are too large.")
        try:
            data = json.loads(self.hunt_approvals_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ValueError("MCP hunt approvals could not be read.") from None
        approvals = data.get("approvals") if isinstance(data, dict) and data.get("version") == 1 else None
        if not isinstance(approvals, list) or len(approvals) > _MAX_HUNT_APPROVALS:
            raise ValueError("MCP hunt approvals have an invalid format.")
        seen: set[tuple[str, str]] = set()
        for item in approvals:
            if (not isinstance(item, dict)
                    or set(item) != {"server", "tool", "evidence_only", "server_fingerprint"}
                    or not self._valid_name(item["server"])
                    or not self._valid_tool_name(item["tool"])
                    or item["evidence_only"] is not True
                    or not isinstance(item["server_fingerprint"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", item["server_fingerprint"])):
                raise ValueError("MCP hunt approvals have an invalid format.")
            key = (item["server"], item["tool"])
            if key in seen:
                raise ValueError("MCP hunt approvals have duplicate tools.")
            seen.add(key)
        return approvals

    def _save_hunt_approvals(self, approvals: list[dict[str, Any]]) -> None:
        if len(approvals) > _MAX_HUNT_APPROVALS:
            raise ValueError("The 64-tool hunt approval limit has been reached.")
        path = self.hunt_approvals_path
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps({"version": 1, "approvals": approvals}, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > _MAX_CONFIG_BYTES:
            raise ValueError("MCP hunt approvals are too large.")
        tmp = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        replaced = False
        try:
            descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            replaced = True
        finally:
            if not replaced:
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def _drop_hunt_approvals(self, server: str) -> None:
        approvals = self._load_hunt_approvals()
        retained = [item for item in approvals if item["server"] != server]
        if len(retained) != len(approvals):
            self._save_hunt_approvals(retained)
        for token, permit in list(self._hunt_permits.items()):
            if permit["server"] == server:
                self._hunt_permits.pop(token, None)

    def _public(self, record: dict[str, Any]) -> dict[str, Any]:
        item = dict(record)
        item.pop("command_target", None)
        item.update(self._status.get(record["name"], {"status": "untested", "tool_count": 0}))
        return item

    def list_servers(self) -> dict[str, Any]:
        try:
            with self._lock:
                return {"ok": True, "servers": [self._public(item) for item in self._load()]}
        except (OSError, ValueError):
            return self._error("MCP server configuration could not be read.")

    def add_server(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            if not isinstance(payload, dict) or set(payload) - _ALLOWED_FIELDS:
                raise ValueError("Unsupported MCP server settings.")
            record = self._normalize(payload, check_executable=False)
            with self._lock:
                servers = self._load()
                if len(servers) >= _MAX_SERVERS:
                    return self._error("The 20-server limit has been reached.")
                if any(item["name"].casefold() == record["name"].casefold() for item in servers):
                    return self._error("A server with that name already exists.")
                servers.append(record)
                self._save(servers)
                self._status.pop(record["name"], None)
                return {"ok": True, "server": self._public(record)}
        except ValueError as exc:
            return self._error(str(exc))
        except OSError:
            return self._error("MCP server configuration could not be saved.")

    def update_server(self, name: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self._valid_name(name):
            return self._error("Invalid server name.")
        if not isinstance(payload, dict) or set(payload) - _ALLOWED_FIELDS:
            return self._error("Unsupported MCP server settings.")
        if "name" in payload and payload["name"] != name:
            return self._error("Server name cannot be changed. Remove and add the server instead.")
        try:
            with self._operation_lock, self._lock:
                servers = self._load()
                index = next((i for i, item in enumerate(servers) if item["name"] == name), None)
                if index is None:
                    return self._error("MCP server was not found.")
                old = servers[index]
                merged = dict(old)
                if payload.get("transport", old["transport"]) != old["transport"]:
                    merged = {"name": name, "enabled": old["enabled"]}
                merged.update(payload)
                merged["name"] = name
                if "command" in payload:
                    # Explicitly saving the command also rebinds an intentionally
                    # retargeted symlink; changed bindings drop approvals below.
                    merged.pop("command_target", None)
                record = self._normalize(merged, check_executable=False)
                servers[index] = record
                # The exact server configuration reviewed by the operator has
                # changed. Remove its approvals and live permits before saving.
                if record != old:
                    self._drop_hunt_approvals(name)
                self._save(servers)
                self._status.pop(name, None)
                return {"ok": True, "server": self._public(record)}
        except ValueError as exc:
            return self._error(str(exc))
        except OSError:
            return self._error("MCP server configuration could not be saved.")

    def delete_server(self, name: str) -> dict[str, Any]:
        if not self._valid_name(name):
            return self._error("Invalid server name.")
        try:
            with self._operation_lock, self._lock:
                servers = self._load()
                retained = [item for item in servers if item["name"] != name]
                if len(retained) == len(servers):
                    return self._error("MCP server was not found.")
                self._drop_hunt_approvals(name)
                self._save(retained)
                self._status.pop(name, None)
                return {"ok": True, "deleted": name}
        except (OSError, ValueError):
            return self._error("MCP server configuration could not be updated.")

    def list_hunt_approvals(self, server: str | None = None) -> dict[str, Any]:
        """List operator-approved evidence-analysis tools without connecting."""
        if server is not None and not self._valid_name(server):
            return self._error("Invalid server name.")
        try:
            with self._lock:
                current = {item["name"]: item for item in self._load()}
                approvals = self._load_hunt_approvals()
                rows = []
                for item in approvals:
                    if server is not None and item["server"] != server:
                        continue
                    record = current.get(item["server"])
                    rows.append({
                        **item,
                        "valid": bool(record and record["enabled"]
                                      and self._launch_target_is_current(record)
                                      and self._server_fingerprint(record) == item["server_fingerprint"]),
                    })
                return {"ok": True, "approvals": rows}
        except (OSError, ValueError):
            return self._error("MCP hunt approvals could not be read.")

    def approve_hunt_tool(self, server: str, tool: str, *, evidence_only: bool) -> dict[str, Any]:
        """Explicit operator review: discover the exact tool before approving it.

        ``evidence_only`` is an operator assertion, not proof that an external
        server has no side effects. A separate per-run opt-in is still required.
        """
        if evidence_only is not True:
            return self._error("Confirm this exact tool is for evidence analysis only.")
        if not self._valid_tool_name(tool):
            return self._error("Invalid MCP tool name.")
        record, error = self._find(server, enabled=True)
        if error:
            return error
        assert record is not None
        listed = self.list_tools(server)
        if not listed.get("ok"):
            return self._error(str(listed.get("error") or "Could not discover MCP tools."))
        if not any(item.get("name") == tool for item in listed.get("tools") or []):
            return self._error("Tool is not advertised by this server.")
        try:
            with self._lock:
                current = next((item for item in self._load() if item["name"] == server), None)
                if current != record or not current["enabled"]:
                    return self._error("MCP server settings changed; retry approval.")
                approvals = self._load_hunt_approvals()
                approval = {
                    "server": server, "tool": tool, "evidence_only": True,
                    "server_fingerprint": self._server_fingerprint(current),
                }
                approvals = [item for item in approvals
                             if (item["server"], item["tool"]) != (server, tool)]
                approvals.append(approval)
                self._save_hunt_approvals(approvals)
                return {"ok": True, "approval": {**approval, "valid": True}}
        except (OSError, ValueError):
            return self._error("MCP hunt approval could not be saved.")

    def revoke_hunt_tool(self, server: str, tool: str) -> dict[str, Any]:
        if not self._valid_name(server) or not self._valid_tool_name(tool):
            return self._error("Invalid server or tool name.")
        try:
            with self._operation_lock, self._lock:
                approvals = self._load_hunt_approvals()
                retained = [item for item in approvals
                            if (item["server"], item["tool"]) != (server, tool)]
                if len(retained) == len(approvals):
                    return {"ok": True, "revoked": False}
                self._save_hunt_approvals(retained)
                for token, permit in list(self._hunt_permits.items()):
                    if (permit["server"], permit["tool"]) == (server, tool):
                        self._hunt_permits.pop(token, None)
                return {"ok": True, "revoked": True}
        except (OSError, ValueError):
            return self._error("MCP hunt approval could not be revoked.")

    def create_hunt_permit(
        self, run_id: str, target: str, scope: str, *, authorized: bool,
        server: str, tool: str, max_calls: int = 1,
    ) -> dict[str, Any]:
        """Mint a short-lived, process-only permit for one exact hunt and tool.

        The caller must perform the engagement's own authorization and scope
        preflight. This permit does not grant target-testing authority to a server.
        """
        if authorized is not True:
            return self._error("An authorized hunt is required for automatic MCP analysis.")
        if (not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id)
                or not self._valid_text(target, max_chars=4000) or not target
                or not self._valid_scope_text(scope)):
            return self._error("A concrete run ID, target, and scope are required.")
        if (not self._valid_name(server) or not self._valid_tool_name(tool)
                or type(max_calls) is not int or not 1 <= max_calls <= _MAX_HUNT_CALLS):
            return self._error("Choose one approved tool and a bounded call count.")
        try:
            with self._lock:
                record = next((item for item in self._load() if item["name"] == server), None)
                if not record or not record["enabled"]:
                    return self._error("Enable this MCP server before automatic hunt analysis.")
                if not self._launch_target_is_current(record):
                    return self._error("MCP server command changed since registration.")
                fingerprint = self._server_fingerprint(record)
                approved = any(
                    item["server"] == server and item["tool"] == tool
                    and item["evidence_only"] is True
                    and item["server_fingerprint"] == fingerprint
                    for item in self._load_hunt_approvals()
                )
                if not approved:
                    return self._error("This exact MCP tool is not approved for hunt evidence analysis.")
                now = time.monotonic()
                for old_token, permit in list(self._hunt_permits.items()):
                    if permit["expires_at"] <= now:
                        self._hunt_permits.pop(old_token, None)
                token = secrets.token_urlsafe(32)
                self._hunt_permits[token] = {
                    "run_id": run_id, "target": target, "scope": scope,
                    "server": server, "tool": tool, "server_fingerprint": fingerprint,
                    "calls_remaining": max_calls, "expires_at": now + _HUNT_PERMIT_TTL_S,
                }
                return {"ok": True, "token": token, "run_id": run_id,
                        "calls_remaining": max_calls,
                        "expires_in_seconds": _HUNT_PERMIT_TTL_S}
        except (OSError, ValueError):
            return self._error("MCP hunt approval could not be verified.")

    def revoke_hunt_permit(self, token: str) -> dict[str, Any]:
        with self._lock:
            return {"ok": True, "revoked": self._hunt_permits.pop(str(token), None) is not None}

    def _find(self, name: str, *, enabled: bool) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if not self._valid_name(name):
            return None, self._error("Invalid server name.")
        try:
            with self._lock:
                record = next((item for item in self._load() if item["name"] == name), None)
        except (OSError, ValueError):
            return None, self._error("MCP server configuration could not be read.")
        if record is None:
            return None, self._error("MCP server was not found.")
        if enabled and not record["enabled"]:
            return None, self._error("Enable this MCP server before using its tools.")
        return record, None

    @staticmethod
    def _http_client_factory(*, headers: dict[str, str] | None = None, timeout: Any = None, auth: Any = None) -> Any:
        import httpx

        if auth is not None:
            raise ValueError("MCP HTTP authentication is not configured.")
        return httpx.AsyncClient(headers=headers, timeout=timeout, trust_env=False, follow_redirects=False)

    @staticmethod
    def _tool_entries(result: Any) -> tuple[list[dict[str, Any]], bool]:
        entries: list[dict[str, Any]] = []
        tools = getattr(result, "tools", []) or []
        for tool in tools[:_MAX_TOOLS]:
            name = getattr(tool, "name", None)
            if not isinstance(name, str) or not name or len(name) > 128:
                continue
            description = str(getattr(tool, "description", "") or "")[:_MAX_TOOL_DESCRIPTION]
            schema = getattr(tool, "inputSchema", None)
            if not isinstance(schema, dict):
                schema = {"type": "object", "properties": {}}
            try:
                encoded = json.dumps(schema, ensure_ascii=True, allow_nan=False)
            except (TypeError, ValueError):
                continue
            if len(encoded.encode("utf-8")) > _MAX_TOOL_SCHEMA_BYTES:
                continue
            entries.append({"name": name, "description": description, "input_schema": schema})
        return entries, len(tools) > _MAX_TOOLS or bool(getattr(result, "nextCursor", None))

    async def _operate(self, record: dict[str, Any], action: str, tool_name: str = "", args: dict[str, Any] | None = None) -> dict[str, Any]:
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        from mcp.client.streamable_http import streamablehttp_client

        if record["transport"] == "stdio":
            params = StdioServerParameters(command=record["command"], args=record["args"])
            transport = stdio_client(params, errlog=subprocess.DEVNULL)
        else:
            transport = streamablehttp_client(
                record["url"], timeout=8.0, sse_read_timeout=8.0,
                httpx_client_factory=self._http_client_factory,
            )
        async with transport as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                listed = await session.list_tools()
                tools, truncated = self._tool_entries(listed)
                if action == "list":
                    return {"tools": tools, "tool_count": len(tools), "truncated": truncated}
                chosen = next((tool for tool in tools if tool["name"] == tool_name), None)
                if chosen is None:
                    raise LookupError("Tool is not advertised by this server.")
                result = await session.call_tool(tool_name, arguments=args or {})
                remaining = _MAX_RESULT_CHARS
                content: list[dict[str, str]] = []
                clipped = False
                for block in getattr(result, "content", []) or []:
                    kind = str(getattr(block, "type", "unknown"))[:40]
                    value = str(getattr(block, "text", "") or "") if kind == "text" else "[non-text MCP content omitted]"
                    if len(value) > remaining:
                        value = value[:remaining]
                        clipped = True
                    content.append({"type": kind, "text": value})
                    remaining -= len(value)
                    if remaining <= 0 or len(content) >= 16:
                        clipped = True
                        break
                return {
                    "content": content, "is_error": bool(getattr(result, "isError", False)),
                    "truncated": clipped, "tool_count": len(tools),
                }

    def _run(self, record: dict[str, Any], action: str, tool_name: str = "", args: dict[str, Any] | None = None) -> dict[str, Any]:
        # The binary may have been removed or replaced since registration. Do
        # this immediately before every launch, then use the resolved path.
        if record["transport"] == "stdio":
            try:
                record = self._normalize(record, check_executable=True)
            except ValueError:
                return self._error("MCP server command is unavailable or not executable.", status="error")
        try:
            return asyncio.run(asyncio.wait_for(
                self._operate(record, action, tool_name, args), timeout=_CONNECT_TIMEOUT_S
            ))
        except TimeoutError:
            return self._error("MCP server did not respond within 12 seconds.", status="error")
        except LookupError:
            return self._error("Tool is not advertised by this server.", status="error")
        except Exception:  # server-controlled details may contain secrets or hostile text
            return self._error("MCP server connection or request failed.", status="error")

    def _run_once(
        self, record: dict[str, Any], action: str, tool_name: str = "",
        args: dict[str, Any] | None = None, *, require_enabled: bool = False,
        require_hunt_approval: bool = False,
    ) -> dict[str, Any]:
        # An untrusted server can stall. Reject competing requests rather than
        # creating an unbounded queue of children/connections behind it.
        if not self._operation_lock.acquire(blocking=False):
            return {**self._error("Another MCP server operation is in progress.", status="error"), "busy": True}
        try:
            current, error = self._find(record["name"], enabled=require_enabled)
            if error:
                return {**error, "status": "error"}
            if current != record:
                return self._error("MCP server settings changed; retry the operation.", status="error")
            if require_hunt_approval:
                try:
                    with self._lock:
                        fingerprint = self._server_fingerprint(record)
                        approved = any(
                            item["server"] == record["name"] and item["tool"] == tool_name
                            and item["evidence_only"] is True
                            and item["server_fingerprint"] == fingerprint
                            for item in self._load_hunt_approvals()
                        )
                except (OSError, ValueError):
                    approved = False
                if not approved:
                    return self._error("This MCP tool is no longer approved for hunt analysis.", status="error")
            return self._run(record, action, tool_name, args)
        finally:
            self._operation_lock.release()

    def _record_status(self, record: dict[str, Any], result: dict[str, Any]) -> None:
        with self._lock:
            try:
                current = next((item for item in self._load() if item["name"] == record["name"]), None)
            except (OSError, ValueError):
                return
            # A connection can finish after the operator edits or removes the
            # server. Never attach that old result to a new configuration.
            if current != record:
                return
            self._status[record["name"]] = {
                "status": "available" if result.get("ok") else "error",
                "tool_count": int(result.get("tool_count") or 0),
            }

    def test_server(self, name: str) -> dict[str, Any]:
        record, error = self._find(name, enabled=False)
        if error:
            return error
        assert record is not None
        result = self._run_once(record, "list")
        if result.get("busy"):
            return {**result, "server": name}
        if "error" in result:
            result.update(server=name, tool_count=0)
        else:
            result.update(ok=True, server=name, status="available")
        self._record_status(record, result)
        return result

    def list_tools(self, name: str) -> dict[str, Any]:
        record, error = self._find(name, enabled=True)
        if error:
            return error
        assert record is not None
        result = self._run_once(record, "list", require_enabled=True)
        if result.get("busy"):
            return {**result, "server": name}
        if "error" in result:
            result.update(server=name, tool_count=0)
        else:
            result.update(ok=True, server=name, status="available")
        self._record_status(record, result)
        return result

    def call_tool(self, name: str, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        record, error = self._find(name, enabled=True)
        if error:
            return error
        assert record is not None
        if not isinstance(tool_name, str) or not tool_name or len(tool_name) > 128:
            return self._error("Invalid MCP tool name.")
        if not isinstance(args, dict):
            return self._error("MCP tool arguments must be an object.")
        try:
            encoded = json.dumps(args, ensure_ascii=True, allow_nan=False)
        except (TypeError, ValueError, RecursionError):
            return self._error("MCP tool arguments must be valid JSON.")
        if len(encoded.encode("utf-8")) > _MAX_ARGUMENT_BYTES:
            return self._error("MCP tool arguments are too large.")
        result = self._run_once(record, "call", tool_name, args, require_enabled=True)
        if result.get("busy"):
            return {**result, "server": name, "tool": tool_name}
        if "error" in result:
            result.update(server=name, tool=tool_name)
        else:
            result.update(ok=True, server=name, tool=tool_name)
        self._record_status(record, result)
        return result

    @staticmethod
    def _safe_hunt_text(value: Any, *, max_chars: int) -> str:
        if (not isinstance(value, str) or len(value) > max_chars
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
            raise ValueError("Hunt snapshot text is invalid or too long.")
        # Never send a known secret or personal datum to a third-party tool.
        # Redaction is defense in depth, not a substitute for classification.
        if sensitive_data.classify(value):
            raise ValueError("Hunt snapshot contains sensitive information.")
        return redact_text(value)[0]

    @classmethod
    def _hunt_snapshot(
        cls, snapshot: dict[str, Any], *, run_id: str,
    ) -> dict[str, Any]:
        """Build analysis metadata without sending the target or scope to MCP.

        Raw URLs and scope text can carry private query parameters that pattern
        classifiers miss. They stay only in the process-local permit check.
        """
        if not isinstance(snapshot, dict) or set(snapshot) - {"summary", "findings"}:
            raise ValueError("Hunt snapshot may contain only summary and findings metadata.")
        summary = snapshot.get("summary")
        findings = snapshot.get("findings")
        if not isinstance(summary, dict) or set(summary) - _HUNT_SUMMARY_FIELDS:
            raise ValueError("Hunt summary contains unsupported fields.")
        if not isinstance(findings, list) or len(findings) > 20:
            raise ValueError("Hunt findings must be a bounded list.")
        clean_summary: dict[str, Any] = {}
        for key in ("risk",):
            if key in summary:
                clean_summary[key] = cls._safe_hunt_text(summary[key], max_chars=40)
        for key in ("score", "finding_count"):
            if key in summary:
                value = summary[key]
                if type(value) not in {int, float} or not 0 <= value <= 1_000_000:
                    raise ValueError("Hunt summary counts must be bounded numbers.")
                clean_summary[key] = value
        if "severity_counts" in summary:
            counts = summary["severity_counts"]
            if not isinstance(counts, dict) or len(counts) > 12:
                raise ValueError("Hunt severity counts are invalid.")
            clean_counts = {}
            for key, value in counts.items():
                safe_key = cls._safe_hunt_text(key, max_chars=40)
                if type(value) is not int or not 0 <= value <= 1_000_000:
                    raise ValueError("Hunt severity counts must be bounded integers.")
                clean_counts[safe_key] = value
            clean_summary["severity_counts"] = clean_counts
        if "scanners_run" in summary:
            names = summary["scanners_run"]
            if not isinstance(names, list) or len(names) > 20:
                raise ValueError("Hunt scanner names are invalid.")
            clean_summary["scanners_run"] = [
                cls._safe_hunt_text(name, max_chars=80) for name in names
            ]
        clean_findings: list[dict[str, str]] = []
        for row in findings:
            if not isinstance(row, dict) or set(row) - _HUNT_FINDING_FIELDS:
                raise ValueError("Hunt finding contains unsupported fields.")
            clean_findings.append({
                key: cls._safe_hunt_text(value, max_chars=600 if key in {
                    "observation", "negative_control", "limitations"
                } else 240)
                for key, value in row.items()
            })
        payload = {
            "run_id": cls._safe_hunt_text(run_id, max_chars=100),
            "summary": clean_summary,
            "findings": clean_findings,
        }
        encoded = json.dumps({"snapshot": payload}, ensure_ascii=True, allow_nan=False)
        if len(encoded.encode("utf-8")) > _MAX_ARGUMENT_BYTES:
            raise ValueError("Hunt snapshot is too large.")
        return payload

    def call_approved_hunt_tool(
        self, server: str, tool: str, snapshot: dict[str, Any], *,
        permit_token: str, target: str, scope: str, run_id: str, stopped: bool = False,
    ) -> dict[str, Any]:
        """One opt-in, approved evidence-analysis call bound to a concrete hunt.

        This cannot constrain requests made by an external server. The caller
        must only opt in a tool whose implementation and engagement controls the
        operator has reviewed. The result remains untrusted and cannot prove a
        finding or authorize another action.
        """
        if stopped:
            return self._error("Hunt was stopped before MCP analysis.")
        if not isinstance(permit_token, str) or not permit_token:
            return self._error("A run-scoped MCP permit is required.")
        try:
            shaped = self._hunt_snapshot(snapshot, run_id=run_id)
        except (ValueError, TypeError, RecursionError) as exc:
            return self._error(str(exc))
        try:
            with self._lock:
                permit = self._hunt_permits.get(permit_token)
                if (not permit or permit["expires_at"] <= time.monotonic()
                        or permit["calls_remaining"] <= 0
                        or any(permit[key] != value for key, value in {
                            "server": server, "tool": tool, "target": target,
                            "scope": scope, "run_id": run_id,
                        }.items())):
                    return self._error("MCP hunt permit is expired, exhausted, or does not match this run.")
                record = next((item for item in self._load() if item["name"] == server), None)
                if (not record or not record["enabled"]
                        or not self._launch_target_is_current(record)
                        or self._server_fingerprint(record) != permit["server_fingerprint"]):
                    return self._error("MCP server settings changed; approval is no longer valid.")
                approved = any(
                    item["server"] == server and item["tool"] == tool
                    and item["evidence_only"] is True
                    and item["server_fingerprint"] == permit["server_fingerprint"]
                    for item in self._load_hunt_approvals()
                )
                if not approved:
                    return self._error("This MCP tool is no longer approved for hunt analysis.")
                # Reserve before starting the external server. A timeout, busy
                # operation, or ambiguous failure must not grant an extra retry.
                permit["calls_remaining"] -= 1
        except (OSError, ValueError):
            return self._error("MCP hunt approval could not be verified.")
        result = self._run_once(
            record, "call", tool, {"snapshot": shaped}, require_enabled=True,
            require_hunt_approval=True,
        )
        if not result.get("ok") and "error" in result:
            return {**result, "server": server, "tool": tool, "auto_hunt": True}
        if "error" in result:
            return {**result, "server": server, "tool": tool, "auto_hunt": True}
        if result.get("is_error"):
            return {**self._error("MCP server marked the analysis as an error."),
                    "server": server, "tool": tool, "auto_hunt": True}
        content: list[dict[str, str]] = []
        total = 0
        for block in (result.get("content") or [])[:8]:
            if not isinstance(block, dict) or block.get("type") != "text":
                continue
            raw = str(block.get("text") or "")
            if sensitive_data.classify(raw):
                return self._error("MCP result contained sensitive information; automatic analysis stopped.")
            value = redact_text(raw)[0][:4000 - total]
            content.append({"type": "text", "text": value})
            total += len(value)
            if total >= 4000:
                break
        return {
            "ok": True, "server": server, "tool": tool, "auto_hunt": True,
            "content": content, "is_error": bool(result.get("is_error")),
            "truncated": bool(result.get("truncated")) or total >= 4000,
        }
