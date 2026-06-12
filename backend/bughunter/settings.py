"""Settings shim for the vendored bughunter engines.

The upstream GN Slop scanner and web fetcher each read a few fields from a
global settings object that GreyIQ does not share. This shim supplies just
those fields, sourced from environment variables with safe defaults.

Env vars:
- GREYIQ_CODE_SCAN_BASE_PATH : if set, refuse any local code-scan target
  outside this absolute path. Empty (default) = no containment, matching the
  local developer-machine behavior the scanner expects.
- GREYIQ_SCAN_ALLOW_PRIVATE_URLS : "1"/"true" to allow scanning private,
  loopback, and reserved hosts (e.g. localhost staging). Default off, which
  blocks SSRF into internal networks for the web/live scanners. When enabled
  (you are testing your own infrastructure) the port allowlist is also lifted.
- GREYIQ_WEB_ALLOWED_PORTS : comma-separated ports allowed for PUBLIC hosts
  (default "80,443"). Ignored when private URLs are allowed.
- GREYIQ_WEB_FETCH_TIMEOUT : per-request fetch timeout in seconds (default 8).
- GREYIQ_WEB_FETCH_MAX_BYTES : max bytes read per fetch (default 3_000_000).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

_DEFAULT_PORTS = frozenset({80, 443})


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "") or default)
    except (TypeError, ValueError):
        return default


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "") or default)
    except (TypeError, ValueError):
        return default


def _ports_env(name: str, default: frozenset[int]) -> frozenset[int]:
    raw = os.getenv(name)
    if not raw:
        return default
    ports = {int(part.strip()) for part in raw.split(",") if part.strip().isdigit()}
    return frozenset(ports) or default


@dataclass(frozen=True)
class ScannerSettings:
    code_scan_base_path: str = ""
    allow_private_urls: bool = False
    web_allowed_ports: frozenset[int] = field(default_factory=lambda: _DEFAULT_PORTS)
    web_fetch_timeout_seconds: float = 8.0
    web_fetch_max_bytes: int = 3_000_000


def get_settings() -> ScannerSettings:
    return ScannerSettings(
        code_scan_base_path=os.getenv("GREYIQ_CODE_SCAN_BASE_PATH", "").strip(),
        allow_private_urls=_bool_env("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", False),
        web_allowed_ports=_ports_env("GREYIQ_WEB_ALLOWED_PORTS", _DEFAULT_PORTS),
        web_fetch_timeout_seconds=_float_env("GREYIQ_WEB_FETCH_TIMEOUT", 8.0),
        web_fetch_max_bytes=_int_env("GREYIQ_WEB_FETCH_MAX_BYTES", 3_000_000),
    )
