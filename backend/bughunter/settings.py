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
- GREYIQ_ACTIVE_MAX_REQUESTS_PER_HOST : hard ceiling of active-verification requests
  the per-host governor allows (default 20).
- GREYIQ_ACTIVE_MIN_INTERVAL_MS : minimum delay between active requests to one host
  (default 500 ms).
- GREYIQ_ACTIVE_SCAN_ALLOWLIST : comma-separated host suffixes that count as in-scope
  for ACTIVE verification even if not named in the hunt's scope text (default empty).
- GREYIQ_ACTIVE_TIME_SQLI_DELAY_S : the bounded SLEEP() the opt-in time-based blind-SQLi
  probe injects, in seconds (default 4; must stay < GREYIQ_WEB_FETCH_TIMEOUT). Raise it for
  jittery targets.
- GREYIQ_ACTIVE_TIME_SQLI_MARGIN_S : how much slower (seconds) BOTH trial probes must be vs
  the fast controls before the probe is confirmed (default 3; keep well under the delay).
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


def _suffixes_env(name: str) -> tuple[str, ...]:
    raw = os.getenv(name) or ""
    return tuple(part.strip().lower().lstrip(".") for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class ScannerSettings:
    code_scan_base_path: str = ""
    allow_private_urls: bool = False
    web_allowed_ports: frozenset[int] = field(default_factory=lambda: _DEFAULT_PORTS)
    web_fetch_timeout_seconds: float = 8.0
    web_fetch_max_bytes: int = 3_000_000
    active_max_requests_per_host: int = 20
    active_min_interval_ms: int = 500
    active_scan_allowlist: tuple[str, ...] = ()
    active_time_sqli_delay_seconds: float = 4.0
    active_time_sqli_margin_seconds: float = 3.0
    # Iterative hunt loop (the AI-driven reactive pass): OFF by default (opt-in) — it adds a brain
    # round-trip per re-plan, so it should only run when the operator turns it on. Bounded by
    # max-iters AND the shared per-host governor + the single hunt's request budget (never expanded).
    hunt_loop_enabled: bool = False
    hunt_loop_max_iters: int = 3
    # Per-request exclusion filter (NOT sourced from env -- callers that resolve a
    # saved portfolio program build a settings override via dataclasses.replace() with
    # that program's out_of_scope_hosts). Checked first, and can only ever NARROW scope
    # -- never an expansion, so an empty default is always safe.
    excluded_hosts: tuple[str, ...] = ()


def get_settings() -> ScannerSettings:
    return ScannerSettings(
        code_scan_base_path=os.getenv("GREYIQ_CODE_SCAN_BASE_PATH", "").strip(),
        allow_private_urls=_bool_env("GREYIQ_SCAN_ALLOW_PRIVATE_URLS", False),
        web_allowed_ports=_ports_env("GREYIQ_WEB_ALLOWED_PORTS", _DEFAULT_PORTS),
        web_fetch_timeout_seconds=_float_env("GREYIQ_WEB_FETCH_TIMEOUT", 8.0),
        web_fetch_max_bytes=_int_env("GREYIQ_WEB_FETCH_MAX_BYTES", 3_000_000),
        active_max_requests_per_host=_int_env("GREYIQ_ACTIVE_MAX_REQUESTS_PER_HOST", 20),
        active_min_interval_ms=_int_env("GREYIQ_ACTIVE_MIN_INTERVAL_MS", 500),
        active_scan_allowlist=_suffixes_env("GREYIQ_ACTIVE_SCAN_ALLOWLIST"),
        active_time_sqli_delay_seconds=_float_env("GREYIQ_ACTIVE_TIME_SQLI_DELAY_S", 4.0),
        active_time_sqli_margin_seconds=_float_env("GREYIQ_ACTIVE_TIME_SQLI_MARGIN_S", 3.0),
        hunt_loop_enabled=_bool_env("GREYIQ_HUNT_LOOP_ENABLED", False),
        hunt_loop_max_iters=max(1, min(_int_env("GREYIQ_HUNT_LOOP_MAX_ITERS", 3), 6)),
    )
