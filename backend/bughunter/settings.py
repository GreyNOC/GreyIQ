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
  the per-host governor allows (default 300). This is the process-wide politeness
  ceiling and it must stay ABOVE the per-pass budget in active_verify_service, or the
  bucket rather than the budget decides when a pass stops and the last checks in the
  suite never run. 300 seats roughly three full-budget passes, so a hunt that fans out
  to sibling endpoints on one host still draws tokens for them.
- GREYIQ_ACTIVE_MIN_INTERVAL_MS : minimum delay between active requests to one host
  (default 500 ms).
- GREYIQ_ACTIVE_SCAN_ALLOWLIST : comma-separated host suffixes that count as in-scope
  for ACTIVE verification even if not named in the hunt's scope text (default empty).
- GREYIQ_ACTIVE_TIME_SQLI_DELAY_S : the bounded SLEEP() the opt-in time-based blind-SQLi
  probe injects, in seconds (default 4; must stay < GREYIQ_WEB_FETCH_TIMEOUT). Raise it for
  jittery targets.
- GREYIQ_ACTIVE_TIME_SQLI_MARGIN_S : how much slower (seconds) BOTH trial probes must be vs
  the fast controls before the probe is confirmed (default 3; keep well under the delay).
- GREYIQ_OFFLINE_RANKER : "0" to force the hand-tuned hunt rules even when a learned
  ranker weight file is present (default on).
- GREYIQ_HUNT_LOOP_OFFLINE : "1" to opt into the offline (brain-free) iterative re-plan
  pass (default off).
- GREYIQ_HUNT_REPLAN : "1" to opt into the outer theorize->act wave — one extra bounded
  pass aimed at the (endpoint, class) the investigation cortex says would most change the
  verdict, across every scanner's findings rather than the seed URL alone (default off).
- GREYIQ_OFFLINE_REPAIR : "0" to disable the offline coder's deterministic verify->repair
  loop (default on).
- GREYIQ_OFFLINE_REPAIR_ROUNDS : repair attempts per failed edit, clamped to 0..3
  (default 2).

See ``ScannerSettings`` for why each offline flag defaults the way it does — the short
version is that none of them can widen scope or authorize a request.
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
    active_max_requests_per_host: int = 300
    active_min_interval_ms: int = 500
    active_scan_allowlist: tuple[str, ...] = ()
    active_time_sqli_delay_seconds: float = 4.0
    active_time_sqli_margin_seconds: float = 3.0
    # Iterative hunt loop (the AI-driven reactive pass): OFF by default (opt-in) — it adds a brain
    # round-trip per re-plan, so it should only run when the operator turns it on. Bounded by
    # max-iters AND the shared per-host governor + the single hunt's request budget (never expanded).
    hunt_loop_enabled: bool = False
    hunt_loop_max_iters: int = 3
    # Outer theorize -> act wave. After the first active pass, the cortex can say which
    # (endpoint, class) pair would most change the verdict — across EVERY scanner's findings,
    # not just the seed URL the iterative loop probes. This runs that plan through the same
    # gated prover once. OFF by default (opt-in), like the loop above, because it spends
    # additional requests; the shared per-host governor still caps the real ceiling either way.
    hunt_replan_enabled: bool = False
    # Passive OSINT recon enrichment (certificate-transparency subdomain seeding via crt.sh): OFF by
    # default (opt-in) — it queries a THIRD-PARTY service (the public CT logs) with the target's apex,
    # so the operator turns it on deliberately. Every CT-returned host is still scope-gated before it
    # becomes a crawl target, so enabling it can only widen discovery WITHIN scope.
    recon_osint_enabled: bool = False
    # --- Offline-brain feature flags (GREYIQ_OFFLINE_*) --------------------------------
    # These gate the LEARNED/offline layers that sit on top of the deterministic engines.
    # None of them can widen scope or authorize a request: a hunt plan is a targeting HINT
    # and the deterministic prover still owns every confirmation, so the worst case of a
    # bad flag is worse ORDERING, never an unauthorized probe. They exist as kill switches
    # because a learned component can degrade in ways a rule cannot.
    #
    # GREYIQ_OFFLINE_RANKER — the learned offline hunt ranker. ON by default because it is
    # already fail-closed at the module level (an absent/corrupt weight file falls back to
    # the hand-tuned rules), so the switch is for an operator who wants the rules even when
    # a model IS present — e.g. reproducing an older run.
    offline_ranker_enabled: bool = True
    # GREYIQ_HUNT_LOOP_OFFLINE — iterative re-plan driven by the OFFLINE planner (no brain
    # round-trip). OFF by default, mirroring hunt_loop_enabled above: extra passes cost
    # requests against the operator's per-host budget, so the operator opts in.
    hunt_loop_offline_enabled: bool = False
    # GREYIQ_OFFLINE_REPAIR — the deterministic verify->repair loop for the offline coder.
    # ON by default: it only re-runs the SAME verifier on the coder's own output through
    # ToolBox, so it can turn a failed edit into a passing one but never widens write reach.
    offline_repair_enabled: bool = True
    # GREYIQ_OFFLINE_REPAIR_ROUNDS — how many repair attempts. CLAMPED to 0..3 in
    # get_settings(): each round is a full verify pass, so a hostile or fat-fingered env
    # value must not be able to spin the loop unbounded.
    offline_repair_rounds: int = 2
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
        active_max_requests_per_host=_int_env("GREYIQ_ACTIVE_MAX_REQUESTS_PER_HOST", 300),
        active_min_interval_ms=_int_env("GREYIQ_ACTIVE_MIN_INTERVAL_MS", 500),
        active_scan_allowlist=_suffixes_env("GREYIQ_ACTIVE_SCAN_ALLOWLIST"),
        active_time_sqli_delay_seconds=_float_env("GREYIQ_ACTIVE_TIME_SQLI_DELAY_S", 4.0),
        active_time_sqli_margin_seconds=_float_env("GREYIQ_ACTIVE_TIME_SQLI_MARGIN_S", 3.0),
        hunt_loop_enabled=_bool_env("GREYIQ_HUNT_LOOP_ENABLED", False),
        hunt_loop_max_iters=max(1, min(_int_env("GREYIQ_HUNT_LOOP_MAX_ITERS", 3), 6)),
        hunt_replan_enabled=_bool_env("GREYIQ_HUNT_REPLAN", False),
        recon_osint_enabled=_bool_env("GREYIQ_RECON_OSINT", False),
        offline_ranker_enabled=_bool_env("GREYIQ_OFFLINE_RANKER", True),
        hunt_loop_offline_enabled=_bool_env("GREYIQ_HUNT_LOOP_OFFLINE", False),
        offline_repair_enabled=_bool_env("GREYIQ_OFFLINE_REPAIR", True),
        # Clamp, don't reject: an out-of-range value is a typo, not a reason to refuse to
        # start. 0 means "verify only, never repair"; 3 is the ceiling on verify passes.
        offline_repair_rounds=max(0, min(3, _int_env("GREYIQ_OFFLINE_REPAIR_ROUNDS", 2))),
    )
