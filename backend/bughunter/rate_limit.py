"""Frozen-safe per-host request governor for the active verification layer.

The active verifier (active_verify_service.py) sends a small number of crafted,
non-destructive requests at an authorized target. This governor makes "we promise
it's gentle" an *enforced* budget rather than a comment: a process-wide token
bucket per registrable host caps how many active requests can ever hit one host,
and a minimum inter-request interval spaces them out so the layer can never burst.

Pure / dependency-free / frozen-safe: stdlib only, a monotonic clock (no wall
clock, no external state, no background threads). Thread-safe via a single lock.
Defaults only ever REDUCE what the active layer may do.
"""

from __future__ import annotations

import threading
import time


# Loopback literals + the reserved name. Kept as a prefix/exact test rather than an ipaddress parse:
# throttle() runs on every single request and the host here is already the resolved, lowercased
# hostname, so this stays allocation-free and total on any input (including "").
_LOOPBACK_NAMES = frozenset({"localhost", "::1", "[::1]", "0:0:0:0:0:0:0:1"})


def _is_loopback(host: str) -> bool:
    """True for a 127.0.0.0/8 dotted-quad, the IPv6 loopback, and the reserved name 'localhost'.

    Matched as a full dotted-quad rather than a "127." prefix: a prefix test also accepts a REGISTRABLE
    name like "127.example.com", which anyone can own, and would hand that host the exemption. Getting
    this wrong costs politeness rather than safety (the token bucket bounds volume either way), but a
    pacing exemption should never be something an attacker can name themselves. Unrecognised input
    simply gets the normal pacing, so the failure direction is the polite one.
    """
    if host in _LOOPBACK_NAMES:
        return True
    octets = host.split(".")
    return (len(octets) == 4 and octets[0] == "127"
            and all(o.isdigit() and len(o) <= 3 and int(o) <= 255 for o in octets))


class HostRateGovernor:
    """A token bucket + minimum-interval gate, keyed by host.

    ``capacity`` is the hard ceiling of active requests a single host can absorb
    before the bucket is empty; it refills slowly so repeated hunts self-heal
    without ever allowing a burst within one hunt. ``min_interval_s`` is the floor
    between two sends to the same host — ``throttle`` sleeps the (bounded) remainder
    so callers stay synchronous and simple.
    """

    def __init__(self, capacity: int = 20, min_interval_s: float = 0.5, refill_per_s: float = 0.5) -> None:
        self.capacity = max(1, int(capacity))
        self.min_interval_s = max(0.0, float(min_interval_s))
        self.refill_per_s = max(0.0, float(refill_per_s))
        self._lock = threading.Lock()
        # host -> {"tokens": float, "last_refill": monotonic, "next_send": monotonic}
        self._buckets: dict[str, dict[str, float]] = {}

    def throttle(self, host: str) -> bool:
        """Reserve one request slot for ``host``. Returns False (send nothing) when
        the per-host bucket is exhausted; otherwise spaces the send by the minimum
        interval (sleeping the bounded remainder) and returns True.

        The interval is waived for LOOPBACK only. It exists to be gentle with somebody else's
        server — a bug-bounty target, a staging box, a third party — and the machine this process is
        already running on is none of those. The token bucket still applies unchanged, so the volume
        cap (the part that actually bounds what a host absorbs) is identical either way; only the
        pacing is dropped, and only where there is no one to pace for. Reaching loopback at all
        already requires the operator to have set GREYIQ_SCAN_ALLOW_PRIVATE_URLS."""
        key = (host or "").strip().lower()
        interval = 0.0 if _is_loopback(key) else self.min_interval_s
        with self._lock:
            now = time.monotonic()
            state = self._buckets.get(key)
            if state is None:
                state = {"tokens": float(self.capacity), "last_refill": now, "next_send": now}
                self._buckets[key] = state
            # Refill since the last touch, capped at capacity.
            state["tokens"] = min(float(self.capacity), state["tokens"] + (now - state["last_refill"]) * self.refill_per_s)
            state["last_refill"] = now
            if state["tokens"] < 1.0:
                return False
            state["tokens"] -= 1.0
            # Schedule this send no sooner than min_interval after the previously
            # scheduled one, so concurrent callers still serialize gently.
            send_at = max(now, state["next_send"])
            state["next_send"] = send_at + interval
            wait = send_at - now
        if wait > 0:
            # Sleep the FULL reserved remainder, not min(wait, min_interval_s):
            # capping at one interval let concurrent callers holding far-future
            # slots (2..N intervals out) all wake after a single interval and fire
            # together, collapsing the per-host floor into a per-thread one and
            # bursting N requests at one host per tick. The token bucket already
            # bounds total volume, so honoring the full wait is safe.
            time.sleep(wait)
        return True

    def remaining(self, host: str) -> int:
        """Approximate tokens left for ``host`` (for reporting; not a reservation)."""
        key = (host or "").strip().lower()
        with self._lock:
            state = self._buckets.get(key)
            if state is None:
                return self.capacity
            now = time.monotonic()
            tokens = min(float(self.capacity), state["tokens"] + (now - state["last_refill"]) * self.refill_per_s)
            return int(tokens)


# Process-wide governors, keyed by config, so the per-host politeness cap is truly PROCESS-WIDE (as
# the module docstring promises) rather than per-hunt. Concurrent hunts — a span's parallel URL
# workers, a portfolio's parallel programs — that each build their OWN governor multiply the effective
# per-host budget by the worker count, risking WAF/IP bans and breaching an avoid_dos VDP policy.
_shared_lock = threading.Lock()
_shared_governors: dict[tuple[int, float, float], "HostRateGovernor"] = {}


def shared_governor(capacity: int = 20, min_interval_s: float = 0.5, refill_per_s: float = 0.5,
                    pool: str = "") -> "HostRateGovernor":
    """Return a PROCESS-WIDE HostRateGovernor for this config so every concurrent hunt hitting the same
    registrable host draws from ONE token bucket. The governor already keys its buckets by host
    internally, so a single instance spans every host. Keyed by config: a differently-tuned caller
    gets its own shared instance; identical config -> the same instance. Thread-safe.

    ``pool`` namespaces the bucket: two callers with the SAME config but a DIFFERENT pool get
    SEPARATE process-wide governors. This keeps the passive-recon crawl (pool='recon') from draining
    the SAME per-host token bucket the active prover uses (pool=''): the recon and active layers are
    sized independently, so sharing one bucket lets a crawl starve the active pass of every token
    (no probes fire, no findings). Recon workers still share ONE 'recon' bucket per host across
    concurrent span/portfolio targets, which is the multi-worker rate-multiplication this guards."""
    cfg = (max(1, int(capacity)), max(0.0, float(min_interval_s)), max(0.0, float(refill_per_s)))
    key = (str(pool), *cfg)
    with _shared_lock:
        gov = _shared_governors.get(key)
        if gov is None:
            gov = HostRateGovernor(*cfg)
            _shared_governors[key] = gov
        return gov
