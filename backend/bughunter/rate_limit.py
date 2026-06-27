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
        interval (sleeping the bounded remainder) and returns True."""
        key = (host or "").strip().lower()
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
            state["next_send"] = send_at + self.min_interval_s
            wait = send_at - now
        if wait > 0:
            time.sleep(min(wait, self.min_interval_s))
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
