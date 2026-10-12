"""Host CPU/RAM/disk for the ``gn`` dashboard's system strip — stdlib only, and never a reason to fail.

The dashboard's whole claim is that an operator can watch a hunt without leaving the terminal. A
hunt that stalls because the box is swapping, or because the disk holding ``runtime/`` filled up
mid-capture, looks identical to a hunt that stalled on a slow target — so the strip exists to tell
those apart at a glance. It is three numbers, not a monitoring product.

``psutil`` would be the obvious answer and is deliberately not used. It is a C extension, which
means a wheel per platform per Python, a PyInstaller hook, and one more thing that can fail to
import inside the frozen bundle — for three counters the OS already publishes. So: ``ctypes``
against ``kernel32`` on Windows, ``/proc`` on Linux, ``shutil`` for disk everywhere.

The same rules that bind ``gn_fx`` bind this, for the same reason — it sits in front of a security
tool and runs on a ticker thread beside a live hunt:

  * **Total.** Nothing here raises. Every probe is guarded, and a probe that fails is retired for
    the life of the process rather than retried four times a second, so a locked-down box or a
    container with no ``/proc`` costs one exception, once. An unavailable metric is ``None``, which
    the strip renders as ``--`` — never zero, because zero is a claim and ``None`` is not.
  * **Cheap.** Measured on the primary target (Windows 11, x64): ~10 us for ``GetSystemTimes``,
    ~2 us for ``GlobalMemoryStatusEx``, ~26-38 us for ``shutil.disk_usage``. Disk is by far the
    dearest and by far the slowest-moving, so it is sampled on its own long interval. Steady state
    is 22-31 us per tick — at 4 Hz, about 0.01% of one core.
  * **Stateful by necessity.** CPU percentage is a *derivative*: both platforms expose monotonic
    busy/idle counters, so a percentage needs two reads and the gap between them. That state lives
    in the sampler, which is why it is a class and not a function. The first tick after
    construction has no previous counter and so reports ``None`` rather than inventing a number.
  * **Not thread-safe by design.** One sampler belongs to one ticker thread, like one ``Scanner``
    belongs to one status line. Sharing one across threads would interleave the CPU deltas and
    produce garbage; make two.
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from typing import Any, Callable

#: Disk moves in minutes, not milliseconds, and costs ~26-38 us against ~12 us for the other two
#: combined. Re-read it this often and serve the cached value in between.
_DISK_INTERVAL_SECONDS = 5.0

#: Below this gap the CPU counters have not moved enough to divide by. Windows accounts CPU time
#: against a ~15.6 ms scheduler tick, so a 50 ms delta is quantised into single digits of ticks and
#: the percentage jitters wildly. Under this, the previous percentage is repeated.
_MIN_CPU_DELTA_SECONDS = 0.15

#: How far the observed CPU-time delta may stray from the delta wall-clock says is possible before
#: we call the counters a liar. See :meth:`SystemSampler._read_cpu` for why this gate exists at all.
_CPU_PLAUSIBLE_LO, _CPU_PLAUSIBLE_HI = 0.5, 1.5

#: EMA weight on each accepted CPU reading. The gate drops roughly a third of ticks on a lumpy host,
#: so the survivors are unevenly spaced; a light EMA keeps the sparkline readable without lagging
#: far enough behind to hide a real spike.
_CPU_SMOOTHING = 0.4


class SystemSampler:
    """Host CPU / memory / disk, sampled on demand. Construct once, call :meth:`sample` on a ticker.

    ``sample()`` always returns the same dict shape. Every measured value may be ``None``, which
    means "this host would not tell us", and is the caller's cue to render ``--``.
    """

    def __init__(self, disk_path: str | os.PathLike[str] | None = None) -> None:
        # The disk the operator actually cares about is the one the hunt writes evidence to, not C:.
        # Resolved once, here, rather than lazily inside the read: the strip labels the cell with
        # this path, and a label that does not name the volume the percentage is about is a lie.
        self._disk_path = str(disk_path) if disk_path else _default_disk_path()
        self._cpu_probe, self._cpu_hz = _pick_cpu_probe()
        self._mem_probe: Callable[[], tuple[int, int] | None] | None = _pick_mem_probe()
        self._prev: tuple[float, int, int] | None = None   # (monotonic, busy_ticks, total_ticks)
        self._cpu_percent: float | None = None
        self._disk: tuple[int, int] | None = None
        self._disk_at = 0.0
        self._cpus = _logical_cpus()
        # Prime the CPU counters now, so the first tick a quarter-second later already has a delta
        # instead of showing "--" on the panel the operator is watching appear.
        self._read_cpu()

    # --- public API ------------------------------------------------------------------------------
    def sample(self) -> dict[str, Any]:
        """One reading. Total: returns a full dict with ``None`` holes, never raises."""
        mem_used, mem_total = self._read_mem()
        disk_used, disk_total = self._read_disk()
        return {
            "cpu_percent": self._read_cpu(),      # 0.0-100.0, aggregated over all logical CPUs
            "cpu_count": self._cpus,              # int | None
            "mem_used": mem_used,                 # bytes | None
            "mem_total": mem_total,               # bytes | None
            "mem_percent": _percent(mem_used, mem_total),
            "disk_used": disk_used,               # bytes | None
            "disk_total": disk_total,             # bytes | None
            "disk_percent": _percent(disk_used, disk_total),
            "disk_path": self._disk_path,         # str - the volume the disk numbers are about
        }

    # --- internals -------------------------------------------------------------------------------
    def _read_cpu(self) -> float | None:
        """CPU busy percent across all logical CPUs, or ``None`` until a reading survives the gate.

        The gate is the interesting part, and it is here because the obvious implementation is
        measurably wrong on the primary target. Sampling ``GetSystemTimes`` at 4 Hz on a Windows 11
        box, 18% of consecutive deltas were not physically possible: the idle counter moved
        BACKWARDS, or the total moved eight times further than the elapsed wall time allows. The
        counters are not torn reads and it is not a ``GetSystemTimes`` quirk —
        ``NtQuerySystemInformation`` returns byte-identical numbers for 1.6x the cost — the host
        simply updates per-processor accounting in lumps, and a 250 ms window can catch a lump or
        miss one entirely.

        Clamping to 0-100 does not fix this, it only hides it: a delta covering a tenth of the
        expected window read 46% on a machine sitting at 2%, which clamps to a perfectly plausible,
        perfectly wrong 46%. So the check cannot be on the percentage — it has to be on the
        denominator. ``d_total`` is elapsed CPU-time summed over every core, which depends only on
        wall time and core count and NOT on load, so ``d_total / (elapsed * hz * ncpu)`` must sit
        near 1.0 whether the box is idle or pinned. Anything outside 0.5-1.5 is the counter lying,
        and the honest answer is to keep the last good number rather than publish a fresh wrong one.
        """
        if self._cpu_probe is None:
            return None
        try:
            reading = self._cpu_probe()
        except Exception:  # noqa: BLE001 - retire the probe rather than raise it at the hunt
            self._cpu_probe = None
            return None
        if reading is None:
            self._cpu_probe = None
            return None
        busy, total = reading
        now = time.monotonic()
        prev = self._prev
        self._prev = (now, busy, total)
        if prev is None:
            return None
        prev_at, prev_busy, prev_total = prev
        elapsed = now - prev_at
        if elapsed < _MIN_CPU_DELTA_SECONDS:
            self._prev = prev          # keep the older anchor; this tick was too close to divide
            return self._cpu_percent
        d_total = total - prev_total
        d_busy = busy - prev_busy
        if d_total <= 0 or d_busy < 0:
            return self._cpu_percent
        # Re-anchored above even on rejection: the next delta measures from this lumped reading and
        # is usually clean again, which is what lets the strip recover within a tick or two.
        if self._cpu_hz and self._cpus:
            expected = elapsed * self._cpu_hz * self._cpus
            if expected > 0 and not (_CPU_PLAUSIBLE_LO <= d_total / expected <= _CPU_PLAUSIBLE_HI):
                return self._cpu_percent
        percent = 100.0 * d_busy / d_total
        if not 0.0 <= percent <= 100.0:
            return self._cpu_percent
        self._cpu_percent = (percent if self._cpu_percent is None
                             else _CPU_SMOOTHING * percent + (1 - _CPU_SMOOTHING) * self._cpu_percent)
        return self._cpu_percent

    def _read_mem(self) -> tuple[int | None, int | None]:
        if self._mem_probe is None:
            return (None, None)
        try:
            reading = self._mem_probe()
        except Exception:  # noqa: BLE001
            self._mem_probe = None
            return (None, None)
        if reading is None:
            self._mem_probe = None
            return (None, None)
        used, total = reading
        return (used, total)

    def _read_disk(self) -> tuple[int | None, int | None]:
        now = time.monotonic()
        if self._disk is not None and now - self._disk_at < _DISK_INTERVAL_SECONDS:
            return self._disk
        try:
            usage = shutil.disk_usage(self._disk_path)
        except Exception:  # noqa: BLE001 - a vanished/permission-denied path is "unavailable"
            self._disk_at = now
            return (None, None)
        self._disk = (int(usage.total) - int(usage.free), int(usage.total))
        self._disk_at = now
        return self._disk


# --- shared helpers -------------------------------------------------------------------------------
def _percent(used: int | None, total: int | None) -> float | None:
    if used is None or not total:
        return None
    return max(0.0, min(100.0, 100.0 * used / total))


def _runtime_dir() -> str | None:
    """``gn_cli.RUNTIME_DIR`` if that module is loaded, without importing it.

    Importing ``gn_cli`` from here would be the wrong trade twice over: it reconfigures ``stdout``
    and ``stderr`` at import time (gn_cli.py:62-66), and a sampler is not allowed to have opinions
    about the caller's streams; and it would put a heavy module behind ``import gn_sysmon``, which
    the dashboard does on a path that already has ``gn_cli`` in ``sys.modules`` anyway — the only
    way here is through the CLI. The env var is the same one ``gn_cli`` reads, so a standalone
    import (a test, a ``python -c`` smoke check) still lands on the right volume.
    """
    runtime = getattr(sys.modules.get("gn_cli"), "RUNTIME_DIR", None)
    if runtime is None:
        runtime = os.getenv("GREYIQ_RUNTIME_DIR")
    text = str(runtime).strip() if runtime else ""
    return text or None


def _default_disk_path() -> str:
    """The volume holding ``runtime/``, not the system volume.

    A hunt does not die when ``C:`` fills, it dies when the disk it is writing evidence and reports
    to fills — and on the boxes this runs on those are routinely different: a small system SSD and
    a large data volume, or the desktop app's ``GREYIQ_RUNTIME_DIR`` pointed at ``<userData>``.
    Showing free space on the wrong one is worse than showing none, because it reads as an
    all-clear on exactly the failure the strip exists to catch.

    ``runtime/`` may not exist yet on a fresh checkout, and ``shutil.disk_usage`` raises on a path
    that is not there, which would render ``--`` for the life of the process. So walk up to the
    nearest directory that does exist: every ancestor is on the same volume, so the answer is the
    same number, and it is available immediately instead of after the first hunt creates the dir.
    """
    try:
        runtime = _runtime_dir()
        if runtime:
            path = os.path.abspath(runtime)
            while not os.path.isdir(path):
                parent = os.path.dirname(path)
                if not parent or parent == path:
                    break
                path = parent
            if os.path.isdir(path):
                return path
    except Exception:  # noqa: BLE001 - an unreadable path is not worth a traceback at the hunt
        pass
    return "C:\\" if os.name == "nt" else "/"


def _logical_cpus() -> int | None:
    """Usable logical CPUs. Affinity first: a cpuset-pinned container has fewer than the box does."""
    try:
        affinity = getattr(os, "sched_getaffinity", None)
        if affinity is not None:
            return len(affinity(0)) or None
    except Exception:  # noqa: BLE001
        pass
    try:
        return os.cpu_count()
    except Exception:  # noqa: BLE001
        return None


# --- Windows ---------------------------------------------------------------------------------------
def _pick_cpu_probe() -> tuple[Callable[[], tuple[int, int] | None] | None, float]:
    """(probe, ticks_per_second_per_cpu). The tick rate is what lets the plausibility gate work."""
    if os.name == "nt":
        return (_win_cpu(), 1e7)            # FILETIME counts 100 ns units
    if sys.platform.startswith("linux"):
        try:
            hz = float(os.sysconf("SC_CLK_TCK"))     # USER_HZ; 100 on every mainstream build
        except (ValueError, OSError, AttributeError):
            hz = 100.0
        return (_linux_cpu, hz if hz > 0 else 100.0)
    return (None, 0.0)


def _pick_mem_probe() -> Callable[[], tuple[int, int] | None] | None:
    if os.name == "nt":
        return _win_mem()
    if sys.platform.startswith("linux"):
        return _linux_mem
    return None


def _kernel32() -> Any:
    """``kernel32`` with the prototypes we use declared. Called once; ~18 us to construct.

    Note what is NOT imported: ``ctypes.wintypes``. It is the natural way to spell these structs and
    it is a trap here. ``wintypes`` is a pure-Python module, so PyInstaller only ships it if
    something in the graph imports it — and in the current bundle it is present by accident, dragged
    in by another dependency rather than by anything we declared. A dependency change could drop it
    and this module would raise ImportError in the frozen exe and nowhere else. The types are
    trivial (``DWORD`` IS ``c_ulong``, ``BOOL`` IS ``c_long``, verified: same sizes, same offsets,
    ``sizeof(MEMORYSTATUSEX) == 64`` either way), so we spell them directly and depend only on
    ``_ctypes.pyd``, which the bootloader always ships.
    """
    import ctypes

    DWORD = ctypes.c_uint32
    BOOL = ctypes.c_int

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", DWORD), ("dwHighDateTime", DWORD)]

    class MEMORYSTATUSEX(ctypes.Structure):
        # Natural alignment gives sizeof == 64 on x64 (verified). The ULONGLONGs force 8-byte
        # alignment, so there is 4 bytes of tail padding and no _pack_ is needed or wanted.
        _fields_ = [
            ("dwLength", DWORD),
            ("dwMemoryLoad", DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    lib = ctypes.WinDLL("kernel32", use_last_error=True)
    lib.GetSystemTimes.argtypes = [ctypes.POINTER(FILETIME)] * 3
    lib.GetSystemTimes.restype = BOOL
    lib.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
    lib.GlobalMemoryStatusEx.restype = BOOL
    return lib, FILETIME, MEMORYSTATUSEX, ctypes


def _win_cpu() -> Callable[[], tuple[int, int] | None] | None:
    try:
        lib, FILETIME, _MEM, ctypes = _kernel32()
    except Exception:  # noqa: BLE001
        return None
    idle, kernel, user = FILETIME(), FILETIME(), FILETIME()
    byref = ctypes.byref

    def probe() -> tuple[int, int] | None:
        if not lib.GetSystemTimes(byref(idle), byref(kernel), byref(user)):
            return None
        # FILETIME is a split 64-bit count of 100 ns units, summed over every logical CPU — so the
        # per-core normalisation is free. The trap: lpKernelTime INCLUDES lpIdleTime, so busy is
        # (kernel + user) - idle, not (kernel + user). Getting that wrong reads ~100% on an idle box.
        idle_t = (idle.dwHighDateTime << 32) | idle.dwLowDateTime
        kernel_t = (kernel.dwHighDateTime << 32) | kernel.dwLowDateTime
        user_t = (user.dwHighDateTime << 32) | user.dwLowDateTime
        total = kernel_t + user_t
        return (total - idle_t, total)

    return probe


def _win_mem() -> Callable[[], tuple[int, int] | None] | None:
    try:
        lib, _FT, MEMORYSTATUSEX, ctypes = _kernel32()
    except Exception:  # noqa: BLE001
        return None
    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    byref = ctypes.byref

    def probe() -> tuple[int, int] | None:
        # dwLength is set once above, not here: the call does NOT clobber it (verified — it reads
        # back as 64 after a successful call). It does have to be right, though. Leaving it at 0,
        # or setting it too small, fails with ERROR_INVALID_PARAMETER (87) rather than filling in
        # a partial struct, which is why the sizeof is assigned before the first call and not after.
        if not lib.GlobalMemoryStatusEx(byref(status)):
            return None
        total = int(status.ullTotalPhys)
        if total <= 0:
            return None
        return (total - int(status.ullAvailPhys), total)

    return probe


# --- Linux -----------------------------------------------------------------------------------------
def _linux_cpu() -> tuple[int, int] | None:
    """The aggregate ``cpu`` line of ``/proc/stat``, in jiffies.

    Fields after the label, in order: user nice system idle iowait irq softirq steal guest
    guest_nice. Only ``idle`` and ``iowait`` are not-busy; ``steal`` IS busy from the guest's point
    of view (the CPU was taken away). ``guest``/``guest_nice`` are already counted inside
    ``user``/``nice``, so summing all ten double-counts them — hence the slice to the first eight.
    """
    with open("/proc/stat", "rb") as handle:
        line = handle.readline()
    parts = line.split()
    if not parts or parts[0] != b"cpu":
        return None
    fields = [int(value) for value in parts[1:9]]
    if len(fields) < 5:
        return None
    total = sum(fields)
    idle = fields[3] + fields[4]          # idle + iowait
    return (total - idle, total)


def _linux_mem() -> tuple[int, int] | None:
    """``MemTotal`` and ``MemAvailable`` from ``/proc/meminfo``, in kB.

    ``MemAvailable`` (kernel 3.14+) is the honest number — it is the kernel's own estimate of what a
    new allocation could get, already accounting for reclaimable page cache. ``MemFree`` is not:
    a healthy Linux box with a warm cache reports almost no MemFree and is not short of memory.
    Fall back to ``MemFree + Cached`` only if MemAvailable is absent.
    """
    total = available = free = cached = None
    with open("/proc/meminfo", "rb") as handle:
        for raw in handle:
            key, _, rest = raw.partition(b":")
            if key == b"MemTotal":
                total = int(rest.split()[0]) * 1024
            elif key == b"MemAvailable":
                available = int(rest.split()[0]) * 1024
            elif key == b"MemFree":
                free = int(rest.split()[0]) * 1024
            elif key == b"Cached":
                cached = int(rest.split()[0]) * 1024
            if total is not None and available is not None:
                break
    if not total:
        return None
    if available is None:
        available = (free or 0) + (cached or 0)
    return (max(0, total - available), total)
