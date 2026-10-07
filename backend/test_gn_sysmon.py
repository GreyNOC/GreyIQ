"""The system strip may be wrong about nothing and unavailable about anything.

``gn_sysmon`` feeds three numbers to a dashboard that sits in front of a live hunt, which makes two
failures interesting and the rest cosmetic:

  * **A plausible lie.** The CPU counters on the primary target periodically move impossibly — the
    idle counter goes backwards, or the total jumps eight times further than wall time allows — and
    the natural fix (clamp to 0-100) turns those into readings an operator cannot tell from real
    load. The gate that rejects them is on the DENOMINATOR, so it has to be pinned from both sides:
    an impossible delta is refused even when its percentage looks sane, and a pinned CPU is still
    reported as 100% rather than refused as implausible.
  * **A raise.** A probe that throws must retire itself and leave a ``None`` hole, once, not throw
    four times a second at the hunt. ``None`` renders ``--``; zero would be a claim.

CI is ubuntu-latest and the primary runtime target is Windows, so the Linux ``/proc`` parsers are
driven as pure functions over synthetic file contents (patching ``open``) and therefore run on both,
and the gate is driven with synthetic counter pairs and a clock we own rather than with ``sleep``.
"""
from __future__ import annotations

import builtins
import contextlib
import io
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_sysmon  # noqa: E402

#: The contract the strip renders. Every one of these is present on every sample, whatever failed.
_KEYS = {
    "cpu_percent", "cpu_count",
    "mem_used", "mem_total", "mem_percent",
    "disk_used", "disk_total", "disk_percent", "disk_path",
}

# A /proc/stat with guest (30) and guest_nice (4) deliberately non-zero: they are already counted
# inside user and nice, so a parser that sums all ten fields reports a larger total than this one.
_STAT_A = b"cpu  100 10 50 1000 20 5 5 2 30 4\ncpu0 1 1 1 1 1 1 1 1 1 1\n"
_STAT_B = b"cpu  200 10 100 1400 20 5 5 2 60 4\ncpu0 1 1 1 1 1 1 1 1 1 1\n"
_MEMINFO = (b"MemTotal:       16384000 kB\nMemFree:          512000 kB\n"
            b"MemAvailable:    8192000 kB\nBuffers:          100000 kB\n"
            b"Cached:          4000000 kB\n")
_MEMINFO_OLD = (b"MemTotal:       16384000 kB\nMemFree:          512000 kB\n"
                b"Buffers:          100000 kB\nCached:          4000000 kB\n")


@contextlib.contextmanager
def _proc(**files: bytes):
    """Serve synthetic ``/proc`` files to the parsers, so they are testable off Linux.

    The parsers are the only thing in the module that touches the filesystem by a fixed path, and
    CI never runs on the platform the rest of the module targets. Patching ``open`` is what lets one
    assertion cover both: the Linux branch is exercised from Windows and from ubuntu alike.
    """
    real_open = builtins.open
    payload = {"/proc/" + name: data for name, data in files.items()}

    def fake_open(path, *args, **kwargs):
        if str(path) in payload:
            return io.BytesIO(payload[str(path)])
        return real_open(path, *args, **kwargs)

    with mock.patch.object(builtins, "open", fake_open):
        yield


class _Clock:
    """A monotonic clock we own. The gate divides by elapsed time; ``sleep`` cannot pin that."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now


class _Counters:
    """A CPU probe driven by hand: returns whatever ``value`` holds, and counts the calls."""

    def __init__(self, value: tuple[int, int] | None) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> tuple[int, int] | None:
        self.calls += 1
        return self.value


class LinuxProcParserTests(unittest.TestCase):
    """The ``/proc`` parsers, as pure functions over file contents."""

    def test_the_cpu_line_sums_the_first_eight_fields_and_not_the_guest_columns(self) -> None:
        # guest/guest_nice are already inside user/nice; summing all ten double-counts them.
        with _proc(stat=_STAT_A):
            self.assertEqual(gn_sysmon._linux_cpu(), (172, 1192))
        self.assertNotEqual(1192, 100 + 10 + 50 + 1000 + 20 + 5 + 5 + 2 + 30 + 4,
                            "the fixture must have non-zero guest columns or it pins nothing")

    def test_two_readings_give_the_hand_computed_percentage(self) -> None:
        with _proc(stat=_STAT_A):
            first = gn_sysmon._linux_cpu()
        with _proc(stat=_STAT_B):
            second = gn_sysmon._linux_cpu()
        self.assertEqual((first, second), ((172, 1192), (322, 1742)))
        d_busy, d_total = second[0] - first[0], second[1] - first[1]
        self.assertEqual((d_busy, d_total), (150, 550))
        self.assertAlmostEqual(100.0 * d_busy / d_total, 27.2727, places=3)

    def test_iowait_is_idle_and_steal_is_busy(self) -> None:
        # A guest whose CPU was taken away was not idle: the work did not happen, but the wall clock
        # says it was unavailable, and reporting that as idle hides the only symptom of a noisy host.
        with _proc(stat=b"cpu  0 0 0 0 0 0 0 100\n"):
            self.assertEqual(gn_sysmon._linux_cpu(), (100, 100), "steal was counted as idle")
        with _proc(stat=b"cpu  0 0 0 0 100 0 0 0\n"):
            self.assertEqual(gn_sysmon._linux_cpu(), (0, 100), "iowait was counted as busy")

    def test_a_stat_file_with_no_aggregate_cpu_line_is_unavailable(self) -> None:
        with _proc(stat=b"intr 123 456\n"):
            self.assertIsNone(gn_sysmon._linux_cpu())

    def test_a_truncated_cpu_line_is_unavailable_rather_than_a_wrong_idle_column(self) -> None:
        # Without the length check, fields[3]/fields[4] would IndexError or read the wrong column.
        with _proc(stat=b"cpu  1 2 3\n"):
            self.assertIsNone(gn_sysmon._linux_cpu())

    def test_meminfo_prefers_memavailable(self) -> None:
        with _proc(meminfo=_MEMINFO):
            self.assertEqual(gn_sysmon._linux_mem(),
                             ((16384000 - 8192000) * 1024, 16384000 * 1024))

    def test_meminfo_falls_back_to_free_plus_cached_on_a_pre_3_14_kernel(self) -> None:
        # MemFree alone would report a warm-cached, perfectly healthy box as nearly out of memory.
        with _proc(meminfo=_MEMINFO_OLD):
            self.assertEqual(gn_sysmon._linux_mem(),
                             ((16384000 - 4512000) * 1024, 16384000 * 1024))

    def test_meminfo_without_a_usable_total_is_unavailable_not_zero(self) -> None:
        for body in (b"Committed_AS: 5 kB\n", b"MemTotal: 0 kB\nMemAvailable: 0 kB\n", b""):
            with self.subTest(body=body):
                with _proc(meminfo=body):
                    self.assertIsNone(gn_sysmon._linux_mem())


class CpuPlausibilityGateTests(unittest.TestCase):
    """The gate, driven with synthetic counter pairs on a clock we own.

    ``hz=100`` jiffies over ``cpus=4`` means the counters may advance by exactly 400 per second of
    wall time, whatever the load. Every number below is derived from that.
    """

    def setUp(self) -> None:
        self.clock = _Clock()
        self.counters = _Counters((1_000, 5_000))
        for name, value in (("_pick_cpu_probe", lambda: (self.counters, 100.0)),
                            ("_pick_mem_probe", lambda: None),
                            ("_logical_cpus", lambda: 4),
                            ("time", self.clock)):
            patcher = mock.patch.object(gn_sysmon, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # The constructor primes the counters, so the anchor below is a known (t, busy, total).
        self.sampler = gn_sysmon.SystemSampler(disk_path=str(BACKEND_DIR))
        self.assertEqual(self.sampler._prev, (1000.0, 1_000, 5_000))

    def _tick(self, after: float, busy: int, total: int) -> float | None:
        self.clock.now = 1000.0 + after
        self.counters.value = (busy, total)
        return self.sampler._read_cpu()

    def test_a_delta_the_clock_allows_is_accepted(self) -> None:
        self.assertEqual(self._tick(1.0, 1_100, 5_400), 25.0)

    def test_a_pinned_cpu_is_reported_not_refused(self) -> None:
        # The gate must not be load-sensitive: 100% busy over a legal denominator is a real reading.
        self.assertEqual(self._tick(1.0, 1_400, 5_400), 100.0)

    def test_an_eight_times_delta_is_refused_even_though_its_percentage_looks_sane(self) -> None:
        # d_total = 3200 where wall time allows 400, but d_busy/d_total is a perfectly ordinary 70%.
        # This is the case clamping to 0-100 cannot catch, and the reason the gate is on d_total: the
        # 70% has to differ from the last good reading, or accepting it and refusing it look alike.
        self.assertEqual(self._tick(1.0, 1_100, 5_400), 25.0)
        self.assertEqual(self._tick(2.0, 3_340, 8_600), 25.0,
                         "an impossible denominator was published because its percentage looked fine")

    def test_an_idle_counter_moving_backwards_is_refused(self) -> None:
        # busy = total - idle, so idle going backwards shows up as busy outrunning total: 150%.
        self.assertIsNone(self._tick(1.0, 1_600, 5_400))
        self.assertIsNone(self.sampler._cpu_percent, "an impossible reading was published")

    def test_counters_that_go_backwards_entirely_are_refused(self) -> None:
        self.assertEqual(self._tick(1.0, 1_100, 5_400), 25.0)
        self.assertEqual(self._tick(2.0, 900, 4_900), 25.0)

    def test_the_anchor_is_re_set_on_rejection_so_the_next_delta_is_clean(self) -> None:
        self.assertEqual(self._tick(1.0, 1_100, 5_400), 25.0)
        self.assertEqual(self._tick(2.0, 3_340, 8_600), 25.0)      # rejected: 8x denominator
        self.assertEqual(self.sampler._prev, (1002.0, 3_340, 8_600),
                         "the rejected reading was not adopted as the anchor")
        # Measured from the rejected reading this is 400 ticks over 1s — legal, and 50% busy. Had the
        # anchor been left behind, the next delta would span 3600 ticks over 2s and be refused too,
        # so the strip would stay stuck on a stale number instead of recovering within a tick.
        self.assertEqual(self._tick(3.0, 3_540, 9_000), 35.0)      # EMA: 0.4*50 + 0.6*25

    def test_the_anchor_is_kept_on_the_too_soon_path(self) -> None:
        self.assertEqual(self._tick(1.0, 1_100, 5_400), 25.0)
        self.assertEqual(self._tick(1.05, 1_105, 5_420), 25.0, "a 50 ms sliver was divided by")
        self.assertEqual(self.sampler._prev, (1001.0, 1_100, 5_400),
                         "a tick too close to divide by replaced the anchor it should have kept")
        # Windows accounts CPU against a ~15.6 ms tick, so a 50 ms window is a handful of ticks and
        # the percentage swings wildly; keeping the older anchor is what makes the next one real.
        self.assertEqual(self._tick(1.5, 1_150, 5_600), 25.0)

    def test_the_first_reading_after_construction_has_no_delta_and_says_so(self) -> None:
        fresh = gn_sysmon.SystemSampler(disk_path=str(BACKEND_DIR))
        self.assertIsNone(fresh.sample()["cpu_percent"],
                          "a percentage was invented before there were two counters to subtract")


class ProbeFailureTests(unittest.TestCase):
    """A dead probe costs one exception for the life of the process, and renders ``--``."""

    def _boom(self) -> tuple[int, int]:
        self.raises += 1
        raise OSError("simulated kernel32 failure")

    def setUp(self) -> None:
        self.raises = 0

    def test_a_raising_probe_still_returns_all_nine_keys_and_is_retired(self) -> None:
        for name, value in (("_pick_cpu_probe", lambda: (self._boom, 1e7)),
                            ("_pick_mem_probe", lambda: self._boom)):
            patcher = mock.patch.object(gn_sysmon, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        gone = os.path.join(str(BACKEND_DIR), "no-such-volume-for-gn-sysmon", "nope")
        sampler = gn_sysmon.SystemSampler(disk_path=gone)   # the constructor primes, and so raises

        reading = sampler.sample()
        self.assertEqual(set(reading), _KEYS, "the strip would KeyError on a missing cell")
        for key in ("cpu_percent", "mem_used", "mem_total", "mem_percent",
                    "disk_used", "disk_total", "disk_percent"):
            self.assertIsNone(reading[key], f"{key} was zero, which is a claim, instead of None")
        self.assertEqual(reading["disk_path"], gone, "the cell must name the volume it is about")

        sampler.sample()
        sampler.sample()
        self.assertIsNone(sampler._cpu_probe)
        self.assertIsNone(sampler._mem_probe)
        self.assertEqual(self.raises, 2,
                         "a dead probe was retried on the ticker instead of being retired: "
                         "one exception per process, not four a second")

    def test_a_probe_that_answers_none_is_retired_too(self) -> None:
        # GetSystemTimes returning FALSE is not a transient: it means this host will not tell us.
        counters = _Counters(None)
        patcher = mock.patch.object(gn_sysmon, "_pick_cpu_probe", lambda: (counters, 1e7))
        patcher.start()
        self.addCleanup(patcher.stop)
        sampler = gn_sysmon.SystemSampler(disk_path=str(BACKEND_DIR))
        self.assertIsNone(sampler.sample()["cpu_percent"])
        self.assertIsNone(sampler._cpu_probe)
        self.assertEqual(counters.calls, 1)

    def test_malformed_proc_content_is_caught_by_the_sampler_not_by_the_hunt(self) -> None:
        # The parsers int() their fields; a truncated or non-numeric /proc read raises there, and the
        # sampler's guard is what stops that reaching the caller. Pin where the guard lives.
        patcher = mock.patch.object(gn_sysmon, "_pick_mem_probe", lambda: gn_sysmon._linux_mem)
        patcher.start()
        self.addCleanup(patcher.stop)
        with _proc(meminfo=b"MemTotal:       banana kB\n"):
            sampler = gn_sysmon.SystemSampler(disk_path=str(BACKEND_DIR))
            reading = sampler.sample()
        self.assertEqual((reading["mem_used"], reading["mem_total"], reading["mem_percent"]),
                         (None, None, None))
        self.assertIsNone(sampler._mem_probe)

    def test_a_disk_that_cannot_be_read_is_unavailable_not_full_and_not_empty(self) -> None:
        sampler = gn_sysmon.SystemSampler(disk_path=os.path.join(str(BACKEND_DIR), "not-a-dir", "x"))
        reading = sampler.sample()
        self.assertEqual((reading["disk_used"], reading["disk_total"], reading["disk_percent"]),
                         (None, None, None))


class DiskTargetTests(unittest.TestCase):
    """The strip measures the volume the hunt writes evidence to, and names the one it measured."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="gn-sysmon-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        modules = mock.patch.dict(sys.modules)
        modules.start()
        self.addCleanup(modules.stop)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        sys.modules.pop("gn_cli", None)
        os.environ.pop("GREYIQ_RUNTIME_DIR", None)

    def test_the_default_volume_is_the_runtime_dir_gn_cli_already_resolved(self) -> None:
        # Not C:. A hunt does not die when the system volume fills, it dies when runtime/ does.
        sys.modules["gn_cli"] = types.SimpleNamespace(RUNTIME_DIR=Path(self.tmp))
        self.assertEqual(gn_sysmon._default_disk_path(), self.tmp)
        self.assertEqual(gn_sysmon.SystemSampler().sample()["disk_path"], self.tmp)

    def test_the_env_var_is_read_when_gn_cli_is_not_loaded(self) -> None:
        # The desktop app relocates the whole runtime into userData with exactly this variable.
        os.environ["GREYIQ_RUNTIME_DIR"] = self.tmp
        self.assertEqual(gn_sysmon._default_disk_path(), self.tmp)

    def test_gn_cli_is_never_imported_for_this(self) -> None:
        # Importing it would reconfigure the caller's stdout/stderr (gn_cli.py:62-66); a sampler does
        # not get to have opinions about the caller's streams.
        os.environ["GREYIQ_RUNTIME_DIR"] = self.tmp
        gn_sysmon._default_disk_path()
        self.assertNotIn("gn_cli", sys.modules)

    def test_a_runtime_dir_that_does_not_exist_yet_measures_its_nearest_existing_ancestor(self) -> None:
        # On a fresh checkout runtime/ is created by the first hunt. disk_usage raises on a missing
        # path, so without this the cell would read "--" for the life of the process — and every
        # ancestor is on the same volume, so the number is the same one.
        os.environ["GREYIQ_RUNTIME_DIR"] = os.path.join(self.tmp, "runtime", "not", "yet")
        picked = gn_sysmon._default_disk_path()
        self.assertEqual(picked, self.tmp)
        shutil.disk_usage(picked)   # raises if the fallback is not actually usable

    def test_the_last_resort_is_a_volume_that_exists(self) -> None:
        self.assertEqual(gn_sysmon._default_disk_path(), "C:\\" if os.name == "nt" else "/")
        shutil.disk_usage(gn_sysmon._default_disk_path())

    def test_an_unusable_runtime_setting_still_yields_a_readable_disk(self) -> None:
        for value in ("", "   ", "C:\\<>|"):
            with self.subTest(value=value):
                os.environ["GREYIQ_RUNTIME_DIR"] = value
                reading = gn_sysmon.SystemSampler().sample()
                self.assertIsNotNone(reading["disk_total"])


class ShapeAndTotalityTests(unittest.TestCase):
    """What the renderer is allowed to assume, asserted against this host, whatever host it is."""

    def test_every_sample_carries_exactly_the_nine_documented_keys(self) -> None:
        sampler = gn_sysmon.SystemSampler()
        for _ in range(3):
            self.assertEqual(set(sampler.sample()), _KEYS)

    def test_nothing_this_host_reports_is_out_of_range(self) -> None:
        sampler = gn_sysmon.SystemSampler()
        for _ in range(3):
            reading = sampler.sample()
            for key in ("cpu_percent", "mem_percent", "disk_percent"):
                value = reading[key]
                if value is not None:
                    self.assertGreaterEqual(value, 0.0, key)
                    self.assertLessEqual(value, 100.0, key)
            for key in ("mem_used", "mem_total", "disk_used", "disk_total"):
                if reading[key] is not None:
                    self.assertGreaterEqual(reading[key], 0, key)

    def test_percent_refuses_to_divide_by_an_unknown_total(self) -> None:
        self.assertIsNone(gn_sysmon._percent(5, None))
        self.assertIsNone(gn_sysmon._percent(5, 0))
        self.assertIsNone(gn_sysmon._percent(None, 100))
        self.assertEqual(gn_sysmon._percent(50, 200), 25.0)
        self.assertEqual(gn_sysmon._percent(300, 200), 100.0, "a percentage must not exceed 100")

    def test_a_sampler_with_every_probe_dead_still_answers(self) -> None:
        sampler = gn_sysmon.SystemSampler(disk_path=str(BACKEND_DIR))
        sampler._cpu_probe = None
        sampler._mem_probe = None
        sampler._disk_path = os.path.join(str(BACKEND_DIR), "gone")
        sampler._disk, sampler._disk_at = None, 0.0
        reading = sampler.sample()
        self.assertEqual(set(reading), _KEYS)
        self.assertIsNone(reading["cpu_percent"])

    def test_the_logical_cpu_count_prefers_affinity_over_the_box(self) -> None:
        # A cpuset-pinned container has fewer CPUs than the host, and the gate divides by this: use
        # the box's count there and every legal delta looks a quarter the size it should be.
        with mock.patch.object(gn_sysmon.os, "sched_getaffinity", lambda _pid: {0, 1}, create=True), \
             mock.patch.object(gn_sysmon.os, "cpu_count", lambda: 16):
            self.assertEqual(gn_sysmon._logical_cpus(), 2)

    def test_the_cpu_count_falls_back_to_the_box_where_there_is_no_affinity_call(self) -> None:
        # Windows, which is the primary runtime target and has no sched_getaffinity at all.
        with mock.patch.object(gn_sysmon.os, "sched_getaffinity", None, create=True), \
             mock.patch.object(gn_sysmon.os, "cpu_count", lambda: 9):
            self.assertEqual(gn_sysmon._logical_cpus(), 9)

    def test_disk_is_cached_between_ticks_rather_than_stat_ed_four_times_a_second(self) -> None:
        clock = _Clock()
        patcher = mock.patch.object(gn_sysmon, "time", clock)
        patcher.start()
        self.addCleanup(patcher.stop)
        calls = []
        real_usage = shutil.disk_usage

        def counting(path):
            calls.append(path)
            return real_usage(path)

        with mock.patch.object(gn_sysmon.shutil, "disk_usage", counting):
            sampler = gn_sysmon.SystemSampler(disk_path=str(BACKEND_DIR))
            for _ in range(8):
                clock.now += 0.25
                sampler.sample()
            self.assertEqual(len(calls), 1, "the dearest probe was re-run inside its cache window")
            clock.now += gn_sysmon._DISK_INTERVAL_SECONDS
            sampler.sample()
            self.assertEqual(len(calls), 2, "the cache never expires, so a filling disk is invisible")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
