"""The dashboard's claims have to survive being wrong about the terminal, the backend and the data.

``gn_dash`` draws over a live hunt against somebody else's production host, so the properties worth
testing are the ones that would let it mislead an operator or take the hunt down with it:

  * :func:`gn_dash.render` is PURE, so the whole layout is testable as data — exactly ``size.rows``
    rows, none wider than ``size.cols``, at every reflow band, with no escape sequence anywhere in a
    frame and no glyph the chosen tier's codec cannot encode. A row that does not encode raises
    inside ``Screen._write``, which deactivates the screen: a still frame over a running hunt.
  * The derived numbers are the ones that could lie. Completion counts ``skipped`` (the built-in stat
    does not, so a stopped run would sit below 100% forever); ``candidate`` is counted, never
    inferred from ``total - confirmed``, which folds in every ``missing``; 400 findings is a CAP and
    is labelled as one rather than plotted as a plateau.
  * **The one-shape invariant**: ``LocalSource.poll`` returns the same keys the HTTP route produces,
    so the renderer cannot tell the two modes apart. Pinned here against the literal expression
    ``greyiq_api.bounty_progress`` uses, so a change to either side fails this file.
  * The attached path is driven against a REAL ``http.server`` on 127.0.0.1:0, every failure row in
    the plan's degradation table included — and it asserts that no session token is ever sent to a
    port that has not first answered ``/api/health``.
  * Nothing raises. A garbage snapshot, a dead source, a verb that explodes: all cost a message line.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gn_dash  # noqa: E402
import gn_tui  # noqa: E402

#: Which codec each tier promises its glyphs survive. cp437 is the cp850/conhost case the ``box``
#: tier exists for; ``ascii`` is the floor.
_TIER_CODECS = {"rich": "utf-8", "box": "cp437", "ascii": "ascii"}


def _tty(encoding: str = "utf-8"):
    """A StringIO that claims to be a terminal. Same shape as ``test_gn_tui._tty`` (``encoding`` is a
    class attribute because ``TextIOBase`` forbids assigning it per instance)."""

    class _Fake(io.StringIO):
        def isatty(self) -> bool:
            return True

    _Fake.encoding = encoding
    return _Fake()


def _tier(name: str = "rich") -> dict:
    for entry in gn_tui._TIERS:  # noqa: SLF001 - the tier table is the fixture
        if entry["name"] == name:
            got = dict(entry)
            got["braille"] = ""
            return got
    raise AssertionError(f"no tier named {name}")


def _state(**overrides: object) -> gn_dash.DashState:
    """A populated run: five work units in every status the engine writes, three findings across
    three proof states, two host buckets, a system sample."""
    base = dict(
        label="https://acme.com", mode="local", run_id="run-1", status="RUNNING",
        elapsed=252.0, started_epoch=1000.0, now_epoch=1300.0,
        capabilities=frozenset({"stop", "reverify", "programs", "governor"}),
        snapshot={
            "targets": [
                {"target": "https://acme.com/a", "status": "done", "findings": 2, "confirmed": 1},
                {"target": "https://acme.com/login", "status": "running"},
                {"target": "https://acme.com/api/v2/users/settings", "status": "queued"},
                {"target": "https://acme.com/err", "status": "error"},
                {"target": "https://acme.com/skip", "status": "skipped"},
            ],
            "findings": [
                {"target": "https://acme.com/a", "severity": "high", "proof": "confirmed",
                 "at": "1970-01-01T00:16:40+00:00", "ref": "F-1", "location": "https://acme.com/a"},
                {"target": "https://acme.com/a", "severity": "low", "proof": "candidate",
                 "at": "1970-01-01T00:20:00+00:00", "ref": "F-2"},
                {"target": "https://acme.com/login", "severity": "critical", "proof": "missing",
                 "at": "1970-01-01T00:21:40+00:00", "ref": "F-3"},
            ],
        },
        governor=({"pool": "", "host": "acme.com", "tokens": 612, "capacity": 700},
                  {"pool": "recon", "host": "cdn.acme.com", "tokens": 40, "capacity": 700}),
        rate=1.8, rate_history=(0.0, 1.0, 2.0, 1.8), cpu_history=(10.0, 40.0, 14.0),
        sysmon={"cpu_percent": 14.0, "mem_percent": 62.0, "disk_percent": 81.0,
                "disk_path": "/x/runtime"},
        events=[{"at": "2026-01-01T04:12:01+00:00", "message": "active pass: 12 endpoints ranked"},
                {"at": "2026-01-01T04:12:09+00:00", "message": "prover: idor on /api/v2/users"}],
        message="stopping - after the current step",
        input_text="program list", input_caret=12,
    )
    base.update(overrides)
    return gn_dash.DashState(**base)  # type: ignore[arg-type]


class _Case(unittest.TestCase):
    _MISSING = object()

    def patch(self, obj: object, name: str, value: object) -> None:
        """Set an attribute for the test. Handles one that does not exist yet, which is how a lazily
        imported engine submodule is faked without paying for the real import."""
        old = getattr(obj, name, self._MISSING)
        setattr(obj, name, value)
        if old is self._MISSING:
            self.addCleanup(lambda: delattr(obj, name))
        else:
            self.addCleanup(setattr, obj, name, old)

    def setenv(self, var: str, value: str | None) -> None:
        old = os.environ.get(var)
        if value is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = value
        if old is None:
            self.addCleanup(lambda v=var: os.environ.pop(v, None))
        else:
            self.addCleanup(os.environ.__setitem__, var, old)

    def assertFrame(self, rows: list[str], size: gn_tui.Size) -> None:
        self.assertEqual(len(rows), size.rows, "a frame must be exactly as tall as the terminal")
        for index, row in enumerate(rows):
            self.assertLessEqual(gn_tui.visible_len(row), size.cols,
                                 f"row {index} is wider than the terminal and would wrap the frame")
            self.assertNotIn("\033", row, f"row {index} carries an escape sequence")


# --- the frame ------------------------------------------------------------------------------------
class FrameShapeTests(_Case):
    def test_every_size_produces_exactly_that_many_rows_none_too_wide(self) -> None:
        state = _state()
        for cols, rows in ((80, 24), (60, 18), (200, 60), (79, 23), (120, 40), (300, 19), (61, 100)):
            size = gn_tui.Size(cols, rows)
            with self.subTest(size=size):
                self.assertFrame(gn_dash.render(state, size, _tier()), size)

    def test_the_80x24_layout_is_the_one_the_plan_specifies(self) -> None:
        size = gn_tui.Size(80, 24)
        rows = gn_dash.render(_state(), size, _tier())
        self.assertIn("gn dash", rows[0])
        self.assertIn("RUNNING", rows[0])
        self.assertTrue(rows[0].rstrip().endswith("3/5 ┐"), rows[0])
        self.assertIn("TARGETS", rows[1])
        self.assertIn("FINDINGS", rows[1])
        self.assertIn("RATE", rows[9], "the rate panel starts at row 10")
        self.assertIn("LOG", rows[14], "the log/output pane starts at row 15")
        self.assertIn("cpu", rows[21], "the system strip is folded into the bottom border")
        self.assertIn("stopping - after the current step", rows[22])
        self.assertTrue(rows[23].startswith("> "), rows[23])

    def test_under_80_columns_the_band_stacks_and_the_rate_panel_is_one_line(self) -> None:
        rows = gn_dash.render(_state(), gn_tui.Size(79, 23), _tier())
        body = "\n".join(rows)
        self.assertIn("TARGETS", body)
        self.assertIn("FINDINGS", body)
        targets_row = next(i for i, row in enumerate(rows) if "TARGETS" in row)
        findings_row = next(i for i, row in enumerate(rows) if "FINDINGS" in row)
        self.assertGreater(findings_row, targets_row, "narrow stacks the two panels, not side by side")
        rate_row = next(i for i, row in enumerate(rows) if "RATE" in row)
        log_row = next(i for i, row in enumerate(rows) if " LOG" in row)
        self.assertEqual(log_row - rate_row, 2, "the narrow rate panel is one body line")

    def test_at_120_columns_the_rate_panel_moves_into_the_band(self) -> None:
        rows = gn_dash.render(_state(), gn_tui.Size(120, 30), _tier())
        self.assertIn("RATE", rows[1], "wide puts RATE in the top band as a third column")
        self.assertEqual([row for row in rows if row.startswith("├─ RATE")], [],
                         "the rate panel must not also keep its own rows")
        pane = next(i for i, row in enumerate(rows) if " LOG" in row)
        self.assertGreaterEqual(len(rows) - pane, 12, "the log pane takes the freed rows")

    def test_below_the_floor_it_refuses_with_one_honest_line(self) -> None:
        for size in (gn_tui.Size(59, 18), gn_tui.Size(80, 17)):
            with self.subTest(size=size):
                rows = gn_dash.render(_state(), size, _tier())
                self.assertFrame(rows, size)
                body = [row for row in rows if row.strip()]
                self.assertEqual(len(body), 1, "a refusal is one line and nothing else")
                self.assertIn("terminal too small (needs 60x18", body[0])
                self.assertIn(f"this is {size.cols}x{size.rows}", body[0])

    def test_a_tiny_terminal_still_gets_the_size_it_needs(self) -> None:
        # The sentence does not fit, so it is replaced rather than clipped: "terminal t" names
        # neither the problem nor the fix.
        for size in (gn_tui.Size(24, 4), gn_tui.Size(14, 3), gn_tui.Size(6, 2)):
            with self.subTest(size=size):
                rows = gn_dash.render(_state(), size, _tier())
                self.assertFrame(rows, size)
                body = [row for row in rows if row.strip()]
                self.assertEqual(len(body), 1)
                self.assertIn("60x18", body[0])

    def test_every_row_encodes_under_its_tier_codec(self) -> None:
        # A loop over all three tiers, not just the last: a typo'd middle tier would otherwise ship,
        # and the failure mode is a UnicodeEncodeError inside Screen._write that kills the screen.
        for name, codec in _TIER_CODECS.items():
            with self.subTest(tier=name):
                for size in (gn_tui.Size(80, 24), gn_tui.Size(60, 18), gn_tui.Size(200, 60)):
                    for row in gn_dash.render(_state(), size, _tier(name)):
                        try:
                            row.encode(codec, errors="strict")
                        except UnicodeEncodeError as exc:
                            self.fail(f"tier {name} drew {exc.object[exc.start:exc.end]!r}, "
                                      f"which {codec} cannot encode: {row!r}")

    def test_a_hostile_target_name_cannot_repaint_the_screen(self) -> None:
        # Target names and finding titles come from the host being tested. An escape sequence in one
        # must reach the frame as visible junk, never as a live control code.
        state = _state(snapshot={"targets": [{"target": "https://x/\033[2J\033[1;1Hgotcha",
                                              "status": "running"}], "findings": []})
        rows = gn_dash.render(state, gn_tui.Size(80, 24), _tier())
        self.assertFrame(rows, gn_tui.Size(80, 24))
        self.assertIn("gotcha", "\n".join(rows), "the row should still show the text, just declawed")

    def test_a_useless_state_still_produces_a_frame(self) -> None:
        for snapshot in ({}, {"targets": "nope", "findings": 7}, {"targets": [None], "findings": [3]}):
            with self.subTest(snapshot=snapshot):
                state = gn_dash.DashState(snapshot=snapshot)  # type: ignore[arg-type]
                self.assertFrame(gn_dash.render(state, gn_tui.Size(80, 24), _tier()),
                                 gn_tui.Size(80, 24))

    def test_a_broken_renderer_reports_itself_instead_of_freezing(self) -> None:
        def _boom(*_args: object, **_kwargs: object) -> list[str]:
            raise RuntimeError("panel exploded")

        self.patch(gn_dash, "_frame", _boom)
        size = gn_tui.Size(80, 24)
        rows = gn_dash.render(_state(), size, _tier())
        self.assertFrame(rows, size)
        self.assertIn("frame error: RuntimeError: panel exploded", rows[0])

    def test_a_nonsense_size_does_not_raise(self) -> None:
        for size in ((0, 0), (-5, -5), ("x", "y")):
            with self.subTest(size=size):
                rows = gn_dash.render(_state(), size, _tier())  # type: ignore[arg-type]
                self.assertIsInstance(rows, list)

    def test_the_cursor_parks_under_the_caret_on_the_input_row(self) -> None:
        size = gn_tui.Size(80, 24)
        row, col = gn_dash.cursor(_state(input_caret=5), size)
        self.assertEqual(row, 24)
        self.assertEqual(col, 8)          # "> " + 5 + 1, 1-based
        row, col = gn_dash.cursor(_state(input_caret=500), size)
        self.assertLessEqual(col, size.cols, "the caret must never be parked off-screen")


class ReflowTests(_Case):
    """The drop priority, asserted at the heights the plan names: 23, 21, 19, 18 and 17."""

    def test_regions_always_add_up_to_the_terminal(self) -> None:
        for rows in range(18, 61):
            for wide, narrow in ((False, False), (True, False), (False, True)):
                plan = gn_dash._plan_rows(rows, wide=wide, narrow=narrow)
                total = 3 + int(plan["strip"]) + plan["band"] + plan["rate"] + plan["log"]
                self.assertEqual(total, rows, f"{rows} rows, wide={wide} narrow={narrow}: {plan}")

    def test_the_drop_order_is_rate_then_strip_then_band_then_log(self) -> None:
        plans = {rows: gn_dash._plan_rows(rows, wide=False, narrow=False) for rows in range(18, 25)}
        self.assertEqual(plans[24], {"band": 8, "rate": 5, "log": 7, "strip": True})
        self.assertEqual(plans[23]["rate"], 4, "the first row lost comes off the rate panel")
        self.assertEqual(plans[23]["band"], 8)
        self.assertEqual(plans[21]["rate"], 2, "the rate panel bottoms out at one body line")
        self.assertTrue(plans[21]["strip"])
        self.assertFalse(plans[20]["strip"], "next the system strip merges into the message line")
        self.assertEqual(plans[19]["band"], 7, "only then does the target band give ground")
        self.assertEqual(plans[18]["band"], 6)
        for rows in range(18, 25):
            self.assertEqual(plans[rows]["log"], 7, "the log pane is the last thing to shrink")

    def test_surplus_rows_are_split_between_the_band_and_the_log(self) -> None:
        plan = gn_dash._plan_rows(60, wide=False, narrow=False)
        self.assertGreater(plan["band"], 8)
        self.assertGreater(plan["log"], 7)
        self.assertLessEqual(plan["band"], 24, "the target band stops growing; the log keeps the rest")

    def test_the_rendered_frame_follows_the_plan_at_each_height(self) -> None:
        state = _state()
        for rows, strip in ((24, True), (23, True), (21, True), (20, False), (19, False), (18, False)):
            size = gn_tui.Size(80, rows)
            with self.subTest(rows=rows):
                frame = gn_dash.render(state, size, _tier())
                self.assertFrame(frame, size)
                # ... bottom border, message line, input line
                bottom_border = frame[-3].startswith("└")
                self.assertEqual(bottom_border, strip,
                                 "the system strip keeps its own row only while there is room")
                self.assertIn("cpu", "\n".join(frame), "the strip is merged, never dropped")


# --- derived metrics ------------------------------------------------------------------------------
class DerivedMetricTests(_Case):
    def test_completion_counts_skipped(self) -> None:
        # stats.targets_done counts done+error only, while a stopped campaign marks the rest
        # 'skipped' — so the built-in stat sticks below 100% on exactly the runs being watched.
        snapshot = {"targets": [{"status": "done"}, {"status": "error"}, {"status": "skipped"},
                                {"status": "running"}, {"status": "queued"}]}
        self.assertEqual(gn_dash.completion(snapshot), (3, 5))
        self.assertEqual(gn_dash.completion({}), (0, 0))
        self.assertEqual(gn_dash.completion({"targets": "nonsense"}), (0, 0))

    def test_candidates_are_counted_not_inferred(self) -> None:
        findings = ([{"proof": "confirmed"}] * 2 + [{"proof": "candidate"}] * 3
                    + [{"proof": "missing"}] * 10 + [{"proof": ""}])
        counts = gn_dash.proof_counts(findings)
        self.assertEqual(counts, {"confirmed": 2, "candidate": 3, "missing": 10})
        self.assertNotEqual(counts["candidate"], len(findings) - counts["confirmed"],
                            "total - confirmed folds in every missing; that is the bug this avoids")

    def test_the_findings_panel_labels_the_400_cap(self) -> None:
        def _panel(count: int) -> str:
            findings = [{"severity": "info", "proof": "missing", "at": "1970-01-01T00:16:40+00:00"}
                        for _ in range(count)]
            state = _state(snapshot={"targets": [], "findings": findings})
            return "\n".join(gn_dash.render(state, gn_tui.Size(80, 24), _tier()))

        self.assertIn("total 399", _panel(399))
        self.assertNotIn("(cap)", _panel(399))
        self.assertIn("total 400 (cap)", _panel(400),
                      "a flatlined series at the cap must be labelled a cap, not read as a plateau")

    def test_the_severity_series_buckets_deterministically(self) -> None:
        findings = [
            {"severity": "high", "at": "1970-01-01T00:00:00+00:00"},
            {"severity": "high", "at": "1970-01-01T00:00:10+00:00"},
            {"severity": "high", "at": "1970-01-01T00:00:29+00:00"},
            {"severity": "low", "at": "1970-01-01T00:00:20+00:00"},
        ]
        series = gn_dash.severity_series(findings, 3, start=0.0, end=30.0)
        self.assertEqual(series["high"], (1, 1, 1))
        self.assertEqual(series["low"], (0, 0, 1))
        self.assertEqual(series["critical"], (0, 0, 0))
        self.assertEqual(set(series), set(gn_dash.SEVERITIES))

    def test_the_bucket_never_goes_below_one_second(self) -> None:
        # Sub-second buckets would draw the ISO stamp's own resolution as structure.
        findings = [{"severity": "info", "at": "1970-01-01T00:00:00+00:00"},
                    {"severity": "info", "at": "1970-01-01T00:00:01+00:00"}]
        series = gn_dash.severity_series(findings, 40, start=0.0, end=2.0)
        self.assertEqual(sum(series["info"]), 2)
        self.assertEqual(series["info"][0], 1)
        self.assertEqual(series["info"][1], 1, "one second per bucket, so these land side by side")

    def test_an_unparseable_or_absent_stamp_is_dropped_not_bucketed_at_zero(self) -> None:
        findings = [{"severity": "high", "at": "not a date"}, {"severity": "high"}]
        series = gn_dash.severity_series(findings, 4, start=0.0, end=4.0)
        self.assertEqual(series["high"], (0, 0, 0, 0))

    def test_per_target_severity_is_rolled_up_from_the_findings(self) -> None:
        rolled = gn_dash.target_severity(_state().snapshot["findings"])
        self.assertEqual(rolled["https://acme.com/a"]["high"], 1)
        self.assertEqual(rolled["https://acme.com/a"]["low"], 1)
        self.assertEqual(rolled["https://acme.com/login"]["critical"], 1)

    def test_probe_rate_adds_the_refill_back_and_never_goes_negative(self) -> None:
        before = [{"pool": "", "host": "a", "tokens": 700, "capacity": 700}]
        after = [{"pool": "", "host": "a", "tokens": 690, "capacity": 700}]
        self.assertAlmostEqual(gn_dash.probe_rate(before, after, 5.0), 3.0)  # (10 + 5*1.0) / 5
        self.assertEqual(gn_dash.probe_rate(before, before, 5.0), 1.0, "a refilling idle bucket")
        refilled = [{"pool": "", "host": "a", "tokens": 700, "capacity": 700}]
        self.assertGreaterEqual(gn_dash.probe_rate(after, refilled, 5.0), 0.0)

    def test_probe_rate_is_none_when_there_is_no_basis(self) -> None:
        rows = [{"pool": "", "host": "a", "tokens": 700, "capacity": 700}]
        self.assertIsNone(gn_dash.probe_rate(rows, rows, 0.0), "no window to divide by")
        self.assertIsNone(gn_dash.probe_rate([], rows, 5.0), "a host with no baseline is skipped")
        self.assertIsNone(gn_dash.probe_rate(None, None, 5.0))

    def test_a_missing_metric_renders_as_two_dashes_and_never_zero(self) -> None:
        state = _state(sysmon={"cpu_percent": None, "mem_percent": None, "disk_percent": None,
                               "disk_path": ""}, cpu_history=(), rate=None, rate_history=())
        frame = "\n".join(gn_dash.render(state, gn_tui.Size(80, 24), _tier()))
        self.assertIn("cpu --", frame)
        self.assertIn("mem --", frame)
        self.assertIn("disk --", frame)
        self.assertNotIn("cpu 0%", frame)
        self.assertIn("probe rate --", frame)

    def test_attached_mode_says_n_a_rather_than_drawing_zeros(self) -> None:
        state = _state(mode="attached", capabilities=frozenset({"stop", "reverify", "programs",
                                                                "operator-stop"}),
                       governor=(), rate=None)
        frame = "\n".join(gn_dash.render(state, gn_tui.Size(80, 24), _tier()))
        self.assertIn(gn_dash.NO_GOVERNOR, frame)
        self.assertNotIn("probe rate ~0", frame)

    def test_the_message_line_falls_back_to_the_run_phase(self) -> None:
        # There is no per-target phase in the engine, so the one run-level line has to be visible
        # somewhere other than the log; a command result outranks it while it is fresh.
        rows = gn_dash.render(_state(message="", phase="active pass: 12 endpoints ranked"),
                              gn_tui.Size(80, 24), _tier())
        self.assertIn("active pass: 12 endpoints ranked", rows[22])
        rows = gn_dash.render(_state(message="acme enabled", phase="active pass"),
                              gn_tui.Size(80, 24), _tier())
        self.assertIn("acme enabled", rows[22])
        self.assertNotIn("active pass", rows[22])

    def test_a_lost_backend_shows_a_stale_badge_beside_the_pill(self) -> None:
        state = _state(status="NO BACKEND", stale_for=12.0)
        header = gn_dash.render(state, gn_tui.Size(80, 24), _tier())[0]
        self.assertIn("NO BACKEND", header)
        self.assertIn("stale 12s", header)

    def test_the_header_keeps_the_pill_and_the_counter_when_the_label_is_enormous(self) -> None:
        state = _state(label="https://" + "a" * 400 + ".example.com/deep/path")
        for cols in (60, 80, 120):
            header = gn_dash.render(state, gn_tui.Size(cols, 24), _tier())[0]
            with self.subTest(cols=cols):
                self.assertLessEqual(len(header), cols)
                self.assertIn("RUNNING", header)
                self.assertIn("3/5", header)


# --- the verb table and the parser ------------------------------------------------------------------
class ParseCommandTests(_Case):
    LOCAL = frozenset({"stop", "reverify", "programs", "governor"})
    ATTACHED = frozenset({"stop", "reverify", "programs", "operator-stop"})
    COMMANDS = ("hunt", "campaign", "osint", "operator", "leads", "findings", "stats", "version")

    def parse(self, line: str, **kwargs: object) -> gn_dash.ParsedCommand:
        kwargs.setdefault("capabilities", self.LOCAL)
        kwargs.setdefault("commands", self.COMMANDS)
        return gn_dash.parse_command(line, **kwargs)  # type: ignore[arg-type]

    def test_an_empty_line_is_not_a_command(self) -> None:
        for line in ("", "   ", "\t"):
            self.assertEqual(self.parse(line).kind, "empty")

    def test_quoting_is_honoured(self) -> None:
        parsed = self.parse('program enable "acme corp"')
        self.assertEqual(parsed.kind, "verb")
        self.assertEqual(parsed.name, "program enable")
        self.assertEqual(parsed.args, ("acme corp",))

    def test_an_unbalanced_quote_is_refused_rather_than_guessed(self) -> None:
        parsed = self.parse('reverify "F-1')
        self.assertEqual(parsed.kind, "refused")
        self.assertIn("unbalanced quotes", parsed.error)

    def test_dash_cannot_be_run_from_inside_the_dashboard(self) -> None:
        for line in ("dash https://x", "gn dash", "DASH"):
            parsed = self.parse(line)
            self.assertEqual(parsed.kind, "refused", line)
            self.assertEqual(parsed.error, gn_dash.DASH_REFUSAL)

    def test_a_second_hunt_is_refused_while_watching_a_local_run(self) -> None:
        for line in ("hunt https://x -y", "campaign https://x", "osint x --hunt", "operator run"):
            with self.subTest(line=line):
                parsed = self.parse(line, watching=True)
                self.assertEqual(parsed.kind, "refused")
                self.assertEqual(parsed.error, gn_dash.HUNT_REFUSAL)
                self.assertIn("_MAX_RUNS=8", parsed.error)

    def test_the_same_hunt_is_allowed_when_attached_to_another_process(self) -> None:
        # The progress store is per-process, so a hunt started here cannot evict the watched run.
        parsed = self.parse("hunt https://x -y", watching=False)
        self.assertEqual(parsed.kind, "subcommand")
        self.assertEqual(parsed.name, "hunt")

    def test_an_osint_without_hunt_is_just_a_subcommand(self) -> None:
        parsed = self.parse("osint acme.com", watching=True)
        self.assertEqual(parsed.kind, "subcommand")
        parsed = self.parse("operator list", watching=True)
        self.assertEqual(parsed.kind, "subcommand")

    def test_a_capability_gated_verb_is_refused_in_the_wrong_mode(self) -> None:
        parsed = self.parse("operator stop", capabilities=self.LOCAL)
        self.assertEqual(parsed.kind, "refused")
        self.assertIn("operator stop", parsed.error)
        self.assertIn("in-process", parsed.error)
        self.assertEqual(self.parse("operator stop", capabilities=self.ATTACHED).kind, "verb")

    def test_a_verb_with_no_capability_at_all_is_refused_not_silently_dropped(self) -> None:
        parsed = self.parse("stop", capabilities=frozenset())
        self.assertEqual(parsed.kind, "refused")
        self.assertIn("`stop`", parsed.error)

    def test_an_unknown_verb_is_named(self) -> None:
        parsed = self.parse("teleport")
        self.assertEqual(parsed.kind, "refused")
        self.assertIn("unknown command: teleport", parsed.error)

    def test_with_no_command_list_the_real_parser_gets_the_last_word(self) -> None:
        # An unimportable gn_cli must not turn every subcommand into a refusal.
        parsed = self.parse("whatever --flag", commands=())
        self.assertEqual(parsed.kind, "subcommand")
        self.assertEqual(parsed.args, ("--flag",))

    def test_longest_match_wins_so_operator_stop_is_a_verb(self) -> None:
        parsed = self.parse("operator stop", capabilities=self.ATTACHED)
        self.assertEqual(parsed.name, "operator stop")
        self.assertEqual(parsed.args, ())

    def test_quit_has_an_alias(self) -> None:
        for line in ("quit", "q"):
            parsed = self.parse(line)
            self.assertEqual(parsed.kind, "verb")
            self.assertEqual(parsed.verb.hook, "quit")  # type: ignore[union-attr]


class VerbTableTests(_Case):
    def test_every_verb_has_a_handler_on_the_dashboard(self) -> None:
        for spec in gn_dash.VERBS:
            self.assertTrue(hasattr(gn_dash.Dashboard, f"_verb_{spec.hook}"),
                            f"{spec.name} points at a hook that does not exist")

    def test_every_verb_is_reachable_from_at_least_one_source(self) -> None:
        offered = (gn_dash.LocalSource("r").capabilities()
                   | gn_dash.AttachedSource("r", port=1, token="t").capabilities())
        for spec in gn_dash.VERBS:
            if spec.needs:
                self.assertIn(spec.needs, offered, f"{spec.name} can never be run by anything")

    def test_names_are_unique(self) -> None:
        names = [spec.name for spec in gn_dash.VERBS]
        self.assertEqual(len(names), len(set(names)))

    def test_help_states_the_real_latency_of_stop(self) -> None:
        text = "\n".join(gn_dash.help_lines(frozenset({"stop"})))
        self.assertIn(gn_dash.STOP_WORDING, text)
        self.assertIn("after the current step", text)
        self.assertNotIn("stopped", text.replace("stopping", ""))
        self.assertIn("cannot be cancelled", text)

    def test_help_marks_the_verbs_this_source_cannot_run(self) -> None:
        text = "\n".join(gn_dash.help_lines(frozenset({"stop"})))
        self.assertTrue(any(line.startswith("x ") and "operator stop" in line
                            for line in text.splitlines()),
                        "an unavailable verb has to be visibly unavailable")


# --- sources --------------------------------------------------------------------------------------
class LocalSourceTests(_Case):
    def setUp(self) -> None:
        from bughunter import progress

        self.progress = progress
        self.run_id = "test-gn-dash-local"
        progress.start_run(self.run_id)
        progress.set_targets(self.run_id, ["https://a.example", "https://b.example"])
        progress.log(self.run_id, "recon: 2 hosts")
        progress.mark_target(self.run_id, "https://a.example", "done")
        progress.add_findings(self.run_id, "https://a.example",
                              [{"ref": "F-1", "title": "t", "severity": "high",
                                "proof_status": "candidate"}])

    def test_poll_returns_the_identical_dict_the_http_route_produces(self) -> None:
        # greyiq_api.GreyIQRuntime.bounty_progress is literally:
        #   {"ok": True, **bounty_progress.tail(run_id, after), "snapshot": bounty_progress.snapshot(run_id)}
        # so the only difference between the two modes is the transport envelope, which
        # AttachedSource strips. Anything else here means the renderer could tell them apart.
        route = {"ok": True, **self.progress.tail(self.run_id, 0),
                 "snapshot": self.progress.snapshot(self.run_id)}
        polled = gn_dash.LocalSource(self.run_id).poll(0)
        self.assertEqual(set(polled), set(route) - {"ok"})
        self.assertEqual(set(polled), {"events", "count", "snapshot"})
        self.assertEqual(polled["count"], route["count"])
        self.assertEqual(polled["snapshot"]["stats"], route["snapshot"]["stats"])

    def test_poll_honours_the_after_cursor(self) -> None:
        source = gn_dash.LocalSource(self.run_id)
        first = source.poll(0)
        self.assertTrue(first["events"])
        self.assertEqual(source.poll(first["count"])["events"], [])

    def test_the_snapshot_renders_without_any_adapter(self) -> None:
        state = gn_dash.DashState(snapshot=gn_dash.LocalSource(self.run_id).poll(0)["snapshot"],
                                  capabilities=gn_dash.LocalSource(self.run_id).capabilities())
        frame = "\n".join(gn_dash.render(state, gn_tui.Size(80, 24), _tier()))
        self.assertIn("a.example", frame)
        self.assertIn("candidate 1", frame)

    def test_stop_sets_the_flag_the_engine_polls_and_says_stopping(self) -> None:
        source = gn_dash.LocalSource(self.run_id)
        ok, message = source.stop()
        self.assertTrue(ok)
        self.assertTrue(self.progress.is_stopped(self.run_id))
        self.assertIn("stopping", message)
        self.assertNotIn("stopped", message)

    def test_it_offers_the_governor_and_the_attached_source_does_not(self) -> None:
        self.assertIn("governor", gn_dash.LocalSource("r").capabilities())
        self.assertNotIn("governor", gn_dash.AttachedSource("r", port=1, token="t").capabilities())

    def test_the_governor_readout_is_a_tuple_of_plain_rows(self) -> None:
        rows = gn_dash.LocalSource(self.run_id).governor()
        self.assertIsInstance(rows, tuple)
        for row in rows:
            self.assertEqual(set(row), {"pool", "host", "tokens", "capacity"})

    def test_an_unimportable_progress_store_is_a_typed_error_not_a_crash(self) -> None:
        source = gn_dash.LocalSource("r", progress=False)
        source._progress = None  # noqa: SLF001
        self.patch(gn_dash.LocalSource, "_progress_module", lambda _self: None)
        with self.assertRaises(gn_dash.SourceError):
            source.poll(0)
        self.assertEqual(source.stop()[0], False)

    def test_reverify_refuses_a_ref_this_run_never_streamed(self) -> None:
        ok, message = gn_dash.LocalSource(self.run_id).reverify("F-does-not-exist")
        self.assertFalse(ok)
        self.assertIn("no streamed finding", message)

    def test_reverify_is_scoped_by_the_runs_targets_not_by_the_url_it_is_aimed_at(self) -> None:
        # Scoping a probe by the host of the URL being probed authorizes every URL. The finding's
        # `location` can be a third party the recon crawl merely observed, so the scope handed to
        # the verifier has to be the hosts the operator launched against.
        self.progress.add_findings(self.run_id, "https://a.example",
                                   [{"ref": "F-9", "title": "t", "severity": "low",
                                     "proof_status": "candidate",
                                     "location": "https://somebody-else.example/x"}])
        import bughunter

        seen: list[dict] = []

        class _Fake:
            @staticmethod
            def verify_active(url, findings, **kwargs):  # noqa: ANN001, ANN205
                seen.append({"url": url, **kwargs})
                return ([], {"in_scope": False})

        self.patch(bughunter, "active_verify_service", _Fake)
        ok, message = gn_dash.LocalSource(self.run_id).reverify("F-9")
        self.assertFalse(ok)
        self.assertIn("not in this run's scope", message)
        self.assertEqual(seen[0]["scope"], "a.example b.example")
        self.assertNotIn("somebody-else", seen[0]["scope"])
        self.assertEqual(seen[0]["requests_budget"], 16, "one re-verify must not fan out")

    def test_run_scope_lists_the_launched_hosts_once_each(self) -> None:
        snapshot = {"targets": [{"target": "https://a.example/one"}, {"target": "https://a.example/two"},
                                {"target": "https://b.example"}, {"target": "not a url"}, None]}
        self.assertEqual(gn_dash.run_scope(snapshot), "a.example b.example")
        self.assertEqual(gn_dash.run_scope({}), "")


class _Backend:
    """A real ``http.server`` standing in for the backend, recording every request it sees."""

    def __init__(self, *, token: str = "tok", health: bool = True, require_key: bool = False,
                 raw_body: bytes | None = None, payload: dict | None = None) -> None:
        self.token = token
        self.health = health
        self.require_key = require_key
        self.raw_body = raw_body
        self.payload = payload if payload is not None else {
            "ok": True, "events": [{"at": "2026-01-01T00:00:01+00:00", "message": "hello"}],
            "count": 1,
            "snapshot": {"targets": [{"target": "https://a.example", "status": "running"}],
                         "findings": [], "stats": {"targets_total": 1, "targets_done": 0,
                                                   "findings_total": 0, "confirmed_total": 0,
                                                   "severity_counts": {}}},
        }
        self.hits: list[tuple[str, str, str | None]] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def tokens_seen(self) -> set[str | None]:
        return {token for _method, _path, token in self.hits}

    def _handler(self):  # noqa: ANN202
        backend = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: object) -> None:
                return None

            def _send(self, status: int, body: bytes, headers: dict | None = None) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def _json(self, status: int, payload: dict) -> None:
                self._send(status, json.dumps(payload).encode("utf-8"))

            def do_GET(self) -> None:  # noqa: N802
                backend.hits.append(("GET", self.path, self.headers.get("X-GreyIQ-Token")))
                if self.path == "/api/health" and backend.health:
                    self._json(200, {"status": "ok"})
                    return
                self._json(404, {"error": "not found"})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                token = self.headers.get("X-GreyIQ-Token")
                backend.hits.append(("POST", self.path, token))
                if backend.require_key:
                    # greyiq_api.send_unauthorized: the GREYIQ_ACCESS_KEY gate answers 401 with a
                    # Basic challenge, ahead of the session-token check.
                    self._send(401, json.dumps({"error": "authentication required"}).encode("utf-8"),
                               {"WWW-Authenticate": 'Basic realm="GreyIQ"'})
                    return
                if token != backend.token:
                    self._json(403, {"error": "missing or invalid session token"})
                    return
                if backend.raw_body is not None:
                    self._send(200, backend.raw_body)
                    return
                self._json(200, backend.payload)

        return Handler


class AttachedSourceTests(_Case):
    def backend(self, **kwargs: object) -> _Backend:
        server = _Backend(**kwargs)  # type: ignore[arg-type]
        self.addCleanup(server.close)
        return server

    def source(self, server: _Backend, **kwargs: object) -> gn_dash.AttachedSource:
        kwargs.setdefault("token", server.token)
        kwargs.setdefault("timeout", 3.0)
        return gn_dash.AttachedSource("run-1", port=server.port, **kwargs)  # type: ignore[arg-type]

    def test_the_happy_path_answers_the_same_three_keys_as_a_local_poll(self) -> None:
        server = self.backend()
        polled = self.source(server).poll(0)
        self.assertEqual(set(polled), {"events", "count", "snapshot"})
        self.assertNotIn("ok", polled, "the transport envelope is not run data")
        self.assertEqual(polled["count"], 1)

    def test_the_token_goes_in_the_x_greyiq_token_header(self) -> None:
        server = self.backend()
        self.source(server).poll(0)
        self.assertEqual(server.hits[-1][2], server.token)
        self.assertEqual(server.hits[-1][1], "/api/bounty/progress")

    def test_no_token_reaches_a_port_that_has_not_answered_health(self) -> None:
        # The credential-leak case: a discovery walk that POSTs a session token at every local port
        # hands it to whatever else is listening. Health is answered 404 here, so this port is never
        # accepted and must never see the token.
        decoy = self.backend(health=False)
        self.patch(gn_dash, "_PORT_BASE", decoy.port)
        self.patch(gn_dash, "_PORT_SPAN", 1)
        self.setenv("GREYIQ_PORT", None)
        source = gn_dash.AttachedSource("run-1", token="super-secret", timeout=2.0)
        with self.assertRaises(gn_dash.SourceError) as caught:
            source.poll(0)
        self.assertTrue(caught.exception.fatal)
        self.assertIn("/api/health", caught.exception.message)
        self.assertEqual(server_tokens := decoy.tokens_seen(), {None},
                         f"a token reached an unverified port: {server_tokens}")
        self.assertTrue(all(method == "GET" for method, _path, _token in decoy.hits))

    def test_discovery_accepts_the_port_that_answers_health(self) -> None:
        server = self.backend()
        self.patch(gn_dash, "_PORT_BASE", server.port)
        self.patch(gn_dash, "_PORT_SPAN", 1)
        self.setenv("GREYIQ_PORT", None)
        source = gn_dash.AttachedSource("run-1", token=server.token, timeout=2.0)
        self.assertEqual(source.poll(0)["count"], 1)
        self.assertEqual(server.hits[0][:2], ("GET", "/api/health"))

    def test_greyiq_port_is_used_before_any_walk(self) -> None:
        server = self.backend()
        self.setenv("GREYIQ_PORT", str(server.port))
        self.patch(gn_dash, "_PORT_SPAN", 0)   # any walk at all would now fail
        source = gn_dash.AttachedSource("run-1", token=server.token, timeout=2.0)
        self.assertEqual(source.poll(0)["count"], 1)

    def test_a_401_with_a_challenge_names_the_access_key_and_is_fatal(self) -> None:
        server = self.backend(require_key=True)
        with self.assertRaises(gn_dash.SourceError) as caught:
            self.source(server).poll(0)
        self.assertTrue(caught.exception.fatal, "looping on a missing credential helps nobody")
        self.assertEqual(caught.exception.message, gn_dash.ACCESS_KEY_MESSAGE)
        self.assertIn("GREYIQ_ACCESS_KEY", caught.exception.message)

    def test_a_403_with_an_unchanged_token_is_reported_once(self) -> None:
        server = self.backend(token="real")
        self.patch(gn_dash, "read_token", lambda explicit="": "stale")
        source = self.source(server, token="stale")
        with self.assertRaises(gn_dash.SourceError) as caught:
            source.poll(0)
        self.assertEqual(caught.exception.message, gn_dash.STALE_TOKEN_MESSAGE)
        self.assertEqual(caught.exception.status, "NO BACKEND")
        posts = [hit for hit in server.hits if hit[0] == "POST"]
        self.assertEqual(len(posts), 1, "re-sending a token the backend just rejected is pointless")

    def test_a_403_is_retried_once_when_the_token_file_has_been_rewritten(self) -> None:
        # The restart case: SESSION_TOKEN is minted per process and the file is rewritten at boot,
        # so a token that differs from the one we hold means the backend restarted.
        server = self.backend(token="fresh")
        with TemporaryDirectory() as tmp:
            token_path = os.path.join(tmp, "session.token")
            with open(token_path, "w", encoding="utf-8") as handle:
                handle.write("stale")
            self.setenv("GREYIQ_SESSION_TOKEN", None)
            self.patch(gn_dash, "runtime_dirs", lambda: (tmp,))
            source = self.source(server, token="stale")
            with open(token_path, "w", encoding="utf-8") as handle:
                handle.write("fresh")
            self.assertEqual(source.poll(0)["count"], 1)
        posts = [hit for hit in server.hits if hit[0] == "POST"]
        self.assertEqual([hit[2] for hit in posts], ["stale", "fresh"])

    def test_a_refused_connection_is_a_no_backend_not_a_crash(self) -> None:
        server = self.backend()
        port = server.port
        server.close()
        source = gn_dash.AttachedSource("run-1", port=port, token="tok", timeout=1.0)
        with self.assertRaises(gn_dash.SourceError) as caught:
            source.poll(0)
        self.assertEqual(caught.exception.status, "NO BACKEND")
        self.assertFalse(caught.exception.fatal, "a dead backend may come back; do not give up")

    def test_a_body_that_is_not_json_says_so_and_stops(self) -> None:
        server = self.backend(raw_body=b"<html>not a backend</html>")
        with self.assertRaises(gn_dash.SourceError) as caught:
            self.source(server).poll(0)
        self.assertIn("not JSON", caught.exception.message)
        self.assertTrue(caught.exception.fatal)

    def test_a_missing_token_is_reported_before_anything_is_sent(self) -> None:
        server = self.backend()
        self.setenv("GREYIQ_SESSION_TOKEN", None)
        with TemporaryDirectory() as tmp:
            self.patch(gn_dash, "runtime_dirs", lambda: (tmp,))
            source = gn_dash.AttachedSource("run-1", port=server.port, token="", timeout=1.0)
            with self.assertRaises(gn_dash.SourceError) as caught:
                source.poll(0)
        self.assertEqual(caught.exception.message, gn_dash.NO_TOKEN_MESSAGE)
        self.assertEqual([hit for hit in server.hits if hit[0] == "POST"], [])

    def test_a_non_loopback_host_is_refused_at_construction(self) -> None:
        for host in ("10.0.0.5", "acme.com", "0.0.0.0"):
            with self.subTest(host=host), self.assertRaises(gn_dash.SourceError) as caught:
                gn_dash.AttachedSource("run-1", host=host, port=8766, token="t")
            self.assertIn("loopback", caught.exception.message)
            self.assertTrue(caught.exception.fatal)
        for host in ("127.0.0.1", "localhost", "::1"):
            gn_dash.AttachedSource("run-1", host=host, port=8766, token="t")

    def test_stop_posts_to_the_campaign_stop_route_and_says_stopping(self) -> None:
        server = self.backend()
        ok, message = self.source(server).stop()
        self.assertTrue(ok)
        self.assertEqual(server.hits[-1][1], "/api/bounty/campaign/stop")
        self.assertIn("stopping", message)

    def test_operator_stop_states_what_it_will_not_interrupt(self) -> None:
        server = self.backend()
        ok, message = self.source(server).operator_stop()
        self.assertTrue(ok)
        self.assertEqual(server.hits[-1][1], "/api/operator/stop")
        self.assertIn("not interrupted", message)

    def test_list_runs_reads_the_discovery_route(self) -> None:
        server = self.backend(payload={"ok": True, "runs": [{"run_id": "abc", "targets_total": 2}]})
        rows = self.source(server).list_runs()
        self.assertEqual(rows, [{"run_id": "abc", "targets_total": 2}])
        self.assertEqual(server.hits[-1][1], "/api/bounty/runs")


class TokenDiscoveryTests(_Case):
    def test_the_explicit_token_wins_then_the_environment_then_the_file(self) -> None:
        with TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "session.token"), "w", encoding="utf-8") as handle:
                handle.write("from-file\n")
            self.patch(gn_dash, "runtime_dirs", lambda: (tmp,))
            self.setenv("GREYIQ_SESSION_TOKEN", None)
            self.assertEqual(gn_dash.read_token("explicit"), "explicit")
            self.assertEqual(gn_dash.read_token(), "from-file")
            self.setenv("GREYIQ_SESSION_TOKEN", "from-env")
            self.assertEqual(gn_dash.read_token(), "from-env")

    def test_a_missing_file_is_empty_not_an_exception(self) -> None:
        with TemporaryDirectory() as tmp:
            self.patch(gn_dash, "runtime_dirs", lambda: (os.path.join(tmp, "nope"),))
            self.setenv("GREYIQ_SESSION_TOKEN", None)
            self.assertEqual(gn_dash.read_token(), "")

    def test_the_runtime_dirs_include_the_desktop_apps_own_location(self) -> None:
        self.setenv("GREYIQ_RUNTIME_DIR", os.path.join("x", "runtime"))
        dirs = gn_dash.runtime_dirs()
        self.assertEqual(dirs[0], os.path.join("x", "runtime"))
        self.assertTrue(any("GreyIQ" in entry for entry in dirs),
                        "an operator attaching to the desktop app's backend is the normal case")


# --- pane commands ----------------------------------------------------------------------------------
def _parser_with(func: object):  # noqa: ANN202
    import argparse

    parser = argparse.ArgumentParser(prog="gn")
    sub = parser.add_subparsers(dest="cmd")
    verb = sub.add_parser("thing")
    verb.set_defaults(func=func)
    return parser


class SubcommandTests(_Case):
    def setUp(self) -> None:
        # Real streams swapped for buffers, so "nothing leaked to the terminal" is checkable: the
        # point of the redirect inside _dash_subcommand is that a verb's output never reaches the
        # frame, and under pytest the real stdout is already a capture object.
        self.stdout, self.stderr = sys.stdout, sys.stderr
        self.leaked_out = self.leaked_err = ""
        self._restored = False
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        if self._restored:
            return
        self._restored = True
        self.leaked_out = sys.stdout.getvalue()  # type: ignore[union-attr]
        self.leaked_err = sys.stderr.getvalue()  # type: ignore[union-attr]
        sys.stdout, sys.stderr = self.stdout, self.stderr

    def test_dash_is_refused_without_touching_the_parser(self) -> None:
        for verb in ("dash", "gn"):
            code, text = gn_dash._dash_subcommand([verb, "https://x"])
            self.assertEqual(code, 2)
            self.assertEqual(text, f"gn: {gn_dash.DASH_REFUSAL}\n")

    def test_an_unknown_verb_exits_2_with_argparse_text_captured(self) -> None:
        import gn_cli

        self.patch(gn_cli, "build_parser", lambda: _parser_with(lambda _a: 0))
        code, text = gn_dash._dash_subcommand(["not-a-verb"])
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", text)
        self._restore()
        self.assertEqual(self.leaked_err, "", "argparse's error must not reach the real terminal")

    def test_a_verb_that_raises_costs_the_command_not_the_cockpit(self) -> None:
        import gn_cli

        def _boom(_args: object) -> int:
            print("some output first")
            raise ValueError("engine said no")

        self.patch(gn_cli, "build_parser", lambda: _parser_with(_boom))
        code, text = gn_dash._dash_subcommand(["thing"])
        self.assertEqual(code, 2)
        self.assertIn("some output first", text)
        self.assertIn("gn: ValueError: engine said no", text)

    def test_a_verb_that_exits_3_returns_3(self) -> None:
        import gn_cli

        def _exit(_args: object) -> int:
            raise SystemExit(3)

        self.patch(gn_cli, "build_parser", lambda: _parser_with(_exit))
        self.assertEqual(gn_dash._dash_subcommand(["thing"])[0], 3)

    def test_output_is_captured_rather_than_punched_through_the_frame(self) -> None:
        import gn_cli

        def _chatty(_args: object) -> int:
            print("line one")
            print("line two", file=sys.stderr)
            return 0

        self.patch(gn_cli, "build_parser", lambda: _parser_with(_chatty))
        code, text = gn_dash._dash_subcommand(["thing"])
        self.assertEqual(code, 0)
        self.assertIn("line one", text)
        self.assertIn("line two", text)
        self._restore()
        self.assertEqual(self.leaked_out, "", "a stray print must not reach the alternate screen")

    def test_it_writes_into_a_sink_so_the_output_pane_can_tail_it(self) -> None:
        import gn_cli

        sink = gn_dash.OutputTail()

        def _chatty(_args: object) -> int:
            print("streamed")
            return 0

        self.patch(gn_cli, "build_parser", lambda: _parser_with(_chatty))
        code, text = gn_dash._dash_subcommand(["thing"], sink)
        self.assertEqual(code, 0)
        self.assertIn("streamed", sink.lines())
        self.assertIn("streamed", text)

    def test_it_drains_gn_fx_because_the_verb_may_have_started_a_scanner(self) -> None:
        import gn_cli
        import gn_fx

        calls: list[int] = []
        self.patch(gn_fx, "stop_all", lambda *_a, **_k: calls.append(1))
        self.patch(gn_cli, "build_parser", lambda: _parser_with(lambda _a: 0))
        gn_dash._dash_subcommand(["thing"])
        self.assertEqual(len(calls), 1)

    def test_the_real_parser_still_runs_a_harmless_verb(self) -> None:
        code, text = gn_dash._dash_subcommand(["version"])
        self.assertEqual(code, 0)
        self.assertIn("GreyIQ gn", text)


class OutputTailTests(_Case):
    def test_a_partial_line_is_visible_before_its_newline_arrives(self) -> None:
        tail = gn_dash.OutputTail()
        tail.write("half a ")
        self.assertEqual(tail.lines(), ("half a ",))
        tail.write("line\nand another\n")
        self.assertEqual(tail.lines(), ("half a line", "and another"))

    def test_it_is_bounded(self) -> None:
        tail = gn_dash.OutputTail(limit=10)
        for index in range(100):
            tail.add(f"line {index}")
        self.assertLessEqual(len(tail.lines()), 11)
        self.assertIn("line 99", tail.lines())

    def test_it_does_not_claim_to_be_a_terminal(self) -> None:
        # A verb that believes it is on a tty colours its output, and those escapes would land in
        # the OUTPUT pane and then in a diffed frame.
        self.assertFalse(gn_dash.OutputTail().isatty())


class StreamResultTests(_Case):
    class _Fake:
        def __init__(self) -> None:
            self.marked: list[tuple] = []
            self.findings: list[tuple] = []

        def mark_target(self, run_id, target, status, **kwargs):  # noqa: ANN001, ANN202
            self.marked.append((run_id, target, status, kwargs))

        def add_findings(self, run_id, target, findings):  # noqa: ANN001, ANN202
            self.findings.append((run_id, target, findings))

    def test_a_finished_hunt_lands_in_the_store_the_panels_read(self) -> None:
        fake = self._Fake()
        result = {"ok": True, "proof_of_impact": {"F-1": {"status": "confirmed"}},
                  "findings": [{"ref": "F-1", "title": "t", "severity": "high",
                                "class_id": "idor", "location": "https://a/x"}]}
        gn_dash.stream_result("r", "https://a", result, progress=fake)
        self.assertEqual(fake.findings[0][2][0]["proof_status"], "confirmed")
        self.assertEqual(fake.findings[0][2][0]["location"], "https://a/x")
        self.assertEqual(fake.marked[-1][2], "done")

    def test_a_failed_hunt_marks_the_unit_error_and_streams_nothing(self) -> None:
        fake = self._Fake()
        gn_dash.stream_result("r", "https://a", {"ok": False, "error": "boom"}, progress=fake)
        self.assertEqual(fake.marked[-1][2], "error")
        self.assertEqual(fake.marked[-1][3]["error"], "boom")
        self.assertEqual(fake.findings, [])

    def test_it_never_raises_over_a_completed_hunt(self) -> None:
        class _Broken:
            def mark_target(self, *_a: object, **_k: object) -> None:
                raise RuntimeError("store is gone")

            def add_findings(self, *_a: object, **_k: object) -> None:
                raise RuntimeError("store is gone")

        gn_dash.stream_result("r", "t", {"ok": True, "findings": []}, progress=_Broken())


# --- the loop ---------------------------------------------------------------------------------------
class _ScriptedSource:
    """A source that answers from a canned list, then repeats the last frame."""

    def __init__(self, frames: list[dict] | None = None, *, caps: frozenset[str] | None = None,
                 error: Exception | None = None) -> None:
        self.frames = frames or [{"events": [], "count": 0, "snapshot": {"targets": [], "findings": []}}]
        self.caps = caps if caps is not None else frozenset({"stop", "reverify", "programs"})
        self.error = error
        self.polls = 0
        self.stopped = False

    def poll(self, after: int = 0) -> dict:
        self.polls += 1
        if self.error is not None:
            raise self.error
        return self.frames[min(self.polls - 1, len(self.frames) - 1)]

    def capabilities(self) -> frozenset[str]:
        return self.caps

    def stop(self) -> tuple[bool, str]:
        self.stopped = True
        return (True, gn_dash.STOP_WORDING)

    def label(self) -> str:
        return "scripted"

    def governor(self) -> tuple[dict, ...]:
        return ()

    def reverify(self, ref: str) -> tuple[bool, str]:
        return (True, f"re-verified {ref}")


class LoopTests(_Case):
    """The loop's decisions, driven without a terminal: every one of them is a method call."""

    def dash(self, source: object | None = None, **kwargs: object) -> gn_dash.Dashboard:
        board = gn_dash.Dashboard(source or _ScriptedSource(), stream=io.StringIO(),
                                  inp=io.StringIO(), size=(80, 24), sampler=False, **kwargs)  # type: ignore[arg-type]
        return board

    def test_a_poll_populates_the_state_the_renderer_sees(self) -> None:
        source = _ScriptedSource([{
            "events": [{"at": "2026-01-01T00:00:01+00:00", "message": "recon"}], "count": 1,
            "snapshot": {"targets": [{"target": "https://a", "status": "running"}], "findings": []},
        }])
        board = self.dash(source)
        board._absorb(source.poll(0))
        state = board.snapshot_state(gn_tui.Size(80, 24))
        self.assertEqual(state.events[0]["message"], "recon")
        self.assertEqual(state.snapshot["targets"][0]["target"], "https://a")
        self.assertIn("https://a", "\n".join(gn_dash.render(state, gn_tui.Size(80, 24), _tier())))

    def test_a_run_that_had_data_and_then_goes_empty_reads_as_evicted(self) -> None:
        board = self.dash()
        board._absorb({"events": [], "count": 1,
                       "snapshot": {"targets": [{"target": "t", "status": "done"}], "findings": []}})
        board._absorb({"events": [], "count": 0, "snapshot": {"targets": [], "findings": []}})
        state = board.snapshot_state(gn_tui.Size(80, 24))
        self.assertEqual(state.status, "EVICTED")
        self.assertIn("_MAX_RUNS=8", state.message)

    def test_a_run_that_never_had_data_is_not_called_evicted(self) -> None:
        board = self.dash()
        board._absorb({"events": [], "count": 0, "snapshot": {"targets": [], "findings": []}})
        self.assertEqual(board.snapshot_state(gn_tui.Size(80, 24)).status, "RUNNING")

    def test_a_source_error_sets_the_pill_and_the_message(self) -> None:
        board = self.dash()
        board._on_source_error(gn_dash.SourceError("the backend went away"))
        state = board.snapshot_state(gn_tui.Size(80, 24))
        self.assertEqual(state.status, "NO BACKEND")
        self.assertEqual(state.message, "the backend went away")

    def test_stop_flips_the_pill_to_stopping_and_never_to_stopped(self) -> None:
        source = _ScriptedSource()
        board = self.dash(source)
        board.submit("stop")
        self.assertTrue(source.stopped)
        state = board.snapshot_state(gn_tui.Size(80, 24))
        self.assertEqual(state.status, "STOPPING")
        self.assertIn("stopping - after the current step", state.message)

    def test_a_refused_command_reports_instead_of_running(self) -> None:
        board = self.dash()
        board.submit("dash")
        self.assertIn(gn_dash.DASH_REFUSAL, board.snapshot_state(gn_tui.Size(80, 24)).message)

    def test_one_pane_command_at_a_time(self) -> None:
        board = self.dash(run_subcommand=lambda argv, sink=None: (0, ""))
        board._busy = "gn leads"
        board.submit("stats")
        message = board.snapshot_state(gn_tui.Size(80, 24)).message
        self.assertIn("one pane command at a time", message)
        self.assertIn("gn leads", message)

    def test_a_pane_command_runs_and_brackets_its_output(self) -> None:
        seen: list[list[str]] = []

        def _fake(argv: list[str], sink: object = None) -> tuple[int, str]:
            seen.append(argv)
            sink.add("two leads")  # type: ignore[union-attr]
            return (0, "two leads")

        board = self.dash(run_subcommand=_fake)
        board._run_gn(["leads", "--status", "new"])
        lines = board.snapshot_state(gn_tui.Size(80, 24)).output
        self.assertEqual(seen, [["leads", "--status", "new"]])
        self.assertEqual(lines[0], "$ gn leads --status new")
        self.assertEqual(lines[-1], "exit 0")
        self.assertTrue(board.snapshot_state(gn_tui.Size(80, 24)).unread_output)

    def test_help_lands_in_the_output_pane_and_switches_to_it(self) -> None:
        board = self.dash()
        board.submit("help")
        state = board.snapshot_state(gn_tui.Size(80, 24))
        self.assertEqual(state.tab, "output")
        self.assertIn("pane commands", state.output)
        self.assertFalse(state.unread_output)

    def test_quit_ends_the_loop(self) -> None:
        board = self.dash()
        board.submit("q")
        self.assertTrue(board._quit.is_set())

    def test_ctrl_c_is_quit_even_where_no_signal_is_coming(self) -> None:
        board = self.dash()
        board.handle_key("CTRL-C")
        self.assertTrue(board._quit.is_set())

    def test_tab_cycles_the_focus_ring_and_follows_the_shown_tab(self) -> None:
        board = self.dash()
        self.assertEqual(board._focus, "log")
        board.handle_key("TAB")
        self.assertEqual((board._focus, board._tab), ("output", "output"))
        board.handle_key("TAB")
        self.assertEqual(board._focus, "targets")
        self.assertEqual(board._tab, "output", "moving to TARGETS leaves the pane showing what it was")
        board.handle_key("TAB")
        self.assertEqual((board._focus, board._tab), ("log", "log"))

    def test_tab_completes_a_partial_verb_instead_of_switching_panes(self) -> None:
        board = self.dash(commands=("leads", "learn", "version"))
        for char in "ver":
            board.handle_key(char)
        board.handle_key("TAB")
        self.assertEqual(board._line.text, "version ")
        self.assertEqual(board._focus, "log", "a partial verb means Tab is completion, not a pane switch")

    def test_completion_with_several_matches_lists_them_rather_than_guessing(self) -> None:
        board = self.dash(commands=("leads", "learn"))
        for char in "le":
            board.handle_key(char)
        board.handle_key("TAB")
        self.assertEqual(board._line.text, "le")
        self.assertIn("leads", board.snapshot_state(gn_tui.Size(80, 24)).message)

    def test_pgup_scrolls_the_focused_region_only(self) -> None:
        board = self.dash()
        board.handle_key("PGUP")
        self.assertGreater(board._pane_scroll, 0)
        self.assertEqual(board._target_scroll, 0)
        board._focus = "targets"
        board.handle_key("PGDN")
        self.assertGreater(board._target_scroll, 0)

    def test_ctrl_l_really_does_repaint_because_the_help_says_it_does(self) -> None:
        class _Screen:
            def __init__(self) -> None:
                self.frames: list[list[str]] = []

            def take_resize(self) -> bool:
                return False

            def size(self) -> gn_tui.Size:
                return gn_tui.Size(80, 24)

            def frame(self, rows: list[str], cursor: object = None) -> None:
                self.frames.append(list(rows))

        class _Reader:
            def __init__(self, keys: list[str]) -> None:
                self.keys = keys

            def read(self, _timeout: float) -> str | None:
                return self.keys.pop(0) if self.keys else None

        board = self.dash()
        screen, reader = _Screen(), _Reader(["CTRL-L"])
        threading.Timer(0.3, board._quit.set).start()
        board._loop(screen, reader)
        self.assertTrue(any(not any(row.strip() for row in frame) for frame in screen.frames),
                        "Ctrl-L must blank the frame; the row diff would otherwise leave whatever "
                        "another process wrote on the rows the dashboard did not change")

    def test_an_unknown_key_is_ignored_not_echoed(self) -> None:
        board = self.dash()
        board.handle_key("F13")
        board.handle_key("")
        self.assertEqual(board._line.text, "")

    def test_a_verb_that_explodes_becomes_a_message(self) -> None:
        class _Angry(_ScriptedSource):
            def stop(self) -> tuple[bool, str]:
                raise RuntimeError("the route is on fire")

        board = self.dash(_Angry())
        board._guarded(lambda: board._run_verb(
            next(spec for spec in gn_dash.VERBS if spec.name == "stop"), ()))
        self.assertIn("RuntimeError: the route is on fire",
                      board.snapshot_state(gn_tui.Size(80, 24)).message)

    def test_a_message_expires_so_the_line_does_not_lie_about_now(self) -> None:
        clock = [1000.0]
        board = gn_dash.Dashboard(_ScriptedSource(), stream=io.StringIO(), inp=io.StringIO(),
                                  size=(80, 24), sampler=False, clock=lambda: clock[0])
        board.note("that worked")
        self.assertEqual(board.snapshot_state(gn_tui.Size(80, 24)).message, "that worked")
        clock[0] += 7.0
        self.assertEqual(board.snapshot_state(gn_tui.Size(80, 24)).message, "")

    def test_control_off_refuses_everything_but_quit_and_help(self) -> None:
        source = _ScriptedSource()
        board = self.dash(source, allow_control=False)
        board.submit("stop")
        self.assertFalse(source.stopped)
        self.assertIn("control is off", board.snapshot_state(gn_tui.Size(80, 24)).message)
        board.submit("q")
        self.assertTrue(board._quit.is_set())

    def test_a_broken_sampler_costs_three_dashes_not_the_frame(self) -> None:
        class _Broken:
            def sample(self) -> dict:
                raise OSError("no counters here")

        board = gn_dash.Dashboard(_ScriptedSource(), stream=io.StringIO(), inp=io.StringIO(),
                                  size=(80, 24), sampler=_Broken())
        self.assertEqual(board._sample(), {})
        self.assertEqual(board._sample(), {}, "the probe is retired, not retried every frame")
        state = board.snapshot_state(gn_tui.Size(80, 24))
        self.assertIn("cpu --", "\n".join(gn_dash.render(state, gn_tui.Size(80, 24), _tier())))

    def test_attached_mode_polls_slower_and_lifts_the_hunt_refusal(self) -> None:
        attached = _ScriptedSource(caps=frozenset({"stop", "reverify", "programs", "operator-stop"}))
        board = self.dash(attached)
        self.assertEqual(board._interval, 1.0)
        self.assertEqual(board._state.mode, "attached")
        self.assertEqual(self.dash(_ScriptedSource())._interval, 0.25)

    def test_the_refresh_rate_is_clamped(self) -> None:
        self.assertEqual(self.dash(refresh_hz=100.0)._hz, 20.0)
        self.assertEqual(self.dash(refresh_hz=0.0)._hz, 0.5)

    def test_supported_needs_a_terminal_and_the_floor_size(self) -> None:
        self.assertFalse(gn_dash.supported(io.StringIO()))


class _FakeConsole:
    """A WinConsole stand-in. Real console modes are gn_tui's contract and are tested there; here
    it exists so the VT refusal can be driven from any platform."""

    def __init__(self, vt: bool = True) -> None:
        self.vt_enabled = vt
        self.vt_state = "enabled" if vt else "unavailable"
        self.entered = self.exited = 0

    def __enter__(self) -> "_FakeConsole":
        self.entered += 1
        return self

    def __exit__(self, *_exc: object) -> None:
        self.exited += 1


class RunLoopTests(_Case):
    """``run()`` end to end against a non-terminal: the loop, the threads and the teardown."""

    def setUp(self) -> None:
        # Both key backends off, so KeyReader.read() just burns its timeout instead of reaching for
        # the real console on Windows or a fileno a StringIO does not have on Linux.
        self.patch(gn_tui, "_msvcrt", None)
        self.patch(gn_tui, "termios", None)
        self.console = _FakeConsole()
        self.patch(gn_tui, "WinConsole", lambda: self.console)
        self.addCleanup(gn_tui.teardown_all)

    def board(self, **kwargs: object) -> tuple[gn_dash.Dashboard, io.StringIO]:
        stream = io.StringIO()
        kwargs.setdefault("refresh_hz", 20.0)
        board = gn_dash.Dashboard(_ScriptedSource(), stream=stream, inp=io.StringIO(),
                                  size=(80, 24), sampler=False, **kwargs)  # type: ignore[arg-type]
        return board, stream

    def _quit_soon(self, board: gn_dash.Dashboard) -> None:
        timer = threading.Timer(0.25, board._quit.set)
        timer.daemon = True
        timer.start()
        self.addCleanup(timer.cancel)

    def test_a_full_run_against_a_non_terminal_writes_not_one_byte(self) -> None:
        board, stream = self.board()
        self._quit_soon(board)
        self.assertEqual(board.run(), 0)
        self.assertEqual(stream.getvalue(), "",
                         "the dashboard drew into a redirected stream")
        self.assertNotIn("\033[?1049h", stream.getvalue())

    def test_the_hunts_exit_code_comes_back_through_the_dashboard(self) -> None:
        board, _stream = self.board(launch=lambda: 7)
        self._quit_soon(board)
        self.assertEqual(board.run(), 7)

    def test_a_hunt_that_raised_is_re_raised_after_the_terminal_is_restored(self) -> None:
        def _boom() -> int:
            raise ValueError("the engine fell over")

        board, _stream = self.board(launch=_boom)
        self._quit_soon(board)
        with self.assertRaises(ValueError):
            board.run()
        self.assertEqual(self.console.exited, 1,
                         "teardown has to have run before the exception leaves run()")
        self.assertEqual(gn_tui._LIVE, [], "something is still holding the terminal")

    def test_a_console_that_will_not_enable_vt_is_refused_rather_than_degraded(self) -> None:
        self.console = _FakeConsole(vt=False)
        board, stream = self.board()
        errors = io.StringIO()
        self.patch(sys, "stderr", errors)
        self.assertEqual(board.run(), 2)
        self.assertIn("will not enable ANSI", errors.getvalue())
        self.assertEqual(stream.getvalue(), "", "no clear-and-home fallback: it eats scrollback")

    def test_the_loop_ends_when_the_operator_quits(self) -> None:
        board, _stream = self.board()
        threading.Timer(0.2, lambda: board.submit("q")).start()
        self.assertEqual(board.run(), 0)

    def test_the_poller_runs_and_stops_with_the_loop(self) -> None:
        source = _ScriptedSource()
        stream = io.StringIO()
        board = gn_dash.Dashboard(source, stream=stream, inp=io.StringIO(), size=(80, 24),
                                  sampler=False, poll_interval=0.01, refresh_hz=20.0)
        self._quit_soon(board)
        board.run()
        self.assertGreater(source.polls, 1)
        polled = source.polls
        threading.Event().wait(0.1)
        self.assertEqual(source.polls, polled, "the poller outlived the loop")

    def test_a_fatal_source_error_stops_the_poller_instead_of_hammering(self) -> None:
        source = _ScriptedSource(error=gn_dash.SourceError("no key", fatal=True))
        board = gn_dash.Dashboard(source, stream=io.StringIO(), inp=io.StringIO(), size=(80, 24),
                                  sampler=False, poll_interval=0.01, refresh_hz=20.0)
        self._quit_soon(board)
        board.run()
        self.assertEqual(source.polls, 1, "a fatal error means reattaching will not help")
        self.assertEqual(board.snapshot_state(gn_tui.Size(80, 24)).status, "NO BACKEND")


class TotalityTests(_Case):
    def test_no_module_level_state_is_mutated_by_rendering(self) -> None:
        before = [dict(spec.__dict__) for spec in gn_dash.VERBS]
        gn_dash.render(_state(), gn_tui.Size(80, 24), _tier())
        self.assertEqual([dict(spec.__dict__) for spec in gn_dash.VERBS], before)

    def test_render_does_not_mutate_the_state_it_is_given(self) -> None:
        state = _state()
        snapshot = json.dumps(state.snapshot, sort_keys=True)
        gn_dash.render(state, gn_tui.Size(80, 24), _tier())
        self.assertEqual(json.dumps(state.snapshot, sort_keys=True), snapshot)

    def test_a_tier_missing_its_glyphs_still_draws(self) -> None:
        for tier in ({}, {"name": "rich"}, {"box": ()}, {"bars": (), "dot": "", "tick": ""}):
            with self.subTest(tier=tier):
                rows = gn_dash.render(_state(), gn_tui.Size(80, 24), tier)
                self.assertEqual(len(rows), 24)


class SelfTestTests(_Case):
    """``gn dash --self-test`` is the only diagnostic a Windows operator has for a console the
    ubuntu-only CI cannot reach, so the properties that matter are: it always answers, it never
    lies about having drawn, and it writes no escape sequence into a stream that is not a
    terminal."""

    def setUp(self) -> None:
        # A predictable terminal on both platforms: no opt-out set, a named TERM (gn_fx.enabled
        # wants one on POSIX), a size shutil will report for a StringIO, and the Windows console
        # seam nulled so the ctypes branch never touches the console pytest is running on.
        for var in ("NO_COLOR", "GN_NO_FX", "GN_NO_DASH", "GN_DASH_GLYPHS"):
            self.setenv(var, None)
        self.setenv("TERM", "xterm-256color")
        self.setenv("COLUMNS", "100")
        self.setenv("LINES", "30")
        self.patch(gn_tui, "_kernel32", None)

    def test_the_size_refusal_names_the_floor_and_the_measurement(self) -> None:
        self.assertEqual(gn_dash.size_refusal(gn_tui.Size(80, 24)), "")
        self.assertEqual(gn_dash.size_refusal(gn_dash.MIN_SIZE), "")
        message = gn_dash.size_refusal(gn_tui.Size(40, 12))
        self.assertIn("60x18", message)
        self.assertIn("40x12", message)

    def test_off_a_terminal_it_reports_everything_and_draws_nothing(self) -> None:
        out, keys = io.StringIO(), io.StringIO()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = gn_dash.self_test(out, keys)
        report = buffer.getvalue()
        self.assertEqual(code, 2, "nothing was drawn, so the exit code must not say otherwise")
        for expected in ("gn dash self-test", "glyph tier", "key reader", "console VT",
                         "host counters", "refused"):
            self.assertIn(expected, report)
        self.assertIn("not drawn", report)
        # The load-bearing property, extended from test_gn_fx's "not one byte": the alternate
        # screen must never be entered on a stream nobody is watching.
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn("\033[?1049h", report)

    def test_it_draws_and_tears_down_on_a_terminal_and_leaves_no_registration(self) -> None:
        out, keys = _tty(), _tty()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = gn_dash.self_test(out, keys)
        painted = out.getvalue()
        self.assertEqual(code, 0, buffer.getvalue())
        self.assertIn("drawn and torn down", buffer.getvalue())
        self.assertIn("\033[?1049h", painted)
        self.assertTrue(painted.endswith(gn_tui._TEARDOWN),  # noqa: SLF001 - the contract under test
                        "the terminal must be handed back as the last thing written")
        self.assertEqual(gn_tui._LIVE, [], "nothing may stay registered after a self-test")  # noqa: SLF001

    def test_a_console_that_refuses_vt_is_reported_rather_than_drawn_over(self) -> None:
        # Clear-and-home would destroy the operator's scrollback, so the answer is "no", said out
        # loud. Driven from Linux CI through the kernel32 seam, or it ships unexercised.
        class _Refusing:
            vt_state, vt_enabled = "unavailable", False

            def acquire(self): return self
            def restore(self): return None
            def __enter__(self): return self
            def __exit__(self, *_exc): return None

        out, keys = _tty(), _tty()
        buffer = io.StringIO()
        self.patch(gn_tui, "WinConsole", _Refusing)
        with contextlib.redirect_stdout(buffer):
            code = gn_dash.self_test(out, keys)
        self.assertEqual(code, 2)
        self.assertIn("unavailable", buffer.getvalue())
        self.assertEqual(out.getvalue(), "", "a console that refuses VT must not be written to")

    def test_a_sampler_that_explodes_costs_a_line_not_the_verb(self) -> None:
        class _Broken:
            def __init__(self, *_a, **_k) -> None:
                raise RuntimeError("no counters here")

        self.patch(gn_dash.gn_sysmon, "SystemSampler", _Broken)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            gn_dash.self_test(io.StringIO(), io.StringIO())
        self.assertIn("unavailable:", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
