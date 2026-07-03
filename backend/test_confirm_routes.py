"""Tests for the shared confirm-route plumbing in greyiq_api.

The IDOR / takeover / OOB-SSRF confirm routes share two pieces of infrastructure that
were previously untested:

  * ``_confirm_route`` — a decorator that turns an unexpected service/render exception
    into a structured ``{ok: False, error}`` (so the cockpit shows a reason instead of a
    blank 500), logging the full traceback server-side.
  * ``_persist_finding_run`` — the shared "render → write .md + .json → cache the run"
    tail. Centralising it guarantees the JSON evidence sidecar on *every* path (the OOB
    route used to skip it) and that all three stay in lock-step.

``render_finding`` is stubbed so the persist helper is exercised in isolation.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402


class ConfirmRouteDecoratorTests(unittest.TestCase):
    def test_exception_becomes_structured_ok_false(self) -> None:
        class R:
            def __init__(self) -> None:
                self.logged: list[str] = []

            def log(self, m: str) -> None:
                self.logged.append(m)

            @api._confirm_route
            def boom(self, request):
                raise RuntimeError("kaboom")

        r = R()
        out = r.boom(object())
        self.assertFalse(out["ok"])
        self.assertIn("boom failed", out["error"])
        self.assertIn("RuntimeError", out["error"])          # the exception TYPE is surfaced (useful, safe)
        self.assertNotIn("kaboom", out["error"])             # but NOT the raw message — it can echo scanned/attacker content
        self.assertTrue(r.logged, "the full traceback must be logged server-side")

    def test_success_passes_through_untouched(self) -> None:
        class R:
            def log(self, m: str) -> None:  # pragma: no cover - not exercised on success
                pass

            @api._confirm_route
            def fine(self, request):
                return {"ok": True, "status": "confirmed", "v": 1}

        self.assertEqual(R().fine(None), {"ok": True, "status": "confirmed", "v": 1})


class PersistFindingRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_render = api.bounty_formats.render_finding
        api.bounty_formats.render_finding = lambda ctx, f, platform: f"# {f['ref']} via {platform}"
        self._written: list[Path] = []

    def tearDown(self) -> None:
        api.bounty_formats.render_finding = self._orig_render
        for p in self._written:
            p.unlink(missing_ok=True)

    def _runtime_stub(self):
        calls: list[tuple] = []

        class R:
            def _cache_bounty_run(self, result, *, target, scope, program, disclose_automation=False):
                result["run_id"] = "run_xyz"
                calls.append((target, scope, program))

        return R(), calls

    def test_writes_md_and_json_sidecar_and_caches_run(self) -> None:
        stub, calls = self._runtime_stub()
        out = api.GreyIQRuntime._persist_finding_run(
            stub,
            findings=[{"ref": "F1"}],
            plans={"F1": {"step": 1}},
            target="https://app.example.com/x",
            scope="example.com",
            platform="hackerone",
            slug="idor",
            host="app.example.com",
            json_extra={"detail": {"d": 1}},
        )
        self.assertEqual(out["run_id"], "run_xyz")
        self.assertEqual(out["platform"], "hackerone")
        self.assertEqual(out["report"], "# F1 via hackerone")

        md, js = Path(out["report_path"]), Path(out["json_path"])
        self._written += [md, js]
        self.assertTrue(md.is_file() and md.suffix == ".md")
        self.assertTrue(js.is_file() and js.suffix == ".json")
        self.assertTrue(md.name.startswith("idor-app_example_com-"))  # dots sanitised out of the filename

        payload = json.loads(js.read_text(encoding="utf-8"))
        # the finding gains a resolved severity (write-back); no cvss + no raw label -> "low"
        self.assertEqual(payload["findings"], [{"ref": "F1", "severity": "low"}])
        self.assertIn("attack_plans", payload)
        self.assertEqual(payload["detail"], {"d": 1})  # json_extra merged in

        # the run was cached with the right target/scope and program=None
        self.assertEqual(calls, [("https://app.example.com/x", "example.com", None)])

    def test_severity_is_resolved_and_written_back_onto_the_finding(self) -> None:
        # A finding whose raw label (medium) disagrees with its plan CVSS (high) must be
        # normalised to the resolved value IN PLACE, so the toast / cache / report all agree.
        stub, _ = self._runtime_stub()
        finding = {"ref": "F1", "severity": "medium"}
        out = api.GreyIQRuntime._persist_finding_run(
            stub, findings=[finding],
            plans={"F1": {"cvss": {"base_severity": "high", "vector": "x"}}},
            target="https://t.example.com", scope="example.com",
            platform="hackerone", slug="oob-ssrf", host="t.example.com")
        self._written += [Path(out["report_path"]), Path(out["json_path"])]
        self.assertEqual(finding["severity"], "high")  # written back in place

    def test_multi_finding_report_is_joined_and_proof_covers_every_ref(self) -> None:
        stub, _ = self._runtime_stub()
        captured: dict = {}
        # capture the result handed to _cache_bounty_run to assert proof_of_impact
        stub._cache_bounty_run = lambda result, **kw: (captured.update(result), result.__setitem__("run_id", "r"))[1]  # type: ignore[assignment]
        out = api.GreyIQRuntime._persist_finding_run(
            stub,
            findings=[{"ref": "F1"}, {"ref": "F2"}],
            plans={"F1": {}, "F2": {}},
            target="https://t.example.com",
            scope="example.com",
            platform="bugcrowd",
            slug="takeover",
            host="example.com",
        )
        self._written += [Path(out["report_path"]), Path(out["json_path"])]
        self.assertIn("---", out["report"])  # two findings joined by a divider
        self.assertEqual(set(captured["proof_of_impact"]), {"F1", "F2"})
        self.assertEqual(captured["proof_of_impact"]["F1"], {"status": "confirmed"})


if __name__ == "__main__":
    unittest.main()
