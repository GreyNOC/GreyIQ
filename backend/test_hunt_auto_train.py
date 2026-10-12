"""Local, bounded retraining after successful hunt-trace writes."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty, campaign, hunt_model, hunt_trace, hunt_train, rate_limit  # noqa: E402

_CLASSES = ["xss", "sqli", "path-traversal", "rce", "redirect"]
_RULES = {"xss": "active.reflected-xss", "sqli": "active.sqli-error",
          "path-traversal": "active.path-traversal",
          "rce": "active.rce-command-injection", "redirect": "active.open-redirect"}


def _trace(runtime: Path, program: str, *, confirmed: str = "rce") -> None:
    endpoint = f"https://{program}.example.com/search?q=1&file=x&cmd=id&redirect=%2F"
    assert hunt_trace.record_trace(
        runtime, program=program, target=endpoint,
        surface={"endpoints": [endpoint], "params": ["q", "file", "cmd", "redirect"],
                 "tech": [], "forms": []},
        plan={"provider": "offline", "probe_priority": [{"endpoint": endpoint, "classes": _CLASSES}]},
        execution=[{"endpoint": endpoint, "classes": _CLASSES}],
        outcomes=[{"endpoint": endpoint, "class": cls, "rule_id": _RULES[cls],
                   "proof_status": "confirmed" if cls == confirmed else "missing"}
                  for cls in _CLASSES],
    )


class AutoTrainerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        env = patch.dict(os.environ, {"GREYIQ_NO_AUTO_TRAIN_BRAIN": "0"})
        env.start()
        self.addCleanup(env.stop)
        self.runtime = Path(self._tmp.name)
        hunt_model._CACHE.clear()

    def tearDown(self) -> None:
        hunt_model._CACHE.clear()

    def test_disable_switch_skips_all_training_and_state_writes(self) -> None:
        for index in range(5):
            _trace(self.runtime, f"program-{index}")
        with patch.dict(os.environ, {"GREYIQ_NO_AUTO_TRAIN_BRAIN": "1"}), \
             patch.object(hunt_train, "train") as trainer:
            result = hunt_train.maybe_auto_train(self.runtime)
        self.assertFalse(result["attempted"])
        self.assertEqual(result["reason"], "disabled")
        trainer.assert_not_called()
        self.assertFalse(hunt_train._auto_state_path(self.runtime).exists())

    def test_new_trace_cooldown_persists_across_calls(self) -> None:
        _trace(self.runtime, "program-1")
        with patch.object(hunt_train, "train", return_value={"ok": False, "reason": "small corpus"}) as trainer:
            first = hunt_train.maybe_auto_train(self.runtime, min_new_traces=2)
            self.assertFalse(first["attempted"])
            _trace(self.runtime, "program-2")
            second = hunt_train.maybe_auto_train(self.runtime, min_new_traces=2)
            self.assertTrue(second["attempted"])
            self.assertFalse(second["ok"])
            trainer.assert_called_once()
            self.assertGreaterEqual(trainer.call_args.kwargs["min_rows"], 200)
            # Refused training is still an attempt: no repeat without new traces.
            third = hunt_train.maybe_auto_train(self.runtime, min_new_traces=2)
            self.assertFalse(third["attempted"])
            self.assertEqual(third["new_traces"], 0)
            _trace(self.runtime, "program-3")
            self.assertFalse(hunt_train.maybe_auto_train(self.runtime, min_new_traces=2)["attempted"])
            _trace(self.runtime, "program-4")
            self.assertTrue(hunt_train.maybe_auto_train(self.runtime, min_new_traces=2)["attempted"])
            self.assertEqual(trainer.call_count, 2)
        state = json.loads(hunt_train._auto_state_path(self.runtime).read_text(encoding="utf-8"))
        self.assertEqual(state["trace_count"], 4)
        self.assertEqual(state["pending_traces"], 0)
        self.assertEqual(state["seen_bytes"], (self.runtime / "hunt_traces.jsonl").stat().st_size)

    def test_failed_fit_does_not_retry_on_every_hunt(self) -> None:
        _trace(self.runtime, "program-1")
        _trace(self.runtime, "program-2")
        with patch.object(hunt_train, "train", side_effect=RuntimeError("fit failed")) as trainer:
            failed = hunt_train.maybe_auto_train(self.runtime, min_new_traces=2)
            self.assertTrue(failed["attempted"])
            self.assertIn("RuntimeError", failed["reason"])
            self.assertFalse(hunt_train.maybe_auto_train(self.runtime, min_new_traces=2)["attempted"])
            trainer.assert_called_once()

    def test_verified_local_corpus_promotes_model_without_cli_command(self) -> None:
        train_programs: list[str] = []
        held_out_programs: list[str] = []
        index = 0
        while len(train_programs) < 20 or len(held_out_programs) < 20:
            program = f"program-{index:04d}"
            group = (held_out_programs if hunt_train._program_in_holdout(program, 0.2)
                     else train_programs)
            if len(group) < 20:
                group.append(program)
            index += 1
        for program in train_programs + held_out_programs:
            _trace(self.runtime, program)

        result = hunt_train.maybe_auto_train(self.runtime)
        self.assertTrue(result["attempted"])
        self.assertTrue(result["written"], result["reason"])
        self.assertEqual(result["rows"], 200)
        model = hunt_model.load_model(None, self.runtime)
        self.assertIsNotNone(model)
        assert model is not None
        order = model.rank_endpoint_classes(
            "https://new.example.com/search?q=1", ["q"], ["q"], "", list(_CLASSES), None)
        self.assertEqual(order[0], "rce")


class _LocalHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<html>local test</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


class AutoRetrainWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.runtime = self.root / "runtime"
        self.reports = self.root / "reports"

    def test_direct_active_hunt_triggers_after_trace_write(self) -> None:
        rate_limit.reset_shared_governors()
        server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}/"
            with patch.dict(os.environ, {"GREYIQ_SCAN_ALLOW_PRIVATE_URLS": "1"}), \
                 patch.object(hunt_train, "maybe_auto_train", return_value={"attempted": False}) as auto:
                result = bounty.run_bounty_hunt(
                    target, "web-app", None, str(self.reports), "127.0.0.1", True, {},
                    active=True, default_reports_dir=self.reports,
                    seed_dir=BACKEND_DIR / "seed", runtime_dir=self.runtime)
            self.assertTrue(result["ok"], result.get("error"))
            self.assertEqual(len(hunt_trace.load_traces(self.runtime)), 1)
            auto.assert_called_once_with(self.runtime, seed_dir=BACKEND_DIR / "seed")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_campaign_triggers_only_when_trace_write_succeeds(self) -> None:
        target = "https://app.example.com/"
        discovery = {"urls": [target], "notes": [], "sources": {}, "js_secrets": [],
                     "tech": [], "params": [], "forms": [], "hints": {}}
        per_url = {"ok": True, "json_path": "", "report_path": ""}
        cve_result = {"ok": True, "findings": [], "components": []}
        for recorded in (False, True):
            with self.subTest(recorded=recorded), \
                 patch.object(campaign.recon, "discover", return_value=discovery), \
                 patch.object(campaign, "run_bounty_hunt", return_value=per_url), \
                 patch.object(campaign.cve_service, "scan_known_cves", return_value=cve_result), \
                 patch.object(campaign.hunt_trace, "record_trace", return_value=recorded), \
                 patch.object(hunt_train, "maybe_auto_train", return_value={"attempted": False}) as auto:
                result = campaign.run_campaign(
                    target, scope="app.example.com", authorized=True, coder_cfg={},
                    default_reports_dir=self.reports, seed_dir=BACKEND_DIR / "seed",
                    runtime_dir=self.runtime, version="test", program="demo")
                self.assertTrue(result["ok"], result.get("error"))
                if recorded:
                    auto.assert_called_once_with(self.runtime, seed_dir=BACKEND_DIR / "seed")
                else:
                    auto.assert_not_called()


if __name__ == "__main__":
    unittest.main()
