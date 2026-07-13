"""Tests for the edit-trace distillation corpus (offline-coder strategy, move 5)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402
import edit_trace  # noqa: E402

_CHANGES = [{"path": "src/foo.py", "operation": "edit_file", "existed": True, "before_size": 10, "after_size": 20,
             "before": "SECRET = 'x'", "after": "SECRET = 'y'"}]
_LOCAL_CFG = {"provider": "local", "enabled": True, "local": {"model": "m", "base_url": "http://127.0.0.1:11434"}}


class RecordTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _one(self) -> dict:
        traces = edit_trace.load_traces(self.rt)
        self.assertEqual(len(traces), 1)
        return traces[0]

    def test_records_a_verified_real_brain_run(self) -> None:
        ok = edit_trace.record_trace(self.rt, message="add a null check to parse", provider="local",
                                     model="qwen2.5-coder:14b", workspace="/home/me/proj",
                                     changes=_CHANGES, touched_files=["src/foo.py"], verified=True, steps=7,
                                     skills=["fix-bug"])
        self.assertTrue(ok)
        rec = self._one()
        self.assertEqual(rec["provider"], "local")
        self.assertEqual(rec["files"][0]["operation"], "edit_file")
        self.assertEqual(rec["files"][0]["after_size"], 20)
        self.assertEqual(rec["skills"], ["fix-bug"])
        self.assertEqual(rec["workspace"]["name"], "proj")

    def test_structure_only_no_content(self) -> None:
        edit_trace.record_trace(self.rt, message="edit it", provider="anthropic", changes=_CHANGES,
                                touched_files=["src/foo.py"], verified=True)
        blob = json.dumps(self._one())
        self.assertNotIn("SECRET = 'y'", blob, "the diff BODY must never be recorded — structure only")
        self.assertNotIn("before", self._one()["files"][0], "no before/after content in the shape")

    def test_intent_is_secret_redacted(self) -> None:
        edit_trace.record_trace(self.rt, message="use token=abcd1234efgh5678ijkl for the client", provider="local",
                                changes=_CHANGES, touched_files=["a"], verified=True)
        self.assertNotIn("abcd1234efgh5678ijkl", json.dumps(self._one()))

    def test_offline_provider_is_not_logged(self) -> None:
        self.assertFalse(edit_trace.record_trace(self.rt, message="x", provider="offline", changes=_CHANGES,
                                                 touched_files=["a"], verified=True))
        self.assertEqual(edit_trace.load_traces(self.rt), [])

    def test_unverified_run_is_not_logged(self) -> None:
        self.assertFalse(edit_trace.record_trace(self.rt, message="x", provider="local", changes=_CHANGES,
                                                 touched_files=["a"], verified=False))

    def test_no_touched_files_not_logged(self) -> None:
        self.assertFalse(edit_trace.record_trace(self.rt, message="x", provider="local", changes=[],
                                                 touched_files=[], verified=True))

    def test_stats(self) -> None:
        edit_trace.record_trace(self.rt, message="a", provider="local", changes=_CHANGES, touched_files=["a"], verified=True)
        edit_trace.record_trace(self.rt, message="b", provider="anthropic",
                                changes=[{"path": "b.py", "operation": "write_file", "before_size": 0, "after_size": 5}],
                                touched_files=["b.py"], verified=True)
        stats = edit_trace.trace_stats(self.rt)
        self.assertEqual(stats["runs"], 2)
        self.assertEqual(stats["operations"]["edit_file"], 1)
        self.assertEqual(stats["operations"]["write_file"], 1)


class RunAgentWiringTests(unittest.TestCase):
    """A verified real-brain run is distilled; an offline run is not (it IS a template)."""

    def test_real_brain_run_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as rt:
            def _fake_loop(messages, system_prompt, cfg, block, settings, toolbox, provider, on_event):
                toolbox._tool_write_file({"path": "new.py", "content": "x = 1\n"})
                toolbox._tool_verify({})
                return agent._finalize("done", [], toolbox, "qwen2.5-coder:14b", "local", completed=True)
            with mock.patch.object(agent, "plan_task", return_value=[]), \
                 mock.patch.object(agent, "_run_tool_loop", _fake_loop):
                result = agent.run_agent("add x", [], ws, _LOCAL_CFG, runtime_dir=rt)
            self.assertTrue(result["verified"])
            traces = edit_trace.load_traces(Path(rt))
            self.assertEqual(len(traces), 1)
            self.assertEqual(traces[0]["provider"], "local")
            self.assertTrue(any(f["path"] == "new.py" for f in traces[0]["files"]))

    def test_offline_run_is_not_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as rt:
            with mock.patch.object(agent, "plan_task", return_value=[]):
                agent.run_agent("add a test for foo", [], ws, {}, runtime_dir=rt)  # {} -> offline
            self.assertEqual(edit_trace.load_traces(Path(rt)), [], "offline runs are templates, not corpus")


if __name__ == "__main__":
    unittest.main()
