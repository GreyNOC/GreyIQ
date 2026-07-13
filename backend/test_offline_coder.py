"""Tests for the deterministic offline code provider (offline-coder strategy, moves 1-2)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402
import greyiq_api  # noqa: E402
import offline_coder  # noqa: E402


class PlanEditsTests(unittest.TestCase):
    def test_add_test_scaffolds_a_valid_python_stub(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            plan = offline_coder.plan_edits("add a unit test for parse_config", td)
            self.assertFalse(plan["needs_brain"])
            self.assertEqual(len(plan["ops"]), 1)
            op = plan["ops"][0]
            self.assertEqual(op["kind"], "new_file")
            self.assertEqual(op["path"], "test_parse_config.py")
            # The scaffold must be valid Python (verify would compile it).
            compile(op["content"], op["path"], "exec")
            self.assertIn("class TestParseConfig", op["content"])

    def test_create_file_with_body(self) -> None:
        plan = offline_coder.plan_edits("create a file notes/todo.md with remember the milk", ".")
        self.assertFalse(plan["needs_brain"])
        self.assertEqual(plan["ops"][0]["path"], "notes/todo.md")
        self.assertIn("remember the milk", plan["ops"][0]["content"])

    def test_path_traversal_is_refused(self) -> None:
        plan = offline_coder.plan_edits("create a file ../../etc/passwd with x", ".")
        # The traversal path is rejected -> no op -> defers to a brain rather than escaping the workspace.
        self.assertTrue(plan["needs_brain"])

    def test_novel_logic_defers_to_a_brain(self) -> None:
        plan = offline_coder.plan_edits("implement an LRU cache with TTL eviction and metrics", ".")
        self.assertTrue(plan["needs_brain"])
        self.assertEqual(plan["ops"], [])
        self.assertIn("configured brain", plan["summary"])


class RunOfflineIntegrationTests(unittest.TestCase):
    """The no-brain agent path now runs the deterministic offline coder instead of dead-ending."""

    def test_no_brain_run_scaffolds_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            with mock.patch.object(agent, "plan_task", return_value=[]):
                result = agent.run_agent("add a test for compute_total", [], ws, {})  # {} -> no brain
            self.assertEqual(result["provider"], "offline")
            self.assertTrue((Path(ws) / "test_compute_total.py").is_file(), "the stub must be written")
            self.assertTrue(result["verified"], "a valid python stub must pass verify")
            self.assertTrue(result["completed"])

    def test_offline_run_never_overwrites_an_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "test_foo.py").write_text("PRECIOUS = 1\n", encoding="utf-8")
            with mock.patch.object(agent, "plan_task", return_value=[]):
                result = agent.run_agent("add a test for foo", [], ws, {})
            self.assertEqual((Path(ws) / "test_foo.py").read_text(encoding="utf-8"), "PRECIOUS = 1\n",
                             "the offline coder must NOT clobber an existing file")
            self.assertEqual(result["provider"], "offline")

    def test_unmappable_task_returns_honest_message(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            with mock.patch.object(agent, "plan_task", return_value=[]):
                result = agent.run_agent("rewrite the billing engine to use event sourcing", [], ws, {})
            self.assertEqual(result["provider"], "offline")
            self.assertIn("configured brain", result["text"])
            self.assertEqual(result["steps"], 0, "no ops applied for a task it can't template")


_SEED = BACKEND_DIR / "seed"


class RetrievalTests(unittest.TestCase):
    """Move 3 — the plan is made repo-specific via manifest/stack retrieval + the seed/snippets library."""

    def test_test_framework_detected_from_repo(self) -> None:
        # pytest repo (a conftest.py) -> a pytest-style stub (no unittest.TestCase).
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "conftest.py").write_text("", encoding="utf-8")
            plan = offline_coder.plan_edits("add a test for parse_config", td, seed_dir=_SEED)
            content = plan["ops"][0]["content"]
            compile(content, "t.py", "exec")
            self.assertIn("def test_parse_config_placeholder", content)
            self.assertNotIn("import unittest", content)
            self.assertIn("pytest", plan["summary"])
        # plain repo -> unittest scaffold.
        with tempfile.TemporaryDirectory() as td:
            plan = offline_coder.plan_edits("add a test for parse_config", td, seed_dir=_SEED)
            self.assertIn("import unittest", plan["ops"][0]["content"])
            self.assertIn("unittest", plan["summary"])

    def test_flask_route_is_gated_on_flask_presence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertTrue(offline_coder.plan_edits("add a route /users", td, seed_dir=_SEED)["needs_brain"])
            (Path(td) / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
            plan = offline_coder.plan_edits("add a route /users/profile", td, seed_dir=_SEED)
            self.assertFalse(plan["needs_brain"])
            self.assertEqual(plan["ops"][0]["path"], "users_profile_route.py")
            compile(plan["ops"][0]["content"], "r.py", "exec")

    def test_dockerfile_and_ci_intents(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(offline_coder.plan_edits("add a dockerfile", td, seed_dir=_SEED)["ops"][0]["path"], "Dockerfile")
            ci = offline_coder.plan_edits("set up a CI workflow", td, seed_dir=_SEED)
            self.assertEqual(ci["ops"][0]["path"], ".github/workflows/ci.yml")

    def test_run_agent_uses_seed_snippets_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "conftest.py").write_text("", encoding="utf-8")  # -> pytest template
            with mock.patch.object(agent, "plan_task", return_value=[]):
                result = agent.run_agent("add a test for compute_total", [], ws, {}, seed_dir=_SEED)
            written = (Path(ws) / "test_compute_total.py").read_text(encoding="utf-8")
            self.assertIn("def test_compute_total_placeholder", written)
            self.assertNotIn("import unittest", written)  # pytest style from retrieval
            self.assertTrue(result["verified"])


class CodegenIntentDetectorTests(unittest.TestCase):
    """Move 1: the honest short-circuit fires on code-WRITING intent, not code discussion."""

    def test_positive_codegen_requests(self) -> None:
        for msg in ["write me a function to sort a list", "fix this script", "generate a pytest test",
                    "create a python function", "add an endpoint", "implement a class Foo",
                    "refactor this code", "make a dockerfile"]:
            self.assertTrue(greyiq_api._looks_like_codegen_request(msg), msg)

    def test_negative_non_codegen(self) -> None:
        for msg in ["what is an API?", "explain how python works", "who wrote the linux kernel",
                    "summarize this article", "what does refactor mean"]:
            self.assertFalse(greyiq_api._looks_like_codegen_request(msg), msg)


if __name__ == "__main__":
    unittest.main()
