"""Coding-agent contract for the read-only investigation tool."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402


class AgentInvestigateToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.box = agent.ToolBox(Path(self.tmp.name), dict(agent.AGENT_DEFAULTS))
        self.original_scan = agent.scan_service.run_code_scan

    def tearDown(self) -> None:
        agent.scan_service.run_code_scan = self.original_scan
        self.tmp.cleanup()

    def test_tool_returns_ranked_brief_without_raw_secret(self) -> None:
        secret = "ghp_THIS_MUST_NEVER_REACH_A_REMOTE_MODEL_123456"
        agent.scan_service.run_code_scan = lambda *args, **kwargs: {
            "ok": True, "files_scanned": 2, "files_skipped": 0, "finding_count": 1,
            "risk": "high", "findings": [{
                "rule_id": "secret.github-pat", "title": "GitHub token",
                "severity": "high", "confidence": "high", "category": "secret",
                "file_path": "app.py", "line_start": 7, "line_end": 7,
                "snippet": "token = <redacted>", "secret_value": secret,
                "remediation": "Revoke and rotate the token.",
            }],
        }
        output, is_error = self.box.run("investigate_code", {"path": ".", "max_files": 20})
        self.assertFalse(is_error, output)
        self.assertIn("INVESTIGATION CORTEX", output)
        self.assertIn("RANKED HYPOTHESES", output)
        self.assertIn("app.py:7", output)
        self.assertNotIn(secret, output)

    def test_tool_is_registered(self) -> None:
        definition = next(item for item in agent._TOOLS if item["name"] == "investigate_code")
        self.assertIn("never modifies", definition["description"])

    def test_running_the_tool_leaves_the_workspace_byte_identical(self) -> None:
        """The read-only claim, asserted against the filesystem rather than the tool's own
        description: a full run over a real workspace must not add, drop or alter a byte."""
        root = Path(self.tmp.name)
        (root / "unsafe.py").write_text(
            "import os\n\ndef run(user_input):\n    return os.system(user_input)\n", encoding="utf-8"
        )
        (root / "notes.md").write_text("# notes\n", encoding="utf-8")
        before = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}

        output, is_error = self.box.run("investigate_code", {"path": ".", "max_files": 20})
        self.assertFalse(is_error, output)

        after = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(self.box.touched, set())
        self.assertFalse(getattr(self.box, "changes", None))

    def test_the_tool_cannot_read_outside_the_workspace(self) -> None:
        for escape in ("../", "../../../../../../etc/passwd", "..\\..\\Windows\\win.ini", "/etc/passwd"):
            with self.subTest(path=escape):
                output, is_error = self.box.run("investigate_code", {"path": escape, "max_files": 5})
                self.assertTrue(is_error, f"{escape!r} was not refused: {output}")

    def test_real_scanner_finds_sink_but_keeps_it_candidate(self) -> None:
        Path(self.tmp.name, "unsafe.py").write_text(
            "import os\n\ndef run(user_input):\n    return os.system(user_input)\n",
            encoding="utf-8",
        )
        output, is_error = self.box.run("investigate_code", {"path": "unsafe.py", "max_files": 5})
        self.assertFalse(is_error, output)
        self.assertIn("unsafe.py:4", output)
        self.assertIn("rce - Python os.system", output)
        self.assertIn("gather-proof", output)
        self.assertIn("static matches remain candidates", output)
        self.assertEqual(self.box.touched, set())


if __name__ == "__main__":
    unittest.main()
