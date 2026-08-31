"""Tests for the verify format coverage added in WS4, plus the offline dispatch fix.

Before this change ``.toml`` / ``.service`` / ``.conf`` / Dockerfile / ``.ps1`` edits all fell into
``_tool_verify``'s ``else: considered -= 1`` arm and were reported as UNVERIFIED — a malformed
pyproject.toml passed. The rule these tests pin down is that coverage may only grow where verify
can genuinely gate the file: a checkable format FAILs when malformed, and an uncheckable one
(PowerShell without commands enabled, a brace-grammar .conf) emits SKIP rather than a false FAIL.
"""
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
import coder  # noqa: E402
import offline_coder  # noqa: E402

_SEED = BACKEND_DIR / "seed"


class _VerifyCase(unittest.TestCase):
    def verify(self, name: str, content: str, **settings: object) -> tuple[str, bool]:
        """Write one file into a temp workspace, mark it touched, and run verify.
        Returns (report, is_error)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            merged = dict(agent.AGENT_DEFAULTS)
            merged.update(settings)
            box = agent.ToolBox(root, merged)
            box.run("write_file", {"path": name, "content": content})
            return box.run("verify", {})


class TomlVerifyTests(_VerifyCase):
    def test_malformed_pyproject_now_fails(self) -> None:
        report, is_error = self.verify("pyproject.toml", '[project\nname = "x"\n')
        self.assertTrue(is_error, report)
        self.assertIn("FAIL pyproject.toml: TOML parse failed", report)

    def test_valid_toml_passes(self) -> None:
        report, is_error = self.verify("pyproject.toml", '[project]\nname = "x"\nversion = "1.0"\n')
        self.assertFalse(is_error, report)
        self.assertIn("OK   pyproject.toml (TOML parse)", report)


class IniVerifyTests(_VerifyCase):
    def test_malformed_systemd_unit_fails(self) -> None:
        report, is_error = self.verify("app.service", "ExecStart=/usr/bin/true\n[Service]\n")
        self.assertTrue(is_error, report)
        self.assertIn("FAIL app.service: config parse failed", report)

    def test_valid_systemd_unit_passes(self) -> None:
        content = "[Unit]\nDescription=App\n\n[Service]\nExecStart=/usr/bin/true\nRestart=always\n"
        report, is_error = self.verify("app.service", content)
        self.assertFalse(is_error, report)
        self.assertIn("OK   app.service (config parse)", report)

    def test_duplicate_keys_and_bare_flags_are_tolerated(self) -> None:
        # systemd legitimately repeats keys and uses valueless directives; the check is structural.
        content = "[Service]\nEnvironment=A=1\nEnvironment=B=2\nPrivateTmp\n"
        report, is_error = self.verify("app.service", content)
        self.assertFalse(is_error, report)

    def test_a_brace_grammar_conf_is_skipped_not_failed(self) -> None:
        # nginx .conf is not INI. Reporting it as broken would be a false FAIL on a file the agent
        # edits constantly, so it must read as UNVERIFIED instead.
        report, is_error = self.verify("nginx.conf", "server {\n    listen 80;\n}\n")
        self.assertFalse(is_error, report)
        self.assertIn("SKIP nginx.conf: not INI-shaped", report)


class DockerfileVerifyTests(_VerifyCase):
    def test_bogus_directive_fails(self) -> None:
        report, is_error = self.verify("Dockerfile", "FROM python:3.11-slim\nFRM alpine\n")
        self.assertTrue(is_error, report)
        self.assertIn("unknown Dockerfile directive 'FRM' on line 2", report)

    def test_a_real_dockerfile_passes(self) -> None:
        content = (
            "# syntax=docker/dockerfile:1\n"
            "FROM python:3.11-slim\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "RUN pip install --no-cache-dir -r requirements.txt \\\n"
            "    && rm -rf /root/.cache\n"
            'CMD ["python", "-m", "app"]\n'
        )
        report, is_error = self.verify("Dockerfile", content)
        self.assertFalse(is_error, report)
        self.assertIn("OK   Dockerfile (Dockerfile directives)", report)

    def test_suffixed_dockerfile_names_are_recognized(self) -> None:
        for name in ("Dockerfile.prod", "api.dockerfile"):
            with self.subTest(name=name):
                report, is_error = self.verify(name, "NOPE something\n")
                self.assertTrue(is_error, report)
                self.assertIn("unknown Dockerfile directive", report)


class PowerShellVerifyTests(_VerifyCase):
    def test_skips_rather_than_fails_when_commands_are_disabled(self) -> None:
        report, is_error = self.verify("deploy.ps1", "Write-Host 'hi'\n", allow_commands=False)
        self.assertFalse(is_error, report)
        self.assertIn("SKIP deploy.ps1: PowerShell syntax check requires commands enabled", report)

    def test_skips_when_powershell_is_not_installed(self) -> None:
        with mock.patch.object(agent.shutil, "which", return_value=None):
            report, is_error = self.verify("deploy.ps1", "Write-Host 'hi'\n", allow_commands=True)
        self.assertFalse(is_error, report)
        self.assertIn("SKIP deploy.ps1: PowerShell is not available", report)

    def test_a_broken_script_fails_when_the_parser_is_available(self) -> None:
        self._require_powershell()
        report, is_error = self.verify("deploy.ps1", "function Broken {\n", allow_commands=True)
        self.assertTrue(is_error, report)
        self.assertIn("FAIL deploy.ps1: PowerShell parse failed", report)

    def test_a_valid_script_passes(self) -> None:
        # Guards the `-Command` argv trap: `-Command <script> <path>` appends the path to the
        # command STRING instead of binding $args, so a `$args[0]` form reports every script —
        # including a perfectly good one — as broken.
        self._require_powershell()
        report, is_error = self.verify(
            "deploy.ps1", "param([string]$Name = 'world')\nWrite-Host \"hello $Name\"\n", allow_commands=True
        )
        self.assertFalse(is_error, report)
        self.assertIn("OK   deploy.ps1 (PowerShell parse)", report)

    def _require_powershell(self) -> None:
        import shutil as _shutil

        if not (_shutil.which("pwsh") or _shutil.which("powershell")):
            self.skipTest("PowerShell is not installed on this host")


class UnverifiableFormatsStayUnverified(_VerifyCase):
    def test_a_markdown_file_still_reports_nothing_to_verify(self) -> None:
        report, is_error = self.verify("NOTES.md", "# hello\n")
        self.assertFalse(is_error, report)
        self.assertIn("Nothing to verify", report)


class OfflineDispatchTests(unittest.TestCase):
    """The second confirmed defect: an EXPLICIT provider='offline' fell through run_agent's
    trailing else, which called _run_offline WITHOUT runtime_dir/seed_dir — so the seed template
    library and the skill hint were silently disabled on the branch a user deliberately chose."""

    def test_explicit_offline_provider_reaches_run_offline_with_seed_dir(self) -> None:
        seen: dict[str, object] = {}
        real = offline_coder.plan_edits

        def spy(message, root, *, seed_dir=None, runtime_dir=None):
            seen["seed_dir"] = seed_dir
            seen["runtime_dir"] = runtime_dir
            return real(message, root, seed_dir=seed_dir, runtime_dir=runtime_dir)

        with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as rt:
            (Path(ws) / "conftest.py").write_text("", encoding="utf-8")  # -> the pytest template
            with mock.patch.object(agent, "plan_task", return_value=[]), \
                 mock.patch.object(offline_coder, "plan_edits", side_effect=spy):
                result = agent.run_agent(
                    "add a test for compute_total", [], ws,
                    {"enabled": True, "provider": "offline"},
                    runtime_dir=rt, seed_dir=_SEED,
                )
            self.assertEqual(str(seen.get("seed_dir")), str(_SEED), "seed_dir must reach the planner")
            self.assertIsNotNone(seen.get("runtime_dir"), "runtime_dir must reach the planner")
            self.assertEqual(result["provider"], "offline")
            written = Path(ws) / "test_compute_total.py"
            self.assertTrue(written.is_file())
            # Proof the SEED template resolved rather than the bundled unittest fallback.
            self.assertNotIn("import unittest", written.read_text(encoding="utf-8"))

    def test_deterministic_provider_alias_also_routes_offline(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            with mock.patch.object(agent, "plan_task", return_value=[]):
                result = agent.run_agent(
                    "add a test for compute_total", [], ws,
                    {"enabled": True, "provider": "deterministic"}, seed_dir=_SEED,
                )
            self.assertEqual(result["provider"], "offline")
            self.assertTrue((Path(ws) / "test_compute_total.py").is_file())

    def test_public_config_reports_the_deterministic_engine_honestly(self) -> None:
        safe = coder.public_config({"enabled": True, "provider": "offline"})
        self.assertTrue(safe["deterministic"])
        self.assertIn("offline", safe["deterministic_providers"])
        self.assertFalse(coder.public_config({"enabled": True, "provider": "anthropic"})["deterministic"])

    def test_generate_gives_an_honest_error_for_the_deterministic_provider(self) -> None:
        with self.assertRaises(coder.CoderError) as ctx:
            coder.generate([{"role": "user", "content": "hi"}], {"enabled": True, "provider": "offline"})
        self.assertIn("does not chat", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
