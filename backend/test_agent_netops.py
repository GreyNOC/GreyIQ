"""Tests for the network-operations and coding-robustness agent additions:
net_probe (DNS/TCP/HTTP/TLS diagnostics), read_file line ranges, verify's test
auto-detection, and the netops-diagnostics skill. Offline-safe: live probes hit
only localhost; the happy-path TLS/HTTP behaviour is covered by parsing/guard tests
rather than reaching the internet (which would be flaky in CI)."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402
import skills as skills_lib  # noqa: E402

# verify's pytest path is only exercised when pytest is importable — the same check
# agent._detect_test_command() makes. Skip (don't fail) the pytest-dependent cases when
# it is absent, e.g. on the CI runner, which installs requirements.txt without pytest.
_PYTEST_AVAILABLE = importlib.util.find_spec("pytest") is not None
_NEEDS_PYTEST = unittest.skipUnless(_PYTEST_AVAILABLE, "pytest is not installed")


def _settings(**overrides: object) -> dict[str, object]:
    settings = dict(agent.AGENT_DEFAULTS)
    settings.update(overrides)
    return settings


class AgentSettingsTests(unittest.TestCase):
    def test_defaults_include_network_settings(self) -> None:
        self.assertIn("allow_network", agent.AGENT_DEFAULTS)
        self.assertIn("net_timeout_s", agent.AGENT_DEFAULTS)
        self.assertTrue(agent.AGENT_DEFAULTS["allow_network"])


class NetProbeToolTests(unittest.TestCase):
    def _box(self, **overrides: object) -> agent.ToolBox:
        return agent.ToolBox(Path(tempfile.gettempdir()), _settings(**overrides))

    def test_net_probe_registered_in_all_tool_schemas(self) -> None:
        self.assertIn("net_probe", {t["name"] for t in agent._TOOLS})
        self.assertIn("net_probe", {t["name"] for t in agent._anthropic_tools()})
        self.assertIn("net_probe", {t["function"]["name"] for t in agent._openai_tools()})

    def test_dns_resolves_localhost(self) -> None:
        out, is_error = self._box().run("net_probe", {"action": "dns", "target": "localhost"})
        self.assertFalse(is_error)
        self.assertIn("DNS localhost:", out)
        self.assertTrue("127.0.0.1" in out or "::1" in out)

    def test_tcp_closed_port_is_not_open(self) -> None:
        # Port 1 on loopback is effectively never listening: a valid diagnostic, not a tool error.
        out, is_error = self._box().run("net_probe", {"action": "tcp", "target": "127.0.0.1", "port": 1})
        self.assertFalse(is_error)
        self.assertIn("127.0.0.1:1", out)
        self.assertNotIn("OPEN", out)

    def test_unknown_action_errors(self) -> None:
        out, is_error = self._box().run("net_probe", {"action": "frob", "target": "x"})
        self.assertTrue(is_error)
        self.assertIn("Unknown action", out)

    def test_http_rejects_non_http_scheme(self) -> None:
        out, is_error = self._box().run("net_probe", {"action": "http", "target": "ftp://example.com"})
        self.assertTrue(is_error)
        self.assertIn("http://", out)

    def test_tcp_requires_a_port(self) -> None:
        out, is_error = self._box().run("net_probe", {"action": "tcp", "target": "localhost"})
        self.assertTrue(is_error)
        self.assertIn("port", out)

    def test_port_out_of_range_errors(self) -> None:
        out, is_error = self._box().run("net_probe", {"action": "tcp", "target": "localhost", "port": 70000})
        self.assertTrue(is_error)
        self.assertIn("between 1 and 65535", out)

    def test_tls_defaults_to_443_when_no_port(self) -> None:
        # No port given + tls => should attempt port 443 (not raise "needs a port").
        out, _ = self._box(net_timeout_s=0.2).run("net_probe", {"action": "tls", "target": "127.0.0.1"})
        self.assertIn("127.0.0.1:443", out)

    def test_network_gate_disables_probe(self) -> None:
        out, is_error = self._box(allow_network=False).run("net_probe", {"action": "dns", "target": "localhost"})
        self.assertTrue(is_error)
        self.assertIn("disabled", out)

    def test_split_host_port(self) -> None:
        self.assertEqual(agent._split_host_port("example.com"), ("example.com", None))
        self.assertEqual(agent._split_host_port("example.com:8443"), ("example.com", 8443))
        self.assertEqual(agent._split_host_port("https://api.example.com:443/health"), ("api.example.com", 443))
        self.assertEqual(agent._split_host_port("http://example.com/path"), ("example.com", None))

    def test_tls_days_left_parsing(self) -> None:
        self.assertIsNone(agent._tls_days_left("not a date"))
        self.assertGreater(agent._tls_days_left("Jan  1 00:00:00 2099 GMT"), 1000)


class ReadFileRangeTests(unittest.TestCase):
    def _box_with_file(self, tmp: str, name: str, content: str, **overrides: object) -> agent.ToolBox:
        (Path(tmp) / name).write_text(content, encoding="utf-8")
        return agent.ToolBox(Path(tmp), _settings(**overrides))

    def test_reads_requested_line_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            box = self._box_with_file(tmp, "big.txt", "".join(f"line{i}\n" for i in range(1, 101)))
            out, is_error = box.run("read_file", {"path": "big.txt", "offset": 10, "limit": 3})
            self.assertFalse(is_error)
            self.assertIn("[lines 10-12", out)
            self.assertIn("line10", out)
            self.assertIn("line12", out)
            self.assertNotIn("line13", out)

    def test_offset_past_eof_reports_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            box = self._box_with_file(tmp, "small.txt", "a\nb\n")
            out, is_error = box.run("read_file", {"path": "small.txt", "offset": 100})
            self.assertFalse(is_error)
            self.assertIn("past the end", out)

    def test_oversized_file_without_range_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            box = self._box_with_file(tmp, "huge.txt", "x" * 4000, max_file_bytes=1000)
            out, is_error = box.run("read_file", {"path": "huge.txt"})
            self.assertTrue(is_error)
            self.assertIn("offset/limit", out)

    def test_oversized_file_with_range_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            content = "".join(f"row{i}\n" for i in range(1, 500))
            box = self._box_with_file(tmp, "huge.txt", content, max_file_bytes=100)
            out, is_error = box.run("read_file", {"path": "huge.txt", "offset": 1, "limit": 2})
            self.assertFalse(is_error)
            self.assertIn("row1", out)
            self.assertIn("row2", out)

    def test_non_integer_offset_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            box = self._box_with_file(tmp, "f.txt", "a\n")
            out, is_error = box.run("read_file", {"path": "f.txt", "offset": "abc"})
            self.assertTrue(is_error)
            self.assertIn("integer", out)


class VerifyTestDetectionTests(unittest.TestCase):
    @_NEEDS_PYTEST
    def test_pytest_detected_and_reported_when_commands_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "test_sample.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
            box = agent.ToolBox(Path(tmp), _settings(allow_commands=False))
            out, is_error = box.run("verify", {})
            self.assertFalse(is_error)
            self.assertIn("VERIFY PASSED", out)
            self.assertIn("tests detected", out)
            self.assertIn("pytest", out)

    @_NEEDS_PYTEST
    def test_pytest_runs_and_passes_when_commands_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "test_pass.py").write_text("def test_ok():\n    assert 1 + 1 == 2\n", encoding="utf-8")
            box = agent.ToolBox(Path(tmp), _settings(allow_commands=True))
            out, is_error = box.run("verify", {})
            self.assertFalse(is_error)
            self.assertIn("VERIFY PASSED", out)
            self.assertIn("tests passed", out)

    @_NEEDS_PYTEST
    def test_pytest_runs_and_fails_when_commands_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "test_fail.py").write_text("def test_bad():\n    assert False\n", encoding="utf-8")
            box = agent.ToolBox(Path(tmp), _settings(allow_commands=True))
            out, is_error = box.run("verify", {})
            self.assertTrue(is_error)
            self.assertIn("VERIFY FAILED", out)
            self.assertIn("tests failed", out)

    def test_npm_test_script_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text('{"scripts":{"test":"jest"}}', encoding="utf-8")
            box = agent.ToolBox(Path(tmp), _settings())
            self.assertEqual(box._detect_test_command(), ("npm test", "npm test"))

    def test_npm_no_test_specified_placeholder_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(
                '{"scripts":{"test":"echo \\"Error: no test specified\\" && exit 1"}}', encoding="utf-8"
            )
            box = agent.ToolBox(Path(tmp), _settings())
            self.assertIsNone(box._detect_test_command())

    def test_watch_mode_test_script_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text('{"scripts":{"test":"vitest --watch"}}', encoding="utf-8")
            box = agent.ToolBox(Path(tmp), _settings())
            self.assertIsNone(box._detect_test_command())

    def test_pnpm_lockfile_selects_pnpm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text('{"scripts":{"test":"jest"}}', encoding="utf-8")
            (Path(tmp) / "pnpm-lock.yaml").write_text("", encoding="utf-8")
            box = agent.ToolBox(Path(tmp), _settings())
            self.assertEqual(box._detect_test_command(), ("pnpm test", "pnpm test"))


class NetopsSkillTests(unittest.TestCase):
    def test_netops_skill_loads_and_is_selected_for_network_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            loaded = skills_lib.load_skills(Path(tmp), BACKEND_DIR / "seed", None)
        self.assertIn("netops-diagnostics", {skill.name for skill in loaded})
        selected = skills_lib.select_skills(
            "diagnose a connection timeout: the port is unreachable and DNS may not resolve", loaded
        )
        self.assertTrue(selected)
        self.assertEqual("netops-diagnostics", selected[0].name)


if __name__ == "__main__":
    unittest.main()
