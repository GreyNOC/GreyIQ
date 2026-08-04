"""A configured-but-failing brain must be distinguishable from no brain at all.

`_ask_brain` returns `used=False` for both "nothing configured" and "Claude rejected the API key",
so the operator progress line used to report an auth failure, a timeout, or a 429 as
"brain enrichment skipped (no brain configured)" — pointing at the wrong problem. The failure
reason is now carried on `brain["error"]` so the caller can say which one actually happened.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
from bughunter import bounty  # noqa: E402

_FINDINGS = [{"ref": "F1", "title": "x", "class_name": "XSS", "location": "https://t/?q=", "snippet": ""}]


class BrainFailureReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = (coder.coder_enabled, coder.coder_config, coder.generate)
        self.addCleanup(self._restore)
        coder.coder_config = lambda cfg: {"provider": "x"}

    def _restore(self) -> None:
        coder.coder_enabled, coder.coder_config, coder.generate = self._orig

    def _ask(self) -> dict:
        return bounty._ask_brain({"provider": "x"}, "https://t", {"name": "web-app"}, None, "t",
                                 _FINDINGS, "playbook guidance")

    def test_no_brain_configured_reports_no_error(self) -> None:
        coder.coder_enabled = lambda cfg: False
        brain = self._ask()
        self.assertFalse(brain["used"])
        self.assertEqual(brain["error"], "")

    def test_rejected_api_key_is_recorded_as_an_error(self) -> None:
        coder.coder_enabled = lambda cfg: True

        def _reject(messages, cfg):
            raise coder.CoderError("Claude rejected the API key (authentication failed).")

        coder.generate = _reject
        brain = self._ask()
        self.assertFalse(brain["used"])
        # The distinguishing signal: configured-but-broken carries a reason, unconfigured does not.
        self.assertIn("authentication failed", brain["error"])

    def test_timeout_is_recorded_as_an_error_too(self) -> None:
        coder.coder_enabled = lambda cfg: True

        def _timeout(messages, cfg):
            raise coder.CoderError("Claude request failed: timed out")

        coder.generate = _timeout
        brain = self._ask()
        self.assertFalse(brain["used"])
        self.assertIn("timed out", brain["error"])

    def test_successful_enrichment_carries_no_error(self) -> None:
        coder.coder_enabled = lambda cfg: True
        coder.generate = lambda m, c: {"text": "{}", "provider": "anthropic", "model": "claude"}
        brain = self._ask()
        self.assertTrue(brain["used"])
        self.assertEqual(brain["error"], "")


if __name__ == "__main__":
    unittest.main()
