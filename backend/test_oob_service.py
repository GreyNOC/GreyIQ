"""Tests for the OOB (out-of-band) blind-SSRF confirm via an operator collaborator.

No network: the target HTTP and the collaborator poll are stubbed. A recorded callback
confirms blind SSRF; no callback never confirms; the scope gate is fail-closed.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import oob_service as oob  # noqa: E402
from bughunter.settings import get_settings  # noqa: E402


class FakeHttp:
    def __init__(self):
        self.fetched: list[str] = []

    def fetch(self, url, **kwargs):
        self.fetched.append(url)
        return {"status": 200, "headers": {}, "body": "", "cookies": [], "final_url": url, "location": None}


class HelperTests(unittest.TestCase):
    def test_mint_token_is_unique_hex(self) -> None:
        a, b = oob.mint_token(), oob.mint_token()
        self.assertRegex(a, r"^[0-9a-f]{32}$")
        self.assertNotEqual(a, b)

    def test_callback_url(self) -> None:
        self.assertEqual(oob.callback_url("https://c.example/", "abc123"), "https://c.example/oob/abc123")
        self.assertEqual(oob.callback_url("https://c.example", "abc123"), "https://c.example/oob/abc123")

    def test_poll_requires_config(self) -> None:
        self.assertFalse(oob.poll_collaborator("", "secret", "tok")["ok"])
        self.assertFalse(oob.poll_collaborator("https://c.example", "", "tok")["ok"])
        self.assertFalse(oob.poll_collaborator("https://c.example", "secret", "")["ok"])


class ConfirmTests(unittest.TestCase):
    def setUp(self) -> None:
        self._guard = oob._guard_url
        self._poll = oob.poll_collaborator
        oob._guard_url = lambda u, *a, **k: u  # bypass DNS/SSRF guard in tests

    def tearDown(self) -> None:
        oob._guard_url = self._guard
        oob.poll_collaborator = self._poll

    def test_confirms_blind_ssrf_on_a_callback_hit(self) -> None:
        seen = {}
        def fake_poll(base, secret, token, **k):
            seen["token"] = token
            return {"ok": True, "count": 1, "hits": [{"method": "GET", "path": f"/oob/{token}", "ip": "9.9.9.9"}]}
        oob.poll_collaborator = fake_poll
        http = FakeHttp()
        res = oob.confirm_blind_ssrf(
            "https://app.example.com/?url=x", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(), http=http, poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["finding"]["class_id"], "ssrf")
        self.assertEqual(res["finding"]["rule_id"], "active.blind-ssrf-oob")
        self.assertEqual(res["attack_plan"]["proof_of_impact"]["status"], "confirmed")
        # the probe injected the unique callback token into the target's 'url' param
        # (the callback URL is urlencoded, so the surrounding /oob/ becomes %2Foob%2F).
        self.assertTrue(any(seen["token"] in u for u in http.fetched))
        # no target data is embedded — the proof is the OOB callback
        self.assertEqual(res["finding"]["snippet"], "")

    def test_no_callback_does_not_confirm(self) -> None:
        oob.poll_collaborator = lambda base, secret, token, **k: {"ok": True, "count": 0, "hits": []}
        res = oob.confirm_blind_ssrf(
            "https://app.example.com/?url=x", base="https://collab.example", secret="s" * 16,
            scope="app.example.com", settings=get_settings(), http=FakeHttp(), poll_attempts=1, poll_delay_s=0.0)
        self.assertEqual(res["status"], "no-callback")
        self.assertNotIn("finding", res)

    def test_out_of_scope_target_refused(self) -> None:
        res = oob.confirm_blind_ssrf(
            "https://evil.example/?url=x", base="https://collab.example", secret="s" * 16,
            scope="other.example", settings=get_settings(), http=FakeHttp(), poll_delay_s=0.0)
        self.assertFalse(res["ok"])
        self.assertIn("scope", res["error"].lower())

    def test_unconfigured_collaborator_errors(self) -> None:
        res = oob.confirm_blind_ssrf("https://app.example.com/?url=x", base="", secret="",
                                     scope="app.example.com", settings=get_settings())
        self.assertFalse(res["ok"])
        self.assertIn("collaborator", res["error"].lower())


if __name__ == "__main__":
    unittest.main()
