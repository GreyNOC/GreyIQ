"""Tests for surface expansion: served-JS mining (recon_js) and tech fingerprinting —
both pure (no network)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import fingerprint, recon_js  # noqa: E402


class MineJsTests(unittest.TestCase):
    JS = (
        'const A = "/api/v2/users"; fetch("/api/graphql");'
        ' var img = "https://cdn.acme.com/x"; var ext = "https://evil.test/y";'
        ' const q = "/search?token=abc&user_id=5&q_term=1";'
        ' const css = "/static/app.css";'
    )

    def test_endpoints_are_in_scope_only(self) -> None:
        m = recon_js.mine_js(self.JS, "https://app.acme.com/main.js", host_filter=lambda h: h.endswith("acme.com"))
        self.assertIn("https://app.acme.com/api/v2/users", m["endpoints"])
        self.assertIn("https://app.acme.com/api/graphql", m["endpoints"])
        # A path without an api/graphql/version hint isn't an endpoint candidate.
        self.assertFalse(any("app.css" in e for e in m["endpoints"]))

    def test_params_extracted(self) -> None:
        m = recon_js.mine_js(self.JS, "https://app.acme.com/main.js")
        self.assertEqual(set(m["params"]), {"token", "user_id", "q_term"})

    def test_same_apex_hosts_only_by_default(self) -> None:
        m = recon_js.mine_js(self.JS, "https://app.acme.com/main.js")
        self.assertIn("cdn.acme.com", m["hosts"])         # same registrable apex
        self.assertNotIn("evil.test", m["hosts"])          # unrelated host dropped

    def test_secrets_are_redacted(self) -> None:
        secret = "AKIA" + "IOSFODNN7EXAMPLE"
        m = recon_js.mine_js(f'var k = "{secret}";', "https://app.acme.com/main.js")
        self.assertTrue(m["secret_findings"])
        for f in m["secret_findings"]:
            self.assertTrue(f["redacted"])
            self.assertNotIn(secret, str(f))  # the raw key never leaks


class FingerprintTests(unittest.TestCase):
    def test_header_cookie_body_signals(self) -> None:
        fp = fingerprint.fingerprint({"X-Powered-By": "PHP/8.1", "Server": "nginx"},
                                     "<html>wp-content __NEXT_DATA__</html>", ["PHPSESSID=x"])
        self.assertIn("PHP", fp["tech"])
        self.assertIn("WordPress", fp["tech"])
        self.assertIn("rce", fp["hints"])  # PHP -> emphasize rce checks

    def test_fails_open_to_empty(self) -> None:
        self.assertEqual(fingerprint.fingerprint(None, None, None), {"tech": [], "hints": {}})

    def test_hints_are_class_ids(self) -> None:
        fp = fingerprint.fingerprint({"Server": "Werkzeug/2.0"}, "<html>csrfmiddlewaretoken</html>", [])
        # Flask + Django markers both hint SSTI emphasis.
        self.assertIn("ssti", fp["hints"])


if __name__ == "__main__":
    unittest.main()
