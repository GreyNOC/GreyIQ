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


class CallUrlRegexTests(unittest.TestCase):
    """_CALL_URL_RE (fetch/axios/.open call targets) had no dedicated coverage --
    only ever exercised incidentally through _ENDPOINT_RE-matching literals."""

    def test_fetch_call_target_is_an_endpoint_candidate(self) -> None:
        m = recon_js.mine_js('fetch("/api/orders")', "https://app.acme.com/main.js")
        self.assertIn("https://app.acme.com/api/orders", m["endpoints"])

    def test_axios_method_call_target_is_an_endpoint_candidate(self) -> None:
        m = recon_js.mine_js('axios.get("/api/v2/orders")', "https://app.acme.com/main.js")
        self.assertIn("https://app.acme.com/api/v2/orders", m["endpoints"])

    def test_axios_bare_call_target_is_an_endpoint_candidate(self) -> None:
        m = recon_js.mine_js('axios("/api/v3/orders")', "https://app.acme.com/main.js")
        self.assertIn("https://app.acme.com/api/v3/orders", m["endpoints"])

    def test_xhr_open_call_target_is_an_endpoint_candidate(self) -> None:
        m = recon_js.mine_js('xhr.open("GET", "/api/v1/orders")', "https://app.acme.com/main.js")
        self.assertIn("https://app.acme.com/api/v1/orders", m["endpoints"])

    def test_call_target_without_a_leading_slash_or_scheme_is_dropped(self) -> None:
        m = recon_js.mine_js('fetch("api/orders")', "https://app.acme.com/main.js")
        self.assertFalse(any("api/orders" in e for e in m["endpoints"]))

    def test_call_target_without_an_endpoint_hint_is_dropped(self) -> None:
        m = recon_js.mine_js('fetch("/static/app.css")', "https://app.acme.com/main.js")
        self.assertEqual(m["endpoints"], [])

    def test_absolute_call_target_on_an_out_of_scope_host_is_dropped_by_default(self) -> None:
        m = recon_js.mine_js('fetch("https://evil.test/api/steal")', "https://app.acme.com/main.js")
        self.assertEqual(m["endpoints"], [])

    def test_absolute_call_target_admitted_when_host_filter_allows_it(self) -> None:
        m = recon_js.mine_js('fetch("https://partner.example.com/api/data")', "https://app.acme.com/main.js",
                              host_filter=lambda h: h in {"app.acme.com", "partner.example.com"})
        self.assertIn("https://partner.example.com/api/data", m["endpoints"])


class RedirectedBaseUrlTests(unittest.TestCase):
    """recon.py passes ``jf.get("final_url") or js_url`` as base_url -- when a served
    JS file was itself redirected, mine_js's default same-origin scoping must key off
    the FINAL (post-redirect) host, not wherever the script tag originally pointed."""

    def test_default_scoping_uses_the_redirected_final_host(self) -> None:
        js = 'fetch("/api/v2/orders"); var img = "https://cdn.new-host.example/x";'
        # base_url reflects the redirect TARGET (new-host.example), not the origin
        # the <script src> was served from.
        m = recon_js.mine_js(js, "https://new-host.example/main.js")
        self.assertIn("https://new-host.example/api/v2/orders", m["endpoints"])
        self.assertIn("cdn.new-host.example", m["hosts"])  # same apex as the redirected host

    def test_relative_paths_resolve_against_the_redirected_base_not_the_original(self) -> None:
        m = recon_js.mine_js('fetch("/api/v1/x")', "https://redirected.acme.com/scripts/main.js")
        self.assertIn("https://redirected.acme.com/api/v1/x", m["endpoints"])


class HostMiningHostFilterTests(unittest.TestCase):
    def test_explicit_host_filter_admits_a_cross_apex_host(self) -> None:
        js = 'var cdn = "https://assets.some-other-cdn.example/logo.png";'
        m = recon_js.mine_js(js, "https://app.acme.com/main.js",
                              host_filter=lambda h: h == "assets.some-other-cdn.example")
        self.assertIn("assets.some-other-cdn.example", m["hosts"])

    def test_host_filter_still_excludes_hosts_it_rejects(self) -> None:
        js = 'var cdn = "https://tracker.evil.test/beacon";'
        m = recon_js.mine_js(js, "https://app.acme.com/main.js", host_filter=lambda h: False)
        self.assertNotIn("tracker.evil.test", m["hosts"])


class MineJsCapTests(unittest.TestCase):
    """Every extracted list is capped so a hostile/huge JS bundle can't blow up
    memory or downstream processing -- previously untested."""

    def test_endpoints_are_capped(self) -> None:
        js = " ".join(f'fetch("/api/v2/thing{i}");' for i in range(200))
        m = recon_js.mine_js(js, "https://app.acme.com/main.js")
        self.assertEqual(len(m["endpoints"]), recon_js._CAP_ENDPOINTS)

    def test_hosts_are_capped(self) -> None:
        js = " ".join(f'var x{i} = "https://sub{i}.acme.com/y";' for i in range(100))
        m = recon_js.mine_js(js, "https://app.acme.com/main.js")
        self.assertEqual(len(m["hosts"]), recon_js._CAP_HOSTS)

    def test_params_are_capped(self) -> None:
        js = " ".join(f'"/api/v2/x?param{i}=1"' for i in range(150))
        m = recon_js.mine_js(js, "https://app.acme.com/main.js")
        self.assertEqual(len(m["params"]), recon_js._CAP_PARAMS)

    def test_secrets_are_capped(self) -> None:
        js = " ".join(f'var k{i} = "AKIA{i:016d}";' for i in range(50))
        m = recon_js.mine_js(js, "https://app.acme.com/main.js")
        self.assertLessEqual(len(m["secret_findings"]), recon_js._CAP_SECRETS)


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
