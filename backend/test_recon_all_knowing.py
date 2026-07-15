"""'All-knowing within scope' recon expansion: deeper JS/inline/comment/sitemap surface discovery,
each proven to stay strictly within scope (the paramount constraint) via a stubbed fetcher."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import recon, recon_js  # noqa: E402
from bughunter.recon_js import mine_js, mine_source_map, source_map_urls  # noqa: E402


def _resp(body: str, final: str, ctype: str = "text/html") -> dict:
    return {"status": 200, "final_url": final, "headers": {"content-type": ctype}, "cookies": [], "body": body}


class ReconSurfaceExpansionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_fetch = recon._safe_fetch  # restore in tearDown so the module-level monkeypatch never leaks into other tests
        self.addCleanup(lambda: setattr(recon, "_safe_fetch", self._orig_fetch))

    def _discover(self, pages: dict, scope: set, **kw):
        recon._safe_fetch = lambda url, s, g: pages.get(url) or {"status": 404, "final_url": url, "headers": {}, "cookies": [], "body": ""}
        return recon.discover("https://example.com/", scope_in=lambda h: h in scope,
                              max_pages=kw.get("max_pages", 50), max_requests=kw.get("max_requests", 40))

    def test_inline_js_and_comment_endpoints_are_crawled(self) -> None:
        pages = {"https://example.com/": _resp(
            '<script>fetch("/checkout")</script><!-- TODO /admin/panel http://evil.com/x -->',
            "https://example.com/")}
        urls = set(self._discover(pages, {"example.com"})["urls"])
        self.assertTrue(any("/checkout" in u for u in urls))       # inline route
        self.assertTrue(any("/admin/panel" in u for u in urls))    # commented route
        self.assertFalse(any("evil.com" in u for u in urls))       # OOS comment URL dropped

    def test_js_mined_endpoint_and_sibling_host_are_reachable(self) -> None:
        pages = {
            "https://example.com/": _resp('<script src="/app.js"></script>', "https://example.com/"),
            "https://example.com/app.js": _resp('axios.get("/api/orders"); var u="https://api.example.com/v1/me";',
                                                "https://example.com/app.js", "application/javascript"),
        }
        urls = set(self._discover(pages, {"example.com", "api.example.com"})["urls"])
        self.assertTrue(any("/api/orders" in u for u in urls))                 # JS-mined route crawled
        self.assertTrue(any(u.startswith("https://api.example.com") for u in urls))  # in-scope sibling seeded

    def test_out_of_scope_js_host_is_never_seeded(self) -> None:
        pages = {
            "https://example.com/": _resp('<script src="/app.js"></script>', "https://example.com/"),
            "https://example.com/app.js": _resp('fetch("https://evil-cdn.com/track");', "https://example.com/app.js", "application/javascript"),
        }
        urls = set(self._discover(pages, {"example.com"})["urls"])
        self.assertFalse(any("evil-cdn" in u for u in urls))  # mine_js keep_host + in_scope both drop it

    def test_sitemap_index_and_robots_sitemap_recursion(self) -> None:
        pages = {
            "https://example.com/": _resp("<html></html>", "https://example.com/"),
            "https://example.com/robots.txt": _resp(
                "Sitemap: https://example.com/sm_news.xml\nSitemap: https://evil.com/oos.xml",
                "https://example.com/robots.txt", "text/plain"),
            "https://example.com/sitemap.xml": _resp(
                "<sitemapindex><sitemap><loc>https://example.com/sm_products.xml</loc></sitemap></sitemapindex>",
                "https://example.com/sitemap.xml", "application/xml"),
            "https://example.com/sm_products.xml": _resp(
                "<urlset><url><loc>https://example.com/product/42</loc></url><url><loc>https://example.com/product/99</loc></url></urlset>",
                "https://example.com/sm_products.xml", "application/xml"),
            "https://example.com/sm_news.xml": _resp(
                "<urlset><url><loc>https://example.com/news/launch</loc></url></urlset>",
                "https://example.com/sm_news.xml", "application/xml"),
        }
        urls = set(self._discover(pages, {"example.com"})["urls"])
        self.assertTrue(any("/product/42" in u for u in urls) and any("/product/99" in u for u in urls))  # index->child->pages, distinct kept
        self.assertTrue(any("/news/launch" in u for u in urls))    # robots Sitemap: -> child pages
        self.assertFalse(any("evil.com" in u for u in urls))       # OOS Sitemap: dropped


class MineJsHintExemptionTests(unittest.TestCase):
    def test_call_target_route_kept_without_hint(self) -> None:
        m = mine_js('fetch("/checkout")', "https://app.acme.com/", host_filter=lambda h: h == "app.acme.com")
        self.assertIn("https://app.acme.com/checkout", m["endpoints"])  # a route needs no api/v1 hint now

    def test_call_target_static_asset_still_dropped(self) -> None:
        m = mine_js('fetch("/static/app.css")', "https://app.acme.com/", host_filter=lambda h: h == "app.acme.com")
        self.assertEqual(m["endpoints"], [])  # a static asset is not an injectable endpoint

    def test_out_of_scope_call_target_dropped(self) -> None:
        m = mine_js('fetch("https://evil.com/checkout")', "https://app.acme.com/", host_filter=lambda h: h == "app.acme.com")
        self.assertEqual(m["endpoints"], [])  # keep_host drops it even though it's a route

    def test_hinted_static_asset_literal_is_dropped(self) -> None:
        # vet finding: a static asset whose path carries an endpoint-hint substring ('/api/...report.pdf')
        # previously bypassed the _STATIC_EXT filter (which only ran on hint-exempt call targets).
        js = 'var a="/api/v1/report.pdf"; var b="/api/assets/logo.png"; axios.get("/api/v1/orders");'
        m = mine_js(js, "https://app.acme.com/", host_filter=lambda h: h == "app.acme.com")
        self.assertNotIn("https://app.acme.com/api/v1/report.pdf", m["endpoints"])  # asset dropped
        self.assertNotIn("https://app.acme.com/api/assets/logo.png", m["endpoints"])
        self.assertIn("https://app.acme.com/api/v1/orders", m["endpoints"])  # a real route survives


class SourceMapReconTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_fetch = recon._safe_fetch
        self.addCleanup(lambda: setattr(recon, "_safe_fetch", self._orig_fetch))

    def test_source_mapping_urls_are_resolved_deduped_and_inline_maps_skipped(self) -> None:
        js = """
        //# sourceMappingURL=app.js.map
        /*# sourceMappingURL=../maps/vendor.map */
        //# sourceMappingURL=data:application/json;base64,AAAA
        //# sourceMappingURL=app.js.map
        """
        self.assertEqual(source_map_urls(js, "https://app.example.com/static/app.js"), [
            "https://app.example.com/static/app.js.map",
            "https://app.example.com/maps/vendor.map",
        ])

    def test_pure_source_map_miner_recovers_only_embedded_surface(self) -> None:
        body = json.dumps({
            "version": 3,
            "sources": ["webpack:///src/export.ts", "https://not-fetched.example/source.ts"],
            "sourcesContent": ['fetch("/api/private/export?file="); const q="?returnUrl=";', None],
        })
        mined = mine_source_map(body, "https://app.example.com/static/app.js.map",
                                host_filter=lambda h: h == "app.example.com")
        self.assertIn("https://app.example.com/api/private/export?file=", mined["endpoints"])
        self.assertIn("file", mined["params"])
        self.assertIn("returnUrl", mined["params"])
        self.assertEqual(mined["source_count"], 1)
        self.assertNotIn("not-fetched.example", " ".join(mined["endpoints"]))

    def test_discovery_mines_explicit_in_scope_source_map(self) -> None:
        map_body = json.dumps({
            "version": 3, "sources": ["src/export.ts"],
            "sourcesContent": ['export const run = () => fetch("/api/private/export?file=")'],
        })
        pages = {
            "https://example.com/": _resp('<script src="/static/app.js"></script>', "https://example.com/"),
            "https://example.com/static/app.js": _resp(
                "minified();\n//# sourceMappingURL=app.js.map", "https://example.com/static/app.js", "application/javascript"),
            "https://example.com/static/app.js.map": _resp(
                map_body, "https://example.com/static/app.js.map", "application/json"),
        }
        recon._safe_fetch = lambda url, s, g: pages.get(url) or {
            "status": 404, "final_url": url, "headers": {}, "cookies": [], "body": "",
        }
        result = recon.discover("https://example.com/", scope_in=lambda h: h == "example.com",
                                max_pages=50, max_requests=40)
        self.assertIn("https://example.com/api/private/export?file=", result["urls"])
        self.assertIn("file", result["params"])
        self.assertEqual(result["sources"].get("source-map"), 1)
        self.assertEqual(result["sources"].get("source-map-endpoint"), 1)
        self.assertEqual(result["source_maps"][0]["source_count"], 1)

    def test_out_of_scope_map_is_never_fetched(self) -> None:
        fetched_urls: list[str] = []

        def fake_fetch(url, settings, governor):
            fetched_urls.append(url)
            if url == "https://example.com/":
                return _resp('<script src="/app.js"></script>', url)
            if url == "https://example.com/app.js":
                return _resp("//# sourceMappingURL=https://evil.example/app.js.map", url, "application/javascript")
            return {"status": 404, "final_url": url, "headers": {}, "cookies": [], "body": ""}

        recon._safe_fetch = fake_fetch
        result = recon.discover("https://example.com/", scope_in=lambda h: h == "example.com",
                                max_pages=20, max_requests=40)
        self.assertNotIn("https://evil.example/app.js.map", fetched_urls)
        self.assertGreaterEqual(result["dropped_out_of_scope"], 1)

    def test_script_and_source_map_redirects_are_regated_before_mining(self) -> None:
        map_doc = json.dumps({"version": 3, "sourcesContent": ['fetch("/api/should-not-leak")']})
        pages = {
            "https://example.com/": _resp(
                '<script src="/redirected.js"></script><script src="/mapped.js"></script>', "https://example.com/"),
            "https://example.com/redirected.js": _resp(
                'fetch("/api/from-oos-script")', "https://evil.example/redirected.js", "application/javascript"),
            "https://example.com/mapped.js": _resp(
                "//# sourceMappingURL=mapped.js.map", "https://example.com/mapped.js", "application/javascript"),
            "https://example.com/mapped.js.map": _resp(
                map_doc, "https://evil.example/mapped.js.map", "application/json"),
        }
        recon._safe_fetch = lambda url, s, g: pages.get(url) or {
            "status": 404, "final_url": url, "headers": {}, "cookies": [], "body": "",
        }
        result = recon.discover("https://example.com/", scope_in=lambda h: h == "example.com",
                                max_pages=30, max_requests=40)
        joined = " ".join(result["urls"])
        self.assertNotIn("from-oos-script", joined)
        self.assertNotIn("should-not-leak", joined)
        self.assertGreaterEqual(result["dropped_out_of_scope"], 2)

    def test_malformed_source_map_is_bounded_and_nonfatal(self) -> None:
        mined = mine_source_map("{ definitely not JSON", "https://app.example.com/app.js.map")
        self.assertEqual(mined["endpoints"], [])
        self.assertEqual(mined["source_count"], 0)

    def test_source_map_content_and_reference_counts_are_hard_capped(self) -> None:
        refs = "\n".join(f"//# sourceMappingURL=bundle-{i}.map" for i in range(20))
        self.assertEqual(
            len(source_map_urls(refs, "https://app.example.com/app.js")),
            recon_js._CAP_SOURCE_MAP_URLS,
        )
        body = json.dumps({"sourcesContent": ["x" * (recon_js._CAP_SOURCE_CONTENT_CHARS + 50)] * 3})
        mined = mine_source_map(body, "https://app.example.com/app.js.map")
        self.assertEqual(mined["embedded_chars"], recon_js._CAP_SOURCE_CONTENT_CHARS)
        self.assertEqual(mined["source_count"], 1)

    def test_source_map_secret_is_redacted_and_attributed_to_the_map(self) -> None:
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        body = json.dumps({"sourcesContent": [f'const aws_access_key_id = "{raw_secret}";']})
        mined = mine_source_map(body, "https://app.example.com/app.js.map")
        self.assertEqual(len(mined["secret_findings"]), 1)
        finding = mined["secret_findings"][0]
        self.assertIn("served source map", finding["title"])
        self.assertEqual(finding["file_path"], "https://app.example.com/app.js.map")
        self.assertNotIn(raw_secret, finding["snippet"])
        self.assertTrue(finding["redacted"])


if __name__ == "__main__":
    unittest.main()
