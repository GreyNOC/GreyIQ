"""'All-knowing within scope' recon expansion: deeper JS/inline/comment/sitemap surface discovery,
each proven to stay strictly within scope (the paramount constraint) via a stubbed fetcher."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import recon  # noqa: E402
from bughunter.recon_js import mine_js  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
