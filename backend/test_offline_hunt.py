"""Offline hunt intelligence — the no-LLM hunt brain. Knowledge rules over the recon surface produce
targeted param/class/idor guidance, sharpened by what the program has confirmed before (learned
priors), and it steers an offline hunt that previously flew blind. Safe: names/verbatim-endpoints only."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hunt_brain, offline_hunt  # noqa: E402

_SURFACE = {"endpoints": ["https://t/search?q=x", "https://t/order/1042", "https://t/download?file=a.pdf",
                          "https://t/api/me", "https://t/redirect?url=x", "https://t/users/9f8e7d6c-1234-4321-8888-abcdef012345",
                          "https://t/admin/users", "https://t/settings/roles"],
            "params": ["q", "file"], "tech": ["Flask", "Jinja"]}


class OfflinePlanTests(unittest.TestCase):
    def test_targets_ssrf_xss_and_idor_surface(self) -> None:
        p = offline_hunt.offline_plan(_SURFACE)
        self.assertIn("url", p["ssrf_params"])                      # redirect?url= is SSRF surface
        self.assertIn("q", p["xss_params"])                        # search q= reflects
        self.assertIn("https://t/order/1042", p["idor_candidates"])  # numeric-id object endpoint
        self.assertIn("https://t/users/9f8e7d6c-1234-4321-8888-abcdef012345", p["idor_candidates"])  # uuid too

    def test_admin_path_endpoints_recon_feed_is_verbatim_and_bounded(self) -> None:
        urls = ["https://t/admin/users", "https://t/api/orders/42", "https://t/settings/roles",
                "https://t/internal/config", "https://t/home", "https://t/manage/billing"]
        got = offline_hunt.admin_path_endpoints(urls)
        self.assertIn("https://t/admin/users", got)          # /admin
        self.assertIn("https://t/settings/roles", got)       # /settings + /role
        self.assertIn("https://t/internal/config", got)      # /internal + /config
        self.assertIn("https://t/manage/billing", got)       # /manage + /billing
        self.assertNotIn("https://t/api/orders/42", got)     # an object endpoint is IDOR, not a privileged FUNCTION
        self.assertNotIn("https://t/home", got)              # a plain page is not privileged
        for u in got:
            self.assertIn(u, set(urls))                      # verbatim in-scope only, never invented
        self.assertLessEqual(len(offline_hunt.admin_path_endpoints(["https://t/admin/%d" % i for i in range(40)])), 8)

    def test_flags_admin_privileged_endpoints_for_bfla(self) -> None:
        p = offline_hunt.offline_plan(_SURFACE)
        self.assertIn("https://t/admin/users", p["privileged_endpoints"])   # /admin function
        self.assertIn("https://t/settings/roles", p["privileged_endpoints"])  # /settings + /role
        # object endpoints are NOT privileged-function candidates (that's IDOR, not BFLA)
        self.assertNotIn("https://t/order/1042", p["privileged_endpoints"])
        for ep in p["privileged_endpoints"]:
            self.assertIn(ep, set(_SURFACE["endpoints"]))                    # verbatim in-scope only

    def test_probe_priority_endpoints_are_verbatim_in_scope(self) -> None:
        p = offline_hunt.offline_plan(_SURFACE)
        allowed = set(_SURFACE["endpoints"])
        for row in p["probe_priority"]:
            self.assertIn(row["endpoint"], allowed)                # never invents a URL

    def test_learned_priors_reorder_classes(self) -> None:
        # the LEARNING signal: a class the program has rewarded is tried first
        base = offline_hunt.offline_plan(_SURFACE)
        search = next(r for r in base["probe_priority"] if "search" in r["endpoint"])
        boosted = offline_hunt.offline_plan(_SURFACE, priors={"path-traversal": 5.0})
        search2 = next(r for r in boosted["probe_priority"] if "search" in r["endpoint"])
        self.assertIn("path-traversal", search["classes"])
        self.assertEqual(search2["classes"][0], "path-traversal")   # boosted to the front

    def test_tech_stack_boosts_ssti(self) -> None:
        p = offline_hunt.offline_plan(_SURFACE)                     # Flask/Jinja -> ssti in the surface
        self.assertTrue(any("ssti" in r["classes"] for r in p["probe_priority"]))

    def test_empty_surface_is_a_clean_empty_plan(self) -> None:
        p = offline_hunt.offline_plan({"endpoints": [], "params": [], "tech": []})
        self.assertFalse(p["used"])
        self.assertEqual(p["probe_priority"], [])

    def test_names_only_never_a_payload(self) -> None:
        p = offline_hunt.offline_plan(_SURFACE)
        for n in p["ssrf_params"] + p["xss_params"] + p["param_hypotheses"]:
            self.assertNotIn(" ", n)
            self.assertNotIn("<", n)
            self.assertNotIn("/", n)


class PlanHuntOfflineFallbackTests(unittest.TestCase):
    def test_no_brain_uses_the_offline_engine(self) -> None:
        hp = hunt_brain.plan_hunt({"enabled": False, "provider": "off"}, "https://t", "t", _SURFACE)
        self.assertEqual(hp["provider"], "offline")
        self.assertTrue(hp["used"])
        self.assertTrue(hp["probe_priority"])                       # offline hunt is no longer blind
        # everything still passes the same validation (verbatim in-scope endpoints)
        for row in hp["probe_priority"]:
            self.assertIn(row["endpoint"], set(_SURFACE["endpoints"]))

    def test_offline_plan_is_validated_out_of_scope_endpoint_dropped(self) -> None:
        # a probe_priority endpoint not in the surface would be dropped by _validate_plan; the offline
        # engine only ever emits surface endpoints, so the plan is fully in-scope by construction
        hp = hunt_brain.plan_hunt(None, "https://t", "t", _SURFACE)
        self.assertEqual(hp["provider"], "offline")
        self.assertTrue(all(r["endpoint"] in set(_SURFACE["endpoints"]) for r in hp["probe_priority"]))


if __name__ == "__main__":
    unittest.main()
