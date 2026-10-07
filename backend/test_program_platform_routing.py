"""A saved program's platform must shape the submission packages its campaign writes.

``report_formats`` renders a DIFFERENT field set and severity vocabulary per platform (Bugcrowd
wants a VRT + a P1-P5 priority, Intigriti a CVSS vector, YesWeHack a CWE bug type). The engine
takes that as ``run_campaign(platform=...)`` and defaults it to "hackerone", but no API entry
point forwarded the saved program's own ``platform`` -- so every on-disk package for a Bugcrowd,
Intigriti or YesWeHack program came out HackerOne-shaped. In a portfolio the platform is
per-PROGRAM, like policy_profile: one portfolio-wide value cannot be right for a portfolio that
spans platforms. Regression.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as g  # noqa: E402
from bughunter import portfolio as bounty_portfolio  # noqa: E402


class ProgramPlatformRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rt = g.runtime
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = g.RUNTIME_DIR
        g.RUNTIME_DIR = Path(self._tmp.name)
        self.saved = {}
        for name, platform in (("Acme BC", "bugcrowd"), ("Beta Intigriti", "intigriti"),
                               ("Gamma YWH", "yeswehack"), ("Delta Manual", "manual")):
            self.saved[name] = bounty_portfolio.upsert_program(g.RUNTIME_DIR, {
                "name": name, "platform": platform, "scope_text": "app.example.com",
                "seed_targets": ["https://app.example.com"],
            })
        # The engine calls are stubbed: this asserts what the API FORWARDS, so no hunt runs.
        self.captured: dict = {}
        self._orig = {}
        for fn in ("run_campaign", "run_campaign_over_targets", "run_portfolio_campaign"):
            self._orig[fn] = getattr(g.bounty_campaign, fn)
            setattr(g.bounty_campaign, fn, self._spy(fn))
        self._orig_coder = self.rt._coder_config
        self.rt._coder_config = lambda: {}

    def tearDown(self) -> None:
        for fn, orig in self._orig.items():
            setattr(g.bounty_campaign, fn, orig)
        self.rt._coder_config = self._orig_coder
        g.RUNTIME_DIR = self._orig_runtime_dir
        self._tmp.cleanup()

    def _spy(self, name):
        def fn(*args, **kwargs):
            if name == "run_portfolio_campaign":
                specs = args[0] if args else kwargs["programs"]
                self.captured[name] = {s["label"]: s.get("platform") for s in specs}
            else:
                self.captured[name] = kwargs.get("platform")
            return {"ok": True, "findings": []}
        return fn

    def test_single_target_run_uses_the_bound_program_s_platform(self) -> None:
        # The cockpit binds a saved program to a single-target run via active_program_id.
        self.rt.run_campaign(g.CampaignRequest(
            target="https://app.example.com", scope="app.example.com", authorized=True,
            active_program_id=str(self.saved["Acme BC"]["id"])))
        self.assertEqual(self.captured["run_campaign"], "bugcrowd")

    def test_span_the_whole_scope_uses_the_program_s_platform(self) -> None:
        self.rt.run_campaign(g.CampaignRequest(
            authorized=True, program_id=str(self.saved["Beta Intigriti"]["id"])))
        self.assertEqual(self.captured["run_campaign_over_targets"], "intigriti")

    def test_portfolio_carries_a_platform_per_program(self) -> None:
        self.rt.run_portfolio(g.PortfolioRequest(all_programs=True, authorized=True))
        self.assertEqual(
            self.captured["run_portfolio_campaign"],
            {"Acme BC": "bugcrowd", "Beta Intigriti": "intigriti", "Gamma YWH": "yeswehack",
             # 'manual' is the portfolio's default and is not a report format -- it normalizes to
             # the engine's own default, so a manual program is shaped exactly as it was before.
             "Delta Manual": "hackerone"})

    def test_unbound_run_keeps_the_engine_default(self) -> None:
        self.rt.run_campaign(g.CampaignRequest(
            target="https://elsewhere.example.com", scope="elsewhere.example.com", authorized=True))
        self.assertEqual(self.captured["run_campaign"], "hackerone")


class PortfolioSpecPlatformTests(unittest.TestCase):
    """The per-spec platform must reach the inner campaign; an empty one falls back to the
    portfolio-wide argument (so an older caller that passes no per-spec platform is unchanged)."""

    def setUp(self) -> None:
        from bughunter import campaign as bounty_campaign
        self.campaign = bounty_campaign
        self.seen: list = []
        self._orig = bounty_campaign.run_campaign_over_targets

        def _spy(targets, **kwargs):
            self.seen.append((kwargs.get("program"), kwargs.get("platform")))
            return {"ok": False, "error": "stubbed"}

        bounty_campaign.run_campaign_over_targets = _spy
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.campaign.run_campaign_over_targets = self._orig
        self._tmp.cleanup()

    def test_spec_platform_wins_and_empty_falls_back(self) -> None:
        self.campaign.run_portfolio_campaign(
            [{"label": "BC", "scope": "a.example.com", "targets": ["https://a.example.com"],
              "platform": "bugcrowd"},
             {"label": "Legacy", "scope": "b.example.com", "targets": ["https://b.example.com"]}],
            authorized=True, coder_cfg=None, default_reports_dir=Path(self._tmp.name),
            platform="yeswehack")
        self.assertEqual(sorted(self.seen), [("BC", "bugcrowd"), ("Legacy", "yeswehack")])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
