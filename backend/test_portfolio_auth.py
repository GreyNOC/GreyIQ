"""Regression: Portfolio Hunt must let each program auto-login from its own stored account_access.

The bug: the portfolio endpoint passed ``auth={"cookie": "", "headers": []}`` — a non-None but EMPTY
dict — even when the request carried no session. ``run_campaign_over_targets`` only auto-logs-in a
program's ``account_access`` when ``auth is None``, so a non-None empty dict silently DISABLED all
authenticated hunting across an entire portfolio run: single-account auth AND the dual-account BFLA /
cross-tenant IDOR confirmation passes (which need a primary session) never fired. The fix mirrors the
single/span paths: pass the request session only when it's actually present, else None.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402


class PortfolioAuthForwardingTests(unittest.TestCase):
    def _captured_auth(self, request: "api.PortfolioRequest") -> dict:
        rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
        rt._coder_config = lambda: {}                      # bare instance — stub the bits run_portfolio calls
        rt._cache_bounty_run = lambda *a, **k: None
        captured: dict = {}
        orig = (api.bounty_portfolio.list_programs, api.bounty_campaign.program_campaign_targets,
                api.bounty_campaign.run_portfolio_campaign)
        api.bounty_portfolio.list_programs = lambda rt_dir: [
            {"id": "p1", "name": "Acme", "scope_text": "acme.example",
             "account_access": {"email": "u@x", "cookie": "sess=stored"}}]
        api.bounty_campaign.program_campaign_targets = lambda prog: ["https://acme.example/"]

        def _capture(specs, **kwargs):
            captured["auth"] = kwargs.get("auth")
            return {"ok": True, "findings": []}
        api.bounty_campaign.run_portfolio_campaign = _capture
        try:
            api.GreyIQRuntime.run_portfolio(rt, request)
        finally:
            (api.bounty_portfolio.list_programs, api.bounty_campaign.program_campaign_targets,
             api.bounty_campaign.run_portfolio_campaign) = orig
        return captured

    def test_no_request_session_passes_auth_none_so_programs_autologin(self) -> None:
        cap = self._captured_auth(api.PortfolioRequest(all_programs=True, authorized=True, active=True))
        self.assertIn("auth", cap)
        self.assertIsNone(cap["auth"])   # None (NOT {}) -> each program's stored account_access can log in

    def test_explicit_request_session_is_still_forwarded(self) -> None:
        cap = self._captured_auth(api.PortfolioRequest(
            all_programs=True, authorized=True, active=True, auth_cookie="sess=request"))
        self.assertEqual(cap["auth"], {"cookie": "sess=request", "headers": []})


if __name__ == "__main__":
    unittest.main()
