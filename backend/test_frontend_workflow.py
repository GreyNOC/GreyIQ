"""Static workflow contracts for the bug-bounty cockpit.

These checks protect the launch rail's progressive disclosure and safety boundaries
without requiring a browser in the normal backend test run. Responsive geometry is
still exercised separately during visual QA.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "public" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "public" / "styles.css").read_text(encoding="utf-8")


class CockpitWorkflowContractTests(unittest.TestCase):
    def test_launch_rail_exposes_a_clear_three_mode_flow(self) -> None:
        self.assertIn('id="ckSetupRest" class="ck-setup-rest"', HTML)
        self.assertIn('id="ckLaunchReadiness" aria-live="polite"', HTML)
        self.assertEqual(HTML.count("data-ck-runtype="), 3)
        self.assertIn('data-ck-when="hunt campaign"', HTML)
        self.assertIn('data-ck-when="campaign portfolio"', HTML)
        self.assertIn('id="ckAuthFold" data-ck-when="hunt campaign"', HTML)
        self.assertIn('id="ckOptionsFold"', HTML)
        self.assertIn('aria-label="Authorize and launch"', HTML)

    def test_mode_switching_and_navigation_publish_accessible_state(self) -> None:
        self.assertIn('split(/\\s+/).filter(Boolean)', JS)
        self.assertIn('seg.setAttribute("aria-pressed", String(on))', JS)
        self.assertIn('btn.setAttribute("aria-current", "page")', JS)
        self.assertIn('th.setAttribute("aria-sort"', JS)
        self.assertIn('tr.addEventListener("keydown"', JS)
        self.assertIn('ev.key === "Enter" || ev.key === " "', JS)

    def test_portfolio_never_reuses_the_shared_single_target_session(self) -> None:
        portfolio = JS.split("async function ckRunPortfolio()", 1)[1].split(
            "async function ckRun()", 1
        )[0]
        regular_run = JS.split("async function ckRun()", 1)[1]

        self.assertNotIn("auth_cookie", portfolio)
        self.assertNotIn("auth_headers", portfolio)
        self.assertNotIn("ck.authCookie", portfolio)
        self.assertIn("ck.authCookie", regular_run)
        self.assertIn("state.ckAuthHeaders", regular_run)

    def test_responsive_and_overflow_guards_remain_in_place(self) -> None:
        self.assertIn(".ck-launch-actions", CSS)
        self.assertIn("grid-template-columns: repeat(3, minmax(0, 1fr))", CSS)
        self.assertIn(".ck-table-wrap", CSS)
        self.assertIn("@media (max-width: 820px)", CSS)
        self.assertIn(".ck-scope-row { grid-template-columns: minmax(0, 1fr)", CSS)
        self.assertIn("@media (prefers-reduced-motion: reduce)", CSS)


if __name__ == "__main__":
    unittest.main()
