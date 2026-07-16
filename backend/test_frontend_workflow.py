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

    def test_repo_onboarding_preflights_and_stays_review_only(self) -> None:
        flow = JS.split("function ckWizardIdentifyRepo(", 1)[1].split(
            "function ckWizardIdentifyH1", 1
        )[0]
        suggestions = JS.split("function ckProgramWithCandidateHosts", 1)[1].split(
            "function ckProgramSetupRow", 1
        )[0]

        # Preflight runs BEFORE any draft is created, so a typo'd/private/missing repo is caught
        # up front with an actionable message instead of failing deep in a clone mid-hunt.
        self.assertIn('apiFetch("/api/repos/preflight"', flow)
        self.assertIn('apiFetch("/api/programs/from-repo"', flow)
        self.assertLess(flow.index("/api/repos/preflight"), flow.index("/api/programs/from-repo"))
        self.assertIn("enrich: enrich.input.checked", flow)
        self.assertIn("ckProgEdit = ckProgramWithCandidateHosts", flow)
        # Candidate hosts arrive unticked and never authorize scope on their own.
        self.assertIn("eligible_for_submission: false", suggestions)
        self.assertIn("confirm you're authorized to test this host", suggestions)
        self.assertIn("leaving a row unticked never authorizes it", JS)
        self.assertIn('repositories.length && String(p.scope_text || "").trim()', JS)
        # A repository hunt is also preflighted at launch, so a bad repo typed straight into the
        # rail can't fire a doomed run either — but ONLY a definitive negative blocks it. A
        # transient/indeterminate preflight (timeout, unreachable) must never refuse a hunt the
        # operator asked for (the real 120s clone is the authoritative attempt).
        run = JS.split("async function ckRun()", 1)[1]
        self.assertIn('apiFetch("/api/repos/preflight"', run)
        self.assertIn('["invalid", "not_found", "private"].includes(pf.status)', run)

    def test_hackenproof_is_a_selectable_platform(self) -> None:
        # Report-format mirror + Program-form platform selector both offer HackenProof, and the
        # saved platform tag comes from the selector (not the old handle-implies-HackerOne rule).
        self.assertIn('id: "hackenproof", name: "HackenProof"', JS)
        self.assertIn('["hackenproof", "HackenProof"]', JS)
        self.assertIn("platform: platSelect.value", JS)
        # The Operator tab's compact editor has no platform picker, so on edit it must PRESERVE the
        # existing platform tag (set in the Program tab) rather than re-derive it from the handle
        # and clobber e.g. a HackenProof program back to HackerOne.
        op = JS.split("function ckProgramForm()", 1)[1].split("function ", 1)[0]
        self.assertIn("editing ? (editing.platform ||", op)

    def test_program_setup_is_a_gentle_stepped_flow(self) -> None:
        # One thing at a time: a calm list with a single New program button opens a guided
        # Start -> Identify -> Scope&save wizard, and advanced fields are tucked behind a disclosure.
        for fn in ("function ckWizardStart", "function ckWizardIdentify(",
                   "function ckWizardIdentifyRepo(", "function ckProgramWizard(", "function ckProgReset("):
            self.assertIn(fn, JS)
        self.assertIn('view: "wizard"', JS)
        self.assertIn("How do you want to start?", JS)
        for card in ("From a repo link", "From HackerOne", "Manually"):
            self.assertIn(card, JS)
        self.assertIn('cel("details", "ck-advanced")', JS)
        for cls in (".ck-wiz-rail", ".ck-choice", ".ck-preflight", ".ck-advanced"):
            self.assertIn(cls, CSS)


if __name__ == "__main__":
    unittest.main()
