"""Static workflow contracts for the bug-bounty cockpit.

These checks protect the New run panel's progressive disclosure and safety boundaries
without requiring a browser in the normal backend test run. Responsive geometry is
still exercised separately during visual QA.
"""

from pathlib import Path
import re
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

    def test_new_run_focuses_the_first_unfinished_requirement(self) -> None:
        self.assertIn('id="ckQuickLaunch"', HTML)
        self.assertIn('id="ckSetupFold" open', HTML)
        flow = JS.split("function ckFocusLaunchStep()", 1)[1].split(
            "// The Portfolio-mode program multi-select", 1
        )[0]
        for requirement in (
            "ck.portfolioList",
            "ck.activeProgram",
            "ck.target",
            "ck.scope",
            "ck.authorized",
            "ck.run",
        ):
            self.assertIn(requirement, flow)
        self.assertIn('ck.quickLaunch?.addEventListener("click"', JS)
        self.assertIn('ck.quickLaunch.textContent = ready ? "Review run" : "New run"', JS)

    def test_new_program_flows_directly_into_launch(self) -> None:
        save = JS.split('const saved = await apiFetch("/api/operator/programs"', 1)[1].split(
            "void ckRenderProgram()", 1
        )[0]
        self.assertIn("savedProgram?.id", save)
        self.assertIn("ckApplyActiveProgram(savedProgram.id)", save)
        self.assertIn('querySelector("#ckSetupFold")', save)
        self.assertIn("ckFocusLaunchStep()", save)

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

    def test_every_platform_is_selectable_in_the_program_flow(self) -> None:
        # The report-format mirror lists all five platforms, and the Program-form platform
        # selector is built FROM that mirror (+ a manual catch-all) so it can't drift — every
        # supported platform, HackenProof included, is selectable. The saved tag comes from the
        # selector (not the old handle-implies-HackerOne rule), and any of the five is preserved.
        for pid, name in (("hackerone", "HackerOne"), ("yeswehack", "YesWeHack"),
                          ("bugcrowd", "Bugcrowd"), ("intigriti", "Intigriti"),
                          ("hackenproof", "HackenProof")):
            self.assertIn(f'id: "{pid}", name: "{name}"', JS)
        self.assertIn("CK_PLATFORMS.map((p) => [p.id, p.name])", JS)   # data-driven selector
        self.assertIn("validPlatforms.has(initialPlatform)", JS)       # preserves any valid tag
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
        # Flow classes use their own namespace so they can't collide with pre-existing components:
        # the wizard container is .ck-progwiz (NOT .ck-wizard, which the guided tour owns as a
        # fixed overlay), the repo preflight is .ck-rpf (NOT .ck-preflight, the submission panel),
        # and the empty state is .ck-prog-empty (NOT .ck-empty, a full-page empty state).
        for cls in (".ck-wiz-rail", ".ck-choice", ".ck-rpf", ".ck-advanced", ".ck-progwiz", ".ck-prog-empty"):
            self.assertIn(cls, CSS)
        wizard_fn = JS.split("function ckProgramWizard()", 1)[1].split("function ckWizardStart", 1)[0]
        self.assertIn('cel("div", "ck-progwiz")', wizard_fn)
        self.assertNotIn('"ck-wizard"', wizard_fn)   # must not reuse the tour's fixed-overlay class


class CockpitQaqcV25ContractTests(unittest.TestCase):
    """Static regression contracts for the v2.5 whole-app QAQC pass.

    Locks in the 23 verified UX defects fixed in that pass so a later refactor can't
    silently regress them (the same static-grep pattern the rest of this module uses)."""

    def _fn(self, name: str) -> str:
        """Source of a top-level `[async] function name(` up to the next top-level function."""
        m = re.search(r"(?:async\s+)?function\s+" + re.escape(name) + r"\s*\(", JS)
        self.assertIsNotNone(m, f"function {name} not found in app.js")
        tail = JS[m.end():]
        nxt = re.search(r"\n(?:async\s+)?function\s+\w+\s*\(", tail)
        return tail[: nxt.start()] if nxt else tail

    # --- Platform-aware submit/export (was hardcoded to HackerOne everywhere) ---
    def test_export_only_platforms_get_an_export_cta_not_a_dead_submit(self) -> None:
        self.assertIn("function ckIsLiveSubmit(", JS)
        self.assertIn("function ckPlatformName(", JS)
        self.assertIn("function ckSyncPlatformToProgram(", JS)
        # Stage 3 branches to an export CTA for non-live (export-only) formats.
        self.assertIn("!ckIsLiveSubmit(ckState.platform)", JS)
        self.assertIn("is export-only.", JS)

    def test_report_format_follows_the_active_program_platform(self) -> None:
        apply = self._fn("ckApplyActiveProgram")
        self.assertIn("ckSyncPlatformToProgram(prog)", apply)   # a picked program sets the format
        self.assertIn("ckSyncPlatformToProgram(null)", apply)   # one-off -> HackerOne generic
        # The reload/restore path re-derives the format from the restored program.
        populate = self._fn("ckPopulateActiveProgramSelect")
        self.assertIn("ckSyncPlatformToProgram(activeProg)", populate)

    def test_findings_detail_shows_which_platform_format_it_exports(self) -> None:
        self.assertIn("ck-export-fmt", JS)

    # --- Gate reason no longer points at a "credentials bar below" that isn't on every surface ---
    def test_submit_gate_reason_names_the_submissions_tab(self) -> None:
        self.assertNotIn("credentials bar below", JS)
        gate = self._fn("ckSubmitGateReason")
        self.assertIn("Submissions tab", gate)

    # --- The live board is titled by run kind; a single hunt is not "Campaign dashboard" ---
    def test_board_title_tracks_run_kind(self) -> None:
        self.assertIn("function ckBoardTitle()", JS)
        self.assertIn('cel("h2", "ck-section-title", ckBoardTitle())', JS)
        self.assertIn('"Live dashboard"', JS)                      # neutral empty-state title
        self.assertIn('kind: isCampaign ? "campaign" : "hunt"', JS)
        self.assertIn('kind: "portfolio"', JS)

    # --- A single hunt can be re-opened from its segment, like a campaign ---
    def test_single_hunt_segment_reopens_the_live_board(self) -> None:
        self.assertIn(
            'ck.segHunt?.addEventListener("click", () => { ckSetRunType("hunt"); '
            'if (ckCampaign && ckCampaign.runId) ckSetView("campaign"); });',
            JS,
        )

    # --- The SSRF/OOB shortcut scrolls to the OOB panel it names ---
    def test_oob_shortcut_scrolls_to_the_oob_panel(self) -> None:
        self.assertIn('wrap.id = "ckOobPanel"', JS)
        self.assertIn('querySelector("#ckOobPanel")', JS)

    # --- The Findings board points to the Report Center instead of reading as data loss ---
    def test_findings_empty_state_points_to_report_center(self) -> None:
        self.assertIn("Open Report Center", JS)

    # --- The HackerOne scope-import wizard pre-checks credentials with a jump ---
    def test_hackerone_scope_wizard_prechecks_creds(self) -> None:
        h1 = self._fn("ckWizardIdentifyH1")
        self.assertIn("ck-wiz-crednote", h1)
        self.assertIn("Save HackerOne credentials", h1)

    # --- Program save reports a server-side rejection instead of a false "Saved." ---
    def test_program_save_checks_the_result(self) -> None:
        self.assertEqual(JS.count("Could not save that program."), 2)   # both editors

    # --- Offline populate helpers explain the empty panel instead of a blank void ---
    def test_populate_helpers_explain_service_down(self) -> None:
        self.assertIn("Toolkit unavailable", self._fn("loadToolkit"))
        self.assertIn("load hunt profiles", self._fn("loadBountyProfiles"))

    # --- The portfolio Select-all toggle keeps an honest label ---
    def test_select_all_label_toggles(self) -> None:
        count = self._fn("ckUpdatePortfolioCount")
        self.assertIn('allOn ? "Deselect all" : "Select all"', count)

    # --- A fresh one-off run doesn't inherit the previous program's target ---
    def test_oneoff_clears_prior_program_target(self) -> None:
        apply = self._fn("ckApplyActiveProgram")
        self.assertIn("if (oneoff) {", apply)
        self.assertIn('state.ckTarget = "";', apply)

    # --- The two program editors cross-reference each other ---
    def test_program_editors_cross_link(self) -> None:
        self.assertIn(".ck-crosslink", CSS)
        self.assertIn("set on the Operator tab.", JS)          # gentle form -> operator
        self.assertIn("edited in the Program tab", JS)         # operator form -> program

    # --- Tour: the step counter and titles agree, and the Studio button is named ---
    def test_tour_titles_have_no_conflicting_numbering(self) -> None:
        self.assertNotIn('title: "1. Add your first program"', JS)
        self.assertIn('title: "Add your first program"', JS)
        self.assertIn("Open the AI studio with the", JS)       # names the Studio button

    # --- Workbench: IME guard, debounced+cached tree, session-only filter, focus restore ---
    def test_workbench_input_and_tree_hardening(self) -> None:
        self.assertIn("event.isComposing || event.keyCode === 229", JS)   # IME-safe Enter
        self.assertIn("_workspaceSearchTimer", JS)                        # search debounce
        self.assertIn("_treeRenderSig", JS)                              # redundant-render cache
        self.assertIn("_treeRenderEntries === entries", JS)
        self.assertIn("workbenchSearch: _search", JS)                    # excluded from persistence
        self.assertIn("hadTreeFocus", JS)                                # focus restore on open

    # --- The new QAQC nodes are themed (no unstyled classes shipped) ---
    def test_qaqc_style_classes_exist(self) -> None:
        for cls in (".ck-export-note", ".ck-export-fmt", ".ck-status.is-warn",
                    ".ck-crosslink", ".ck-wiz-crednote"):
            self.assertIn(cls, CSS)

    # --- The nav label matches the heading/guide/tour ("Program", not "Overview") ---
    def test_program_nav_label_matches_everywhere_else(self) -> None:
        self.assertNotIn(">Overview<", HTML)
        self.assertIn(
            'data-ck-view="program" type="button" aria-current="page">Program<', HTML
        )


if __name__ == "__main__":
    unittest.main()
