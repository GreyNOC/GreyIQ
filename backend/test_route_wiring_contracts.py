"""Wiring contracts for the app/API seams where a value is produced and then dropped.

Every defect covered here is INVISIBLE at runtime. A response field the client never reads looks
exactly like a field the server never sent; a route with no caller looks exactly like a route
nobody needs; a rollback that overwrites your edits looks exactly like one that restored them.
Nothing fails, nothing logs, and the capability simply is not there.

So these are contracts over the files that have to agree:

  * public/app.js          the value is read, and the control is bound
  * backend/greyiq_api.py  the field is produced, and the route exists
  * backend/agent.py       the snapshot carries what restore needs to be safe

They run in BOTH directions on purpose: "the client reads a field the server sends" catches a
deleted producer, and "every field the server sends is read by the client" catches the original
defect — a server that computes a real artifact nobody ever collects.

A browser is not needed. Behaviour that genuinely needs one stays in visual QA.
"""

from __future__ import annotations

import ast
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402
import greyiq_api  # noqa: E402

JS = (ROOT / "public" / "app.js").read_text(encoding="utf-8")
API_SRC = (BACKEND_DIR / "greyiq_api.py").read_text(encoding="utf-8")
API_TREE = ast.parse(API_SRC)


def _js_function(name: str) -> str:
    """The source of one top-level JS function: from its declaration to the next one.

    Functions in app.js are all at column 0, so the next ``function`` / ``async function`` at the
    start of a line is the boundary. Any doc comment in between rides along, which is harmless for
    the "this body contains X" assertions below.
    """
    match = re.search(rf"^(?:async )?function {re.escape(name)}\(", JS, re.M)
    if not match:
        raise AssertionError(f"{name}() is gone from app.js — this contract has lost its subject")
    rest = JS[match.end():]
    end = re.search(r"^(?:async )?function \w+\(", rest, re.M)
    return rest[: end.start()] if end else rest


def _api_method(name: str) -> ast.FunctionDef:
    for node in ast.walk(API_TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name}() is gone from greyiq_api.py — this contract has lost its subject")


def _result_dict_keys(func_name: str, var: str = "result") -> set[str]:
    """Every key a route builds into its response dict, read off the AST rather than by regex so a
    nested dict literal's keys (e.g. ready's poc/poi/poe) are not mistaken for top-level ones."""
    keys: set[str] = set()
    for node in ast.walk(_api_method(func_name)):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == var and isinstance(node.value, ast.Dict):
            keys |= {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
        elif (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                and target.value.id == var and isinstance(target.slice, ast.Constant)):
            keys.add(target.slice.value)
    if not keys:
        raise AssertionError(f"{func_name}() no longer builds a `{var}` dict — this contract moved")
    return keys


def _model_fields(name: str) -> set[str]:
    for node in ast.walk(API_TREE):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return {n.target.id for n in node.body if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)}
    raise AssertionError(f"{name} is gone from greyiq_api.py")


def _handled_routes() -> set[str]:
    return set(re.findall(r'path == "(/api/[^"]+)"', API_SRC))


def _routes_called_from_the_app() -> set[str]:
    # A route is called as "/api/x", '/api/x', or as the head of a template literal that appends a
    # query string (`/api/bounty/stats${qs}`) — all three count as wired.
    return {route for route in _handled_routes()
            if f'"{route}"' in JS or f"'{route}'" in JS or f"`{route}" in JS}


class ReportReadyArtifactsTests(unittest.TestCase):
    """get_report_ready rebuilds a runnable replay.sh + findings.har for the one finding being
    readied. They exist on that response only — they are not stored in the ledger — so the client
    either collects them there or the operator has no reproduction artifact for that finding."""

    # Keys get_report_ready returns that ckGetReportReady deliberately does not read:
    #   package    the row rebuilds the report from the ledger on demand (Copy / Download .md)
    #   persisted  the same boolean as ok, which the error path already branches on
    #   dedup_key  the record the client passed in already carries it
    #   platform   an echo of the platform the row just sent; the row renders its own
    _NOT_READ_BY_THE_ROW = {"package", "persisted", "dedup_key", "platform"}

    def test_the_client_reads_every_field_the_route_returns(self) -> None:
        body = _js_function("ckGetReportReady")
        unread = sorted(k for k in _result_dict_keys("get_report_ready") - self._NOT_READ_BY_THE_ROW
                        if f"res.{k}" not in body)
        self.assertFalse(unread, f"get_report_ready returns field(s) ckGetReportReady drops: {unread}")

    def test_the_poc_artifacts_are_kept_on_the_record(self) -> None:
        body = _js_function("ckGetReportReady")
        self.assertIn("res.replay", body, "the runnable replay.sh is thrown away again")
        self.assertIn("res.har", body, "the findings.har is thrown away again")
        self.assertIn("rec.poc_replay", body)
        self.assertIn("rec.poc_har", body)

    def test_the_row_offers_them_for_download(self) -> None:
        # Kept is not the same as reachable: without a control, the artifact is cached and unusable.
        row = _js_function("ckReportTr")
        self.assertIn("rec.poc_replay", row, "no control downloads the replay.sh")
        self.assertIn("rec.poc_har", row, "no control downloads the findings.har")
        self.assertIn("Download replay.sh", row)
        self.assertIn("Download findings.har", row)

    def test_a_finding_with_no_runnable_artifact_is_offered_none(self) -> None:
        # The server returns "" / None when nothing was reconstructable; an unconditional menu item
        # would hand a triager an empty file and claim it is a reproduction.
        row = _js_function("ckReportTr")
        self.assertIn("if (rec.poc_replay)", row)
        self.assertIn("if (rec.poc_har)", row)


class ProveEvidenceReachesTheReportTests(unittest.TestCase):
    """/prove returns the captured request/response artifact per result (_compact_active carries
    proof_evidence). A finding re-proven from history has no cached run to read it back from, so
    the client copy is the only place that artifact survives into the report."""

    def test_the_prove_response_still_carries_the_artifact(self) -> None:
        compact = ast.get_source_segment(API_SRC, _api_method("_compact_active"))
        self.assertIn('"proof_evidence"', compact,
                      "_compact_active stopped carrying the captured artifact — the client fold below is now moot")

    def test_every_prove_call_site_folds_the_artifact_onto_the_finding(self) -> None:
        for fn in ("ckPrepareFullReport", "ckCreateProofOfImpact", "ckProveFinding"):
            with self.subTest(prove_site=fn):
                body = _js_function(fn)
                self.assertIn("/api/bounty/finding/prove", body, f"{fn} no longer proves — contract moved")
                self.assertIn("ckActiveProofEvidence(", body,
                              f"{fn} keeps the observed/control prose but drops the captured artifact")
                self.assertIn("f.proofEvidence", body)

    def test_the_drawer_report_sends_the_artifact_it_gathered(self) -> None:
        body = _js_function("ckDrawerReport")
        self.assertIn("ckActiveProofEvidence(", body)
        self.assertIn("proof_evidence: proofEvidence", body,
                      "the drawer gathers the artifact and then does not send it")

    def test_the_normalizer_and_the_report_request_both_carry_it(self) -> None:
        # The path the folded artifact travels: f.proofEvidence -> focus.proofEvidence -> the
        # report request's proof_evidence. A break anywhere here makes the fold above pointless.
        self.assertIn("proofEvidence: f.proof_evidence || f.proofEvidence", _js_function("ckNormalizeForReport"))
        self.assertIn("proof_evidence: focus.proofEvidence", _js_function("ckFullReportMarkdown"))

    def test_the_labels_the_capturing_check_classified_are_declared(self) -> None:
        # report._sensitive_read_captured and the CORS wording read sensitive_data_labels off
        # proof_evidence. An input model that does not declare it drops it silently, so a rebuilt
        # report under-reports what the original hunt proved.
        self.assertIn("sensitive_data_labels", _model_fields("ProofEvidenceInput"))
        self.assertIn("sensitive_data_labels", _js_function("ckCapturedProofFields"))


class SensitiveLabelsSurviveTheRequestModelTests(unittest.TestCase):
    def test_labels_reach_the_finding_the_report_is_built_from(self) -> None:
        captured: dict = {}

        def _capture(ctx, finding, platform):
            captured["finding"] = finding
            return {"proof_status": "candidate", "vulnerability_information": "stub"}

        runtime = greyiq_api.GreyIQRuntime()
        request = greyiq_api.FindingReportRequest(
            title="CORS misconfiguration", severity="medium", class_id="cors",
            location="https://app.example.com/api/me",
            proof_evidence={"read_data": "an authenticated account record",
                            "sensitive_data_labels": "a JWT (session/bearer token)"},
        )
        with mock.patch.object(greyiq_api.bounty_submission, "build_submission", _capture):
            out = runtime.build_finding_report(request)
        self.assertTrue(out.get("ok"), out)
        self.assertEqual(
            captured["finding"]["proof_evidence"].get("sensitive_data_labels"),
            "a JWT (session/bearer token)",
            "the labels were dropped at the request model, so the report can't name the data at risk",
        )


class RestoreAFindingTests(unittest.TestCase):
    """Deleting a finding is a SUPPRESSION keyed by its dedup key, and /finding/restore lifts it.
    The dismiss response's dedup_key is the only handle on that suppression — the server derives
    the key itself when the caller had none — so discarding it makes a mis-click permanent."""

    def test_the_restore_route_is_reachable_from_the_app(self) -> None:
        self.assertIn('path == "/api/bounty/finding/restore"', API_SRC)
        self.assertIn('"/api/bounty/finding/restore"', JS, "the restore route has no caller again")

    def test_the_undo_control_spends_the_key_the_dismiss_returned(self) -> None:
        bar = _js_function("ckUndoDeleteBar")
        self.assertIn("/api/bounty/finding/restore", bar)
        self.assertIn("dedup_key: dedupKey", bar)
        # restore is idempotent; the control must report which of the two things happened rather
        # than claiming a restore that did nothing.
        self.assertIn("res.restored", bar)

    def test_both_delete_sites_keep_the_dedup_key_and_offer_undo(self) -> None:
        board = _js_function("ckDeleteFinding")
        self.assertIn("res.dedup_key", board, "the board delete drops the only handle on the suppression")
        self.assertIn("ckState.lastDeleted", board)
        history = _js_function("ckHistoryRow")
        self.assertIn("res.dedup_key || rec.dedup_key", history,
                      "the history delete drops the dedup_key the dismiss response returned")
        self.assertIn("ckUndoDeleteBar(rec.title", history,
                      "the history row removes itself with no way back")

    def test_the_board_renders_the_undo_before_the_empty_state(self) -> None:
        # Deleting the last finding leaves an empty board — exactly when an accidental delete is
        # hardest to notice — so the bar must be appended above the early return, not after it.
        body = _js_function("ckRenderFindings")
        bar = body.index("ckUndoDeleteBar")
        early_return = body.index('cel("div", "ck-empty")')
        self.assertLess(bar, early_return, "the undo bar is unreachable when the board empties out")


class OobPollTests(unittest.TestCase):
    """Minting a callback token is only useful if the operator can ask the collaborator whether
    anything hit it. The blind provers poll their own tokens internally; a payload pasted by hand
    has no other read-back."""

    def test_the_poll_route_is_reachable_from_the_app(self) -> None:
        self.assertIn('path == "/api/oob/poll"', API_SRC)
        self.assertIn('"/api/oob/poll"', JS, "Mint still hands out a token that can never be checked")

    def test_mint_hands_its_token_to_the_poll_control(self) -> None:
        panel = _js_function("ckOobPanel")
        self.assertIn("ptoken.input.value = m.token", panel,
                      "the minted token is not carried to the poll field, so the operator retypes it")
        self.assertIn("Check for callbacks", panel)

    def test_the_poll_result_renders_the_hits_not_just_the_count(self) -> None:
        panel = _js_function("ckOobPanel")
        for field in ("res.count", "res.hits"):
            self.assertIn(field, panel, f"the poll response's {field} is dropped")
        self.assertIn("hit.ip", panel)
        self.assertIn("user-agent", panel)


class StoredXssBeaconIsServerConfiguredTests(unittest.TestCase):
    """The beacon route used to take the collaborator base + secret as REQUEST fields, which made
    it unreachable from the app on purpose-built grounds: oob_config_status returns only
    ``has_secret``, never the secret, so no client could ever fill them in. The fix is server-side
    — read the saved config like every other OOB route — not a client that learns the secret."""

    _CONFIG = {"oob.collaborator_url": "https://collab.example", "oob.secret": "s3cr3t"}

    def _run(self, request: greyiq_api.StoredXssBeaconRequest) -> dict:
        captured: dict = {}

        def _capture(**kwargs):
            captured.update(kwargs)
            return {"ok": False, "error": "stopped after capturing the arguments"}

        with mock.patch.object(greyiq_api, "_load_secrets", return_value=dict(self._CONFIG)), \
             mock.patch.object(greyiq_api.bounty_stored_xss, "confirm_stored_xss_beacon", _capture):
            greyiq_api.GreyIQRuntime().check_stored_xss_beacon(request)
        return captured

    def test_the_request_model_cannot_carry_the_collaborator_secret(self) -> None:
        fields = _model_fields("StoredXssBeaconRequest")
        self.assertNotIn("secret", fields, "the beacon route asks the client for the OOB secret again")
        self.assertNotIn("base", fields)

    def test_the_route_reads_the_saved_collaborator_config(self) -> None:
        captured = self._run(greyiq_api.StoredXssBeaconRequest(
            view_url="https://app.example.com/profile", scope="app.example.com"))
        self.assertEqual(captured.get("base"), "https://collab.example")
        self.assertEqual(captured.get("secret"), "s3cr3t")

    def test_a_client_supplied_secret_is_ignored(self) -> None:
        request = greyiq_api.StoredXssBeaconRequest.model_validate({
            "view_url": "https://app.example.com/profile", "scope": "app.example.com",
            "base": "https://attacker.example", "secret": "attacker-controlled",
        })
        captured = self._run(request)
        self.assertEqual(captured.get("base"), "https://collab.example",
                         "a client-supplied base steered the beacon away from the operator's collaborator")
        self.assertEqual(captured.get("secret"), "s3cr3t")

    def test_the_config_endpoint_still_never_returns_the_secret(self) -> None:
        with mock.patch.object(greyiq_api, "_load_secrets", return_value=dict(self._CONFIG)):
            status = greyiq_api.GreyIQRuntime().oob_config_status()
        self.assertTrue(status["has_secret"])
        self.assertNotIn("secret", status)
        self.assertNotIn("s3cr3t", repr(status))

    def test_the_route_is_now_reachable_from_the_app(self) -> None:
        self.assertIn('"/api/bounty/stored-xss-beacon"', JS)
        form = _js_function("ckStoredXssBeaconForm")
        self.assertNotIn("secret", form, "the beacon form is collecting a secret from the operator")


class AgentUndoNeverOverwritesYourEditsTests(unittest.TestCase):
    """``/api/agent/undo`` writes the pre-run text back over whatever is on disk now. Without a
    post-run fingerprint it cannot tell "still what the run wrote" from "the user has been working
    in this file since", and silently destroys the second. ``workspace.rollback_changes`` has
    always refused that case; this is the same guarantee on the wired route."""

    def _toolbox(self, root: Path) -> "agent.ToolBox":
        return agent.ToolBox(root, {"allow_commands": False, "allow_network": False})

    def test_the_payload_carries_what_restore_needs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            toolbox = self._toolbox(Path(td))
            (Path(td) / "a.txt").write_text("original", encoding="utf-8")
            toolbox._tool_write_file({"path": "a.txt", "content": "the agent wrote this"})
            entry = next(e for e in toolbox.snapshot_payload() if e["path"] == "a.txt")
            self.assertIn("after_sha256", entry)
            self.assertTrue(entry["after_sha256"], "no post-run fingerprint, so restore can't detect a conflict")
            self.assertIn("content_unavailable", entry,
                          "capture records content_unavailable and the payload drops it again")

    def test_a_file_edited_after_the_run_is_refused_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "a.txt"
            target.write_text("original", encoding="utf-8")
            toolbox = self._toolbox(Path(td))
            toolbox._tool_write_file({"path": "a.txt", "content": "the agent wrote this"})
            payload = toolbox.snapshot_payload()
            target.write_text("and then I spent an hour on it", encoding="utf-8")

            out = agent.restore_snapshot(payload, td)

            self.assertEqual(target.read_text(encoding="utf-8"), "and then I spent an hour on it",
                             "undo overwrote work the agent run never touched")
            self.assertNotIn("a.txt", out["restored"])
            self.assertTrue(any("changed after the agent run" in e for e in out["errors"]), out["errors"])

    def test_an_untouched_file_still_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "a.txt"
            target.write_text("original", encoding="utf-8")
            toolbox = self._toolbox(Path(td))
            toolbox._tool_write_file({"path": "a.txt", "content": "the agent wrote this"})

            out = agent.restore_snapshot(toolbox.snapshot_payload(), td)

            self.assertEqual(target.read_text(encoding="utf-8"), "original")
            self.assertEqual(out["errors"], [])
            self.assertIn("a.txt", out["restored"])

    def test_a_file_already_reverted_one_at_a_time_is_not_a_conflict(self) -> None:
        # Per-file Revert (via /api/workspace/rollback) puts a file back to its pre-run text. A
        # later whole-run Undo must treat that as done, not as an edit it refuses to touch.
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "a.txt"
            target.write_text("original", encoding="utf-8")
            toolbox = self._toolbox(Path(td))
            toolbox._tool_write_file({"path": "a.txt", "content": "the agent wrote this"})
            payload = toolbox.snapshot_payload()
            target.write_text("original", encoding="utf-8")  # reverted by hand

            out = agent.restore_snapshot(payload, td)

            self.assertEqual(out["errors"], [])
            self.assertIn("a.txt", out["restored"])

    def test_a_created_file_the_user_kept_working_in_is_not_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "new.txt"
            toolbox = self._toolbox(Path(td))
            toolbox._tool_write_file({"path": "new.txt", "content": "the agent created this"})
            payload = toolbox.snapshot_payload()
            target.write_text("and I built on it", encoding="utf-8")

            out = agent.restore_snapshot(payload, td)

            self.assertTrue(target.is_file(), "undo deleted a created file the user had since edited")
            self.assertNotIn("new.txt", out["deleted"])
            self.assertTrue(any("changed after the agent run" in e for e in out["errors"]), out["errors"])

    def test_an_uncaptured_original_is_left_alone_through_the_real_payload(self) -> None:
        # The end-to-end version of the existing content_unavailable guard: the flag is set at
        # capture time, and the guard only fires if snapshot_payload actually carries it.
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "e.txt"
            target.write_text("do-not-lose", encoding="utf-8")
            toolbox = self._toolbox(Path(td))
            with mock.patch.object(toolbox, "_safe_read", return_value=None):  # exists, unreadable
                toolbox._tool_write_file({"path": "e.txt", "content": "the agent wrote this"})

            agent.restore_snapshot(toolbox.snapshot_payload(), td)

            self.assertEqual(target.read_text(encoding="utf-8"), "the agent wrote this",
                             "an original we never captured was 'restored' to an empty string")

    def test_a_snapshot_written_before_the_fingerprint_still_restores(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "a.txt"
            target.write_text("whatever is there now", encoding="utf-8")
            out = agent.restore_snapshot([{"path": "a.txt", "existed": True, "content": "original"}], td)
            self.assertEqual(target.read_text(encoding="utf-8"), "original")
            self.assertEqual(out["errors"], [])

    def test_the_client_names_the_files_it_refused(self) -> None:
        undo = _js_function("undoLastAgentRun")
        self.assertIn("res.errors", undo,
                      "the per-file reasons are dropped, so 'Undo failed' is all the operator gets")


class WorkspaceRollbackTests(unittest.TestCase):
    """The conservative sibling of Undo: one file at a time, refusing anything it cannot restore
    faithfully. It was orphaned while the all-or-nothing route was the only one wired."""

    def test_the_rollback_route_is_reachable_from_the_app(self) -> None:
        self.assertIn('path == "/api/workspace/rollback"', API_SRC)
        self.assertIn('"/api/workspace/rollback"', JS, "the rollback route has no caller again")

    def test_the_changes_panel_offers_a_per_file_revert(self) -> None:
        panel = _js_function("renderChangesPanel")
        self.assertIn("buildRevertControl(change)", panel, "a change card shows a diff and no way to undo it")
        control = _js_function("buildRevertControl")
        self.assertIn("/api/workspace/rollback", control)
        self.assertIn("changes: [change]", control, "the revert posts something other than this card's change")

    def test_a_clipped_snapshot_offers_no_revert_button(self) -> None:
        # The route refuses a truncated payload; a button that can only fail is worse than none.
        control = _js_function("buildRevertControl")
        self.assertIn("change.before_truncated || change.after_truncated", control)

    def test_the_reverted_file_leaves_the_change_list(self) -> None:
        control = _js_function("buildRevertControl")
        self.assertIn("state.lastAgentChanges", control,
                      "the panel keeps offering a revert for a file already reverted")

    def test_the_route_still_refuses_a_file_changed_after_the_run(self) -> None:
        import workspace as workspace_fs

        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "a.txt"
            target.write_text("mine now", encoding="utf-8")
            out = workspace_fs.rollback_changes(td, [{
                "path": "a.txt", "existed": True, "before": "original", "after": "the agent wrote this",
            }])
            self.assertFalse(out["ok"])
            self.assertEqual(target.read_text(encoding="utf-8"), "mine now")


class NoNewOrphanRoutesTests(unittest.TestCase):
    """A register of the /api routes the app does not call, so a new one is a test failure rather
    than a capability that quietly never shipped. Wiring a listed route means deleting its line
    here — which is the point: the list can only shrink by someone looking at it."""

    # route -> why it has no app.js caller today
    KNOWN = {
        "/api/health": "the readiness gate the Electron shell and the release smoke tests poll",
        "/api/bounty/finding/reverify": "superseded in the UI by /finding/prove; still served for API clients",
        "/api/bounty/platforms": "the app ships the same list as CK_PLATFORMS and renders it offline",
        "/api/operator/vdp-profiles": "the app ships the profile list; the route is for API clients",
        "/api/scan/code": "the pre-cockpit scan API, kept for CLI/API clients",
        "/api/scan/live": "the pre-cockpit scan API, kept for CLI/API clients",
        "/api/scan/web": "the pre-cockpit scan API, kept for CLI/API clients",
        "/api/train/status": "the same training_payload the app already receives inside /api/status",
    }

    def test_no_route_becomes_orphaned_without_being_declared(self) -> None:
        orphans = _handled_routes() - _routes_called_from_the_app()
        new = sorted(orphans - set(self.KNOWN))
        self.assertFalse(new, f"route(s) the app never calls, with no entry in KNOWN: {new}")

    def test_the_register_does_not_rot(self) -> None:
        called = _routes_called_from_the_app()
        wired = sorted(r for r in self.KNOWN if r in called)
        self.assertFalse(wired, f"KNOWN still lists route(s) the app now calls: {wired}")
        gone = sorted(r for r in self.KNOWN if r not in _handled_routes())
        self.assertFalse(gone, f"KNOWN lists route(s) the server no longer serves: {gone}")


if __name__ == "__main__":
    unittest.main()
