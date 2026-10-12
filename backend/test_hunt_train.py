"""Tests for the in-tree trainer and its promotion gate (`gn train-brain`).

The gate is the point of this module, so it is what is tested hardest: a model that does not
beat the hand-tuned rules on a held-out, program-level split must NOT be promoted, must leave
any previously promoted file untouched, and must say so. Training itself must be bit-
reproducible, or the gate's comparison is noise."""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hunt_model, hunt_train, hunt_trace, ledger  # noqa: E402
from bughunter.prover_classes import ACTIVE_RULE_CHECK_TAGS, PROVER_CLASSES, confirmed_learning_tag  # noqa: E402

# The classes every synthetic hunt probes, in the order the plan records them. The rules order
# for a `/search?q=` endpoint is [xss, sqli] + the rest sorted, so "rce" sits at index 3 —
# outside recall@3 — which is what gives the learned model room to win in CorpusA.
_CLASSES = ["xss", "sqli", "path-traversal", "rce", "redirect"]
_RULE_IDS = {"xss": "active.reflected-xss", "sqli": "active.sqli-error",
             "path-traversal": "active.path-traversal", "rce": "active.rce-command-injection",
             "redirect": "active.open-redirect"}
_FIXED_NOW = "2026-08-01T00:00:00+00:00"


def _split_programs(count: int) -> tuple[list[str], list[str]]:
    """`count` program names on each side of the by-program hash split (holdout=0.2)."""
    train: list[str] = []
    hold: list[str] = []
    index = 0
    while len(train) < count or len(hold) < count:
        name = f"prog-{index:04d}"
        (hold if hunt_train._program_in_holdout(name, 0.2) else train).append(name)
        index += 1
        if index > 5000:  # pragma: no cover - the hash is uniform; this is a runaway guard
            raise AssertionError("could not build a two-sided program split")
    return train[:count], hold[:count]


def _write_trace(rt: Path, program: str, confirms: set[str]) -> str:
    """One synthetic hunt with five rule-plausible classes and known execution."""
    endpoint = f"https://{program}.example.com/search?q=1&file=x&cmd=id&redirect=%2F"
    surface = {"endpoints": [endpoint], "params": ["q", "file", "cmd", "redirect"],
               "tech": [], "forms": []}
    plan = {"provider": "offline", "used": True,
            "probe_priority": [{"endpoint": endpoint, "classes": list(_CLASSES)}],
            "param_hypotheses": [], "idor_candidates": [], "privileged_endpoints": [],
            "ssrf_params": [], "xss_params": []}
    outcomes = [{"endpoint": endpoint, "class": cls, "rule_id": _RULE_IDS[cls],
                 "proof_status": "confirmed" if cls in confirms else "missing",
                 "severity": "medium", "dedup_key": ""} for cls in _CLASSES]
    hunt_trace.record_trace(rt, program=program, target=endpoint, surface=surface, plan=plan,
                            outcomes=outcomes, execution=[{"endpoint": endpoint, "classes": list(_CLASSES)}])
    return endpoint


class _Tmp(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)
        self.out = self.rt / "hunt_model" / "hunt_ranker.json"
        hunt_model._CACHE.clear()

    def tearDown(self) -> None:
        hunt_model._CACHE.clear()
        self._tmp.cleanup()


class ConstantsTests(unittest.TestCase):
    def test_rule_to_suite_map_covers_every_active_verifier_finding(self) -> None:
        source = (BACKEND_DIR / "bughunter" / "active_verify_service.py").read_text(encoding="utf-8")
        emitted = set(re.findall(r'_finding\(\s*"(active\.[a-z0-9-]+)"', source))
        self.assertEqual(set(ACTIVE_RULE_CHECK_TAGS), emitted)
        self.assertTrue(set(ACTIVE_RULE_CHECK_TAGS.values()) <= PROVER_CLASSES)

    def test_output_path_matches_what_the_loader_resolves(self) -> None:
        # The two modules must never drift: hunt_train writes where hunt_model reads.
        self.assertEqual(hunt_train._OUT_SUBDIR, hunt_model._SUBDIR)
        self.assertEqual(hunt_train._OUT_NAME, hunt_model._FILENAME)

    def test_the_weight_file_is_never_a_dot_pt(self) -> None:
        # The PyInstaller spec silently drops *.pt; a file that vanishes only in the frozen
        # build is the worst failure mode there is.
        self.assertTrue(hunt_train._OUT_NAME.endswith(".json"))
        self.assertFalse(hunt_train._OUT_NAME.endswith(".pt"))


class SplitTests(unittest.TestCase):
    def test_the_program_split_is_a_partition(self) -> None:
        names = [f"prog-{i:04d}" for i in range(300)]
        hold = {n for n in names if hunt_train._program_in_holdout(n, 0.2)}
        train = {n for n in names if not hunt_train._program_in_holdout(n, 0.2)}
        self.assertTrue(hold)
        self.assertTrue(train)
        self.assertEqual(hold & train, set())          # never both sides
        self.assertEqual(hold | train, set(names))     # never neither

    def test_the_split_is_stable_across_calls(self) -> None:
        for name in ("acme", "example.com", "prog-0007"):
            self.assertEqual(hunt_train._program_in_holdout(name, 0.2),
                             hunt_train._program_in_holdout(name, 0.2))

    def test_holdout_zero_keeps_everything_in_train(self) -> None:
        self.assertFalse(any(hunt_train._program_in_holdout(f"p{i}", 0.0) for i in range(50)))


class DatasetTests(_Tmp):
    def test_rule_ids_attribute_ambiguous_impacts_to_exact_checked_suites(self) -> None:
        cases = (
            ("debug-rce", "rce", "active.debug-endpoint", "debug"),
            ("debug-disclosure", "disclosure", "active.debug-endpoint", "debug"),
            ("framing", "headers", "active.clickjacking", "clickjacking"),
            ("crlf", "redirect", "active.crlf", "crlf"),
            ("host", "redirect", "active.host-header-injection", "host-header"),
            ("open", "redirect", "active.open-redirect", "redirect"),
        )
        for path, impact, rule_id, tag in cases:
            endpoint = f"https://acme.example.com/{path}"
            hunt_trace.record_trace(self.rt, program="acme", target=endpoint,
                                    surface={"endpoints": [endpoint]}, plan={},
                                    outcomes=[{"endpoint": endpoint, "class": impact,
                                               "rule_id": rule_id, "proof_status": "confirmed"}],
                                    execution=[{"endpoint": endpoint, "classes": [tag, "xss"]}])
        by_endpoint = {}
        for row in hunt_train._collect(self.rt):
            by_endpoint.setdefault(row["endpoint"].rsplit("/", 1)[-1], {})[row["class_id"]] = row["label"]
        for path, impact, rule_id, tag in cases:
            self.assertEqual(confirmed_learning_tag(impact, rule_id), tag)
            self.assertEqual(by_endpoint[path][tag], 1)
            self.assertEqual(by_endpoint[path]["xss"], 0)
            if impact != tag:
                self.assertNotIn(impact, by_endpoint[path])

    def test_unknown_ambiguous_confirm_neither_invents_positive_nor_negative(self) -> None:
        endpoint = "https://acme.example.com/admin"
        hunt_trace.record_trace(self.rt, program="acme", target=endpoint,
                                surface={"endpoints": [endpoint]}, plan={},
                                outcomes=[{"endpoint": endpoint, "class": "rce",
                                           "rule_id": "active.unrecognized", "proof_status": "confirmed"}],
                                execution=[{"endpoint": endpoint, "classes": ["debug", "rce", "xss"]}])
        # A v1 trace has no execution evidence; its ambiguous confirmation also
        # cannot identify the check that produced the impact.
        with (self.rt / "hunt_traces.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"v": 1, "program": "legacy", "surface": {}, "plan": {},
                                     "outcomes": [{"endpoint": endpoint, "class": "headers",
                                                   "proof_status": "confirmed"}]}) + "\n")
        rows = hunt_train._collect(self.rt)
        self.assertEqual({(row["program"], row["class_id"], row["label"]) for row in rows},
                         {("acme", "xss", 0)})

    def test_probed_but_unconfirmed_classes_become_negatives(self) -> None:
        # Completed verifier suites, not the plan, establish that an absent confirm is a miss.
        _write_trace(self.rt, "acme", {"rce"})
        rows = hunt_train.build_dataset(self.rt)
        self.assertEqual(len(rows), len(_CLASSES))
        labels = {class_id: label for _f, class_id, label, _w, _p in rows}
        self.assertEqual(labels["rce"], 1)
        self.assertEqual(sum(labels.values()), 1)
        for cls in _CLASSES:
            self.assertIn(cls, labels)

    def test_rows_carry_features_program_and_a_base_weight(self) -> None:
        _write_trace(self.rt, "acme", set())
        feats, class_id, label, weight, program = hunt_train.build_dataset(self.rt)[0]
        self.assertIn("bias", feats)
        self.assertIn("path:kw=search", feats)
        self.assertEqual(class_id, "xss")
        self.assertEqual(label, 0)
        self.assertEqual(weight, 1.0)
        self.assertEqual(program, "acme")

    def test_a_paid_finding_is_weighted_up_to_three(self) -> None:
        endpoint = "https://paid.example.com/search?q=1"
        finding = {"class_id": "sqli", "rule_id": "active.sqli", "location": endpoint,
                   "title": "SQLi", "severity": "high"}
        consolidated = [{"finding": finding, "proof_status": "confirmed", "source_url": endpoint}]
        ledger.upsert_findings(self.rt, "acme", "https://paid.example.com/", consolidated)
        key = consolidated[0]["dedup_key"]
        ledger.advance_stage(self.rt, "acme", "https://paid.example.com/", key, "paid",
                             bounty=500.0, outcome="accepted")
        hunt_trace.record_trace(
            self.rt, program="acme", target=endpoint,
            surface={"endpoints": [endpoint], "params": ["q"], "tech": [], "forms": []},
            plan={"probe_priority": [{"endpoint": endpoint, "classes": ["sqli", "xss"]}]},
            outcomes=[{"endpoint": endpoint, "class": "sqli", "rule_id": "active.sqli",
                       "proof_status": "confirmed", "dedup_key": key},
                      {"endpoint": endpoint, "class": "xss", "rule_id": "active.xss",
                       "proof_status": "missing", "dedup_key": ""}],
            execution=[{"endpoint": endpoint, "classes": ["sqli", "xss"]}])
        rows = {class_id: (label, weight) for _f, class_id, label, weight, _p in
                hunt_train.build_dataset(self.rt)}
        self.assertEqual(rows["sqli"], (1, 3.0))
        self.assertEqual(rows["xss"], (0, 1.0))

    def test_payout_weights_only_the_finding_that_received_it(self) -> None:
        endpoint = "https://acme.example.com/admin"
        debug = {"class_id": "rce", "rule_id": "active.debug-endpoint",
                 "location": endpoint, "title": "Exposed management endpoint"}
        command = {"class_id": "rce", "rule_id": "active.rce-command-injection",
                   "location": endpoint, "title": "Command injection"}
        items = [{"finding": debug, "proof_status": "confirmed", "source_url": endpoint},
                 {"finding": command, "proof_status": "confirmed", "source_url": endpoint}]
        ledger.upsert_findings(self.rt, "acme", endpoint, items)
        ledger.advance_stage(self.rt, "acme", endpoint, items[0]["dedup_key"], "paid",
                             bounty=500.0, outcome="accepted")
        hunt_trace.record_trace(
            self.rt, program="acme", target=endpoint,
            surface={"endpoints": [endpoint], "params": [], "tech": [], "forms": []},
            plan={},
            outcomes=[{"endpoint": endpoint, "class": "rce", "rule_id": finding["rule_id"],
                       "proof_status": "confirmed", "dedup_key": item["dedup_key"]}
                      for finding, item in ((debug, items[0]), (command, items[1]))],
            execution=[{"endpoint": endpoint, "classes": ["debug", "rce"]}],
        )
        rows = {row["class_id"]: row for row in hunt_train._collect(self.rt)}
        self.assertEqual((rows["debug"]["paid"], rows["debug"]["weight"]), (True, 3.0))
        self.assertEqual((rows["rce"]["paid"], rows["rce"]["weight"]), (False, 1.0))

    def test_a_class_that_confirmed_outside_the_plan_is_still_learned_from(self) -> None:
        endpoint = "https://acme.example.com/download?file=a"
        hunt_trace.record_trace(
            self.rt, program="acme", target=endpoint,
            surface={"endpoints": [endpoint], "params": ["file"], "tech": [], "forms": []},
            plan={"probe_priority": [{"endpoint": endpoint, "classes": ["xss"]}]},
            outcomes=[{"endpoint": endpoint, "class": "path-traversal",
                       "rule_id": "active.path-traversal", "proof_status": "confirmed"}])
        labels = {c: label for _f, c, label, _w, _p in hunt_train.build_dataset(self.rt)}
        self.assertNotIn("xss", labels)  # planned but never verified as checked
        self.assertEqual(labels["path-traversal"], 1)

    def test_partial_and_legacy_traces_never_invent_negative_labels(self) -> None:
        endpoint = "https://acme.example.com/search?q=1"
        plan = {"probe_priority": [{"endpoint": endpoint, "classes": ["xss", "sqli", "rce"]}]}
        surface = {"endpoints": [endpoint], "params": ["q"], "tech": [], "forms": []}
        hunt_trace.record_trace(self.rt, program="acme", target=endpoint, surface=surface,
                                plan=plan, outcomes=[{"endpoint": endpoint, "class": "rce",
                                                      "rule_id": "active.rce-command-injection",
                                                      "proof_status": "confirmed"}],
                                execution=[{"endpoint": endpoint, "classes": ["xss"]}])
        # A v1 trace lacks verifier coverage. Its unconfirmed outcomes are unknown.
        with (self.rt / "hunt_traces.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"v": 1, "program": "legacy", "target": endpoint,
                                     "surface": surface, "plan": plan,
                                     "outcomes": [{"endpoint": endpoint, "class": "sqli",
                                                   "proof_status": "candidate"}]}) + "\n")
        rows = hunt_train._collect(self.rt)
        self.assertEqual({(row["program"], row["class_id"], row["label"]) for row in rows},
                         {("acme", "xss", 0), ("acme", "rce", 1)})

    def test_an_empty_corpus_yields_no_rows(self) -> None:
        self.assertEqual(hunt_train.build_dataset(self.rt), [])


class EvaluationTests(_Tmp):
    def test_unexecuted_planner_classes_still_compete_for_top_three(self) -> None:
        endpoint = "https://acme.example.com/search/download/admin/api?file=x&q=1&cmd=id"
        hunt_trace.record_trace(
            self.rt, program="acme", target=endpoint,
            surface={"endpoints": [endpoint], "params": ["file", "q", "cmd"],
                     "tech": [], "forms": []},
            plan={"probe_priority": [{"endpoint": endpoint,
                                      "classes": ["path-traversal", "xss", "sqli", "rce", "cors"]}]},
            outcomes=[{"endpoint": endpoint, "class": "path-traversal",
                       "rule_id": "active.path-traversal", "proof_status": "confirmed"}],
            execution=[{"endpoint": endpoint, "classes": ["path-traversal"]}],
        )
        rows = hunt_train._collect(self.rt)
        self.assertEqual([(r["class_id"], r["label"]) for r in rows], [("path-traversal", 1)])

        class DemotingModel:
            candidates: list[str] = []

            def rank_endpoint_classes(self, _url, _query, _recon, _tech, candidates, _priors, *, form=None):
                self.candidates = list(candidates)
                return [c for c in candidates if c != "path-traversal"] + ["path-traversal"]

        model = DemotingModel()
        scores = hunt_train._evaluate(model, rows)
        self.assertEqual(model.candidates,
                         ["path-traversal", "xss", "sqli", "rce", "cors"])
        self.assertEqual(scores["recall_at_3_rules"], 1.0)
        self.assertEqual(scores["recall_at_3_model"], 0.0)

    def test_unproposed_confirmation_is_unscorable_for_a_permutation_ranker(self) -> None:
        endpoint = "https://acme.example.com/search/download/admin/api?file=x&q=1&cmd=id"
        hunt_trace.record_trace(
            self.rt, program="acme", target=endpoint,
            surface={"endpoints": [endpoint], "params": ["file", "q", "cmd"],
                     "tech": [], "forms": []}, plan={},
            outcomes=[{"endpoint": endpoint, "class": "redirect",
                       "rule_id": "active.open-redirect", "proof_status": "confirmed"}],
            execution=[{"endpoint": endpoint, "classes": ["redirect"]}],
        )
        rows = hunt_train._collect(self.rt)
        self.assertEqual([(r["class_id"], r["label"]) for r in rows], [("redirect", 1)])

        class NeverCalled:
            def rank_endpoint_classes(self, *_args, **_kwargs):
                raise AssertionError("an absent planner class cannot be ranked in production")

        scores = hunt_train._evaluate(NeverCalled(), rows)
        self.assertIsNone(scores["recall_at_3_model"])
        self.assertIsNone(scores["recall_at_3_rules"])
        self.assertEqual(scores["scored_endpoints"], 0)


class RefusalTests(_Tmp):
    def test_below_min_rows_it_refuses_and_writes_nothing(self) -> None:
        _write_trace(self.rt, "acme", {"rce"})
        result = hunt_train.train(self.rt, min_rows=200)
        self.assertFalse(result["ok"])
        self.assertFalse(result["written"])
        self.assertIn("not enough training data", result["reason"])
        self.assertEqual(result["rows"], len(_CLASSES))
        self.assertEqual(result["rows_needed"], 200 - len(_CLASSES))
        self.assertFalse(self.out.exists())

    def test_a_model_that_loses_to_the_rules_is_not_promoted(self) -> None:
        # Train programs confirm rce/redirect/path-traversal; held-out programs confirm xss on
        # an identically-shaped endpoint. The model therefore ranks the three it learned first
        # and pushes xss out of the top 3, while the rules put xss first. Model < rules.
        train_programs, hold_programs = _split_programs(8)
        for program in train_programs:
            _write_trace(self.rt, program, {"rce", "redirect", "path-traversal"})
        for program in hold_programs:
            _write_trace(self.rt, program, {"xss"})
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.out.write_text("PREVIOUSLY PROMOTED MODEL", encoding="utf-8")

        result = hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        self.assertFalse(result["ok"])
        self.assertFalse(result["written"])
        self.assertIn("did not beat the rules", result["reason"])
        self.assertLess(result["recall_at_3_model"], result["recall_at_3_rules"])
        # The existing file is untouched — a failed retrain never costs you a working model.
        self.assertEqual(self.out.read_text(encoding="utf-8"), "PREVIOUSLY PROMOTED MODEL")

    def test_no_confirmed_holdout_outcome_reports_undetermined_not_zero(self) -> None:
        train_programs, hold_programs = _split_programs(8)
        for program in train_programs:
            _write_trace(self.rt, program, {"rce"})
        for program in hold_programs:
            _write_trace(self.rt, program, set())   # nothing ever confirmed on the holdout
        result = hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        self.assertFalse(result["ok"])
        self.assertFalse(result["written"])
        self.assertIsNone(result["recall_at_3_model"])
        self.assertIsNone(result["recall_at_3_rules"])
        self.assertIn("undetermined", result["reason"])
        self.assertFalse(self.out.exists())

    def test_a_single_program_cannot_be_split_and_is_refused(self) -> None:
        for index in range(60):
            hunt_trace.record_trace(
                self.rt, program="acme", target=f"https://acme.example.com/search?q={index}",
                surface={"endpoints": [], "params": ["q"], "tech": [], "forms": []},
                plan={"probe_priority": [{"endpoint": f"https://acme.example.com/s{index}?q=1",
                                          "classes": list(_CLASSES)}]},
                outcomes=[], execution=[{"endpoint": f"https://acme.example.com/s{index}?q=1",
                                         "classes": list(_CLASSES)}])
        result = hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        self.assertFalse(result["ok"])
        self.assertIn("undetermined", result["reason"])
        self.assertFalse(self.out.exists())


class PromotionTests(_Tmp):
    def _corpus(self) -> None:
        train_programs, hold_programs = _split_programs(8)
        for program in train_programs + hold_programs:
            _write_trace(self.rt, program, {"rce"})

    def test_a_model_that_beats_the_rules_is_promoted_and_round_trips(self) -> None:
        self._corpus()
        result = hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        self.assertTrue(result["ok"], result["reason"])
        self.assertTrue(result["written"])
        self.assertGreater(result["recall_at_3_model"], result["recall_at_3_rules"])
        self.assertTrue(self.out.exists())

        payload = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(payload["kind"], "greyiq-hunt-ranker")
        self.assertEqual(payload["created_at"], _FIXED_NOW)
        self.assertEqual(payload["eval"]["recall_at_3_model"], result["recall_at_3_model"])
        self.assertEqual(payload["eval"]["recall_at_3_rules"], result["recall_at_3_rules"])
        self.assertIn("rce", payload["ranker"])

        model = hunt_model.load_model(None, self.rt)
        self.assertIsNotNone(model)
        assert model is not None
        self.assertIn(_FIXED_NOW, model.version_tag)
        order = model.rank_endpoint_classes(
            "https://held.example.com/search?q=1", ["q"], ["q"], "", list(_CLASSES), None)
        self.assertEqual(sorted(order), sorted(_CLASSES))   # still only a permutation
        self.assertEqual(order[0], "rce")                   # and it learned what confirmed

    def test_dry_run_evaluates_but_writes_nothing(self) -> None:
        self._corpus()
        result = hunt_train.train(self.rt, min_rows=20, dry_run=True, now=_FIXED_NOW)
        self.assertTrue(result["ok"])
        self.assertFalse(result["written"])
        self.assertIn("dry run", result["reason"])
        self.assertIsNotNone(result["recall_at_3_model"])
        self.assertFalse(self.out.exists())

    def test_retrain_keeps_better_valid_incumbent_on_same_holdout(self) -> None:
        self._corpus()
        first = hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        self.assertTrue(first["written"])
        self.assertIsNotNone(hunt_model.load_model(None, self.rt))
        original = self.out.read_bytes()

        # Both candidate and incumbent clear the rules baseline. The new model must
        # still be refused when the already deployed model scores better on this
        # retrain's exact held-out rows, regardless of its historical eval metadata.
        with patch.object(hunt_train, "_evaluate", side_effect=[
            {"recall_at_3_model": 0.5, "recall_at_3_rules": 0.25, "scored_endpoints": 8},
            {"recall_at_3_model": 0.75, "recall_at_3_rules": 0.25, "scored_endpoints": 8},
        ]) as evaluate:
            result = hunt_train.train(self.rt, min_rows=20, now="2026-08-02T00:00:00+00:00")

        self.assertFalse(result["ok"])
        self.assertFalse(result["written"])
        self.assertEqual(result["recall_at_3_incumbent"], 0.75)
        self.assertIn("regressed against the active model", result["reason"])
        self.assertEqual(self.out.read_bytes(), original)
        self.assertEqual(evaluate.call_count, 2)
        self.assertIs(evaluate.call_args_list[0].args[1], evaluate.call_args_list[1].args[1])

    def test_retrain_may_replace_equal_incumbent(self) -> None:
        self._corpus()
        first = hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        self.assertTrue(first["written"])
        second = hunt_train.train(self.rt, min_rows=20, now="2026-08-02T00:00:00+00:00")
        self.assertTrue(second["written"], second["reason"])
        self.assertEqual(second["recall_at_3_incumbent"], second["recall_at_3_model"])
        self.assertEqual(json.loads(self.out.read_text(encoding="utf-8"))["eval"]
                         ["recall_at_3_incumbent"], second["recall_at_3_incumbent"])

    def test_retrain_rejects_regression_hidden_by_display_rounding(self) -> None:
        self._corpus()
        self.assertTrue(hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)["written"])
        original = self.out.read_bytes()
        with patch.object(hunt_train, "_evaluate", side_effect=[
            {"recall_at_3_model": 0.50001, "recall_at_3_rules": 0.25, "scored_endpoints": 8},
            {"recall_at_3_model": 0.50002, "recall_at_3_rules": 0.25, "scored_endpoints": 8},
        ]):
            result = hunt_train.train(self.rt, min_rows=20, now="2026-08-02T00:00:00+00:00")
        self.assertFalse(result["written"])
        self.assertEqual(result["recall_at_3_model"], result["recall_at_3_incumbent"])
        self.assertEqual(self.out.read_bytes(), original)

    def test_invalid_incumbent_does_not_block_promotion(self) -> None:
        self._corpus()
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.out.write_text("{invalid model", encoding="utf-8")
        result = hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        self.assertTrue(result["written"], result["reason"])
        self.assertIsNone(result["recall_at_3_incumbent"])
        self.assertIsNotNone(hunt_model.load_model(None, self.rt))

    def test_two_runs_over_one_corpus_are_byte_identical(self) -> None:
        self._corpus()
        hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        first = self.out.read_bytes()
        self.out.unlink()
        hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        second = self.out.read_bytes()
        self.assertEqual(first, second)
        self.assertGreater(len(first), 0)

    def test_the_split_used_by_train_never_shares_a_program(self) -> None:
        self._corpus()
        rows = hunt_train._collect(self.rt)
        train_side = {r["program"] for r in rows if not hunt_train._program_in_holdout(r["program"], 0.2)}
        hold_side = {r["program"] for r in rows if hunt_train._program_in_holdout(r["program"], 0.2)}
        self.assertTrue(train_side and hold_side)
        self.assertEqual(train_side & hold_side, set())
        result = hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        self.assertEqual(result["train_rows"] + result["held_out_rows"], result["rows"])
        self.assertEqual(result["held_out_programs"], len(hold_side))


class SideModelTests(_Tmp):
    def test_selectors_train_only_for_a_kind_with_positives(self) -> None:
        train_programs, hold_programs = _split_programs(8)
        for program in train_programs + hold_programs:
            endpoint = f"https://{program}.example.com/order/1001?id=2"
            hunt_trace.record_trace(
                self.rt, program=program, target=endpoint,
                surface={"endpoints": [endpoint], "params": ["id"], "tech": [], "forms": []},
                plan={"probe_priority": [{"endpoint": endpoint, "classes": list(_CLASSES)}]},
                execution=[{"endpoint": endpoint, "classes": list(_CLASSES)}],
                outcomes=[{"endpoint": endpoint, "class": "access-control",
                           "rule_id": "active.idor", "proof_status": "confirmed"},
                          {"endpoint": endpoint, "class": "sqli",
                           "rule_id": "active.sqli-error", "proof_status": "confirmed"}])
        result = hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        self.assertTrue(result["ok"], result["reason"])
        payload = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertIn("idor", payload["selectors"])
        # No BFLA/mass-assignment rule_id ever confirmed, so no privileged selector is
        # fabricated — a kind with zero positives has learned nothing.
        self.assertNotIn("privileged", payload["selectors"])

    def test_param_model_is_keyed_by_bucket_and_tech_and_holds_names_only(self) -> None:
        train_programs, hold_programs = _split_programs(8)
        for program in train_programs + hold_programs:
            endpoint = f"https://{program}.example.com/download?filepath=abc"
            hunt_trace.record_trace(
                self.rt, program=program, target=endpoint,
                surface={"endpoints": [endpoint], "params": ["filepath"], "tech": ["PHP 8.1"],
                         "forms": []},
                plan={"probe_priority": [{"endpoint": endpoint, "classes": list(_CLASSES)}]},
                execution=[{"endpoint": endpoint, "classes": list(_CLASSES)}],
                outcomes=[{"endpoint": endpoint, "class": "path-traversal",
                           "rule_id": "active.path-traversal", "proof_status": "confirmed"}])
        result = hunt_train.train(self.rt, min_rows=20, now=_FIXED_NOW)
        self.assertTrue(result["ok"], result["reason"])
        payload = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertIn("download|php", payload["param_model"])
        names = [row[0] for row in payload["param_model"]["download|php"]]
        self.assertEqual(names, ["filepath"])
        self.assertNotIn("abc", json.dumps(payload["param_model"]))  # a NAME, never the value

        model = hunt_model.load_model(None, self.rt)
        assert model is not None
        self.assertEqual(model.suggest_params("download", "nginx PHP 8.1", 4), ["filepath"])


class CliTests(_Tmp):
    """`gn train-brain` — registered through gn_cli's plugin hook."""

    def setUp(self) -> None:
        super().setUp()
        import gn_cli

        self._gn_cli = gn_cli
        self._runtime = gn_cli.RUNTIME_DIR
        gn_cli.RUNTIME_DIR = self.rt

    def tearDown(self) -> None:
        self._gn_cli.RUNTIME_DIR = self._runtime
        super().tearDown()

    def _run(self, **flags: object) -> tuple[int, str]:
        args = argparse.Namespace(dry_run=False, show=False, min_rows=200, json=False)
        for key, value in flags.items():
            setattr(args, key, value)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = hunt_train._cmd_train_brain(args)
        return code, buffer.getvalue()

    def test_the_verb_is_registered_on_the_real_parser(self) -> None:
        parser = self._gn_cli.build_parser()
        parsed = parser.parse_args(["train-brain", "--show"])
        self.assertTrue(parsed.show)
        self.assertIs(parsed.func, hunt_train._cmd_train_brain)

    def test_show_on_an_empty_corpus_states_what_is_collected_and_what_is_needed(self) -> None:
        code, output = self._run(show=True)
        self.assertEqual(code, 0)
        self.assertIn("active model: none", output)
        self.assertIn("GreyIQ ships no pre-trained weights", output)
        self.assertIn("0 labeled row(s)", output)
        self.assertIn("200 more row(s) needed", output)

    def test_show_json_reports_the_corpus_counts(self) -> None:
        _write_trace(self.rt, "acme", {"rce"})
        code, output = self._run(show=True, json=True)
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertIsNone(payload["active_model"])
        self.assertFalse(payload["loaded"])
        self.assertEqual(payload["corpus"]["labeled_rows"], len(_CLASSES))
        self.assertEqual(payload["corpus"]["confirmed_rows"], 1)
        self.assertEqual(payload["corpus"]["programs"], 1)
        self.assertEqual(payload["corpus"]["rows_needed"], 200 - len(_CLASSES))

    def test_a_refused_gate_exits_one_and_says_why(self) -> None:
        _write_trace(self.rt, "acme", {"rce"})
        code, output = self._run()
        self.assertEqual(code, 1)
        self.assertIn("refused:", output)
        self.assertIn("not enough training data", output)

    def test_a_promotion_exits_zero_and_then_show_reports_the_model(self) -> None:
        train_programs, hold_programs = _split_programs(8)
        for program in train_programs + hold_programs:
            _write_trace(self.rt, program, {"rce"})
        code, output = self._run(min_rows=20)
        self.assertEqual(code, 0)
        self.assertIn("recall@3: model", output)
        self.assertIn("promoted:", output)

        hunt_model._CACHE.clear()
        code, output = self._run(show=True, min_rows=20)
        self.assertEqual(code, 0)
        self.assertIn("(runtime)", output)
        self.assertIn("loaded:     yes", output)
        self.assertIn("recall@3:", output)


if __name__ == "__main__":
    unittest.main()
