"""Tests for the learned offline hunt ranker (inference side).

The two things that must hold no matter what is on disk: a bad weight file degrades to
``None`` (== "use the hand-tuned rules") without raising, and a loaded model can only ever
PERMUTE the candidate class list it is handed."""
from __future__ import annotations

import json
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hunt_features, hunt_model  # noqa: E402


def _payload(**overrides: object) -> dict:
    data = {
        "v": 1,
        "kind": "greyiq-hunt-ranker",
        "feature_version": hunt_features.FEATURE_VERSION,
        "created_at": "2026-08-01T00:00:00+00:00",
        "trained_on": {"traces": 4, "rows": 40, "confirmed": 8, "paid": 1},
        "eval": {"recall_at_3_model": 0.71, "recall_at_3_rules": 0.58,
                 "held_out_rows": 10, "held_out_programs": 2},
        "classes": ["xss", "sqli"],
        "ranker": {
            "xss": {"bias": 0.0, "w": {}},
            "sqli": {"bias": -1.0, "w": {"path:kw=search": 4.0}},
        },
        "param_model": {"download|php": [["filepath", 0.41], ["attachment", 0.22]]},
        "selectors": {"idor": {"bias": -2.0, "w": {"shape:numeric_seg": 4.0}}},
    }
    data.update(overrides)
    return data


def _write(base: Path, payload: object) -> Path:
    path = base / "hunt_model" / "hunt_ranker.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    path.write_text(text, encoding="utf-8")
    return path


class _Tmp(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self._tmp.name)
        hunt_model._CACHE.clear()  # the mtime cache is module-global; tests must not see each other

    def tearDown(self) -> None:
        hunt_model._CACHE.clear()
        self._tmp.cleanup()


class LoadRejectionTests(_Tmp):
    """Every rejection path returns None and raises NOTHING. Absent/invalid == use the rules."""

    def test_missing_file(self) -> None:
        self.assertIsNone(hunt_model.load_model(None, self.rt))
        self.assertIsNone(hunt_model.model_file(None, self.rt))

    def test_truncated_json(self) -> None:
        _write(self.rt, '{"v": 1, "kind": "greyiq-hunt-ranker", "ranker": {')
        self.assertIsNone(hunt_model.load_model(None, self.rt))

    def test_non_dict_root(self) -> None:
        for text in ("[]", '"a string"', "42", "null"):
            _write(self.rt, text)
            hunt_model._CACHE.clear()
            self.assertIsNone(hunt_model.load_model(None, self.rt), text)

    def test_wrong_schema_version(self) -> None:
        _write(self.rt, _payload(v=2))
        self.assertIsNone(hunt_model.load_model(None, self.rt))

    def test_wrong_kind(self) -> None:
        _write(self.rt, _payload(kind="something-else"))
        self.assertIsNone(hunt_model.load_model(None, self.rt))

    def test_wrong_feature_version(self) -> None:
        _write(self.rt, _payload(feature_version=hunt_features.FEATURE_VERSION + 1))
        self.assertIsNone(hunt_model.load_model(None, self.rt))

    def test_nan_weight(self) -> None:
        # NaN poisons a comparison sort into producing a NON-permutation — the one failure the
        # safety contract cannot absorb quietly. Rejected at load, not at score time.
        _write(self.rt, _payload(ranker={"xss": {"bias": 0.0, "w": {"path:kw=search": float("nan")}}}))
        self.assertIsNone(hunt_model.load_model(None, self.rt))

    def test_inf_weight(self) -> None:
        _write(self.rt, _payload(ranker={"xss": {"bias": 0.0, "w": {"path:kw=search": float("inf")}}}))
        self.assertIsNone(hunt_model.load_model(None, self.rt))

    def test_nan_bias(self) -> None:
        _write(self.rt, _payload(ranker={"xss": {"bias": float("-inf"), "w": {}}}))
        self.assertIsNone(hunt_model.load_model(None, self.rt))

    def test_non_numeric_and_malformed_blocks(self) -> None:
        cases = [
            _payload(ranker={"xss": "not a block"}),
            _payload(ranker={"xss": {"bias": 0.0, "w": {"f": "0.5"}}}),
            _payload(ranker="not a dict"),
            _payload(selectors={"idor": {"bias": None, "w": {}}}),
            _payload(param_model={"download|php": [["filepath", "high"]]}),
            _payload(param_model={"download|php": [["filepath"]]}),
            _payload(param_model="not a dict"),
        ]
        for data in cases:
            _write(self.rt, data)
            hunt_model._CACHE.clear()
            self.assertIsNone(hunt_model.load_model(None, self.rt), json.dumps(data)[:80])

    def test_a_directory_where_the_file_should_be(self) -> None:
        (self.rt / "hunt_model" / "hunt_ranker.json").mkdir(parents=True)
        self.assertIsNone(hunt_model.load_model(None, self.rt))


class ResolutionTests(_Tmp):
    def test_runtime_file_wins_over_seed_file(self) -> None:
        seed = self.rt / "seed"
        runtime = self.rt / "runtime"
        _write(seed, _payload(classes=["seed-only"], ranker={"seed-only": {"bias": 0.0, "w": {}}}))
        _write(runtime, _payload(classes=["runtime-only"], ranker={"runtime-only": {"bias": 0.0, "w": {}}}))
        model = hunt_model.load_model(seed, runtime)
        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model.classes, ["runtime-only"])

    def test_seed_used_when_no_runtime_file(self) -> None:
        seed = self.rt / "seed"
        _write(seed, _payload(classes=["seed-only"], ranker={"seed-only": {"bias": 0.0, "w": {}}}))
        model = hunt_model.load_model(seed, self.rt / "runtime")
        assert model is not None
        self.assertEqual(model.classes, ["seed-only"])

    def test_mtime_cache_rereads_after_a_touch(self) -> None:
        path = _write(self.rt, _payload(classes=["first"], ranker={"first": {"bias": 0.0, "w": {}}}))
        first = hunt_model.load_model(None, self.rt)
        assert first is not None
        self.assertEqual(first.classes, ["first"])
        self.assertIs(hunt_model.load_model(None, self.rt), first)  # cached: same object
        _write(self.rt, _payload(classes=["second"], ranker={"second": {"bias": 0.0, "w": {}}}))
        stamp = path.stat().st_mtime + 10
        os.utime(path, (stamp, stamp))
        second = hunt_model.load_model(None, self.rt)
        assert second is not None
        self.assertEqual(second.classes, ["second"])


class ScoringTests(_Tmp):
    def _model(self, **overrides: object) -> hunt_model.Ranker:
        _write(self.rt, _payload(**overrides))
        hunt_model._CACHE.clear()  # same path rewritten inside one mtime tick
        model = hunt_model.load_model(None, self.rt)
        assert model is not None
        return model

    def test_version_tag_and_eval_are_reported_verbatim(self) -> None:
        model = self._model()
        self.assertIn("2026-08-01T00:00:00+00:00", model.version_tag)
        self.assertIn("hunt-ranker", model.version_tag)
        self.assertEqual(model.evaluation["recall_at_3_model"], 0.71)
        self.assertEqual(model.evaluation["recall_at_3_rules"], 0.58)

    def test_untrained_class_scores_neutrally(self) -> None:
        model = self._model()
        self.assertEqual(model.score("never-seen", {"bias": 1.0}), 0.5)

    def test_score_is_a_probability_and_uses_the_weights(self) -> None:
        model = self._model()
        hot = model.score("sqli", {"bias": 1.0, "path:kw=search": 1.0})
        cold = model.score("sqli", {"bias": 1.0})
        self.assertGreater(hot, cold)
        self.assertTrue(0.0 < cold < hot < 1.0)

    def test_absurd_weights_saturate_instead_of_overflowing(self) -> None:
        model = self._model(ranker={"xss": {"bias": 0.0, "w": {"bias": 1e308}}})
        self.assertAlmostEqual(model.score("xss", {"bias": 1.0}), 1.0)
        model = self._model(ranker={"xss": {"bias": 0.0, "w": {"bias": -1e308}}})
        self.assertAlmostEqual(model.score("xss", {"bias": 1.0}), 0.0)

    def test_selector_scores_and_the_missing_kind_is_neutral(self) -> None:
        model = self._model()
        self.assertGreater(model.select("idor", {"shape:numeric_seg": 1.0}), 0.5)
        self.assertLess(model.select("idor", {}), 0.5)
        self.assertEqual(model.select("privileged", {}), 0.5)  # untrained kind -> no opinion

    def test_suggest_params_returns_names_only(self) -> None:
        model = self._model()
        self.assertEqual(model.suggest_params("download", "nginx PHP 8.1", 5), ["filepath", "attachment"])
        self.assertEqual(model.suggest_params("download", "PHP", 1), ["filepath"])
        self.assertEqual(model.suggest_params("download", "PHP", 0), [])
        self.assertEqual(model.suggest_params("search", "PHP", 5), [])  # no learned opinion


class PermutationTests(_Tmp):
    def _model(self, **overrides: object) -> hunt_model.Ranker:
        _write(self.rt, _payload(**overrides))
        hunt_model._CACHE.clear()  # same path rewritten inside one mtime tick
        model = hunt_model.load_model(None, self.rt)
        assert model is not None
        return model

    def test_output_is_always_a_permutation_of_candidates(self) -> None:
        model = self._model()
        cases = [
            ["xss", "sqli", "rce", "redirect", "cors"],
            ["xss", "xss", "sqli"],           # duplicates
            ["never-trained-a", "never-trained-b"],
            ["only-one"],
            [],
        ]
        for candidates in cases:
            out = model.rank_endpoint_classes(
                "https://t.example/search?q=1", ["q"], ["q", "url"], "php", list(candidates), None)
            self.assertEqual(sorted(out), sorted(candidates), candidates)
            self.assertEqual(len(out), len(candidates), candidates)

    def test_identical_inputs_give_identical_order(self) -> None:
        model = self._model()
        args = ("https://t.example/search?q=1", ["q"], ["q"], "php", ["xss", "sqli", "rce"], {"sqli": 1.5})
        self.assertEqual(model.rank_endpoint_classes(*args), model.rank_endpoint_classes(*args))

    def test_learned_weight_promotes_the_class(self) -> None:
        model = self._model()
        order = model.rank_endpoint_classes(
            "https://t.example/search?q=1", ["q"], [], "", ["xss", "sqli"], None)
        self.assertEqual(order[0], "sqli")  # path:kw=search fires the trained sqli weight

    def test_ties_keep_the_callers_order(self) -> None:
        model = self._model(ranker={})  # nothing trained -> every class scores a neutral 0.5
        candidates = ["rce", "xss", "cors", "sqli"]
        self.assertEqual(model.rank_endpoint_classes("https://t.example/x", [], [], "", candidates), candidates)

    def test_absent_prior_is_neutral_and_does_not_sink_below_a_noisy_class(self) -> None:
        # Ported from test_offline_hunt.py::test_noisy_prior_falls_below_unseen_neutral_classes.
        # learned_priors are multipliers around 1.0; a class with NO prior must keep its raw
        # score rather than being zeroed, and a class absent from the ranker must score the
        # neutral 0.5 rather than 0.0. Both together: the known-noisy 0.5-prior class loses.
        model = self._model(ranker={"xss": {"bias": 0.0, "w": {}}})
        order = model.rank_endpoint_classes(
            "https://t.example/x", [], [], "", ["xss", "sqli"], {"xss": 0.5})
        self.assertEqual(order, ["sqli", "xss"])
        self.assertLess(order.index("sqli"), order.index("xss"))

    def test_priors_are_clamped_and_corrupt_priors_degrade_to_neutral(self) -> None:
        model = self._model(ranker={})
        boosted = model.rank_endpoint_classes(
            "https://t.example/x", [], [], "", ["xss", "sqli"], {"sqli": 10_000.0})
        self.assertEqual(boosted[0], "sqli")
        for bad in ({"sqli": "lots"}, {"sqli": None}, {"sqli": float("nan")}):
            self.assertEqual(
                model.rank_endpoint_classes("https://t.example/x", [], [], "", ["xss", "sqli"], bad),
                ["xss", "sqli"], bad)

    def test_malformed_arguments_fall_back_to_the_candidate_order(self) -> None:
        model = self._model()
        candidates = ["xss", "sqli", "rce"]
        out = model.rank_endpoint_classes(None, None, None, None, list(candidates), None)  # type: ignore[arg-type]
        self.assertEqual(sorted(out), sorted(candidates))


class SigmoidTests(unittest.TestCase):
    def test_z_is_clamped_before_exp(self) -> None:
        # Unclamped, exp(-(-1e30)) raises OverflowError mid-hunt.
        self.assertTrue(math.isfinite(hunt_model._sigmoid(1e30)))
        self.assertTrue(math.isfinite(hunt_model._sigmoid(-1e30)))
        self.assertAlmostEqual(hunt_model._sigmoid(0.0), 0.5)


if __name__ == "__main__":
    unittest.main()
