"""Contract tests for the Studio's training HTTP surface.

This file exists because the training surface had ZERO coverage, and two real drifts survived a full
`npm run check:python` run because of it:

  * ``greyiq_api`` mirrors ``training_runtime``'s constants so request models can validate without
    paying the torch import cost at boot. The mirror of ``MAX_TRAINING_CHARS`` went stale, so every
    Studio run silently capped the corpus at half what the trainer was configured for.
  * ``TrainingSettings`` grew ``validation`` (the whole early-stopping monitor) and
    ``batch_size_override``, and ``start_training`` never passed either — implemented, documented,
    and unreachable from the app.

Both are the same class of bug: a field that exists on one side of the boundary and not the other.
The tests below assert the boundary itself rather than any one field, so the next one fails here.

Torch is NOT required: TrainingSettings is captured with a stub, so these run in CI and on a machine
with no ML runtime installed.
"""
from __future__ import annotations

import json
import sys
import unittest
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import greyiq_api as api  # noqa: E402


# --- stand-ins for the torch-backed dataclasses, with the same field names/defaults -------------
@dataclass
class _StubValidation:
    patience: int = 3
    min_delta: float = 0.0001
    auto_stop: bool = True
    save_best_only: bool = True
    restore_best: bool = True


@dataclass
class _StubSettings:
    pdf_folder: Any = None
    method: str = "auto"
    continuous: bool = False
    trigger_mode: str = "changes"
    idle_sleep_seconds: float = 5.0
    post_cycle_sleep_seconds: float = 1.0
    max_iters: int = 1000
    eval_interval: int = 100
    learning_rate: float = 3e-4
    skip_pdf_ingest: bool = False
    max_cycles: int = 0
    device_preference: str = "auto"
    batch_size_override: int = 0
    dataset_char_cap: int = 8_000_000
    source_ids: list[str] = field(default_factory=list)
    fresh_start: bool = False
    model_size: str = "compact"
    validation: Any = field(default_factory=_StubValidation)


class TrainingRequestReachesSettingsTests(unittest.TestCase):
    """Every operator-facing TrainingRequest field must land in the TrainingSettings the trainer gets."""

    def setUp(self) -> None:
        self._saved = (api.TrainingSettings, api.ValidationMonitorSettings, api.run_training_loop,
                       api._ML_RUNTIME_AVAILABLE, api.MODEL_PRESETS)
        self.captured: dict[str, Any] = {}

        def _capture(**kwargs: Any) -> _StubSettings:
            self.captured.update(kwargs)
            return _StubSettings(**kwargs)

        api.TrainingSettings = _capture           # type: ignore[assignment]
        api.ValidationMonitorSettings = _StubValidation  # type: ignore[assignment]
        api.run_training_loop = lambda *a, **k: None      # type: ignore[assignment]
        api._ML_RUNTIME_AVAILABLE = True
        api.MODEL_PRESETS = {"compact": {}, "standard": {}, "large": {}}  # type: ignore[assignment]

    def tearDown(self) -> None:
        (api.TrainingSettings, api.ValidationMonitorSettings, api.run_training_loop,
         api._ML_RUNTIME_AVAILABLE, api.MODEL_PRESETS) = self._saved

    def _start(self, **overrides: Any) -> dict[str, Any]:
        runtime = object.__new__(api.GreyIQRuntime)
        import threading

        runtime.lock = threading.RLock()
        runtime.training = api.TrainingState()
        runtime.log = lambda *a, **k: None
        runtime.reload_engine = lambda *a, **k: None
        api.GreyIQRuntime.start_training(runtime, api.TrainingRequest(**overrides))
        return runtime.training.settings

    def test_the_validation_monitor_is_actually_passed(self) -> None:
        self._start(patience=7, min_delta=0.01, auto_stop=False, save_best_only=False, restore_best=False)
        monitor = self.captured.get("validation")
        self.assertIsNotNone(monitor, "start_training did not pass validation= at all")
        self.assertEqual(monitor.patience, 7)
        self.assertEqual(monitor.min_delta, 0.01)
        self.assertFalse(monitor.auto_stop)
        self.assertFalse(monitor.save_best_only)
        self.assertFalse(monitor.restore_best)

    def test_batch_size_override_and_model_size_are_passed(self) -> None:
        self._start(batch_size_override=12, model_size="standard")
        self.assertEqual(self.captured.get("batch_size_override"), 12)
        self.assertEqual(self.captured.get("model_size"), "standard")

    def test_an_unknown_model_size_falls_back_instead_of_failing_the_run(self) -> None:
        self._start(model_size="enormous")
        self.assertEqual(self.captured.get("model_size"), "compact")

    def test_every_request_field_reaches_the_settings_or_is_deliberately_local(self) -> None:
        # The boundary assertion: a new TrainingRequest field must be threaded through (or explicitly
        # listed here as one the API resolves itself), so "added the field, forgot the wiring" fails.
        self._start()
        resolved_locally = {
            # normalize_* helpers rename these on the way through.
            "device_preference", "source_ids", "model_size",
            # folded into the validation monitor object rather than passed as flat kwargs
            "patience", "min_delta", "auto_stop", "save_best_only", "restore_best",
        }
        request_fields = set(api.TrainingRequest.model_fields)
        for name in sorted(request_fields - resolved_locally):
            with self.subTest(field=name):
                self.assertIn(name, self.captured,
                              f"TrainingRequest.{name} never reaches TrainingSettings — wire it in "
                              f"start_training or add it to resolved_locally with a reason")
        # And the renamed ones must still arrive under their settings names.
        for name in ("device_preference", "source_ids", "model_size"):
            self.assertIn(name, self.captured)

    def test_the_settings_echo_lets_the_panel_show_what_is_running(self) -> None:
        echo = self._start(model_size="large", patience=9, max_iters=321)
        self.assertEqual(echo["model_size"], "large")
        self.assertEqual(echo["patience"], 9)
        self.assertEqual(echo["max_iters"], 321)

    def test_a_fresh_run_resets_the_loss_history(self) -> None:
        runtime = object.__new__(api.GreyIQRuntime)
        import threading

        runtime.lock = threading.RLock()
        runtime.training = api.TrainingState(history=[{"step": 1, "val_loss": 9.9}])
        runtime.log = lambda *a, **k: None
        runtime.reload_engine = lambda *a, **k: None
        api.GreyIQRuntime.start_training(runtime, api.TrainingRequest())
        self.assertEqual(runtime.training.history, [], "a new run must not inherit the old curve")


class MirroredConstantsTests(unittest.TestCase):
    """greyiq_api's boot-time mirror of training_runtime's defaults must not drift."""

    def test_the_mirror_matches_the_trainer(self) -> None:
        source = (BACKEND_DIR / "training_runtime.py").read_text(encoding="utf-8")
        # Read the literals out of the source rather than importing (training_runtime needs torch).
        import re

        def literal(name: str) -> str:
            match = re.search(rf"^{name} = ([0-9_.e-]+)", source, re.M)
            self.assertIsNotNone(match, f"{name} not found in training_runtime.py")
            return match.group(1).replace("_", "")

        self.assertEqual(float(literal("MAX_TRAINING_CHARS")), float(api.MAX_TRAINING_CHARS))
        self.assertEqual(float(literal("DEFAULT_MAX_ITERS")), float(api.DEFAULT_MAX_ITERS))
        self.assertEqual(float(literal("DEFAULT_EVAL_INTERVAL")), float(api.DEFAULT_EVAL_INTERVAL))
        self.assertEqual(float(literal("DEFAULT_LEARNING_RATE")), float(api.DEFAULT_LEARNING_RATE))

    def test_the_dataset_cap_cannot_be_unbounded_or_exceed_the_ram_ceiling(self) -> None:
        field_info = api.TrainingRequest.model_fields["dataset_char_cap"]
        bounds = {type(m).__name__: getattr(m, "ge", getattr(m, "le", None)) for m in field_info.metadata}
        # 0 used to mean "read everything", which OOM-kills the backend on a large corpus.
        with self.assertRaises(Exception):
            api.TrainingRequest(dataset_char_cap=0)
        with self.assertRaises(Exception):
            api.TrainingRequest(dataset_char_cap=api.MAX_TRAINING_CHARS + 1)
        self.assertTrue(bounds)  # the field really is bounded, not just coincidentally rejecting

    def test_the_learning_rate_ceiling_rejects_a_certainly_diverging_value(self) -> None:
        api.TrainingRequest(learning_rate=1e-3)          # ordinary
        with self.assertRaises(Exception):
            api.TrainingRequest(learning_rate=0.9)        # diverges to NaN within a few steps


class SeedConfigMatchesShippedCheckpointTests(unittest.TestCase):
    """The shipped seed config must describe the shipped seed weights.

    seed/best_model.pt is a bare state_dict, so solin_core rebuilds it from seed/solin_config.json. If
    the two ever disagree, a fresh install cannot load the model it ships with and every first-run chat
    silently degrades to the fallback path — which is exactly why the 'compact' preset (and not the
    larger default) has to match this file.
    """

    def test_the_seed_config_is_the_compact_preset(self) -> None:
        import re

        seed = json.loads((BACKEND_DIR / "seed" / "solin_config.json").read_text(encoding="utf-8"))
        source = (BACKEND_DIR / "training_runtime.py").read_text(encoding="utf-8")
        match = re.search(r'"compact":\s*\{([^}]*)\}', source)
        self.assertIsNotNone(match, "the compact preset is gone from training_runtime.MODEL_PRESETS")
        compact = dict(re.findall(r'"(\w+)":\s*([0-9.]+)', match.group(1)))
        for key in ("block_size", "n_embd", "n_head", "n_layer"):
            self.assertIn(key, compact)
            self.assertEqual(float(seed[key]), float(compact[key]),
                             f"seed/solin_config.json {key} does not match the compact preset — a fresh "
                             f"install would be unable to load seed/best_model.pt")

    def test_the_default_model_size_is_the_one_the_seed_weights_match(self) -> None:
        source = (BACKEND_DIR / "training_runtime.py").read_text(encoding="utf-8")
        self.assertIn('DEFAULT_MODEL_SIZE = "compact"', source,
                      "the default preset must stay the shipped checkpoint's shape, or a single "
                      "'Train the local model' click replaces a trained brain with a few-step one")


if __name__ == "__main__":
    unittest.main()
