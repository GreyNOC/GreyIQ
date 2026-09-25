"""Static wiring contracts for the Studio's Train panel.

The Train panel is the app's face on the local brain, and its controls had drifted badly out of step
with the backend that serves them: the button posted a hardcoded {max_iters: 160, eval_interval: 40}
while the trainer accepted a dozen more fields; the pause/resume/stop routes existed with nothing in
the app posting to them; a failed run reported nothing anywhere; and the "Model" meter read "Trained"
off an in-browser preference fit rather than any actual training run.

Every failure mode there is INVISIBLE at runtime — a control that posts nothing looks identical to one
that works — so these are static contracts over the three files that have to agree:

  * public/index.html   the control exists, and is labelled
  * public/app.js       the control is bound, and sends the field
  * greyiq_api.py       the field is declared, and the route exists

A browser is not needed. Anything that genuinely needs a rendered DOM stays in visual QA.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
BACKEND = Path(__file__).resolve().parent
HTML = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "public" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "public" / "styles.css").read_text(encoding="utf-8")
API = (BACKEND / "greyiq_api.py").read_text(encoding="utf-8")
TRAINER = (BACKEND / "training_runtime.py").read_text(encoding="utf-8")


class TrainPanelControlsExistTests(unittest.TestCase):
    def test_every_new_control_is_present_and_registered(self) -> None:
        # id -> it must exist in the markup AND be looked up in app.js's els map, or the listener
        # below it silently binds to undefined.
        for element_id in (
            "trainStatus", "trainPause", "trainStop", "trainProgress", "trainCurve",
            "trainModelSize", "trainMaxIters", "trainEvalInterval", "trainLearningRate",
            "trainBatchSize", "trainDevice", "trainDatasetCap", "trainFreshStart",
            "trainAutoStop", "trainPatience", "trainMinDelta", "trainRestoreBest",
            "trainSaveBestOnly", "trainSettingsReset", "trainDatasetRefresh",
            "huntModelSource", "huntBrainTrain", "huntBrainDryRun", "huntBrainRefresh",
        ):
            with self.subTest(element=element_id):
                self.assertIn(f'id="{element_id}"', HTML, f"#{element_id} is missing from the markup")
                self.assertIn(f'document.querySelector("#{element_id}")', JS,
                              f"#{element_id} is never looked up, so nothing can bind to it")

    def test_the_run_controls_are_bound_to_the_real_routes(self) -> None:
        for route in ("/api/train/start", "/api/train/pause", "/api/train/resume",
                      "/api/train/stop", "/api/train/dataset", "/api/hunt/model", "/api/hunt/train"):
            with self.subTest(route=route):
                self.assertIn(f'"{route}"', JS, f"{route} is not called from the app")
                self.assertIn(f'path == "{route}"', API, f"{route} has no handler")

    def test_the_primary_action_class_has_a_style(self) -> None:
        # .primary-action was applied to the panel's main CTA with no rule anywhere, so the most
        # important button in the panel rendered as an ordinary one.
        self.assertIn(".text-button.primary-action", CSS)

    def test_the_new_classes_used_by_the_panel_are_all_styled(self) -> None:
        for class_name in ("toggle-row", "train-progress", "train-curve", "is-inert"):
            with self.subTest(css_class=class_name):
                self.assertIn(f".{class_name}", CSS, f".{class_name} is used but never styled")

    def test_controls_carry_accessible_labelling(self) -> None:
        # The progress bar and the curve are the two non-text widgets; both must announce themselves.
        self.assertIn('role="progressbar"', HTML)
        self.assertIn('aria-labelledby="trainProgressLabel"', HTML)
        self.assertIn('role="img"', HTML)
        self.assertIn('aria-labelledby="trainCurveLabel"', HTML)
        # Status lines must be announced as they change, not silently replaced.
        self.assertRegex(HTML, r'id="trainStatus"[^>]*aria-live="polite"')
        self.assertRegex(HTML, r'id="trainDatasetStatus"[^>]*aria-live="polite"')
        self.assertRegex(HTML, r'id="huntBrainStatus"[^>]*aria-live="polite"')


class TrainRequestFieldsReachTheBackendTests(unittest.TestCase):
    """Every field the panel sends must be declared on TrainingRequest, and vice versa."""

    def _body_fields(self) -> set[str]:
        match = re.search(r"function trainRequestBody\(\) \{(.*?)\n\}", JS, re.S)
        self.assertIsNotNone(match, "trainRequestBody() is gone — the train button's payload moved")
        return set(re.findall(r"^\s{4}(\w+):", match.group(1), re.M))

    def _request_model_fields(self) -> set[str]:
        match = re.search(r"class TrainingRequest\(BaseModel\):(.*?)\n\nclass ", API, re.S)
        self.assertIsNotNone(match, "TrainingRequest moved")
        return set(re.findall(r"^\s{4}(\w+)\s*:", match.group(1), re.M))

    def test_no_field_is_posted_that_the_backend_does_not_declare(self) -> None:
        # A field the model does not declare is silently dropped (or 422s, depending on config), so
        # the control would appear to work and change nothing.
        unknown = self._body_fields() - self._request_model_fields()
        self.assertFalse(unknown, f"the panel posts field(s) TrainingRequest does not declare: {sorted(unknown)}")

    def test_every_operator_facing_backend_field_has_a_control(self) -> None:
        # The reverse drift: a capability implemented in the trainer, declared in the request, and
        # unreachable from the UI — which is exactly how the whole early-stopping monitor sat unused.
        missing = self._request_model_fields() - self._body_fields()
        self.assertFalse(missing, f"TrainingRequest field(s) no control drives: {sorted(missing)}")

    def test_the_hardcoded_run_parameters_are_gone(self) -> None:
        body = re.search(r"function trainRequestBody\(\) \{(.*?)\n\}", JS, re.S).group(1)
        self.assertNotIn("max_iters: 160", body, "the step count is hardcoded again")
        self.assertNotIn("eval_interval: 40", body)
        self.assertNotIn("fresh_start: false", body)
        # …and each one now comes from the persisted settings object.
        for field in ("settings.maxIters", "settings.evalInterval", "settings.freshStart"):
            self.assertIn(field, body)


class ModelStateMeterTests(unittest.TestCase):
    def test_the_meter_does_not_read_trained_from_the_in_browser_fit(self) -> None:
        # activeBot().trainedAt is set by the local preference fit on every message rating, so using
        # it made the meter claim a trained TinyGPT that had never run a step.
        # The assignment is an IIFE, so capture to its closing `})();` rather than the first `;`
        # (which lands inside the first early return).
        match = re.search(r"els\.modelState\.textContent = (\(\(\) => \{.*?\n  \}\)\(\));", JS, re.S)
        self.assertIsNotNone(match, "the model-state meter assignment moved")
        expression = match.group(1)
        self.assertNotIn("trainedAt", expression,
                         "the Model meter is reading the in-browser fit again, not the backend run")
        for signal in ("training?.active", "engine_ready"):
            self.assertIn(signal, expression, f"the meter ignores {signal}")


class HuntModelPayloadContractTests(unittest.TestCase):
    """The hunting-brain panel must read the keys the backend actually sends.

    Caught live: the panel was written against corpus.rows / corpus.total, while
    hunt_train.show_status reports labeled_rows / min_rows / rows_needed — so the "Trace rows" meter
    would have read 0 forever, and an operator would conclude they had no corpus to train on.
    """

    def _status_keys(self) -> tuple[set[str], set[str]]:
        import sys

        if str(BACKEND) not in sys.path:
            sys.path.insert(0, str(BACKEND))
        from bughunter import hunt_train

        payload = hunt_train.show_status(Path("/nonexistent-runtime"), BACKEND / "seed",
                                         hunt_train.DEFAULT_MIN_ROWS)
        corpus = payload.get("corpus") or {}
        return set(payload), set(corpus)

    def test_the_panel_reads_real_top_level_keys(self) -> None:
        top, _corpus = self._status_keys()
        # Each of these is dereferenced in renderHuntModel.
        for key in ("active_model", "source", "loaded", "version_tag", "eval", "corpus"):
            with self.subTest(key=key):
                self.assertIn(key, top, f"renderHuntModel reads {key}, which show_status no longer returns")

    def test_the_panel_reads_real_corpus_keys(self) -> None:
        _top, corpus = self._status_keys()
        for key in ("labeled_rows", "min_rows", "rows_needed", "hunts"):
            with self.subTest(key=key):
                self.assertIn(key, corpus, f"renderHuntModel reads corpus.{key}, which is not reported")
                self.assertIn(f"corpus.{key}", JS, f"corpus.{key} exists but the panel ignores it")

    def test_the_panel_does_not_read_keys_that_do_not_exist(self) -> None:
        _top, corpus = self._status_keys()
        for stale in ("corpus.rows ", "corpus.total"):
            self.assertNotIn(stale, JS, f"the panel still reads {stale.strip()}, which is not in the payload")


class TrainerSafetyContractTests(unittest.TestCase):
    """The guards that keep a click on Train from costing the operator their model."""

    def test_the_default_preset_resumes_rather_than_replacing(self) -> None:
        self.assertIn('DEFAULT_MODEL_SIZE = "compact"', TRAINER)
        self.assertIn('modelSize: "compact"', JS, "the panel's default brain size must match the trainer's")

    def test_a_superseded_architecture_is_archived_before_it_is_replaced(self) -> None:
        self.assertIn("supersedes", TRAINER)
        self.assertIn("_published_model_config", TRAINER)
        # best_model.pt is a bare state_dict, so an overwrite is unrecoverable without this.
        self.assertIn("STABLE_MODELS_DIR", TRAINER)

    def test_a_diverged_run_is_not_persisted(self) -> None:
        self.assertIn("math.isfinite", TRAINER)
        self.assertIn('stop_reason = "diverged"', TRAINER)

    def test_validation_loss_is_averaged_in_eval_mode(self) -> None:
        self.assertIn("def estimate_loss(", TRAINER)
        self.assertIn("model.eval()", TRAINER)
        # And the eval step must actually use it rather than a single sampled batch.
        self.assertIn("estimate_loss(model, val_data", TRAINER)

    def test_metadata_is_written_with_the_weights_not_before_them(self) -> None:
        self.assertIn("_publish_metadata", TRAINER)
        # save_config must not be called unconditionally ahead of training any more.
        self.assertNotIn('save_config(MODEL_CONFIG, base_dir / "solin_config.json")', TRAINER)

    def test_pause_actually_pauses_the_step_loop(self) -> None:
        self.assertIn("_wait_while_paused(should_pause, should_stop, logger)", TRAINER)
        self.assertIn("def set_training_paused", API)
        # And it refuses when nothing is running, so the UI cannot show a paused idle runtime.
        self.assertIn("No training run is active.", API)


if __name__ == "__main__":
    unittest.main()
