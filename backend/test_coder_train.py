"""``gn train-coder`` — training the coding brain on your own folders, from a terminal.

GreyIQ has two trainable brains. ``gn train-brain`` has always trained the HUNT ranker from hunt
traces; the coding brain (the TinyGPT behind chat and the offline coder) could only be trained by
clicking a button in the desktop Studio. On the headless CLI tarball — which is precisely where an
operator runs a long job — the corpus could not be extended and the model could not be trained at all.

The properties worth pinning are the ones that make it safe on the machines it will actually run on:

  * ``--show`` and ``--dry-run`` work with **no torch**, because the whole CLI is torch-free by design.
  * Plain text and Markdown ingest with **no pypdf**, because ``document_ingest`` imports it at module
    scope and a folder of notes must not need a PDF library.
  * A ``--size`` that cannot resume the existing checkpoint **refuses** without ``--yes``.
  * ``--json`` stdout stays one parseable document.
  * Registration stays import-light: it runs on every ``import gn_cli``, including the frozen
    backend's API-server start.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder_train  # noqa: E402
import gn_cli  # noqa: E402


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = gn_cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _args(**overrides: object) -> argparse.Namespace:
    """A Namespace with every default the parser would supply, so a test overrides only its subject."""
    base = gn_cli.build_parser().parse_args(["train-coder"])
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


class RegistrationTests(unittest.TestCase):
    def test_the_verb_is_registered_and_dispatchable(self) -> None:
        self.assertIn("train-coder", gn_cli.CLI_COMMANDS)
        parsed = gn_cli.build_parser().parse_args(["train-coder", "--show"])
        self.assertIs(parsed.func, coder_train._cmd_train_coder)
        self.assertTrue(parsed.show)

    def test_registration_imports_neither_torch_nor_the_document_extractor(self) -> None:
        # register_cli runs on EVERY `import gn_cli`, including the frozen backend's API-server start,
        # so a heavy import here is a startup-latency regression for every invocation of anything.
        code = (
            "import sys; import gn_cli; gn_cli.build_parser();"
            "print('torch', 'torch' in sys.modules);"
            "print('pypdf', 'pypdf' in sys.modules);"
            "print('training_runtime', 'training_runtime' in sys.modules);"
            "print('document_ingest', 'document_ingest' in sys.modules)"
        )
        proc = subprocess.run([sys.executable, "-B", "-c", code], cwd=str(BACKEND_DIR),
                              capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for module in ("torch", "pypdf", "training_runtime", "document_ingest"):
            with self.subTest(module=module):
                self.assertIn(f"{module} False", proc.stdout,
                              f"{module} is imported just by building the CLI parser")

    def test_the_frozen_spec_picks_the_plugin_up_without_being_edited(self) -> None:
        # The PyInstaller spec derives the plugin list from gn_cli._VERB_PLUGINS by AST, so a new
        # plugin must be force-included automatically. If that ever stops being true, the verb works
        # in a dev checkout and vanishes from the shipped binary.
        self.assertIn("coder_train", gn_cli._VERB_PLUGINS)
        spec = (BACKEND_DIR.parent / "build" / "greyiq-backend.spec").read_text(encoding="utf-8")
        self.assertIn("_verb_plugin_modules", spec)
        self.assertIn("gn_cli.py", spec, "the spec no longer derives the plugin list from gn_cli")


class WorksWithoutTorchTests(unittest.TestCase):
    """The inspect-and-plan paths must answer on a machine that can never train."""

    def test_show_reports_the_corpus_the_model_and_the_presets(self) -> None:
        with TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "rt"
            (runtime / "data").mkdir(parents=True)
            (runtime / "data" / "notes.txt").write_text("x" * 4096, encoding="utf-8")
            code, out, err = self._show(runtime)
        self.assertEqual(code, 0, err)
        self.assertIn("corpus:", out)
        self.assertIn("notes.txt", out)
        self.assertIn("brain sizes:", out)
        for size in ("compact", "standard", "large"):
            self.assertIn(size, out)
        self.assertIn("default, resumes the shipped checkpoint", out)

    def test_show_says_so_when_the_corpus_is_empty_and_how_to_fill_it(self) -> None:
        with TemporaryDirectory() as tmp:
            code, out, _err = self._show(Path(tmp) / "rt")
        self.assertEqual(code, 0)
        self.assertIn("empty", out)
        self.assertIn("gn train-coder", out, "it does not say how to add a corpus")

    def test_show_json_is_one_document(self) -> None:
        with TemporaryDirectory() as tmp:
            args = _args(show=True, json=True)
            code, out, err = self._call(Path(tmp) / "rt", args)
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertIn("presets", payload)
        self.assertIn("compact", payload["presets"])
        self.assertIn("extracted_characters", payload)

    def test_the_presets_are_read_from_the_trainer_without_importing_it(self) -> None:
        # Parsed from training_runtime.py's source by AST: duplicating them here would let the CLI
        # advertise an architecture the trainer does not have.
        presets, default = coder_train._presets()
        self.assertEqual(default, "compact")
        self.assertEqual(set(presets), {"compact", "standard", "large"})
        for name, config in presets.items():
            with self.subTest(size=name):
                for key in ("block_size", "n_embd", "n_head", "n_layer"):
                    self.assertIn(key, config)
        # And they must match the trainer's real table, read the same way the gate reads it.
        source = (BACKEND_DIR / "training_runtime.py").read_text(encoding="utf-8")
        self.assertIn('"compact": {"block_size": 64', source,
                      "the compact preset changed shape; --show would now advertise the wrong one")

    def test_training_without_torch_refuses_with_an_install_hint(self) -> None:
        if coder_train._torch_available():
            self.skipTest("torch is installed here, so the refusal path cannot be exercised")
        with TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "rt"
            (runtime / "data").mkdir(parents=True)
            (runtime / "data" / "c.txt").write_text("y" * 2048, encoding="utf-8")
            code, _out, err = self._call(runtime, _args())
        self.assertEqual(code, 2)
        self.assertIn("torch", err.lower())
        self.assertIn("pip install torch", err)
        self.assertIn("--show", err, "it does not say which paths still work")

    # --- helpers ---------------------------------------------------------------------------------
    def _call(self, runtime: Path, args: argparse.Namespace) -> tuple[int, str, str]:
        original = coder_train._resolve_dirs
        coder_train._resolve_dirs = lambda: (runtime, BACKEND_DIR / "seed")
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = coder_train._cmd_train_coder(args)
        finally:
            coder_train._resolve_dirs = original
        return code, out.getvalue(), err.getvalue()

    def _show(self, runtime: Path) -> tuple[int, str, str]:
        return self._call(runtime, _args(show=True))


class DirectoryIngestionTests(unittest.TestCase):
    """The feature the Studio never had: arbitrary folders as the training corpus."""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.runtime = self.root / "rt"
        self.source = self.root / "docs"
        (self.source / "nested").mkdir(parents=True)
        (self.source / "notes.md").write_text("CRLF injection is CWE-113.\n", encoding="utf-8")
        (self.source / "nested" / "traversal.txt").write_text("Path traversal reads files.\n", encoding="utf-8")
        (self.source / "code.py").write_text("def probe():\n    return 1\n", encoding="utf-8")
        (self.source / "ignore.bin").write_bytes(b"\x00\x01binary")
        self._emitted: list[str] = []

    def _ingest(self, **kwargs: object) -> dict:
        return coder_train._ingest([str(self.source)], self.runtime, recursive=True,
                                  emit=self._emitted.append, **kwargs)

    def test_text_and_markdown_ingest_with_no_pdf_library(self) -> None:
        # document_ingest imports pypdf at MODULE scope, so routing plain text through it made a
        # folder of notes fail with "No module named 'pypdf'" on a minimal install.
        summary = self._ingest()
        self.assertEqual(summary["ingested"], 3, summary)
        self.assertEqual(summary["failed"], 0, summary)
        self.assertIsNone(summary["extractor_available"],
                          "the document extractor was reached although no document needed it")
        written = sorted((self.runtime / "data").glob("*.txt"))
        self.assertEqual(len(written), 1, "one chunk per source directory")
        body = written[0].read_text(encoding="utf-8")
        for expected in ("CRLF injection is CWE-113.", "Path traversal reads files.", "def probe():"):
            self.assertIn(expected, body)
        self.assertNotIn("binary", body, "an unsupported file was ingested")

    def test_each_passage_is_labelled_with_where_it_came_from(self) -> None:
        # So the model sees provenance and a human can grep the corpus back to a file.
        self._ingest()
        body = next(iter((self.runtime / "data").glob("*.txt"))).read_text(encoding="utf-8")
        self.assertIn("# notes.md", body)
        self.assertIn("# nested/traversal.txt", body)

    def test_re_running_replaces_its_own_chunk_rather_than_duplicating(self) -> None:
        self._ingest()
        first = next(iter((self.runtime / "data").glob("*.txt")))
        before = first.read_text(encoding="utf-8")
        self._ingest()
        files = sorted((self.runtime / "data").glob("*.txt"))
        self.assertEqual(len(files), 1, f"a second run created another chunk: {files}")
        self.assertEqual(files[0].read_text(encoding="utf-8"), before)

    def test_two_directories_get_two_chunks_with_stable_names(self) -> None:
        other = self.root / "rfcs"
        other.mkdir()
        (other / "rfc.txt").write_text("HTTP/1.1 defines Transfer-Encoding.\n", encoding="utf-8")
        coder_train._ingest([str(self.source), str(other)], self.runtime, recursive=True,
                            emit=self._emitted.append)
        names = sorted(p.name for p in (self.runtime / "data").glob("*.txt"))
        expected = sorted([f"gn_corpus_{coder_train._slug(self.source)}.txt",
                           f"gn_corpus_{coder_train._slug(other)}.txt"])
        self.assertEqual(len(expected), 2, "two directories must hash to two distinct names")
        self.assertEqual(names, expected)

    def test_no_recursive_stops_at_the_top_level(self) -> None:
        coder_train._ingest([str(self.source)], self.runtime, recursive=False,
                            emit=self._emitted.append)
        body = next(iter((self.runtime / "data").glob("*.txt"))).read_text(encoding="utf-8")
        self.assertIn("CRLF injection", body)
        self.assertNotIn("Path traversal", body, "it descended despite --no-recursive")

    def test_a_document_that_needs_the_extractor_is_reported_not_fatal(self) -> None:
        (self.source / "paper.pdf").write_bytes(b"%PDF-1.4 not really\n")
        summary = self._ingest()
        # Either the extractor is installed and tries, or it is not and the files are skipped with a
        # reason — but the three text files land in both worlds, which is the contract.
        body = next(iter((self.runtime / "data").glob("gn_corpus_*.txt"))).read_text(encoding="utf-8")
        self.assertIn("CRLF injection is CWE-113.", body)
        entry = summary["directories"][0]
        if summary["extractor_available"] is False:
            self.assertIn("documents_reason", entry)
            self.assertIn("pip install", entry["documents_reason"])
            self.assertEqual(entry["documents_skipped"], 1)

    def test_a_missing_directory_is_reported_and_does_not_lose_the_others(self) -> None:
        summary = coder_train._ingest([str(self.root / "nope"), str(self.source)], self.runtime,
                                      recursive=True, emit=self._emitted.append)
        self.assertEqual(summary["failed"], 1, summary)
        self.assertEqual(summary["ingested"], 3, "the good directory was lost with the bad one")
        self.assertEqual(summary["directories"][0]["error"], "not a directory")

    def test_a_file_in_a_foreign_encoding_does_not_lose_the_folder(self) -> None:
        (self.source / "cp1252.md").write_bytes(b"caf\xe9 latte and a \x93quote\x94\n")
        summary = self._ingest()
        self.assertEqual(summary["failed"], 0, summary)
        body = next(iter((self.runtime / "data").glob("*.txt"))).read_text(encoding="utf-8")
        self.assertIn("caf", body)
        self.assertIn("CRLF injection is CWE-113.", body, "the whole folder was lost to one file")

    def test_an_empty_file_is_skipped_not_counted_as_ingested(self) -> None:
        (self.source / "blank.md").write_text("   \n", encoding="utf-8")
        summary = self._ingest()
        self.assertEqual(summary["ingested"], 3)
        self.assertGreaterEqual(summary["skipped"], 1)

    def test_the_text_extension_set_matches_the_extractors_own(self) -> None:
        # Two lists of extensions would drift, and the drift is silent: a file type document_ingest
        # calls text would be routed to the extractor and need pypdf for nothing.
        import ast

        source = (BACKEND_DIR / "document_ingest.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        found: dict[str, set[str]] = {}
        for node in tree.body:
            targets = getattr(node, "targets", None) or []
            for target in targets:
                if isinstance(target, ast.Name) and target.id in {
                        "TEXT_EXTENSIONS", "PDF_EXTENSIONS", "DOCX_EXTENSIONS", "IMAGE_EXTENSIONS"}:
                    found[target.id] = set(ast.literal_eval(node.value))
        self.assertEqual(found.get("TEXT_EXTENSIONS"), set(coder_train.TEXT_EXTENSIONS),
                         "the no-dependency text list drifted from document_ingest's")
        binary = (found.get("PDF_EXTENSIONS", set()) | found.get("DOCX_EXTENSIONS", set())
                  | found.get("IMAGE_EXTENSIONS", set()))
        self.assertEqual(binary, set(coder_train.BINARY_EXTENSIONS),
                         "the extractor-required list drifted from document_ingest's")


class LineageSafetyTests(unittest.TestCase):
    """A click must not be able to trade a trained model for an untrained one."""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.runtime = Path(self._tmp.name) / "rt"
        (self.runtime / "data").mkdir(parents=True)
        (self.runtime / "data" / "c.txt").write_text("z" * 4096, encoding="utf-8")
        (self.runtime / "best_model.pt").write_bytes(b"not-a-real-checkpoint")
        (self.runtime / "solin_config.json").write_text(
            json.dumps({"block_size": 64, "n_embd": 128, "n_head": 4, "n_layer": 4}), encoding="utf-8")

    def _call(self, args: argparse.Namespace) -> tuple[int, str, str]:
        original = coder_train._resolve_dirs
        coder_train._resolve_dirs = lambda: (self.runtime, BACKEND_DIR / "seed")
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = coder_train._cmd_train_coder(args)
        finally:
            coder_train._resolve_dirs = original
        return code, out.getvalue(), err.getvalue()

    def test_a_size_change_refuses_without_yes_and_says_why(self) -> None:
        code, _out, err = self._call(_args(size="large"))
        self.assertEqual(code, 2)
        self.assertIn("NEW lineage", err)
        self.assertIn("--yes", err)
        self.assertIn("--size compact", err, "it does not name the safe alternative")
        self.assertIn("archived", err, "it does not say the old model is kept")

    def test_the_same_size_resumes_with_no_warning(self) -> None:
        code, _out, err = self._call(_args(size="compact"))
        # It proceeds past the lineage gate; the only stop left here is torch's absence.
        self.assertNotIn("NEW lineage", err)
        if not coder_train._torch_available():
            self.assertEqual(code, 2)
            self.assertIn("torch", err.lower())

    def test_yes_clears_the_lineage_gate(self) -> None:
        _code, _out, err = self._call(_args(size="large", yes=True))
        self.assertNotIn("NEW lineage", err)

    def test_dry_run_reports_a_lineage_change_without_needing_yes(self) -> None:
        code, out, err = self._call(_args(size="large", dry_run=True))
        self.assertEqual(code, 0, err)
        self.assertIn("NEW LINEAGE", out)
        self.assertIn("dry run", out)

    def test_dry_run_reports_resuming_when_the_shape_matches(self) -> None:
        code, out, _err = self._call(_args(size="compact", dry_run=True))
        self.assertEqual(code, 0)
        self.assertIn("resuming the existing checkpoint", out)

    def test_an_unknown_size_is_refused_with_the_valid_ones_named(self) -> None:
        code, _out, err = self._call(_args(size="enormous"))
        self.assertEqual(code, 2)
        self.assertIn("compact", err)
        self.assertIn("standard", err)

    def test_a_missing_published_config_is_not_treated_as_a_lineage_change(self) -> None:
        # Nothing to resume means nothing to warn about.
        (self.runtime / "solin_config.json").unlink()
        _code, _out, err = self._call(_args(size="large"))
        self.assertNotIn("NEW lineage", err)


class EmptyCorpusTests(unittest.TestCase):
    def test_training_an_empty_corpus_says_how_to_fill_it(self) -> None:
        with TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "rt"
            original = coder_train._resolve_dirs
            coder_train._resolve_dirs = lambda: (runtime, BACKEND_DIR / "seed")
            err = io.StringIO()
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    code = coder_train._cmd_train_coder(_args())
            finally:
                coder_train._resolve_dirs = original
        self.assertEqual(code, 2)
        self.assertIn("empty", err.getvalue())
        self.assertIn("gn train-coder", err.getvalue())


class HuntBrainKnobsTests(unittest.TestCase):
    """``gn train-brain``'s own parameters were unreachable: train() took five, the CLI passed none."""

    def test_every_parameter_train_accepts_has_a_flag(self) -> None:
        import inspect

        from bughunter import hunt_train

        signature = inspect.signature(hunt_train.train)
        parsed = gn_cli.build_parser().parse_args(["train-brain"])
        # dry_run/min_rows/seed_dir/now are handled separately; these five are the fit itself.
        for name in ("epochs", "lr", "l2", "holdout"):
            with self.subTest(parameter=name):
                self.assertIn(name, signature.parameters)
                self.assertTrue(hasattr(parsed, name), f"--{name.replace('_', '-')} is not a flag")
                self.assertEqual(getattr(parsed, name), signature.parameters[name].default,
                                 f"the CLI default for {name} disagrees with train()'s")
        self.assertEqual(parsed.rng_seed, signature.parameters["rng_seed"].default)

    def test_the_flags_reach_train(self) -> None:
        from bughunter import hunt_train

        captured: dict = {}
        original = hunt_train.train
        hunt_train.train = lambda runtime_dir, **kwargs: captured.update(kwargs) or {
            "ok": False, "reason": "stub", "written": False, "path": "", "traces": 0, "rows": 0,
            "programs": 0, "confirmed": 0, "paid": 0, "held_out_rows": 0, "train_rows": 0,
            "held_out_programs": 0, "recall_at_3_model": None, "recall_at_3_rules": None,
            "scored_endpoints": 0,
        }
        self.addCleanup(lambda: setattr(hunt_train, "train", original))
        args = gn_cli.build_parser().parse_args(
            ["train-brain", "--holdout", "0.3", "--epochs", "80", "--lr", "0.05",
             "--l2", "1e-3", "--seed", "7", "--min-rows", "50"])
        with contextlib.redirect_stdout(io.StringIO()):
            hunt_train._cmd_train_brain(args)
        self.assertEqual(captured["holdout"], 0.3)
        self.assertEqual(captured["epochs"], 80)
        self.assertEqual(captured["lr"], 0.05)
        self.assertEqual(captured["l2"], 1e-3)
        self.assertEqual(captured["rng_seed"], 7)
        self.assertEqual(captured["min_rows"], 50)

    def test_a_holdout_of_zero_is_refused_because_it_disables_the_gate(self) -> None:
        from bughunter import hunt_train

        for bad in ("0", "1", "1.5", "-0.2"):
            with self.subTest(holdout=bad):
                args = gn_cli.build_parser().parse_args(["train-brain", "--holdout", bad])
                err = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    code = hunt_train._cmd_train_brain(args)
                self.assertEqual(code, 1)
                message = err.getvalue()
                self.assertIn("refused", message)
                # Not just "invalid": it must say what the holdout is FOR, because an operator who
                # reaches for --holdout 0 is trying to make the gate pass, and the answer is that
                # doing so would promote a model scored on its own training data.
                self.assertIn("own training data", message)

    def test_the_default_invocation_is_unchanged(self) -> None:
        # Adding flags must not have moved the behaviour of a bare `gn train-brain`.
        parsed = gn_cli.build_parser().parse_args(["train-brain"])
        self.assertEqual((parsed.holdout, parsed.epochs, parsed.lr, parsed.l2, parsed.rng_seed),
                         (0.2, 40, 0.1, 1e-4, 1337))


class JsonPurityTests(unittest.TestCase):
    def test_a_real_subprocess_show_json_is_exactly_one_document(self) -> None:
        with TemporaryDirectory() as tmp:
            import os

            env = dict(os.environ, GREYIQ_RUNTIME_DIR=str(Path(tmp) / "rt"))
            proc = subprocess.run(
                [sys.executable, "-B", "gn_cli.py", "train-coder", "--show", "--json"],
                cwd=str(BACKEND_DIR), capture_output=True, text=True, timeout=180, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertIn("presets", payload)
        self.assertNotIn("\033", proc.stdout, "an escape sequence reached a redirected stdout")


if __name__ == "__main__":
    unittest.main()
