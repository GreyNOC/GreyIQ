"""Tests for the deterministic offline code provider (offline-coder strategy, moves 1-3).

The registry tests below are the guard on the thing that makes the planner safe: a recipe fires ONLY
when the repo surface says it should, and never when the verify gate that would catch a bad template
is unavailable. Every generated Python template is compile()-checked here rather than trusted, so a
broken .tmpl fails in CI instead of landing in a user's repo.
"""
from __future__ import annotations

import configparser
import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402
import greyiq_api  # noqa: E402
import offline_coder  # noqa: E402

_SEED = BACKEND_DIR / "seed"


def _repo(td: str, files: dict[str, str]) -> str:
    """Materialize a fixture repo. Retrieval reads real files, so a fixture must be real files."""
    for name, body in files.items():
        path = Path(td) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return td


_PKG_EXPRESS = json.dumps({"name": "api", "dependencies": {"express": "^4.19.0"},
                           "scripts": {"test": "node --test"}})
_FASTAPI_REQS = "fastapi==0.115.0\nuvicorn==0.34.0\n"
_PYTEST_REQS = "pytest==8.3.0\n"


class PlanEditsTests(unittest.TestCase):
    def test_add_test_scaffolds_a_valid_python_stub(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            plan = offline_coder.plan_edits("add a unit test for parse_config", td)
            self.assertFalse(plan["needs_brain"])
            self.assertEqual(len(plan["ops"]), 1)
            op = plan["ops"][0]
            self.assertEqual(op["kind"], "new_file")
            self.assertEqual(op["path"], "test_parse_config.py")
            # The scaffold must be valid Python (verify would compile it).
            compile(op["content"], op["path"], "exec")
            self.assertIn("class TestParseConfig", op["content"])

    def test_create_file_with_body(self) -> None:
        plan = offline_coder.plan_edits("create a file notes/todo.md with remember the milk", ".")
        self.assertFalse(plan["needs_brain"])
        self.assertEqual(plan["ops"][0]["path"], "notes/todo.md")
        self.assertIn("remember the milk", plan["ops"][0]["content"])

    def test_path_traversal_is_refused(self) -> None:
        plan = offline_coder.plan_edits("create a file ../../etc/passwd with x", ".")
        # The traversal path is rejected -> no op -> defers to a brain rather than escaping the workspace.
        self.assertTrue(plan["needs_brain"])
        self.assertEqual(plan["ops"], [])

    def test_novel_logic_defers_to_a_brain(self) -> None:
        plan = offline_coder.plan_edits("implement an LRU cache with TTL eviction and metrics", ".")
        self.assertTrue(plan["needs_brain"])
        self.assertEqual(plan["ops"], [])
        self.assertIn("configured brain", plan["summary"])

    def test_c2_traffic_request_maps_to_bounded_http_client(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            plan = offline_coder.plan_edits(
                "build a C2 traffic simulator script with a user agent and CA cert",
                td,
            )
        self.assertFalse(plan["needs_brain"])
        op = plan["ops"][0]
        self.assertEqual(op["path"], "authorized_http_client.py")
        compile(op["content"], op["path"], "exec")
        self.assertIn("--user-agent", op["content"])
        self.assertIn("--ca-cert", op["content"])
        self.assertIn("--client-cert", op["content"])
        self.assertIn("--count", op["content"])
        self.assertNotIn("CERT_NONE", op["content"])
        self.assertNotIn("subprocess", op["content"])
        self.assertIn("never executes remote commands", plan["summary"])

    def test_http_client_honors_safe_requested_filename(self) -> None:
        plan = offline_coder.plan_edits(
            "create an HTTP traffic sender named tools/lab_sender.py",
            ".",
        )
        self.assertFalse(plan["needs_brain"])
        self.assertEqual(plan["ops"][0]["path"], "tools/lab_sender.py")

    def test_generated_http_client_dry_run_is_reproducible(self) -> None:
        plan = offline_coder.plan_edits("write an HTTP client script to send traffic", ".")
        namespace: dict[str, object] = {"__name__": "generated_client"}
        exec(compile(plan["ops"][0]["content"], "generated_client.py", "exec"), namespace)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = namespace["main"](  # type: ignore[operator]
                [
                    "--url", "https://lab.example.test/checkin",
                    "--method", "POST",
                    "--data", '{"status":"ok"}',
                    "--user-agent", "Authorized-Test/7",
                    "--count", "2",
                    "--dry-run",
                ]
            )
        rendered = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(rendered["headers"]["User-Agent"], "Authorized-Test/7")
        self.assertEqual(rendered["count"], 2)
        self.assertEqual(rendered["method"], "POST")
        self.assertEqual(rendered["body_bytes"], len('{"status":"ok"}'))

    def test_generated_http_client_rejects_oversize_file_before_opening_it(self) -> None:
        plan = offline_coder.plan_edits("write an HTTP client script to send traffic", ".")
        namespace: dict[str, object] = {"__name__": "generated_client"}
        exec(compile(plan["ops"][0]["content"], "generated_client.py", "exec"), namespace)
        opened: list[bool] = []
        maximum = namespace["MAX_REQUEST_BYTES"]

        class OversizePath:
            def __init__(self, value: str) -> None:
                self.value = value

            def stat(self):
                return mock.Mock(st_size=maximum + 1)

            def open(self, mode: str):
                opened.append(True)
                raise AssertionError("oversize body file must not be opened")

        namespace["Path"] = OversizePath
        args = mock.Mock(data=None, data_file="oversize.bin")
        with self.assertRaisesRegex(ValueError, "request body exceeds"):
            namespace["read_body"](args)  # type: ignore[operator]
        self.assertEqual(opened, [])

    def test_generated_http_client_sends_attributed_traffic(self) -> None:
        seen: dict[str, object] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
                length = int(self.headers.get("Content-Length", "0"))
                seen["user_agent"] = self.headers.get("User-Agent")
                seen["body"] = self.rfile.read(length)
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"accepted":true}')

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        plan = offline_coder.plan_edits("create a network traffic client script", ".")
        namespace: dict[str, object] = {"__name__": "generated_client"}
        exec(compile(plan["ops"][0]["content"], "generated_client.py", "exec"), namespace)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                exit_code = namespace["main"](  # type: ignore[operator]
                    [
                        "--url", f"http://127.0.0.1:{server.server_port}/checkin",
                        "--method", "POST",
                        "--data", "hello lab",
                        "--user-agent", "Authorized-Lab/1",
                        "--expect-status", "201",
                    ]
                )
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

        rendered = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(rendered["ok"])
        self.assertEqual(rendered["status"], 201)
        self.assertEqual(seen["user_agent"], "Authorized-Lab/1")
        self.assertEqual(seen["body"], b"hello lab")


class RunOfflineIntegrationTests(unittest.TestCase):
    """The no-brain agent path now runs the deterministic offline coder instead of dead-ending."""

    def test_no_brain_run_scaffolds_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            with mock.patch.object(agent, "plan_task", return_value=[]):
                result = agent.run_agent("add a test for compute_total", [], ws, {})  # {} -> no brain
            self.assertEqual(result["provider"], "offline")
            self.assertTrue((Path(ws) / "test_compute_total.py").is_file(), "the stub must be written")
            self.assertTrue(result["verified"], "a valid python stub must pass verify")
            self.assertTrue(result["completed"])

    def test_offline_run_never_overwrites_an_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "test_foo.py").write_text("PRECIOUS = 1\n", encoding="utf-8")
            with mock.patch.object(agent, "plan_task", return_value=[]):
                result = agent.run_agent("add a test for foo", [], ws, {})
            self.assertEqual((Path(ws) / "test_foo.py").read_text(encoding="utf-8"), "PRECIOUS = 1\n",
                             "the offline coder must NOT clobber an existing file")
            self.assertEqual(result["provider"], "offline")

    def test_no_brain_run_scaffolds_and_verifies_http_client(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            with mock.patch.object(agent, "plan_task", return_value=[]):
                result = agent.run_agent(
                    "build a C2 traffic simulator script with custom useragent and CA certs",
                    [],
                    ws,
                    {},
                )
            written = Path(ws) / "authorized_http_client.py"
            self.assertTrue(written.is_file())
            self.assertIn("--ca-cert", written.read_text(encoding="utf-8"))
            self.assertEqual(result["provider"], "offline")
            self.assertTrue(result["verified"])
            self.assertTrue(result["completed"])

    def test_unmappable_task_returns_honest_message(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            with mock.patch.object(agent, "plan_task", return_value=[]):
                result = agent.run_agent("rewrite the billing engine to use event sourcing", [], ws, {})
            self.assertEqual(result["provider"], "offline")
            self.assertIn("configured brain", result["text"])
            self.assertEqual(result["steps"], 0, "no ops applied for a task it can't template")


class RetrievalTests(unittest.TestCase):
    """Move 3 — the plan is made repo-specific via manifest/stack retrieval + the seed/snippets library."""

    def test_test_framework_detected_from_repo(self) -> None:
        # pytest repo (a conftest.py) -> a pytest-style stub (no unittest.TestCase).
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "conftest.py").write_text("", encoding="utf-8")
            plan = offline_coder.plan_edits("add a test for parse_config", td, seed_dir=_SEED)
            content = plan["ops"][0]["content"]
            compile(content, "t.py", "exec")
            self.assertIn("def test_parse_config_placeholder", content)
            self.assertNotIn("import unittest", content)
            self.assertIn("pytest", plan["summary"])
        # plain repo -> unittest scaffold.
        with tempfile.TemporaryDirectory() as td:
            plan = offline_coder.plan_edits("add a test for parse_config", td, seed_dir=_SEED)
            self.assertIn("import unittest", plan["ops"][0]["content"])
            self.assertIn("unittest", plan["summary"])

    def test_flask_route_is_gated_on_flask_presence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertTrue(offline_coder.plan_edits("add a route /users", td, seed_dir=_SEED)["needs_brain"])
            (Path(td) / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
            plan = offline_coder.plan_edits("add a route /users/profile", td, seed_dir=_SEED)
            self.assertFalse(plan["needs_brain"])
            self.assertEqual(plan["ops"][0]["path"], "users_profile_route.py")
            compile(plan["ops"][0]["content"], "r.py", "exec")

    def test_dockerfile_and_ci_intents(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(offline_coder.plan_edits("add a dockerfile", td, seed_dir=_SEED)["ops"][0]["path"], "Dockerfile")
            ci = offline_coder.plan_edits("set up a CI workflow", td, seed_dir=_SEED)
            self.assertEqual(ci["ops"][0]["path"], ".github/workflows/ci.yml")

    def test_run_agent_uses_seed_snippets_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "conftest.py").write_text("", encoding="utf-8")  # -> pytest template
            with mock.patch.object(agent, "plan_task", return_value=[]):
                result = agent.run_agent("add a test for compute_total", [], ws, {}, seed_dir=_SEED)
            written = (Path(ws) / "test_compute_total.py").read_text(encoding="utf-8")
            self.assertIn("def test_compute_total_placeholder", written)
            self.assertNotIn("import unittest", written)  # pytest style from retrieval
            self.assertTrue(result["verified"])

    def test_surface_reports_the_real_repo_facts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _repo(td, {"package.json": _PKG_EXPRESS, "package-lock.json": "{}",
                       "requirements.txt": _FASTAPI_REQS, "Dockerfile": "FROM python:3.11\n"})
            surface = offline_coder._surface(Path(td))
            self.assertIn("node", surface["stack"])
            self.assertIn("express", surface["stack"])
            self.assertIn("fastapi", surface["stack"])
            self.assertIn("python", surface["stack"])
            self.assertIn("docker", surface["stack"])
            self.assertEqual(surface["package_manager"], "npm")
            self.assertIn("package.json", surface["key_files"])
            # The gate blob carries the derived facts as explicit prefixed tokens.
            self.assertIn("stack:fastapi", surface["gate_blob"])
            self.assertIn("test:unittest", surface["gate_blob"])

    def test_surface_degrades_when_every_retrieval_source_raises(self) -> None:
        """Retrieval is an optimization, never a dependency: if devops_detect / project_memory /
        repomap all blow up, the surface must come back with empty fields and the plan must still be
        produced from the manifests alone."""
        import devops_detect
        import project_memory
        import repomap

        boom = mock.Mock(side_effect=RuntimeError("retrieval exploded"))
        with tempfile.TemporaryDirectory() as td:
            _repo(td, {"requirements.txt": _FASTAPI_REQS})
            with mock.patch.object(devops_detect, "build_project_setup_block", boom), \
                    mock.patch.object(project_memory, "load", boom), \
                    mock.patch.object(repomap, "build_repo_map", boom):
                surface = offline_coder._surface(Path(td), runtime_dir=td)
                self.assertEqual(surface["package_manager"], "")
                self.assertEqual(surface["ci"], "")
                self.assertEqual(surface["check_commands"], ())
                self.assertEqual(surface["ports"], ())
                self.assertEqual(surface["memory_facts"], {})
                self.assertEqual(surface["top_symbols"], ())
                self.assertIn("fastapi", surface["stack"], "manifests still parse without retrieval")

                plan = offline_coder.plan_edits("add a route /users", td, seed_dir=_SEED, runtime_dir=td)
            self.assertFalse(plan["needs_brain"])
            self.assertEqual(plan["ops"][0]["path"], "users_router.py")

    def test_project_memory_facts_reach_the_plan(self) -> None:
        """The per-project memory was loaded for the LLM prompt and ignored by the planner. A run
        command the user already recorded must win over anything the planner would guess."""
        import project_memory
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as rt:
            _repo(td, {"requirements.txt": "uvicorn\n"})
            project_memory.save(rt, td, [{"category": "run", "text": "python -m greyiq.serve",
                                          "source": "user"}])
            plan = offline_coder.plan_edits("create a systemd unit for greyiq", td,
                                            seed_dir=_SEED, runtime_dir=rt)
            self.assertFalse(plan["needs_brain"])
            self.assertIn("ExecStart=python -m greyiq.serve", plan["ops"][0]["content"])


class RecipeGatingTests(unittest.TestCase):
    """Every recipe is retrieval-gated: no Flask route in a repo with no Flask, no pytest fixture in
    a unittest repo. The SAME words must resolve to the repo's real stack."""

    def test_same_message_routes_to_different_recipes_per_stack(self) -> None:
        message = "add a route /users/profile"
        with tempfile.TemporaryDirectory() as fast, tempfile.TemporaryDirectory() as node, \
                tempfile.TemporaryDirectory() as bare:
            _repo(fast, {"requirements.txt": _FASTAPI_REQS})
            _repo(node, {"package.json": _PKG_EXPRESS})
            fast_plan = offline_coder.plan_edits(message, fast, seed_dir=_SEED)
            node_plan = offline_coder.plan_edits(message, node, seed_dir=_SEED)
            bare_plan = offline_coder.plan_edits(message, bare, seed_dir=_SEED)

            self.assertEqual(fast_plan["ops"][0]["path"], "users_profile_router.py")
            self.assertIn("APIRouter", fast_plan["ops"][0]["content"])
            self.assertEqual(node_plan["ops"][0]["path"], "users_profile_route.js")
            self.assertIn("express.Router()", node_plan["ops"][0]["content"])
            # No web framework at all -> refuse, and say WHICH fact was missing.
            self.assertTrue(bare_plan["needs_brain"])
            self.assertEqual(bare_plan["ops"], [])

    def test_fastapi_recipes_require_fastapi(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertTrue(offline_coder.plan_edits("create a fastapi app", td, seed_dir=_SEED)["needs_brain"])
            _repo(td, {"requirements.txt": _FASTAPI_REQS})
            plan = offline_coder.plan_edits("create a fastapi app", td, seed_dir=_SEED)
            self.assertFalse(plan["needs_brain"])
            self.assertIn("FastAPI(", plan["ops"][0]["content"])

    def test_express_recipe_requires_package_json_and_express(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # express in a manifest-less repo: no package.json -> refused.
            self.assertTrue(offline_coder.plan_edits(
                "add an express middleware named audit", td, seed_dir=_SEED)["needs_brain"])
            _repo(td, {"package.json": json.dumps({"dependencies": {"koa": "^2"}})})
            self.assertTrue(offline_coder.plan_edits(
                "add an express middleware named audit", td, seed_dir=_SEED)["needs_brain"],
                "a package.json without express must not unlock the Express template")
            _repo(td, {"package.json": _PKG_EXPRESS})
            plan = offline_coder.plan_edits("add an express middleware named audit", td, seed_dir=_SEED)
            self.assertFalse(plan["needs_brain"])
            self.assertEqual(plan["ops"][0]["path"], "audit_middleware.js")

    def test_pytest_recipes_are_refused_in_a_unittest_repo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _repo(td, {"requirements.txt": "requests\n"})  # python, no pytest
            for message in ("add a pytest fixture named db", "add a conftest",
                            "add a parametrized test for normalize"):
                with self.subTest(message=message):
                    plan = offline_coder.plan_edits(message, td, seed_dir=_SEED)
                    self.assertTrue(plan["needs_brain"], message)
                    self.assertEqual(plan["ops"], [])
            # ...and offered once the repo actually declares pytest.
            _repo(td, {"requirements.txt": _PYTEST_REQS})
            plan = offline_coder.plan_edits("add a pytest fixture named db", td, seed_dir=_SEED)
            self.assertFalse(plan["needs_brain"])
            self.assertEqual(plan["ops"][0]["path"], "fixtures_db.py")

    def test_unittest_table_recipe_is_refused_in_a_pytest_repo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _repo(td, {"requirements.txt": _PYTEST_REQS})
            plan = offline_coder.plan_edits("add a table-driven test for parse_config", td, seed_dir=_SEED)
            self.assertTrue(plan["needs_brain"])

    def test_stack_agnostic_recipes_are_ungated(self) -> None:
        """nginx / systemd / gitignore describe the machine, not the repo — they must fire in an
        empty workspace, or the offline coder is useless on a fresh VPS checkout."""
        expected = {
            "add an nginx reverse proxy for app.example.com": "deploy/nginx/app-example-com",
            "create a systemd unit for greyiq": "deploy/systemd/greyiq.service",
            "add a gitignore": ".gitignore",
            "add a makefile": "Makefile",
            "add a dockerignore": ".dockerignore",
        }
        with tempfile.TemporaryDirectory() as td:
            for message, path in expected.items():
                with self.subTest(message=message):
                    plan = offline_coder.plan_edits(message, td, seed_dir=_SEED)
                    self.assertFalse(plan["needs_brain"], message)
                    self.assertEqual(plan["ops"][0]["path"], path)

    def test_recipe_defers_when_its_verify_gate_is_unavailable(self) -> None:
        """The non-negotiable rule: no gate, no output. With node missing from PATH there is no
        `node --check`, so the JS templates must refuse rather than emit unverifiable text."""
        with tempfile.TemporaryDirectory() as td:
            _repo(td, {"package.json": _PKG_EXPRESS})
            with mock.patch.object(offline_coder.shutil, "which", return_value=None):
                plan = offline_coder.plan_edits("add a route /users", td, seed_dir=_SEED)
            self.assertTrue(plan["needs_brain"])
            self.assertEqual(plan["ops"], [])
            self.assertIn("node --check", plan["summary"])
            self.assertIn("cannot verify", plan["summary"])
            # Positive control: with node on PATH the very same request produces the op.
            with mock.patch.object(offline_coder.shutil, "which", return_value="/usr/bin/node"):
                plan = offline_coder.plan_edits("add a route /users", td, seed_dir=_SEED)
            self.assertFalse(plan["needs_brain"])
            self.assertEqual(plan["ops"][0]["path"], "users_route.js")

    def test_yaml_recipes_defer_without_a_yaml_parser(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(offline_coder.importlib.util, "find_spec", return_value=None):
                plan = offline_coder.plan_edits("add a docker compose file", td, seed_dir=_SEED)
            self.assertTrue(plan["needs_brain"])
            self.assertIn("YAML parse", plan["summary"])


class HonestDeferralTests(unittest.TestCase):
    def test_deferral_names_the_concrete_gap_not_a_canned_string(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _repo(td, {"requirements.txt": "requests\n"})
            summary = offline_coder.plan_edits("add a route /users", td, seed_dir=_SEED)["summary"]
        self.assertIn("I can scaffold", summary, "it must say what it CAN do here")
        self.assertIn("fastapi", summary.lower(), "it must name the missing dependency")
        self.assertIn("configured brain", summary)

    def test_deferral_lists_only_recipes_that_would_really_fire(self) -> None:
        """The 'I can scaffold X' list is computed from the same gates as the plan, so it can never
        promise a template the repo would refuse."""
        with tempfile.TemporaryDirectory() as td:
            _repo(td, {"requirements.txt": "requests\n"})  # no pytest, no web framework
            summary = offline_coder.plan_edits(
                "rewrite the billing engine to use event sourcing", td, seed_dir=_SEED)["summary"]
        self.assertNotIn("pytest fixture", summary)
        self.assertNotIn("Express", summary)

    def test_out_of_workspace_path_is_named_explicitly(self) -> None:
        plan = offline_coder.plan_edits("create a file ../../etc/passwd with x", ".", seed_dir=_SEED)
        self.assertTrue(plan["needs_brain"])
        self.assertIn("outside the workspace", plan["summary"])


class EditOpContractTests(unittest.TestCase):
    """The boundary with the applier: the planner declares INTENT and never builds a diff."""

    def test_add_import_emits_a_declared_op_not_a_diff(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _repo(td, {"main.py": "print('hi')\n"})
            plan = offline_coder.plan_edits("add an import of json to main.py", td, seed_dir=_SEED)
        self.assertFalse(plan["needs_brain"])
        op = plan["ops"][0]
        self.assertEqual(set(op), {"kind", "path", "op", "args"})
        self.assertEqual(op["kind"], "edit_op")
        self.assertEqual(op["op"], "add_import")
        self.assertEqual(op["path"], "main.py")
        self.assertEqual(op["args"]["module"], "json")
        # The planner must NEVER construct the text transformation itself.
        flat = json.dumps(op, default=str)
        self.assertNotIn("old_string", flat)
        self.assertNotIn("new_string", flat)
        self.assertNotIn("content", op)

    def test_module_never_imports_edit_ops(self) -> None:
        """File-disjointness with the applier is a build-time property, not a convention: importing
        edit_ops here would couple the planner to the writer's internals."""
        source = (BACKEND_DIR / "offline_coder.py").read_text(encoding="utf-8")
        self.assertNotIn("import edit_ops", source)
        self.assertNotIn("from edit_ops", source)


class TemplateLibraryTests(unittest.TestCase):
    """Every generated artifact is parsed here with the SAME parser _tool_verify would use, so a
    broken template fails in CI rather than in a user's repo."""

    def _plan(self, message: str, files: dict[str, str] | None = None) -> dict:
        with tempfile.TemporaryDirectory() as td:
            _repo(td, files or {})
            plan = offline_coder.plan_edits(message, td, seed_dir=_SEED)
        self.assertFalse(plan["needs_brain"], f"{message!r} should have matched a recipe: {plan['summary']}")
        return plan["ops"][0]

    def _python(self, message: str, files: dict[str, str] | None = None) -> str:
        op = self._plan(message, files)
        compile(op["content"], op["path"], "exec")
        self.assertNotIn("{{", op["content"], "every slot must be filled")
        return op["content"]

    # --- one case per new .py template ---------------------------------------------------------
    def test_fastapi_router_template_compiles(self) -> None:
        body = self._python("add a route /users/profile", {"requirements.txt": _FASTAPI_REQS})
        self.assertIn("users_profile_router = APIRouter", body)
        self.assertIn('@users_profile_router.get("/users/profile")', body)

    def test_fastapi_app_template_compiles(self) -> None:
        body = self._python("create a fastapi app", {"requirements.txt": _FASTAPI_REQS})
        self.assertIn("app = FastAPI(", body)
        self.assertIn("127.0.0.1", body, "the scaffold must document a loopback bind")

    def test_fastapi_dependency_template_compiles(self) -> None:
        body = self._python("add a fastapi dependency named require_token",
                            {"requirements.txt": _FASTAPI_REQS})
        self.assertIn("async def require_token(", body)
        self.assertIn("RequireTokenDep = Annotated[str, Depends(require_token)]", body)

    def test_flask_blueprint_template_compiles(self) -> None:
        body = self._python("add a flask blueprint for /admin", {"requirements.txt": "flask==3.0.0\n"})
        self.assertIn('admin_bp = Blueprint("admin", __name__, url_prefix="/admin")', body)

    def test_pytest_fixture_template_compiles(self) -> None:
        body = self._python("add a pytest fixture named db", {"requirements.txt": _PYTEST_REQS})
        self.assertIn("def db(tmp_path)", body)
        self.assertIn("yield resource", body)

    def test_pytest_parametrize_template_compiles(self) -> None:
        body = self._python("add a parametrized test for normalize", {"requirements.txt": _PYTEST_REQS})
        self.assertIn("@pytest.mark.parametrize(", body)
        self.assertIn("def test_normalize_cases(", body)

    def test_conftest_template_compiles(self) -> None:
        body = self._python("add a conftest", {"requirements.txt": _PYTEST_REQS})
        self.assertIn("def repo_root(", body)

    def test_unittest_subtest_template_compiles(self) -> None:
        body = self._python("add a table-driven test for parse_config", {"requirements.txt": "requests\n"})
        self.assertIn("class TestParseConfigCases(unittest.TestCase)", body)
        self.assertIn("with self.subTest(case=label)", body)

    def test_detection_rule_template_compiles_and_refuses_to_guess(self) -> None:
        body = self._python("add a detection rule for password spraying")
        self.assertIn('RULE_ID = "GN-PASSWORD-SPRAYING"', body)
        self.assertIn('SEVERITY = "undetermined"', body)
        self.assertIn("ATTACK_TECHNIQUES: tuple[str, ...] = ()", body)

    # --- non-Python artifacts, parsed with their real parser ------------------------------------
    def test_hunt_scope_template_is_valid_json_and_starts_unauthorized(self) -> None:
        op = self._plan("create a hunt scope file")
        self.assertEqual(op["path"], "hunt_scope.json")
        data = json.loads(op["content"])
        self.assertFalse(data["authorization"]["signed_scope_on_file"],
                         "a scaffolded scope must never assert authorization it does not have")
        self.assertIn("undetermined", data["authorization"]["reference"])
        self.assertTrue(data["rules_of_engagement"]["prefer_read_only"])

    def test_yaml_templates_parse(self) -> None:
        import yaml
        cases = {
            "add a docker compose file": "docker-compose.yml",
            "add a codeql workflow": ".github/workflows/codeql.yml",
            "add dependabot": ".github/dependabot.yml",
            "set up pre-commit": ".pre-commit-config.yaml",
            "set up a CI workflow": ".github/workflows/ci.yml",
        }
        for message, path in cases.items():
            with self.subTest(message=message):
                op = self._plan(message)
                self.assertEqual(op["path"], path)
                parsed = yaml.safe_load(op["content"])
                self.assertIsInstance(parsed, dict)

    def test_node_ci_workflow_is_used_in_a_node_repo(self) -> None:
        import yaml
        op = self._plan("set up a CI workflow", {"package.json": _PKG_EXPRESS,
                                                 "package-lock.json": "{}"})
        parsed = yaml.safe_load(op["content"])
        steps = parsed["jobs"]["test"]["steps"]
        self.assertTrue(any("setup-node" in str(step.get("uses", "")) for step in steps),
                        "a node repo must get the node workflow, not the python one")

    def test_codeql_workflow_keeps_github_expressions_intact(self) -> None:
        op = self._plan("add a codeql workflow")
        self.assertIn("${{ matrix.language }}", op["content"],
                      "slot filling must not eat GitHub Actions expressions")

    def test_systemd_unit_parses_as_ini_and_is_hardened(self) -> None:
        op = self._plan("create a systemd unit for greyiq")
        parser = configparser.ConfigParser(strict=False, allow_no_value=True)
        parser.read_string(op["content"])
        self.assertEqual(parser["Service"]["NoNewPrivileges"], "true")
        self.assertEqual(parser["Service"]["ProtectSystem"], "strict")
        self.assertNotEqual(parser["Service"]["User"], "root")

    def test_env_example_passes_the_agent_secret_scan_by_construction(self) -> None:
        op = self._plan("add an env example")
        self.assertEqual(op["path"], ".env.example")
        self.assertEqual(agent._scan_env_example_for_secrets(op["content"]), [],
                         "the example file must be placeholder-only")

    def test_nginx_site_binds_the_upstream_to_loopback(self) -> None:
        op = self._plan("add an nginx reverse proxy for app.example.com")
        self.assertIn("proxy_pass http://127.0.0.1:", op["content"])
        self.assertIn("server_name app.example.com;", op["content"])
        self.assertNotIn("proxy_pass http://0.0.0.0", op["content"])

    def test_makefile_recipe_lines_use_real_tabs(self) -> None:
        op = self._plan("add a makefile")
        recipe_lines = [line for line in op["content"].splitlines()
                        if line.startswith(("\t", "    ")) and line.strip()]
        self.assertTrue(recipe_lines, "the Makefile must have recipe lines")
        for line in recipe_lines:
            self.assertTrue(line.startswith("\t"), f"space-indented recipe line breaks make: {line!r}")

    def test_powershell_script_sets_strict_mode_before_any_work(self) -> None:
        op = self._plan("write a powershell script to rotate logs")
        self.assertEqual(op["path"], "scripts/rotate-logs.ps1")
        lines = [line.strip() for line in op["content"].splitlines()]
        strict = lines.index("Set-StrictMode -Version Latest")
        self.assertEqual(lines[strict + 1], "$ErrorActionPreference = 'Stop'")
        # param() has to be the first statement in a .ps1 (the language demands it), but nothing
        # else executable may run before strict mode is on.
        self.assertLess(lines.index("param("), strict)
        self.assertLess(strict, lines.index("function Write-Step {"))

    def test_finding_report_leaves_unproven_fields_undetermined(self) -> None:
        op = self._plan("write a finding report for idor on invoices")
        self.assertEqual(op["path"], "findings/idor-on-invoices.md")
        self.assertIn("reproducible or it didn't happen", op["content"])
        self.assertIn("undetermined", op["content"])
        self.assertNotIn("{{", op["content"])

    @unittest.skipUnless(shutil.which("node"), "node is not on PATH")
    def test_js_templates_pass_node_check(self) -> None:
        cases = {
            "add a route /users/profile": {"package.json": _PKG_EXPRESS},
            "add an express middleware named audit": {"package.json": _PKG_EXPRESS},
            "add a pm2 ecosystem config": {"package.json": _PKG_EXPRESS},
        }
        node = shutil.which("node")
        for message, files in cases.items():
            with self.subTest(message=message):
                op = self._plan(message, files)
                with tempfile.TemporaryDirectory() as out:
                    target = Path(out) / Path(op["path"]).name
                    target.write_text(op["content"], encoding="utf-8")
                    proc = subprocess.run([node, "--check", str(target)], capture_output=True,
                                          text=True, timeout=60)
                self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_pm2_config_uses_cjs_in_an_esm_package(self) -> None:
        esm = json.dumps({"name": "api", "type": "module", "dependencies": {"express": "^4"}})
        op = self._plan("add a pm2 ecosystem config", {"package.json": esm})
        self.assertEqual(op["path"], "ecosystem.config.cjs",
                         "PM2 require()s this file; .js in an ESM package fails to load")


class RecipeRegistryTests(unittest.TestCase):
    """The registry is data — these are the invariants that keep adding a row safe."""

    def test_recipe_names_are_unique_and_freeform_is_last(self) -> None:
        names = [r.name for r in offline_coder._REGISTRY]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names[-1], "new_file",
                         "the least-specific pattern must never shadow a specific one")

    def test_every_recipe_has_a_resolvable_template_and_a_known_gate(self) -> None:
        for recipe in offline_coder._REGISTRY:
            with self.subTest(recipe=recipe.name):
                if recipe.template:
                    self.assertIsNotNone(offline_coder._load_snippet(_SEED, recipe.template),
                                         f"missing seed/snippets/{recipe.template}")
                else:
                    self.assertTrue(recipe.fallback or recipe.kind != "new_file",
                                    "a new_file recipe needs a template or a bundled fallback")
                self.assertTrue(offline_coder._gate_available(recipe.verify_hint)
                                or recipe.verify_hint in ("node --check", "PowerShell parser", "YAML parse"),
                                f"unrecognized verify gate {recipe.verify_hint!r}")
                self.assertTrue(recipe.label and recipe.label[0].islower(),
                                "labels are inlined mid-sentence in the deferral message")

    def test_route_picks_a_family_or_says_undetermined(self) -> None:
        surface = {"stack": frozenset()}
        self.assertEqual(offline_coder._route("add a route /users", surface, []), "web")
        self.assertEqual(offline_coder._route("add a dockerfile", surface, []), "container")
        self.assertEqual(offline_coder._route("add a detection rule", surface, []), "security")
        self.assertEqual(offline_coder._route("xyzzy plugh", surface, []), "",
                         "no signal must read as undetermined, never a guess")

    def test_routing_promotes_a_family_without_bypassing_its_gate(self) -> None:
        """A promoted recipe is still gated — routing changes priority, never permission."""
        with tempfile.TemporaryDirectory() as td:
            promoted = offline_coder._ordered("web")
            self.assertEqual(promoted[0].family, "web")
            self.assertEqual(promoted[-1].name, "new_file")
            plan = offline_coder.plan_edits("add a route /users", td, seed_dir=_SEED)
            self.assertTrue(plan["needs_brain"])


class DottedFilenamePhrasingTests(unittest.TestCase):
    """A recipe named after a DOTFILE must fire on the dotted name the user actually types.

    Regression for the class of bug where the registry advertised `.gitignore` / `.dockerignore` /
    `.env.example` by name and then refused every phrasing containing the dot: the shared `_GAP`
    banned '.' outright, and each pattern put `\\b` in front of its optional dot (which only holds
    after a word char), so the dot branch was dead code. Both halves are needed — these phrasings
    fail if either regresses."""

    _DOTTED = {
        "add a .gitignore": ".gitignore",
        "add .gitignore": ".gitignore",
        "create the .gitignore file": ".gitignore",
        "make me a .gitignore": ".gitignore",
        "create a .dockerignore": ".dockerignore",
        "add a .dockerignore file": ".dockerignore",
        "create a .env.example": ".env.example",
        "add a .env file": ".env.example",
        "add a .pre-commit-config.yaml": ".pre-commit-config.yaml",
        # The dot-free forms already worked and must keep working.
        "add a gitignore": ".gitignore",
        "add a dockerignore": ".dockerignore",
        "create an env example": ".env.example",
        "add a pre-commit config": ".pre-commit-config.yaml",
    }

    def test_dotted_config_filenames_reach_their_recipe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            for message, path in self._DOTTED.items():
                with self.subTest(message=message):
                    plan = offline_coder.plan_edits(message, td, seed_dir=_SEED)
                    self.assertFalse(plan["needs_brain"],
                                     f"{message!r} deferred: {plan['summary']}")
                    self.assertEqual(plan["ops"][0]["path"], path)

    def test_no_pattern_puts_a_word_boundary_before_an_optional_dot(self) -> None:
        """The registry-wide invariant behind the fix: `\\b\\.?` can never match a leading dot, so a
        row written that way silently loses its dotted phrasing. Use `_ODOT` instead."""
        for recipe in offline_coder._REGISTRY:
            with self.subTest(recipe=recipe.name):
                self.assertNotIn(r"\b\.?", recipe.pattern.pattern,
                                 "a word boundary before an optional dot is dead code — use _ODOT")
                self.assertNotIn(r"\b(?:\.?", recipe.pattern.pattern,
                                 "a word boundary before an optional dot is dead code — use _ODOT")

    def test_the_gap_still_refuses_to_cross_a_sentence_boundary(self) -> None:
        """Negative control on the same fix: letting `_GAP` span an INTRA-TOKEN dot must not let it
        span a sentence-ending one, or one request would bleed into the next."""
        with tempfile.TemporaryDirectory() as td:
            for message in ("explain the auth flow. then tell me about caching",
                            "read the docs. summarize them",
                            "create the release notes. do not touch the gitignore"):
                with self.subTest(message=message):
                    plan = offline_coder.plan_edits(message, td, seed_dir=_SEED)
                    self.assertTrue(plan["needs_brain"], plan["summary"])


class RouteRequestPhrasingTests(unittest.TestCase):
    """`route` was the only noun the web rows understood, with no room for a framework word — so
    "add a fastapi router /orders" (the FastAPI row's own label) hit nothing and the user was told to
    configure a brain for a template that was sitting right there."""

    _POLYGLOT = {"requirements.txt": _FASTAPI_REQS + "flask==3.0.0\n", "package.json": _PKG_EXPRESS}

    def _path(self, message: str, files: dict[str, str]) -> str:
        with tempfile.TemporaryDirectory() as td:
            _repo(td, files)
            plan = offline_coder.plan_edits(message, td, seed_dir=_SEED)
        return "NEEDS_BRAIN" if plan["needs_brain"] else plan["ops"][0]["path"]

    def test_router_handler_and_framework_qualifiers_are_understood(self) -> None:
        fastapi_only = {"requirements.txt": _FASTAPI_REQS}
        for message in ("add a route /orders", "add a fastapi router /orders",
                        "add a fastapi route /orders", "create a router /orders",
                        "add an endpoint /orders", "add a new api endpoint /orders",
                        "add an http handler /orders", "scaffold a fast api router /orders"):
            with self.subTest(message=message):
                self.assertEqual(self._path(message, fastapi_only), "orders_router.py",
                                 f"{message!r} must reach the FastAPI row")

    def test_a_named_framework_beats_registry_order(self) -> None:
        """In a repo that declares all three, naming the framework must decide — otherwise the row
        that happens to sit first scaffolds a stack the user did not ask for."""
        self.assertEqual(self._path("add a flask route /orders", self._POLYGLOT), "orders_route.py")
        self.assertEqual(self._path("add a flask endpoint /orders", self._POLYGLOT), "orders_route.py")
        if shutil.which("node"):  # the JS row refuses without its `node --check` gate
            self.assertEqual(self._path("add an express route /orders", self._POLYGLOT),
                             "orders_route.js")
        # Unqualified, retrieval still picks — registry order, first row that passes its gate.
        self.assertEqual(self._path("add a route /orders", self._POLYGLOT), "orders_router.py")

    def test_naming_a_framework_the_repo_lacks_still_defers(self) -> None:
        """Accepting the framework word must not become a way around the retrieval gate."""
        with tempfile.TemporaryDirectory() as td:
            _repo(td, {"requirements.txt": _FASTAPI_REQS})
            plan = offline_coder.plan_edits("add a flask route /orders", td, seed_dir=_SEED)
        self.assertTrue(plan["needs_brain"], plan["summary"])
        self.assertEqual(plan["ops"], [])

    def test_framework_qualified_test_stub_reaches_the_test_row(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _repo(td, {"requirements.txt": _PYTEST_REQS})
            plan = offline_coder.plan_edits("add a pytest test stub for parse_config", td,
                                            seed_dir=_SEED)
        self.assertFalse(plan["needs_brain"], plan["summary"])
        self.assertEqual(plan["ops"][0]["path"], "test_parse_config.py")
        self.assertIn("pytest", plan["summary"])


class CorruptTemplateTests(unittest.TestCase):
    """One unreadable seed template must disable THAT recipe, never the registry.

    `_gate_block` reads every template in the registry to decide what this install can offer, so an
    exception out of `_load_snippet` takes down requests that have nothing to do with the bad file.
    `Path.read_text(encoding="utf-8")` raises `UnicodeDecodeError` (a `ValueError`, not an `OSError`)
    on a truncated or cp1252-saved .tmpl, which the old guard did not catch."""

    def _seed_with_corrupt(self, td: str, name: str) -> Path:
        seed = Path(td) / "seed"
        shutil.copytree(_SEED, seed)
        (seed / "snippets" / name).write_bytes(b"import pytest\n# caf\xe9 fixture\n")  # cp1252
        return seed

    def test_load_snippet_returns_none_for_an_undecodable_template(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            seed = self._seed_with_corrupt(td, "conftest.py.tmpl")
            self.assertIsNone(offline_coder._load_snippet(seed, "conftest.py.tmpl"))
            self.assertIsNotNone(offline_coder._load_snippet(seed, "gitignore.tmpl"),
                                 "the healthy templates must be unaffected")

    def test_one_corrupt_template_does_not_disable_the_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as repo:
            seed = self._seed_with_corrupt(td, "conftest.py.tmpl")
            _repo(repo, {"requirements.txt": _PYTEST_REQS})
            # An UNRELATED request must still plan (this raised UnicodeDecodeError before the fix).
            other = offline_coder.plan_edits("add a gitignore", repo, seed_dir=seed)
            self.assertFalse(other["needs_brain"], other["summary"])
            self.assertEqual(other["ops"][0]["path"], ".gitignore")
            # ...and so must a request that reaches the registry gate and matches nothing.
            deferred = offline_coder.plan_edits("refactor the widget subsystem to be faster", repo,
                                                seed_dir=seed)
            self.assertTrue(deferred["needs_brain"])
            self.assertIn("configured brain", deferred["summary"])
            # The bad template's OWN recipe degrades to the declared, honest deferral.
            own = offline_coder.plan_edits("create a conftest.py", repo, seed_dir=seed)
            self.assertTrue(own["needs_brain"])
            self.assertIn("conftest.py.tmpl", own["summary"])
            self.assertIn("isn't readable", own["summary"])
            # It must not claim WHICH failure it was — _load_snippet cannot tell missing from corrupt.
            self.assertNotIn("missing", own["summary"].lower())

    def test_corrupt_template_is_not_offered_in_the_deferral_list(self) -> None:
        """`_offerable` is computed from the same gate, so a recipe whose template will not load can
        never appear in the 'here I can scaffold X' half of the message."""
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as repo:
            seed = self._seed_with_corrupt(td, "hunt_scope.json.tmpl")
            _repo(repo, {"requirements.txt": _PYTEST_REQS})
            offerable = offline_coder._offerable(offline_coder._surface(Path(repo)), Path(repo),
                                                 seed, limit=40)
        self.assertNotIn("a bug-bounty / engagement scope file", offerable)
        self.assertIn("a pytest conftest.py", offerable, "healthy rows must still be offered")


class LabelPhrasingMatrixTests(unittest.TestCase):
    """THE systematic guard: every recipe must fire on a phrasing derived from its OWN label.

    A label is not decoration — `_needs_brain` prints it back to the user ("I have a template for a
    FastAPI router, but ..."), so a row whose label is not a phrasing its pattern accepts advertises
    a capability the user then cannot invoke. Running this over the whole registry is what caught the
    dotted-filename and route-noun gaps as one class instead of three anecdotes; it also means a NEW
    row cannot be added with a pattern that misses its own name."""

    # The ARGUMENT a row's pattern requires but a label never carries (a URL path, a symbol).
    _ARG_TAIL = {
        "fastapi_router": " /orders",
        "flask_route": " /orders",
        "express_route": " /orders",
        "test_case_pytest": " for parse_config",
        "test_case_unittest": " for parse_config",
    }
    # Rows whose LABEL is not a request phrasing at all, with the reason and the phrasing asserted
    # instead. Keep this dict as close to empty as the registry allows.
    _NOT_A_REQUEST = {
        "add_import": (
            "add an import of json to main.py",
            "the one edit_op row: its label names the RESULT ('an import added to an existing "
            "Python file') while the request names a module and a target file, so no suffix can "
            "turn the label into something a user would type.",
        ),
    }
    # requires-token -> the fixture that satisfies it, so each row is exercised in a repo its own
    # retrieval gate accepts.
    _GATE_FIXTURES = {
        "stack:fastapi": ("requirements.txt", _FASTAPI_REQS),
        "stack:flask": ("requirements.txt", "flask==3.0.0\n"),
        "stack:python": ("requirements.txt", "requests\n"),
        "stack:express": ("package.json", _PKG_EXPRESS),
        "stack:node": ("package.json", _PKG_EXPRESS),
        "test:pytest": ("requirements.txt", _PYTEST_REQS),
        "test:unittest": ("requirements.txt", "requests\n"),
    }

    def _fixture(self, recipe) -> dict[str, str]:
        files: dict[str, str] = {}
        for token in recipe.requires:
            self.assertIn(token, self._GATE_FIXTURES, f"no fixture for gate token {token!r}")
            name, body = self._GATE_FIXTURES[token]
            files[name] = files.get(name, "") + body if name.endswith(".txt") else body
        for name in recipe.requires_file:
            files.setdefault(name, _PKG_EXPRESS if name == "package.json" else "")
        return files

    def _phrase(self, recipe) -> str:
        if recipe.name in self._NOT_A_REQUEST:
            return self._NOT_A_REQUEST[recipe.name][0]
        return "add " + recipe.label + self._ARG_TAIL.get(recipe.name, "")

    def test_every_recipe_fires_on_a_phrasing_from_its_own_label(self) -> None:
        for recipe in offline_coder._REGISTRY:
            with self.subTest(recipe=recipe.name):
                if not offline_coder._gate_available(recipe.verify_hint):
                    self.skipTest(f"{recipe.verify_hint} is unavailable on this host")
                phrase = self._phrase(recipe)
                with tempfile.TemporaryDirectory() as td:
                    _repo(td, self._fixture(recipe))
                    surface = offline_coder._surface(Path(td))
                    family = offline_coder._route(phrase, surface, [])
                    hit = offline_coder._match_recipe(phrase, surface, root=Path(td),
                                                      seed_dir=_SEED, family=family)
                    self.assertIsNotNone(hit, f"{phrase!r} matched no recipe at all")
                    self.assertEqual(hit[0].name, recipe.name,
                                     f"{phrase!r} resolved to {hit[0].name!r}")
                    plan = offline_coder.plan_edits(phrase, td, seed_dir=_SEED)
                self.assertFalse(plan["needs_brain"], f"{phrase!r} deferred: {plan['summary']}")
                self.assertTrue(plan["ops"][0]["path"])

    def test_the_label_exemption_list_stays_justified_and_small(self) -> None:
        """An exemption is a documented decision, not a place to hide a broken pattern."""
        names = {r.name for r in offline_coder._REGISTRY}
        for name, (phrase, reason) in self._NOT_A_REQUEST.items():
            self.assertIn(name, names, "exemption for a recipe that no longer exists")
            self.assertTrue(phrase and len(reason) > 40, f"{name} needs a real justification")
        self.assertLessEqual(len(self._NOT_A_REQUEST), 1,
                             "more than one row whose own label is unusable means the labels, not "
                             "the exemption list, need fixing")
        for name in self._ARG_TAIL:
            self.assertIn(name, names, "argument tail for a recipe that no longer exists")


class CodegenIntentDetectorTests(unittest.TestCase):
    """Move 1: the honest short-circuit fires on code-WRITING intent, not code discussion."""

    def test_positive_codegen_requests(self) -> None:
        for msg in ["write me a function to sort a list", "fix this script", "generate a pytest test",
                    "create a python function", "add an endpoint", "implement a class Foo",
                    "refactor this code", "make a dockerfile"]:
            self.assertTrue(greyiq_api._looks_like_codegen_request(msg), msg)

    def test_negative_non_codegen(self) -> None:
        for msg in ["what is an API?", "explain how python works", "who wrote the linux kernel",
                    "summarize this article", "what does refactor mean"]:
            self.assertFalse(greyiq_api._looks_like_codegen_request(msg), msg)


if __name__ == "__main__":
    unittest.main()
