from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import agent  # noqa: E402
import devops_detect  # noqa: E402
import skills as skills_lib  # noqa: E402


def _settings(**overrides: object) -> dict[str, object]:
    settings = dict(agent.AGENT_DEFAULTS)
    settings.update(overrides)
    return settings


class SkillDevOpsTests(unittest.TestCase):
    def test_skill_frontmatter_parsing_still_works(self) -> None:
        parsed = skills_lib._parse(
            """---
name: sample-devops
description: Sample deployment playbook
when: deploy, pm2
---
Follow the steps.
""",
            "user",
            "sample-devops.md",
        )

        self.assertEqual(parsed.name, "sample-devops")
        self.assertEqual(parsed.description, "Sample deployment playbook")
        self.assertEqual(parsed.triggers, ["deploy", "pm2"])
        self.assertIn("Follow the steps.", parsed.body)

    def test_devops_seed_skills_are_loaded(self) -> None:
        expected = {
            "pm2-node-service",
            "ubuntu-vps-node-python",
            "nginx-reverse-proxy",
            "env-and-secrets-setup",
            "deploy-doc-generator",
            "git-workflow",
        }
        with tempfile.TemporaryDirectory() as tmp:
            loaded = skills_lib.load_skills(Path(tmp), BACKEND_DIR / "seed", None)

        self.assertTrue(expected.issubset({skill.name for skill in loaded}))

    def test_git_requests_select_git_workflow_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            loaded = skills_lib.load_skills(Path(tmp), BACKEND_DIR / "seed", None)

        selected = skills_lib.select_skills("commit my changes and push the branch", loaded)

        self.assertTrue(selected)
        self.assertEqual("git-workflow", selected[0].name)

    def test_ci_requests_select_ci_pipeline_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            loaded = skills_lib.load_skills(Path(tmp), BACKEND_DIR / "seed", None)

        self.assertIn("ci-pipeline", {skill.name for skill in loaded})
        selected = skills_lib.select_skills("create a github actions ci pipeline for this repo", loaded)

        self.assertTrue(selected)
        self.assertEqual("ci-pipeline", selected[0].name)


class ProjectDetectionTests(unittest.TestCase):
    def test_detects_sample_node_python_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"scripts": {"start": "node server.mjs", "build": "vite build", "check": "npm test"}}),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text("{}", encoding="utf-8")
            (root / "server.mjs").write_text(
                'const port = Number.parseInt(process.env.PORT || "5173", 10);\n',
                encoding="utf-8",
            )
            (root / "backend").mkdir()
            (root / "backend" / "app.py").write_text(
                'PORT = int(os.getenv("GREYIQ_PORT", "8766"))\n',
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("uvicorn\n", encoding="utf-8")
            (root / "ecosystem.config.cjs").write_text("module.exports = { apps: [] };\n", encoding="utf-8")
            (root / ".env.example").write_text("GREYIQ_HOST=127.0.0.1\n", encoding="utf-8")
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text("name: ci\n", encoding="utf-8")

            block = devops_detect.build_project_setup_block(root)

        self.assertIn("- Node package: yes", block)
        self.assertIn("- package manager: npm", block)
        self.assertIn("- scripts: start, build, check", block)
        self.assertIn("- Python backend: yes", block)
        self.assertIn("- Existing PM2 config: yes", block)
        self.assertIn("- Env example: yes", block)
        self.assertIn("- CI: GitHub Actions", block)
        self.assertIn("ci.yml", block)
        self.assertIn("- Check/test commands: npm run check", block)
        self.assertIn("- Likely frontend port: 5173", block)
        self.assertIn("- Likely backend port: 8766", block)

    def test_detects_non_github_ci_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitlab-ci.yml").write_text("stages: [test]\n", encoding="utf-8")

            block = devops_detect.build_project_setup_block(root)

        self.assertIn("- CI: GitLab CI", block)

    def test_reports_none_when_no_ci(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            block = devops_detect.build_project_setup_block(Path(tmp))

        self.assertIn("- CI: none detected", block)

    def test_surfaces_check_commands_from_package_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"scripts": {"lint": "eslint .", "test": "vitest run"}}), encoding="utf-8"
            )

            block = devops_detect.build_project_setup_block(root)

        self.assertIn("- Check/test commands:", block)
        self.assertIn("npm run lint", block)
        self.assertIn("npm test", block)


class VerifyDevOpsTests(unittest.TestCase):
    def _verify_written_file(self, filename: str, content: str, allow_commands: bool = False) -> tuple[str, bool]:
        with tempfile.TemporaryDirectory() as tmp:
            toolbox = agent.ToolBox(Path(tmp), _settings(allow_commands=allow_commands))
            _, write_error = toolbox.run("write_file", {"path": filename, "content": content})
            self.assertFalse(write_error)
            return toolbox.run("verify", {})

    def test_verify_catches_invalid_json(self) -> None:
        output, is_error = self._verify_written_file("broken.json", '{"ok":')

        self.assertTrue(is_error)
        self.assertIn("VERIFY FAILED", output)
        self.assertIn("broken.json", output)

    def test_verify_catches_python_syntax_errors(self) -> None:
        output, is_error = self._verify_written_file("broken.py", "def broken(:\n    pass\n")

        self.assertTrue(is_error)
        self.assertIn("VERIFY FAILED", output)
        self.assertIn("broken.py", output)

    def test_verify_fails_env_example_with_secret_shaped_value(self) -> None:
        fake_key = "sk-proj-" + ("a" * 48)
        output, is_error = self._verify_written_file(".env.example", f"OPENAI_API_KEY={fake_key}\n")

        self.assertTrue(is_error)
        self.assertIn("VERIFY FAILED", output)
        self.assertIn("OPENAI_API_KEY", output)
        self.assertNotIn(fake_key, output)

    def test_verify_reports_js_skipped_when_commands_disabled(self) -> None:
        output, is_error = self._verify_written_file("broken.js", "function nope( {\n")

        self.assertFalse(is_error)
        self.assertIn("VERIFY PASSED", output)
        self.assertIn("SKIP broken.js: node --check requires commands enabled", output)


if __name__ == "__main__":
    unittest.main()
