"""Deterministic DevOps/project detection for the GreyIQ agent prompt."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_MAX_READ_BYTES = 200_000
_PORT_RE = re.compile(
    r"(?:\b(?:PORT|GREYIQ_PORT|VITE_PORT|port)\b[^0-9\n]{0,80}|listen\([^0-9\n]{0,80})"
    r"([1-9][0-9]{2,5})",
    re.IGNORECASE,
)


def _yes(value: bool) -> str:
    return "yes" if value else "no"


def _read_text(path: Path) -> str:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_READ_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _load_package_json(root: Path) -> dict[str, Any]:
    path = root / "package.json"
    try:
        payload = json.loads(_read_text(path))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _package_manager(root: Path) -> str:
    if (root / "pnpm-lock.yaml").is_file():
        return "pnpm"
    if (root / "yarn.lock").is_file():
        return "yarn"
    if (root / "package-lock.json").is_file() or (root / "npm-shrinkwrap.json").is_file():
        return "npm"
    if (root / "package.json").is_file():
        return "npm (no lockfile)"
    return "unknown"


def _script_summary(package_json: dict[str, Any]) -> str:
    scripts = package_json.get("scripts")
    if not isinstance(scripts, dict) or not scripts:
        return "(none)"
    priority = ["start", "dev", "build", "check", "test", "backend", "desktop"]
    names = [name for name in priority if name in scripts]
    names.extend(sorted(name for name in scripts if name not in set(priority)))
    return ", ".join(names)


def _glob_any(root: Path, *patterns: str) -> bool:
    return any(any(root.glob(pattern)) for pattern in patterns)


# CI providers identified by a single well-known config file.
_CI_MARKERS: tuple[tuple[str, str], ...] = (
    ("GitLab CI", ".gitlab-ci.yml"),
    ("CircleCI", ".circleci/config.yml"),
    ("Travis CI", ".travis.yml"),
    ("Azure Pipelines", "azure-pipelines.yml"),
    ("Jenkins", "Jenkinsfile"),
    ("Drone CI", ".drone.yml"),
    ("Bitbucket Pipelines", "bitbucket-pipelines.yml"),
)


def _ci_summary(root: Path) -> str:
    """Name the CI provider(s) in use, and for GitHub Actions list the workflow
    files — so the agent knows what already runs before it edits or adds a pipeline."""
    providers: list[str] = []
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        names = sorted(path.name for path in workflows.glob("*.y*ml") if path.is_file())
        if names:
            shown = ", ".join(names[:4]) + (" …" if len(names) > 4 else "")
            plural = "s" if len(names) != 1 else ""
            providers.append(f"GitHub Actions ({len(names)} workflow{plural}: {shown})")
    for label, rel in _CI_MARKERS:
        if (root / rel).is_file():
            providers.append(label)
    return "; ".join(providers) if providers else "none detected"


def _pm_run_prefix(root: Path) -> str:
    if (root / "pnpm-lock.yaml").is_file():
        return "pnpm"
    if (root / "yarn.lock").is_file():
        return "yarn"
    return "npm run"


def _check_commands(root: Path, package_json: dict[str, Any]) -> str:
    """The commands a CI job would run to gate this project, so the agent can
    reproduce CI locally before touching a workflow. Skips watch-mode and the npm
    'no test specified' placeholder."""
    scripts = package_json.get("scripts") if isinstance(package_json, dict) else {}
    scripts = scripts if isinstance(scripts, dict) else {}
    prefix = _pm_run_prefix(root)
    manager = prefix.split()[0]
    commands: list[str] = []
    for name in ("check", "lint", "typecheck", "test", "build"):
        script = scripts.get(name)
        if not isinstance(script, str) or not script.strip():
            continue
        if "no test specified" in script or "watch" in script:
            continue
        if name == "test" and manager == "npm":
            commands.append("npm test")
        else:
            commands.append(f"{prefix} {name}" if manager == "npm" else f"{manager} {name}")
    if not commands and (
        (root / "pyproject.toml").is_file()
        or (root / "tests").is_dir()
        or any(root.glob("test_*.py"))
    ):
        commands.append("python -m pytest")
    return ", ".join(commands) if commands else "(none detected)"


def _find_ports(files: list[Path]) -> list[str]:
    found: list[str] = []
    for path in files:
        text = _read_text(path)
        if not text:
            continue
        for match in _PORT_RE.finditer(text):
            port = match.group(1)
            if port not in found:
                found.append(port)
            if len(found) >= 4:
                return found
    return found


def build_project_setup_block(workspace: str | Path) -> str:
    """Return a compact, non-secret project setup summary for the agent prompt."""
    root = Path(workspace).resolve()
    package_json = _load_package_json(root)
    has_package = (root / "package.json").is_file()
    backend_py = sorted((root / "backend").glob("*.py")) if (root / "backend").is_dir() else []
    python_backend = bool(backend_py or (root / "requirements.txt").is_file() or (root / "pyproject.toml").is_file())
    docker = _glob_any(root, "Dockerfile", "docker-compose.yml", "docker-compose.yaml")
    pm2 = _glob_any(root, "ecosystem.config.*")
    env_example = (root / ".env.example").is_file()
    env_file = (root / ".env").is_file()
    frontend_files = [
        path
        for pattern in ("server.mjs", "vite.config.*", "next.config.*", "public/*.js", "package.json")
        for path in root.glob(pattern)
        if path.is_file()
    ]
    backend_files = backend_py + [root / "requirements.txt", root / "pyproject.toml"]
    frontend_ports = _find_ports(frontend_files)
    backend_ports = _find_ports([path for path in backend_files if path.is_file()])

    return "\n".join(
        [
            "Detected project setup:",
            f"- Node package: {_yes(has_package)}",
            f"- package manager: {_package_manager(root)}",
            f"- scripts: {_script_summary(package_json)}",
            f"- Python backend: {_yes(python_backend)}",
            f"- Docker: {_yes(docker)}",
            f"- Existing PM2 config: {_yes(pm2)}",
            f"- Env example: {_yes(env_example)}",
            f"- Env file present: {_yes(env_file)}",
            f"- CI: {_ci_summary(root)}",
            f"- Check/test commands: {_check_commands(root, package_json)}",
            f"- Likely frontend port: {', '.join(frontend_ports) if frontend_ports else 'unknown'}",
            f"- Likely backend port: {', '.join(backend_ports) if backend_ports else 'unknown'}",
        ]
    )
