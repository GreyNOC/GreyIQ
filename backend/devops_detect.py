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


def _github_actions(root: Path) -> bool:
    workflows = root / ".github" / "workflows"
    return workflows.is_dir() and any(path.is_file() for path in workflows.glob("*"))


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
            f"- GitHub Actions: {_yes(_github_actions(root))}",
            f"- Likely frontend port: {', '.join(frontend_ports) if frontend_ports else 'unknown'}",
            f"- Likely backend port: {', '.join(backend_ports) if backend_ports else 'unknown'}",
        ]
    )
