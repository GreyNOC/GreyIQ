"""Skill playbooks for the coding agent.

A skill is a markdown file (SKILL.md style) with a small frontmatter block:

    ---
    name: add-endpoint
    description: Add an HTTP route/endpoint and a test for it
    when: route, endpoint, api, handler, add a route
    ---
    <step-by-step procedure the agent should follow>

Skills make a weaker local model reliable: instead of inventing an approach, the
agent follows a vetted recipe. Bundled defaults ship in backend/seed/skills and
are copied to the per-user RUNTIME_DIR/skills (without clobbering edits). Users
add their own there, or per-project ones under <workspace>/.greyiq/skills
(which override same-named global skills).
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import trust

SKILLS_DIRNAME = "skills"

_FRONTMATTER = re.compile(r"^﻿?---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_WORD = re.compile(r"[a-z0-9_+#.-]{2,}")
_STOPWORDS = {
    "the", "a", "an", "to", "and", "for", "with", "in", "of", "on", "that", "this",
    "it", "is", "be", "my", "me", "i", "you", "can", "please", "help", "want",
    "add", "make", "create", "do", "fix", "use", "using", "how",
}


@dataclass(slots=True)
class Skill:
    name: str
    description: str
    triggers: list[str]
    body: str
    source: str  # "user" | "workspace"
    path: str


def _parse(text: str, source: str, path: str) -> Skill:
    front: dict[str, str] = {}
    body = text
    match = _FRONTMATTER.match(text)
    if match:
        for line in match.group(1).splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                front[key.strip().lower()] = value.strip()
        body = text[match.end():]
    name = front.get("name") or Path(path).stem
    description = front.get("description", "")
    triggers = [t.strip().lower() for t in re.split(r"[,;]", front.get("when", "")) if t.strip()]
    return Skill(name=name, description=description, triggers=triggers, body=body.strip(), source=source, path=path)


def ensure_user_skills(runtime_dir: Path, seed_dir: Path) -> Path:
    """Seed the per-user skills folder with bundled defaults (never overwriting)."""
    dst = Path(runtime_dir) / SKILLS_DIRNAME
    dst.mkdir(parents=True, exist_ok=True)
    src = Path(seed_dir) / SKILLS_DIRNAME
    if src.is_dir():
        for bundled in src.glob("*.md"):
            target = dst / bundled.name
            if not target.exists():
                try:
                    shutil.copy2(bundled, target)
                except OSError:
                    pass
    return dst


def load_skills(runtime_dir: Path, seed_dir: Path, workspace: str | Path | None) -> list[Skill]:
    ensure_user_skills(runtime_dir, seed_dir)
    by_name: dict[str, Skill] = {}
    search: list[tuple[Path, str]] = [(Path(runtime_dir) / SKILLS_DIRNAME, "user")]
    if workspace:
        search.append((Path(workspace) / ".greyiq" / SKILLS_DIRNAME, "workspace"))
    # workspace skills are loaded last so they override same-named global ones
    for directory, source in search:
        if not Path(directory).is_dir():
            continue
        for path in sorted(Path(directory).glob("*.md")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            skill = _parse(text, source, str(path))
            by_name[skill.name] = skill
    return list(by_name.values())


def select_skills(task: str, skills: list[Skill], limit: int = 2) -> list[Skill]:
    """Deterministic keyword match — don't rely on the weak model to pick."""
    task_lower = task.lower()
    tokens = {t for t in _WORD.findall(task_lower) if t not in _STOPWORDS}
    scored: list[tuple[int, Skill]] = []
    for skill in skills:
        haystack = f"{skill.name} {skill.description} {' '.join(skill.triggers)}".lower()
        score = 0
        for trigger in skill.triggers:
            if trigger and trigger in task_lower:
                score += 3
        for token in tokens:
            if token in haystack:
                score += 1
        if score > 0:
            scored.append((score, skill))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [skill for _, skill in scored[:limit]]


def _safe_body(skill: "Skill") -> str:
    # A "workspace" skill comes from the UNTRUSTED repo checkout — fence its body as DATA so a
    # malicious playbook can't inject first-party instructions into the trusted system prompt
    # (same boundary read_file/grep use). "user"/bundled skills are operator-owned → trusted.
    if skill.source == "workspace":
        return trust.wrap_for_model(skill.body, path=skill.path or "workspace skill")
    return skill.body


def _safe_desc(skill: "Skill") -> str:
    desc = str(skill.description or "")
    if skill.source == "workspace":  # collapse to one line + cap so the index can't carry an injection
        desc = re.sub(r"\s+", " ", desc).strip()[:200]
    return desc


def skills_prompt(selected: list[Skill], all_skills: list[Skill]) -> str:
    parts: list[str] = []
    if selected:
        parts.append("Relevant playbook(s) for this task — follow the steps in order:")
        for skill in selected:
            parts.append(f"\n## Playbook: {skill.name}\n{_safe_body(skill)}")
    others = [s for s in all_skills if s not in selected and s.description]
    if others:
        index = "\n".join(f"- {s.name}: {_safe_desc(s)}" for s in others)
        parts.append("\nOther available playbooks (read/apply one if it fits better):\n" + index)
    return "\n".join(parts).strip()
