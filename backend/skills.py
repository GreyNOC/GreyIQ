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

A third source is read-only: RUNTIME_DIR/agents/<slug>/SKILL.md, written by
`gn agent clone` for each cloned Hugging Face agent (see hf_agent_clone.py). Its
text came off the public internet, so it is loaded with source "cloned" and
fenced exactly like a workspace skill — see _UNTRUSTED_SOURCES.
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import trust

SKILLS_DIRNAME = "skills"
AGENTS_DIRNAME = "agents"
CLONED_PLAYBOOK = "SKILL.md"
CLONED_MANIFEST = "greyiq-agent.json"

# Sources whose body/name/description are NOT operator-authored. Everything here is
# fenced as untrusted DATA before it reaches the model: "workspace" comes from the
# repo checkout under analysis, "cloned" from a public Hugging Face agent. Only
# "user" (RUNTIME_DIR/skills and the bundled seed) is trusted enough to splice
# straight into the system prompt.
_UNTRUSTED_SOURCES = frozenset({"workspace", "cloned"})

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
    source: str  # "user" | "workspace" | "cloned"
    path: str


def _parse(text: str, source: str, path: str, fallback_name: str = "") -> Skill:
    front: dict[str, str] = {}
    body = text
    match = _FRONTMATTER.match(text)
    if match:
        for line in match.group(1).splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                front[key.strip().lower()] = value.strip()
        body = text[match.end():]
    # Skills are keyed by name, so an empty one collides. Every cloned agent's
    # playbook is literally "SKILL.md", which would make the stem identical for
    # all of them and silently drop every clone but the last — hence the caller's
    # fallback (the clone's directory name) taking precedence over the stem.
    name = front.get("name") or fallback_name or Path(path).stem
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


def cloned_agent_playbooks(runtime_dir: Path | str) -> list[Path]:
    """Each cloned Hugging Face agent's playbook, written by `gn agent clone`.

    A directory counts only when it holds BOTH the playbook and the manifest —
    the same bar hf_agent_clone.list_agents uses. `gn agent clone` stages into
    `<slug>.partial` and renames on success, so a clone killed mid-download can
    leave a playbook behind whose files were never fully verified. Requiring the
    manifest keeps that text out of the agent's prompt instead of feeding it in
    as a clone that the store itself does not acknowledge.
    """
    root = Path(runtime_dir) / AGENTS_DIRNAME
    if not root.is_dir():
        return []
    found: list[Path] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return []
    for directory in entries:
        playbook = directory / CLONED_PLAYBOOK
        if (directory.is_dir() and not directory.is_symlink() and playbook.is_file()
                and (directory / CLONED_MANIFEST).is_file()):
            found.append(playbook)
    return found


def load_skills(runtime_dir: Path, seed_dir: Path, workspace: str | Path | None) -> list[Skill]:
    ensure_user_skills(runtime_dir, seed_dir)
    by_name: dict[str, Skill] = {}
    # Precedence, lowest first: a cloned agent's playbook is remote text, so an
    # operator-authored skill of the same name must win over it; workspace skills
    # stay last so they still override the same-named global ones.
    search: list[tuple[list[Path], str]] = [
        (cloned_agent_playbooks(runtime_dir), "cloned"),
        (sorted((Path(runtime_dir) / SKILLS_DIRNAME).glob("*.md"))
         if (Path(runtime_dir) / SKILLS_DIRNAME).is_dir() else [], "user"),
    ]
    if workspace:
        directory = Path(workspace) / ".greyiq" / SKILLS_DIRNAME
        search.append((sorted(directory.glob("*.md")) if directory.is_dir() else [], "workspace"))
    for paths, source in search:
        for path in paths:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # A cloned playbook is always "SKILL.md"; its clone directory is the
            # unique part of the path, so that is its fallback name.
            fallback = path.parent.name if source == "cloned" else ""
            skill = _parse(text, source, str(path), fallback)
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
    # A "workspace" skill comes from the UNTRUSTED repo checkout, a "cloned" one from a public
    # Hugging Face agent — fence either body as DATA so a malicious playbook can't inject
    # first-party instructions into the trusted system prompt (same boundary read_file/grep
    # use). "user"/bundled skills are operator-owned → trusted.
    if skill.source in _UNTRUSTED_SOURCES:
        return trust.wrap_for_model(skill.body, path=skill.path or f"{skill.source} skill")
    return skill.body


def _safe_desc(skill: "Skill") -> str:
    desc = str(skill.description or "")
    if skill.source in _UNTRUSTED_SOURCES:  # collapse to one line + cap so the index can't carry an injection
        desc = re.sub(r"\s+", " ", desc).strip()[:200]
    return desc


def _safe_name(skill: "Skill") -> str:
    name = str(skill.name or "")
    if skill.source in _UNTRUSTED_SOURCES:  # untrusted: collapse to one line + cap so the frontmatter NAME
        name = re.sub(r"\s+", " ", name).strip()[:80]  # can't inject a newline+instruction into the prompt
    return name


def skills_prompt(selected: list[Skill], all_skills: list[Skill]) -> str:
    parts: list[str] = []
    if selected:
        parts.append("Relevant playbook(s) for this task — follow the steps in order:")
        for skill in selected:
            parts.append(f"\n## Playbook: {_safe_name(skill)}\n{_safe_body(skill)}")
    others = [s for s in all_skills if s not in selected and s.description]
    if others:
        index = "\n".join(f"- {_safe_name(s)}: {_safe_desc(s)}" for s in others)
        parts.append("\nOther available playbooks (read/apply one if it fits better):\n" + index)
    return "\n".join(parts).strip()
