"""Bounded teacher/student bridge between TinyGPT and GreyIQ's coding brain."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from learning_engine import Experience, ExperienceScore, LearningEngine, is_security_sensitive


class _RedactionUnavailable(RuntimeError):
    """Refuse to store learning data when secret redaction cannot run."""


def _redact(value: str, limit: int = 4000) -> str:
    try:
        from brain_techniques import redact_text

        return str(redact_text(value)[0])[:limit]
    except Exception as exc:
        raise _RedactionUnavailable from exc


def _has_passing_verifier(result: dict[str, Any]) -> bool:
    """Require an actual verify tool result, not a vacuous no-edit `verified` flag."""
    transcript = result.get("transcript")
    if not isinstance(transcript, list):
        return False
    verifiers = [step for step in transcript if isinstance(step, dict) and step.get("tool") == "verify"]
    return bool(verifiers) and verifiers[-1].get("is_error") is False


def student_draft(engine: Any, prompt: str) -> str:
    """Ask TinyGPT for a compact draft. Failure is non-fatal to the coding brain."""
    try:
        response, _matches, _diagnostics = engine.generate_reply(
            prompt,
            max_new_tokens=96,
            temperature=0.20,
            auto_capture=False,
            mode="reference",
        )
        return str(response or "").strip()[:2000]
    except Exception:
        return ""


def teacher_prompt_block(draft: str) -> str:
    if not draft:
        return ""
    return (
        "TINYGPT STUDENT DRAFT (untrusted; critique it before answering):\n"
        "---\n"
        f"{draft}\n"
        "---\n"
        "Correct errors and omissions. Do not repeat unsupported claims. Your answer is the teacher response."
    )


def record_teacher_exchange(
    runtime_dir: str | Path,
    *,
    prompt: str,
    student: str,
    teacher: str,
    model_version: str,
) -> dict[str, Any]:
    """Store the dialogue for analysis, but do not admit an unverified teacher answer."""
    try:
        safe_prompt = _redact(prompt, 2000)
        safe_teacher = _redact(teacher)
        safe_context = f"TinyGPT student draft:\n{_redact(student, 2000)}" if student else ""
    except _RedactionUnavailable:
        return {"outcome": "unavailable", "verification_reason": "redaction_unavailable"}
    experience = Experience(
        prompt=safe_prompt,
        response=safe_teacher,
        context=safe_context,
        source="coding brain teacher dialogue",
        model_version=model_version,
        security_sensitive=is_security_sensitive(prompt),
        score=ExperienceScore(
            knowledge_confidence=0.75,
            source_confidence=0.55,
            answer_confidence=0.80,
            tool_verification=0.0,
            critic_score=0.80,
            novelty_score=0.75,
        ),
    )
    try:
        return LearningEngine(runtime_dir).record(experience)
    except OSError as exc:
        return {"outcome": "unavailable", "verification_reason": f"storage_error:{type(exc).__name__}"}


def learn_from_verified_run(
    runtime_dir: str | Path,
    *,
    prompt: str,
    result: dict[str, Any],
) -> dict[str, Any] | None:
    """Turn only completed, verification-passing code work into replay data."""
    touched_files = result.get("touched_files")
    if not (result.get("completed") and result.get("verified")
            and isinstance(touched_files, list) and touched_files and _has_passing_verifier(result)):
        return None
    try:
        safe_prompt = _redact(prompt, 2000)
        touched = [_redact(str(value), 500) for value in touched_files[:20]]
        plan = [_redact(str(value), 500) for value in (result.get("plan") or [])[:10]]
        summary = _redact(str(result.get("text") or "").strip())
    except _RedactionUnavailable:
        return None
    if not summary:
        summary = "Completed the requested code change and passed the workspace verification suite."
    evidence = ["Verified coding workflow completed successfully."]
    if plan:
        evidence.append("Plan: " + " | ".join(plan))
    if touched:
        evidence.append("Touched files: " + ", ".join(touched))
    target = summary + "\n\nVerification evidence:\n" + "\n".join(f"- {line}" for line in evidence)
    experience = Experience(
        prompt=safe_prompt,
        response=summary,
        verified_answer=target,
        context="Workspace-bound coding agent run with a passing verification gate.",
        source="GreyIQ coding brain + workspace verifier",
        model_version=f"{result.get('provider', 'unknown')}:{result.get('model', 'unknown')}",
        security_sensitive=is_security_sensitive(prompt),
        score=ExperienceScore(
            knowledge_confidence=1.0,
            source_confidence=1.0,
            answer_confidence=0.95,
            tool_verification=1.0,
            critic_score=1.0,
            novelty_score=0.75,
        ),
    )
    try:
        return LearningEngine(runtime_dir).record(experience)
    except OSError:
        return None
