"""Dataset-level recursive learning for GreyIQ.

The live model never updates its own weights.  This module records experience as
JSONL, applies deterministic admission gates, and materializes only verified,
deduplicated examples as trainer-readable text.  Model training and promotion
remain separate operations.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
DEFAULT_THRESHOLD = 0.90
SECURITY_THRESHOLD = 0.96
_LOCK = threading.RLock()
_SECURITY_TERMS = (
    "vulnerability", "exploit", "ssrf", "xss", "sql injection", "authentication",
    "authorization", "credential", "malware", "ransomware", "kerberos", "cryptograph",
    "cve-", "penetration test", "bug bounty",
)


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def is_security_sensitive(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in _SECURITY_TERMS)


@dataclass(slots=True)
class ExperienceScore:
    knowledge_confidence: float = 0.0
    source_confidence: float = 0.0
    answer_confidence: float = 0.0
    user_correction: float = 0.0
    tool_verification: float = 0.0
    critic_score: float = 0.0
    novelty_score: float = 0.0

    @property
    def learning_score(self) -> float:
        # A correction is valuable only after it has been converted into a clean
        # verified target; it therefore boosts the knowledge component instead of
        # bypassing the source/tool gates.
        knowledge = max(_bounded(self.knowledge_confidence), _bounded(self.user_correction))
        score = (
            _bounded(self.source_confidence) * 0.25
            + _bounded(self.tool_verification) * 0.25
            + _bounded(self.critic_score) * 0.20
            + knowledge * 0.15
            + _bounded(self.novelty_score) * 0.15
        )
        return round(score, 6)


@dataclass(slots=True)
class Experience:
    prompt: str
    response: str
    verified_answer: str = ""
    context: str = ""
    source: str = ""
    model_version: str = "unknown"
    outcome: str = "pending"
    security_sensitive: bool = False
    score: ExperienceScore = field(default_factory=ExperienceScore)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    schema_version: int = SCHEMA_VERSION

    @property
    def target(self) -> str:
        return (self.verified_answer or self.response).strip()

    @property
    def example_id(self) -> str:
        normalized = "\n".join((self.prompt.strip().lower(), self.target.lower()))
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def as_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["learning_score"] = self.score.learning_score
        record["example_id"] = self.example_id
        return record


class LearningEngine:
    """Append-only experience store with fail-closed replay admission."""

    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self.root = self.base_dir / "datasets"
        self.pools = {
            name: self.root / name
            for name in ("foundation", "manuals", "conversations", "verified", "corrections", "failures", "replay")
        }
        for path in self.pools.values():
            path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def threshold(experience: Experience) -> float:
        return SECURITY_THRESHOLD if experience.security_sensitive else DEFAULT_THRESHOLD

    @staticmethod
    def verify(experience: Experience) -> tuple[bool, str]:
        if len(experience.prompt.strip()) < 4:
            return False, "prompt_too_short"
        if len(experience.target) < 8:
            return False, "target_too_short"
        if experience.score.learning_score < LearningEngine.threshold(experience):
            return False, "score_below_threshold"
        # High confidence must come from evidence, not the model grading itself.
        if max(experience.score.source_confidence, experience.score.tool_verification) < 0.90:
            return False, "no_trusted_verification"
        if experience.security_sensitive and not experience.verified_answer.strip():
            return False, "security_answer_not_explicitly_verified"
        return True, "verified"

    def record(self, experience: Experience) -> dict[str, Any]:
        passed, reason = self.verify(experience)
        experience.outcome = "verified" if passed else "rejected"
        pool = "verified" if passed else "failures"
        record = experience.as_record()
        record["verification_reason"] = reason
        self._append_jsonl(self.pools["conversations"] / "experiences.jsonl", record)
        self._append_jsonl(self.pools[pool] / "experiences.jsonl", record)
        if passed:
            self.rebuild_replay()
        return record

    def weakness_summary(self, limit: int = 8) -> list[dict[str, Any]]:
        """Return deterministic failure clusters for curriculum generation."""
        path = self.pools["failures"] / "experiences.jsonl"
        counts: dict[str, int] = {}
        if not path.exists():
            return []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            reason = str(row.get("verification_reason") or "unknown")
            counts[reason] = counts.get(reason, 0) + 1
        return [
            {"reason": reason, "count": count}
            for reason, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[: max(1, limit)]
        ]

    def status(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for name in ("conversations", "verified", "corrections", "failures"):
            total = 0
            for path in self.pools[name].glob("*.jsonl"):
                try:
                    total += sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
                except OSError:
                    continue
            counts[name] = total
        replay_path = self.pools["replay"] / "verified_replay.txt"
        replay_examples = 0
        try:
            replay_examples = replay_path.read_text(encoding="utf-8").count("<START_CONVO>")
        except OSError:
            pass
        return {
            **counts,
            "replay_examples": replay_examples,
            "weaknesses": self.weakness_summary(),
            "security_threshold": SECURITY_THRESHOLD,
            "default_threshold": DEFAULT_THRESHOLD,
        }

    def record_correction(
        self,
        prompt: str,
        corrected_answer: str,
        *,
        source: str,
        model_version: str = "unknown",
        tool_verified: bool = False,
        security_sensitive: bool = False,
    ) -> dict[str, Any]:
        score = ExperienceScore(
            knowledge_confidence=1.0,
            source_confidence=1.0,
            answer_confidence=1.0,
            user_correction=1.0,
            tool_verification=1.0 if tool_verified else 0.9,
            critic_score=1.0,
            novelty_score=1.0,
        )
        exp = Experience(
            prompt=prompt,
            response="",
            verified_answer=corrected_answer,
            source=source,
            model_version=model_version,
            security_sensitive=security_sensitive,
            score=score,
        )
        record = exp.as_record()
        self._append_jsonl(self.pools["corrections"] / "corrections.jsonl", record)
        return self.record(exp)

    def rebuild_replay(self) -> Path:
        """Deduplicate verified records and atomically create the trainer corpus."""
        source = self.pools["verified"] / "experiences.jsonl"
        unique: dict[str, dict[str, Any]] = {}
        if source.exists():
            for line in source.read_text(encoding="utf-8").splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = str(item.get("example_id") or "")
                if key and key not in unique:
                    unique[key] = item

        blocks = []
        for item in unique.values():
            prompt = str(item.get("prompt") or "").strip()
            target = str(item.get("verified_answer") or item.get("response") or "").strip()
            if prompt and target:
                blocks.append(f"<START_CONVO>\n<USER>\n{prompt}\n<ASSISTANT>\n{target}\n<END_CONVO>")
        payload = "\n\n".join(blocks)
        replay_path = self.pools["replay"] / "verified_replay.txt"
        self._atomic_write(replay_path, payload + ("\n" if payload else ""))

        # The trainer includes this file when the default Preferred Examples source is selected.
        trainer_path = self.base_dir / "data" / "greyiq_verified_replay.txt"
        trainer_path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write(trainer_path, payload + ("\n" if payload else ""))
        return replay_path

    @staticmethod
    def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        with _LOCK:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line)

    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        temp = path.with_suffix(path.suffix + ".tmp")
        with _LOCK:
            temp.write_text(text, encoding="utf-8")
            temp.replace(path)


class ModelRegistry:
    """Versioned candidate/stable checkpoints with an atomic promotion gate."""

    def __init__(self, base_dir: str | Path):
        self.root = Path(base_dir) / "checkpoints"
        self.stable_dir = self.root / "stable"
        self.candidate_dir = self.root / "candidates"
        self.rollback_dir = self.root / "rollback"
        for path in (self.stable_dir, self.candidate_dir, self.rollback_dir):
            path.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.root / "registry.json"

    def stage_candidate(self, checkpoint: str | Path, metrics: dict[str, float]) -> Path:
        source = Path(checkpoint)
        if not source.is_file():
            raise FileNotFoundError(source)
        manifest = self._manifest()
        sequence = int(manifest.get("sequence", 0)) + 1
        target = self.candidate_dir / f"greyiq_candidate_{sequence:05d}{source.suffix or '.pt'}"
        shutil.copy2(source, target)
        manifest.update({"sequence": sequence, "candidate": target.name, "candidate_metrics": metrics})
        self._write_manifest(manifest)
        return target

    def promote_if_better(
        self,
        candidate: str | Path,
        candidate_metrics: dict[str, float],
        *,
        higher_is_better: tuple[str, ...] = ("accuracy", "safety", "groundedness"),
        lower_is_better: tuple[str, ...] = ("loss", "hallucination"),
    ) -> bool:
        candidate_path = Path(candidate)
        if not candidate_path.is_file() or candidate_path.parent.resolve() != self.candidate_dir.resolve():
            raise ValueError("candidate must be a staged checkpoint")
        manifest = self._manifest()
        stable_metrics = manifest.get("stable_metrics") or {}
        if stable_metrics and not self._strictly_better(
            candidate_metrics, stable_metrics, higher_is_better=higher_is_better, lower_is_better=lower_is_better
        ):
            manifest.update({"last_decision": "rollback", "rejected_candidate": candidate_path.name})
            self._write_manifest(manifest)
            return False

        sequence = int(manifest.get("sequence", 0))
        stable_path = self.stable_dir / f"greyiq_stable_{sequence:05d}{candidate_path.suffix}"
        current_name = str(manifest.get("stable") or "")
        current = self.stable_dir / current_name if current_name else None
        if current and current.is_file():
            shutil.copy2(current, self.rollback_dir / current.name)
        temp = stable_path.with_suffix(stable_path.suffix + ".tmp")
        shutil.copy2(candidate_path, temp)
        temp.replace(stable_path)
        manifest.update(
            {
                "stable": stable_path.name,
                "stable_metrics": candidate_metrics,
                "last_decision": "promote",
                "promoted_at": datetime.now(UTC).isoformat(),
            }
        )
        self._write_manifest(manifest)
        return True

    @staticmethod
    def _strictly_better(
        candidate: dict[str, float],
        stable: dict[str, float],
        *,
        higher_is_better: tuple[str, ...],
        lower_is_better: tuple[str, ...],
    ) -> bool:
        compared = 0
        improved = False
        for key in higher_is_better:
            if key in candidate and key in stable:
                compared += 1
                if float(candidate[key]) < float(stable[key]):
                    return False
                improved |= float(candidate[key]) > float(stable[key])
        for key in lower_is_better:
            if key in candidate and key in stable:
                compared += 1
                if float(candidate[key]) > float(stable[key]):
                    return False
                improved |= float(candidate[key]) < float(stable[key])
        return compared > 0 and improved

    def _manifest(self) -> dict[str, Any]:
        try:
            value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_manifest(self, value: dict[str, Any]) -> None:
        LearningEngine._atomic_write(self.manifest_path, json.dumps(value, indent=2, sort_keys=True) + "\n")
