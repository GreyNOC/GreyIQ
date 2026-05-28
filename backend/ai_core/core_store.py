from __future__ import annotations

import copy
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

AI_CORE_STORE_FILE = "ai_cores.json"
DEFAULT_CORE_ID = "core_greyiq_companion"
DEFAULT_DEPLOYMENT_CHANNEL = "GreyIQ Chat"

GREYIQ_TRUST_CONTRACT = {
    "privacy": "Prefer local memory and user-provided sources; do not imply cloud knowledge is available.",
    "uncertainty": "Separate what is known, what is inferred, and what needs verification.",
    "citations": "Cite local documents when they influence an answer.",
    "judgment": "Give a clear recommendation when there is enough signal, with the reason behind it.",
    "limits": "Name important limits without becoming timid or evasive.",
}

GREYIQ_RESPONSE_CONTRACT = [
    "lead_with_the_answer",
    "explain_the_reasoning_when_it_changes_the_decision",
    "offer_the_next_useful_action",
    "match_depth_to_risk_and_complexity",
    "stay_warm_precise_and_non_performative",
]

GREYIQ_STARTER_KNOWLEDGE = [
    "software_engineering",
    "systems_troubleshooting",
    "local_ai_and_training",
    "research_synthesis",
    "writing_and_editing",
    "planning_and_decision_support",
    "data_analysis",
    "security_basics",
    "personal_preference_learning",
]


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def slugify(value: str, fallback: str = "core") -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    return slug or fallback


def bump_semver(version: str) -> str:
    parts = [int(part) if part.isdigit() else 0 for part in str(version or "0.1.0").split(".")]
    while len(parts) < 3:
        parts.append(0)
    parts[2] += 1
    return ".".join(str(part) for part in parts[:3])


def default_templates() -> list[dict[str, Any]]:
    return [
        {
            "id": "tpl_greyiq_companion",
            "name": "GreyIQ Companion",
            "mode": "Friendly Power",
            "type": "local_companion",
            "description": (
                "Soft, friendly, very powerful local AI that learns personal choices, "
                "remembers useful preferences, and helps with serious work without becoming cold."
            ),
            "personality": "warm",
            "skills": [
                "conversation",
                "coding",
                "research",
                "planning",
                "writing",
                "debugging",
                "local_training",
                "knowledge_retrieval",
            ],
            "safetyMode": "open_local",
            "confidencePolicy": [
                "plain_language",
                "use_local_memory",
                "name_uncertainty",
                "separate_fact_from_inference",
                "cite_local_sources",
            ],
            "trustContract": GREYIQ_TRUST_CONTRACT,
            "responseContract": GREYIQ_RESPONSE_CONTRACT,
            "starterKnowledge": GREYIQ_STARTER_KNOWLEDGE,
            "sourceIds": [
                "src_starter_knowledge",
                "src_personal_choices",
                "src_preferred_examples",
                "src_local_notes",
            ],
        },
        {
            "id": "tpl_greyiq_builder",
            "name": "GreyIQ Builder",
            "mode": "Build Partner",
            "type": "builder",
            "description": (
                "A practical maker that can plan, code, debug, test, document, and turn fuzzy goals "
                "into working systems with sober tradeoff calls."
            ),
            "personality": "direct",
            "skills": [
                "coding",
                "debugging",
                "architecture",
                "automation",
                "release",
                "testing",
                "systems_design",
            ],
            "safetyMode": "open_local",
            "confidencePolicy": [
                "show_next_step",
                "verify_with_tests",
                "state_assumptions",
                "stay_concrete",
            ],
            "trustContract": {
                **GREYIQ_TRUST_CONTRACT,
                "verification": "Prefer commands, checks, and observable results over vibes.",
            },
            "responseContract": [
                "define_the_boundary",
                "name_the_likely_fault_or_design_choice",
                "give_the_smallest_test_or_patch",
                "explain_tradeoffs_briefly",
            ],
            "starterKnowledge": [
                "software_engineering",
                "debugging",
                "architecture",
                "automation",
                "release_management",
                "local_development",
            ],
            "sourceIds": ["src_starter_knowledge", "src_preferred_examples", "src_imported_docs"],
        },
        {
            "id": "tpl_greyiq_researcher",
            "name": "GreyIQ Researcher",
            "mode": "Deep Research",
            "type": "researcher",
            "description": (
                "A patient research partner for documents, notes, comparisons, summaries, and careful "
                "synthesis that marks evidence quality."
            ),
            "personality": "curious",
            "skills": [
                "research",
                "summarization",
                "comparison",
                "writing",
                "knowledge_base",
                "source_review",
                "decision_memos",
            ],
            "safetyMode": "open_local",
            "confidencePolicy": [
                "cite_local_sources",
                "separate_fact_from_guess",
                "mark_source_quality",
                "show_open_questions",
            ],
            "trustContract": {
                **GREYIQ_TRUST_CONTRACT,
                "evidence": "Rank claims by source strength and say when the answer is synthesis.",
            },
            "responseContract": [
                "summarize_the_answer_first",
                "separate_evidence_from_interpretation",
                "compare_options_when_useful",
                "end_with_open_questions_or_next_checks",
            ],
            "starterKnowledge": [
                "research_synthesis",
                "document_analysis",
                "writing_and_editing",
                "data_analysis",
                "planning",
            ],
            "sourceIds": ["src_starter_knowledge", "src_imported_docs", "src_local_notes"],
        },
    ]


def default_sources() -> list[dict[str, Any]]:
    return [
        {
            "id": "src_starter_knowledge",
            "name": "Starter Knowledge",
            "type": "seed",
            "icon": "doc",
            "connection": "connected",
            "permission": "local_seed",
            "records": 9,
            "lastSyncedAt": None,
            "lastTrainedAt": None,
            "includedCores": [DEFAULT_CORE_ID],
            "trustLevel": "curated_seed",
            "sensitivity": "public_general",
        },
        {
            "id": "src_personal_choices",
            "name": "Personal Choices",
            "type": "preferences",
            "icon": "doc",
            "connection": "connected",
            "permission": "local_private",
            "records": 0,
            "lastSyncedAt": None,
            "lastTrainedAt": None,
            "includedCores": [DEFAULT_CORE_ID],
            "trustLevel": "personal",
            "sensitivity": "private",
        },
        {
            "id": "src_preferred_examples",
            "name": "Preferred Examples",
            "type": "files",
            "icon": "doc",
            "connection": "connected",
            "permission": "local_private",
            "records": 0,
            "lastSyncedAt": None,
            "lastTrainedAt": None,
            "includedCores": [DEFAULT_CORE_ID],
            "trustLevel": "personal",
            "sensitivity": "private",
        },
        {
            "id": "src_local_notes",
            "name": "Local Notes",
            "type": "files",
            "icon": "doc",
            "connection": "connected",
            "permission": "local_private",
            "records": 0,
            "lastSyncedAt": None,
            "lastTrainedAt": None,
            "includedCores": [DEFAULT_CORE_ID],
            "trustLevel": "personal",
            "sensitivity": "private",
        },
        {
            "id": "src_imported_docs",
            "name": "Imported Documents",
            "type": "files",
            "icon": "doc",
            "connection": "connected",
            "permission": "local_private",
            "records": 0,
            "lastSyncedAt": None,
            "lastTrainedAt": None,
            "includedCores": [],
            "trustLevel": "user_selected",
            "sensitivity": "depends_on_source",
        },
    ]


def core_from_template(template: dict[str, Any], *, core_id: str, name: str | None = None) -> dict[str, Any]:
    return {
        "id": core_id,
        "name": name or str(template.get("name") or "Untitled Core"),
        "mode": str(template.get("mode") or "Custom"),
        "type": str(template.get("type") or "custom"),
        "description": str(template.get("description") or ""),
        "personality": str(template.get("personality") or "calm"),
        "skills": list(template.get("skills") or []),
        "safetyMode": str(template.get("safetyMode") or "open_local"),
        "confidencePolicy": list(template.get("confidencePolicy") or ["plain_language"]),
        "trustContract": copy.deepcopy(template.get("trustContract") or GREYIQ_TRUST_CONTRACT),
        "responseContract": list(template.get("responseContract") or GREYIQ_RESPONSE_CONTRACT),
        "starterKnowledge": list(template.get("starterKnowledge") or []),
        "status": "online",
        "activeVersion": "0.1.0",
        "trainingEnabled": True,
        "lastTrainedAt": None,
        "readinessScore": 0.25,
        "templateId": str(template.get("id") or ""),
        "createdAt": utc_now_iso(),
        "updatedAt": utc_now_iso(),
    }


def default_state() -> dict[str, Any]:
    templates = default_templates()
    default_core = core_from_template(templates[0], core_id=DEFAULT_CORE_ID)
    default_core.update(
        {
            "activeVersion": "1.0.0",
            "readinessScore": 0.86,
            "createdAt": None,
            "updatedAt": None,
        }
    )
    return {
        "templates": templates,
        "cores": [default_core],
        "sources": default_sources(),
        "jobs": [],
        "versions": [
            {
                "id": "ver_1_0_0",
                "coreId": DEFAULT_CORE_ID,
                "version": "1.0.0",
                "trainedAt": None,
                "trainedBy": "system",
                "sourcesUsed": [
                    "src_starter_knowledge",
                    "src_personal_choices",
                    "src_preferred_examples",
                ],
                "sourceSnapshotIds": [],
                "modelProvider": "greyiq-local",
                "embeddingModel": "greyiq-memory-v1",
                "retrievalConfig": {"topK": 8, "rerank": True, "sourceQuality": True},
                "safetyPolicyVersion": "open-local",
                "evaluationScore": None,
                "deploymentStatus": "production",
                "rollbackAvailable": False,
            }
        ],
        "deployments": [
            {
                "id": "dep_chat_main",
                "channel": DEFAULT_DEPLOYMENT_CHANNEL,
                "coreId": DEFAULT_CORE_ID,
                "version": "1.0.0",
                "status": "active",
                "since": None,
            }
        ],
        "audit": [
            {
                "id": "ev_init",
                "at": None,
                "who": "system",
                "action": "core_published",
                "target": "core_greyiq_companion@1.0.0",
                "summary": "Default core published to GreyIQ Chat",
            }
        ],
    }


class AICoreStore:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.path = self.base_dir / "data" / AI_CORE_STORE_FILE

    def load(self) -> dict[str, Any]:
        state = default_state()
        if self.path.exists():
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    for key in state:
                        if isinstance(payload.get(key), list):
                            state[key] = payload[key]
            except (OSError, json.JSONDecodeError):
                pass
        self._ensure_defaults(state)
        return state

    def save(self, state: dict[str, Any]) -> dict[str, Any]:
        self._ensure_defaults(state)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_suffix(".tmp")
        payload = json.dumps(state, indent=2)
        try:
            tmp_path.write_text(payload, encoding="utf-8")
            tmp_path.replace(self.path)
        except PermissionError:
            # OneDrive/Windows can briefly deny atomic replaces. The file is
            # small and operator-local, so a direct write is a practical fallback.
            self.path.write_text(payload, encoding="utf-8")
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        return state

    def audit(self, state: dict[str, Any], action: str, target: str, summary: str, *, who: str = "operator") -> None:
        state.setdefault("audit", []).insert(
            0,
            {
                "id": f"ev_{uuid4().hex[:12]}",
                "at": utc_now_iso(),
                "who": who,
                "action": action,
                "target": target,
                "summary": summary,
            },
        )
        del state["audit"][200:]

    def create_from_template(
        self, template_id: str, *, name: str | None = None, who: str = "operator"
    ) -> dict[str, Any]:
        state = self.load()
        template = next((item for item in state["templates"] if item.get("id") == template_id), None)
        if template is None:
            raise ValueError(f"Unknown AI Core template: {template_id}")
        base_id = slugify(name or str(template.get("name") or "core"), "core")
        core_id = f"core_{base_id}_{uuid4().hex[:8]}"
        core = core_from_template(template, core_id=core_id, name=name)
        state["cores"].append(core)
        self._set_source_membership(state, core_id, list(template.get("sourceIds") or []))
        self._ensure_deployment(state, core_id, core["activeVersion"])
        self.audit(state, "core_created", core_id, f"Created core {core['name']} from template {template_id}", who=who)
        self.save(state)
        return state

    def save_core(self, core: dict[str, Any], *, who: str = "operator") -> dict[str, Any]:
        if not isinstance(core, dict):
            raise ValueError("Core payload must be an object.")
        core_id = str(core.get("id") or "").strip()
        if not core_id:
            core_id = f"core_custom_{uuid4().hex[:8]}"
            core["id"] = core_id
        now = utc_now_iso()
        state = self.load()
        existing_index = next((idx for idx, item in enumerate(state["cores"]) if item.get("id") == core_id), -1)
        if existing_index >= 0:
            merged = {**state["cores"][existing_index], **copy.deepcopy(core), "updatedAt": now}
            state["cores"][existing_index] = merged
        else:
            merged = {
                "name": "Untitled Core",
                "mode": "Custom",
                "type": "custom",
                "description": "",
                "personality": "calm",
                "skills": [],
                "safetyMode": "open_local",
                "confidencePolicy": ["plain_language"],
                "trustContract": copy.deepcopy(GREYIQ_TRUST_CONTRACT),
                "responseContract": list(GREYIQ_RESPONSE_CONTRACT),
                "starterKnowledge": [],
                "status": "draft",
                "activeVersion": "0.1.0",
                "trainingEnabled": True,
                "lastTrainedAt": None,
                "readinessScore": 0.10,
                "createdAt": now,
                "updatedAt": now,
                **copy.deepcopy(core),
            }
            state["cores"].append(merged)
            self._ensure_deployment(state, core_id, str(merged.get("activeVersion") or "0.1.0"))
        self.audit(state, "core_saved", core_id, f"Saved core {merged.get('name', core_id)}", who=who)
        self.save(state)
        return state

    def delete_core(self, core_id: str, *, who: str = "operator") -> dict[str, Any]:
        state = self.load()
        if len(state["cores"]) <= 1:
            raise ValueError("At least one AI Core must remain.")
        before = len(state["cores"])
        state["cores"] = [core for core in state["cores"] if core.get("id") != core_id]
        if len(state["cores"]) == before:
            raise ValueError(f"AI Core not found: {core_id}")
        state["versions"] = [version for version in state["versions"] if version.get("coreId") != core_id]
        state["deployments"] = [dep for dep in state["deployments"] if dep.get("coreId") != core_id]
        for source in state["sources"]:
            source["includedCores"] = [item for item in source.get("includedCores", []) if item != core_id]
        self.audit(state, "core_deleted", core_id, f"Deleted core {core_id}", who=who)
        self.save(state)
        return state

    def start_job(
        self, core_id: str, source_ids: list[str], *, who: str = "operator"
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        state = self.load()
        core = self._find_core(state, core_id)
        if core is None:
            raise ValueError(f"AI Core not found: {core_id}")
        now = utc_now_iso()
        job = {
            "id": f"job_{uuid4().hex[:12]}",
            "coreId": core_id,
            "sources": list(source_ids),
            "status": "queued",
            "recordsProcessed": 0,
            "recordsSkipped": 0,
            "startedBy": who,
            "startedAt": now,
            "completedAt": None,
            "outputVersion": None,
            "progress": 0.02,
        }
        state["jobs"].insert(0, job)
        del state["jobs"][100:]
        self._set_source_membership(state, core_id, source_ids)
        self.audit(
            state,
            "training_started",
            str(job["id"]),
            f"Training started for {core.get('name', core_id)}",
            who=who,
        )
        self.save(state)
        return state, job

    def sync_job(
        self,
        state: dict[str, Any],
        job_id: str,
        *,
        status: str,
        progress: float,
        records_processed: int = 0,
        output_version: str | None = None,
        completed: bool = False,
        failed: bool = False,
        who: str = "operator",
    ) -> dict[str, Any]:
        job = next((item for item in state.get("jobs", []) if item.get("id") == job_id), None)
        if job is None:
            return state
        job["status"] = status
        job["progress"] = max(0.0, min(1.0, float(progress)))
        job["recordsProcessed"] = int(records_processed or 0)
        if output_version:
            job["outputVersion"] = output_version
        if completed or failed:
            job["completedAt"] = job.get("completedAt") or utc_now_iso()
        if completed and not job.get("_versionRecorded"):
            version = self.create_version_record(state, job["coreId"], job.get("sources", []), who=who)
            job["outputVersion"] = version["version"]
            job["_versionRecorded"] = True
        self.save(state)
        return state

    def delete_job(self, job_id: str, *, who: str = "operator") -> dict[str, Any]:
        clean_job_id = str(job_id or "").strip()
        if not clean_job_id:
            raise ValueError("Training job id is required.")
        state = self.load()
        before = len(state.get("jobs", []))
        state["jobs"] = [job for job in state.get("jobs", []) if str(job.get("id") or "") != clean_job_id]
        if len(state["jobs"]) == before:
            raise ValueError(f"Training job not found: {clean_job_id}")
        self.audit(state, "training_job_deleted", clean_job_id, f"Deleted training job {clean_job_id}", who=who)
        self.save(state)
        return state

    def create_version_record(
        self,
        state: dict[str, Any],
        core_id: str,
        source_ids: list[str],
        *,
        who: str = "operator",
    ) -> dict[str, Any]:
        core = self._find_core(state, core_id)
        if core is None:
            raise ValueError(f"AI Core not found: {core_id}")
        next_version = bump_semver(str(core.get("activeVersion") or "0.1.0"))
        record = {
            "id": f"ver_{next_version.replace('.', '_')}_{uuid4().hex[:8]}",
            "coreId": core_id,
            "version": next_version,
            "trainedAt": utc_now_iso(),
            "trainedBy": who,
            "sourcesUsed": list(source_ids),
            "sourceSnapshotIds": [],
            "modelProvider": "greyiq-local",
            "embeddingModel": "greyiq-memory-v1",
            "retrievalConfig": {"topK": 6, "rerank": True},
            "safetyPolicyVersion": "open-local",
            "evaluationScore": None,
            "deploymentStatus": "staging",
            "rollbackAvailable": True,
        }
        state["versions"].insert(0, record)
        core["lastTrainedAt"] = record["trainedAt"]
        core["readinessScore"] = min(0.98, float(core.get("readinessScore") or 0.3) + 0.10)
        for source in state.get("sources", []):
            if source.get("id") in source_ids:
                source["lastTrainedAt"] = record["trainedAt"]
        self.audit(state, "version_created", f"{core_id}@{next_version}", f"Created version {next_version}", who=who)
        return record

    def promote_version(self, core_id: str, version: str, *, who: str = "operator") -> dict[str, Any]:
        state = self.load()
        core = self._find_core(state, core_id)
        if core is None:
            raise ValueError(f"AI Core not found: {core_id}")
        target = None
        for record in state["versions"]:
            if record.get("coreId") != core_id:
                continue
            if record.get("deploymentStatus") == "production":
                record["deploymentStatus"] = "archived"
                record["rollbackAvailable"] = True
            if record.get("version") == version:
                target = record
        if target is None:
            raise ValueError(f"Version not found: {core_id}@{version}")
        target["deploymentStatus"] = "production"
        target["rollbackAvailable"] = False
        core["activeVersion"] = version
        core["status"] = "online"
        self._ensure_deployment(state, core_id, version)
        self.audit(state, "version_promoted", f"{core_id}@{version}", f"Version {version} promoted", who=who)
        self.save(state)
        return state

    def _ensure_defaults(self, state: dict[str, Any]) -> None:
        defaults = default_state()
        for key, value in defaults.items():
            if not isinstance(state.get(key), list):
                state[key] = copy.deepcopy(value)
        templates_by_id = {item.get("id"): item for item in state["templates"]}
        for template in default_templates():
            existing = templates_by_id.get(template["id"])
            if existing is None:
                state["templates"].append(copy.deepcopy(template))
            else:
                existing.update(copy.deepcopy(template))
        if not state["cores"]:
            state["cores"] = defaults["cores"]
        default_core = self._find_core(state, DEFAULT_CORE_ID)
        if default_core is not None:
            fresh_default = copy.deepcopy(defaults["cores"][0])
            for key in (
                "name",
                "mode",
                "type",
                "description",
                "personality",
                "skills",
                "safetyMode",
                "confidencePolicy",
                "trustContract",
                "responseContract",
                "starterKnowledge",
                "templateId",
            ):
                default_core[key] = fresh_default[key]
            default_core.setdefault("activeVersion", fresh_default["activeVersion"])
            default_core["readinessScore"] = max(float(default_core.get("readinessScore") or 0.0), 0.86)
        sources_by_id = {item.get("id"): item for item in state["sources"]}
        for source in default_sources():
            existing = sources_by_id.get(source["id"])
            if existing is None:
                state["sources"].append(copy.deepcopy(source))
            else:
                for key, value in source.items():
                    if key not in {"includedCores", "lastSyncedAt", "lastTrainedAt", "records"}:
                        existing[key] = copy.deepcopy(value)
                if source["id"] == "src_starter_knowledge":
                    included = set(existing.get("includedCores") or [])
                    included.add(DEFAULT_CORE_ID)
                    existing["includedCores"] = sorted(included)

    def _find_core(self, state: dict[str, Any], core_id: str) -> dict[str, Any] | None:
        return next((core for core in state.get("cores", []) if core.get("id") == core_id), None)

    def _ensure_deployment(self, state: dict[str, Any], core_id: str, version: str) -> None:
        deployment = next(
            (
                item
                for item in state.get("deployments", [])
                if item.get("coreId") == core_id and item.get("channel") == DEFAULT_DEPLOYMENT_CHANNEL
            ),
            None,
        )
        if deployment is None:
            state.setdefault("deployments", []).append(
                {
                    "id": f"dep_{uuid4().hex[:10]}",
                    "channel": DEFAULT_DEPLOYMENT_CHANNEL,
                    "coreId": core_id,
                    "version": version,
                    "status": "active",
                    "since": utc_now_iso(),
                }
            )
        else:
            deployment["version"] = version
            deployment["status"] = "active"
            deployment["since"] = utc_now_iso()

    def _set_source_membership(self, state: dict[str, Any], core_id: str, source_ids: list[str]) -> None:
        selected = set(source_ids)
        for source in state.get("sources", []):
            included = set(source.get("includedCores") or [])
            if source.get("id") in selected:
                included.add(core_id)
            else:
                included.discard(core_id)
            source["includedCores"] = sorted(included)
