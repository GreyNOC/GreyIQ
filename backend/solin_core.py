from __future__ import annotations

import difflib
import inspect
import json
import math
import os
import re
import threading
import unicodedata
import urllib.parse
import urllib.request
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F

from solin_typo import normalize_known_typos

CONFIG_FILE = "solin_config.json"
VOCAB_FILE = "solin_vocab.json"
INFERENCE_CONFIG_FILE = "solin_inference_config.json"
RUNTIME_CONFIG_FILE = "solin_runtime_config.json"
SAFETY_CONFIG_FILE = "greyiq_open_policy.json"
AUDIT_LOG_FILE = "greyiq_policy_audit.log"
DEFAULT_DATA_FOLDER = "data"
CHAT_TRAIN_FILE = "chat_training_auto.txt"
CHAT_MEMORY_FILE = "chat_memory.jsonl"
MAX_RECENT_TURNS = 6

SOURCE_ID_BY_FILE = {
    "train.txt": "src_starter_knowledge",
    "greyiq_starter_knowledge.txt": "src_starter_knowledge",
    "greyiq_bug_bounty_knowledge.txt": "src_bug_bounty",
    "greyiq_personal_choices.txt": "src_personal_choices",
    "greyiq_profile.txt": "src_personal_choices",
    "greyiq_preferred_examples.txt": "src_preferred_examples",
    "greyiq_local_notes.txt": "src_local_notes",
    "greyiq_imported_docs.txt": "src_imported_docs",
    "greyiq_repo_knowledge.txt": "src_imported_docs",
}
GENERATED_KNOWLEDGE_FILES = {
    "chat_memory.jsonl",
    "chat_training_auto.txt",
    "combined_train.txt",
    "greyiq_selected_sources.txt",
}

# Retrieval trust multiplier by SOURCE FILE NAME, applied to the search score before the
# min_score cut. Rationale: greyiq_manual_pdfs.txt is ~6.27 MB of native-text PDF extract
# (sensor fusion, category theory, English-language textbooks) sitting in the SAME lexical
# index as 9.4 KB of actual bug-bounty knowledge — roughly 99.8% of the corpus by bytes and
# overwhelmingly off-domain. The hardcoded "practice makes perfect" / "ch\d+.indd" junk
# filters downstream in _compress_context are the smoking gun that it was already winning
# retrievals it should not. Down-weighting it (and lifting the curated corpus) fixes the
# RANKING without removing anything: every chunk is still indexed, still citable, and still
# reachable through exactly the same source_ids filter as before — a deliberate choice over
# re-keying its source id, which would have silently dropped it out of every existing core's
# saved sourceIds with no UI to add it back.
_SOURCE_TRUST_BY_FILE: dict[str, float] = {
    "greyiq_bug_bounty_knowledge.txt": 1.25,
    "greyiq_manual_pdfs.txt": 0.70,
}


def _source_trust(source_name: str) -> float:
    """Trust multiplier for a chunk's source file (1.0 = unchanged, the default for
    everything not explicitly listed)."""
    try:
        return _SOURCE_TRUST_BY_FILE.get(Path(str(source_name)).name, 1.0)
    except Exception:  # noqa: BLE001 - a weird source name must never break retrieval
        return 1.0


class _OpenPolicyResult:
    allowed = True
    reason = ""
    category = ""
    refusal_message = ""
    requires_ack = False
    audit_tag = ""


class SafetyPolicy:
    """GreyIQ keeps the imported engine open and user-directed."""

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def screen_input(self, _text: str) -> _OpenPolicyResult:
        return _OpenPolicyResult()

    def screen_output(self, _text: str) -> _OpenPolicyResult:
        return _OpenPolicyResult()

    def snapshot(self) -> dict[str, str]:
        return {"mode": "open"}

    def system_prompt_addendum(self) -> str:
        return ""

    def set_flag(self, name: str, value: Any) -> dict[str, Any]:
        return {"mode": "open", "flag": name, "value": value}

    def set_authorization(self, _ack_text: str, _scope_note: str) -> dict[str, str]:
        return {"mode": "open", "authorization": "not_required"}

    def clear_authorization(self) -> dict[str, str]:
        return {"mode": "open", "authorization": "not_required"}

    def audit_tail(self, _lines: int = 200) -> str:
        return ""

    def capability_label(self) -> str:
        return "open local"

MODEL_CANDIDATES = (
    "best_model.pt",
    "checkpoint.pt",
    "solin_checkpoint.pt",
    "model.pt",
)
BEST_MODEL_ARCHIVE_GLOB = "best_model_*.pt"
STABLE_MODELS_DIR = "StableModels"

STOP_MARKERS = (
    "\nUser:",
    "\nAssistant:",
    "\nuser:",
    "\nassistant:",
    "User:",
    "Assistant:",
    "user:",
    "assistant:",
    "\n<USER>",
    "\n<ASSISTANT>",
    "<USER>",
    "<ASSISTANT>",
    "<END_CONVO>",
    "<START_CONVO>",
    "### FILE:",
    "### ROOT TRAIN FILE ###",
)

INFERENCE_MODES = ("conversational", "balanced", "reference")
DEFAULT_INFERENCE_CONFIG = {"mode": "conversational"}

SEARCH_WORD_RE = re.compile(r"[a-z0-9_+#-]{2,}")
SEARCH_STOPWORDS = {
    "about",
    "been",
    "being",
    "could",
    "does",
    "from",
    "have",
    "into",
    "just",
    "know",
    "like",
    "need",
    "please",
    "tell",
    "than",
    "that",
    "their",
    "them",
    "then",
    "there",
    "this",
    "want",
    "what",
    "when",
    "where",
    "which",
    "will",
    "with",
    "would",
    "your",
}

SEARCH_STOPWORDS |= {
    "a",
    "am",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "can",
    "did",
    "do",
    "for",
    "had",
    "has",
    "how",
    "in",
    "into",
    "is",
    "it",
    "its",
    "may",
    "might",
    "more",
    "much",
    "must",
    "my",
    "mine",
    "of",
    "on",
    "or",
    "our",
    "over",
    "should",
    "than",
    "the",
    "them",
    "they",
    "this",
    "those",
    "through",
    "to",
    "under",
    "was",
    "were",
    "why",
    "who",
    "whom",
    "whose",
    "you",
    "yourself",
}

QUERY_INTENT_SIMPLE = "simple_question"
QUERY_INTENT_KNOWLEDGE = "knowledge_lookup"
QUERY_INTENT_DOCUMENT = "document_based_question"
# Richer taxonomy. The legacy three above are kept for backwards compatibility
# with callers that import them, but routing prefers the labels below.
QUERY_INTENT_CASUAL_GREETING = "casual_greeting"
QUERY_INTENT_CASUAL_SMALLTALK = "casual_smalltalk"
QUERY_INTENT_CASUAL_CHECKIN = "casual_personal_checkin"
QUERY_INTENT_CASUAL_OPINION = "casual_opinion"
QUERY_INTENT_EMOTIONAL_SUPPORT = "emotional_support_light"
QUERY_INTENT_IDENTITY = "identity_question"
QUERY_INTENT_SIMPLE_MATH = "simple_math"
QUERY_INTENT_SERIOUS = "serious_task"
QUERY_INTENT_CODING = "coding_task"
QUERY_INTENT_PLANNING = "planning_task"
QUERY_INTENT_WEB = "current_web_lookup"
QUERY_INTENT_BUG_BOUNTY = "bug_bounty_hunt"

CASUAL_INTENT_LABELS = frozenset(
    {
        QUERY_INTENT_CASUAL_GREETING,
        QUERY_INTENT_CASUAL_SMALLTALK,
        QUERY_INTENT_CASUAL_CHECKIN,
        QUERY_INTENT_CASUAL_OPINION,
        QUERY_INTENT_EMOTIONAL_SUPPORT,
        QUERY_INTENT_IDENTITY,
        QUERY_INTENT_SIMPLE_MATH,
        QUERY_INTENT_SIMPLE,  # legacy alias still treated as casual-ish
    }
)
SERIOUS_INTENT_LABELS = frozenset(
    {
        QUERY_INTENT_SERIOUS,
        QUERY_INTENT_CODING,
        QUERY_INTENT_PLANNING,
        QUERY_INTENT_BUG_BOUNTY,
    }
)
DOCUMENT_INTENT_LABELS = frozenset({QUERY_INTENT_DOCUMENT})
KNOWLEDGE_INTENT_LABELS = frozenset({QUERY_INTENT_KNOWLEDGE, QUERY_INTENT_WEB})


def _is_casual_intent(label: str) -> bool:
    return label in CASUAL_INTENT_LABELS


def _is_serious_intent(label: str) -> bool:
    return label in SERIOUS_INTENT_LABELS or label in DOCUMENT_INTENT_LABELS


MATH_RE = re.compile(
    r"^\s*(?:what\s+is\s+)?(-?\d+(?:\.\d+)?)\s*(plus|\+|minus|-|times|\*|x|multiplied by|divided by|/)\s*(-?\d+(?:\.\d+)?)\s*\??\s*$",
    re.IGNORECASE,
)
INLINE_MATH_RE = re.compile(
    r"(?<!\w)(-?\d+(?:\.\d+)?)\s*(plus|\+|minus|-|times|\*|x|multiplied by|divided by|/)\s*(-?\d+(?:\.\d+)?)(?!\w)",
    re.IGNORECASE,
)
MATH_HINT_RE = re.compile(
    r"\b(what(?:'s| is)|calculate|solve|compute|how much is|can you tell me|tell me|do you know)\b",
    re.IGNORECASE,
)
DOC_HINT_RE = re.compile(
    r"\b(my docs?|documents?|pdfs?|files?|notes?|manuals?|sources?|knowledge base|kb)\b",
    re.IGNORECASE,
)
SUMMARY_HINT_RE = re.compile(r"\b(summarize|summary|recap|overview)\b", re.IGNORECASE)
CODE_HINT_RE = re.compile(r"\b(code|snippet|function|syntax|implementation|example)\b", re.IGNORECASE)
GREETING_RE = re.compile(r"^\s*(hi|hello|hey|yo|good morning|good afternoon|good evening)\b", re.IGNORECASE)
WELLBEING_RE = re.compile(r"^\s*(how are you|how're you|how are u)\b(?:\s+(today|doing|going))?", re.IGNORECASE)
NAME_RE = re.compile(r"^\s*(what(?:'s|s| is)\s+your\s+name|who\s+are\s+you)\b", re.IGNORECASE)
GREETING_ONLY_RE = re.compile(r"^\s*(hi|hello|hey|yo|good morning|good afternoon|good evening)[.!?\s]*$", re.IGNORECASE)
WELLBEING_ONLY_RE = re.compile(
    r"^\s*(how are you|how're you|how are u)\b(?:\s+(today|doing|going))?[.!?\s]*$",
    re.IGNORECASE,
)
NAME_ONLY_RE = re.compile(r"^\s*(what(?:'s|s| is)\s+your\s+name|who\s+are\s+you)[.!?\s]*$", re.IGNORECASE)
RETRIEVAL_FRAME_RE = re.compile(
    r"\b(summarize|summary|explain|tell me|about|my|docs?|documents?|pdfs?|files?|notes?|manuals?|sources?|knowledge base|kb|please)\b",
    re.IGNORECASE,
)
REMEMBER_RE = re.compile(r"^\s*remember(?:\s+that|\s+this)?\b", re.IGNORECASE)
SENSITIVE_MEMORY_RE = re.compile(
    r"\b(password|passcode|secret|api[_ -]?key|token|private key|ssn|social security|credit card|card number|cvv|pin)\b",
    re.IGNORECASE,
)
PERSONAL_MEMORY_RE = re.compile(r"\b(i|i'm|im|me|my|mine|myself|we|we're|our|ours|us)\b", re.IGNORECASE)
CONVERSATION_MEMORY_RE = re.compile(
    r"\b(earlier|before|previous|previously|last time|you said|we said|did i say|did you say|remember when|recall)\b",
    re.IGNORECASE,
)
WEB_HINT_RE = re.compile(
    r"\b(latest|current|today|news|online|internet|web|look up|lookup|search the web|search online)\b",
    re.IGNORECASE,
)
CASUAL_SMALLTALK_RE = re.compile(
    r"\b("
    r"what'?s\s*up|whats\s*up|wassup|sup|"
    r"how'?s\s*it\s*going|how\s*you\s*doin[g']?|"
    r"you\s*good|u\s*good|you\s*there|"
    r"tell\s*me\s*something\s*(funny|interesting|weird|cool|random)|"
    r"that'?s\s*(crazy|wild|insane|nuts|cool|awesome|sick)|"
    r"lol|lmao|haha|hehe|"
    r"nice(\s*one)?|sweet|dope|bet|"
    r"thanks?|thank\s*you|thx|ty|appreciate\s*(it|you|that)|"
    r"no\s*worries|np|cool\s*cool|"
    r"can\s*we\s*(just\s*)?(chat|talk|hang)|"
    r"wanna\s*chat|let'?s\s*chat"
    r")\b",
    re.IGNORECASE,
)
CASUAL_OPINION_RE = re.compile(
    r"\b(what\s+do\s+you\s+think|your\s+opinion|your\s+take|how\s+do\s+you\s+feel\s+about)\b",
    re.IGNORECASE,
)
EMOTIONAL_SUPPORT_RE = re.compile(
    r"\b("
    r"i'?m\s+(bored|stressed|tired|exhausted|sad|down|lonely|anxious|worried|frustrated|annoyed|upset|overwhelmed|excited|happy|nervous|scared|angry|mad|pissed)|"
    r"i\s+am\s+(bored|stressed|tired|exhausted|sad|down|lonely|anxious|worried|frustrated|annoyed|upset|overwhelmed|excited|happy|nervous|scared|angry|mad|pissed)|"
    r"feeling\s+(down|low|blue|off|stressed|anxious|tired|sad|happy|great|amazing)|"
    r"rough\s+day|long\s+day|bad\s+day|tough\s+day|hard\s+day|"
    r"i\s+(hate|love)\s+(this|that|my|today)|"
    r"i\s+need\s+to\s+vent|just\s+venting"
    r")\b",
    re.IGNORECASE,
)
CODING_HINT_RE = re.compile(
    r"\b("
    r"debug|refactor|stack\s*trace|traceback|exception|compile|compiler|"
    r"python|javascript|typescript|java|kotlin|rust|golang|\bgo\b|c\+\+|c#|ruby|php|sql|html|css|bash|shell|"
    r"function|method|class|module|library|framework|api|endpoint|"
    r"regex|json|yaml|xml|csv|"
    r"unit\s*test|pytest|jest|mocha|"
    r"git\b|docker|kubernetes|k8s|"
    r"write\s+(me\s+)?(a|some)?\s*(code|script|function|program)|"
    r"fix\s+(this|my)?\s*(bug|code|function|script)"
    r")\b",
    re.IGNORECASE,
)
PLANNING_HINT_RE = re.compile(
    r"\b("
    r"(make|create|build|draft|put\s+together)\s+(me\s+)?(a|an|the)?\s*(plan|roadmap|outline|schedule|timeline|strategy|proposal)|"
    r"project\s+plan|action\s+plan|milestones?|deliverables?|risks?\s+and\s+(mitigations?|tradeoffs?)|"
    r"break\s+(this|it|down)|"
    r"help\s+me\s+plan|plan\s+(out\s+)?(this|my|the)"
    r")\b",
    re.IGNORECASE,
)
SERIOUS_TASK_HINT_RE = re.compile(
    r"\b(analyze|analysis|evaluate|assessment|review|critique|compare|"
    r"explain\s+(in\s+detail|how|why)|walk\s+me\s+through|deep\s*dive|"
    r"write\s+(a|an|me)\s+(report|essay|memo|spec|summary|document)|"
    r"draft\s+(a|an)?\s*(email|letter|message|response))\b",
    re.IGNORECASE,
)
BUG_BOUNTY_HINT_RE = re.compile(
    r"\b("
    r"bug\s*bount(?:y|ies)|bounty\s*hunt|hackerone|bugcrowd|intigriti|yeswehack|"
    r"vrp|vulnerability\s*disclosure|proof\s*of\s*impact|poc|repro(?:duction)?\s*steps?|"
    r"idor|bola|bfla|xss|csrf|cors|ssrf|ssti|sqli|nosqli|xxe|jwt|graphql|"
    r"open\s*redirect|path\s*traversal|lfi|rce|command\s*injection|request\s*smuggling|"
    r"subdomain\s*takeover|race\s*condition|business\s*logic|mass\s*assignment|"
    r"broken\s*access\s*control|account\s*takeover|ato|vulnerability\s*triage|"
    r"security\s*report|bounty\s*report"
    r")\b",
    re.IGNORECASE,
)

INTENT_TYPO_TERMS = frozenset(
    {
        "afternoon",
        "analysis",
        "analyze",
        "anxious",
        "api",
        "are",
        "assessment",
        "bash",
        "base",
        "bored",
        "bugs",
        "build",
        "calculate",
        "chat",
        "class",
        "code",
        "compile",
        "compiler",
        "compute",
        "cool",
        "crazy",
        "current",
        "debug",
        "detail",
        "doing",
        "document",
        "documents",
        "docs",
        "draft",
        "email",
        "endpoint",
        "evening",
        "evaluate",
        "example",
        "exception",
        "exhausted",
        "explain",
        "files",
        "framework",
        "frustrated",
        "function",
        "going",
        "good",
        "hello",
        "hey",
        "how",
        "internet",
        "javascript",
        "json",
        "knowledge",
        "latest",
        "letter",
        "library",
        "lonely",
        "manuals",
        "method",
        "module",
        "morning",
        "name",
        "news",
        "notes",
        "online",
        "opinion",
        "overview",
        "pdf",
        "pdfs",
        "plan",
        "planning",
        "proposal",
        "python",
        "question",
        "random",
        "recap",
        "refactor",
        "regex",
        "remember",
        "report",
        "response",
        "review",
        "roadmap",
        "rough",
        "sad",
        "schedule",
        "search",
        "snippet",
        "sources",
        "stressed",
        "strategy",
        "summary",
        "summarize",
        "syntax",
        "thanks",
        "tired",
        "today",
        "traceback",
        "typescript",
        "up",
        "venting",
        "web",
        "what",
        "whats",
        "who",
        "worried",
        "write",
        "your",
        "you",
    }
)

SEMANTIC_SEARCH_EQUIVALENTS = {
    "document": {
        "doc",
        "docs",
        "document",
        "documents",
        "file",
        "files",
        "manual",
        "manuals",
        "note",
        "notes",
        "pdf",
        "pdfs",
        "kb",
    },
    "summary": {"summarize", "summary", "recap", "overview"},
    "issue": {"bug", "bugs", "error", "errors", "failure", "fail", "issue", "issues", "problem", "problems"},
    "memory": {"context", "history", "memory", "recall", "remember"},
    "speed": {"fast", "faster", "latency", "responsive", "responsiveness", "slow", "speed"},
    "training": {"fine-tune", "finetune", "learn", "learning", "retrain", "training"},
    "code": {"code", "function", "implementation", "snippet", "syntax"},
}
SEMANTIC_TERM_MAP = {
    variant: canonical for canonical, variants in SEMANTIC_SEARCH_EQUIVALENTS.items() for variant in variants
}

MODE_SETTINGS = {
    "conversational": {
        "retrieval_threshold": 0.42,
        "fallback_threshold": 0.55,
        "retrieval_limit": 2,
        "summary_sentences": 2,
    },
    "balanced": {
        "retrieval_threshold": 0.35,
        "fallback_threshold": 0.62,
        "retrieval_limit": 3,
        "summary_sentences": 3,
    },
    "reference": {
        "retrieval_threshold": 0.32,
        "fallback_threshold": 0.45,
        "retrieval_limit": 4,
        "summary_sentences": 3,
    },
}

ROLE_BLOCK_RE = re.compile(r"(?im)^\s*(user|assistant)\s*:\s*")
ROLE_TAG_RE = re.compile(r"(?im)^\s*(<USER>|<ASSISTANT>|user:|assistant:)\s*$")


@dataclass(slots=True)
class DeviceInfo:
    name: str
    reason: str


@dataclass(slots=True)
class SourceMatch:
    source: str
    score: float
    excerpt: str
    source_id: str = ""


@dataclass(slots=True)
class QueryIntent:
    label: str
    use_retrieval: bool
    wants_summary: bool = False
    wants_code: bool = False
    direct_response: str = ""


@dataclass(slots=True)
class ReplyDiagnostics:
    used_fallback: bool
    captured_for_training: bool = False
    intent_label: str = ""
    mode: str = ""
    strategy: str = ""
    confidence: float = 0.0
    retrieval_count: int = 0
    memory_count: int = 0
    note_count: int = 0


@dataclass(slots=True)
class MemoryMatch:
    score: float
    user: str
    assistant: str
    timestamp: str = ""


@dataclass(slots=True)
class NoteMatch:
    score: float
    note: str
    timestamp: str = ""


@dataclass(slots=True)
class PromptSection:
    label: str
    text: str
    priority: int
    min_budget: int
    max_budget: int
    required: bool = False
    keep_tail: bool = False


@dataclass(slots=True)
class WebResult:
    summary: str
    source: str


UNICODE_TRANSLATION_TABLE = str.maketrans(
    {
        "‘": "'",
        "’": "'",
        "“": '"',
        "”": '"',
        "–": "-",
        "—": "-",
        "…": "...",
        " ": " ",
        "•": "-",
        "	": " ",
    }
)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\u200b\u200c\u200d\ufeff]")


def normalize_user_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text or "")
    normalized = normalized.translate(UNICODE_TRANSLATION_TABLE)
    normalized = CONTROL_CHAR_RE.sub("", normalized)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    normalized = re.sub(r"[ \t]+", " ", normalized)
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    return normalized.strip()


def clean_text(text: str) -> str:
    normalized = normalize_user_text(text)
    if not normalized:
        return ""

    lines = [line.strip() for line in normalized.splitlines()]
    return "\n".join([line for line in lines if line])


def normalize_intent_routing_text(text: str) -> str:
    normalized = clean_text(text)
    if not normalized:
        return ""
    return normalize_known_typos(normalized, INTENT_TYPO_TERMS)


def _configure_torch_runtime() -> None:
    setter = getattr(torch, "set_float32_matmul_precision", None)
    if callable(setter):
        try:
            setter("high")
        except Exception:
            pass
    if torch.cuda.is_available():
        try:
            torch.backends.cuda.matmul.allow_tf32 = True
        except Exception:
            pass
        try:
            torch.backends.cudnn.allow_tf32 = True
        except Exception:
            pass


def _format_timestamp(timestamp: float | None) -> str:
    if not timestamp:
        return "unknown time"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def normalize_generated_response(text: str) -> str:
    """Keep only the first assistant answer, even if generation drifts into more turns."""
    if not text:
        return ""

    normalized = text.replace("\r\n", "\n").strip()

    # Drop a leading assistant label if the model echoes one.
    normalized = re.sub(r"(?is)^\s*(<ASSISTANT>|assistant:)\s*", "", normalized, count=1)

    lines = normalized.split("\n")
    kept_lines: list[str] = []
    seen_content = False

    for line in lines:
        stripped = line.strip()
        if ROLE_TAG_RE.match(stripped):
            if seen_content:
                break
            continue
        if ROLE_BLOCK_RE.match(line) and seen_content:
            break

        kept_lines.append(line)
        if stripped:
            seen_content = True

    normalized = "\n".join(kept_lines).strip()
    return clean_text(normalized)


def _parse_sm_arch(arch: str) -> tuple[int, int] | None:
    if not arch.startswith("sm_"):
        return None

    digits = arch[3:]
    if not digits.isdigit() or len(digits) < 2:
        return None
    return int(digits[:-1]), int(digits[-1])


def detect_best_device(preferred: str | None = None) -> DeviceInfo:
    requested = (preferred or os.environ.get("SOLIN_DEVICE") or "auto").lower().strip()

    if requested == "cpu":
        return DeviceInfo("cpu", "Forced to CPU by configuration.")

    if requested not in {"auto", "cuda"}:
        return DeviceInfo("cpu", f"Unknown device '{requested}', falling back to CPU.")

    if not torch.cuda.is_available():
        reason = "CUDA is unavailable, using CPU."
        if requested == "cuda":
            reason = "CUDA was requested but is unavailable, using CPU."
        return DeviceInfo("cpu", reason)

    try:
        capability = torch.cuda.get_device_capability(0)
        supported_arches = {
            parsed for parsed in (_parse_sm_arch(arch) for arch in torch.cuda.get_arch_list()) if parsed
        }
        if supported_arches and capability > max(supported_arches):
            return DeviceInfo(
                "cpu",
                (
                    "Installed PyTorch does not support this GPU architecture "
                    f"(sm_{capability[0]}{capability[1]}), using CPU."
                ),
            )
        # Hard floor: even if get_arch_list() reports support for the latest
        # SM, on consumer cards >= sm_100 (Blackwell, e.g. RTX 5060 Ti) we have
        # seen real-size generation hang in the CUDA driver despite tiny
        # smoke tests passing via PTX JIT. Until a wheel with native
        # sm_100/sm_120 binaries is the norm, refuse CUDA in auto mode and
        # require the operator to opt in with SOLIN_DEVICE=cuda.
        if capability[0] >= 10 and requested != "cuda":
            return DeviceInfo(
                "cpu",
                (
                    f"GPU compute capability sm_{capability[0]}{capability[1]} is too new for "
                    "reliable inference with this PyTorch build; using CPU. Set "
                    "SOLIN_DEVICE=cuda to override."
                ),
            )
    except Exception:
        pass

    # Representative smoke test: dimensions close to the smallest production
    # model, multiple generation steps, and an explicit .cpu() to force a
    # device-side sync. A trivial (1x8) probe used to slip through under
    # PTX JIT and then real generation would hang.
    try:
        probe_config = {
            "block_size": 64,
            "n_embd": 96,
            "n_head": 4,
            "n_layer": 2,
            "dropout": 0.0,
        }
        probe_model = TinyGPT(64, probe_config).to("cuda")
        probe_input = torch.randint(0, 64, (1, 32), device="cuda", dtype=torch.long)
        with torch.inference_mode():
            logits, _ = probe_model(probe_input)
            # Force a sync — async CUDA errors only surface on device->host copy.
            _ = logits.detach().to("cpu").float().sum().item()
        del probe_model
        try:
            torch.cuda.synchronize()
        except Exception:
            pass
        return DeviceInfo("cuda", "CUDA is available and passed a transformer smoke test.")
    except Exception as exc:
        try:
            torch.cuda.empty_cache()
        except Exception:
            pass
        return DeviceInfo("cpu", f"CUDA kernel test failed, using CPU. {exc}")


def _is_retryable_cuda_failure(exc: BaseException) -> bool:
    message = str(exc).lower()
    retry_markers = (
        "no kernel image is available",
        "kernel image",
        "sm_",
        "not compatible with the current pytorch installation",
        "acceleratorerror",
        "cuda error",
        "device kernel image is invalid",
        "cublas",
        "cudnn",
        "cuda out of memory",
    )
    return any(marker in message for marker in retry_markers)


def save_config(config: dict[str, Any], config_path: str | Path = CONFIG_FILE) -> None:
    with Path(config_path).open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)


def load_config(config_path: str | Path = CONFIG_FILE) -> dict[str, Any]:
    with Path(config_path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_inference_config(config_path: str | Path = INFERENCE_CONFIG_FILE) -> dict[str, str]:
    path = Path(config_path)
    if not path.exists():
        return dict(DEFAULT_INFERENCE_CONFIG)
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return dict(DEFAULT_INFERENCE_CONFIG)

    mode = str(payload.get("mode", DEFAULT_INFERENCE_CONFIG["mode"])).strip().lower()
    if mode not in INFERENCE_MODES:
        mode = DEFAULT_INFERENCE_CONFIG["mode"]
    return {"mode": mode}


def save_inference_config(config: dict[str, str], config_path: str | Path = INFERENCE_CONFIG_FILE) -> None:
    mode = str(config.get("mode", DEFAULT_INFERENCE_CONFIG["mode"])).strip().lower()
    if mode not in INFERENCE_MODES:
        mode = DEFAULT_INFERENCE_CONFIG["mode"]
    with Path(config_path).open("w", encoding="utf-8") as handle:
        json.dump({"mode": mode}, handle, indent=2)


_VALID_DEVICE_PREF = {"auto", "cpu", "cuda"}


def _default_runtime_config() -> dict[str, Any]:
    return {
        "internet_enabled": False,
        "device_preference": "auto",
    }


def _normalize_device_pref(value: Any) -> str:
    candidate = str(value or "auto").lower().strip()
    return candidate if candidate in _VALID_DEVICE_PREF else "auto"


def load_runtime_config(config_path: str | Path = RUNTIME_CONFIG_FILE) -> dict[str, Any]:
    path = Path(config_path)
    defaults = _default_runtime_config()
    try:
        exists = path.exists()
    except OSError:
        return defaults
    if not exists:
        return defaults
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return defaults
    if not isinstance(payload, dict):
        return defaults
    return {
        "internet_enabled": bool(payload.get("internet_enabled", defaults["internet_enabled"])),
        "device_preference": _normalize_device_pref(payload.get("device_preference", defaults["device_preference"])),
    }


def save_runtime_config(config: dict[str, Any], config_path: str | Path = RUNTIME_CONFIG_FILE) -> None:
    path = Path(config_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    payload.update(
        {
            "internet_enabled": bool(config.get("internet_enabled", False)),
            "device_preference": _normalize_device_pref(config.get("device_preference", "auto")),
        }
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
    except OSError:
        # Runtime config is a convenience file. A transient OneDrive/Windows
        # lock should not prevent the local engine from starting.
        return


def build_codecs(
    stoi: dict[str, int],
    raw_itos,
) -> tuple[dict[int, str], Callable[[str], list[int]], Callable[[list[int]], str]]:
    if isinstance(raw_itos, dict):
        itos = {int(key): value for key, value in raw_itos.items()}
    else:
        itos = {index: value for index, value in enumerate(raw_itos)}

    def encode(text: str) -> list[int]:
        return [stoi[char] for char in text if char in stoi]

    def decode(tokens: list[int]) -> str:
        return "".join([itos[token] for token in tokens if token in itos])

    return itos, encode, decode


def load_vocab(vocab_path: str | Path = VOCAB_FILE):
    with Path(vocab_path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    # BPE tokenizer file → use the BPE codecs. Same return shape as the
    # char-level path so the rest of the engine is none the wiser.
    if payload.get("tokenizer_kind") == "bpe":
        from solin_bpe import BPETokenizer

        merges = [tuple(p) for p in payload.get("merges", [])]
        tok = BPETokenizer(stoi=payload["stoi"], merges=merges)
        return len(tok.stoi), tok.stoi, tok.itos, tok.encode, tok.decode

    stoi = payload["stoi"]
    itos, encode, decode = build_codecs(stoi, payload["itos"])
    return len(stoi), stoi, itos, encode, decode


def save_vocab(stoi: dict[str, int], itos: dict[int, str], vocab_path: str | Path = VOCAB_FILE) -> None:
    payload = {
        "stoi": stoi,
        "itos": {str(key): value for key, value in itos.items()},
    }
    with Path(vocab_path).open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


class Head(nn.Module):
    """Legacy single-head attention retained for compatibility and testing."""

    def __init__(self, head_size: int, config: dict[str, Any]):
        super().__init__()
        n_embd = int(config["n_embd"])
        dropout = float(config.get("dropout", 0.1))
        scale_mode = str(config.get("attention_scale_mode", "head")).strip().lower()

        self.head_size = head_size
        self.attention_scale = (n_embd**-0.5) if scale_mode == "legacy" else (head_size**-0.5)
        self.use_sdpa = bool(config.get("use_sdpa", True)) and hasattr(F, "scaled_dot_product_attention")

        self.key = nn.Linear(n_embd, head_size, bias=False)
        self.query = nn.Linear(n_embd, head_size, bias=False)
        self.value = nn.Linear(n_embd, head_size, bias=False)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        batch, time_steps, channels = x.shape
        k = self.key(x).view(batch, 1, time_steps, self.head_size)
        q = self.query(x).view(batch, 1, time_steps, self.head_size)
        v = self.value(x).view(batch, 1, time_steps, self.head_size)

        if self.use_sdpa:
            default_scale = self.head_size**-0.5
            if abs(self.attention_scale - default_scale) > 1e-12:
                q = q * (self.attention_scale / default_scale)
            out = F.scaled_dot_product_attention(
                q,
                k,
                v,
                dropout_p=self.dropout.p if self.training else 0.0,
                is_causal=True,
            )
            return out.view(batch, time_steps, self.head_size)

        weights = q @ k.transpose(-2, -1) * self.attention_scale
        causal_mask = torch.ones(time_steps, time_steps, device=x.device, dtype=torch.bool).tril()
        weights = weights.masked_fill(~causal_mask, float("-inf"))
        weights = F.softmax(weights, dim=-1)
        weights = self.dropout(weights)
        return (weights @ v).view(batch, time_steps, self.head_size)


class MultiHeadAttention(nn.Module):
    """Fused multi-head causal attention with optional SDPA acceleration."""

    def __init__(self, num_heads: int, head_size: int, config: dict[str, Any]):
        super().__init__()
        n_embd = int(config["n_embd"])
        dropout = float(config.get("dropout", 0.1))
        scale_mode = str(config.get("attention_scale_mode", "head")).strip().lower()

        if num_heads * head_size != n_embd:
            raise ValueError(f"n_embd ({n_embd}) must be divisible by n_head ({num_heads}).")

        self.num_heads = num_heads
        self.head_size = head_size
        self.dropout_p = dropout
        self.use_sdpa = bool(config.get("use_sdpa", True)) and hasattr(F, "scaled_dot_product_attention")
        self.attention_scale = (n_embd**-0.5) if scale_mode == "legacy" else (head_size**-0.5)

        self.q_proj = nn.Linear(n_embd, n_embd, bias=False)
        self.k_proj = nn.Linear(n_embd, n_embd, bias=False)
        self.v_proj = nn.Linear(n_embd, n_embd, bias=False)
        self.proj = nn.Linear(n_embd, n_embd)
        self.dropout = nn.Dropout(dropout)

    def _reshape_heads(self, tensor: torch.Tensor, batch: int, time_steps: int) -> torch.Tensor:
        return tensor.view(batch, time_steps, self.num_heads, self.head_size).transpose(1, 2).contiguous()

    def forward(self, x, *, layer_past=None, use_cache=False):
        batch, time_steps, channels = x.shape
        q = self._reshape_heads(self.q_proj(x), batch, time_steps)
        k = self._reshape_heads(self.k_proj(x), batch, time_steps)
        v = self._reshape_heads(self.v_proj(x), batch, time_steps)

        if layer_past is not None:
            past_k, past_v = layer_past
            k = torch.cat((past_k, k), dim=2)
            v = torch.cat((past_v, v), dim=2)

        present = (k, v) if use_cache else None
        query_len = q.shape[2]
        key_len = k.shape[2]

        if self.use_sdpa:
            default_scale = self.head_size**-0.5
            if abs(self.attention_scale - default_scale) > 1e-12:
                q = q * (self.attention_scale / default_scale)
            if query_len == key_len:
                # Prefill / training: standard square causal attention.
                out = F.scaled_dot_product_attention(
                    q,
                    k,
                    v,
                    dropout_p=self.dropout_p if self.training else 0.0,
                    is_causal=True,
                )
            else:
                # Cached decode (query_len < key_len): the new queries sit at the
                # tail of the sequence and may attend to every cached key, which is
                # already causal. is_causal=True applies a top-left aligned mask and
                # would be wrong here, so build an explicit bottom-right causal mask.
                attn_mask = torch.ones(
                    query_len, key_len, device=x.device, dtype=torch.bool
                ).tril(diagonal=key_len - query_len)
                out = F.scaled_dot_product_attention(
                    q,
                    k,
                    v,
                    attn_mask=attn_mask,
                    dropout_p=self.dropout_p if self.training else 0.0,
                )
        else:
            weights = q @ k.transpose(-2, -1) * self.attention_scale
            causal_mask = torch.ones(query_len, key_len, device=x.device, dtype=torch.bool).tril(
                diagonal=key_len - query_len
            )
            weights = weights.masked_fill(~causal_mask, float("-inf"))
            weights = F.softmax(weights, dim=-1)
            weights = F.dropout(weights, p=self.dropout_p, training=self.training)
            out = weights @ v

        out = out.transpose(1, 2).contiguous().view(batch, time_steps, channels)
        out = self.proj(out)
        return self.dropout(out), present


def _build_activation(name: str) -> nn.Module:
    normalized = name.strip().lower()
    if normalized == "relu":
        return nn.ReLU()
    if normalized == "silu":
        return nn.SiLU()
    return nn.GELU(approximate="tanh")


class FeedForward(nn.Module):
    def __init__(self, config: dict[str, Any]):
        super().__init__()
        n_embd = int(config["n_embd"])
        dropout = float(config.get("dropout", 0.1))
        hidden_mult = float(config.get("ffn_mult", 4.0))
        hidden_size = max(n_embd, int(round(n_embd * hidden_mult)))
        activation = str(config.get("activation", "gelu"))

        self.net = nn.Sequential(
            nn.Linear(n_embd, hidden_size),
            _build_activation(activation),
            nn.Linear(hidden_size, n_embd),
            nn.Dropout(dropout),
        )

    def forward(self, x):
        return self.net(x)


class Block(nn.Module):
    def __init__(self, config: dict[str, Any]):
        super().__init__()
        n_embd = int(config["n_embd"])
        n_head = int(config["n_head"])
        head_size = n_embd // n_head

        self.sa = MultiHeadAttention(n_head, head_size, config)
        self.ffwd = FeedForward(config)
        self.ln1 = nn.LayerNorm(n_embd)
        self.ln2 = nn.LayerNorm(n_embd)

    def forward(self, x, *, layer_past=None, use_cache=False):
        attn_out, present = self.sa(self.ln1(x), layer_past=layer_past, use_cache=use_cache)
        x = x + attn_out
        x = x + self.ffwd(self.ln2(x))
        return x, present


class TinyGPT(nn.Module):
    def __init__(self, vocab_size: int, config: dict[str, Any]):
        super().__init__()

        config = _normalize_model_config(config)
        block_size = int(config["block_size"])
        n_embd = int(config["n_embd"])
        n_layer = int(config["n_layer"])

        self.config = config
        self.block_size = block_size
        self.tie_weights = bool(config.get("tie_weights", True))

        self.token_embedding = nn.Embedding(vocab_size, n_embd)
        self.position_embedding = nn.Embedding(block_size, n_embd)
        self.blocks = nn.Sequential(*[Block(config) for _ in range(n_layer)])
        self.ln = nn.LayerNorm(n_embd)
        self.head = nn.Linear(n_embd, vocab_size)

        self.apply(self._init_weights)
        self._scale_residual_projections(n_layer)
        if self.tie_weights:
            self.head.weight = self.token_embedding.weight

    def _init_weights(self, module: nn.Module) -> None:
        if isinstance(module, nn.Linear):
            nn.init.normal_(module.weight, mean=0.0, std=0.02)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            nn.init.normal_(module.weight, mean=0.0, std=0.02)
        elif isinstance(module, nn.LayerNorm):
            nn.init.ones_(module.weight)
            nn.init.zeros_(module.bias)

    def _scale_residual_projections(self, n_layer: int) -> None:
        scaled_std = 0.02 / math.sqrt(2 * max(n_layer, 1))
        for name, param in self.named_parameters():
            if name.endswith("sa.proj.weight") or name.endswith("ffwd.net.2.weight"):
                nn.init.normal_(param, mean=0.0, std=scaled_std)

    def num_parameters(self) -> int:
        return sum(parameter.numel() for parameter in self.parameters())

    def configure_optimizer(
        self,
        weight_decay: float = 0.1,
        learning_rate: float = 3e-4,
        betas: tuple[float, float] = (0.9, 0.95),
        device_type: str | None = None,
    ) -> torch.optim.AdamW:
        decay_params: list[torch.nn.Parameter] = []
        no_decay_params: list[torch.nn.Parameter] = []

        for name, parameter in self.named_parameters():
            if not parameter.requires_grad:
                continue
            if parameter.ndim >= 2 and "ln" not in name and "norm" not in name and not name.endswith(".bias"):
                decay_params.append(parameter)
            else:
                no_decay_params.append(parameter)

        optim_groups = [
            {"params": decay_params, "weight_decay": weight_decay},
            {"params": no_decay_params, "weight_decay": 0.0},
        ]
        adamw_signature = inspect.signature(torch.optim.AdamW)
        use_fused = bool(device_type == "cuda" and "fused" in adamw_signature.parameters)
        extra_kwargs = {"fused": True} if use_fused else {}
        return torch.optim.AdamW(
            optim_groups,
            lr=learning_rate,
            betas=betas,
            **extra_kwargs,
        )

    def forward(self, idx, targets=None, *, past_key_values=None, use_cache=False):
        _, time_steps = idx.shape

        past_length = 0
        if past_key_values is not None and past_key_values[0] is not None:
            # Cache entries are (k, v) shaped (batch, n_head, T_past, head_size).
            past_length = past_key_values[0][0].shape[2]

        if past_length + time_steps > self.block_size:
            raise ValueError(
                f"Sequence length {past_length + time_steps} exceeds block_size {self.block_size}. "
                "Crop the input or increase block_size before training."
            )

        tok = self.token_embedding(idx)
        # Offset positions by the cached length so a single decoded token lands at
        # its true absolute position rather than position 0.
        positions = torch.arange(past_length, past_length + time_steps, device=idx.device)
        pos = self.position_embedding(positions).unsqueeze(0)
        x = tok + pos

        new_cache = [] if use_cache else None
        for index, block in enumerate(self.blocks):
            layer_past = past_key_values[index] if past_key_values is not None else None
            x, present = block(x, layer_past=layer_past, use_cache=use_cache)
            if use_cache:
                new_cache.append(present)

        x = self.ln(x)
        logits = self.head(x)

        loss = None
        if targets is not None:
            batch, steps, channels = logits.shape
            loss = F.cross_entropy(
                logits.reshape(batch * steps, channels),
                targets.reshape(batch * steps),
            )

        if use_cache:
            return logits, loss, new_cache
        return logits, loss

    @staticmethod
    def _tail_is_degenerate(
        sequence: torch.Tensor,
        max_period: int = 6,
        min_repeats: int = 3,
        min_span: int = 8,
    ) -> bool:
        """True when the tail is a short repeating cycle (period 1..max_period),
        i.e. generation is stuck looping. Each period is checked against its own
        window of ``period * repeats`` tokens — so unlike a single fixed window,
        this covers every period (including 5). Short periods require more repeats
        (``span >= min_span``: e.g. 8 identical tokens for period 1), so it does
        not fire on ordinary short patterns like "..." or "===" mid-sentence."""
        length = int(sequence.shape[0])
        for period in range(1, max_period + 1):
            repeats = max(min_repeats, -(-min_span // period))  # ceil(min_span / period)
            span = period * repeats
            if length < span:
                continue
            tail = sequence[-span:]
            block = tail[:period]
            if torch.equal(tail, block.repeat(repeats)):
                return True
        return False

    def generate(
        self,
        idx,
        max_new_tokens: int = 120,
        temperature: float = 0.45,
        top_k: int = 40,
        top_p: float = 0.0,
        repetition_penalty: float = 1.08,
        no_repeat_ngram_size: int = 0,
        stop_sequences: list[list[int]] | None = None,
    ):
        compiled_stops = [
            torch.tensor(sequence, dtype=idx.dtype, device=idx.device)
            for sequence in (stop_sequences or [])
            if sequence
        ]
        # Incremental K/V cache. Valid only while the whole sequence still fits
        # inside block_size: with learned absolute position embeddings a sliding
        # window changes which token sits at each position, so once we cross
        # block_size we drop the cache and recompute the cropped window (the
        # original behaviour). Switching to rotary embeddings would lift this.
        past_key_values = None

        for _ in range(max_new_tokens):
            seq_len = idx.shape[1]
            if seq_len <= self.block_size:
                if past_key_values is None:
                    logits, _, past_key_values = self(idx, use_cache=True)
                else:
                    logits, _, past_key_values = self(
                        idx[:, -1:], past_key_values=past_key_values, use_cache=True
                    )
            else:
                past_key_values = None
                logits, _ = self(idx[:, -self.block_size :], use_cache=False)

            logits = logits[:, -1, :]
            recent = idx[:, -self.block_size :]

            if repetition_penalty and repetition_penalty != 1.0:
                for batch_index in range(idx.shape[0]):
                    recent_tokens = torch.unique(recent[batch_index])
                    selected = logits[batch_index, recent_tokens]
                    # Sign-aware penalty: plain division only suppresses positive
                    # logits — a negative logit divided by penalty>1 grows toward
                    # zero and becomes *more* likely, inverting the intent.
                    logits[batch_index, recent_tokens] = torch.where(
                        selected < 0,
                        selected * repetition_penalty,
                        selected / repetition_penalty,
                    )

            if no_repeat_ngram_size and no_repeat_ngram_size > 1 and seq_len >= no_repeat_ngram_size:
                ngram = no_repeat_ngram_size
                for batch_index in range(idx.shape[0]):
                    tokens = idx[batch_index].tolist()
                    prefix = tuple(tokens[-(ngram - 1) :])
                    banned = {
                        tokens[start + ngram - 1]
                        for start in range(len(tokens) - ngram + 1)
                        if tuple(tokens[start : start + ngram - 1]) == prefix
                    }
                    if banned and len(banned) < logits.shape[-1]:
                        logits[batch_index, list(banned)] = float("-inf")

            if temperature <= 0:
                next_token = torch.argmax(logits, dim=-1, keepdim=True)
            else:
                logits = logits / max(temperature, 1e-6)

                if top_k and 0 < top_k < logits.shape[-1]:
                    top_values, _ = torch.topk(logits, top_k)
                    cutoff = top_values[:, [-1]]
                    logits = logits.masked_fill(logits < cutoff, float("-inf"))

                if top_p and 0.0 < top_p < 1.0:
                    sorted_logits, sorted_indices = torch.sort(logits, descending=True, dim=-1)
                    sorted_probs = F.softmax(sorted_logits, dim=-1)
                    cumulative_probs = sorted_probs.cumsum(dim=-1)

                    sorted_remove = cumulative_probs > top_p
                    sorted_remove[..., 1:] = sorted_remove[..., :-1].clone()
                    sorted_remove[..., 0] = False

                    remove_mask = torch.zeros_like(logits, dtype=torch.bool)
                    remove_mask.scatter_(1, sorted_indices, sorted_remove)
                    logits = logits.masked_fill(remove_mask, float("-inf"))

                probs = F.softmax(logits, dim=-1)
                next_token = torch.multinomial(probs, num_samples=1)

            idx = torch.cat((idx, next_token), dim=1)

            if idx.shape[0] == 1:
                for stop_sequence in compiled_stops:
                    stop_length = int(stop_sequence.numel())
                    if (
                        stop_length
                        and idx.shape[1] >= stop_length
                        and torch.equal(idx[0, -stop_length:], stop_sequence)
                    ):
                        return idx
                if self._tail_is_degenerate(idx[0]):
                    return idx

        return idx


def _state_dict_is_legacy_attention(state_dict: dict[str, torch.Tensor] | None) -> bool:
    if not state_dict:
        return False
    return any(".sa.heads." in key for key in state_dict)


def _state_dict_uses_tied_embeddings(state_dict: dict[str, torch.Tensor] | None) -> bool:
    if not state_dict:
        return True
    token_weight = state_dict.get("token_embedding.weight")
    head_weight = state_dict.get("head.weight")
    if token_weight is None or head_weight is None:
        return True
    return torch.equal(token_weight, head_weight)


def _infer_layer_count_from_state_dict(state_dict: dict[str, torch.Tensor]) -> int | None:
    layer_ids = {int(match.group(1)) for key in state_dict for match in [re.match(r"blocks\.(\d+)\.", key)] if match}
    if not layer_ids:
        return None
    return max(layer_ids) + 1


def _infer_head_count_from_state_dict(state_dict: dict[str, torch.Tensor]) -> int | None:
    head_ids = {
        int(match.group(1)) for key in state_dict for match in [re.search(r"\.sa\.heads\.(\d+)\.", key)] if match
    }
    if not head_ids:
        return None
    return max(head_ids) + 1


def _normalize_model_config(
    config: dict[str, Any] | None,
    state_dict: dict[str, torch.Tensor] | None = None,
) -> dict[str, Any]:
    normalized = dict(config or {})
    legacy_attention = _state_dict_is_legacy_attention(state_dict)

    if state_dict:
        if "token_embedding.weight" in state_dict:
            normalized.setdefault("n_embd", int(state_dict["token_embedding.weight"].shape[1]))
        if "position_embedding.weight" in state_dict:
            normalized.setdefault("block_size", int(state_dict["position_embedding.weight"].shape[0]))
        inferred_layers = _infer_layer_count_from_state_dict(state_dict)
        if inferred_layers is not None:
            normalized.setdefault("n_layer", inferred_layers)
        inferred_heads = _infer_head_count_from_state_dict(state_dict)
        if inferred_heads is not None:
            normalized.setdefault("n_head", inferred_heads)

    normalized.setdefault("dropout", 0.1)
    normalized.setdefault("ffn_mult", 4.0)
    normalized.setdefault("use_sdpa", True)
    if "activation" not in normalized:
        normalized["activation"] = "relu" if legacy_attention else "gelu"
    if "tie_weights" not in normalized:
        normalized["tie_weights"] = _state_dict_uses_tied_embeddings(state_dict)
    if "attention_scale_mode" not in normalized:
        normalized["attention_scale_mode"] = "legacy" if legacy_attention else "head"

    required_keys = ("block_size", "n_embd", "n_layer", "n_head")
    missing = [key for key in required_keys if key not in normalized]
    if missing:
        raise KeyError(f"Model config is missing required keys: {', '.join(missing)}")

    return normalized


def _upgrade_legacy_attention_state_dict(
    state_dict: dict[str, torch.Tensor],
    config: dict[str, Any],
) -> dict[str, torch.Tensor]:
    if not _state_dict_is_legacy_attention(state_dict):
        return state_dict

    upgraded = dict(state_dict)
    n_layer = int(config["n_layer"])
    n_head = int(config["n_head"])

    for layer_index in range(n_layer):
        prefix = f"blocks.{layer_index}.sa"
        query_keys = [f"{prefix}.heads.{head_index}.query.weight" for head_index in range(n_head)]
        key_keys = [f"{prefix}.heads.{head_index}.key.weight" for head_index in range(n_head)]
        value_keys = [f"{prefix}.heads.{head_index}.value.weight" for head_index in range(n_head)]
        legacy_mask_keys = [f"{prefix}.heads.{head_index}.tril" for head_index in range(n_head)]

        if not all(key in state_dict for key in (*query_keys, *key_keys, *value_keys)):
            continue

        upgraded[f"{prefix}.q_proj.weight"] = torch.cat([state_dict[key] for key in query_keys], dim=0)
        upgraded[f"{prefix}.k_proj.weight"] = torch.cat([state_dict[key] for key in key_keys], dim=0)
        upgraded[f"{prefix}.v_proj.weight"] = torch.cat([state_dict[key] for key in value_keys], dim=0)

        for key in (*query_keys, *key_keys, *value_keys, *legacy_mask_keys):
            upgraded.pop(key, None)

    return upgraded


def _safe_torch_load(path: Path, map_location: str = "cpu"):
    try:
        return torch.load(path, map_location=map_location, mmap=True)
    except TypeError:
        return torch.load(path, map_location=map_location)


def _autocast_for_device(device: str):
    if device != "cuda" or not torch.cuda.is_available():
        return nullcontext()
    bf16_supported = getattr(torch.cuda, "is_bf16_supported", lambda: False)()
    autocast_dtype = torch.bfloat16 if bf16_supported else torch.float16
    return torch.autocast(device_type="cuda", dtype=autocast_dtype)


def _chunk_text(text: str, chunk_size: int = 1600, overlap: int = 250) -> list[str]:
    paragraphs = [paragraph.strip() for paragraph in text.split("\n\n") if paragraph.strip()]
    if not paragraphs:
        return []

    chunks: list[str] = []
    current: list[str] = []
    current_length = 0

    for paragraph in paragraphs:
        if len(paragraph) > chunk_size:
            if current:
                chunks.append("\n\n".join(current).strip())
                current = []
                current_length = 0

            start = 0
            step = max(chunk_size - overlap, 100)
            while start < len(paragraph):
                chunk = paragraph[start : start + chunk_size].strip()
                if chunk:
                    chunks.append(chunk)
                start += step
            continue

        projected = current_length + len(paragraph) + (2 if current else 0)
        if current and projected > chunk_size:
            chunks.append("\n\n".join(current).strip())
            current = [paragraph]
            current_length = len(paragraph)
        else:
            current.append(paragraph)
            current_length = projected

    if current:
        chunks.append("\n\n".join(current).strip())

    return [chunk for chunk in chunks if chunk]


def _expand_search_term(term: str) -> list[str]:
    variants = [term]
    if len(term) > 4 and term.endswith("ies"):
        variants.append(term[:-3] + "y")
    if len(term) > 4 and term.endswith("es"):
        variants.append(term[:-2])
    if len(term) > 3 and term.endswith("s"):
        variants.append(term[:-1])
    if len(term) > 5 and term.endswith("ing"):
        variants.append(term[:-3])
        variants.append(term[:-3] + "e")
    if len(term) > 4 and term.endswith("ed"):
        variants.append(term[:-2])
        variants.append(term[:-1])

    ordered: list[str] = []
    seen = set()
    for variant in variants:
        cleaned = variant.strip("+-_#")
        canonical = SEMANTIC_TERM_MAP.get(cleaned, cleaned)
        for candidate in (cleaned, canonical):
            if len(candidate) < 2 or candidate in SEARCH_STOPWORDS or candidate in seen:
                continue
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _tokenize_search_terms(text: str) -> list[str]:
    lowered = normalize_user_text(text).lower()
    raw_terms = [term for term in SEARCH_WORD_RE.findall(lowered) if term not in SEARCH_STOPWORDS]
    terms: list[str] = []
    for term in raw_terms:
        terms.extend(_expand_search_term(term))
    if terms:
        return terms

    fallback_raw = [part for part in re.findall(r"[a-z0-9_+#-]{2,}", lowered) if part.strip()]
    fallback: list[str] = []
    for term in fallback_raw:
        fallback.extend(_expand_search_term(term))
    return fallback


def _build_bigrams(tokens: list[str]) -> set[str]:
    if len(tokens) < 2:
        return set()
    return {f"{tokens[index]} {tokens[index + 1]}" for index in range(len(tokens) - 1)}


def _char_ngrams(text: str, size: int = 4) -> set[str]:
    normalized = re.sub(r"\s+", " ", normalize_user_text(text).lower()).strip()
    if not normalized:
        return set()
    if len(normalized) <= size:
        return {normalized}

    padded = f" {normalized} "
    return {padded[index : index + size] for index in range(len(padded) - size + 1)}


def _jaccard_similarity(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / max(len(left | right), 1)


def _hybrid_similarity(
    query: str,
    candidate: str,
    *,
    query_terms: set[str] | None = None,
    candidate_terms: set[str] | None = None,
    query_chargrams: set[str] | None = None,
    candidate_chargrams: set[str] | None = None,
) -> float:
    normalized_query = clean_text(query)
    normalized_candidate = clean_text(candidate)
    if not normalized_query or not normalized_candidate:
        return 0.0

    query_terms = query_terms if query_terms is not None else set(_tokenize_search_terms(normalized_query))
    candidate_terms = (
        candidate_terms if candidate_terms is not None else set(_tokenize_search_terms(normalized_candidate))
    )
    query_chargrams = query_chargrams if query_chargrams is not None else _char_ngrams(normalized_query)
    candidate_chargrams = candidate_chargrams if candidate_chargrams is not None else _char_ngrams(normalized_candidate)

    coverage = len(query_terms & candidate_terms) / max(len(query_terms), 1) if query_terms else 0.0
    token_jaccard = _jaccard_similarity(query_terms, candidate_terms)
    char_jaccard = _jaccard_similarity(query_chargrams, candidate_chargrams)
    sequence_ratio = difflib.SequenceMatcher(
        None,
        normalized_query.lower()[:280],
        normalized_candidate.lower()[:420],
    ).ratio()
    return min(1.0, coverage * 0.4 + token_jaccard * 0.15 + char_jaccard * 0.25 + sequence_ratio * 0.2)


def _normalize_search_score(
    coverage: float,
    bigram_coverage: float,
    exact_query_hit: float,
    source_bonus: float,
    density: float,
    semantic_similarity: float,
    single_term_penalty: float,
) -> float:
    score = (
        coverage * 0.34
        + bigram_coverage * 0.16
        + exact_query_hit * 0.12
        + source_bonus * 0.08
        + density * 0.08
        + semantic_similarity * 0.22
    )
    score -= single_term_penalty
    return max(0.0, min(score, 1.0))


def _trim_summary_sentence(sentence: str, max_chars: int = 220) -> str:
    cleaned = clean_text(sentence)
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[:max_chars].rsplit(" ", 1)[0].rstrip(".,;:!?") + "."


def _best_excerpt_window(
    text: str,
    query: str,
    query_terms: set[str],
    query_chargrams: set[str],
    max_chars: int = 420,
) -> str:
    cleaned = clean_text(text)
    if not cleaned:
        return ""
    if len(cleaned) <= max_chars:
        return cleaned

    parts = [clean_text(part) for part in re.split(r"(?<=[.!?])\s+|\n+", cleaned) if clean_text(part)]
    best_excerpt = cleaned[:max_chars].rstrip() + "..."
    best_score = 0.0

    for index, part in enumerate(parts):
        if len(part) < 20:
            continue
        window_parts = [part]
        if len(part) < max_chars // 2 and index + 1 < len(parts):
            window_parts.append(parts[index + 1])
        candidate = " ".join(window_parts).strip()
        score = _hybrid_similarity(
            query,
            candidate,
            query_terms=query_terms,
            query_chargrams=query_chargrams,
        )
        if score > best_score:
            best_score = score
            best_excerpt = candidate

    if len(best_excerpt) <= max_chars:
        return best_excerpt
    return best_excerpt[:max_chars].rsplit(" ", 1)[0].rstrip(".,;:!?") + "..."


def _looks_sensitive_for_memory(text: str) -> bool:
    return bool(SENSITIVE_MEMORY_RE.search(text))


def _clean_memory_value(value: str, max_chars: int = 120) -> str:
    cleaned = clean_text(value).strip(" .,:;!?")
    cleaned = re.sub(r"\s+", " ", cleaned)
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars].rsplit(" ", 1)[0]
    return cleaned


def _to_second_person_fact(value: str) -> str:
    cleaned = _clean_memory_value(value)
    if not cleaned:
        return ""

    substitutions = (
        (r"^i am\b", "You are"),
        (r"^i'm\b", "You are"),
        (r"^i use\b", "You use"),
        (r"^i prefer\b", "You prefer"),
        (r"^i like\b", "You like"),
        (r"^my\b", "Your"),
    )
    transformed = cleaned
    for pattern, replacement in substitutions:
        transformed = re.sub(pattern, replacement, transformed, count=1, flags=re.IGNORECASE)
    if transformed == cleaned and not transformed.lower().startswith(("you ", "your ")):
        transformed = f"Remembered detail: {transformed}"
    if transformed[-1] not in ".!?":
        transformed += "."
    return transformed[:1].upper() + transformed[1:]


def _extract_user_note(text: str) -> str:
    normalized = clean_text(text)
    if not normalized or "?" in normalized or _looks_sensitive_for_memory(normalized):
        return ""

    patterns: tuple[tuple[re.Pattern[str], str | None], ...] = (
        (re.compile(r"\bmy name is\s+(.+)", re.IGNORECASE), "Your name is {value}."),
        (re.compile(r"\bi prefer\s+(.+)", re.IGNORECASE), "You prefer {value}."),
        (re.compile(r"\bi like\s+(.+)", re.IGNORECASE), "You like {value}."),
        (re.compile(r"\bi use\s+(.+)", re.IGNORECASE), "You use {value}."),
        (re.compile(r"\bi(?: am|'m)\s+working on\s+(.+)", re.IGNORECASE), "You are working on {value}."),
        (re.compile(r"\bmy project is\s+(.+)", re.IGNORECASE), "Your project is {value}."),
        (re.compile(r"\bremember(?:\s+that|\s+this)?\s*:?\s*(.+)", re.IGNORECASE), None),
    )

    for pattern, template in patterns:
        match = pattern.search(normalized)
        if not match:
            continue
        value = _clean_memory_value(match.group(1))
        if not value:
            return ""
        note = template.format(value=value) if template else _to_second_person_fact(value)
        if 8 <= len(note) <= 140 and not _looks_sensitive_for_memory(note):
            return note
        return ""

    return ""


def _fetch_json(url: str, timeout: float = 4.0) -> dict[str, Any] | list[Any] | None:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "GreyIQ/1.0",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            payload = response.read().decode(charset, errors="replace")
        return json.loads(payload)
    except Exception:
        return None


def _sentence_similarity(left: str, right: str) -> float:
    left_tokens = set(_tokenize_search_terms(left))
    right_tokens = set(_tokenize_search_terms(right))
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def _source_id_for_file_name(file_name: str) -> str:
    name = Path(file_name).name
    if name in SOURCE_ID_BY_FILE:
        return SOURCE_ID_BY_FILE[name]
    if name in GENERATED_KNOWLEDGE_FILES:
        return "src_local_notes"
    return "src_imported_docs"


def _normalize_source_filter(source_ids: list[str] | tuple[str, ...] | set[str] | None) -> set[str]:
    return {str(source_id).strip() for source_id in source_ids or [] if str(source_id).strip()}


def _format_core_contract(core_contract: dict[str, Any] | None) -> str:
    if not isinstance(core_contract, dict):
        return ""

    pieces: list[str] = []
    mode = clean_text(str(core_contract.get("mode") or ""))
    personality = clean_text(str(core_contract.get("personality") or ""))
    if mode or personality:
        pieces.append("mode " + ", ".join(part for part in (mode, personality) if part))

    response_contract = [
        str(item).replace("_", " ").strip()
        for item in core_contract.get("responseContract") or []
        if str(item).strip()
    ][:3]
    if response_contract:
        pieces.append("respond by " + ", ".join(response_contract))

    confidence_policy = [
        str(item).replace("_", " ").strip()
        for item in core_contract.get("confidencePolicy") or []
        if str(item).strip()
    ][:3]
    if confidence_policy:
        pieces.append("confidence: " + ", ".join(confidence_policy))

    trust_contract = core_contract.get("trustContract")
    if isinstance(trust_contract, dict):
        trust_notes = [
            clean_text(str(trust_contract.get(key) or ""))
            for key in ("uncertainty", "citations", "judgment")
        ]
        trust_notes = [note for note in trust_notes if note][:2]
        if trust_notes:
            pieces.append("trust: " + " ".join(trust_notes))

    return "; ".join(pieces)


class KnowledgeBase:
    def __init__(self, base_dir: str | Path = ".", data_folder: str = DEFAULT_DATA_FOLDER):
        self.base_dir = Path(base_dir)
        self.data_folder = self.base_dir / data_folder
        self.documents: list[tuple[str, str]] = []
        self.chunks: list[dict[str, str | int]] = []
        self.reload()

    @property
    def document_count(self) -> int:
        return len(self.documents)

    @property
    def chunk_count(self) -> int:
        return len(self.chunks)

    def reload(self) -> None:
        """Index all known training text into searchable chunks.

        Tokens are NOT pre-computed here — building 270k token sets up front
        was the single slowest startup step (~10s on a large corpus). Instead
        each chunk stores `tokens=None` and `search()` materializes the set
        on first access, caching it on the chunk so subsequent queries are
        free. This drops cold-startup KB build time by ~8x.
        """
        self.documents = []
        self.chunks = []
        self.data_folder.mkdir(parents=True, exist_ok=True)

        for txt_path in sorted(self.data_folder.glob("*.txt")):
            try:
                text = txt_path.read_text(encoding="utf-8").strip()
            except Exception:
                continue
            if not text:
                continue

            self.documents.append((txt_path.name, text))
            for chunk in _chunk_text(text):
                self.chunks.append(
                    {
                        "source": txt_path.name,
                        "source_lower": txt_path.name.lower(),
                        "source_id": _source_id_for_file_name(txt_path.name),
                        "text": chunk,
                        "search_text": chunk.lower(),
                        "tokens": None,
                        "chargrams": None,
                    }
                )

        root_train = self.base_dir / "train.txt"
        if root_train.exists():
            try:
                text = root_train.read_text(encoding="utf-8").strip()
            except Exception:
                text = ""
            if text:
                self.documents.append((root_train.name, text))
                for chunk in _chunk_text(text):
                    self.chunks.append(
                        {
                            "source": root_train.name,
                            "source_lower": root_train.name.lower(),
                            "source_id": _source_id_for_file_name(root_train.name),
                            "text": chunk,
                            "search_text": chunk.lower(),
                            "tokens": None,
                            "chargrams": None,
                        }
                    )

    def _chunk_tokens(self, chunk: dict) -> set:
        tokens = chunk.get("tokens")
        if tokens is None:
            tokens = set(_tokenize_search_terms(str(chunk.get("search_text", ""))))
            chunk["tokens"] = tokens
        return tokens

    def _chunk_chargrams(self, chunk: dict) -> set[str]:
        chargrams = chunk.get("chargrams")
        if chargrams is None:
            chargrams = _char_ngrams(str(chunk.get("search_text", "")))
            chunk["chargrams"] = chargrams
        return chargrams

    def search(
        self,
        query: str,
        limit: int = 3,
        min_score: float = 0.45,
        *,
        source_ids: list[str] | tuple[str, ...] | set[str] | None = None,
    ) -> list[SourceMatch]:
        query = query.strip()
        if not query or not self.chunks:
            return []

        allowed_source_ids = _normalize_source_filter(source_ids)
        lowered_query = query.lower()
        query_terms = _tokenize_search_terms(lowered_query)
        query_term_set = set(query_terms)
        query_bigrams = _build_bigrams(query_terms)
        query_term_count = max(len(query_term_set), 1)
        query_bigram_count = max(len(query_bigrams), 1)
        query_chargrams: set[str] | None = None

        scored: list[SourceMatch] = []
        for chunk in self.chunks:
            chunk_source_id = str(chunk.get("source_id") or _source_id_for_file_name(str(chunk.get("source", ""))))
            if allowed_source_ids and chunk_source_id not in allowed_source_ids:
                continue
            text = str(chunk["search_text"])
            source_name = str(chunk.get("source_lower") or chunk["source"]).lower()
            # Lazy: tokens are built on first scan and cached on the chunk.
            chunk_tokens = self._chunk_tokens(chunk)
            matched_terms = query_term_set & chunk_tokens
            term_hits = len(matched_terms)
            exact_query_hit = 1.0 if lowered_query in text else 0.0
            bigram_hits = sum(1 for gram in query_bigrams if gram in text)
            source_bonus = min(
                1.0,
                sum(1 for term in query_term_set if term in source_name) / max(len(query_term_set), 1),
            )
            if not term_hits and exact_query_hit == 0.0 and bigram_hits == 0 and source_bonus == 0.0:
                continue

            coverage = term_hits / query_term_count
            bigram_coverage = bigram_hits / query_bigram_count if query_bigrams else 0.0
            density = term_hits / max(len(chunk_tokens), 1)
            single_term_penalty = 0.0
            if len(query_term_set) >= 2 and term_hits <= 1 and exact_query_hit == 0.0 and bigram_coverage == 0.0:
                single_term_penalty = 0.35
            elif len(query_term_set) >= 3 and coverage < 0.34 and bigram_coverage == 0.0:
                single_term_penalty = 0.2

            semantic_similarity = 0.0
            if exact_query_hit == 0.0 and (coverage < 0.95 or bigram_coverage < 0.95):
                if query_chargrams is None:
                    query_chargrams = _char_ngrams(lowered_query)
                semantic_similarity = _hybrid_similarity(
                    lowered_query,
                    text,
                    query_terms=query_term_set,
                    candidate_terms=chunk_tokens,
                    query_chargrams=query_chargrams,
                    candidate_chargrams=self._chunk_chargrams(chunk),
                )

            score = _normalize_search_score(
                coverage=coverage,
                bigram_coverage=bigram_coverage,
                exact_query_hit=exact_query_hit,
                source_bonus=source_bonus,
                density=density,
                semantic_similarity=semantic_similarity,
                single_term_penalty=single_term_penalty,
            )
            # De-poison the ranking BEFORE the min_score cut: a lexical hit inside the 6 MB
            # off-domain PDF blob must not outrank the curated bug-bounty corpus (see
            # _SOURCE_TRUST_BY_FILE). Clamped back into 0..1 so downstream confidence math,
            # which assumes a normalized score, is unaffected.
            score = max(0.0, min(1.0, score * _source_trust(str(chunk.get("source", "")))))

            if score >= min_score:
                excerpt = _best_excerpt_window(
                    str(chunk["text"]),
                    query,
                    query_term_set,
                    query_chargrams,
                    max_chars=420,
                )
                scored.append(
                    SourceMatch(
                        source=str(chunk["source"]),
                        score=score,
                        excerpt=excerpt,
                        source_id=chunk_source_id,
                    )
                )

        scored.sort(key=lambda match: (match.score, len(match.excerpt)), reverse=True)

        unique_results: list[SourceMatch] = []
        source_counts: dict[str, int] = {}
        for match in scored:
            current_count = source_counts.get(match.source, 0)
            if current_count >= 2:
                continue
            if any(
                existing.source == match.source and _sentence_similarity(existing.excerpt, match.excerpt) > 0.82
                for existing in unique_results
            ):
                continue
            unique_results.append(match)
            source_counts[match.source] = current_count + 1
            if len(unique_results) >= limit:
                break

        return unique_results


def _is_usable_model_file(path: Path) -> bool:
    """Filter out partially-written or zero-byte files that would crash torch.load."""
    if not path.exists() or not path.is_file():
        return False
    if path.suffix == ".tmp" or path.name.endswith(".pt.tmp"):
        return False
    try:
        return path.stat().st_size > 1024
    except OSError:
        return False


def _best_model_candidates(root: Path) -> list[Path]:
    """Return best-model files ordered by their actual save time."""
    candidates = [
        path for path in (root / STABLE_MODELS_DIR).rglob(BEST_MODEL_ARCHIVE_GLOB) if _is_usable_model_file(path)
    ]
    latest_alias = root / MODEL_CANDIDATES[0]
    if _is_usable_model_file(latest_alias):
        candidates.append(latest_alias)

    unique: dict[Path, Path] = {}
    for candidate in candidates:
        try:
            key = candidate.resolve()
        except OSError:
            key = candidate
        unique[key] = candidate

    return sorted(unique.values(), key=lambda path: path.stat().st_mtime, reverse=True)


def find_model_path(base_dir: str | Path = ".") -> Path | None:
    """Locate the most recent usable model.

    Priority:
      1. Newest best model by save time, including the project-root
         `best_model.pt` alias and dated StableModels snapshots
      2. Any other known checkpoint file at the project root

    Partial writes (`*.tmp`) and empty files are ignored so the chat engine
    never tries to load a half-written checkpoint while the trainer is
    flushing it to disk.
    """
    root = Path(base_dir)
    best_models = _best_model_candidates(root)
    if best_models:
        return best_models[0]
    for filename in MODEL_CANDIDATES[1:]:
        candidate = root / filename
        if _is_usable_model_file(candidate):
            return candidate
    return None


def _load_model_artifacts(base_dir: Path, model_path: Path, device: str):
    payload = _safe_torch_load(model_path, map_location="cpu")
    config: dict[str, Any] | None = None
    vocab_size = None
    encode = None
    decode = None

    if isinstance(payload, dict) and "model_state_dict" in payload:
        state_dict = payload["model_state_dict"]
        config = payload.get("config")
        # BPE-trained checkpoint? Detect via tokenizer_kind or presence of
        # merges; fall through to the char-level path otherwise.
        if (payload.get("tokenizer_kind") == "bpe" or payload.get("merges") is not None) and payload.get("stoi"):
            from solin_bpe import BPETokenizer

            merges = [tuple(p) for p in payload.get("merges") or []]
            tok = BPETokenizer(stoi=payload["stoi"], merges=merges)
            encode = tok.encode
            decode = tok.decode
            vocab_size = int(payload.get("vocab_size") or len(tok.stoi))
        elif payload.get("stoi") and payload.get("itos"):
            stoi = payload["stoi"]
            itos, encode, decode = build_codecs(stoi, payload["itos"])
            vocab_size = int(payload.get("vocab_size") or len(stoi))
    else:
        state_dict = payload

    if config is None:
        config_path = base_dir / CONFIG_FILE
        if config_path.exists():
            config = load_config(config_path)
        else:
            config = {}

    config = _normalize_model_config(config, state_dict)
    state_dict = _upgrade_legacy_attention_state_dict(state_dict, config)

    if encode is None or decode is None or vocab_size is None:
        vocab_size, _, _, encode, decode = load_vocab(base_dir / VOCAB_FILE)

    return state_dict, config, vocab_size, encode, decode


class ChatMemory:
    def __init__(self, memory_path: str | Path):
        self.memory_path = Path(memory_path)
        self.entries: list[dict[str, Any]] = []
        self.notes: list[dict[str, Any]] = []
        self.load()

    def load(self) -> None:
        self.entries = []
        self.notes = []
        if not self.memory_path.exists():
            return

        try:
            with self.memory_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except Exception:
                        continue
                    kind = str(payload.get("kind", "exchange")).strip().lower()
                    if kind == "note":
                        note = clean_text(str(payload.get("note", "")))
                        if not note:
                            continue
                        payload["kind"] = "note"
                        payload["note"] = note
                        payload["_tokens"] = set(_tokenize_search_terms(note))
                        payload["_chargrams"] = _char_ngrams(note)
                        self.notes.append(payload)
                        continue

                    user = clean_text(str(payload.get("user", "")))
                    assistant = clean_text(str(payload.get("assistant", "")))
                    if not user or not assistant:
                        continue
                    combined = f"{user} {assistant}".lower()
                    payload["kind"] = "exchange"
                    payload["user"] = user
                    payload["assistant"] = assistant
                    payload["_tokens"] = set(_tokenize_search_terms(combined))
                    payload["_chargrams"] = _char_ngrams(combined)
                    self.entries.append(payload)
        except Exception:
            self.entries = []
            self.notes = []

    def _append_record(self, runtime_record: dict[str, Any]) -> dict[str, Any]:
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        serializable = {key: value for key, value in runtime_record.items() if not key.startswith("_")}
        with self.memory_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(serializable, ensure_ascii=False) + "\n")
        return runtime_record

    def add_exchange(self, user: str, assistant: str) -> dict[str, Any] | None:
        record = {
            "kind": "exchange",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": clean_text(user),
            "assistant": clean_text(assistant),
        }
        if not record["user"] or not record["assistant"]:
            return None
        if self.entries:
            last = self.entries[-1]
            if last.get("user") == record["user"] and last.get("assistant") == record["assistant"]:
                return last

        combined = f"{record['user']} {record['assistant']}".lower()
        runtime_record = dict(record)
        runtime_record["_tokens"] = set(_tokenize_search_terms(combined))
        runtime_record["_chargrams"] = _char_ngrams(combined)
        self.entries.append(runtime_record)
        return self._append_record(runtime_record)

    def add_note(self, note: str, *, source_user: str = "") -> dict[str, Any] | None:
        cleaned_note = clean_text(note)
        if not cleaned_note or _looks_sensitive_for_memory(cleaned_note):
            return None
        if any(existing.get("note") == cleaned_note for existing in self.notes[-40:]):
            return None

        record = {
            "kind": "note",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "note": cleaned_note,
            "source_user": clean_text(source_user),
        }
        runtime_record = dict(record)
        runtime_record["_tokens"] = set(_tokenize_search_terms(cleaned_note))
        runtime_record["_chargrams"] = _char_ngrams(cleaned_note)
        self.notes.append(runtime_record)
        return self._append_record(runtime_record)

    def remember_user_note(self, user_text: str) -> dict[str, Any] | None:
        note = _extract_user_note(user_text)
        if not note:
            return None
        return self.add_note(note, source_user=user_text)

    def search(self, query: str, limit: int = 2, min_score: float = 0.24) -> list[MemoryMatch]:
        normalized_query = clean_text(query)
        if not normalized_query:
            return []

        query_terms = set(_tokenize_search_terms(normalized_query))
        if not query_terms:
            return []
        query_chargrams: set[str] | None = None

        recent_entries = self.entries[-300:]
        total = max(len(recent_entries), 1)
        scored: list[MemoryMatch] = []

        for index, payload in enumerate(reversed(recent_entries)):
            combined = f"{payload.get('user', '')} {payload.get('assistant', '')}".lower()
            tokens = payload.get("_tokens")
            if not tokens:
                tokens = set(_tokenize_search_terms(combined))
                payload["_tokens"] = tokens
            chargrams = payload.get("_chargrams")
            if not chargrams:
                chargrams = _char_ngrams(combined)
                payload["_chargrams"] = chargrams

            overlap = len(query_terms & set(tokens))
            exact_query_hit = 1.0 if normalized_query.lower() in combined else 0.0
            if not overlap and exact_query_hit == 0.0:
                continue
            semantic_similarity = 0.0
            if exact_query_hit == 0.0:
                if query_chargrams is None:
                    query_chargrams = _char_ngrams(normalized_query)
                semantic_similarity = _hybrid_similarity(
                    normalized_query,
                    combined,
                    query_terms=query_terms,
                    candidate_terms=set(tokens),
                    query_chargrams=query_chargrams,
                    candidate_chargrams=chargrams,
                )

            assistant_terms = set(_tokenize_search_terms(str(payload.get("assistant", ""))))
            coverage = overlap / max(len(query_terms), 1)
            assistant_overlap = len(query_terms & assistant_terms) / max(len(query_terms), 1)
            recency_bonus = max(0.0, 1.0 - (index / total)) * 0.08
            score = min(
                1.0,
                coverage * 0.33
                + assistant_overlap * 0.12
                + exact_query_hit * 0.14
                + semantic_similarity * 0.33
                + recency_bonus,
            )
            if score < min_score:
                continue

            scored.append(
                MemoryMatch(
                    score=score,
                    user=str(payload.get("user", "")),
                    assistant=str(payload.get("assistant", "")),
                    timestamp=str(payload.get("timestamp", "")),
                )
            )

        scored.sort(key=lambda match: match.score, reverse=True)
        unique: list[MemoryMatch] = []
        seen_pairs: set[tuple[str, str]] = set()
        for match in scored:
            pair = (match.user, match.assistant)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            unique.append(match)
            if len(unique) >= limit:
                break
        return unique

    def search_notes(self, query: str, limit: int = 2, min_score: float = 0.24) -> list[NoteMatch]:
        normalized_query = clean_text(query)
        if not normalized_query or not self.notes:
            return []

        query_terms = set(_tokenize_search_terms(normalized_query))
        if not query_terms:
            return []
        query_chargrams: set[str] | None = None

        recent_notes = self.notes[-200:]
        total = max(len(recent_notes), 1)
        scored: list[NoteMatch] = []

        for index, payload in enumerate(reversed(recent_notes)):
            note = str(payload.get("note", ""))
            tokens = payload.get("_tokens")
            if not tokens:
                tokens = set(_tokenize_search_terms(note))
                payload["_tokens"] = tokens
            chargrams = payload.get("_chargrams")
            if not chargrams:
                chargrams = _char_ngrams(note)
                payload["_chargrams"] = chargrams

            overlap = len(query_terms & set(tokens))
            exact_query_hit = 1.0 if normalized_query.lower() in note.lower() else 0.0
            if not overlap and exact_query_hit == 0.0:
                continue
            semantic_similarity = 0.0
            if exact_query_hit == 0.0:
                if query_chargrams is None:
                    query_chargrams = _char_ngrams(normalized_query)
                semantic_similarity = _hybrid_similarity(
                    normalized_query,
                    note,
                    query_terms=query_terms,
                    candidate_terms=set(tokens),
                    query_chargrams=query_chargrams,
                    candidate_chargrams=chargrams,
                )

            coverage = overlap / max(len(query_terms), 1)
            recency_bonus = max(0.0, 1.0 - (index / total)) * 0.06
            score = min(1.0, coverage * 0.34 + exact_query_hit * 0.16 + semantic_similarity * 0.44 + recency_bonus)
            if score < min_score:
                continue

            scored.append(
                NoteMatch(
                    score=score,
                    note=note,
                    timestamp=str(payload.get("timestamp", "")),
                )
            )

        scored.sort(key=lambda match: match.score, reverse=True)
        unique: list[NoteMatch] = []
        seen_notes: set[str] = set()
        for match in scored:
            if match.note in seen_notes:
                continue
            seen_notes.add(match.note)
            unique.append(match)
            if len(unique) >= limit:
                break
        return unique


class SolinEngine:
    def __init__(
        self,
        base_dir: str | Path = ".",
        *,
        status_callback: Callable[[str], None] | None = None,
    ):
        report = status_callback or (lambda _msg: None)
        self.base_dir = Path(base_dir)
        # Load runtime config FIRST so device_preference can drive detection.
        self.runtime_config = load_runtime_config(self.base_dir / RUNTIME_CONFIG_FILE)
        self.internet_enabled = bool(self.runtime_config.get("internet_enabled", False))
        self.device_preference = _normalize_device_pref(self.runtime_config.get("device_preference", "auto"))
        try:
            runtime_config_exists = (self.base_dir / RUNTIME_CONFIG_FILE).exists()
        except OSError:
            runtime_config_exists = True
        if not runtime_config_exists:
            save_runtime_config(self.runtime_config, self.base_dir / RUNTIME_CONFIG_FILE)
        report("Detecting compute device...")
        self.device_info = detect_best_device(self.device_preference)
        _configure_torch_runtime()
        report("Indexing knowledge base...")
        self.knowledge_base = KnowledgeBase(self.base_dir)
        report("Loading chat memory...")
        self.chat_memory = ChatMemory(self.base_dir / DEFAULT_DATA_FOLDER / CHAT_MEMORY_FILE)
        report("Reading inference config...")
        self.inference_config = load_inference_config(self.base_dir / INFERENCE_CONFIG_FILE)
        self.response_mode = self.inference_config["mode"]
        try:
            inference_config_exists = (self.base_dir / INFERENCE_CONFIG_FILE).exists()
        except OSError:
            inference_config_exists = True
        if not inference_config_exists:
            try:
                save_inference_config(self.inference_config, self.base_dir / INFERENCE_CONFIG_FILE)
            except OSError:
                pass
        report("Loading safety policy...")
        self.safety = SafetyPolicy(
            self.base_dir / SAFETY_CONFIG_FILE,
            self.base_dir / AUDIT_LOG_FILE,
        )
        try:
            from solin_persona import PersonaState

            self.persona = PersonaState(mode="auto")
        except Exception:
            self.persona = None
        self.model = None
        self.model_error = ""
        self.model_path: Path | None = None
        self.config: dict[str, Any] | None = None
        self.block_size = 64
        self.encode = lambda _: []
        self.decode = lambda _: ""
        self.memory_recording_enabled = True
        self.max_history_turns = MAX_RECENT_TURNS
        self._turns: list[tuple[str, str]] = []
        self._stop_sequences: list[list[int]] = []
        self._engine_lock = threading.RLock()
        self._history = [
            "<START_CONVO>\n<USER>\nWhat is your name?\n<ASSISTANT>\nMy name is GreyIQ.\n<END_CONVO>",
        ]
        report("Loading latest stable model...")
        self._load_model()
        report("Ready")

    @property
    def ready(self) -> bool:
        return self.model is not None

    @property
    def live_memory_learning(self) -> bool:
        return self.memory_recording_enabled

    @live_memory_learning.setter
    def live_memory_learning(self, value: bool) -> None:
        self.memory_recording_enabled = bool(value)

    def _load_model(self) -> None:
        candidates = self._collect_model_candidates(limit=5)
        if not candidates:
            self.model = None
            self.model_path = None
            self.model_error = (
                "No trained model file was found. " f"Run a training cycle to populate {STABLE_MODELS_DIR}/<date>/."
            )
            return

        last_error = ""
        for candidate in candidates:
            try:
                state_dict, config, vocab_size, encode, decode = _load_model_artifacts(
                    self.base_dir,
                    candidate,
                    self.device_info.name,
                )

                model = TinyGPT(vocab_size, config)
                model.load_state_dict(state_dict)
                model.to(self.device_info.name)
                model.eval()

                self.model = model
                self.model_path = candidate
                self.model_error = ""
                self.config = config
                self.block_size = int(config["block_size"])
                self.encode = encode
                self.decode = decode
                self._refresh_stop_sequences()
                return
            except Exception as exc:
                last_error = f"{candidate.name}: {exc}"
                continue

        self.model = None
        self.model_path = None
        self._stop_sequences = []
        self.model_error = f"Could not load latest model. Last error -> {last_error}"

    def _collect_model_candidates(self, limit: int = 5) -> list[Path]:
        root = Path(self.base_dir)
        candidates: list[Path] = _best_model_candidates(root)[:limit]
        for filename in MODEL_CANDIDATES[1:]:
            candidate = root / filename
            if _is_usable_model_file(candidate) and candidate not in candidates:
                candidates.append(candidate)
        return candidates

    def refresh_knowledge(self) -> None:
        with self._engine_lock:
            self.knowledge_base.reload()
            self.chat_memory.load()

    def _resolve_mode(self, mode: str | None = None) -> str:
        candidate = self.response_mode if mode is None else mode
        normalized = str(candidate).strip().lower()
        if normalized not in INFERENCE_MODES:
            return DEFAULT_INFERENCE_CONFIG["mode"]
        return normalized

    def _mode_settings(self, mode: str | None = None) -> dict[str, float | int]:
        return MODE_SETTINGS[self._resolve_mode(mode)]

    def set_response_mode(self, mode: str) -> None:
        with self._engine_lock:
            normalized = self._resolve_mode(mode)
            self.response_mode = normalized
            self.inference_config = {"mode": normalized}
            save_inference_config(self.inference_config, self.base_dir / INFERENCE_CONFIG_FILE)

    def set_internet_enabled(self, enabled: bool) -> None:
        with self._engine_lock:
            self.internet_enabled = bool(enabled)
            self.runtime_config = {
                "internet_enabled": self.internet_enabled,
                "device_preference": self.device_preference,
            }
            save_runtime_config(self.runtime_config, self.base_dir / RUNTIME_CONFIG_FILE)

    def set_device_preference(self, preference: str) -> str:
        """Persist the device preference. Re-detection happens on next reload.

        Returns the normalized value actually stored (auto/cpu/cuda).
        """
        with self._engine_lock:
            normalized = _normalize_device_pref(preference)
            self.device_preference = normalized
            self.runtime_config = {
                "internet_enabled": self.internet_enabled,
                "device_preference": normalized,
            }
            save_runtime_config(self.runtime_config, self.base_dir / RUNTIME_CONFIG_FILE)
            return normalized

    def reload_with_device_preference(self, preference: str | None = None) -> None:
        """Re-run device detection and reload the model. Use after the
        operator changes device preference so they don't have to restart."""
        with self._engine_lock:
            if preference is not None:
                self.device_preference = _normalize_device_pref(preference)
                self.runtime_config = {
                    "internet_enabled": self.internet_enabled,
                    "device_preference": self.device_preference,
                }
                save_runtime_config(self.runtime_config, self.base_dir / RUNTIME_CONFIG_FILE)
            self.device_info = detect_best_device(self.device_preference)
            self.model = None
            self.model_error = ""
            self.model_path = None
            self.config = None
            self._stop_sequences = []
            self._load_model()

    # --- Safety policy passthroughs ---------------------------------------
    # These exist so the GUI talks to the engine, not directly to the policy
    # object. The policy is the source of truth and enforces invariants.

    def safety_state(self) -> dict[str, Any]:
        return self.safety.snapshot()

    def set_safety_flag(self, name: str, value: Any) -> dict[str, Any]:
        with self._engine_lock:
            return self.safety.set_flag(name, value)

    def set_safety_authorization(self, ack_text: str, scope_note: str) -> dict[str, Any]:
        with self._engine_lock:
            return self.safety.set_authorization(ack_text, scope_note)

    def clear_safety_authorization(self) -> dict[str, Any]:
        with self._engine_lock:
            return self.safety.clear_authorization()

    def safety_audit_tail(self, lines: int = 200) -> str:
        return self.safety.audit_tail(lines)

    def safety_capability_label(self) -> str:
        return self.safety.capability_label()

    def reload_model(self) -> None:
        with self._engine_lock:
            self.model = None
            self.model_error = ""
            self.model_path = None
            self.config = None
            self._stop_sequences = []
            self._load_model()

    def _reload_model_on_cpu_after_failure(self, exc: BaseException) -> bool:
        if self.device_info.name != "cuda" or not _is_retryable_cuda_failure(exc):
            return False

        try:
            torch.cuda.empty_cache()
        except Exception:
            pass

        self.device_info = DeviceInfo("cpu", f"Recovered from CUDA inference failure by falling back to CPU. {exc}")
        self.model = None
        self.model_error = ""
        self.model_path = None
        self.config = None
        self._stop_sequences = []
        self._load_model()
        return self.ready

    def reset_conversation(self) -> None:
        with self._engine_lock:
            self._turns = []
            self._history = [
                "<START_CONVO>\n<USER>\nWhat is your name?\n<ASSISTANT>\nMy name is GreyIQ.\n<END_CONVO>",
            ]

    def _refresh_stop_sequences(self) -> None:
        if not self.ready:
            self._stop_sequences = []
            return

        sequences: list[list[int]] = []
        seen: set[tuple[int, ...]] = set()
        for marker in STOP_MARKERS:
            try:
                encoded = self.encode(marker)
            except Exception:
                continue
            if not encoded:
                continue
            sequence = tuple(encoded)
            if sequence in seen:
                continue
            seen.add(sequence)
            sequences.append(list(sequence))
        self._stop_sequences = sequences

    def search_documents(
        self,
        query: str,
        limit: int = 3,
        *,
        mode: str | None = None,
        source_ids: list[str] | tuple[str, ...] | set[str] | None = None,
    ) -> list[SourceMatch]:
        with self._engine_lock:
            settings = self._mode_settings(mode)
            return self.knowledge_base.search(
                query,
                limit=limit,
                min_score=float(settings["retrieval_threshold"]),
                source_ids=source_ids,
            )

    def status_summary(self) -> str:
        with self._engine_lock:
            model_name = self.model_path.name if self.model_path else "no model"
            memory_count = len(self.chat_memory.entries) + len(self.chat_memory.notes)
            internet_label = "on" if self.internet_enabled else "off"
            if self.ready:
                saved_at = _format_timestamp(
                    self.model_path.stat().st_mtime if self.model_path and self.model_path.exists() else None
                )
                origin = ""
                if self.model_path and STABLE_MODELS_DIR in self.model_path.parts:
                    try:
                        stable_index = self.model_path.parts.index(STABLE_MODELS_DIR)
                        origin = " | From: " + "/".join(self.model_path.parts[stable_index : stable_index + 2])
                    except ValueError:
                        origin = ""
                return (
                    f"Model: {model_name} | Saved: {saved_at}{origin} | Device: {self.device_info.name} "
                    f"| Mode: {self.response_mode} | Internet: {internet_label} | Memory: {memory_count}"
                )
            return (
                f"Model unavailable | Device: {self.device_info.name} | Mode: {self.response_mode} "
                f"| Internet: {internet_label} | Memory: {memory_count}"
            )

    def detailed_status(self) -> str:
        if self.ready:
            return f"{self.status_summary()} | {self.device_info.reason}"
        return f"{self.status_summary()} | {self.device_info.reason} | {self.model_error}"

    def _fallback_response(
        self,
        matches: list[SourceMatch],
        summary: str = "",
        intent: QueryIntent | None = None,
        memory_summary: str = "",
        note_summary: str = "",
    ) -> str:
        label = intent.label if intent else ""

        # Casual fallbacks: stay warm, never mention documents/grounding.
        if intent and _is_casual_intent(label) and label != QUERY_INTENT_SIMPLE_MATH:
            if label == QUERY_INTENT_CASUAL_GREETING:
                return "Hey, what's up?"
            if label == QUERY_INTENT_CASUAL_CHECKIN:
                return "Doing alright — what about you?"
            if label == QUERY_INTENT_EMOTIONAL_SUPPORT:
                return "That sounds rough. Want to vent for a minute, or talk it through?"
            if label == QUERY_INTENT_CASUAL_OPINION:
                return "Honestly, I could go either way on that — what's pulling at you about it?"
            if label == QUERY_INTENT_IDENTITY:
                return "I'm GreyIQ."
            return "I'm not totally sure what you mean, but I'm with you. Say it another way?"

        support_parts: list[str] = []
        if label in {QUERY_INTENT_SIMPLE, QUERY_INTENT_SIMPLE_MATH}:
            if note_summary:
                support_parts.append(note_summary.strip())
            if memory_summary:
                support_parts.append(memory_summary.strip())
        elif label in KNOWLEDGE_INTENT_LABELS:
            if note_summary:
                support_parts.append(note_summary.strip())
        if summary:
            support_parts.append(summary.strip())
        support = " ".join(part for part in support_parts if part).strip()

        if support:
            if intent and intent.wants_summary:
                return f"Here's the short version: {support}"
            if label == QUERY_INTENT_DOCUMENT and summary:
                if len(support) > 1:
                    return f"Based on your documents, {support[0].lower() + support[1:]}"
                return f"Based on your documents, {support}"
            return support

        if label == QUERY_INTENT_DOCUMENT:
            if matches:
                return (
                    f"I couldn't pull a clean answer, but the closest match is {matches[0].source}. "
                    "Try a more specific keyword or file name."
                )
            return (
                "I couldn't find a strong match in your indexed documents for that. "
                "Try a file name, topic keyword, or add the document to the data folder."
            )
        if label == QUERY_INTENT_CODING:
            return "I don't have enough to write that code yet — share the function signature, an example input/output, or the error you're seeing."
        if label == QUERY_INTENT_BUG_BOUNTY:
            return (
                "For bug bounty, start with scope, asset type, auth state, and one concrete surface. "
                "Prioritize high-impact classes (access control, auth, injection, SSRF, secrets), prove one root cause with a clean observed-vs-control artifact, then write the smallest reproducible report."
            )
        if label == QUERY_INTENT_PLANNING:
            return "I need a bit more to plan this — what's the goal, the deadline, and the main constraints?"
        if label == QUERY_INTENT_WEB:
            return "I couldn't fetch a current result for that. Try rephrasing the search or check your connection."
        if matches:
            return f"I couldn't produce a clean grounded answer, but the closest source is {matches[0].source}."
        return "I don't have enough to give a confident answer yet. A bit more context would help."

    def _build_system_prompt(
        self,
        intent: QueryIntent,
        has_context: bool,
        has_memory: bool = False,
        user_input: str = "",
        core_contract: dict[str, Any] | None = None,
    ) -> str:
        if _is_casual_intent(intent.label):
            style = self._casual_style_instruction(intent, user_input)
        elif _is_serious_intent(intent.label) or intent.label == QUERY_INTENT_WEB:
            style = self._work_style_instruction(intent, user_input)
        elif intent.wants_summary:
            style = "give a short conversational summary"
        else:
            style = "answer clearly and directly"
        if intent.wants_code and "code" not in style:
            style += "; include concrete code only if it helps"
        if _is_casual_intent(intent.label):
            context_note = "use remembered details only if personally relevant; do not mention documents"
        elif has_context or has_memory:
            context_note = "use remembered details only when relevant; do not guess"
        else:
            context_note = "do not over-explain"
        prompt = f"{style}; {context_note}"
        core_note = _format_core_contract(core_contract)
        if core_note:
            prompt = f"{prompt}; core: {core_note}"
        safety_note = self.safety.system_prompt_addendum() if hasattr(self, "safety") else ""
        if safety_note:
            prompt = f"{prompt}; {safety_note}"
        persona = getattr(self, "persona", None)
        overlay = persona.overlay_for(user_input) if persona is not None else ""
        if overlay:
            prompt = f"{overlay}\n\n{prompt}"
        return prompt

    def _encoded_length(self, text: str) -> int:
        if not text:
            return 0
        if not self.ready:
            return len(text)
        try:
            return len(self.encode(text))
        except Exception:
            return len(text)

    def _trim_to_budget(self, text: str, budget: int, *, keep_tail: bool = False) -> str:
        normalized = clean_text(text)
        if not normalized or budget <= 0:
            return ""
        if self._encoded_length(normalized) <= budget:
            return normalized

        lo, hi = 1, len(normalized)
        best = ""
        while lo <= hi:
            mid = (lo + hi) // 2
            candidate = normalized[-mid:] if keep_tail else normalized[:mid]
            if self._encoded_length(candidate) <= budget:
                best = candidate
                lo = mid + 1
            else:
                hi = mid - 1

        best = best.strip()
        if not best:
            return ""
        if len(best) < len(normalized):
            if keep_tail and len(best) > 4:
                best = "..." + best[-(len(best) - 3) :]
            elif not keep_tail and len(best) > 4:
                best = best[: len(best) - 3].rstrip(" ,.;:") + "..."
        return best

    def _build_recent_history_snapshot(self, user_input: str, limit: int = 3) -> str:
        if not self._turns:
            return ""
        query_terms = set(_tokenize_search_terms(user_input))
        query_chargrams = _char_ngrams(user_input)
        recent_turns = self._turns[-self.max_history_turns :]
        total = max(len(recent_turns), 1)
        scored_turns: list[tuple[float, int, str, str]] = []
        for index, (user, assistant) in enumerate(recent_turns):
            combined = f"{user}\n{assistant}"
            relevance = _hybrid_similarity(
                user_input,
                combined,
                query_terms=query_terms,
                query_chargrams=query_chargrams,
            )
            recency_bonus = ((index + 1) / total) * 0.18
            scored_turns.append((relevance + recency_bonus, index, user, assistant))

        selected_turns = sorted(scored_turns, key=lambda item: item[0], reverse=True)[:limit]
        selected_turns.sort(key=lambda item: item[1])
        pieces: list[str] = []
        for _, _, user, assistant in selected_turns:
            user_short = self._trim_to_budget(user, 70, keep_tail=True)
            assistant_short = self._trim_to_budget(assistant, 90)
            if not user_short or not assistant_short:
                continue
            pieces.append(f"U:{user_short} A:{assistant_short}")
        return " | ".join(pieces)

    def _compress_memory_context(self, user_input: str, matches: list[MemoryMatch]) -> str:
        if not matches:
            return ""

        snippets: list[str] = []
        lowered_query = user_input.lower().strip()
        for match in matches[:2]:
            answer = self._trim_to_budget(match.assistant, 110)
            if not answer:
                continue
            if match.user.lower().strip() == lowered_query:
                snippets.append(f"Earlier answer: {answer}")
                continue
            question = self._trim_to_budget(match.user, 45, keep_tail=True)
            snippets.append(f"{question} -> {answer}")
        return " | ".join(dict.fromkeys(snippets))

    def _compress_note_context(self, matches: list[NoteMatch]) -> str:
        if not matches:
            return ""

        snippets: list[str] = []
        for match in matches[:2]:
            note = self._trim_to_budget(match.note, 110)
            if note:
                snippets.append(note)
        return " ".join(dict.fromkeys(snippets))

    def _pack_prompt_sections(self, sections: list[PromptSection], prompt_budget: int) -> str:
        scaffold_prefix = "<START_CONVO>\n<USER>\n"
        scaffold_suffix = "\n<ASSISTANT>\n"
        fixed_overhead = self._encoded_length(scaffold_prefix + scaffold_suffix)
        active_sections = [section for section in sections if clean_text(section.text)]
        if not active_sections:
            return scaffold_prefix + scaffold_suffix

        remaining = max(prompt_budget - fixed_overhead, 0)
        allocations: dict[str, int] = {}
        required_sections = [section for section in active_sections if section.required]
        optional_sections = sorted(
            [section for section in active_sections if not section.required],
            key=lambda section: section.priority,
            reverse=True,
        )

        for index, section in enumerate(required_sections):
            line_overhead = self._encoded_length(f"{section.label}: ") + 1
            reserve_required = sum(
                self._encoded_length(f"{later.label}: ") + 1 + later.min_budget
                for later in required_sections[index + 1 :]
            )
            available = max(remaining - line_overhead - reserve_required, 1)
            budget = min(section.max_budget, max(section.min_budget, available))
            budget = min(budget, available)
            if budget <= 0:
                continue
            allocations[section.label] = budget
            remaining -= line_overhead + budget

        for section in optional_sections:
            line_overhead = self._encoded_length(f"{section.label}: ") + 1
            available = remaining - line_overhead
            if available < section.min_budget:
                continue
            budget = min(section.max_budget, available)
            allocations[section.label] = budget
            remaining -= line_overhead + budget

        for section in sorted(active_sections, key=lambda item: (item.required, item.priority), reverse=True):
            if remaining <= 0 or section.label not in allocations:
                break
            extra_capacity = section.max_budget - allocations[section.label]
            if extra_capacity <= 0:
                continue
            extra = min(extra_capacity, remaining)
            allocations[section.label] += extra
            remaining -= extra

        lines: list[str] = []
        for section in sections:
            budget = allocations.get(section.label)
            if not budget:
                continue
            trimmed = self._trim_to_budget(section.text, budget, keep_tail=section.keep_tail)
            if trimmed:
                lines.append(f"{section.label}: {trimmed}")

        prompt = scaffold_prefix + "\n".join(lines) + scaffold_suffix
        if self._encoded_length(prompt) <= prompt_budget:
            return prompt

        for label in [section.label for section in sorted(optional_sections, key=lambda item: item.priority)]:
            lines = [line for line in lines if not line.startswith(f"{label}:")]
            prompt = scaffold_prefix + "\n".join(lines) + scaffold_suffix
            if self._encoded_length(prompt) <= prompt_budget:
                return prompt

        question_section = next(
            (section for section in sections if section.label in {"USER", "Question"}),
            None,
        )
        label = question_section.label if question_section else "USER"
        question_text = self._trim_to_budget(
            question_section.text if question_section else "",
            max(prompt_budget - self._encoded_length(scaffold_prefix + scaffold_suffix + f"{label}: "), 8),
            keep_tail=True,
        )
        return scaffold_prefix + f"{label}: {question_text}" + scaffold_suffix

    def _build_prompt(
        self,
        user_input: str,
        intent: QueryIntent,
        context_summary: str = "",
        memory_summary: str = "",
        note_summary: str = "",
        core_contract: dict[str, Any] | None = None,
    ) -> str:
        has_memory = bool(memory_summary or note_summary)
        style_note = self._build_system_prompt(
            intent,
            has_context=bool(context_summary),
            has_memory=has_memory,
            user_input=user_input,
            core_contract=core_contract,
        )
        recent_history = self._build_recent_history_snapshot(user_input, limit=3)
        prompt_budget = max(self.block_size, 24)
        available_for_body = max(prompt_budget - self._encoded_length("<START_CONVO>\n<USER>\n<ASSISTANT>\n"), 8)
        casual = _is_casual_intent(intent.label)
        # Casual chat: prioritize style + recent history + the question itself.
        # Serious / document work: keep retrieved DOCS and MEMORY high priority.
        if casual:
            sections = [
                PromptSection(
                    "SYS", style_note, priority=1, min_budget=10, max_budget=max(14, int(available_for_body * 0.18))
                ),
                PromptSection(
                    "MEMORY",
                    note_summary,
                    priority=2,
                    min_budget=10,
                    max_budget=max(14, int(available_for_body * 0.14)),
                ),
                PromptSection(
                    "RECENT",
                    recent_history,
                    priority=4,
                    min_budget=12,
                    max_budget=max(18, int(available_for_body * 0.24)),
                    keep_tail=True,
                ),
                PromptSection(
                    "USER",
                    user_input,
                    priority=6,
                    min_budget=max(18, int(available_for_body * 0.40)),
                    max_budget=max(26, int(available_for_body * 0.55)),
                    required=True,
                    keep_tail=True,
                ),
            ]
        else:
            sections = [
                PromptSection(
                    "SYS", style_note, priority=1, min_budget=10, max_budget=max(14, int(available_for_body * 0.16))
                ),
                PromptSection(
                    "MEMORY",
                    note_summary,
                    priority=5,
                    min_budget=12,
                    max_budget=max(18, int(available_for_body * 0.22)),
                ),
                PromptSection(
                    "DOCS",
                    context_summary,
                    priority=4,
                    min_budget=16,
                    max_budget=max(24, int(available_for_body * 0.30)),
                ),
                PromptSection(
                    "RECALL",
                    memory_summary,
                    priority=3,
                    min_budget=12,
                    max_budget=max(18, int(available_for_body * 0.18)),
                ),
                PromptSection(
                    "RECENT",
                    recent_history,
                    priority=2,
                    min_budget=12,
                    max_budget=max(18, int(available_for_body * 0.16)),
                    keep_tail=True,
                ),
                PromptSection(
                    "USER",
                    user_input,
                    priority=6,
                    min_budget=max(18, int(available_for_body * 0.34)),
                    max_budget=max(26, int(available_for_body * 0.46)),
                    required=True,
                    keep_tail=True,
                ),
            ]
        return self._pack_prompt_sections(sections, prompt_budget)

    def _classify_intent(self, user_input: str) -> QueryIntent:
        lowered = normalize_intent_routing_text(user_input).strip().lower()
        wants_summary = bool(SUMMARY_HINT_RE.search(lowered))
        wants_code = bool(CODE_HINT_RE.search(lowered)) or bool(CODING_HINT_RE.search(lowered))
        token_count = len(re.findall(r"\S+", lowered))

        # 1) Direct canned responses (math, greeting, name) — keep these as
        #    seeds but tag the intent so style/fallback know it was casual.
        math_match = self._extract_math_match(lowered)
        if math_match:
            direct_response = self._try_direct_response(lowered)
            return QueryIntent(
                label=QUERY_INTENT_SIMPLE_MATH,
                use_retrieval=False,
                direct_response=direct_response,
            )

        if NAME_ONLY_RE.search(lowered):
            return QueryIntent(
                label=QUERY_INTENT_IDENTITY,
                use_retrieval=False,
                direct_response=self._try_direct_response(lowered),
            )

        if GREETING_ONLY_RE.search(lowered):
            return QueryIntent(label=QUERY_INTENT_CASUAL_GREETING, use_retrieval=False)

        if WELLBEING_ONLY_RE.search(lowered) or WELLBEING_RE.search(lowered):
            return QueryIntent(label=QUERY_INTENT_CASUAL_CHECKIN, use_retrieval=False)

        # 2) Emotional / supportive cues take priority over generic doc/web routing.
        if EMOTIONAL_SUPPORT_RE.search(lowered):
            return QueryIntent(label=QUERY_INTENT_EMOTIONAL_SUPPORT, use_retrieval=False)

        # 3) Smalltalk markers — these should never trigger retrieval.
        if CASUAL_SMALLTALK_RE.search(lowered) and token_count <= 12:
            return QueryIntent(label=QUERY_INTENT_CASUAL_SMALLTALK, use_retrieval=False)

        # 4) Document-grounded questions: explicit doc hints, or "summarize my X".
        if DOC_HINT_RE.search(lowered) or (wants_summary and re.search(r"\bmy\b", lowered)):
            return QueryIntent(
                label=QUERY_INTENT_DOCUMENT,
                use_retrieval=True,
                wants_summary=wants_summary,
                wants_code=wants_code,
            )

        # 5) "Latest / current / news" routes to web lookup when enabled,
        #    otherwise fall back to a knowledge lookup.
        if WEB_HINT_RE.search(lowered):
            if getattr(self, "internet_enabled", False):
                return QueryIntent(label=QUERY_INTENT_WEB, use_retrieval=False)
            return QueryIntent(label=QUERY_INTENT_KNOWLEDGE, use_retrieval=True)

        # 6) Bug-bounty and vulnerability-hunt requests should use the local
        # bounty playbook instead of falling into generic coding/planning.
        if BUG_BOUNTY_HINT_RE.search(lowered):
            return QueryIntent(
                label=QUERY_INTENT_BUG_BOUNTY,
                use_retrieval=True,
                wants_summary=wants_summary,
                wants_code=wants_code,
            )

        # 7) Coding / planning / serious task signals.
        if CODING_HINT_RE.search(lowered) or wants_code:
            return QueryIntent(
                label=QUERY_INTENT_CODING,
                use_retrieval=False,
                wants_code=True,
            )
        if PLANNING_HINT_RE.search(lowered):
            return QueryIntent(label=QUERY_INTENT_PLANNING, use_retrieval=False)
        if SERIOUS_TASK_HINT_RE.search(lowered):
            return QueryIntent(
                label=QUERY_INTENT_SERIOUS,
                use_retrieval=False,
                wants_summary=wants_summary,
            )

        # 8) Opinion questions stay casual unless they look technical/document-y.
        if CASUAL_OPINION_RE.search(lowered) and not (
            DOC_HINT_RE.search(lowered) or CODING_HINT_RE.search(lowered) or WEB_HINT_RE.search(lowered)
        ):
            return QueryIntent(label=QUERY_INTENT_CASUAL_OPINION, use_retrieval=False)

        # 9) Short greeting-shaped utterances stay casual rather than being
        #    treated as knowledge lookups.
        if token_count <= 4 and (GREETING_RE.search(lowered) or not lowered.endswith("?")):
            return QueryIntent(label=QUERY_INTENT_CASUAL_SMALLTALK, use_retrieval=False)
        if token_count <= 5 and GREETING_RE.search(lowered):
            return QueryIntent(label=QUERY_INTENT_CASUAL_GREETING, use_retrieval=False)

        # 10) Default: factual knowledge lookup.
        return QueryIntent(
            label=QUERY_INTENT_KNOWLEDGE,
            use_retrieval=True,
            wants_summary=wants_summary,
            wants_code=wants_code,
        )

    # ------------------------------------------------------------------
    # Style policy helpers
    # ------------------------------------------------------------------
    def _casual_style_instruction(self, intent: QueryIntent, user_input: str) -> str:
        base = (
            "sound natural, relaxed, and human; respond to the social cue first; "
            "keep it to 1-3 sentences; do not force productivity; "
            "do not end with 'how can I help?'; ask at most one light follow-up if useful"
        )
        if intent.label == QUERY_INTENT_EMOTIONAL_SUPPORT:
            return (
                "be warm and human, acknowledge the feeling first, do not pretend to be a therapist, "
                "keep it short (1-2 sentences), then offer one gentle option without pressuring"
            )
        if intent.label == QUERY_INTENT_CASUAL_GREETING:
            return "greet back warmly and briefly; do not ask 'how can I help?'; one short line"
        if intent.label == QUERY_INTENT_CASUAL_CHECKIN:
            return "answer the check-in casually like a friend; short; do not pivot to support-desk language"
        if intent.label == QUERY_INTENT_CASUAL_OPINION:
            return "share a brief, honest take in 1-3 sentences; it's okay to be opinionated"
        if intent.label == QUERY_INTENT_IDENTITY:
            return "answer the identity question briefly and naturally"
        return base

    def _work_style_instruction(self, intent: QueryIntent, user_input: str) -> str:
        if intent.label == QUERY_INTENT_CODING:
            return (
                "be direct and technical; provide concrete code when useful; "
                "briefly explain how to use it; surface assumptions; no casual filler"
            )
        if intent.label == QUERY_INTENT_BUG_BOUNTY:
            return (
                "answer like a careful authorized bug-bounty operator; prioritize scope, attack surface, "
                "highest-impact classes, proof-of-impact artifacts, triage likelihood, and report quality; "
                "separate confirmed facts from hypotheses; avoid mass exploitation or out-of-scope advice"
            )
        if intent.label == QUERY_INTENT_PLANNING:
            return (
                "produce a practical plan: goal, milestones, risks, and concrete next steps; "
                "use short bullets; be concise but not shallow"
            )
        if intent.label == QUERY_INTENT_DOCUMENT:
            return (
                "stay grounded in the retrieved notes; do not invent facts; "
                "cite the source name(s) inline; structure answer, evidence, and next step"
            )
        if intent.label == QUERY_INTENT_WEB:
            return "answer with up-to-date framing; cite the source; flag uncertainty"
        return (
            "be clear and structured; use short bullets or steps when helpful; "
            "surface assumptions; separate answer, reasoning, and next steps when useful; avoid filler"
        )

    def _extract_math_match(self, lowered_input: str) -> re.Match[str] | None:
        direct_match = MATH_RE.match(lowered_input)
        if direct_match:
            return direct_match

        inline_match = INLINE_MATH_RE.search(lowered_input)
        if not inline_match:
            return None

        if "?" in lowered_input or MATH_HINT_RE.search(lowered_input):
            return inline_match
        return None

    def _try_direct_response(self, lowered_input: str) -> str:
        math_match = self._extract_math_match(lowered_input)
        if math_match:
            left = float(math_match.group(1))
            operator = math_match.group(2).lower()
            right = float(math_match.group(3))

            if operator in {"plus", "+"}:
                result = left + right
            elif operator in {"minus", "-"}:
                result = left - right
            elif operator in {"times", "*", "x", "multiplied by"}:
                result = left * right
            elif operator in {"divided by", "/"}:
                if right == 0:
                    return "Division by zero is undefined."
                result = left / right
            else:
                return ""

            if result.is_integer():
                return str(int(result))
            return f"{result:.6g}"

        # Note: short canned seeds. Casual intents may bypass these and let the
        # model handle the reply for more variety; we keep them for offline /
        # not-ready scenarios.
        if GREETING_ONLY_RE.search(lowered_input):
            return "Hey, what's up?"
        if WELLBEING_ONLY_RE.search(lowered_input):
            return "Doing alright — what about you?"
        if NAME_ONLY_RE.search(lowered_input):
            return "I'm GreyIQ."
        return ""

    def _prepare_retrieval_query(self, user_input: str, intent: QueryIntent) -> str:
        prepared = (normalize_intent_routing_text(user_input) or user_input).strip()
        if intent.label in {QUERY_INTENT_DOCUMENT, QUERY_INTENT_KNOWLEDGE, QUERY_INTENT_BUG_BOUNTY}:
            prepared = RETRIEVAL_FRAME_RE.sub(" ", prepared)
            prepared = re.sub(r"\s+", " ", prepared).strip(" ,.-")
        if intent.label == QUERY_INTENT_BUG_BOUNTY:
            prepared = (
                f"{prepared} bug bounty authorized scope proof impact triage "
                "reproduction steps high impact vulnerability report"
            ).strip()
        return prepared or user_input.strip()

    def _is_broad_document_summary_query(self, user_input: str, intent: QueryIntent) -> bool:
        if intent.label != QUERY_INTENT_DOCUMENT or not intent.wants_summary:
            return False
        prepared = RETRIEVAL_FRAME_RE.sub(" ", (normalize_intent_routing_text(user_input) or user_input).strip())
        prepared = re.sub(r"\s+", " ", prepared).strip(" ,.-")
        prepared_terms = _tokenize_search_terms(prepared)
        return len(prepared_terms) <= 1

    def _document_overview_response(self) -> str:
        document_count = self.knowledge_base.document_count
        chunk_count = self.knowledge_base.chunk_count
        if document_count <= 0:
            return "I don't have any indexed documents yet. Add files in the Documents or Training tab first."
        return (
            f"I have {document_count} indexed document files across {chunk_count} searchable chunks. "
            "To keep replies fast and useful, ask for a specific file, topic, or question instead of the whole library at once."
        )

    def _should_use_note_memory(self, user_input: str, intent: QueryIntent) -> bool:
        if intent.label == QUERY_INTENT_SIMPLE:
            return True
        # Casual intents: only pull note memory if the user is talking about themselves
        # or explicitly referencing remembered facts. Avoid retrieval-style memory.
        if _is_casual_intent(intent.label):
            if REMEMBER_RE.search(user_input) or CONVERSATION_MEMORY_RE.search(user_input):
                return True
            return bool(PERSONAL_MEMORY_RE.search(user_input))
        if REMEMBER_RE.search(user_input):
            return True
        if CONVERSATION_MEMORY_RE.search(user_input):
            return True
        return bool(PERSONAL_MEMORY_RE.search(user_input))

    def _should_use_exchange_memory(self, user_input: str, intent: QueryIntent) -> bool:
        if intent.label == QUERY_INTENT_SIMPLE:
            return True
        if _is_casual_intent(intent.label):
            return bool(CONVERSATION_MEMORY_RE.search(user_input))
        return bool(CONVERSATION_MEMORY_RE.search(user_input))

    def _should_try_web_lookup(self, user_input: str, intent: QueryIntent, matches: list[SourceMatch]) -> bool:
        if not self.internet_enabled:
            return False
        if intent.label == QUERY_INTENT_DOCUMENT:
            return False
        # Casual chat never auto-triggers web lookups unless the user explicitly asked.
        if _is_casual_intent(intent.label) and not WEB_HINT_RE.search(user_input):
            return False
        if intent.label == QUERY_INTENT_WEB:
            return True
        if matches and not WEB_HINT_RE.search(user_input):
            return False
        return bool(WEB_HINT_RE.search(user_input)) or not matches

    def _lookup_web_result(self, user_input: str) -> WebResult | None:
        query = self._prepare_retrieval_query(user_input, QueryIntent(label=QUERY_INTENT_KNOWLEDGE, use_retrieval=True))
        if not query:
            return None

        encoded_query = urllib.parse.quote(query)
        ddg_payload = _fetch_json(
            f"https://api.duckduckgo.com/?q={encoded_query}&format=json&no_redirect=1&no_html=1&skip_disambig=1"
        )
        if isinstance(ddg_payload, dict):
            answer = clean_text(str(ddg_payload.get("Answer") or ddg_payload.get("AbstractText") or ""))
            if not answer:
                for topic in ddg_payload.get("RelatedTopics", []):
                    if isinstance(topic, dict) and topic.get("Text"):
                        answer = clean_text(str(topic["Text"]))
                        break
                    if isinstance(topic, dict):
                        for nested in topic.get("Topics", []):
                            if isinstance(nested, dict) and nested.get("Text"):
                                answer = clean_text(str(nested["Text"]))
                                break
                        if answer:
                            break
            source = str(ddg_payload.get("AbstractURL") or ddg_payload.get("AbstractSource") or "DuckDuckGo").strip()
            if answer:
                return WebResult(summary=_trim_summary_sentence(answer, max_chars=260), source=source or "DuckDuckGo")

        wiki_search = _fetch_json(
            f"https://en.wikipedia.org/w/api.php?action=opensearch&limit=1&namespace=0&format=json&search={encoded_query}"
        )
        if isinstance(wiki_search, list) and len(wiki_search) >= 2 and wiki_search[1]:
            title = wiki_search[1][0]
            title_encoded = urllib.parse.quote(str(title))
            wiki_summary = _fetch_json(f"https://en.wikipedia.org/api/rest_v1/page/summary/{title_encoded}")
            if isinstance(wiki_summary, dict):
                extract = clean_text(str(wiki_summary.get("extract") or ""))
                if extract:
                    source = str(
                        wiki_summary.get("content_urls", {}).get("desktop", {}).get("page") or "Wikipedia"
                    ).strip()
                    return WebResult(
                        summary=_trim_summary_sentence(extract, max_chars=260), source=source or "Wikipedia"
                    )
        return None

    def _retrieve_supporting_context(
        self,
        user_input: str,
        intent: QueryIntent,
        *,
        mode: str | None = None,
        source_ids: list[str] | tuple[str, ...] | set[str] | None = None,
    ) -> list[SourceMatch]:
        if not intent.use_retrieval:
            return []

        retrieval_query = self._prepare_retrieval_query(user_input, intent)
        settings = self._mode_settings(mode)
        min_score = float(settings["retrieval_threshold"])
        if intent.label == QUERY_INTENT_DOCUMENT:
            min_score = min(min_score, 0.2)
        if intent.label == QUERY_INTENT_BUG_BOUNTY:
            min_score = min(min_score, 0.24)
        limit = int(settings["retrieval_limit"])
        if intent.label == QUERY_INTENT_BUG_BOUNTY:
            limit = max(limit, 4)
        matches = self.knowledge_base.search(
            retrieval_query,
            limit=limit,
            min_score=min_score,
            source_ids=source_ids,
        )
        if not matches and retrieval_query != user_input:
            fallback_threshold = min(
                min_score,
                0.18 if intent.label in {QUERY_INTENT_DOCUMENT, QUERY_INTENT_BUG_BOUNTY} else 0.3,
            )
            matches = self.knowledge_base.search(
                user_input,
                limit=limit,
                min_score=fallback_threshold,
                source_ids=source_ids,
            )
        return matches

    def _compress_context(
        self,
        user_input: str,
        matches: list[SourceMatch],
        intent: QueryIntent,
        *,
        mode: str | None = None,
    ) -> str:
        if not matches:
            return ""

        settings = self._mode_settings(mode)
        max_sentences = int(settings["summary_sentences"])
        query_terms = set(_tokenize_search_terms(self._prepare_retrieval_query(user_input, intent)))
        candidates: list[tuple[float, str, str]] = []

        for match in matches:
            excerpt = re.sub(r"<[^>]+>", "", match.excerpt)
            excerpt = excerpt.replace("```", " ")
            raw_lines = [clean_text(line) for line in excerpt.splitlines() if clean_text(line)]
            sentences: list[str] = []
            previous_line = ""
            for line in raw_lines:
                cleaned = re.sub(r"---\s*page\s*\d+\s*---", " ", line, flags=re.IGNORECASE)
                cleaned = re.sub(r"\bch\d+\.indd\b", " ", cleaned, flags=re.IGNORECASE)
                cleaned = re.sub(r"\s+", " ", cleaned).strip(" -")
                lowered_cleaned = cleaned.lower()
                if len(cleaned) < 25:
                    previous_line = cleaned or previous_line
                    continue
                if not previous_line and cleaned[:1].islower():
                    continue
                if re.match(r"^(chapter|section)\b", cleaned, re.IGNORECASE):
                    previous_line = cleaned
                    continue
                if re.match(r"^\d+\.", cleaned):
                    previous_line = cleaned
                    continue
                if "practice makes perfect" in lowered_cleaned or "complete english all-in-one" in lowered_cleaned:
                    previous_line = cleaned
                    continue
                if lowered_cleaned.startswith("review ") and "proceeding" in lowered_cleaned:
                    previous_line = cleaned
                    continue
                if len(re.findall(r"\d", cleaned)) > max(4, len(cleaned) // 5):
                    previous_line = cleaned
                    continue
                if lowered_cleaned.startswith("answer :") and previous_line:
                    answer = cleaned.split(":", 1)[1].strip()
                    cleaned = f"The material includes worked examples such as changing '{previous_line}' to '{answer}'."
                sentences.append(cleaned)
                previous_line = cleaned

            for sentence in sentences:
                if not intent.wants_code and re.search(r"::|->|\[[^\]]+\]|[{}();=]{2,}|^\s{4,}", sentence):
                    continue
                sentence_terms = set(_tokenize_search_terms(sentence))
                overlap = len(query_terms & sentence_terms) / max(len(query_terms), 1) if query_terms else 0.0
                candidates.append((match.score + overlap * 0.25, sentence, match.source))

        candidates.sort(key=lambda item: item[0], reverse=True)
        selected: list[tuple[str, str]] = []
        for _, sentence, source in candidates:
            if any(_sentence_similarity(sentence, existing) > 0.7 for existing, _ in selected):
                continue
            selected.append((_trim_summary_sentence(sentence), source))
            if len(selected) >= max_sentences:
                break

        if not selected:
            return ""

        merged = " ".join(sentence for sentence, _ in selected).strip()
        sources = ", ".join(dict.fromkeys(source for _, source in selected))
        if intent.label == QUERY_INTENT_DOCUMENT:
            return f"Relevant points from {sources}: {merged}"
        return merged

    def _response_mirrors_context(self, response: str, matches: list[SourceMatch]) -> bool:
        lowered_response = response.lower()
        if len(lowered_response) < 20:
            return False
        for match in matches[:2]:
            excerpt = re.sub(r"<[^>]+>", "", match.excerpt).lower()
            if not excerpt:
                continue
            sequence_ratio = difflib.SequenceMatcher(None, lowered_response[:360], excerpt[:500]).ratio()
            if sequence_ratio >= 0.88:
                return True
            response_ngrams = _char_ngrams(lowered_response, size=5)
            excerpt_ngrams = _char_ngrams(excerpt[:500], size=5)
            if response_ngrams and excerpt_ngrams:
                shared = len(response_ngrams & excerpt_ngrams) / len(response_ngrams)
                if shared >= 0.78 and len(lowered_response) >= 80:
                    return True
        return False

    def _response_addresses_query(self, response: str, user_input: str, intent: QueryIntent) -> bool:
        if intent.label == QUERY_INTENT_SIMPLE or _is_casual_intent(intent.label):
            return True
        query_terms = set(_tokenize_search_terms(user_input))
        if not query_terms:
            return True
        response_terms = set(_tokenize_search_terms(response))
        overlap = len(query_terms & response_terms)
        similarity = _hybrid_similarity(
            user_input,
            response,
            query_terms=query_terms,
            candidate_terms=response_terms,
        )
        if intent.label == QUERY_INTENT_DOCUMENT:
            return overlap >= 1 or similarity >= 0.18
        return overlap >= min(2, len(query_terms)) or similarity >= 0.22

    def _response_looks_low_quality(self, text: str) -> bool:
        stripped = text.strip()
        if len(stripped) < 12:
            return True

        letters = sum(char.isalpha() for char in stripped)
        spaces = stripped.count(" ")
        noisy = sum(1 for char in stripped if not (char.isalnum() or char.isspace() or char in ".,!?;:'\"-()/"))

        if letters / max(len(stripped), 1) < 0.45:
            return True
        if spaces < max(1, len(stripped) // 30) and len(stripped) > 40:
            return True
        if noisy / max(len(stripped), 1) > 0.1:
            return True
        if re.search(r"(.)\1{6,}", stripped):
            return True

        if stripped and stripped[-1].isalpha() and len(stripped) > 30:
            return True

        return False

    def _tighten_response(self, text: str) -> str:
        cleaned = clean_text(text)
        if not cleaned:
            return ""
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        if len(lines) > 4:
            cleaned = "\n".join(lines[:4])
        sentences = re.split(r"(?<=[.!?])\s+", cleaned)
        if len(sentences) > 3:
            cleaned = " ".join(sentences[:3]).strip()
        if len(cleaned) > 360:
            cleaned = cleaned[:360].rsplit(" ", 1)[0].rstrip(".,;:!?") + "."
        return cleaned.strip()

    def _should_capture_training_example(self, user_input: str, response: str, used_fallback: bool) -> bool:
        if used_fallback:
            return False
        if len(user_input.strip()) < 4 or len(response.strip()) < 12:
            return False
        if len(response) > 500:
            return False
        return not self._response_looks_low_quality(response)

    def _should_store_memory(self, user_input: str, response: str, used_fallback: bool) -> bool:
        if used_fallback:
            return False
        if len(user_input.strip()) < 4 or len(response.strip()) < 8:
            return False
        if len(response) > 600:
            return False
        if self._response_looks_low_quality(response):
            return False
        low_confidence_patterns = (
            "i don't know",
            "not sure",
            "couldn't form",
            "don't have enough grounded context",
        )
        lowered = response.lower()
        return not any(pattern in lowered for pattern in low_confidence_patterns)

    def append_chat_training_example(self, user_input: str, response: str) -> Path:
        """Queue a good exchange for later offline retraining. This does not update weights live."""
        data_dir = self.base_dir / DEFAULT_DATA_FOLDER
        data_dir.mkdir(parents=True, exist_ok=True)
        output_path = data_dir / CHAT_TRAIN_FILE
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        block = (
            f"### AUTO CHAT TRAINING {timestamp} ###\n"
            f"<START_CONVO>\n<USER>\n{user_input.strip()}\n<ASSISTANT>\n{response.strip()}\n<END_CONVO>\n\n"
        )
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(block)
        return output_path

    def _generation_settings(
        self,
        intent: QueryIntent,
        max_new_tokens: int,
        temperature: float,
        *,
        has_context: bool,
        has_memory: bool,
    ) -> dict[str, float | int]:
        settings: dict[str, float | int] = {
            "max_new_tokens": max_new_tokens,
            "temperature": temperature,
            "top_k": 32,
            "top_p": 0.92,
            "repetition_penalty": 1.1,
        }

        if intent.label == QUERY_INTENT_EMOTIONAL_SUPPORT:
            settings.update(
                {
                    "max_new_tokens": min(max_new_tokens, 56),
                    "temperature": max(float(temperature), 0.50),
                    "top_k": 40,
                    "top_p": 0.94,
                    "repetition_penalty": 1.05,
                }
            )
        elif _is_casual_intent(intent.label):
            settings.update(
                {
                    "max_new_tokens": min(max_new_tokens, 72),
                    "temperature": max(float(temperature), 0.55),
                    "top_k": 48,
                    "top_p": 0.95,
                    "repetition_penalty": 1.05,
                }
            )
        elif intent.label == QUERY_INTENT_CODING:
            settings.update(
                {
                    "max_new_tokens": min(max(max_new_tokens, 128), 192),
                    "temperature": min(float(temperature), 0.24),
                    "top_k": 28,
                    "top_p": 0.85,
                    "repetition_penalty": 1.1,
                }
            )
        elif intent.label in {QUERY_INTENT_SERIOUS, QUERY_INTENT_PLANNING, QUERY_INTENT_BUG_BOUNTY}:
            settings.update(
                {
                    "max_new_tokens": min(max(max_new_tokens, 128), 160),
                    "temperature": min(max(float(temperature), 0.25), 0.32),
                    "top_k": 32,
                    "top_p": 0.9,
                    "repetition_penalty": 1.1,
                }
            )
        elif intent.label == QUERY_INTENT_DOCUMENT:
            settings.update(
                {
                    "max_new_tokens": min(max_new_tokens, 96),
                    "temperature": min(float(temperature), 0.24),
                    "top_k": 28,
                    "top_p": 0.88,
                    "repetition_penalty": 1.12,
                }
            )
        else:
            settings.update(
                {
                    "max_new_tokens": min(max_new_tokens, 88),
                    "temperature": min(max(float(temperature), 0.28), 0.36),
                    "top_k": 32,
                    "top_p": 0.92,
                    "repetition_penalty": 1.1,
                }
            )

        if intent.wants_summary:
            settings.update(
                {
                    "max_new_tokens": min(int(settings["max_new_tokens"]), 64),
                    "temperature": min(float(settings["temperature"]), 0.22),
                    "top_k": min(int(settings["top_k"]), 24),
                    "top_p": min(float(settings["top_p"]), 0.86),
                }
            )
        if intent.wants_code:
            settings.update(
                {
                    "max_new_tokens": min(max_new_tokens, 112),
                    "temperature": min(float(settings["temperature"]), 0.26),
                    "top_k": min(int(settings["top_k"]), 26),
                    "top_p": min(float(settings["top_p"]), 0.86),
                    "repetition_penalty": max(float(settings["repetition_penalty"]), 1.12),
                }
            )
        if has_context or has_memory:
            settings["temperature"] = min(float(settings["temperature"]), 0.28)
            settings["top_k"] = min(int(settings["top_k"]), 28)
            settings["top_p"] = min(float(settings["top_p"]), 0.9)
        if intent.label == QUERY_INTENT_DOCUMENT and has_context:
            settings["temperature"] = min(float(settings["temperature"]), 0.18)
            settings["top_k"] = min(int(settings["top_k"]), 20)
            settings["top_p"] = min(float(settings["top_p"]), 0.82)
        if self.device_info.name == "cpu":
            settings["max_new_tokens"] = min(int(settings["max_new_tokens"]), 48)
            settings["top_k"] = min(int(settings["top_k"]), 24)
        return settings

    def _estimate_reply_confidence(
        self,
        response: str,
        matches: list[SourceMatch],
        diagnostics: ReplyDiagnostics,
        *,
        intent: QueryIntent | None = None,
        context_summary: str = "",
        memory_summary: str = "",
        note_summary: str = "",
    ) -> float:
        if not response.strip():
            return 0.0

        if intent and intent.direct_response:
            base = 0.92
        elif diagnostics.used_fallback:
            base = 0.42 if matches else 0.28
        elif self.ready:
            base = 0.68
        else:
            base = 0.46

        if matches:
            base = max(base, min(0.93, 0.42 + matches[0].score * 0.5))
        if context_summary:
            base += 0.06
        if memory_summary or note_summary:
            base += 0.03
        if intent and intent.label == QUERY_INTENT_DOCUMENT and not matches:
            base -= 0.18
        if self._response_looks_low_quality(response):
            base -= 0.24
        if diagnostics.used_fallback and not matches and not context_summary:
            base = min(base, 0.42)

        return round(max(0.05, min(0.98, base)), 2)

    def _register_turn(self, user_input: str, response: str) -> None:
        self._turns.append((user_input, response))
        self._turns = self._turns[-self.max_history_turns :]
        self._history.append(f"<START_CONVO>\n<USER>\n{user_input}\n<ASSISTANT>\n{response}\n<END_CONVO>")
        self._history = self._history[-max(self.max_history_turns, 4) :]

    def _finalize_reply(
        self,
        user_input: str,
        response: str,
        matches: list[SourceMatch],
        diagnostics: ReplyDiagnostics,
        *,
        auto_capture: bool,
        remembered_note: str = "",
        store_exchange: bool = True,
        intent: QueryIntent | None = None,
        context_summary: str = "",
        memory_summary: str = "",
        note_summary: str = "",
        strategy: str = "",
    ) -> tuple[str, list[SourceMatch], ReplyDiagnostics]:
        if intent is not None and not diagnostics.intent_label:
            diagnostics.intent_label = intent.label
        if strategy:
            diagnostics.strategy = strategy
        diagnostics.retrieval_count = len(matches)
        diagnostics.confidence = self._estimate_reply_confidence(
            response,
            matches,
            diagnostics,
            intent=intent,
            context_summary=context_summary,
            memory_summary=memory_summary,
            note_summary=note_summary,
        )
        # Output safety gate. We screen every assistant utterance before storing it.
        if hasattr(self, "safety"):
            output_screen = self.safety.screen_output(response)
            if not output_screen.allowed:
                response = output_screen.refusal_message
                diagnostics.used_fallback = True
                store_exchange = False
                auto_capture = False
                diagnostics.strategy = "output_safety_refusal"
                diagnostics.confidence = self._estimate_reply_confidence(
                    response,
                    matches,
                    diagnostics,
                    intent=intent,
                    context_summary=context_summary,
                    memory_summary=memory_summary,
                    note_summary=note_summary,
                )
        self._register_turn(user_input, response)
        if self.memory_recording_enabled and remembered_note:
            self.chat_memory.add_note(remembered_note, source_user=user_input)
        if (
            store_exchange
            and self.memory_recording_enabled
            and self._should_store_memory(
                user_input,
                response,
                diagnostics.used_fallback,
            )
        ):
            self.chat_memory.add_exchange(user_input, response)
        if auto_capture and self._should_capture_training_example(user_input, response, diagnostics.used_fallback):
            self.append_chat_training_example(user_input, response)
            diagnostics.captured_for_training = True
        return response, matches, diagnostics

    def generate_reply(
        self,
        user_input: str,
        max_new_tokens: int = 80,
        temperature: float = 0.32,
        auto_capture: bool = False,
        mode: str | None = None,
        core_contract: dict[str, Any] | None = None,
        source_ids: list[str] | tuple[str, ...] | set[str] | None = None,
    ) -> tuple[str, list[SourceMatch], ReplyDiagnostics]:
        with self._engine_lock:
            cleaned_input = clean_text(user_input)
            diagnostics = ReplyDiagnostics(used_fallback=False)
            if not cleaned_input:
                return "Please type a message first.", [], diagnostics
            understood_input = normalize_intent_routing_text(cleaned_input) or cleaned_input
            resolved_mode = self._resolve_mode(mode)
            diagnostics.mode = resolved_mode

            # Safety gate: refuse before we ever touch the model if the input
            # falls into a blocked category for the current capability mode.
            input_screen = self.safety.screen_input(cleaned_input)
            if not input_screen.allowed:
                diagnostics.used_fallback = True
                return self._finalize_reply(
                    cleaned_input,
                    input_screen.refusal_message,
                    [],
                    diagnostics,
                    auto_capture=False,
                    remembered_note="",
                    store_exchange=False,
                    strategy="input_safety_refusal",
                )

            remembered_note = _extract_user_note(cleaned_input) if self.memory_recording_enabled else ""
            if (
                not remembered_note
                and self.memory_recording_enabled
                and understood_input != cleaned_input
                and REMEMBER_RE.search(understood_input)
            ):
                remembered_note = _extract_user_note(understood_input)
            if REMEMBER_RE.search(understood_input) and remembered_note:
                response = "Okay, I'll remember that."
                return self._finalize_reply(
                    cleaned_input,
                    response,
                    [],
                    diagnostics,
                    auto_capture=auto_capture,
                    remembered_note=remembered_note,
                    store_exchange=False,
                    strategy="memory_ack",
                )

            intent = self._classify_intent(understood_input)
            diagnostics.intent_label = intent.label
            if intent.direct_response:
                response = intent.direct_response
                return self._finalize_reply(
                    cleaned_input,
                    response,
                    [],
                    diagnostics,
                    auto_capture=auto_capture,
                    remembered_note=remembered_note,
                    intent=intent,
                    strategy="direct_response",
                )

            if self._is_broad_document_summary_query(understood_input, intent):
                response = self._document_overview_response()
                return self._finalize_reply(
                    cleaned_input,
                    response,
                    [],
                    diagnostics,
                    auto_capture=auto_capture,
                    remembered_note=remembered_note,
                    intent=intent,
                    strategy="document_overview",
                )
            matches = self._retrieve_supporting_context(
                understood_input,
                intent,
                mode=resolved_mode,
                source_ids=source_ids,
            )
            note_matches: list[NoteMatch] = []
            if self._should_use_note_memory(understood_input, intent):
                note_matches = self.chat_memory.search_notes(
                    understood_input,
                    limit=2,
                    min_score=0.26 if (intent.label == QUERY_INTENT_SIMPLE or _is_casual_intent(intent.label)) else 0.3,
                )

            memory_matches: list[MemoryMatch] = []
            if self._should_use_exchange_memory(understood_input, intent):
                memory_matches = self.chat_memory.search(
                    understood_input,
                    limit=2,
                    min_score=0.28
                    if (intent.label == QUERY_INTENT_SIMPLE or _is_casual_intent(intent.label))
                    else 0.34,
                )
            context_summary = self._compress_context(understood_input, matches, intent, mode=resolved_mode)
            note_summary = self._compress_note_context(note_matches)
            memory_summary = self._compress_memory_context(understood_input, memory_matches)
            diagnostics.retrieval_count = len(matches)
            diagnostics.note_count = len(note_matches)
            diagnostics.memory_count = len(memory_matches)

            # On CPU, retrieval-grounded document/summary answers are much faster and
            # more reliable when we return the compressed context directly instead of
            # spending many seconds generating a paraphrase token by token.
            if (
                context_summary
                and not _is_casual_intent(intent.label)
                and (
                    intent.label == QUERY_INTENT_DOCUMENT
                    or intent.wants_summary
                    or (self.device_info.name == "cpu" and matches and not intent.wants_code)
                )
            ):
                response = self._fallback_response(
                    matches,
                    summary=context_summary,
                    intent=intent,
                    memory_summary=memory_summary,
                    note_summary=note_summary,
                )
                return self._finalize_reply(
                    cleaned_input,
                    response,
                    matches,
                    diagnostics,
                    auto_capture=auto_capture,
                    remembered_note=remembered_note,
                    intent=intent,
                    context_summary=context_summary,
                    memory_summary=memory_summary,
                    note_summary=note_summary,
                    strategy="retrieval_summary",
                )

            web_result = (
                self._lookup_web_result(understood_input)
                if self._should_try_web_lookup(understood_input, intent, matches)
                else None
            )
            if web_result and (WEB_HINT_RE.search(understood_input) or (not matches and not context_summary)):
                response = f"{web_result.summary}\n\nSource: {web_result.source}"
                return self._finalize_reply(
                    cleaned_input,
                    response,
                    matches,
                    diagnostics,
                    auto_capture=auto_capture,
                    remembered_note=remembered_note,
                    intent=intent,
                    context_summary=context_summary,
                    memory_summary=memory_summary,
                    note_summary=note_summary,
                    strategy="web_lookup",
                )

            if intent.label == QUERY_INTENT_DOCUMENT and not matches and not memory_matches:
                diagnostics.used_fallback = True
                response = "I couldn't find a relevant match in your documents for that yet."
                return self._finalize_reply(
                    cleaned_input,
                    response,
                    matches,
                    diagnostics,
                    auto_capture=auto_capture,
                    remembered_note=remembered_note,
                    intent=intent,
                    context_summary=context_summary,
                    memory_summary=memory_summary,
                    note_summary=note_summary,
                    strategy="document_no_match",
                )

            if not self.ready:
                diagnostics.used_fallback = True
                response = self._fallback_response(
                    matches,
                    summary=context_summary,
                    intent=intent,
                    memory_summary=memory_summary,
                    note_summary=note_summary,
                )
                return self._finalize_reply(
                    cleaned_input,
                    response,
                    matches,
                    diagnostics,
                    auto_capture=auto_capture,
                    remembered_note=remembered_note,
                    intent=intent,
                    context_summary=context_summary,
                    memory_summary=memory_summary,
                    note_summary=note_summary,
                    strategy="engine_not_ready_fallback",
                )

            prompt = self._build_prompt(
                understood_input,
                intent,
                context_summary=context_summary,
                memory_summary=memory_summary,
                note_summary=note_summary,
                core_contract=core_contract,
            )
            input_ids = self.encode(prompt)
            if not input_ids:
                diagnostics.used_fallback = True
                response = self._fallback_response(
                    matches,
                    summary=context_summary,
                    intent=intent,
                    memory_summary=memory_summary,
                    note_summary=note_summary,
                )
                return self._finalize_reply(
                    cleaned_input,
                    response,
                    matches,
                    diagnostics,
                    auto_capture=auto_capture,
                    remembered_note=remembered_note,
                    intent=intent,
                    context_summary=context_summary,
                    memory_summary=memory_summary,
                    note_summary=note_summary,
                    strategy="encoding_fallback",
                )

            prompt_ids = input_ids[-self.block_size :]
            prompt_seed = self.decode(prompt_ids)
            x = torch.tensor([prompt_ids], dtype=torch.long, device=self.device_info.name)
            generation_settings = self._generation_settings(
                intent,
                max_new_tokens,
                temperature,
                has_context=bool(context_summary),
                has_memory=bool(memory_summary or note_summary),
            )

            try:
                autocast_context = _autocast_for_device(self.device_info.name)
                with torch.inference_mode(), autocast_context:
                    output = self.model.generate(x, stop_sequences=self._stop_sequences, **generation_settings)[
                        0
                    ].tolist()
            except Exception as exc:
                if not self._reload_model_on_cpu_after_failure(exc):
                    raise

                x = torch.tensor([prompt_ids], dtype=torch.long, device=self.device_info.name)
                autocast_context = _autocast_for_device(self.device_info.name)
                with torch.inference_mode(), autocast_context:
                    output = self.model.generate(x, stop_sequences=self._stop_sequences, **generation_settings)[
                        0
                    ].tolist()

            generated = self.decode(output)
            response = generated[len(prompt_seed) :]
            for marker in STOP_MARKERS:
                if marker in response:
                    response = response.split(marker)[0]

            response = normalize_generated_response(response)
            response = self._tighten_response(response)
            reply_strategy = "model_generation"
            if (
                not response
                or self._response_looks_low_quality(response)
                or self._response_mirrors_context(response, matches)
                or (
                    (context_summary or memory_summary or note_summary)
                    and not self._response_addresses_query(response, understood_input, intent)
                )
            ):
                diagnostics.used_fallback = True
                reply_strategy = "quality_fallback"
                response = self._fallback_response(
                    matches,
                    summary=context_summary,
                    intent=intent,
                    memory_summary=memory_summary,
                    note_summary=note_summary,
                )

            return self._finalize_reply(
                cleaned_input,
                response,
                matches,
                diagnostics,
                auto_capture=auto_capture,
                remembered_note=remembered_note,
                intent=intent,
                context_summary=context_summary,
                memory_summary=memory_summary,
                note_summary=note_summary,
                strategy=reply_strategy,
            )
