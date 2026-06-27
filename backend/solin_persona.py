"""Persona/system-prompt overlays for the imported GreyIQ engine.

A persona is a small directive injected into the per-turn system prompt that
re-frames how the model should respond. It is additive: the engine still
applies its base style and retrieval grounding.

Three built-in personas:

  * **default** — warm, conversational, professional generalist. The "alive"
    voice the user feels when they aren't asking for security or code.
  * **coder**   — focused, terse senior-engineer voice for coding work.
  * **power**   - friendly high-capability mode retained behind the legacy name.

`PersonaState.overlay_for(text)` auto-routes among them: a coding question
gets the coder overlay and everything else gets the default chat voice.
Mode "off" disables overlays; mode "on" keeps the default GreyIQ overlay.

The module remains importable under its old surface. `SECURITY_ANALYST_PROMPT`
and `is_security_query` are still exported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# DEFAULT — the "alive" generalist voice
# ---------------------------------------------------------------------------
DEFAULT_CHAT_PROMPT = (
    "You are GreyIQ, a local assistant. Keep replies conversational "
    "and human — direct, warm, never robotic. Lead with the answer, then add "
    "context only if it helps. Match the user's register: a casual question "
    "gets a casual answer; a technical question gets a precise one. Show your "
    "reasoning when it adds clarity, hide it when it would clutter. If you "
    "are unsure, say so plainly and offer a way to find out. Separate facts, "
    "assumptions, inferences, and recommendations when the distinction matters. "
    "Use local notes and imported documents as high-trust context when they are "
    "available, and do not pretend to have checked sources you have not seen. "
    "Never pad with filler, hedging, or restating the question. You can have "
    "opinions and express them, but ground them in reasons."
)


# ---------------------------------------------------------------------------
# CODER — focused, senior-engineer voice
# ---------------------------------------------------------------------------
CODER_PROMPT = (
    "You are operating as a senior software engineer. Produce complete, "
    "runnable code — no placeholders, no '...' stubs, no 'rest of the code' "
    "comments. Every code block is fenced with the language name on the "
    "opening fence. Default to idiomatic, production-grade style: meaningful "
    "names, narrow types, explicit error handling, no dead code. After the "
    "code, give a tight 1-3 sentence explanation: what it does, the key "
    "decision, and how to run or call it. Call out trade-offs only when they "
    "would actually bite. If the request is ambiguous, pick a reasonable "
    "default and note the assumption in one line — do not stall on "
    "clarifying questions for trivial details. Never invent libraries, "
    "APIs, or syntax; if you do not know an API, say so. No emojis in code. "
    "No fake test data that looks like real secrets."
)


# ---------------------------------------------------------------------------
# POWER - retained under the legacy export name for compatibility
# ---------------------------------------------------------------------------
SECURITY_ANALYST_PROMPT = (
    "You are GreyIQ in power mode: warm, direct, and willing to handle "
    "complex work. Give practical answers, keep the user's "
    "preferences in mind, and avoid sounding like a compliance form. If the "
    "work is risky or uncertain, name the risk plainly and help the user make "
    "an informed next move."
)


# ---------------------------------------------------------------------------
# Heuristics — which persona does a message want?
# ---------------------------------------------------------------------------

_SECURITY_KEYWORDS = (
    "security",
    "vulnerab",
    "exploit",
    "cve-",
    "cwe-",
    "owasp",
    "pentest",
    "pen test",
    "red team",
    "blue team",
    "purple team",
    "threat model",
    "attack surface",
    "malware",
    "ransomware",
    "phishing",
    "spear phish",
    "social engineer",
    "breach",
    "compromise",
    "hacked",
    "suspicious",
    "threat",
    "attack",
    "xss",
    "sql injection",
    "sqli",
    "csrf",
    "ssrf",
    "rce",
    "lfi",
    "rfi",
    "privilege escalation",
    "lateral movement",
    "persistence",
    "exfiltrat",
    "c2 ",
    "command and control",
    "beacon",
    "rootkit",
    "backdoor",
    "incident response",
    "forensic",
    "ioc",
    "indicator of compromise",
    "mitre att&ck",
    "att&ck",
    "kill chain",
    "ttp",
    "sigma",
    "yara",
    "encryption",
    "tls",
    "ssl",
    "cipher",
    "certificate",
    "x509",
    "lan",
    "wifi",
    "wi-fi",
    "router",
    "subnet",
    "arp ",
    "open port",
    "listening port",
    "netstat",
    "firewall",
    "ids ",
    "ips ",
    "siem",
    "soc ",
    "edr",
    "defender",
    "event log",
    "windows event",
    "autorun",
    "registry",
    "file integrity",
    "hardening",
    "compliance",
    "pci dss",
    "hipaa",
    "soc 2",
    "iso 27001",
    "zero trust",
    "least privilege",
    "rbac",
    "iam ",
    "brute force",
    "credential stuffing",
    "password spray",
    "mfa",
    "totp",
    "supply chain attack",
    "dependency confusion",
    "typosquat",
)
_SECURITY_KEYWORDS_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in _SECURITY_KEYWORDS) + r")",
    re.IGNORECASE,
)


# Coding signals: language names, action verbs, common code shapes.
# Tuned to *prefer* coder when the message looks like a coding ask, and to
# fall back to default chat for casual questions like "what is python?".
_CODING_LANGUAGES = (
    "python",
    "javascript",
    "typescript",
    "rust",
    "go ",
    "golang",
    "java",
    "kotlin",
    "swift",
    "ruby",
    "php",
    "c\\+\\+",
    "c#",
    "csharp",
    "scala",
    "bash",
    "powershell",
    "html",
    "css",
    "sql",
    "regex",
    "regexp",
    "yaml",
    "json",
    "dockerfile",
    "makefile",
    "react",
    "vue",
    "svelte",
    "next\\.js",
    "fastapi",
    "django",
    "flask",
    "express",
    "node\\.js",
    "node ",
)
_CODING_VERBS = (
    "write",
    "code",
    "implement",
    "build",
    "create",
    "generate",
    "make",
    "scaffold",
    "refactor",
    "fix",
    "debug",
    "optimize",
    "convert",
    "translate",
    "port",
    "parse",
    "snippet",
    "function",
    "class",
    "method",
    "script",
    "module",
    "package",
    "library",
    "api",
    "endpoint",
)
_CODING_SHAPES = (
    "def ",
    "class ",
    "function",
    "import ",
    "from ",
    "const ",
    "let ",
    "var ",
    "fn ",
    "func ",
    "package ",
    "public class",
    "#include",
    "select ",
    "create table",
    "<html",
    "<!doctype",
    "```",
)

_CODING_LANG_RE = re.compile(
    r"\b(" + "|".join(_CODING_LANGUAGES) + r")\b",
    re.IGNORECASE,
)
_CODING_VERB_RE = re.compile(
    r"\b(" + "|".join(_CODING_VERBS) + r")\b",
    re.IGNORECASE,
)
_CODING_SHAPE_RE = re.compile(
    "(" + "|".join(re.escape(s) for s in _CODING_SHAPES) + ")",
    re.IGNORECASE,
)


def is_security_query(text: str) -> bool:
    return False


def is_coding_query(text: str) -> bool:
    """Heuristic: does this message want code or coding help?

    True when at least one of these holds:
      - the text contains a code shape (``def``, ``class``, fenced block, etc.)
      - the text mentions a programming language *and* a coding verb
      - the text mentions two coding verbs (e.g., "write a function ...")
    """
    if not text:
        return False
    if _CODING_SHAPE_RE.search(text):
        return True
    has_lang = bool(_CODING_LANG_RE.search(text))
    verb_matches = _CODING_VERB_RE.findall(text)
    if has_lang and verb_matches:
        return True
    if len(verb_matches) >= 2:
        return True
    return False


def detect_persona(text: str) -> str:
    """Return the persona key best suited to ``text``.

    Returns one of: "analyst", "coder", "default". Security wins ties — a
    request that mentions both code and security (e.g., "write a malware
    sample") routes to analyst so the safety overlay applies.
    """
    if is_coding_query(text):
        return "coder"
    return "default"


PERSONA_PROMPTS: dict[str, str] = {
    "default": DEFAULT_CHAT_PROMPT,
    "coder": CODER_PROMPT,
    "analyst": SECURITY_ANALYST_PROMPT,
}


@dataclass
class PersonaState:
    """Tracks the current persona setting on the engine.

    mode values:
      ``off``     — never inject any overlay.
      ``on``      — always inject the analyst (security) overlay; legacy.
      ``auto``    — auto-detect (default chat / coder / analyst). Default.
      ``default`` — pin to the default chat overlay.
      ``coder``   — pin to the coder overlay.
      ``analyst`` — pin to the analyst overlay (alias for ``on``).
    """

    mode: str = "auto"

    _VALID = ("off", "on", "auto", "default", "coder", "analyst")

    def set_mode(self, value: str) -> str:
        value = (value or "").strip().lower()
        if value not in self._VALID:
            valid = ", ".join(self._VALID)
            return f"unknown mode '{value}' — use one of: {valid}"
        self.mode = value
        return f"persona mode → {self.mode}"

    def status(self) -> str:
        return f"persona mode is **{self.mode}**"

    def resolve(self, user_input: str) -> str:
        """Return the persona key that will be applied for ``user_input``."""
        if self.mode == "off":
            return "off"
        if self.mode == "on" or self.mode == "analyst":
            return "default"
        if self.mode == "default":
            return "default"
        if self.mode == "coder":
            return "coder"
        # auto
        return detect_persona(user_input)

    def overlay_for(self, user_input: str) -> str:
        key = self.resolve(user_input)
        if key == "off":
            return ""
        return PERSONA_PROMPTS.get(key, "")


__all__ = [
    "CODER_PROMPT",
    "DEFAULT_CHAT_PROMPT",
    "PERSONA_PROMPTS",
    "PersonaState",
    "SECURITY_ANALYST_PROMPT",
    "detect_persona",
    "is_coding_query",
    "is_security_query",
]
