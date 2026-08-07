"""Per-brain reasoning profiles — how hard each GreyIQ brain is allowed to think.

Until v2.7.0 every brain shared ONE global ``effort`` and ``max_tokens``, so the hunt planner (which
decides where an entire engagement probes) reasoned exactly as hard as the one-line impact narrator
that runs once per finding. That is the wrong trade in both directions: the planner was
under-powered and the narrator was over-priced.

A profile names, per brain:

* ``effort``     — how much the model thinks/acts before answering. ``xhigh`` is the best setting for
  coding and agentic work; ``high`` is the general default; ``low``/``medium`` are the real cost
  levers for short, mechanical calls.
* ``max_tokens`` — the OUTPUT ceiling. On current models this is a shared cap on *thinking plus
  response*, so a deep-reasoning brain needs real headroom or the answer truncates mid-sentence
  (see ``coder._generate_anthropic``, which now detects that instead of returning a partial string).

Design rules:

* A profile is a **default, not an override**. If the operator has explicitly set ``effort`` or
  ``max_tokens`` in their coding-brain settings, that wins — we never silently spend more of someone
  else's money or quota than they configured. ``apply`` therefore only fills values the operator
  left at the shipped default.
* Profiles are advisory metadata only. They cannot enable a brain, change a provider, or reach the
  network; every safety gate (scope, the differential prover, ``brain_safety.sanitize_brain_field``)
  is unchanged and still owns the result.
* Unknown brain names fall through to the caller's config untouched, so adding a call site can never
  raise.

Stdlib-only, so it stays importable in the frozen desktop build.
"""

from __future__ import annotations

from typing import Any, Final

# Effort levels the current models accept, weakest first. Used to validate a profile at import time.
EFFORT_LEVELS: Final = ("low", "medium", "high", "xhigh", "max")

# The values a fresh install ships with (mirrors coder.CODER_DEFAULTS). A config still holding these
# is treated as "operator did not choose", so a profile may raise it.
_SHIPPED_EFFORT: Final = "high"
_SHIPPED_MAX_TOKENS: Final = 16000

# Values that ANY shipped version has defaulted to. An install that upgrades carries its old
# persisted config forward, so "the operator chose this" cannot be decided against the current
# default alone: a v2.6.x install has 8192 on disk, and treating that as a deliberate choice would
# pair a profile's raised effort with the OLD ceiling — precisely the combination that now fails
# hard on a truncated turn. Any historical default is therefore still "unset".
_UNSET_MAX_TOKENS: Final = frozenset({0, 8192, _SHIPPED_MAX_TOKENS})

# Per-brain profiles. Keys are stable identifiers used at the call sites.
PROFILES: Final[dict[str, dict[str, Any]]] = {
    # Decides where an entire engagement points its probe budget. The highest-leverage single call in
    # the product: one better hypothesis here is a finding the deterministic scanners never reach.
    "hunt_plan": {"effort": "xhigh", "max_tokens": 16000},
    # Runs once per observe->re-plan turn inside a loop, so it is bounded harder than the planner.
    "hunt_react": {"effort": "high", "max_tokens": 8192},
    # Long-horizon strategy/dossier reasoning over a whole target. Deep, and one-shot per target.
    "strategy": {"effort": "xhigh", "max_tokens": 16000},
    # Writes the delivered report: reproduction steps, attack plans, triager-facing narrative.
    "report": {"effort": "high", "max_tokens": 16000},
    # One short impact clause per confirmed finding — hot path, deliberately cheap.
    "narrate": {"effort": "low", "max_tokens": 2048},
    # A single platform-voiced submission summary.
    "submission": {"effort": "medium", "max_tokens": 4096},
    # Multi-step agentic coding in the Workbench: the closest analogue to a coding agent, so xhigh.
    "code_agent": {"effort": "xhigh", "max_tokens": 16000},
    # The agent's up-front plan stage — cheaper than executing, but still real reasoning.
    "code_plan": {"effort": "high", "max_tokens": 8192},
    # Interactive chat: responsiveness matters as much as depth.
    "chat": {"effort": "high", "max_tokens": 8192},
    # Derives a one-line project purpose from a README. Mechanical.
    "memory": {"effort": "low", "max_tokens": 1024},
}

# Fail fast on a typo'd profile rather than silently sending an invalid effort the API will 400 on.
for _name, _p in PROFILES.items():
    if _p["effort"] not in EFFORT_LEVELS:  # pragma: no cover - import-time contract
        raise ValueError(f"brain profile {_name!r} has invalid effort {_p['effort']!r}")
    if not isinstance(_p["max_tokens"], int) or _p["max_tokens"] <= 0:  # pragma: no cover
        raise ValueError(f"brain profile {_name!r} has invalid max_tokens {_p['max_tokens']!r}")


def profile_for(brain: str) -> dict[str, Any]:
    """The profile for ``brain``, or an empty dict if it has none."""
    return dict(PROFILES.get(str(brain or ""), {}))


def apply(cfg: dict[str, Any], brain: str) -> dict[str, Any]:
    """Fill ``cfg`` with ``brain``'s profile where the operator left the shipped defaults.

    ``cfg`` is mutated in place and returned (call sites already hold a private copy from
    ``coder.coder_config``). An explicit operator setting always wins; an unknown brain is a no-op.
    """
    profile = PROFILES.get(str(brain or ""))
    if not profile or not isinstance(cfg, dict):
        return cfg

    # max_tokens lives at the top level of the config.
    try:
        current_max = int(cfg.get("max_tokens") or 0)
    except (TypeError, ValueError):
        current_max = 0
    if current_max in _UNSET_MAX_TOKENS:
        cfg["max_tokens"] = int(profile["max_tokens"])

    # effort lives inside the anthropic provider block (it is an Anthropic-only control).
    block = cfg.get("anthropic")
    if isinstance(block, dict):
        current_effort = str(block.get("effort") or "").strip().lower()
        if current_effort in ("", _SHIPPED_EFFORT):
            block["effort"] = str(profile["effort"])

    cfg["brain_profile"] = str(brain)  # provenance, surfaced in traces/telemetry
    return cfg
