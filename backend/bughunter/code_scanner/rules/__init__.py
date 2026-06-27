"""Rule registry.

Each rule pack module exposes a ``RULES`` constant of ``Rule`` objects.
The registry stitches all packs together so the scanner can iterate
once. Adding a new pack is a single import + tuple append below.
"""

from __future__ import annotations

from bughunter.code_scanner.rules.backdoor import RULES as BACKDOOR_RULES
from bughunter.code_scanner.rules.base import RegexRule, Rule
from bughunter.code_scanner.rules.ci_workflow import RULES as CI_RULES
from bughunter.code_scanner.rules.cmd_inject import RULES as CMD_RULES
from bughunter.code_scanner.rules.crypto import RULES as CRYPTO_RULES
from bughunter.code_scanner.rules.deps import RULES as DEP_RULES
from bughunter.code_scanner.rules.eval_exec import RULES as EVAL_RULES
from bughunter.code_scanner.rules.network import RULES as NETWORK_RULES
from bughunter.code_scanner.rules.secrets import RULES as SECRET_RULES
from bughunter.code_scanner.rules.sqli import RULES as SQLI_RULES
from bughunter.code_scanner.rules.ssrf import RULES as SSRF_RULES

ALL_RULES: tuple[Rule, ...] = (
    *SECRET_RULES,
    *EVAL_RULES,
    *CMD_RULES,
    *NETWORK_RULES,
    *CRYPTO_RULES,
    *CI_RULES,
    *BACKDOOR_RULES,
    *DEP_RULES,
    *SQLI_RULES,
    *SSRF_RULES,
)


__all__ = ["ALL_RULES", "RegexRule", "Rule"]
