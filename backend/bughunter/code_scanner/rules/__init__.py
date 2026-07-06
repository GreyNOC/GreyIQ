"""Rule registry.

Each rule pack module exposes a ``RULES`` constant of ``Rule`` objects.
The registry stitches all packs together so the scanner can iterate
once. Adding a new pack is a single import + tuple append below.
"""

from __future__ import annotations

from bughunter.code_scanner.rules.backdoor import RULES as BACKDOOR_RULES
from bughunter.code_scanner.rules.access_control import RULES as ACCESS_CONTROL_RULES
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
from bughunter.code_scanner.rules.deserialize import RULES as DESERIALIZE_RULES
from bughunter.code_scanner.rules.open_redirect import RULES as REDIRECT_RULES
from bughunter.code_scanner.rules.ssti_source import RULES as SSTI_SOURCE_RULES
from bughunter.code_scanner.rules.xxe import RULES as XXE_RULES
from bughunter.code_scanner.rules.jwt_weak import RULES as JWT_WEAK_RULES
from bughunter.code_scanner.rules.chrome_extension import RULES as CHROME_EXT_RULES

ALL_RULES: tuple[Rule, ...] = (
    *SECRET_RULES,
    *ACCESS_CONTROL_RULES,
    *EVAL_RULES,
    *CMD_RULES,
    *NETWORK_RULES,
    *CRYPTO_RULES,
    *CI_RULES,
    *BACKDOOR_RULES,
    *DEP_RULES,
    *SQLI_RULES,
    *SSRF_RULES,
    *DESERIALIZE_RULES,
    *REDIRECT_RULES,
    *SSTI_SOURCE_RULES,
    *XXE_RULES,
    *JWT_WEAK_RULES,
    *CHROME_EXT_RULES,
)


__all__ = ["ALL_RULES", "RegexRule", "Rule"]
