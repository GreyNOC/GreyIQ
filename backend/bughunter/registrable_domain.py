"""GreyIQ BugHunter — best-effort public-suffix-aware registrable domain.

Every "last two dotted labels" heuristic in this codebase (scope-naming checks, the
learning/ledger memory bucket key, JS-mined same-apex host filtering) is wrong for the
common multi-label public suffixes: a real eTLD+1 like ``foo.co.uk`` collapses to the
bare suffix ``co.uk``, and conversely a bare public suffix typed into free-text scope
(``herokuapp.com``, ``github.io``) gets treated as though it were someone's own apex
domain — which would authorize EVERY unrelated tenant under that shared host.

This is NOT a full Public Suffix List implementation (no bundled data file, no ICANN/
PSL fetch — this is a frozen-safe, dependency-free tool). It is a small built-in set of
the multi-label suffixes an operator is actually likely to encounter: common
country-code second-level domains (co.uk, com.au, ...) and the multi-tenant PaaS/cloud
hosts this engine's own takeover/CVE scanners already reason about (github.io,
herokuapp.com, ...). Good enough for a scope-naming / memory-bucketing heuristic; not a
substitute for the real Public Suffix List.
"""

from __future__ import annotations

# Common multi-label ccSLDs an operator's scope text might genuinely contain a 3+-label
# host under (e.g. "shop.example.co.uk"). Last TWO labels alone is wrong for these.
_CC_SECOND_LEVEL = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "ne.kr", "or.kr",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.za", "org.za", "gov.za", "net.za",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "gen.in",
    "co.id", "or.id", "go.id", "ac.id",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "id.au",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "com.sg", "com.tw", "com.hk", "co.il", "co.th",
})

# Multi-tenant PaaS / static-hosting / cloud-storage suffixes: many unrelated parties
# each own ONE subdomain. Naming the bare suffix in scope must NEVER authorize the whole
# platform (the "victim-unrelated.herokuapp.com" bug). Cross-referenced with the
# dangling-service suffixes takeover_service.py already treats as third-party platforms.
_SHARED_HOSTING = frozenset({
    "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev",
    "web.app", "firebaseapp.com", "appspot.com", "s3.amazonaws.com", "azurewebsites.net",
    "blob.core.windows.net", "cloudfront.net", "surge.sh", "render.com", "fly.dev",
    "ngrok.io", "ngrok-free.app", "repl.co", "glitch.me", "azureedge.net", "z13.web.core.windows.net",
    # Bare parent forms of the multi-label entries above: "amazonaws.com" and
    # "core.windows.net"/"windows.net" must ALSO be refused as bare scope tokens --
    # without these, is_bare_public_suffix("amazonaws.com") returns False, so naming
    # the parent (not the full "s3.amazonaws.com"/"blob.core.windows.net") in
    # free-text scope falls through to the dotted-suffix match and authorizes
    # probing EVERY unrelated tenant's S3 bucket / Azure Storage container.
    "amazonaws.com", "core.windows.net", "windows.net",
})

_KNOWN_MULTI_LABEL_SUFFIXES = _CC_SECOND_LEVEL | _SHARED_HOSTING


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1: the last two dotted labels, EXCEPT when those two labels are
    themselves a known multi-label public suffix (a ccSLD like ``co.uk`` or a shared
    PaaS host like ``herokuapp.com``) — then one more label is included so a real owned
    domain under that suffix (``foo.co.uk``, ``myapp.herokuapp.com``) resolves to
    itself, not to the bare suffix. Never resolves a host to FEWER labels than it has."""
    labels = (host or "").strip(".").lower().split(".")
    if len(labels) < 2:
        return host or ""
    two = ".".join(labels[-2:])
    if two in _KNOWN_MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return two


def is_bare_public_suffix(token: str) -> bool:
    """True when ``token`` IS (as a whole, exactly) a known multi-label public suffix
    (e.g. ``herokuapp.com``, ``co.uk``) rather than a real, ownable apex domain. A direct
    set-membership check, not a derived comparison via registrable_domain() — a bare
    2-label suffix like ``herokuapp.com`` can't be "bumped" any further (it has no third
    label to take), so registrable_domain() would just return it unchanged and a
    ``registrable_domain(token) != token`` test would wrongly say it's NOT a suffix. Used
    to refuse a free-text scope token that would otherwise authorize an entire
    shared-hosting platform."""
    return (token or "").strip(".").lower() in _KNOWN_MULTI_LABEL_SUFFIXES
