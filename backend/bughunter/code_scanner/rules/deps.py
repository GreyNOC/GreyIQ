"""Dependency-manifest rules.

Static checks of package manifests that flag versions known to be
malicious (post-compromise rotations of an account that pushed a poisoned
release) and patterns that have been weaponized for supply-chain
attacks (postinstall scripts that run network code, install URLs in
requirements.txt, etc.).

The bundled malicious-version list is small on purpose: it covers the
high-profile incidents (event-stream, ua-parser-js, colors/faker
rage-publishes, polyfill.io, the November 2024 Solana-Web3.js
hijack). Users who need broader coverage should connect the BYO LLM
or wire an external vulnerability feed.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Finding, Severity
from bughunter.code_scanner.rules.base import RegexRule, Rule

# pkg name -> set of compromised version specifiers.
# All entries here represent versions where the published artifact was
# either malicious or a forced rage-publish that broke installs in the
# wild. The list is short on purpose; it's a known-bad signal, not a
# coverage claim.
KNOWN_BAD_NPM_VERSIONS: dict[str, tuple[str, ...]] = {
    "event-stream": ("3.3.6",),
    "flatmap-stream": ("0.1.1",),
    "ua-parser-js": ("0.7.29", "0.8.0", "1.0.0"),
    "colors": ("1.4.1", "1.4.2"),
    "faker": ("6.6.6",),
    "node-ipc": ("10.1.1", "10.1.2", "10.1.3"),
    "rc": ("1.2.9", "1.3.9", "2.3.9"),
    "coa": ("2.0.3",),
    "@solana/web3.js": ("1.95.6", "1.95.7"),
    "lottie-player": ("2.0.5", "2.0.6", "2.0.7"),
}

# Same pattern for PyPI.
KNOWN_BAD_PYPI_VERSIONS: dict[str, tuple[str, ...]] = {
    # ctx / phpass — June 2022 takeover by a researcher.
    "ctx": ("0.2.2", "0.2.6"),
    "phpass": ("1.2.23",),
    # Examples of common typosquats that landed on PyPI in 2023-2024.
    "colourama": ("*",),
    "request": ("*",),
    "djano": ("*",),
}


_NPM_VERSION_RE = re.compile(
    r"\"(?P<name>@?[\w./\-]+)\"\s*:\s*\"\^?~?(?P<version>\d+\.\d+\.\d+[\w.\-]*)\"",
)
_PYPI_REQ_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)\s*==\s*(?P<version>\d+(?:\.\d+){1,3}[\w.\-]*)",
    re.MULTILINE,
)


class NpmKnownBadVersionRule(Rule):
    """Match package.json / package-lock.json entries against the malicious list."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="deps.npm-known-bad-version",
            title="npm dependency at a known-compromised version",
            description=(
                "Package version was flagged as malicious or rage-published in the wild."
            ),
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="dependency",
            remediation=(
                "Bump to a clean version per the project's security advisory, scrub "
                "lockfiles, audit any postinstall side-effects."
            ),
            languages=(),
            path_globs=("**/package.json", "**/package-lock.json", "**/npm-shrinkwrap.json"),
        )

    def scan(self, *, path: str, text: str):  # type: ignore[override]
        for match in _NPM_VERSION_RE.finditer(text):
            name = match.group("name")
            version = match.group("version")
            bad = KNOWN_BAD_NPM_VERSIONS.get(name)
            if not bad:
                continue
            if "*" in bad or version in bad:
                line = text.count("\n", 0, match.start()) + 1
                yield Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"{name}@{version} matches a published malicious / rage-published "
                        f"version: {', '.join(bad)}."
                    ),
                    severity=self.severity,
                    confidence=self.confidence,
                    category=self.category,
                    file_path=path,
                    line_start=line,
                    line_end=line,
                    snippet=match.group(0)[:240],
                    remediation=self.remediation,
                )


class PypiKnownBadVersionRule(Rule):
    """Match requirements.txt / pyproject.toml entries against the malicious list."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="deps.pypi-known-bad-version",
            title="PyPI dependency at a known-compromised version",
            description=(
                "Package version was flagged as malicious or a known typosquat package."
            ),
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="dependency",
            remediation=(
                "Bump to a clean version per the published advisory, audit any post-install "
                "side-effects, rebuild from a clean ref."
            ),
            languages=(),
            path_globs=(
                "**/requirements*.txt",
                "**/setup.py",
                "**/setup.cfg",
                "**/Pipfile",
                "**/pyproject.toml",
            ),
        )

    def scan(self, *, path: str, text: str):  # type: ignore[override]
        for match in _PYPI_REQ_RE.finditer(text):
            name = match.group("name").lower()
            version = match.group("version")
            bad = KNOWN_BAD_PYPI_VERSIONS.get(name)
            if not bad:
                continue
            if "*" in bad or version in bad:
                line = text.count("\n", 0, match.start()) + 1
                yield Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"{name}=={version} matches the bundled compromised-version list: "
                        f"{', '.join(bad)}."
                    ),
                    severity=self.severity,
                    confidence=self.confidence,
                    category=self.category,
                    file_path=path,
                    line_start=line,
                    line_end=line,
                    snippet=match.group(0)[:240],
                    remediation=self.remediation,
                )


RULES = (
    RegexRule(
        rule_id="deps.npm-postinstall-network",
        title="npm postinstall runs a network call",
        description=(
            "postinstall scripts run during `npm install` with full filesystem and network "
            "access. Calls to curl / wget / sh -c download in a postinstall are a common "
            "supply-chain attack pattern."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="dependency",
        remediation="Replace the postinstall with an explicit setup step the user opts into.",
        path_globs=("**/package.json",),
        pattern=r"\"postinstall\"\s*:\s*\"[^\"]*(?:curl|wget|node\s+-e|eval)",
    ),
    RegexRule(
        rule_id="deps.requirements-vcs-or-url",
        title="requirements file installs from a raw URL or git ref",
        description=(
            "pip install -r requirements.txt that resolves a name to a git+https / file URL "
            "bypasses package signing and tag-pinning. Used by some legitimate projects but "
            "a common supply-chain attack carrier."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category="dependency",
        remediation="Pin to a PyPI release with a SHA256, or vendor the dependency.",
        path_globs=("**/requirements*.txt",),
        pattern=r"^(?:git\+|hg\+|svn\+|bzr\+|file://|https?://|\-e\s+git\+)",
        flags=re.MULTILINE,
    ),
    NpmKnownBadVersionRule(),
    PypiKnownBadVersionRule(),
)
