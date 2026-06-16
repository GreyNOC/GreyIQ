"""CI / build-workflow rules.

Source-poisoning attacks like the xz / Codecov bash-uploader incidents
ride on innocuous-looking CI shapes: a fresh curl|bash in a workflow,
an action pinned to a moving tag rather than a SHA, a secret read into
the environment of a PR-triggered job, or a workflow that downloads a
build script over plain HTTP.
"""

from __future__ import annotations

import re

from bughunter.code_scanner.model import Confidence, Severity
from bughunter.code_scanner.rules.base import RegexRule

_GITHUB_WORKFLOW_GLOB = ("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml")

RULES = (
    RegexRule(
        rule_id="ci.curl-pipe-shell-in-workflow",
        title="Workflow pipes a remote download into a shell",
        description=(
            "A GitHub Actions step downloads a script over HTTP(S) and pipes it into a shell. "
            "The script is unpinned and unverified."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="ci",
        remediation=(
            "Download to a file, verify a pinned SHA256, then execute. Or use a tagged action "
            "pinned to a SHA."
        ),
        path_globs=_GITHUB_WORKFLOW_GLOB,
        pattern=r"(?:curl|wget)[^\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python|node)\b",
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="ci.unpinned-action-version",
        title="Action pinned to a moving tag instead of a SHA",
        description=(
            "uses: third-party/action@v1 follows the v1 tag. A maintainer compromise or "
            "tag-force-push silently swaps in attacker code on the next run."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category="ci",
        remediation="Pin to a full commit SHA: uses: actor/action@<40-char-sha>.",
        path_globs=_GITHUB_WORKFLOW_GLOB,
        pattern=r"uses:\s*(?!actions/)[\w\-./]+/[\w\-.]+@(?:v?\d+(?:\.\d+){0,2}|main|master|latest)\b",
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="ci.pull-request-target-with-checkout-ref",
        title="pull_request_target trigger + checkout of the PR ref",
        description=(
            "pull_request_target runs with write tokens. Checking out the PR head and running its "
            "code (build, test, npm install) is the canonical PR-poison attack."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        category="ci",
        remediation=(
            "Don't run untrusted code under pull_request_target. Use pull_request, or only run "
            "deterministic linters / label gates."
        ),
        path_globs=_GITHUB_WORKFLOW_GLOB,
        pattern=r"on:[\s\S]{0,400}?pull_request_target[\s\S]{0,1000}?ref:\s*\$\{\{\s*github\.event\.pull_request\.head",
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="ci.secrets-in-issue-comment",
        title="Workflow reads secrets in an issue / PR comment trigger",
        description=(
            "Issue / PR comment triggers run on attacker-influenced input. Loading secrets in the "
            "same job is exfil-ready."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category="ci",
        remediation="Gate secret access behind a labeled / restricted environment.",
        path_globs=_GITHUB_WORKFLOW_GLOB,
        pattern=r"on:[\s\S]{0,400}?issue_comment[\s\S]{0,2000}?secrets\.\w+",
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="ci.http-download-in-build",
        title="Build step downloads over plain HTTP",
        description="A workflow downloads a tarball or installer over plain HTTP — trivially MITM-able.",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category="ci",
        remediation="Switch to HTTPS, verify a pinned checksum, and prefer a packaged dependency.",
        path_globs=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml", "*.sh"),
        pattern=r"(?:curl|wget)[^\n]*\bhttp://[\w\-./?=&%]+",
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="ci.dockerfile-add-remote-url",
        title="Dockerfile ADD from a remote URL",
        description=(
            "ADD https://... in a Dockerfile fetches over the network without integrity check. "
            "ADD also auto-extracts archives, which has bitten image builds before."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category="ci",
        remediation="Use RUN curl + sha256sum verification, or vendor the artifact.",
        path_globs=("**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile"),
        pattern=r"^\s*ADD\s+https?://\S+",
        flags=re.MULTILINE | re.IGNORECASE,
    ),
    RegexRule(
        rule_id="ci.npm-install-no-lock",
        title="Build runs npm install without lockfile enforcement",
        description=(
            "npm install without npm ci or --no-package-lock can silently resolve to a newer "
            "transitive dependency than was vetted."
        ),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        category="ci",
        remediation="Use npm ci in CI, or commit package-lock.json and pin via npm install --no-package-lock --no-save false.",
        path_globs=_GITHUB_WORKFLOW_GLOB,
        pattern=r"\brun:\s*['\"]?npm\s+install\b",
        flags=re.MULTILINE,
    ),
)
