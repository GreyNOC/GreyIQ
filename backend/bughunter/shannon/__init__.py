"""GreyIQ BugHunter — the Shannon bridge.

Shannon (``KeygraphHQ/shannon``) is an external autonomous web-pentest engine that pairs
source-code analysis with live exploitation. It is **not vendored**: it is AGPL-3.0, it
runs in Docker behind its own Temporal worker, and GreyIQ talks to it across a process
boundary and reads its output files.

Three modules, one direction of travel:

* :mod:`bughunter.shannon.sarif`     — parse ``report.sarif`` into neutral candidate records.
* :mod:`bughunter.shannon.ingest`    — turn those into GreyIQ hunt findings, as candidates.
* :mod:`bughunter.shannon.workspace` — find a finished run on disk and import it.

GreyIQ owns authorization and the request budget. Shannon owns its own run.

This package reads output Shannon has already produced. It does **not** launch Shannon,
and deliberately so: Shannon has no allowlist, no rate limit, no request cap, no
concurrency control and no cost cap — none of those keys exist in its config schema, and
its ``rules.avoid`` entries for network scope are rendered into a model prompt rather than
enforced by anything. An engine with no limiter cannot be driven inside GreyIQ's politeness
ceiling by asking it nicely, and ``HostRateGovernor`` has no non-blocking
``reserve(host, n)`` for an out-of-process caller to draw against.

``docs/shannon-integration.md`` carries the full architecture, the egress-chokepoint design
that would make driving it safe, and the ordering constraint that keeps this package
read-only until that lands.
"""

from __future__ import annotations

from .ingest import SOURCE, findings_from_run, greyiq_proved, is_external
from .sarif import ShannonCandidate, ShannonRun, parse_sarif_file, parse_sarif_text
from .workspace import find_sarif, ingest_workspace

__all__ = [
    "SOURCE",
    "ShannonCandidate",
    "ShannonRun",
    "find_sarif",
    "findings_from_run",
    "greyiq_proved",
    "ingest_workspace",
    "is_external",
    "parse_sarif_file",
    "parse_sarif_text",
]
