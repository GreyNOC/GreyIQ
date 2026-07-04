"""Safety substrate for AI-brain-authored text that will land in a delivered report or steer a probe.

The brain is an ENRICHER, never an authority: it may only write NARRATIVE into descriptive report
fields (never proof_status / CVSS / the confirmed gate) and may only PROPOSE in-scope probes the
deterministic engine then executes. But its output can still (a) echo a secret it was shown, or
(b) carry a prompt-injection payload reflected from a scanned page/response.

``sanitize_brain_field`` is the single sink every brain-authored string passes through before it is
rendered or used: redact any secret, then scan for injection — and DROP the field entirely (return
None) on a high-risk signal, so the caller falls back to the deterministic value. This is the
symmetric OUT guard to the trust.wrap_for_model IN guard applied to the untrusted inputs at each call
site (captured responses / recon surface fed to the brain).
"""

from __future__ import annotations

from typing import Any

import trust
from bughunter.code_scanner.redaction import redact_text


def sanitize_brain_field(text: Any, *, source: str = "brain output", max_len: int = 6000) -> str | None:
    """Return brain-authored text that is safe to render, or None to fall back to the deterministic value.

    Redacts any secret the brain may have echoed, then scans for prompt-injection; a high-risk signal
    (``trust.scan_text`` level == "risk") discards the text entirely — a tainted narrative never reaches
    the report. Length-bounded so a runaway generation can't bloat a report."""
    raw = str(text or "").strip()
    if not raw:
        return None
    redacted, _ = redact_text(raw[:max_len])
    scan = trust.scan_text(redacted, source=source)
    if scan.get("level") == "risk":
        return None  # a prompt-injection-tainted narrative is dropped, never rendered
    return redacted.strip() or None


def wrap_untrusted_for_brain(text: Any, *, path: str = "captured target content") -> str:
    """Wrap target-derived text (a captured response body, a recon excerpt) in the model DATA boundary
    before the brain sees it — the symmetric IN guard. Empty input yields an empty string."""
    raw = str(text or "").strip()
    if not raw:
        return ""
    return trust.wrap_for_model(raw, path=path)
