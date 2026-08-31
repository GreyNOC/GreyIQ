"""Attack-plan mapper — a GRAPHICAL (SVG → PNG) diagram of the attack GreyIQ ran against a finding.

Turns a finding's attack plan + captured differential into a top-down flow diagram
(actor → crafted probe → observed tell vs negative control → impact), saved as a ``.png``
beside the proof screenshot in the finding's POC download so a triager SEES the attack, not just reads
it. This is the visual counterpart to the text reproduction steps.

HONEST BY CONSTRUCTION: the map is a proof artifact — it is embedded in the report body and copied
into the platform submission package — so it renders the state the CONFIRM GATE assigned the finding
(``report._proof_of_impact_detail``) and never a confirmation the gate withheld. Any renderable
finding may be mapped, including a passive lead, so an unproven stage is drawn as the capture that is
still outstanding rather than dropped or filled with narrative.

SAFE BY CONSTRUCTION:
- The SVG is built ENTIRELY from our own data. Every dynamic string is XML-escaped, control-char
  stripped, and length-capped, so target-derived proof text can never break the markup or inject a
  ``<script>``.
- Rasterized by the bundled Chromium with JavaScript DISABLED and ALL network BLOCKED — the document is
  self-contained (inline styles, system fonts, no external refs), so there is zero egress and any
  attacker-controlled proof text is only ever drawn as inert text.
- Playwright-lazy and FAIL-OPEN: no Chromium / any render error → no map, never an exception that could
  break a hunt (the caller treats a falsy return as "no map this time", exactly like a screenshot).
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

from bughunter import report as report_lib
from bughunter.code_scanner.redaction import redact_text
from bughunter.playwright_env import ensure_bundled_browsers_path

# Stage palette (accent, fill) — cool→warm as the attack advances to the confirmed impact. The two
# unproven kinds are deliberately neutral slate: a green tell or a red impact box reads as proof at a
# glance, so a stage that was never captured must not borrow that colour.
_STAGES = {
    "actor": ("#6366f1", "#eef2ff"),
    "probe": ("#0ea5e9", "#e0f2fe"),
    "observed": ("#16a34a", "#dcfce7"),
    "control": ("#d97706", "#fef3c7"),
    "confirmed": ("#dc2626", "#fee2e2"),
    "pending": ("#64748b", "#f1f5f9"),
    "candidate": ("#475569", "#e2e8f0"),
}
_SEVERITY_COLOR = {"critical": "#7f1d1d", "high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#4b5563"}
_WIDTH = 860
_MARGIN = 28
_BOX_W = _WIDTH - 2 * _MARGIN
_PAD = 14
_LINE_H = 19
_LABEL_H = 20
_GAP = 30          # vertical gap between boxes (the arrow lives here)
_WRAP = 78         # chars per wrapped line (approx, for the ~13px monospace-ish body)
_MAX_LINES = 4     # cap each box body so one huge field can't make a giant image


def _clean(text: Any, cap: int = 400) -> str:
    """Redact, strip control chars, collapse whitespace, cap — before XML-escaping. A defensive
    normalize so target-derived proof text is safe and compact in the diagram."""
    s, _ = redact_text(str(text or ""))
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:cap]


def _wrap(text: str, width: int = _WRAP, max_lines: int = _MAX_LINES) -> list[str]:
    """Greedy word-wrap into at most ``max_lines`` lines; a very long token is hard-split; overflow is
    truncated with an ellipsis so the box height stays bounded."""
    words = text.split(" ")
    lines: list[str] = []
    cur = ""
    for w in words:
        while len(w) > width:  # a single token longer than a line (e.g. a URL/token) — hard split
            if cur:
                lines.append(cur); cur = ""
            lines.append(w[:width]); w = w[width:]
            if len(lines) >= max_lines:
                break
        if len(lines) >= max_lines:
            break
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= width:
            cur += " " + w
        else:
            lines.append(cur); cur = w
        if len(lines) >= max_lines:
            break
    if cur and len(lines) < max_lines:
        lines.append(cur)
    if not lines:
        return [""]
    # If we ran out of room but there was more text, mark the truncation on the last line.
    joined = " ".join(lines)
    if len(joined) < len(text):
        last = lines[-1]
        lines[-1] = (last[: width - 1].rstrip() + "…") if last else "…"
    return lines[:max_lines]


def _e(text: str) -> str:
    """XML-escape for safe embedding as SVG text (the single most important safety step)."""
    return html.escape(text, quote=True)


def _box(y: int, kind: str, label: str, body_lines: list[str]) -> tuple[str, int]:
    """One rounded stage box at ``y``; returns (svg, next_y). Height grows with the wrapped body."""
    accent, fill = _STAGES.get(kind, ("#475569", "#f1f5f9"))
    body_h = max(1, len(body_lines)) * _LINE_H
    h = _LABEL_H + _PAD + body_h + _PAD
    parts = [
        f'<rect x="{_MARGIN}" y="{y}" width="{_BOX_W}" height="{h}" rx="10" '
        f'fill="{fill}" stroke="{accent}" stroke-width="1.5"/>',
        f'<rect x="{_MARGIN}" y="{y}" width="6" height="{h}" rx="3" fill="{accent}"/>',
        f'<text x="{_MARGIN + _PAD}" y="{y + _LABEL_H}" font-family="Segoe UI,Arial,sans-serif" '
        f'font-size="13" font-weight="700" fill="{accent}" letter-spacing="0.5">{_e(label)}</text>',
    ]
    ty = y + _LABEL_H + _PAD + 4
    for line in body_lines:
        parts.append(
            f'<text x="{_MARGIN + _PAD}" y="{ty}" font-family="Consolas,SFMono-Regular,Menlo,monospace" '
            f'font-size="13" fill="#0f172a">{_e(line)}</text>')
        ty += _LINE_H
    return "\n".join(parts), y + h


def _arrow(y: int) -> str:
    """A downward connector arrow centered between two boxes, occupying the _GAP below ``y``."""
    cx = _WIDTH // 2
    return (f'<line x1="{cx}" y1="{y + 4}" x2="{cx}" y2="{y + _GAP - 6}" stroke="#94a3b8" '
            f'stroke-width="2" marker-end="url(#arrow)"/>')


def _gate_confirmed(finding: dict[str, Any], plan: dict[str, Any]) -> bool:
    """Ask THE confirm authority — ``report._proof_of_impact_detail``, the same gate the report body,
    the submission package and the proof badge read — whether this finding is confirmed.

    Deriving a second "looks confirmed" rule here would be a softer gate on the artifact a triager
    trusts most, so this delegates and FAILS CLOSED: any error means the map claims nothing."""
    try:
        return str(report_lib._proof_of_impact_detail(finding, plan).get("status") or "") == "confirmed"
    except Exception:  # noqa: BLE001 - an unreadable finding is not a confirmed one
        return False


def build_attack_svg(finding: dict[str, Any], plan: dict[str, Any] | None = None) -> str:
    """Build the attack-flow SVG for a finding from its plan + captured differential, rendering the
    state the confirm gate assigned it. Deterministic and dependency-free; every dynamic value is
    cleaned + XML-escaped."""
    plan = plan if isinstance(plan, dict) else {}
    poi = plan.get("proof_of_impact") if isinstance(plan.get("proof_of_impact"), dict) else {}
    ev = finding.get("proof_evidence") if isinstance(finding.get("proof_evidence"), dict) else {}
    confirmed = _gate_confirmed(finding, plan)

    title = _clean(finding.get("title") or finding.get("class_name") or "Finding", 120)
    severity = _clean(finding.get("severity") or "", 12).lower() or "info"
    cls = _clean(finding.get("class_name") or finding.get("class_id") or "finding", 80)
    target = _clean(finding.get("location") or finding.get("file_path") or "", 200)
    actor = _clean(poi.get("actor") or "an unauthenticated attacker", 160)
    request_line = _clean(ev.get("request_line") or poi.get("method") or "", 200)
    request_header = _clean(ev.get("request_header") or "", 160)
    observed = _clean(poi.get("observed_result") or ev.get("matched_value") or "", 320)
    control = _clean(poi.get("control_result") or "", 320)
    obligation = _clean(poi.get("proof_obligation") or "", 260)
    impact = _clean(poi.get("proof_obligation") or plan.get("impact") or poi.get("affected_asset") or "", 260)

    # Assemble the ordered stages. A proof stage with nothing captured is drawn as the outstanding
    # capture, never dropped and never filled with narrative — the gap IS the finding's state.
    stages: list[tuple[str, str, list[str]]] = []
    stages.append(("actor", "1 · ACTOR", _wrap(actor)))
    probe_body = [request_line] if request_line else []
    if request_header:
        probe_body.append(request_header)
    if target and (not request_line or target not in request_line):
        probe_body.append(f"target: {target}")
    stages.append(("probe", "2 · CRAFTED PROBE", _wrap(" ".join(probe_body) if not request_line else request_line)
                   if len(probe_body) <= 1 else [_clean(x, 200) for x in probe_body][:_MAX_LINES]))
    # 3 · the tell. Only a real captured string may fill this box: writing "the vulnerable behaviour
    # was observed" when nothing was captured put a fabricated observation into a submitted artifact.
    if observed:
        stages.append(("observed" if confirmed else "pending",
                       "3 · OBSERVED (the tell)" if confirmed
                       else "3 · OBSERVED — NOT ACCEPTED BY THE CONFIRM GATE", _wrap(observed)))
    else:
        stages.append(("pending", "3 · OBSERVED — NOT CAPTURED YET",
                       _wrap("still to capture: " + (obligation or "the response that shows the vulnerable "
                                                                  "behaviour, beside the request that caused it"))))
    # 4 · the negative control. NEVER dropped when empty: a missing control is exactly what a triager
    # has to see, and silently omitting the stage made the map read as if the check had passed.
    if control:
        stages.append(("control", "4 · NEGATIVE CONTROL (rules out a false positive)", _wrap(control)))
    else:
        stages.append(("pending", "4 · NEGATIVE CONTROL — NOT CAPTURED YET",
                       _wrap("still to capture: the same request without the attack condition, showing the "
                             "benign response the tell differs from")))
    conf_body = [f"{cls} — severity {severity}"]
    if confirmed:
        if impact:
            conf_body += _wrap(impact, _WRAP, _MAX_LINES - 1)
        stages.append(("confirmed", "✓ CONFIRMED", conf_body[:_MAX_LINES]))
    else:
        conf_body += _wrap("still to prove: " + (obligation or impact or "a captured artifact the confirm "
                                                                        "gate accepts as proof of impact"),
                           _WRAP, _MAX_LINES - 1)
        stages.append(("candidate", "CANDIDATE — NOT YET CONFIRMED", conf_body[:_MAX_LINES]))

    # Header height, then lay out the boxes with arrows.
    header_h = 74
    y = header_h + _MARGIN
    body_parts: list[str] = []
    for i, (kind, label, lines) in enumerate(stages):
        svg_box, y2 = _box(y, kind, label, lines)
        body_parts.append(svg_box)
        if i < len(stages) - 1:
            body_parts.append(_arrow(y2))
            y = y2 + _GAP
        else:
            y = y2
    total_h = y + _MARGIN

    sev_color = _SEVERITY_COLOR.get(severity, "#4b5563")
    # The eyebrow carries the gate's verdict: the .png is pasted into a report on its own, so the
    # state has to be legible without the surrounding prose.
    eyebrow = "GreyIQ · ATTACK PLAN · CONFIRMED" if confirmed else "GreyIQ · ATTACK PLAN · CANDIDATE (NOT CONFIRMED)"
    header = (
        f'<rect x="0" y="0" width="{_WIDTH}" height="{header_h}" fill="#0f172a"/>'
        f'<text x="{_MARGIN}" y="30" font-family="Segoe UI,Arial,sans-serif" font-size="12" '
        f'font-weight="700" fill="#94a3b8" letter-spacing="1.5">{_e(eyebrow)}</text>'
        f'<text x="{_MARGIN}" y="56" font-family="Segoe UI,Arial,sans-serif" font-size="18" '
        f'font-weight="700" fill="#f8fafc">{_e(title)}</text>'
        f'<rect x="{_WIDTH - _MARGIN - 96}" y="20" width="96" height="34" rx="6" fill="{sev_color}"/>'
        f'<text x="{_WIDTH - _MARGIN - 48}" y="42" text-anchor="middle" font-family="Segoe UI,Arial,sans-serif" '
        f'font-size="13" font-weight="700" fill="#ffffff">{_e(severity.upper())}</text>'
    )
    defs = ('<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="7" refY="3" orient="auto" '
            'markerUnits="strokeWidth"><path d="M0,0 L7,3 L0,6 Z" fill="#94a3b8"/></marker></defs>')
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_WIDTH}" height="{total_h}" '
        f'viewBox="0 0 {_WIDTH} {total_h}" font-family="Segoe UI,Arial,sans-serif">'
        f'{defs}<rect x="0" y="0" width="{_WIDTH}" height="{total_h}" fill="#ffffff"/>'
        f'{header}{"".join(body_parts)}</svg>'
    )


def render_attack_map(finding: dict[str, Any], plan: dict[str, Any] | None, out_path: str | Path,
                      settings: Any = None) -> dict[str, Any]:
    """Render the attack-flow diagram to a PNG at ``out_path`` via the bundled Chromium. Returns
    ``{ok, path}`` or ``{ok: False, error}`` — NEVER raises. JS disabled + all network blocked, so the
    self-contained (and fully escaped) SVG is rasterized with zero egress."""
    out = Path(out_path)
    try:
        svg = build_attack_svg(finding, plan)
    except Exception as exc:  # noqa: BLE001 - the map is enrichment; a build error must not break a hunt
        return {"ok": False, "error": f"attack-map build failed: {exc}"}
    try:
        ensure_bundled_browsers_path()  # point Playwright at the bundled Chromium (frozen build)
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001 - optional dependency / env probe; fail open, never raise
        return {"ok": False, "error": "Playwright/Chromium unavailable — attack map skipped."}
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "error": f"could not create the output directory: {exc}"}
    doc = ('<!doctype html><html><head><meta charset="utf-8"></head>'
           '<body style="margin:0;display:inline-block;background:#ffffff">' + svg + "</body></html>")
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            # No JS (the SVG is static), and abort EVERY request — the document is self-contained, so a
            # crafted external ref (there are none) could never egress. Pure local rasterization.
            context = browser.new_context(java_script_enabled=False)
            context.route("**/*", lambda route: route.abort())
            page = context.new_page()
            page.set_content(doc, wait_until="load")
            element = page.query_selector("svg")
            (element or page).screenshot(path=str(out))
            browser.close()
    except Exception as exc:  # noqa: BLE001 - any render error -> no map, never fatal
        return {"ok": False, "error": f"attack-map render failed: {exc}"}
    return {"ok": True, "path": str(out)}
