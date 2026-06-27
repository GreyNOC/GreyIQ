"""GreyIQ BugHunter — expected-value ranking.

Order a campaign's consolidated findings by what's most likely to PAY, so the
operator works the money first. Pure, deterministic, no deps.

EV = severity_value x learned_prior x confirmed_weight x program_pay_factor, every
factor bounded so no single outlier can dominate. CRITICAL invariant: a CONFIRMED
finding always outranks any non-confirmed one (confirmed is the outermost sort key),
because only confirmed findings are auto-submittable — EV must never let a high
pay-factor lead leapfrog a confirmed finding.
"""

from __future__ import annotations

from typing import Any

_SEV_VALUE = {"critical": 1.0, "high": 0.75, "medium": 0.45, "low": 0.2, "info": 0.05}
_CONFIRMED_WEIGHT = {"confirmed": 2.0, "candidate": 1.0, "missing": 0.4}


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _program_pay_factor(class_id: str, program_stats: dict[str, Any] | None) -> float:
    """A class that has PAID for this program is worth more; one that's been pure
    noise (duplicate/N-A) is worth less. Bounded [0.5, 2.0]; neutral 1.0 with no data."""
    stats = (program_stats or {}).get(str(class_id or "")) if program_stats else None
    if not stats:
        return 1.0
    rewarded = int(stats.get("rewarded", 0))
    noise = int(stats.get("noise", 0))
    adjudicated = rewarded + noise
    paid = float(stats.get("bounty_total", 0.0)) > 0
    if adjudicated == 0:
        return 1.0 + (0.2 if paid else 0.0)
    score = (rewarded - noise) / adjudicated
    return _clamp(1.0 + 0.8 * score + (0.2 if paid else 0.0), 0.5, 2.0)


def expected_value(item: dict[str, Any], priors: dict[str, float] | None, program_stats: dict[str, Any] | None) -> dict[str, Any]:
    """Return {'ev': float, 'breakdown': {...}} for one consolidated item."""
    finding = item.get("finding") or item
    class_id = str(finding.get("class_id") or "")
    sev = _SEV_VALUE.get(str(finding.get("severity") or "info").lower(), 0.05)
    cvss = float((item.get("cvss") or {}).get("base_score") or 0.0)
    sev_value = max(sev, cvss / 10.0)  # prefer the computed CVSS when present
    prior = _clamp(float((priors or {}).get(class_id, 1.0)), 0.5, 2.0)
    proof = str(item.get("proof_status") or finding.get("proof_status") or "missing")
    confirmed_weight = _CONFIRMED_WEIGHT.get(proof, 0.4)
    pay = _program_pay_factor(class_id, program_stats)
    ev = round(sev_value * prior * confirmed_weight * pay, 4)
    return {"ev": ev, "breakdown": {"severity_value": round(sev_value, 3), "prior": prior,
                                    "confirmed_weight": confirmed_weight, "program_pay_factor": round(pay, 3)}}


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def rank_by_ev(consolidated: list[dict[str, Any]], priors: dict[str, float] | None, program_stats: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Stamp item['ev']/item['ev_breakdown'] and sort by (confirmed, ev, severity,
    cvss) — confirmed OUTERMOST so a confirmed finding never sinks below a lead."""
    for item in consolidated:
        ev = expected_value(item, priors, program_stats)
        item["ev"] = ev["ev"]
        item["ev_breakdown"] = ev["breakdown"]

    def _key(item: dict[str, Any]) -> tuple:
        finding = item.get("finding") or item
        confirmed = 1 if str(item.get("proof_status")) == "confirmed" else 0
        sev = _SEV_RANK.get(str(finding.get("severity") or "").lower(), 0)
        cvss = float((item.get("cvss") or {}).get("base_score") or 0.0)
        return (confirmed, item.get("ev", 0.0), sev, cvss)

    consolidated.sort(key=_key, reverse=True)
    return consolidated
