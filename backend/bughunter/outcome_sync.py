"""GreyIQ BugHunter — close the outcome loop: real platform verdicts into the learning store.

THE LOOP THIS CLOSES
--------------------
The engine learns a great deal from its own observations — negative knowledge cools an
``(endpoint, class)`` pair after two misses, and ``brain_techniques.learned_hunt_priors``
reweights classes from its own hunt traces. Both are autonomous and both work.

What it could not learn on its own is **what pays**. At submission time the engine records
``status="submitted"``, and ``learning.learned_priors`` deliberately discards that — "I sent
it" is not "it paid", and counting it would be fabricating an outcome. The only adjudicated
source is the platform, and reaching it used to require a human in the desktop UI:

    the engine's own automatic write (status='submitted')  ->  learned_priors == {}
    a human-recorded adjudicated outcome ('accepted')      ->  learned_priors == {'xss': 2.0}

So payout priors stayed empty forever, ``ranking._program_pay_factor`` stayed at its
neutral 1.0, and the operator loop hunted programs in alphabetical order regardless of
which had ever paid.

This module is that logic as ONE function, callable from three places: the HTTP route, the
``gn sync`` CLI verb, and the operator loop's own per-cycle sync. It was previously a method
on the API runtime, which is why neither the CLI nor the operator could reach it.

WHAT KEEPS IT SAFE
------------------
* **Read-only.** It issues GETs for reports GreyIQ itself submitted. It never files, never
  comments, never changes anything on the platform.
* **Bounded.** ``ledger.submitted_records`` caps the poll at the most recently submitted
  findings and excludes any report already synced to a terminal state, so a repeat pass
  never re-polls a finished report. HackerOne's report-read limit is 300/min; the default
  cap is far below it.
* **Terminal states only.** ``H1_STATE_TO_LEARNING_OUTCOME`` maps only states that are
  actually over. An in-progress state (``new``, ``triaged``, ``needs-more-info``,
  ``retesting``, ``pending-program-review``) is deliberately absent, so a sync pass can
  never record a premature "it's over" verdict.
* **Fail-soft.** Missing credentials, a network error or a single bad report degrade to a
  reported error in the result envelope. A sync failure must never take a hunt cycle down.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bughunter import hackerone_activity, learning, ledger

#: HackerOne report state -> ``learning`` outcome. TERMINAL states only, on purpose: an
#: in-progress state has no outcome yet, and recording one would teach the ranker a verdict
#: the program has not actually reached.
H1_STATE_TO_LEARNING_OUTCOME: dict[str, str] = {
    "resolved": "resolved",
    "duplicate": "duplicate",
    "not-applicable": "not-applicable",
    "informative": "informative",
    "spam": "spam",
}

#: Default poll cap per pass. Well under HackerOne's 300/min report-read limit, and the
#: operator loop calls this once per cycle rather than once per target.
DEFAULT_LIMIT = 25


def sync_outcomes(
    runtime_dir: str | Path,
    *,
    api_username: str,
    api_token: str,
    limit: int = DEFAULT_LIMIT,
    fetch_status: Any = None,
) -> dict[str, Any]:
    """Poll the platform for every locally-'submitted' finding and reflect real outcomes.

    Returns ``{"ok", "checked", "updated", "outcomes", "errors"}``. ``outcomes`` counts the
    rows that reached the learning store, which is the number that actually matters — an
    update to the ledger's ``h1_state`` alone (new -> triaged) changes no ranking.

    ``fetch_status`` is injectable so tests never touch the network.
    """
    if not (str(api_username or "").strip() and str(api_token or "").strip()):
        return {"ok": False, "error": "HackerOne API username + token are required to sync outcomes.",
                "checked": 0, "updated": 0, "outcomes": 0, "errors": []}

    fetch = fetch_status or hackerone_activity.fetch_report_status
    records = ledger.submitted_records(runtime_dir, limit=limit)
    checked = updated = outcomes = 0
    errors: list[str] = []

    for rec in records:
        checked += 1
        status = fetch(rec.get("h1_report_id", ""), api_username, api_token)
        if not status.get("ok"):
            errors.append(f"#{rec.get('h1_report_id')}: {status.get('error', 'unknown error')}")
            continue
        state = str(status.get("state") or "")
        resolved_with_reward = bool(status.get("bounty_awarded_at") or status.get("swag_awarded_at"))
        # A reward can land on the live report before (or without) a state change — still
        # 'triaged' but bounty_awarded_at just got set — so skip only when NEITHER signal
        # moved. submitted_records() never returns an already-'paid' record, so a reward
        # here is always new information.
        if state == str(rec.get("h1_state") or "") and not resolved_with_reward:
            continue
        try:
            reward_amount = float(status.get("total_awarded_amount") or 0.0)
        except (TypeError, ValueError):
            reward_amount = 0.0

        try:
            ledger.record_h1_sync(runtime_dir, rec["pid"], rec["key"], state=state,
                                  resolved_with_reward=resolved_with_reward, bounty=reward_amount)
            updated += 1
        except (KeyError, OSError, ValueError) as error:
            errors.append(f"#{rec.get('h1_report_id')}: ledger write failed: {error}")
            continue

        learning_status = H1_STATE_TO_LEARNING_OUTCOME.get(state)
        if not learning_status:
            continue  # in-progress — real news for the ledger, not yet an outcome to learn
        try:
            # rec["program"] is the ledger's already-slugified pid. learning.program_key
            # treats a non-empty `program` as authoritative and re-slugifies (a no-op on a
            # slug), so this lands in the SAME bucket the ledger used whatever `target` is.
            learning.record_outcome(
                runtime_dir, program=rec.get("program"), target=rec.get("source_url", ""),
                class_id=str(rec.get("class_id") or "other"), title=str(rec.get("title") or ""),
                status=learning_status, severity=str(rec.get("severity") or ""),
                # The freshly-fetched amount; rec['bounty'] is the pre-sync copy, still 0.0.
                bounty=reward_amount if resolved_with_reward else 0.0,
                notes=f"HackerOne report {rec.get('h1_report_id')} synced to '{state}'",
            )
            outcomes += 1
        except (ValueError, OSError) as error:
            errors.append(f"#{rec.get('h1_report_id')}: learning write failed: {error}")

    return {"ok": True, "checked": checked, "updated": updated, "outcomes": outcomes, "errors": errors}
