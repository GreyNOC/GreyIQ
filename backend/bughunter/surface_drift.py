"""Surface-drift engine — the hunt's memory of what this target looked like last time.

Every other engine in GreyIQ reasons about ONE moment. Recon maps the surface, the prover
probes it, the cortex weighs the evidence, the chain engine composes it — and then the run
ends and all of it is thrown away. ``operator.OperatorLoop`` re-runs whole campaigns on a
cadence, and each cycle rediscovers the world from scratch, so the engine cannot notice the
single highest-signal event in bug bounty: **something changed**.

A newly deployed endpoint, a JS bundle that grew an API route, an auth gate that came off
``/admin`` in a refactor, a security header that disappeared, a response that grew an
``is_admin`` key — these are staple human techniques (asset monitoring, JS-change alerting,
"be first on the new feature") and none of them existed here. Worse, the chain engine already
computes exactly what a temporal engine needs — which step a chain is BLOCKED on and which
capability is missing — and discards it at report time, so a chain blocked at step 2 on
``disclose.identifier`` in run N-1 is re-derived identically and re-blocked in run N, even
when run N's surface just started leaking object identifiers.

WHAT IT DOES
    1. Fingerprints each crawled URL's response SHAPE from a response recon already fetched.
    2. Diffs this run against the last snapshot for the same (program, host).
    3. Turns the deltas into ranked probe targets, so the fixed active budget is spent on what
       is NEW rather than on the same hot-word URLs every single run.
    4. Re-opens attack chains whose blocking capability a delta may have just unlocked.
    5. Flags proofs that may have gone stale because the endpoint under them moved.

ZERO NEW REQUESTS, structurally rather than by enforcement. Every observation is derived from
a response ``recon.discover`` already fetched and currently discards; this module makes no HTTP
request, so it has no method, no host and no URL of its own. The scope gate, the SSRF guard,
the per-host governor and the request budget are untouched by construction, and
denial-of-wallet is not merely capped but impossible.

HONESTY INVARIANTS (contract-tested in ``backend/test_surface_drift.py``)
------------------------------------------------------------------------
* **A DELTA IS NEVER A FINDING.** This module returns no finding dicts and sets no severity,
  class or ref. A hunt's reportable findings are byte-identical with drift present and absent.
* **A DELTA NEVER CONFIRMS ANYTHING.** It cannot reach the confirm gate, and it deliberately
  emits no chain-engine signal: a statement that something CHANGED is not a statement that
  anything is exploitable, and the chain layer's whole discipline is that steps rest on
  observations of the target's behaviour rather than on inferences about its history.
* **A RE-OPENED CHAIN IS A PROBE, NOT A CHAIN.** Re-opened rows carry ``status="untested"``
  and go to the probe queue. The prior run's confidence is never carried forward.
* **A MISSING BASELINE IS NOT A CLEAN BASELINE.** The first run for a (program, host) reports
  ``first-observation``, never "surface stable" or "no changes detected".
* **A DEGRADED BASELINE IS REFUSED, NOT DIFFED.** A prior run cut short by a WAF, an outage or
  an exhausted budget would otherwise make the NEXT run report a flood of "new" endpoints that
  always existed. Below half this run's coverage, the diff is declined outright.
* **ABSENCE IS NEVER EVIDENCE OF A FIX.** An endpoint that stopped answering, or that started
  returning 401, is recorded as an observation explicitly annotated as not a verified
  remediation. Nothing here closes a finding or advances a ledger stage.
* **A TRUNCATED FINGERPRINT IS NOT COMPARED.** The digest caps its key extraction, and the cap
  is hit in encounter order, so two runs over the same unchanged response can legitimately
  produce different key sets. A capped observation is stored but never diffed for shape.
* **SHAPES ARE NAMES, NEVER VALUES.** Only names, flag facts, status codes and a shape hash are
  stored; body length only as a magnitude bucket; every string is redacted.
* **DECAY IS MONOTONE.** A delta that persists unchanged never scores higher than the run it
  first appeared in, so the engine chases the new and stops re-shouting about an endpoint that
  appeared six runs ago and was already probed.
* **IDENTITY IS SCOPE-BOUND.** Snapshots are keyed by (program, host); a diff never compares
  across hosts or programs.

Pure stdlib, deterministic (no clock beyond a recorded timestamp, no model, no randomness),
bounded on every dimension, and total — every entry point degrades to an empty result rather
than raising, because this runs inside a hunt and must never cost one.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from bughunter.code_scanner.redaction import redact_text
from bughunter.learning import program_key

ALGORITHM_VERSION = "surface-drift-v1"

_STORE_NAME = "surface_snapshots.jsonl"
_SCHEMA_VERSION = 1
_LOCK = threading.Lock()  # serialize appends, mirroring hunt_trace/ledger write discipline

# Bounds — this runs inside a hunt, so every dimension is capped.
_MAX_OBSERVATIONS = 300
_MAX_DELTAS = 120
_MAX_SNAPSHOTS_PER_KEY = 8
_MAX_LINES_BEFORE_COMPACTION = 600
_MAX_NAMES_PER_DELTA = 12
_MAX_LIST = 300
_MAX_PROGRAM = 120

# A baseline that saw less than half of what this run saw is not a baseline: every URL it
# missed would surface as "new". Refuse rather than emit.
_BASELINE_MIN_RATIO = 0.5
# If most shared URLs changed shape at once, that is a deploy, not a signal about any one of
# them. Collapse to a single row instead of reporting a hundred.
_REDEPLOY_RATIO = 0.6

# What each kind of change is worth chasing, before decay. Deliberately short: a delta that
# nobody would act on is noise wearing a score, and the engine's whole value is that its
# output changes what gets probed next.
_DELTA_WEIGHT: dict[str, int] = {
    "auth.removed": 95,           # a gate came off — the single highest-signal change there is
    "shape.changed": 70,          # the response grew fields it did not have
    "cookie.flag-lost": 60,       # a session cookie protection disappeared
    "js.bundle-changed": 55,      # a bundle changed AND its mined route/param set grew
    "header.security-removed": 55,
    "endpoint.new": 50,
    "param.new": 45,
    "form.new": 40,
    "auth.added": 20,             # not a fix — a reason to re-verify a proof that rests here
}

_DELTA_LABEL: dict[str, str] = {
    "auth.removed": "an endpoint that required authentication now answers without it",
    "shape.changed": "the response structure grew new field names",
    "cookie.flag-lost": "a session cookie lost a protection flag it previously had",
    "js.bundle-changed": "a script bundle changed and now exposes new routes or parameters",
    "header.security-removed": "a security header that was present is gone",
    "endpoint.new": "an endpoint that did not exist in the previous run",
    "param.new": "a parameter name that did not exist in the previous run",
    "form.new": "a form that did not exist in the previous run",
    "auth.added": "an endpoint that answered openly now requires authentication",
}

# Decay: a delta unchanged across runs loses value, so the engine chases the new rather than
# re-shouting about an endpoint that appeared six runs ago and has already been probed.
_DECAY_STEP = 0.15
_DECAY_FLOOR = 0.4
_EMIT_FLOOR = 20

# Which kinds of change can plausibly unblock which capability. This is the temporal half of
# the chain engine: a chain blocked on `disclose.identifier` for four runs becomes worth
# retrying the moment the JS bundle starts exposing an object-id route.
#
# Deliberately a MAY-unblock table, never a does: the output is a probe to run, not a step to
# report. Nothing here can mark anything proven.
_CAPABILITY_UNBLOCKERS: dict[str, frozenset[str]] = {
    "disclose.identifier": frozenset({"js.bundle-changed", "shape.changed", "endpoint.new"}),
    "identity.other-user": frozenset({"auth.removed", "cookie.flag-lost"}),
    "identity.admin": frozenset({"auth.removed", "shape.changed"}),
    "exec.browser-script": frozenset({"param.new", "form.new"}),
    "act.as-victim-session": frozenset({"cookie.flag-lost", "form.new"}),
    "read.session-token": frozenset({"cookie.flag-lost", "header.security-removed"}),
    "read.other-object": frozenset({"endpoint.new", "shape.changed", "auth.removed"}),
    "write.other-object": frozenset({"form.new", "auth.removed"}),
    "net.internal": frozenset({"param.new", "endpoint.new"}),
    "cred.service": frozenset({"js.bundle-changed"}),
    "read.server-file": frozenset({"param.new"}),
}

_SECURITY_HEADERS = (
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy",
)
_COOKIE_FLAGS = ("httponly", "secure", "samesite")
_AUTH_STATUSES = frozenset({401, 403})
_SCRIPT_RE = re.compile(r"\.(?:js|mjs|cjs)(?:$|\?)", re.IGNORECASE)


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------
def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _text(value: Any, limit: int = 300) -> str:
    return str(value or "").strip()[:limit]


def _redact(value: Any, limit: int = 300) -> str:
    """Every stored string passes the shared redactor. A URL can carry a magic-link token or an
    ``?access_token=`` in its query, and this store outlives the run that wrote it."""
    try:
        redacted, _ = redact_text(_text(value, limit))
        return str(redacted)[:limit]
    except Exception:  # noqa: BLE001 - a redaction failure must not cost the snapshot
        return ""


def _store_path(runtime_dir: str | Path) -> Path:
    return Path(runtime_dir) / _STORE_NAME


def _magnitude(length: Any) -> int:
    """Body length as a log2 bucket. The exact byte count of a page moves on every request on
    any real site (timestamps, nonces, ad ids), so storing it would make everything look
    changed; the magnitude only moves when the response genuinely got bigger or smaller."""
    try:
        size = int(length or 0)
    except (TypeError, ValueError):
        return 0
    return int(math.log2(size)) if size > 1 else 0


def canonical_url(url: str) -> str:
    """A URL's identity for diffing: scheme, host, PORT, path.

    The query is dropped — a session id or a cache-buster in it would make the same page look new
    on every run. The port is kept: two services on one host are two different surfaces, and
    collapsing them made an app on :8080 and an admin panel on :8443 diff against each other.
    """
    try:
        parsed = urlparse(_text(url, 600))
    except ValueError:
        return ""
    if not parsed.hostname:
        return ""
    try:
        port = parsed.port
    except ValueError:
        port = None
    authority = parsed.hostname.lower() + (f":{port}" if port else "")
    return f"{parsed.scheme.lower()}://{authority}{parsed.path or '/'}"


def _query_names(url: str) -> list[str]:
    try:
        return sorted({_text(name, 60) for name, _ in parse_qsl(urlparse(url).query) if name})
    except ValueError:
        return []


def _cookie_facts(cookies: Any) -> list[str]:
    """``name:flags`` for each cookie — names and flag letters only, never a value."""
    out: list[str] = []
    if not isinstance(cookies, (list, tuple)):
        return out
    for raw in list(cookies)[:40]:
        parts = str(raw or "").split(";")
        name = parts[0].split("=", 1)[0].strip()
        if not name:
            continue
        attrs = {p.partition("=")[0].strip().lower() for p in parts[1:]}
        flags = "".join(flag[0] for flag in _COOKIE_FLAGS if flag in attrs)
        out.append(f"{_redact(name, 80)}:{flags}")
    return sorted(set(out))


def _present_security_headers(headers: Any) -> list[str]:
    if not isinstance(headers, dict):
        return []
    lowered = {str(key).lower() for key in headers}
    return sorted(name for name in _SECURITY_HEADERS if name in lowered)


def observe(url: str, fetched: dict[str, Any] | None) -> dict[str, Any]:
    """Build one Observation from a response that was ALREADY fetched. Never raises.

    The shape fingerprint is the core of the engine, and hashing the body is the naive failure
    mode: it moves on every request on any real site, so every run would report that everything
    changed and the whole thing would be noise. It hashes the name-only STRUCTURE the response
    digest already extracts instead — JSON key names, form field names, the error family, the
    JWT algorithm, which security headers are present. A price change does not move the hash;
    a new ``is_admin`` key does.
    """
    try:
        if not isinstance(fetched, dict):
            return {}
        from bughunter import digest_builder

        canonical = canonical_url(fetched.get("final_url") or url)
        if not canonical:
            return {}
        status = int(fetched.get("status") or 0)
        # An observation describes a surface that EXISTS. Recon spends most of its request budget
        # on a constant list of well-known paths (`/swagger.json`, `/.well-known/…`), and on a
        # typical target every one of them 404s — so without this filter a snapshot was ~90%
        # identical not-found rows. That is not merely wasted space: those rows inflate the
        # observation count that the baseline-confidence gate divides by, so a run whose real
        # surface collapsed could still look well-covered. A 401/403 is kept deliberately — a
        # gated endpoint is real, and it coming ungated is the highest-signal change there is.
        if not (200 <= status < 400 or status in _AUTH_STATUSES):
            return {}
        digest = digest_builder.build_digest(fetched, url=fetched.get("final_url") or url)
        digest = digest if isinstance(digest, dict) else {}
        json_keys = [k for k in (digest.get("json_keys") or []) if isinstance(k, str)]
        form_fields = [f for f in (digest.get("form_fields") or []) if isinstance(f, str)]
        # The digest caps its key extraction and fills that cap in ENCOUNTER order, so two runs
        # over the same unchanged response can legitimately disagree about which 40 keys they
        # kept. A fingerprint built from a capped list is not comparable; record the fact and
        # let the diff decline to use it, rather than reporting a change nobody made.
        capped = (len(json_keys) >= digest_builder._MAX_JSON_KEYS
                  or len(form_fields) >= digest_builder._MAX_FORM_FIELDS)
        shape_source = {
            "json_keys": sorted({k.lower() for k in json_keys}),
            "form_fields": sorted({f.lower() for f in form_fields}),
            "error_family": _text(digest.get("error_family"), 40),
            "jwt_alg": _text((digest.get("jwt") or {}).get("alg")
                             if isinstance(digest.get("jwt"), dict) else "", 20),
            "sec_headers": _present_security_headers(fetched.get("headers")),
        }
        blob = json.dumps(shape_source, sort_keys=True, ensure_ascii=False)
        return {
            "u": _redact(canonical, 400),
            "st": status,
            "cl": _magnitude(len(str(fetched.get("body") or ""))),
            "bt": hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:16],
            "cap": bool(capped),
            "sh": shape_source["sec_headers"],
            "ck": _cookie_facts(fetched.get("cookies")),
            "pn": [_redact(name, 60) for name in _query_names(url)][:20],
            # The NAMES the fingerprint was built from, so a `shape.changed` delta can say WHICH
            # fields appeared instead of only that the hash moved. Names only, already redacted
            # by the digest, and capped.
            "kn": (shape_source["json_keys"] + shape_source["form_fields"])[:60],
        }
    except Exception:  # noqa: BLE001 - an observation is optional; a hunt is not
        return {}


# --------------------------------------------------------------------------------------
# Snapshot store
# --------------------------------------------------------------------------------------
def _snapshot_key(program: str | None, target: str, host: str) -> tuple[str, str]:
    return (program_key(program, target)[:_MAX_PROGRAM], _text(host, 200).lower())


def record_snapshot(
    runtime_dir: str | Path | None,
    *,
    program: str | None,
    target: str,
    host: str,
    observations: dict[str, Any] | None,
    surface: dict[str, Any] | None,
    chains: list[dict[str, Any]] | None = None,
    deltas: list[dict[str, Any]] | None = None,
    now: str | None = None,
) -> bool:
    """Append ONE snapshot line. Best-effort and fail-closed: any write error returns False and
    never raises, because a memory write must never break a hunt."""
    if runtime_dir is None:
        return False
    try:
        prog, hostname = _snapshot_key(program, target, host)
        if not hostname:
            return False
        rows = observations if isinstance(observations, dict) else {}
        surf = surface if isinstance(surface, dict) else {}
        record = {
            "v": _SCHEMA_VERSION,
            "ts": now or _now(),
            "program": prog,
            "host": hostname,
            "obs": dict(list(rows.items())[:_MAX_OBSERVATIONS]),
            "struct": _compact_struct(surf),
            # What the chain engine was BLOCKED on, so the next run can notice when a delta may
            # have unlocked it. Keyed by the chain's SHAPE, never its positional id: ids are
            # renumbered at every render, so they identify nothing across runs.
            "chains": _compact_chains(chains),
            # The deltas this run reported, kind+subject only. This is what makes decay work: a
            # change that has been sitting there for six runs has already been looked at, and
            # re-shouting about it at full volume is how a change feed stops being read.
            # Stored VERBATIM: _delta already redacted the subject, and redacting a second time
            # is what stopped _age from ever matching a delta to its previous run — so decay never
            # engaged and a change that appeared six runs ago kept shouting at full volume.
            "deltas": [{"kind": _text(d.get("kind"), 60), "subject": _text(d.get("subject"), 400)}
                       for d in (deltas or []) if isinstance(d, dict)][:_MAX_DELTAS],
        }
        line = json.dumps(record, default=str, ensure_ascii=False) + "\n"
        path = _store_path(runtime_dir)
        with _LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            existing = ""
            if path.exists():
                existing = path.read_text(encoding="utf-8", errors="replace")
                # A crash mid-append can leave a fragment with no trailing newline; terminate it
                # so it cannot concatenate with this record into one unparseable line.
                if existing and not existing.endswith("\n"):
                    line = "\n" + line
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            if existing.count("\n") + 1 > _MAX_LINES_BEFORE_COMPACTION:
                _compact(path)
        return True
    except Exception:  # noqa: BLE001 - fail-closed: a snapshot write must never break a hunt
        return False


def _compact_struct(surface: Any) -> dict[str, list[str]]:
    """The surface lists as they are BOTH stored and diffed.

    One function for both sides on purpose: when the writer redacted and the reader did not, every
    string the redactor touched compared unequal forever, so those endpoints were reported as new
    on every run and their decay never engaged.
    """
    surf = surface if isinstance(surface, dict) else {}
    return {
        "endpoints": [_redact(u, 400) for u in _as_list(surf.get("endpoints"))][:_MAX_LIST],
        "params": [_redact(v, 60) for v in _as_list(surf.get("params"))][:_MAX_LIST],
        "forms": sorted({_redact(f.get("action"), 300) for f in (surf.get("forms") or [])
                         if isinstance(f, dict) and f.get("action")})[:_MAX_LIST],
    }


def _as_list(value: Any) -> list[str]:
    return [str(item) for item in value if isinstance(item, (str, int))] if isinstance(value, list) else []


def chain_shape(chain: dict[str, Any]) -> str:
    """A chain's identity ACROSS RUNS: its impact plus its ordered technique ids.

    Not the rendered id. ``AC1``/``C1`` is a position in one report's sorted list and is
    reassigned on every render, so keying the re-open matcher on it would match whichever
    chain happened to rank first this time — which is worse than not matching at all.
    """
    steps = chain.get("steps") if isinstance(chain.get("steps"), list) else []
    ids = tuple(_text(step.get("technique_id"), 60) for step in steps if isinstance(step, dict))
    raw = f"{_text(chain.get('projected_impact') or chain.get('impact_label'), 120)}|{'>'.join(ids)}"
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


def _compact_chains(chains: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Persist only what a re-open decision needs: which chain, what it reaches, where it stuck,
    and which capability the stuck step was waiting for."""
    out: list[dict[str, Any]] = []
    for chain in (chains or [])[:16]:
        if not isinstance(chain, dict):
            continue
        steps = chain.get("steps") if isinstance(chain.get("steps"), list) else []
        blocking = next((s for s in steps if isinstance(s, dict) and not s.get("proven")), None)
        out.append({
            "shape": chain_shape(chain),
            "impact": _redact(chain.get("projected_impact") or chain.get("impact_label"), 200),
            "title": _redact(chain.get("title"), 240),
            "status": _text(chain.get("status"), 40),
            "blocking_step": int(chain.get("blocking_step") or 0),
            "blocking_title": _redact((blocking or {}).get("title"), 200),
            # The capability the blocked step would have granted — the thing a delta has to
            # plausibly unlock for the chain to be worth retrying.
            "needs": [_text(cap, 80) for cap in ((blocking or {}).get("grants_ids") or [])][:4],
            "refs": [_text(r, 40) for r in (chain.get("refs") or [])][:8],
        })
    return out


def load_snapshots(runtime_dir: str | Path | None, program: str | None, target: str,
                   host: str) -> list[dict[str, Any]]:
    """Every stored snapshot for one (program, host), oldest first. Tolerates a torn line."""
    if runtime_dir is None:
        return []
    try:
        path = _store_path(runtime_dir)
        if not path.exists():
            return []
        prog, hostname = _snapshot_key(program, target, host)
        rows: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue  # a torn final line must never poison the memory
            if isinstance(row, dict) and row.get("program") == prog and row.get("host") == hostname:
                rows.append(row)
        return rows[-_MAX_SNAPSHOTS_PER_KEY:]
    except Exception:  # noqa: BLE001
        return []


def _compact(path: Path) -> None:
    """Keep the most recent snapshots per key so the store cannot grow without bound."""
    try:
        buckets: dict[tuple[str, str], list[str]] = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict):
                continue
            buckets.setdefault((str(row.get("program")), str(row.get("host"))), []).append(line)
        kept: list[str] = []
        for key in sorted(buckets):
            kept.extend(buckets[key][-_MAX_SNAPSHOTS_PER_KEY:])
        path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    except Exception:  # noqa: BLE001 - compaction is housekeeping; never break on it
        pass


# --------------------------------------------------------------------------------------
# The diff
# --------------------------------------------------------------------------------------
def _delta(kind: str, subject: str, why: str, *, names: list[str] | None = None,
           frm: str = "", to: str = "") -> dict[str, Any]:
    return {"kind": kind, "subject": _redact(subject, 400), "why": _redact(why, 300),
            "names": [_redact(n, 60) for n in (names or [])][:_MAX_NAMES_PER_DELTA],
            "from": _text(frm, 80), "to": _text(to, 80),
            "base_score": _DELTA_WEIGHT.get(kind, 10)}


def _diff_observations(prior: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    shared = [url for url in current if url in prior]
    shape_changes: list[dict[str, Any]] = []
    control_losses: list[dict[str, Any]] = []
    for url in sorted(shared):
        was, now = prior[url], current[url]
        if not isinstance(was, dict) or not isinstance(now, dict):
            continue
        was_status, now_status = int(was.get("st") or 0), int(now.get("st") or 0)
        if was_status in _AUTH_STATUSES and now_status == 200:
            out.append(_delta("auth.removed", url,
                              "this endpoint required authentication in the previous run and now answers without it",
                              frm=str(was_status), to=str(now_status)))
        elif now_status in _AUTH_STATUSES and was_status == 200:
            out.append(_delta("auth.added", url,
                              "this endpoint answered openly in the previous run and now requires authentication "
                              "— an observation, NOT a verified remediation",
                              frm=str(was_status), to=str(now_status)))
        # A capped fingerprint is not comparable (see `observe`): the digest fills its key cap in
        # encounter order, so two runs over an unchanged response can disagree.
        if (was.get("bt") != now.get("bt") and not was.get("cap") and not now.get("cap")
                and was_status == now_status):
            added = [n for n in (now.get("kn") or []) if n not in set(was.get("kn") or [])]
            shape_changes.append(_delta(
                "shape.changed", url,
                "the response structure changed" + (f"; new field names: {', '.join(added[:6])}" if added else ""),
                names=added))
        lost_headers = [h for h in (was.get("sh") or []) if h not in set(now.get("sh") or [])]
        if lost_headers:
            control_losses.append(_delta(
                "header.security-removed", url,
                f"security header(s) present in the previous run are gone: {', '.join(lost_headers)}",
                names=lost_headers))
        was_flags = {c.split(":", 1)[0]: c.split(":", 1)[-1] for c in (was.get("ck") or []) if ":" in c}
        now_flags = {c.split(":", 1)[0]: c.split(":", 1)[-1] for c in (now.get("ck") or []) if ":" in c}
        for name, flags in was_flags.items():
            lost = [f for f in flags if f not in now_flags.get(name, "")]
            if name in now_flags and lost:
                out.append(_delta("cookie.flag-lost", url,
                                  f"cookie '{name}' lost protection flag(s) it previously set",
                                  names=[name], frm=flags, to=now_flags.get(name, "")))
    # A site-wide change is one fact about the site, not N facts about N endpoints. Emitting a row
    # per URL is how a change feed becomes unreadable: dropping one CSP header from a shared
    # middleware produced eighteen identical rows that crowded out the auth gate that came off.
    out.extend(_collapse(shape_changes, len(shared), "shape.changed",
                         "changed shape at once — this reads as a redeploy rather than a change "
                         "to any one endpoint"))
    out.extend(_collapse(control_losses, len(shared), "header.security-removed",
                         "lost the same security header(s) at once — this reads as one "
                         "middleware/config change rather than a change to any one endpoint"))
    return out


def _collapse(rows: list[dict[str, Any]], shared: int, kind: str, why: str) -> list[dict[str, Any]]:
    """Fold a site-wide change into a single row, or pass the rows through unchanged."""
    if not (shared and len(rows) >= max(3, int(shared * _REDEPLOY_RATIO))):
        return rows
    names = sorted({name for row in rows for name in row.get("names") or []})
    return [_delta(kind, f"{len(rows)} endpoint(s)", f"{len(rows)} of {shared} shared endpoints {why}",
                   names=names)]


def _diff_structure(prior: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for field, kind, noun, is_url in (("endpoints", "endpoint.new", "endpoint", True),
                                      ("params", "param.new", "parameter name", False),
                                      ("forms", "form.new", "form", True)):
        # URLs are compared canonically. Raw, a session id or cache-buster in the query makes the
        # same page look new on every single run — the fastest way to make the feed worthless.
        norm = (lambda v: canonical_url(v) or _text(v, 400)) if is_url else (lambda v: _text(v, 400))
        was = {norm(v) for v in _as_list(prior.get(field))}
        now = list(dict.fromkeys(norm(v) for v in _as_list(current.get(field))))
        for item in [i for i in now if i and i not in was][:_MAX_DELTAS]:
            out.append(_delta(kind, item, f"a {noun} that did not exist in the previous run"))
    return out


def _diff_bundles(prior: dict[str, Any], current: dict[str, Any],
                  prior_struct: dict[str, Any], current_struct: dict[str, Any]) -> list[dict[str, Any]]:
    """A changed script bundle only matters when the surface it yields GREW — a rebuilt bundle
    with the same routes is a release, not an opportunity."""
    new_endpoints = ({_text(v, 400) for v in _as_list(current_struct.get("endpoints"))}
                     - {_text(v, 400) for v in _as_list(prior_struct.get("endpoints"))})
    new_params = ({_text(v, 60) for v in _as_list(current_struct.get("params"))}
                  - {_text(v, 60) for v in _as_list(prior_struct.get("params"))})
    if not new_endpoints and not new_params:
        return []
    out: list[dict[str, Any]] = []
    for url in sorted(url for url in current if url in prior and _SCRIPT_RE.search(url)):
        if current[url].get("bt") == prior[url].get("bt"):
            continue
        out.append(_delta("js.bundle-changed", url,
                          "this script bundle changed and the mined route/parameter surface grew with it",
                          names=sorted(new_params)[:6] or sorted(new_endpoints)[:6]))
    return out


def _age(kind: str, subject: str, history: list[dict[str, Any]]) -> int:
    """How many consecutive prior snapshots already carried this delta."""
    runs = 0
    for snapshot in reversed(history):
        seen = snapshot.get("deltas") if isinstance(snapshot.get("deltas"), list) else []
        if any(isinstance(d, dict) and d.get("kind") == kind and d.get("subject") == subject
               for d in seen):
            runs += 1
        else:
            break
    return runs


def build_drift(
    runtime_dir: str | Path | None,
    *,
    program: str | None,
    target: str,
    host: str,
    observations: dict[str, Any] | None,
    surface: dict[str, Any] | None,
) -> dict[str, Any]:
    """Diff this run's surface against the last snapshot for the same (program, host).

    Returns ``{algorithm, status, deltas, summary}``. Total: any internal error degrades to an
    empty, explicitly-labelled result rather than breaking the hunt.
    """
    empty = {"algorithm": ALGORITHM_VERSION, "status": "unavailable", "deltas": [],
             "summary": {}, "baseline_ts": ""}
    try:
        current = {k: v for k, v in (observations or {}).items() if isinstance(v, dict)}
        surf = surface if isinstance(surface, dict) else {}
        history = load_snapshots(runtime_dir, program, target, host)
        if not history:
            # A first run is not a clean run. Saying "no changes detected" here would be a claim
            # about a comparison that never happened.
            return {**empty, "status": "first-observation",
                    "summary": {"note": "no previous snapshot for this host yet — "
                                        "this run becomes the baseline for the next one"}}
        prior = history[-1]
        prior_obs = prior.get("obs") if isinstance(prior.get("obs"), dict) else {}
        prior_struct = prior.get("struct") if isinstance(prior.get("struct"), dict) else {}
        if prior_obs and len(current) < len(prior_obs) * _BASELINE_MIN_RATIO:
            # The MIRROR of the guard below, and the more dangerous direction: when THIS run is the
            # degraded one (a WAF block, 429s, an exhausted budget), there are no shared URLs left
            # to compare, so every behavioural delta is structurally undetectable and the diff
            # returns zero — which the report would render as an all-clear. "We could not look"
            # must never read as "nothing changed".
            return {**empty, "status": "degraded-run", "baseline_ts": _text(prior.get("ts"), 40),
                    "summary": {"note": f"this run observed {len(current)} url(s) against "
                                        f"{len(prior_obs)} in the baseline — too thin to compare"}}
        if current and len(prior_obs) < len(current) * _BASELINE_MIN_RATIO:
            # A prior run cut short by a WAF, an outage or an exhausted budget would otherwise
            # make every URL it missed look new. Refuse the diff rather than flood the queue.
            return {**empty, "status": "low-confidence-baseline", "baseline_ts": _text(prior.get("ts"), 40),
                    "summary": {"note": f"the previous snapshot covered {len(prior_obs)} url(s) against "
                                        f"{len(current)} this run — too thin to diff against"}}

        # Built through the SAME normalization record_snapshot stores, because the diff compares
        # this against a stored snapshot. Comparing raw-current against redacted-prior meant any
        # endpoint whose string trips the redactor (a signed URL, a token in a path) never compared
        # equal and was reported as new on every single run, forever.
        current_struct = _compact_struct(surf)
        deltas = (_diff_observations(prior_obs, current)
                  + _diff_structure(prior_struct, current_struct)
                  + _diff_bundles(prior_obs, current, prior_struct, current_struct))

        scored: list[dict[str, Any]] = []
        for delta in deltas:
            age = _age(delta["kind"], delta["subject"], history)
            factor = max(_DECAY_FLOOR, 1.0 - _DECAY_STEP * age)
            score = int(delta["base_score"] * factor)
            if score < _EMIT_FLOOR:
                continue
            scored.append({**delta, "age_runs": age, "score": score,
                           "label": _DELTA_LABEL.get(delta["kind"], delta["kind"])})
        scored.sort(key=lambda row: (row["score"], row["kind"], row["subject"]), reverse=True)
        scored = scored[:_MAX_DELTAS]

        counts: dict[str, int] = {}
        for delta in scored:
            counts[delta["kind"]] = counts.get(delta["kind"], 0) + 1
        return {
            "algorithm": ALGORITHM_VERSION,
            "status": "compared",
            "baseline_ts": _text(prior.get("ts"), 40),
            "deltas": scored,
            "summary": {
                "runs_compared": len(history),
                "urls_now": len(current),
                "urls_before": len(prior_obs),
                "deltas": len(scored),
                "by_kind": counts,
                # How much of the shared surface moved at once. A high ratio means a redeploy,
                # and the operator should read the rest of this section with that in mind.
                "noise_ratio": round(
                    counts.get("shape.changed", 0) / max(1, len(set(current) & set(prior_obs))), 2),
            },
        }
    except Exception:  # noqa: BLE001 - drift is advisory; a hunt must still report
        return empty


# --------------------------------------------------------------------------------------
# Consumers
# --------------------------------------------------------------------------------------
def delta_targets(drift: dict[str, Any] | None, limit: int = 2) -> list[str]:
    """The changed URLs worth spending the active budget on, best first.

    This is the engine's payoff for the hunt loop: the fixed probe budget is otherwise spent on
    the same hot-word URLs every single run, regardless of which part of the app is new. Only
    URLs — the caller re-applies its own scope gate, and this module never introduces a host.
    """
    try:
        out: list[str] = []
        for delta in (drift or {}).get("deltas") or []:
            if not isinstance(delta, dict):
                continue
            url = _text(delta.get("subject"), 400)
            if not canonical_url(url) or url in out:
                continue
            out.append(url)
            if len(out) >= max(0, int(limit)):
                break
        return out
    except Exception:  # noqa: BLE001
        return []


def reopened_chains(drift: dict[str, Any] | None, runtime_dir: str | Path | None, *,
                    program: str | None, target: str, host: str) -> list[dict[str, Any]]:
    """Chains a previous run left blocked whose missing capability a delta MAY have unlocked.

    This is the whole point of giving the hunt a memory. ``build_attack_chains`` already computes
    which step a chain is blocked on and which capability that step would have granted, then
    throws it away at report time — so run N re-derives and re-blocks the identical chain even
    when run N's surface just started leaking exactly what it needed.

    Every row is a PROBE, never a chain: ``status`` is ``untested``, no confidence is carried
    forward from the run that built it, and nothing here can mark a step proven.
    """
    try:
        deltas = [d for d in (drift or {}).get("deltas") or [] if isinstance(d, dict)]
        if not deltas:
            return []
        kinds = {d["kind"] for d in deltas}
        history = load_snapshots(runtime_dir, program, target, host)
        if not history:
            return []
        # How long each chain shape has been blocked, and the most recent record of it.
        blocked_for: dict[str, int] = {}
        latest: dict[str, dict[str, Any]] = {}
        for snapshot in history:
            shapes = {row.get("shape") for row in (snapshot.get("chains") or [])
                      if isinstance(row, dict) and row.get("blocking_step")}
            for row in snapshot.get("chains") or []:
                if not isinstance(row, dict) or not row.get("blocking_step"):
                    continue
                latest[str(row.get("shape"))] = row
            for shape in list(blocked_for):
                if shape not in shapes:
                    blocked_for.pop(shape, None)
            for shape in shapes:
                blocked_for[str(shape)] = blocked_for.get(str(shape), 0) + 1

        out: list[dict[str, Any]] = []
        for shape, runs in sorted(blocked_for.items(), key=lambda kv: -kv[1]):
            row = latest.get(shape) or {}
            needs = [cap for cap in (row.get("needs") or []) if cap in _CAPABILITY_UNBLOCKERS]
            unlockers = {kind for cap in needs for kind in _CAPABILITY_UNBLOCKERS[cap]} & kinds
            if not unlockers:
                continue
            trigger = next((d for d in deltas if d["kind"] in unlockers), None)
            if trigger is None:
                continue
            out.append({
                "id": "",
                "title": _text(row.get("title"), 240),
                "impact": _text(row.get("impact"), 200),
                "hypothesis": (
                    f"This chain has been blocked at step {row.get('blocking_step')} "
                    f"({_text(row.get('blocking_title'), 160)}) for {runs} run(s), waiting on "
                    f"{', '.join(needs)}. This run's surface changed in a way that may supply it: "
                    f"{_text(trigger.get('label'), 200)} — {_text(trigger.get('subject'), 200)}."
                ),
                "next_action": (
                    f"Re-probe {_text(trigger.get('subject'), 300)} for the blocked step. "
                    "The change is an observation, not evidence: nothing about this chain is "
                    "proven until that step captures its own artifact."
                ),
                "blocked_runs": runs,
                "trigger_kind": _text(trigger.get("kind"), 60),
                "signals": [],
                "status": "untested",
            })
            if len(out) >= 6:
                break
        return out
    except Exception:  # noqa: BLE001
        return []


def stale_proof_probes(drift: dict[str, Any] | None,
                       chains: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Chains that were proven on an endpoint whose response has since moved.

    A proof is a statement about a response that existed when it was captured. When that
    endpoint's shape or auth state changes, the honest thing is to say the proof may be stale —
    not to keep carrying it, and not to withdraw it either.
    """
    try:
        moved = {canonical_url(_text(d.get("subject"), 400))
                 for d in (drift or {}).get("deltas") or []
                 if isinstance(d, dict) and d.get("kind") in {"shape.changed", "auth.added"}}
        moved -= {""}
        if not moved:
            return []
        out: list[dict[str, Any]] = []
        for chain in chains or []:
            if not isinstance(chain, dict) or chain.get("status") != "confirmed":
                continue
            # Match the ENDPOINT the step's evidence was captured against. The step's title is
            # human-readable prose ("SQL injection in the q parameter") and never contains a URL,
            # so testing a canonical URL against it was false for every normally-titled finding
            # and the whole feature could not fire.
            step_urls = {canonical_url(_text(step.get("evidence_location"), 400))
                         for step in (chain.get("steps") or []) if isinstance(step, dict)}
            hit = next((url for url in sorted(moved) if url in step_urls), "")
            if not hit:
                continue
            out.append({
                "chain": _text(chain.get("id"), 40),
                "title": _text(chain.get("title"), 240),
                "why": f"an endpoint this chain rests on changed since the proof was captured: {hit}",
                "next_action": "Replay the captured proof against the current response before submitting.",
            })
        return out[:6]
    except Exception:  # noqa: BLE001
        return []


def summary_lines(drift: dict[str, Any] | None) -> list[str]:
    """Operator-facing prose. Says what was compared, never asserts a clean bill of health."""
    result = drift if isinstance(drift, dict) else {}
    status = _text(result.get("status"), 40)
    if status == "first-observation":
        return ["No baseline for this host yet — this run becomes the baseline for the next one. "
                "Nothing has been compared, so nothing here says the surface is unchanged."]
    if status == "low-confidence-baseline":
        return ["The previous snapshot covered too little of this host to diff against "
                "(a truncated or blocked run). Refusing to report changes rather than "
                "reporting every missed URL as new."]
    if status == "degraded-run":
        return ["This run reached too little of the host to compare against the baseline "
                "(a blocked, rate-limited or truncated crawl). Nothing has been compared, so "
                "nothing here says the surface is unchanged."]
    if status != "compared":
        return []
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    deltas = result.get("deltas") or []
    if not deltas:
        return [f"Compared against the snapshot from {_text(result.get('baseline_ts'), 40)}: "
                f"no change worth chasing in the {summary.get('urls_now', 0)} url(s) observed."]
    lines = [f"Compared against the snapshot from {_text(result.get('baseline_ts'), 40)} "
             f"({summary.get('urls_before', 0)} url(s) then, {summary.get('urls_now', 0)} now): "
             f"{len(deltas)} change(s) worth chasing."]
    for delta in deltas[:6]:
        age = int(delta.get("age_runs") or 0)
        seen = f" (unchanged for {age} run(s))" if age else " (new this run)"
        lines.append(f"- {delta.get('label')}: {delta.get('subject')}{seen}")
    return lines
