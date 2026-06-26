"""GreyIQ BugHunter — bug-bounty hunt orchestration.

Ties the deterministic scanners (code / web / live) together into a *bounty
hunt*: pick a target profile (+ optional vuln-class focus), run the right
scanner(s), classify and prioritize findings, ask the configured coding brain
(Claude / local Ollama) to write reproduction steps and attack plans, and emit a
Markdown report + JSON sidecar to a chosen folder.

Authorization: bug-bounty testing is authorized testing. A hunt refuses to run
unless the caller confirms the target is in scope (``authorized=True``). The
underlying scanners are static (source) or passive (one GET) and keep their own
SSRF / base-path guards — nothing here exploits a live target.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import coder
from bughunter import next_steps as next_steps_lib
from bughunter import report as report_lib
from bughunter import toolkit as toolkit_lib
from bughunter.live_scan_service import run_live_scan
from bughunter.scan_service import run_code_scan
from bughunter.web_scan_service import run_web_scan

# --- Vuln classes: how a finding category maps to a bounty bug class, plus the
# CWE/OWASP refs and a deterministic attack-plan template used when no brain is
# configured (the brain enriches these when it is). ---
VULN_CLASSES: dict[str, dict[str, Any]] = {
    "rce": {
        "name": "Remote code execution / command injection",
        "cwe": "CWE-78 / CWE-94",
        "owasp": "A03:2021 Injection",
        # Scanner emits these for shell-out / eval / backdoor / curl|sh / obfuscated code.
        "categories": {"injection", "supply-chain", "backdoor", "obfuscation"},
        "checklist": [
            "Trace each flagged sink back to a request parameter, header, or filename the attacker controls.",
            "Try a benign marker payload first (e.g. `;echo greyiq123`) and look for the marker in the response or logs.",
            "If input reaches a shell/eval, confirm with a time-based probe (e.g. `sleep 5`) before any real payload.",
        ],
    },
    "secrets": {
        "name": "Exposed secret / credential",
        "cwe": "CWE-200",
        "owasp": "A07:2021 Identification & Authentication Failures",
        "categories": {"secret", "secret_exposed"},
        "checklist": [
            "Confirm the secret is live (test against the matching service) — only in scope.",
            "Determine blast radius: what does this key access, and is it production?",
            "Check git history for the same secret if you have source access.",
        ],
    },
    "xss": {
        "name": "Cross-site scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "categories": {"client_sink"},
        "checklist": [
            "Map every place reflected/stored input reaches the DOM (the flagged sinks are starting points).",
            "Inject a unique marker (e.g. `gq<svg/onload=...>`) and confirm it executes, not just renders as text.",
            "Test both reflected (URL/query) and stored (saved fields) paths; note any CSP that blocks execution.",
        ],
    },
    "ssrf": {
        "name": "Server-side request forgery (SSRF)",
        "cwe": "CWE-918",
        "owasp": "A10:2021 SSRF",
        # The static scanner can't confirm SSRF (it's a request-flow bug) — this is a
        # manual-hunt class; the checklist below guides it.
        "categories": set(),
        "checklist": [
            "Find parameters that take a URL/host (webhooks, image/import-by-URL, PDF/render).",
            "Point one at a collaborator host you control and confirm the server connects out.",
            "If it connects, try internal targets in scope only (e.g. cloud metadata) to gauge impact.",
        ],
    },
    "access-control": {
        "name": "Broken access control / IDOR",
        "cwe": "CWE-639 / CWE-284",
        "owasp": "A01:2021 Broken Access Control",
        "categories": set(),
        "checklist": [
            "Enumerate object identifiers (ids, UUIDs, filenames) in requests.",
            "Replay a request as a second, lower-privileged account and swap the identifier.",
            "Test forced browsing to admin/internal endpoints and missing function-level checks.",
        ],
    },
    "auth": {
        "name": "Authentication / session weakness",
        "cwe": "CWE-287 / CWE-384",
        "owasp": "A07:2021 Identification & Authentication Failures",
        "categories": {"cookies"},
        "checklist": [
            "Check session cookie flags (Secure/HttpOnly/SameSite) and token entropy/expiry.",
            "Test for session fixation, missing rate-limiting on login, and password-reset token reuse.",
            "Confirm logout/refresh actually invalidates the session server-side.",
        ],
    },
    "sqli": {
        "name": "SQL injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "categories": set(),
        "checklist": [
            "Identify parameters that reach a query; a SQL error in the response (flagged as disclosure) is a strong lead.",
            "Probe with a single quote and a balanced pair; compare error vs. normal responses.",
            "Confirm with a boolean- or time-based test before any data extraction.",
        ],
    },
    "csrf": {
        "name": "Cross-site request forgery (CSRF)",
        "cwe": "CWE-352",
        "owasp": "A01:2021 Broken Access Control",
        "categories": set(),
        "checklist": [
            "List state-changing actions (email/password changes, invites, billing, admin updates).",
            "Confirm whether each request requires an unpredictable anti-CSRF token and a SameSite cookie posture.",
            "Build a minimal same-site/cross-site form or fetch proof that changes state for the victim account.",
        ],
    },
    "cors": {
        "name": "CORS / cross-origin trust misconfiguration",
        "cwe": "CWE-942",
        "owasp": "A05:2021 Security Misconfiguration",
        "categories": set(),
        "checklist": [
            "Check whether the API reflects arbitrary Origin values or trusts attacker-controlled subdomains.",
            "If credentials are allowed, prove a browser can read sensitive response data from an untrusted origin.",
            "Document the exact Origin, response headers, and data class exposed.",
        ],
    },
    "redirect": {
        "name": "Open redirect / unsafe forwarding",
        "cwe": "CWE-601",
        "owasp": "A01:2021 Broken Access Control",
        "categories": set(),
        "checklist": [
            "Find redirect parameters such as next, returnUrl, callback, continue, redirect_uri, or url.",
            "Confirm whether an absolute external URL is accepted after login, OAuth, password reset, or invite flows.",
            "Assess chainability with token leakage, phishing, OAuth allow-list bypass, or account takeover paths.",
        ],
    },
    "file-upload": {
        "name": "Unsafe file upload / file handling",
        "cwe": "CWE-434",
        "owasp": "A04:2021 Insecure Design",
        "categories": set(),
        "checklist": [
            "Identify upload, import, avatar, attachment, document-conversion, and archive-extraction flows.",
            "Test extension/MIME validation, storage location, executable handling, and direct object access.",
            "For archives, check path traversal and zip-bomb protections without causing resource exhaustion.",
        ],
    },
    "business-logic": {
        "name": "Business logic / workflow abuse",
        "cwe": "CWE-840",
        "owasp": "A04:2021 Insecure Design",
        "categories": set(),
        "checklist": [
            "Model the intended workflow and try skipping, repeating, or reordering each server-side step.",
            "Test negative quantities, duplicate coupons, race-sensitive actions, quota resets, and role transitions.",
            "Capture the before/after state that proves unauthorized value, privilege, or data movement.",
        ],
    },
    "supply-chain": {
        "name": "Supply-chain / dependency risk",
        "cwe": "CWE-1104 / CWE-1395",
        "owasp": "A06:2021 Vulnerable & Outdated Components",
        "categories": {"dependency", "ci"},
        "checklist": [
            "Confirm the vulnerable package, workflow, or artifact is reachable in the deployed build path.",
            "Map exploitability to the program's policy: vulnerable dependency, malicious install script, or CI secret exposure.",
            "Recommend the smallest upgrade, pin, checksum, or permission reduction that removes the path.",
        ],
    },
    # --- Modern high-value classes (manual-hunt: the static/passive scanners can't
    # confirm these, so they carry no scanner category and live in the checklist /
    # guided-next-steps guidance). ---
    "ssti": {
        "name": "Server-side template injection (SSTI)",
        "cwe": "CWE-1336 / CWE-94",
        "owasp": "A03:2021 Injection",
        "categories": set(),
        "checklist": [
            "Find input that reaches a server-side template (search, display names, profile fields, email/PDF/report generators).",
            "Send per-engine probes (`${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`) and look for `49` rendered back.",
            "Once the engine is identified, escalate within scope from expression evaluation toward file read or RCE — stop at proof.",
        ],
    },
    "xxe": {
        "name": "XML external entity (XXE)",
        "cwe": "CWE-611",
        "owasp": "A05:2021 Security Misconfiguration",
        "categories": set(),
        "checklist": [
            "Identify endpoints that parse XML (SOAP, SAML, SVG/DOCX/XLSX uploads, RSS, `application/xml` bodies).",
            "Submit a benign external entity pointing at a collaborator host and confirm the server fetches it (out-of-band).",
            "If entities resolve, test in-scope file read and internal SSRF reach; prefer OOB exfiltration when responses are blind.",
        ],
    },
    "nosqli": {
        "name": "NoSQL injection",
        "cwe": "CWE-943",
        "owasp": "A03:2021 Injection",
        "categories": set(),
        "checklist": [
            "Target JSON/query params reaching Mongo/Couch/Elastic-style backends (login, search, filters).",
            "Swap scalars for operator payloads (`{\"$ne\": null}`, `{\"$gt\": \"\"}`, `[$where]`) and compare to baseline.",
            "Confirm an auth bypass or changed result set, then prove the minimal real impact.",
        ],
    },
    "jwt": {
        "name": "JWT / token forgery & weakness",
        "cwe": "CWE-347 / CWE-345",
        "owasp": "A07:2021 Identification & Authentication Failures",
        "categories": set(),
        "checklist": [
            "Decode the token; check `alg`/`kid`/`iss`/`exp` and whether the signature is actually verified server-side.",
            "Test `alg:none`, RS/HS key confusion (sign with the public key as the HMAC secret), `kid` injection, and weak secrets.",
            "Prove a privilege change (swap `sub`/`role`/`scope`) only with a token the server accepts as valid.",
        ],
    },
    "graphql": {
        "name": "GraphQL abuse",
        "cwe": "CWE-639 / CWE-770",
        "owasp": "A01:2021 Broken Access Control",
        "categories": set(),
        "checklist": [
            "Try introspection; if enabled, map the full schema for hidden queries and mutations.",
            "Test field-level authorization (BOLA/BFLA) by reaching objects or mutations another role should not.",
            "Probe batching/aliasing for rate-limit bypass and query depth/complexity for DoS — measure, never exhaust.",
        ],
    },
    "prototype-pollution": {
        "name": "Prototype pollution",
        "cwe": "CWE-1321",
        "owasp": "A03:2021 Injection",
        "categories": set(),
        "checklist": [
            "Find merges of attacker JSON into objects (config merge, query parsing, `Object.assign` / lodash `merge`).",
            "Inject `__proto__` / `constructor.prototype` keys and confirm a polluted property on a fresh object.",
            "Chain to a real gadget in scope (XSS, auth bypass, Node RCE) — pollution alone is usually informational.",
        ],
    },
    "race-condition": {
        "name": "Race condition / TOCTOU",
        "cwe": "CWE-362 / CWE-367",
        "owasp": "A04:2021 Insecure Design",
        "categories": set(),
        "checklist": [
            "List single-use or limit-enforcing actions (coupon redeem, withdraw, vote, invite, 2FA verify).",
            "Fire concurrent requests (single-packet / last-byte sync) and check for double-spend or limit bypass.",
            "Capture the before/after state proving the invariant broke, and the request count it took.",
        ],
    },
    "request-smuggling": {
        "name": "HTTP request smuggling / desync",
        "cwe": "CWE-444",
        "owasp": "A06:2021 Vulnerable & Outdated Components",
        "categories": set(),
        "checklist": [
            "Identify a front-end/back-end chain (CDN, proxy, LB) and test CL.TE / TE.CL / TE.TE desync with timing probes.",
            "Use a self-contained desync (capture your own next request) to prove the split without affecting other users.",
            "Map impact (cache poisoning, request hijack, control bypass) and report the proof, not a weaponized chain.",
        ],
    },
    "subdomain-takeover": {
        "name": "Subdomain takeover / dangling DNS",
        "cwe": "CWE-350",
        "owasp": "A05:2021 Security Misconfiguration",
        "categories": set(),
        "checklist": [
            "Enumerate subdomains and resolve CNAMEs to third-party services (S3, GitHub Pages, Heroku, Azure, Fastly).",
            "Flag any pointing at an unclaimed/decommissioned resource returning a takeover fingerprint.",
            "Prove control by claiming the resource and serving a benign marker — never host real content.",
        ],
    },
    "cloud-exposure": {
        "name": "Exposed cloud storage / metadata",
        "cwe": "CWE-732 / CWE-668",
        "owasp": "A05:2021 Security Misconfiguration",
        "categories": set(),
        "checklist": [
            "Find referenced buckets/blobs (S3, GCS, Azure) in HTML/JS/configs and test public list/read/write.",
            "Where an SSRF exists, check reach to cloud metadata (169.254.169.254) for credentials — in scope only.",
            "Document the exact object/permission and the sensitive data class exposed.",
        ],
    },
}

# Categories that aren't a core bounty class get a readable label so every
# finding carries a class in the report.
_CATEGORY_LABELS: dict[str, dict[str, str]] = {
    "crypto": {"name": "Weak cryptography", "cwe": "CWE-327"},
    "dependency": {"name": "Vulnerable dependency", "cwe": "CWE-1104"},
    "network": {"name": "Insecure network / transport", "cwe": "CWE-295"},
    "ci": {"name": "Insecure CI/CD workflow", "cwe": "CWE-1395"},
    "headers": {"name": "Security hardening (headers)", "cwe": "CWE-693"},
    "mixed_content": {"name": "Mixed content", "cwe": "CWE-311"},
    "disclosure": {"name": "Information disclosure", "cwe": "CWE-200"},
}


def vuln_class_names() -> dict[str, str]:
    """{class_id: human name} across the core vuln classes + category labels. Used
    by the Pentest Toolkit UI to render friendly 'maps to' badges."""
    names = {cid: meta["name"] for cid, meta in VULN_CLASSES.items()}
    names.update({cid: meta["name"] for cid, meta in _CATEGORY_LABELS.items()})
    return names


# --- Profiles: a target type + which scanners run + which classes it emphasizes. ---
BOUNTY_PROFILES: dict[str, dict[str, Any]] = {
    "web-app": {
        "name": "Web application",
        "description": "Passive scan of a live web page/app: headers, cookies, mixed content, exposed secrets, client-side XSS sinks, disclosure. Optionally a dynamic (Playwright) pass.",
        "kinds": {"url"},
        "scanners": ["web"],
        "classes": ["xss", "auth", "ssrf", "secrets", "access-control", "csrf", "cors", "redirect", "file-upload", "business-logic", "ssti", "xxe", "nosqli", "jwt", "graphql", "prototype-pollution", "race-condition", "request-smuggling", "subdomain-takeover", "cloud-exposure"],
        "checklist": [
            "Spider the app for input points (forms, query params, JSON bodies, file uploads).",
            "Review CSP and CORS for gaps that enable XSS or cross-origin data theft.",
            "Review every state-changing flow for CSRF, IDOR, and workflow bypass potential.",
        ],
    },
    "api": {
        "name": "API endpoint",
        "description": "Passive review of an HTTP API endpoint: auth headers, disclosure, error leakage, transport hardening. Most API bugs need authenticated manual testing — the checklist guides it.",
        "kinds": {"url"},
        "scanners": ["web"],
        "classes": ["access-control", "auth", "ssrf", "sqli", "cors", "business-logic", "nosqli", "jwt", "graphql", "ssti", "xxe", "race-condition", "request-smuggling", "cloud-exposure"],
        "checklist": [
            "Diff responses across roles for the same object id (IDOR / BOLA).",
            "Fuzz content-type and HTTP verbs; check for verb tampering and mass assignment.",
            "Look for missing rate-limits and verbose error bodies.",
            "Test workflow invariants: idempotency, replay, quota, coupon, and state-machine transitions.",
        ],
    },
    "source-code": {
        "name": "Source-code audit",
        "description": "Static scan of a repo or folder for injection sinks, eval/exec, hardcoded secrets, weak crypto, vulnerable deps, risky CI, and backdoor patterns.",
        "kinds": {"path", "git"},
        "scanners": ["code"],
        "classes": ["rce", "secrets", "ssrf", "sqli", "supply-chain", "file-upload", "csrf", "ssti", "xxe", "nosqli", "jwt", "prototype-pollution"],
        "checklist": [
            "Grep for the framework's raw-query / template-render / deserialization APIs.",
            "Map untrusted input (request, env, file) to each flagged sink to confirm reachability.",
            "Trace package install hooks, CI permissions, and artifact download paths for build-time compromise.",
        ],
    },
    "secrets": {
        "name": "Secrets & credential exposure",
        "description": "Hunt for leaked credentials in source (static) or served pages (passive) — API keys, tokens, private keys.",
        "kinds": {"path", "git", "url"},
        "scanners": ["auto"],
        "classes": ["secrets", "supply-chain"],
        "checklist": [
            "Check JS bundles, source maps, and .env-style files served to the client.",
            "Validate any candidate secret against its service (in scope) before reporting.",
        ],
    },
    "full-sweep": {
        "name": "Full sweep",
        "description": "Run the right scanner for the target and report every class found — a broad first pass before you focus.",
        "kinds": {"path", "git", "url"},
        "scanners": ["auto"],
        "classes": list(VULN_CLASSES.keys()),
        "checklist": [
            "Use this as a map: pick the highest-severity class and switch to a focused hunt.",
        ],
    },
}

BOUNTY_SYSTEM_PROMPT = (
    "You are GreyIQ BugHunter, a security analyst preparing an AUTHORIZED bug-bounty report. "
    "You are given automated scan findings for an in-scope target. Your job is to prioritize them, "
    "write clear reproduction / proof-of-concept steps suitable for a bounty submission, assess impact, "
    "capture concrete proof of impact, and recommend a fix. Reproduction steps describe how to confirm the bug on the authorized target — "
    "they are for the report. Do NOT provide mass-exploitation tooling, malware, ways to attack systems "
    "you are not authorized to test, or techniques to evade detection. Stay strictly within the named scope. "
    "Respond with a single JSON object and nothing else."
)


def list_profiles() -> dict[str, Any]:
    """Profiles + classes for the UI to render selectors."""
    return {
        "ok": True,
        "profiles": [
            {
                "id": pid,
                "name": p["name"],
                "description": p["description"],
                "kinds": sorted(p["kinds"]),
                "classes": list(p.get("classes", [])),
            }
            for pid, p in BOUNTY_PROFILES.items()
        ],
        "classes": [{"id": cid, "name": c["name"]} for cid, c in VULN_CLASSES.items()],
    }


def _infer_kind(target: str) -> str:
    raw = target.strip()
    lowered = raw.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if lowered.endswith(".git") or "github.com/" in lowered or "gitlab.com/" in lowered or lowered.startswith(("git@", "ssh://")):
        return "git"
    if re.search(r"[\\/]", raw) or re.match(r"^[a-z]:", lowered) or raw in {".", "./"}:
        return "path"
    if " " not in raw and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:/.*)?$", lowered):
        return "url"
    return "unknown"


def _classify(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return (class_id, class_name, cwe, owasp) for a raw finding."""
    category = str(finding.get("category") or "").lower()
    for cid, meta in VULN_CLASSES.items():
        if category in meta["categories"]:
            return cid, meta["name"], meta["cwe"], meta.get("owasp", "")
    label = _CATEGORY_LABELS.get(category)
    if label:
        return category, label["name"], label["cwe"], ""
    return category or "other", (category or "Other").replace("_", " ").title(), "", ""


def _deterministic_attack_plan(finding: dict[str, Any], class_id: str) -> dict[str, Any]:
    where = finding.get("location") or finding.get("file_path") or "the affected location"
    meta = VULN_CLASSES.get(class_id)
    steps = [f"Locate the issue at `{where}` (rule `{finding.get('rule_id', '')}`)."]
    if meta:
        steps.extend(meta["checklist"])
    else:
        steps.append("Confirm the finding is reachable from untrusted input, then assess impact.")
    return {"steps": steps, "impact": "", "proof_of_impact": "", "poc": ""}


def _safe_slug(value: str, fallback: str = "target") -> str:
    cleaned = re.sub(r"^[a-z]+://", "", str(value or "").strip().lower())
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", cleaned).strip("-.")
    return (cleaned[:48] or fallback)


def _resolve_output_dir(output_dir: str | None, default_reports_dir: Path) -> Path:
    if output_dir and str(output_dir).strip():
        target = Path(str(output_dir).strip()).expanduser()
    else:
        target = Path(default_reports_dir)
    target.mkdir(parents=True, exist_ok=True)
    return target.resolve()


def _run_scanners(profile: dict[str, Any], kind: str, target: str, max_files: int, run_live: bool) -> tuple[list[dict[str, Any]], list[str], dict[str, Any], str, float]:
    """Run the profile's scanners for the inferred target kind. Returns
    (raw_findings, scanners_run, scan_meta, risk, score)."""
    scanners = profile["scanners"]
    if "auto" in scanners:
        scanners = ["code"] if kind in {"path", "git"} else ["web"]

    raw: list[dict[str, Any]] = []
    ran: list[str] = []
    meta: dict[str, Any] = {}
    risks: list[str] = []
    scores: list[float] = []

    for scanner in scanners:
        if scanner == "code":
            result = run_code_scan(target, "git_remote" if kind == "git" else "path", max_files=max_files)
        elif scanner == "web":
            result = run_web_scan(target)
        else:
            continue
        ran.append(scanner)
        if result.get("ok"):
            raw.extend(result.get("findings", []))
            risks.append(str(result.get("risk", "low")))
            scores.append(float(result.get("score") or 0.0))
            meta[scanner] = {
                key: result.get(key)
                for key in ("files_scanned", "status", "final_url", "finding_count", "elapsed_seconds")
                if result.get(key) is not None
            }
        else:
            meta[scanner] = {"error": result.get("error", "scan failed")}

    if run_live and kind == "url":
        live = run_live_scan(target)
        ran.append("live")
        if live.get("ok"):
            raw.extend(live.get("findings", []))
            risks.append(str(live.get("risk", "low")))
            scores.append(float(live.get("score") or 0.0))
            meta["live"] = {"finding_count": live.get("finding_count")}
        else:
            meta["live"] = {"error": live.get("error", "live scan unavailable (Playwright not installed?)")}

    rank = {"high": 3, "critical": 4, "moderate": 2, "low": 1, "clean": 0}
    overall_risk = max(risks, key=lambda r: rank.get(r, 0)) if risks else "low"
    overall_score = round(max(scores), 3) if scores else 0.0
    return raw, ran, meta, overall_risk, overall_score


def _ask_brain(coder_cfg: dict[str, Any], target: str, profile: dict[str, Any], vuln_class: dict[str, Any] | None, scope: str, findings: list[dict[str, Any]], playbook: str, recommended_tools: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Best-effort LLM enrichment. Returns a brain dict; on any failure the
    caller falls back to the deterministic report."""
    brain: dict[str, Any] = {"used": False, "provider": "", "model": "", "summary": "", "notes": "", "attack_plans": {}, "manual_tests": [], "next_steps": []}
    if not coder.coder_enabled(coder_cfg):
        return brain
    cfg = dict(coder.coder_config(coder_cfg))
    cfg["system_prompt"] = BOUNTY_SYSTEM_PROMPT
    compact = [
        {
            "ref": f.get("ref"),
            "severity": f.get("severity"),
            "class": f.get("class_name"),
            "title": f.get("title"),
            "location": f.get("location"),
            "snippet": str(f.get("snippet") or "")[:200],
        }
        for f in findings[:30]
    ]
    tool_hint = ""
    if recommended_tools:
        names = "; ".join(
            f"{t.get('name')} ({t.get('url')})" for t in recommended_tools[:10] if t.get("name")
        )
        if names:
            tool_hint = (
                "Relevant tooling you may name in the reproduction steps (reference only — "
                f"do not output exploit code or payloads): {names}\n\n"
            )
    prompt = (
        f"AUTHORIZED bug-bounty hunt.\nTarget: {target}\nProfile: {profile.get('name')}\n"
        f"Focus class: {vuln_class.get('name') if vuln_class else 'none (report all)'}\n"
        f"Scope/authorization notes: {scope or '(none provided)'}\n\n"
        f"Playbook guidance:\n{playbook[:2500]}\n\n"
        f"{tool_hint}"
        f"Automated findings (JSON):\n{json.dumps(compact, default=str)[:8000]}\n\n"
        "Return ONLY a JSON object:\n"
        '{"executive_summary": "2-4 sentences, most important issue first",\n'
        ' "attack_plans": [{"ref": "F1", "steps": ["..."], "poc": "short PoC outline", "impact": "...", '
        '"proof_of_impact": {"status": "confirmed|candidate|missing", "method": "authorized test used", '
        '"actor": "role/account used", "affected_asset": "data/action affected", '
        '"observed_result": "exact response/state proving impact", "control_result": "expected/negative-control result", '
        '"evidence": "safe concise proof, redacted", "limitations": "what is not yet proven"}}],\n'
        ' "manual_tests": ["lead the scanner cannot confirm, to try by hand in scope"],\n'
        ' "next_steps": ["the single most valuable thing to do next, target-specific, imperative — '
        'ordered most-valuable first"],\n'
        ' "notes": "optional extra analysis"}\n'
        "For next_steps, be specific to THIS target and these findings — name the endpoint/parameter/file and the "
        "concrete check, not generic advice. If there are no findings, still suggest concrete in-scope manual tests "
        "and next steps for the focus class."
    )
    try:
        result = coder.generate([{"role": "user", "content": prompt}], cfg)
    except coder.CoderError:
        return brain
    brain["used"] = True
    brain["provider"] = result.get("provider", "")
    brain["model"] = result.get("model", "")
    parsed = _parse_json_object(result.get("text", ""))
    if parsed is None:
        brain["notes"] = str(result.get("text", "")).strip()[:4000]
        return brain
    brain["summary"] = str(parsed.get("executive_summary") or "").strip()
    brain["notes"] = str(parsed.get("notes") or "").strip()
    brain["manual_tests"] = [str(t).strip() for t in (parsed.get("manual_tests") or []) if str(t).strip()][:12]
    brain["next_steps"] = [str(t).strip() for t in (parsed.get("next_steps") or []) if str(t).strip()][:8]
    for plan in parsed.get("attack_plans") or []:
        ref = str(plan.get("ref") or "").strip()
        if not ref:
            continue
        proof = plan.get("proof_of_impact") or plan.get("impact_proof") or ""
        if isinstance(proof, dict):
            proof_value: Any = {
                "status": str(proof.get("status") or proof.get("proof_status") or "").strip(),
                "method": str(proof.get("method") or proof.get("test_method") or "").strip(),
                "actor": str(proof.get("actor") or proof.get("role") or proof.get("account") or "").strip(),
                "affected_asset": str(proof.get("affected_asset") or proof.get("asset") or proof.get("data") or "").strip(),
                "observed_result": str(proof.get("observed_result") or proof.get("result") or "").strip(),
                "control_result": str(proof.get("control_result") or proof.get("negative_control") or "").strip(),
                "evidence": str(proof.get("evidence") or proof.get("summary") or proof.get("description") or "").strip(),
                "limitations": str(proof.get("limitations") or proof.get("scope_limitations") or proof.get("notes") or "").strip(),
            }
        else:
            proof_value = str(proof or "").strip()
        brain["attack_plans"][ref] = {
            "steps": [str(s).strip() for s in (plan.get("steps") or []) if str(s).strip()],
            "poc": str(plan.get("poc") or "").strip(),
            "impact": str(plan.get("impact") or "").strip(),
            "proof_of_impact": proof_value,
        }
    return brain


def _parse_json_object(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        obj = json.loads(text[start : end + 1])
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def run_bounty_hunt(
    target: str,
    profile_id: str,
    vuln_class: str | None,
    output_dir: str | None,
    scope: str,
    authorized: bool,
    coder_cfg: dict[str, Any] | None,
    *,
    default_reports_dir: Path,
    seed_dir: Path | None = None,
    runtime_dir: Path | None = None,
    version: str = "",
    run_live: bool = False,
    max_files: int = 5000,
    per_finding: bool = False,
) -> dict[str, Any]:
    """Run a bounty hunt end to end and write a Markdown + JSON report.

    Returns {ok, report_path, json_path, summary, risk, score, finding_count, ...}
    or {ok: False, error} on bad input (never raises to the API)."""
    clean_target = str(target or "").strip()
    if not clean_target:
        return {"ok": False, "error": "No target provided."}
    if not authorized:
        return {
            "ok": False,
            "error": "Confirm the target is in scope and you're authorized to test it before running a hunt.",
        }
    profile = BOUNTY_PROFILES.get(str(profile_id or "").strip())
    if profile is None:
        return {"ok": False, "error": f"Unknown profile '{profile_id}'. Choose one of: {', '.join(BOUNTY_PROFILES)}."}
    vuln_class_id = str(vuln_class).strip() if vuln_class else ""
    if vuln_class_id and vuln_class_id not in VULN_CLASSES:
        return {"ok": False, "error": f"Unknown focus class '{vuln_class_id}'. Choose one of: {', '.join(VULN_CLASSES)}, or leave it blank."}
    class_meta = VULN_CLASSES.get(vuln_class_id) if vuln_class_id else None
    class_obj = {"id": vuln_class_id, "name": class_meta["name"]} if class_meta else None

    kind = _infer_kind(clean_target)
    if kind == "unknown":
        return {"ok": False, "error": "Could not tell if the target is a URL or a path. Use a full http(s):// URL or a folder/repo path."}
    if kind not in profile["kinds"]:
        return {
            "ok": False,
            "error": f"The '{profile['name']}' profile expects {' or '.join(sorted(profile['kinds']))} targets, but that looks like a {kind}.",
        }
    if kind == "git" and not clean_target.lower().startswith("https://"):
        return {"ok": False, "error": "Point git hunts at a full https:// URL (e.g. https://github.com/org/repo). SSH/SCP git URLs aren't supported."}

    raw_findings, scanners_run, scan_meta, risk, score = _run_scanners(profile, kind, clean_target, max_files, run_live)
    # Surface scanner failures instead of letting a failed scan read as a clean
    # target (the worst failure mode for a bug-finding tool). If every scanner
    # failed, that's an error, not a clean result.
    scan_errors = [f"{name}: {m['error']}" for name, m in scan_meta.items() if isinstance(m, dict) and m.get("error")]
    scan_succeeded = any(isinstance(m, dict) and not m.get("error") for m in scan_meta.values())
    if scan_errors and not scan_succeeded:
        return {"ok": False, "error": "Scan could not run — " + "; ".join(scan_errors), "scan_errors": scan_errors}

    # Annotate + rank.
    annotated: list[dict[str, Any]] = []
    for finding in raw_findings:
        cid, cname, cwe, owasp = _classify(finding)
        annotated.append(
            {
                **finding,
                "location": str(finding.get("file_path") or ""),
                "line": finding.get("line_start"),
                "class_id": cid,
                "class_name": cname,
                "cwe": cwe,
                "owasp": owasp,
            }
        )
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    annotated.sort(key=lambda f: rank.get(str(f.get("severity")).lower(), 0), reverse=True)

    # Focus filter. A class-narrowed hunt shows ONLY matching findings — if none
    # match we render the no-findings/checklist path for that class (and note how
    # many other-class findings exist) rather than mislabeling unrelated findings
    # under the focus class.
    if vuln_class_id:
        primary = [f for f in annotated if f.get("class_id") == vuln_class_id]
    else:
        primary = annotated
    focus_unmatched = bool(vuln_class_id and not primary)
    other_findings_count = (len(annotated) - len(primary)) if vuln_class_id else 0
    display = primary

    for index, finding in enumerate(display, 1):
        finding["ref"] = f"F{index}"

    # Deterministic attack plans, then brain enrichment (brain wins per ref).
    attack_plans = {f["ref"]: _deterministic_attack_plan(f, f.get("class_id", "")) for f in display}

    playbook = _load_playbook(profile_id, seed_dir, runtime_dir)
    # Curated tools that fit this hunt: the profile's classes + the focus class +
    # whatever classes the scanners actually surfaced (most-relevant first).
    rec_class_ids = list(dict.fromkeys(
        list(profile.get("classes", []))
        + ([vuln_class_id] if vuln_class_id else [])
        + [str(f.get("class_id")) for f in display if f.get("class_id")]
    ))
    recommended_tools = toolkit_lib.recommended_tools(rec_class_ids, seed_dir, runtime_dir, limit=12)
    brain = _ask_brain(coder_cfg or {}, clean_target, profile, class_obj, scope, display, playbook, recommended_tools)
    for ref, plan in brain.get("attack_plans", {}).items():
        if ref in attack_plans and (plan.get("steps") or plan.get("poc")):
            attack_plans[ref] = {**attack_plans[ref], **{k: v for k, v in plan.items() if v}}

    # Manual checklist = profile + selected-class + brain ideas.
    checklist = list(profile.get("checklist", []))
    if class_meta:
        checklist = list(class_meta["checklist"]) + checklist
    checklist += [t for t in brain.get("manual_tests", []) if t not in checklist]

    methodology = (
        f"GreyIQ BugHunter ran the **{', '.join(scanners_run) or 'no'}** scanner(s) against a "
        f"{kind} target. Source scans are static; web scans are a single passive GET. Findings are "
        f"automated leads — confirm each within your authorized scope."
    )

    ctx = {
        "tool": "GreyIQ BugHunter",
        "version": version,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "target": clean_target,
        "kind": kind,
        "profile": {"id": profile_id, "name": profile["name"], "description": profile["description"]},
        "vuln_class": class_obj,
        "scope": scope,
        "authorized": bool(authorized),
        "scanners_run": scanners_run,
        "scan_meta": scan_meta,
        "risk": risk,
        "score": score,
        "findings": display,
        "attack_plans": attack_plans,
        "manual_checklist": checklist,
        "methodology": methodology,
        "brain": brain,
        "scan_errors": scan_errors,
        "focus_unmatched": focus_unmatched,
        "other_findings_count": other_findings_count,
        "recommended_tools": recommended_tools,
        "toolkit_source": toolkit_lib.load_catalog(seed_dir, runtime_dir).get("source", {}),
        "run_live_requested": bool(run_live and kind == "url"),
        "recommendation": "",
    }

    # Guided next steps: a deterministic, ordered operator action plan (brain leads
    # folded in), plus a coverage/gaps summary. Built from the finished context so
    # it reflects exactly what ran.
    ctx["next_steps"] = next_steps_lib.build_next_steps(ctx, brain.get("next_steps"))
    ctx["coverage"] = next_steps_lib.coverage_summary(ctx)

    markdown = report_lib.build_markdown(ctx)
    json_doc = report_lib.build_json(ctx)

    try:
        out_dir = _resolve_output_dir(output_dir, default_reports_dir)
    except OSError as exc:
        return {"ok": False, "error": f"Could not use the output folder: {exc}"}
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    stem = f"bounty-{_safe_slug(profile_id)}-{_safe_slug(clean_target)}-{stamp}"
    md_path = out_dir / f"{stem}.md"
    json_path = out_dir / f"{stem}.json"
    try:
        md_path.write_text(markdown, encoding="utf-8")
        json_path.write_text(json.dumps(json_doc, indent=2, default=str), encoding="utf-8")
    except OSError as exc:
        return {"ok": False, "error": f"Could not write the report: {exc}"}

    # Optional: one self-contained, submission-ready file per finding.
    per_finding_paths: list[str] = []
    if per_finding:
        for finding in display:
            fstem = f"{stem}-{finding.get('ref', 'F')}-{_safe_slug(finding.get('title', ''), 'finding')}"
            fpath = out_dir / f"{fstem}.md"
            try:
                fpath.write_text(report_lib.build_finding_markdown(ctx, finding), encoding="utf-8")
                per_finding_paths.append(str(fpath))
            except OSError:
                continue

    counts = report_lib.severity_counts(display)
    return {
        "ok": True,
        "report_path": str(md_path),
        "json_path": str(json_path),
        "per_finding_paths": per_finding_paths,
        "output_dir": str(out_dir),
        "target": clean_target,
        "profile": profile_id,
        "vuln_class": vuln_class_id or None,
        "risk": risk,
        "score": score,
        "finding_count": len(display),
        "severity_counts": counts,
        "scanners_run": scanners_run,
        "scan_errors": scan_errors,
        "used_brain": brain.get("used", False),
        "brain_model": f"{brain.get('provider')}:{brain.get('model')}" if brain.get("used") else "",
        "next_steps": ctx["next_steps"],
        "coverage": ctx["coverage"],
        "report_markdown": markdown,
    }


def _load_playbook(profile_id: str, seed_dir: Path | None, runtime_dir: Path | None) -> str:
    """Read the profile's .md playbook (runtime override wins over the bundled
    seed). Best-effort — returns '' if none is found."""
    name = f"{profile_id}.md"
    for base in (runtime_dir, seed_dir):
        if base is None:
            continue
        path = Path(base) / "bounty" / name
        try:
            if path.is_file():
                return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return ""
