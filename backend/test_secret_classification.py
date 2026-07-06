"""Strict secret classification — BugHunter must stop reporting public frontend API keys (Google/
Firebase AIza…, OAuth client ids, analytics ids, Firebase web config) as confirmed secrets / High
severity without proof. These lock in the four-way classification and the confirm-authority gate."""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import report, secret_classification as sc  # noqa: E402

_AIZA = "AIzaSyDEADBEEF00112233445566778899aabbccd"   # a well-formed AIza (4 + 35)
_GHP = "ghp_" + "a" * 36


def _f(**kw):
    base = {"category": "secret", "severity": "high"}
    base.update(kw)
    return base


# --- is_public_client_key -------------------------------------------------------------------------

def test_public_client_key_indicators():
    assert sc.is_public_client_key(_f(rule_id="secret.google-api-key", secret_value=_AIZA))
    assert sc.is_public_client_key(_f(rule_id="web.exposed.secret.google-api-key", snippet=f"apiKey:{_AIZA}"))
    assert sc.is_public_client_key(_f(rule_id="secret.generic-password-assignment",
                                      snippet="client_id: 12345-abcde.apps.googleusercontent.com"))
    assert sc.is_public_client_key(_f(rule_id="secret.generic-password-assignment", snippet="measurementId: G-ABC123XYZ"))
    assert sc.is_public_client_key(_f(rule_id="secret.generic-password-assignment",
                                      snippet='{"apiKey":"x","authDomain":"a.firebaseapp.com","projectId":"p"}'))
    # A real server token is never a public client key.
    assert not sc.is_public_client_key(_f(rule_id="secret.github-pat", secret_value=_GHP))


# --- classify_secret_finding (the core rules) -----------------------------------------------------

def test_aiza_in_source_without_proof_is_public_client_key():
    assert sc.classify_secret_finding(_f(rule_id="secret.google-api-key", secret_value=_AIZA)) == sc.PUBLIC_CLIENT_KEY


def test_live_firebase_key_is_public_client_key_NOT_confirmed():
    # THE core regression: a live AIza key (getProjectConfig 200) is EXPECTED public behaviour.
    f = _f(rule_id="secret.google-api-key", secret_value=_AIZA,
           _credential_proof={"checked": True, "live": True, "http_status": 200, "project_id": "p"})
    assert sc.classify_secret_finding(f) == sc.PUBLIC_CLIENT_KEY
    assert sc.has_confirmed_secret_proof(f) is False


def test_inconclusive_key_is_candidate_unverified():
    f = _f(rule_id="secret.google-api-key", secret_value=_AIZA,
           _credential_proof={"checked": True, "live": None, "http_status": 0})
    # a Google key stays public by shape even when inconclusive; a non-public inconclusive token is candidate
    assert sc.classify_secret_finding(f) == sc.PUBLIC_CLIENT_KEY
    gh = _f(rule_id="secret.github-pat", secret_value=_GHP,
            _credential_proof={"checked": True, "live": None, "http_status": 0})
    assert sc.classify_secret_finding(gh) == sc.CANDIDATE_UNVERIFIED


def test_regex_match_without_validation_is_candidate_unverified():
    assert sc.classify_secret_finding(_f(rule_id="secret.generic-password-assignment",
                                         secret_value="s3cr3tishvalue123")) == sc.CANDIDATE_UNVERIFIED


def test_live_validated_server_token_is_confirmed_secret():
    f = _f(rule_id="secret.github-pat", secret_value=_GHP,
           _credential_proof={"checked": True, "live": True, "http_status": 200, "principal": "octocat"})
    assert sc.classify_secret_finding(f) == sc.CONFIRMED_SECRET
    assert sc.has_confirmed_secret_proof(f) is True


def test_proven_active_artifact_is_confirmed_secret():
    # e.g. a Firebase open-store row (probe read it unauthenticated) — a real captured artifact.
    f = _f(rule_id="secret.google-api-key", secret_value=_AIZA, category="secret_exposed",
           _active_proof={"status": "confirmed"})
    assert sc.classify_secret_finding(f) == sc.CONFIRMED_SECRET


def test_dead_server_token_is_false_positive():
    f = _f(rule_id="secret.github-pat", secret_value=_GHP,
           _credential_proof={"checked": True, "live": False, "http_status": 401})
    assert sc.classify_secret_finding(f) == sc.FALSE_POSITIVE


def test_has_confirmed_secret_proof_never_from_none_or_false():
    for live in (None, False):
        assert sc.has_confirmed_secret_proof(_f(rule_id="secret.github-pat", secret_value=_GHP,
                                                _credential_proof={"checked": True, "live": live})) is False


# --- redaction ------------------------------------------------------------------------------------

def test_redact_secret_never_shows_full_value():
    out = sc.redact_secret(_AIZA)
    assert _AIZA not in out and out.startswith("AIza") and "REDACTED" in out


def test_redact_value_in_strips_key_even_if_pattern_misses():
    weird = "XKEY-" + "9" * 50  # not a known vendor pattern
    text = f"curl https://x?token={weird}"
    assert weird not in sc.redact_value_in(text, weird)


# --- apply_secret_classification (severity downgrade + evidence) ----------------------------------

def test_apply_downgrades_public_key_to_info_and_stamps_evidence():
    f = _f(rule_id="secret.google-api-key", secret_value=_AIZA, severity="high")
    sc.apply_secret_classification([f])
    assert f["severity"] == "info"
    assert f["secret_classification"] == sc.PUBLIC_CLIENT_KEY
    ev = f["secret_evidence"]
    assert ev["proof_present"] is False and ev["impact_proven"] is False
    assert ev["reportability"] == "informational_only"
    assert _AIZA not in ev["redacted_secret"]
    # every required evidence field is present
    for k in ("evidence_status", "secret_classification", "proof_required", "proof_present",
              "validation_method", "request_evidence", "response_evidence", "impact_proven",
              "impact_summary", "redacted_secret", "reportability"):
        assert k in ev


def test_apply_keeps_confirmed_secret_severity():
    f = _f(rule_id="secret.github-pat", secret_value=_GHP, severity="critical",
           _credential_proof={"checked": True, "live": True, "http_status": 200, "principal": "octocat"})
    sc.apply_secret_classification([f])
    assert f["severity"] == "critical" and f["secret_classification"] == sc.CONFIRMED_SECRET


# --- confirm-authority + severity gates in report.py ----------------------------------------------

def test_report_captured_artifact_gate():
    live_fire = _f(rule_id="secret.google-api-key", secret_value=_AIZA, secret_classification=sc.PUBLIC_CLIENT_KEY,
                   _credential_proof={"checked": True, "live": True, "http_status": 200, "project_id": "p"})
    live_gh = _f(rule_id="secret.github-pat", secret_value=_GHP, secret_classification=sc.CONFIRMED_SECRET,
                 _credential_proof={"checked": True, "live": True, "http_status": 200, "principal": "octocat"})
    assert report._has_captured_artifact(live_fire, None, "") is False   # public key never confirmed
    assert report._has_captured_artifact(live_gh, None, "") is True      # validated server token still confirmed


def test_report_severity_clamp_beats_cvss():
    f = _f(rule_id="secret.google-api-key", severity="info", secret_classification=sc.PUBLIC_CLIENT_KEY)
    assert report.resolve_severity(f, {"cvss": {"base_severity": "high"}}) == "info"
    g = _f(rule_id="secret.github-pat", severity="high", secret_classification=sc.CONFIRMED_SECRET)
    assert report.resolve_severity(g, {"cvss": {"base_severity": "high"}}) == "high"


def test_reportable_findings_drops_false_positive_secret():
    dead = _f(rule_id="secret.github-pat", secret_classification=sc.FALSE_POSITIVE)
    public = _f(rule_id="secret.google-api-key", secret_classification=sc.PUBLIC_CLIENT_KEY)
    kept = report._reportable_findings([dead, public])
    assert dead not in kept and public in kept   # dead dropped, public kept (shown as informational)


# --- QAQC regressions -----------------------------------------------------------------------------

def test_secret_artifacts_stay_confirmed_and_keep_severity():
    # A committed private key / SA JSON / .env / AWS secret key is a real exposed secret by its nature —
    # it must NOT be crushed to Low just because there's no live validator to hit.
    for rule, sev, val in [
        ("secret.private-key-pem", "critical", "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END"),
        ("secret.gcp-service-account", "critical", '{"type":"service_account","private_key":"-----BEGIN"}'),
        ("secret.aws-secret-access-key", "critical", "aws_secret_access_key=" + "b" * 40),
        ("secret.dotenv-committed", "high", "DB_PASSWORD=Str0ngR3alValue99Prod"),
    ]:
        f = _f(rule_id=rule, severity=sev, secret_value=val)
        sc.apply_secret_classification([f])
        assert f["secret_classification"] == sc.CONFIRMED_SECRET, rule
        assert f["severity"] == sev, rule   # severity preserved, not downgraded


def test_real_secret_next_to_firebase_config_is_not_public():
    # A genuine leaked token/private key sitting inside a Firebase/analytics config blob must NOT be
    # force-downgraded to Info as a "public client key".
    stripe = _f(rule_id="secret.generic-password-assignment", secret_value="sk_live_" + "A" * 24,
                snippet='{apiKey:"x",authDomain:"a.firebaseapp.com",stripe:"sk_live_..."}')
    assert not sc.is_public_client_key(stripe)


def test_apply_scrubs_raw_secret_and_token_from_finding():
    import json
    gh = "ghp_" + "a" * 36
    f = _f(rule_id="secret.github-pat", secret_value=gh,
           _credential_proof={"checked": True, "live": True, "http_status": 200, "principal": "octocat",
                              "poc": f"curl -H 'Authorization: Bearer {gh}' https://api.github.com/user",
                              "response_excerpt": '{"login":"octocat"}'})
    sc.apply_secret_classification([f])
    # the raw token must not survive anywhere in the serialized finding (JSON sidecar / ledger / submission)
    assert gh not in json.dumps(f)
    assert f["secret_value"] != gh and "REDACTED" in f["secret_value"]


def test_aws_example_documentation_key_is_false_positive():
    # The AWS docs placeholder key is not a real secret.
    f = _f(rule_id="secret.aws-access-key-id", secret_value="AKIAIOSFODNN7EXAMPLE")
    assert sc.classify_secret_finding(f) == sc.FALSE_POSITIVE


def test_class_id_secrets_is_recognized_even_without_rule_id():
    # A finding reconstructed from client fields (class_id set, no category, empty rule_id) must still be
    # classified — otherwise every strict-secret gate silently no-ops.
    f = _f(category=None, rule_id="", class_id="secrets", severity="high",
           secret_value=_AIZA, description="AIza browser key")
    sc.apply_secret_classification([f])
    assert f.get("secret_classification")  # classified, not skipped
    assert f["severity"] != "high"          # and downgraded (public/unverified, never High)


def test_forged_artifact_rule_without_value_is_not_confirmed():
    # A client can set rule_id='secret.private-key-pem' with no real PEM — the value guard must stop it
    # reaching confirmed_secret from the rule_id alone.
    assert sc.classify_secret_finding(_f(rule_id="secret.private-key-pem", class_id="secrets")) != sc.CONFIRMED_SECRET
    # ...but a REAL PEM body is confirmed.
    assert sc.classify_secret_finding(_f(rule_id="secret.private-key-pem",
                                         secret_value="-----BEGIN RSA PRIVATE KEY-----\nx\n-----END")) == sc.CONFIRMED_SECRET


def test_real_env_beside_public_id_stays_confirmed_not_public():
    # A genuine committed .env with a real value must win over a GA/OAuth id on an adjacent line.
    f = _f(rule_id="secret.dotenv-committed", secret_value="DB_PASSWORD=Str0ngRealValue",
           snippet="measurementId=G-ABC123\nDB_PASSWORD=Str0ngRealValue")
    assert sc.classify_secret_finding(f) == sc.CONFIRMED_SECRET


def test_scrub_covers_snippet_for_vendor_token_the_pattern_list_misses():
    import json
    gl = "glpat-" + "a" * 22
    f = _f(rule_id="secret.gitlab-pat", secret_value=gl, snippet=f'const t = "{gl}";',
           _credential_proof={"checked": True, "live": True, "http_status": 200, "principal": "user"})
    sc.apply_secret_classification([f])
    assert gl not in json.dumps(f)   # not in secret_value, snippet, or _credential_proof


def test_on_demand_report_classifies_public_key_not_high_confirmed():
    # The dashboard/ledger "View full report" path (build_finding_report) reconstructs a finding from
    # client fields — it must classify too, so a public Google/Firebase key can't re-inflate to
    # High/Confirmed/reportable there. Even a client-supplied observed+control "proof" can't confirm it.
    import greyiq_api as api
    rt = api.GreyIQRuntime.__new__(api.GreyIQRuntime)
    req = api.FindingReportRequest(
        title="Exposed Google API key", severity="high", class_id="secrets",
        rule_id="secret.google-api-key", location="https://tiktok.com/app.js",
        proof=api.ProofInput(status="confirmed", observed_result="getProjectConfig returned HTTP 200",
                             control_result="an invalid key returns HTTP 400"))
    res = api.GreyIQRuntime.build_finding_report(rt, req)
    assert res.get("ok") is True
    pkg = res["package"]
    # never High, never a confirmed-quality secret from a public key
    assert str(pkg.get("severity_rating", "")).lower() in ("none", "info", "low")
    body = pkg.get("vulnerability_information", "")
    assert "public_client_key" in body or "Informational only" in body
