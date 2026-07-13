"""Regression tests for the QA/QC v1.8 active-verify fixes.

Two defect classes are covered:

1. Crafted JWT header / JWKS / payload in an untrusted TARGET response makes json.loads
   raise RecursionError (a RuntimeError, NOT a ValueError subclass). Every json.loads over
   target-derived JWT bytes must catch it so a single crafted token cannot abort the whole
   active pass. Sites: _forge_alg_none_variants, _extract_jwt_token (call site at verify_active),
   _fetch_rsa_public_pems, _check_jwt_alg_confusion, _crack_jwt_hs_secret.

2. The open-redirect and host-header oracles must only CONFIRM when their negative control was
   actually observed — a failed control fetch must not count as a passing differential.

Offline/deterministic: no network, all http objects are in-process fakes.
"""
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from bughunter import active_verify_service as avs  # noqa: E402


def _nested_object_json(depth: int) -> str:
    """A syntactically valid but deeply-nested JSON object; json.loads(...) raises RecursionError."""
    return '{"a":' * depth + "1" + "}" * depth


def _recursion_bomb_token(depth: int = 40000) -> str:
    """A JWT-shaped token whose header base64url-decodes to deeply-nested JSON. The header encodes a
    JSON object so the whole token starts with 'eyJ' and matches _EMBEDDED_JWT_RE / _JWT_RE, and all
    three segments are non-empty so it reaches the json.loads in every JWT check."""
    header = avs._b64url_encode(_nested_object_json(depth).encode("utf-8"))
    payload = avs._b64url_encode(b'{"sub":"x"}')
    sig = avs._b64url_encode(b"sig-not-empty")
    return f"{header}.{payload}.{sig}"


class _FakeHttp:
    """Minimal stand-in for _Http: only .auth and .fetch are used by the checks under test."""

    def __init__(self, fetch_impl, auth=None):
        self.auth = auth
        self._fetch_impl = fetch_impl

    def fetch(self, url, *args, **kwargs):
        return self._fetch_impl(url, *args, **kwargs)


class JwtRecursionBombTests(unittest.TestCase):
    """A crafted deeply-nested JWT header must never crash a check with RecursionError."""

    def setUp(self):
        self.token = _recursion_bomb_token()
        # Guard the test itself: confirm the raw bomb really would raise RecursionError, so a
        # regression that stops catching it is genuinely re-exposed by these asserts.
        import json
        with self.assertRaises(RecursionError):
            json.loads(avs._b64url_decode(self.token.split(".")[0]))

    def test_forge_alg_none_variants_returns_empty_not_crash(self):
        # Before the fix this propagated RecursionError; now it is a clean skip -> [].
        self.assertEqual(avs._forge_alg_none_variants(self.token), [])

    def test_extract_jwt_token_from_bomb_body_returns_empty(self):
        # _extract_jwt_token is called OUTSIDE the per-check try/except in verify_active, so a
        # malformed landing body must not abort the pass. The bomb token matches _EMBEDDED_JWT_RE.
        self.assertRegex(self.token, avs._EMBEDDED_JWT_RE.pattern)
        landing = {"body": self.token}
        self.assertEqual(avs._extract_jwt_token(landing), "")

    def test_check_jwt_alg_confusion_bomb_token_returns_none(self):
        # discovered_token path (no operator auth): the header json.loads at the alg-confusion site
        # must swallow RecursionError. fetch must never be reached (parse happens first).
        def _no_fetch(url, *a, **k):
            raise AssertionError("fetch should not be reached after the header parse fails")

        http = _FakeHttp(_no_fetch, auth=None)
        self.assertIsNone(avs._check_jwt_alg_confusion(http, "https://target.example/", discovered_token=self.token))

    def test_crack_jwt_hs_secret_bomb_token_returns_none(self):
        # Offline HMAC-crack helper: the header json.loads must not crash on a crafted token.
        self.assertIsNone(avs._crack_jwt_hs_secret(self.token))

    def test_fetch_rsa_public_pems_bomb_jwks_returns_empty(self):
        # A deeply-nested /.well-known/jwks.json served by the target must not crash the JWKS parse.
        try:
            import cryptography  # noqa: F401
        except Exception:  # pragma: no cover - optional dep; JWKS path early-returns [] without it
            self.skipTest("cryptography not installed; JWKS parse is unreachable")
        bomb_jwks = _nested_object_json(40000)
        http = _FakeHttp(lambda url, *a, **k: {"body": bomb_jwks, "status": 200})
        self.assertEqual(avs._fetch_rsa_public_pems(http, "https://target.example/"), [])


class ControlFetchDifferentialTests(unittest.TestCase):
    """Open-redirect / host-header oracles must not confirm when their negative control fetch fails."""

    def test_open_redirect_does_not_confirm_when_control_fetch_fails(self):
        # Probe succeeds (Location -> the reserved marker host, i.e. an off-host redirect), but the
        # negative control fetch raises _ActiveError. Without the observed control we cannot prove
        # the target is attacker-supplied, so the oracle must NOT emit a confirmed finding.
        calls = {"n": 0}

        def _fetch(url, *a, **k):
            calls["n"] += 1
            if calls["n"] == 1:  # the probe with the marker origin
                return {"status": 302, "location": f"https://{avs._MARKER_HOST}/", "body": "", "headers": {}}
            raise avs._ActiveError("control fetch reset")  # every control fetch fails

        http = _FakeHttp(_fetch)
        result = avs._check_open_redirect(http, "https://target.example/go?next=x")
        self.assertIsNone(result)

    def test_open_redirect_still_confirms_with_clean_control(self):
        # Sanity: when the control IS observed and lacks the marker, the confirmed finding still fires
        # (the fix must not break the intended offensive detection).
        def _fetch(url, *a, **k):
            if avs._MARKER_ORIGIN in url or "greyiq-marker" in url:
                return {"status": 302, "location": f"https://{avs._MARKER_HOST}/", "body": "", "headers": {}}
            # control ('/greyiq-control') -> a same-origin redirect, no marker host
            return {"status": 302, "location": "https://target.example/home", "body": "", "headers": {}}

        http = _FakeHttp(_fetch)
        result = avs._check_open_redirect(http, "https://target.example/go?next=x")
        self.assertIsNotNone(result)
        self.assertEqual(result["_active_proof"]["status"], "confirmed")

    def test_host_header_does_not_confirm_when_control_fetch_fails(self):
        # The marker is reflected into the Location header (would be a confirmed host-header injection),
        # but the control (real Host) fetch fails. Without observing the control we cannot rule out the
        # marker already being present under the real Host, so the oracle must bail (return None).
        def _fetch(url, *a, **k):
            headers = k.get("extra_headers") or {}
            if avs._MARKER_HOST in (headers.get("Host") or "") or avs._MARKER_HOST in (headers.get("X-Forwarded-Host") or ""):
                return {"status": 200, "location": f"https://{avs._MARKER_HOST}/reset", "body": "", "headers": {}}
            raise avs._ActiveError("control fetch reset")  # the real-Host control fetch fails

        http = _FakeHttp(_fetch)
        self.assertIsNone(avs._check_host_header(http, "https://target.example/"))

    def test_host_header_confirms_with_clean_control(self):
        # Sanity: with the control observed and marker-free, the confirmed finding still fires.
        def _fetch(url, *a, **k):
            headers = k.get("extra_headers") or {}
            if avs._MARKER_HOST in (headers.get("Host") or "") or avs._MARKER_HOST in (headers.get("X-Forwarded-Host") or ""):
                return {"status": 200, "location": f"https://{avs._MARKER_HOST}/reset", "body": "", "headers": {}}
            return {"status": 200, "location": "https://target.example/reset", "body": "", "headers": {}}

        http = _FakeHttp(_fetch)
        result = avs._check_host_header(http, "https://target.example/")
        self.assertIsNotNone(result)
        self.assertEqual(result["_active_proof"]["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
