"""Regression tests for QA/QC v18 credential-validation fixes (offline/deterministic).

Fixed finding:
  - validate_aws_key marked a LIVE AWS key "NOT live" on a 403 caused by clock skew
    (RequestTimeTooSkewed) or throttling, because the 403/401 branch keyed off the HTTP
    STATUS alone and ignored the STS <Code>. Only genuine invalid-credential codes should
    mark the key dead; skew/throttling/unknown codes are inconclusive (live=None).
"""
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

from bughunter import credential_validation  # noqa: E402

# A well-formed (but fake) AKIA pair: matches _AKID_RE and a >=40-char secret, so it passes the
# well-formedness gate and actually reaches the STS request/response handling.
_FAKE_AKID = "AKIA" + "A" * 16
_FAKE_SECRET = "s" * 40


def _sts_error_body(code: str) -> str:
    return (
        '<?xml version="1.0"?><ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
        f"<Error><Type>Sender</Type><Code>{code}</Code>"
        f"<Message>{code} message</Message></Error></ErrorResponse>"
    )


class _StubGetFull:
    """Replaces credential_validation._get_full with a canned (status, headers, body) response so
    the test never hits the network."""

    def __init__(self, status: int, body: str):
        self._status = status
        self._body = body

    def __call__(self, url, extra_headers=None):  # noqa: ANN001
        return self._status, {}, self._body


class AwsKeySkewInconclusiveTest(unittest.TestCase):
    def setUp(self):
        self._orig_get_full = credential_validation._get_full

    def tearDown(self):
        credential_validation._get_full = self._orig_get_full

    def _validate_with(self, status: int, body: str):
        credential_validation._get_full = _StubGetFull(status, body)
        return credential_validation.validate_aws_key(_FAKE_AKID, _FAKE_SECRET)

    def test_clock_skew_403_is_inconclusive_not_dead(self):
        # BEFORE the fix: a 403 unconditionally set live=False, so a genuinely live key on a
        # skewed host clock was reported dead. AFTER: RequestTimeTooSkewed -> live stays None.
        res = self._validate_with(403, _sts_error_body("RequestTimeTooSkewed"))
        self.assertIsNone(res["live"], "clock-skew 403 must NOT be marked dead")
        self.assertNotEqual(res["live"], False)
        self.assertIn("Inconclusive", res["detail"])

    def test_throttling_403_is_inconclusive_not_dead(self):
        res = self._validate_with(403, _sts_error_body("Throttling"))
        self.assertIsNone(res["live"])
        self.assertIn("Inconclusive", res["detail"])

    def test_signature_mismatch_403_is_dead(self):
        # A genuine invalid-credential code still marks the key dead (feature preserved).
        res = self._validate_with(403, _sts_error_body("SignatureDoesNotMatch"))
        self.assertIs(res["live"], False)
        self.assertIn("NOT live", res["detail"])

    def test_invalid_client_token_403_is_dead(self):
        res = self._validate_with(403, _sts_error_body("InvalidClientTokenId"))
        self.assertIs(res["live"], False)

    def test_live_200_still_live(self):
        body = "<GetCallerIdentityResponse><GetCallerIdentityResult>" \
               "<Arn>arn:aws:iam::123456789012:user/alice</Arn>" \
               "<Account>123456789012</Account>" \
               "</GetCallerIdentityResult></GetCallerIdentityResponse>"
        res = self._validate_with(200, body)
        self.assertIs(res["live"], True)


if __name__ == "__main__":
    unittest.main()
