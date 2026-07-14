"""Tests for BugHunter submission packaging + the hard-gated HackerOne submit."""
from __future__ import annotations

import base64
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import submission  # noqa: E402


def _ctx_and_finding(*, ref: str = "F1", severity: str = "high", cvss: dict | None = None) -> tuple[dict, dict]:
    finding = {
        "ref": ref,
        "title": "Reflected XSS in search",
        "severity": severity,
        "confidence": "high",
        "class_id": "xss",
        "class_name": "Cross-site scripting",
        "cwe": "CWE-79",
        "location": "https://app.example.com/search?q=",
        "rule_id": "web-xss-reflected",
    }
    plan = {"impact": "Run script in a victim session.", "steps": ["..."]}
    if cvss:
        plan["cvss"] = cvss
    ctx = {
        "tool": "GreyIQ BugHunter", "version": "9.9.9", "generated_at": "now",
        "target": "https://app.example.com", "scope": "*.example.com",
        "attack_plans": {ref: plan},
    }
    return ctx, finding


class BuildSubmissionTests(unittest.TestCase):
    def test_package_has_core_fields(self) -> None:
        ctx, finding = _ctx_and_finding()
        pkg = submission.build_submission(ctx, finding)
        self.assertIsNotNone(pkg)
        assert pkg is not None
        self.assertIn("Reflected XSS", pkg["title"])
        self.assertEqual(pkg["weakness"], "79")
        self.assertTrue(pkg["vulnerability_information"].strip())
        self.assertIn(pkg["severity_rating"], {"none", "low", "medium", "high", "critical"})

    def test_severity_rating_prefers_cvss(self) -> None:
        ctx, finding = _ctx_and_finding(severity="low", cvss={"base_severity": "Critical", "vector": "X", "base_score": 9.1})
        self.assertEqual(submission.severity_rating(finding, ctx["attack_plans"]["F1"]), "critical")

    def test_write_package_round_trip(self) -> None:
        ctx, finding = _ctx_and_finding()
        with tempfile.TemporaryDirectory() as tmp:
            written = submission.write_submission_package(ctx, finding, Path(tmp), "sub-01-xss")
            self.assertIsNotNone(written)
            assert written is not None
            self.assertTrue(Path(written["markdown_path"]).is_file())
            self.assertTrue(Path(written["json_path"]).is_file())


class WriteSubmissionPackageScreenshotTests(unittest.TestCase):
    """write_submission_package co-locates a proof screenshot next to the .md by
    BASENAME (report.py's _append_screenshot embeds `![](basename)`, so the copy
    must keep the source's name) -- never previously exercised."""

    def test_screenshot_is_copied_alongside_the_package(self) -> None:
        ctx, finding = _ctx_and_finding()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            shot_src = tmp_path / "src" / "01-f1.png"
            shot_src.parent.mkdir()
            shot_src.write_bytes(b"\x89PNG fake bytes")
            finding["screenshot_path"] = str(shot_src)
            out_dir = tmp_path / "out"
            out_dir.mkdir()
            written = submission.write_submission_package(ctx, finding, out_dir, "sub-01-xss")
            self.assertIsNotNone(written)
            copied = out_dir / "01-f1.png"
            self.assertTrue(copied.is_file())
            self.assertEqual(copied.read_bytes(), b"\x89PNG fake bytes")

    def test_missing_screenshot_file_is_skipped_without_error(self) -> None:
        ctx, finding = _ctx_and_finding()
        finding["screenshot_path"] = "/does/not/exist/ghost.png"
        with tempfile.TemporaryDirectory() as tmp:
            written = submission.write_submission_package(ctx, finding, Path(tmp), "sub-01-xss")
        self.assertIsNotNone(written)  # missing screenshot must not drop the whole package

    def test_screenshot_already_at_destination_is_not_recopied(self) -> None:
        # src.resolve() == (out_dir / src.name).resolve() -- the in-place guard must
        # skip the copy rather than erroring on copyfile(same, same).
        ctx, finding = _ctx_and_finding()
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            shot = out_dir / "01-f1.png"
            shot.write_bytes(b"already here")
            finding["screenshot_path"] = str(shot)
            written = submission.write_submission_package(ctx, finding, out_dir, "sub-01-xss")
            self.assertIsNotNone(written)
            self.assertEqual(shot.read_bytes(), b"already here")

    def test_copy_failure_is_swallowed_package_still_written(self) -> None:
        # Best-effort: a screenshot copy failure (e.g. a locked/unreadable source on a
        # concurrent capture) must not drop the .md/.json package that's already on disk.
        ctx, finding = _ctx_and_finding()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            shot_src = tmp_path / "src" / "01-f1.png"
            shot_src.parent.mkdir()
            shot_src.write_bytes(b"data")
            finding["screenshot_path"] = str(shot_src)
            out_dir = tmp_path / "out"
            out_dir.mkdir()
            with mock.patch.object(submission.shutil, "copyfile", side_effect=OSError("locked")):
                written = submission.write_submission_package(ctx, finding, out_dir, "sub-01-xss")
        self.assertIsNotNone(written)
        self.assertFalse((out_dir / "01-f1.png").exists())

    def test_basename_collision_silently_overwrites_the_existing_file(self) -> None:
        # PINS current (not necessarily desirable) behavior: write_submission_package
        # copies by basename, so a second finding whose screenshot happens to share a
        # basename with an already-copied screenshot (e.g. a stale file left over from a
        # prior run reusing the same out_dir/stem numbering) silently clobbers it --
        # no collision detection, no error, no rename. Documented here so a future change
        # can't silently make this worse (or better) without a test noticing.
        ctx1, finding1 = _ctx_and_finding(ref="F1")
        ctx2, finding2 = _ctx_and_finding(ref="F2")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "out"
            out_dir.mkdir()

            src1 = tmp_path / "run1" / "01-shot.png"
            src1.parent.mkdir()
            src1.write_bytes(b"finding-one-proof")
            finding1["screenshot_path"] = str(src1)
            submission.write_submission_package(ctx1, finding1, out_dir, "sub-01-xss")
            self.assertEqual((out_dir / "01-shot.png").read_bytes(), b"finding-one-proof")

            src2 = tmp_path / "run2" / "01-shot.png"  # same basename, different source/content
            src2.parent.mkdir()
            src2.write_bytes(b"finding-two-proof")
            finding2["screenshot_path"] = str(src2)
            submission.write_submission_package(ctx2, finding2, out_dir, "sub-02-xss")

            # finding 1's embedded screenshot now silently shows finding 2's proof.
            self.assertEqual((out_dir / "01-shot.png").read_bytes(), b"finding-two-proof")

    def test_non_reportable_finding_returns_none_without_touching_disk(self) -> None:
        ctx, finding = _ctx_and_finding()
        finding["rule_id"] = "secret.jwt"  # unconfirmed JWT credential -> body drops it
        del finding["location"]
        finding["jwt_exposure"] = {"replay_authenticated": False}
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            written = submission.write_submission_package(ctx, finding, out_dir, "sub-01-jwt")
            self.assertEqual(list(out_dir.iterdir()), [])
        self.assertIsNone(written)

    def test_write_failure_returns_none(self) -> None:
        ctx, finding = _ctx_and_finding()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(submission.fsutil, "write_text_safe", side_effect=OSError("disk full")):
                written = submission.write_submission_package(ctx, finding, Path(tmp), "sub-01-xss")
        self.assertIsNone(written)


class SubmitGateTests(unittest.TestCase):
    """The HackerOne submit must never fire without an explicit confirm, a
    confirmed proof, and real credentials — these never touch the network."""

    def _pkg(self, proof: str = "confirmed") -> dict:
        return {
            "title": "t", "vulnerability_information": "body", "impact": "i",
            "severity_rating": "high", "proof_status": proof,
        }

    def test_refuses_without_confirm(self) -> None:
        with self.assertRaises(submission.SubmissionError):
            submission.submit_to_hackerone(self._pkg(), team_handle="t", api_username="u", api_token="k", confirm=False)

    def test_refuses_unconfirmed_proof(self) -> None:
        with self.assertRaises(submission.SubmissionError):
            submission.submit_to_hackerone(self._pkg("candidate"), team_handle="t", api_username="u", api_token="k", confirm=True)

    def test_refuses_missing_credentials(self) -> None:
        with self.assertRaises(submission.SubmissionError):
            submission.submit_to_hackerone(self._pkg(), team_handle="", api_username="", api_token="", confirm=True)


class _FakeUrlopenResponse:
    """Mimics the subset of http.client.HTTPResponse that submit_to_hackerone reads:
    a context manager whose .read() returns bytes."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_FakeUrlopenResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class SubmitToHackeroneNetworkTests(unittest.TestCase):
    """Exercises the parts of submit_to_hackerone past the refusal gates: payload
    build, basic-auth header, report_id parsing, and HTTPError/URLError decoding.
    The real HackerOne API URL is hardcoded in the function, so urlopen is mocked
    rather than redirected to a local server."""

    def _pkg(self, **overrides: object) -> dict:
        pkg = {
            "title": "Reflected XSS", "vulnerability_information": "steps...",
            "impact": "session takeover", "severity_rating": "high", "proof_status": "confirmed",
        }
        pkg.update(overrides)
        return pkg

    def test_success_parses_report_id_and_builds_url(self) -> None:
        captured: dict[str, object] = {}

        def fake_urlopen(request, timeout=None):
            captured["request"] = request
            captured["timeout"] = timeout
            return _FakeUrlopenResponse(json.dumps({"data": {"id": "12345"}}).encode("utf-8"))

        with mock.patch.object(submission.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = submission.submit_to_hackerone(
                self._pkg(), team_handle="acme", api_username="bob", api_token="s3cret", confirm=True, timeout=7.0,
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["report_id"], "12345")
        self.assertEqual(result["url"], "https://hackerone.com/reports/12345")
        # v2: the routed-fields summary rides along; None when no weakness/asset was resolved.
        self.assertEqual(result["routed"], {"weakness_id": None, "structured_scope_id": None})
        self.assertNotIn("attachments", result)  # no attachments passed -> no upload attempted
        self.assertEqual(captured["timeout"], 7.0)

        request = captured["request"]
        self.assertEqual(request.full_url, "https://api.hackerone.com/v1/reports")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        expected_auth = "Basic " + base64.b64encode(b"bob:s3cret").decode()
        self.assertEqual(request.get_header("Authorization"), expected_auth)

        body = json.loads(request.data.decode("utf-8"))
        attrs = body["data"]["attributes"]
        self.assertEqual(attrs["team_handle"], "acme")
        self.assertEqual(attrs["title"], "Reflected XSS")
        self.assertEqual(attrs["vulnerability_information"], "steps...")
        self.assertEqual(attrs["impact"], "session takeover")
        self.assertEqual(attrs["severity_rating"], "high")

    def test_missing_impact_falls_back_to_default_text(self) -> None:
        def fake_urlopen(request, timeout=None):
            body = json.loads(request.data.decode("utf-8"))
            self.assertEqual(body["data"]["attributes"]["impact"], "See the report.")
            return _FakeUrlopenResponse(json.dumps({"data": {"id": "1"}}).encode("utf-8"))

        with mock.patch.object(submission.urllib.request, "urlopen", side_effect=fake_urlopen):
            submission.submit_to_hackerone(
                self._pkg(impact=""), team_handle="acme", api_username="bob", api_token="s3cret", confirm=True,
            )

    def test_missing_report_id_in_response_is_an_empty_string_and_url(self) -> None:
        def fake_urlopen(request, timeout=None):
            return _FakeUrlopenResponse(json.dumps({"data": {}}).encode("utf-8"))

        with mock.patch.object(submission.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = submission.submit_to_hackerone(
                self._pkg(), team_handle="acme", api_username="bob", api_token="s3cret", confirm=True,
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["report_id"], "")
        self.assertEqual(result["url"], "")

    def test_http_error_decodes_body_and_status_into_message(self) -> None:
        def fake_urlopen(request, timeout=None):
            raise urllib.error.HTTPError(
                "https://api.hackerone.com/v1/reports", 422, "Unprocessable Entity",
                hdrs=None, fp=io.BytesIO(b'{"errors":[{"detail":"title too short"}]}'),
            )

        with mock.patch.object(submission.urllib.request, "urlopen", side_effect=fake_urlopen):
            with self.assertRaises(submission.SubmissionError) as cm:
                submission.submit_to_hackerone(
                    self._pkg(), team_handle="acme", api_username="bob", api_token="s3cret", confirm=True,
                )
        self.assertIn("422", str(cm.exception))
        self.assertIn("title too short", str(cm.exception))

    def test_http_error_with_unreadable_body_falls_back_to_reason(self) -> None:
        def fake_urlopen(request, timeout=None):
            raise urllib.error.HTTPError(
                "https://api.hackerone.com/v1/reports", 500, "Internal Server Error", hdrs=None, fp=None,
            )

        with mock.patch.object(submission.urllib.request, "urlopen", side_effect=fake_urlopen):
            with self.assertRaises(submission.SubmissionError) as cm:
                submission.submit_to_hackerone(
                    self._pkg(), team_handle="acme", api_username="bob", api_token="s3cret", confirm=True,
                )
        self.assertIn("500", str(cm.exception))
        self.assertIn("Internal Server Error", str(cm.exception))

    def test_url_error_is_wrapped(self) -> None:
        def fake_urlopen(request, timeout=None):
            raise urllib.error.URLError("name resolution failed")

        with mock.patch.object(submission.urllib.request, "urlopen", side_effect=fake_urlopen):
            with self.assertRaises(submission.SubmissionError) as cm:
                submission.submit_to_hackerone(
                    self._pkg(), team_handle="acme", api_username="bob", api_token="s3cret", confirm=True,
                )
        self.assertIn("HackerOne submit failed", str(cm.exception))
        self.assertIn("name resolution failed", str(cm.exception))

    def test_os_error_is_wrapped(self) -> None:
        def fake_urlopen(request, timeout=None):
            raise OSError("connection reset")

        with mock.patch.object(submission.urllib.request, "urlopen", side_effect=fake_urlopen):
            with self.assertRaises(submission.SubmissionError):
                submission.submit_to_hackerone(
                    self._pkg(), team_handle="acme", api_username="bob", api_token="s3cret", confirm=True,
                )

    def test_value_error_on_malformed_json_response_is_wrapped(self) -> None:
        # A 200 OK with a non-JSON body (e.g. an upstream proxy error page) must not
        # propagate a raw json.JSONDecodeError -- it's caught by the (..., ValueError) branch.
        def fake_urlopen(request, timeout=None):
            return _FakeUrlopenResponse(b"not json at all")

        with mock.patch.object(submission.urllib.request, "urlopen", side_effect=fake_urlopen):
            with self.assertRaises(submission.SubmissionError) as cm:
                submission.submit_to_hackerone(
                    self._pkg(), team_handle="acme", api_username="bob", api_token="s3cret", confirm=True,
                )
        self.assertIn("HackerOne submit failed", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
