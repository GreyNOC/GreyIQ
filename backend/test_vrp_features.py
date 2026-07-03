"""VRP (Vulnerability Reward Program) features: open Firebase data-store exposure, the Chrome
extension manifest analyzer, and the unrestricted-key note. Network is mocked; no real request runs.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import credential_validation as cv  # noqa: E402
from bughunter.bounty import _firebase_exposure_finding  # noqa: E402
from bughunter.code_scanner.rules.chrome_extension import RULES as CHROME_RULES  # noqa: E402

_KEY = "AIza" + "B" * 35


class FirebaseExposureTests(unittest.TestCase):
    def tearDown(self) -> None:
        import importlib
        importlib.reload(cv)

    def test_host_allowlist_covers_firebase_infra_only(self) -> None:
        self.assertTrue(cv._host_allowed("acme-prod.firebaseio.com"))
        self.assertTrue(cv._host_allowed("firestore.googleapis.com"))
        self.assertFalse(cv._host_allowed("evil.example.com"))
        self.assertFalse(cv._host_allowed("acme.firebaseio.com.evil.com"))

    def test_open_rtdb_detected_via_shallow_read(self) -> None:
        cv._get = lambda url: (200, '{"users":true,"config":true}') if "shallow=true" in url else (403, "{}")
        exps = cv.probe_firebase_exposure("acme-prod")
        self.assertEqual(len(exps), 1)
        self.assertEqual(exps[0]["service"], "Firebase Realtime Database")
        self.assertIn("users", exps[0]["evidence"])  # shallow read shows KEY NAMES only

    def test_locked_rtdb_yields_nothing(self) -> None:
        cv._get = lambda url: (401, '{"error":"Permission denied"}')
        self.assertEqual(cv.probe_firebase_exposure("acme-prod"), [])

    def test_bad_project_id_is_rejected(self) -> None:
        cv._get = lambda url: (200, '{"x":true}')
        self.assertEqual(cv.probe_firebase_exposure("../etc/passwd"), [])

    def test_exposure_finding_is_confirmed_cloud_exposure(self) -> None:
        f = _firebase_exposure_finding(
            {"service": "Firebase Realtime Database", "endpoint": "https://acme.firebaseio.com/.json",
             "severity": "high", "detail": "open", "evidence": "top-level keys: users"}, "acme")
        self.assertEqual(f["_active_proof"]["status"], "confirmed")
        self.assertEqual(f["_active_class_hint"], "cloud-exposure")
        self.assertEqual(f["rule_id"], "active.firebase-exposure")
        self.assertIn("control_result", f["_active_proof"])  # default-deny rules are the negative control

    def test_live_key_is_flagged_unrestricted(self) -> None:
        cv._get = lambda url: (200, '{"projectId":"acme-prod","authorizedDomains":["acme.com"]}')
        r = cv.validate_firebase_key(_KEY)
        self.assertIs(r["live"], True)
        self.assertTrue(r.get("unrestricted"))
        self.assertIn("UNRESTRICTED", r["detail"])


class ChromeExtensionManifestTests(unittest.TestCase):
    _RULE = CHROME_RULES[0]

    def _scan(self, manifest: dict) -> list:
        return list(self._RULE.scan(path="ext/manifest.json", text=json.dumps(manifest, indent=2)))

    def test_dangerous_manifest_is_flagged(self) -> None:
        findings = self._scan({
            "manifest_version": 3, "name": "x",
            "permissions": ["cookies", "debugger"], "host_permissions": ["<all_urls>"],
            "content_security_policy": {"extension_pages": "script-src 'self' 'unsafe-eval'"},
            "externally_connectable": {"matches": ["*://*/*"]},
        })
        ids = {f.rule_id for f in findings}
        self.assertIn("chrome.ext.broad-host-access", ids)
        self.assertIn("chrome.ext.csp-unsafe-eval", ids)
        self.assertIn("chrome.ext.externally-connectable-any", ids)
        self.assertIn("chrome.ext.dangerous-permission", ids)
        self.assertTrue(all(f.category == "chrome-extension" for f in findings))
        self.assertTrue(all(f.line_start >= 1 for f in findings))  # exact location

    def test_web_app_manifest_is_not_an_extension(self) -> None:
        # No manifest_version -> a PWA/web-app manifest.json, never flagged.
        self.assertEqual(self._scan({"name": "PWA", "start_url": "/", "permissions": ["notifications"]}), [])

    def test_tightly_scoped_extension_is_clean(self) -> None:
        self.assertEqual(self._scan({
            "manifest_version": 3, "name": "x", "permissions": ["storage"],
            "host_permissions": ["https://api.example.com/*"]}), [])

    def test_malformed_json_does_not_raise(self) -> None:
        self.assertEqual(list(self._RULE.scan(path="ext/manifest.json", text="{not json")), [])


if __name__ == "__main__":
    unittest.main()
