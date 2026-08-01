"""Static security contracts for the Electron shell and its local system pages."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "electron" / "main.cjs").read_text(encoding="utf-8")


class ElectronSecurityContractTests(unittest.TestCase):
    def test_renderer_keeps_electron_privileges_isolated(self) -> None:
        self.assertIn("contextIsolation: true", MAIN)
        self.assertIn("nodeIntegration: false", MAIN)
        self.assertIn("sandbox: true", MAIN)
        self.assertIn("webSecurity: true", MAIN)
        self.assertIn("allowRunningInsecureContent: false", MAIN)
        self.assertIn("setWindowOpenHandler", MAIN)
        self.assertIn("will-navigate", MAIN)

    def test_local_fallback_pages_escape_dynamic_text_and_define_csp(self) -> None:
        self.assertIn("function escapeSystemPageHtml(value)", MAIN)
        for encoded in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
            self.assertIn(encoded, MAIN)
        self.assertIn('default-src \'none\'; style-src \'unsafe-inline\'; img-src data:', MAIN)
        self.assertIn("escapeSystemPageHtml(startupError", MAIN)
        self.assertIn("escapeSystemPageHtml(backendLogPath())", MAIN)

    def test_every_permission_is_denied_except_notifications(self) -> None:
        self.assertIn("setPermissionRequestHandler", MAIN)
        self.assertIn("callback(permission === 'notifications')", MAIN)

if __name__ == "__main__":
    unittest.main()
