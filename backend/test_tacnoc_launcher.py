"""Static contracts for the GREYIQ-to-TACNOC desktop launcher."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "public" / "app.js").read_text(encoding="utf-8")
MAIN = (ROOT / "electron" / "main.cjs").read_text(encoding="utf-8")
PRELOAD = (ROOT / "electron" / "preload.cjs").read_text(encoding="utf-8")


class TacnocLauncherContractTests(unittest.TestCase):
    def test_tacnoc_is_a_first_class_desktop_option(self) -> None:
        self.assertIn('id="ckTacnoc"', HTML)
        self.assertIn('tacnoc: document.querySelector("#ckTacnoc")', JS)
        self.assertIn('ck.tacnoc?.addEventListener("click"', JS)
        self.assertIn('window.greyiqDesktop.launchTacnoc', JS)
        self.assertIn('Browser-only mode cannot launch desktop applications', JS)

    def test_command_selection_stays_out_of_the_renderer(self) -> None:
        self.assertIn("launchTacnoc: () => ipcRenderer.invoke('greyiq:launch-tacnoc')", PRELOAD)
        self.assertIn("ipcMain.handle('greyiq:launch-tacnoc'", MAIN)
        self.assertIn("function resolveTacnocCommand()", MAIN)
        self.assertIn("process.env.GREYIQ_TACNOC_PATH", MAIN)
        self.assertIn("spawn(command.exe, command.args", MAIN)
        self.assertIn("stdio: 'ignore'", MAIN)
        self.assertNotIn("launchTacnoc: (path", PRELOAD)


if __name__ == "__main__":
    unittest.main()
