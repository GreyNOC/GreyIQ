"""Startup guard: the API must boot fast and degrade gracefully WITHOUT torch.

The packaged build deliberately omits PyTorch (it dominated the portable download +
first-launch unpack and the bug-hunting engine never uses it). These tests pin two
invariants in a clean subprocess:

  1. importing the API does NOT drag torch / pandas onto the boot path (so the frozen
     app answers /api/health seconds sooner), and
  2. when torch is absent (the frozen condition), the service still boots and reports
     the local model unavailable instead of crashing.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", code], cwd=str(BACKEND_DIR),
        capture_output=True, text=True, timeout=120,
    )


class BootWithoutTorchTests(unittest.TestCase):
    def test_import_does_not_load_torch_or_pandas_at_boot(self) -> None:
        code = (
            "import sys; sys.path.insert(0, '.')\n"
            "import greyiq_api\n"
            "print('torch', 'torch' in sys.modules)\n"
            "print('pandas', 'pandas' in sys.modules)\n"
        )
        proc = _run(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("torch False", proc.stdout)
        self.assertIn("pandas False", proc.stdout)

    def test_boots_and_degrades_when_torch_absent(self) -> None:
        # Block torch + the TinyGPT modules at import time, mimicking the frozen build.
        code = (
            "import sys, builtins, importlib.util as ilu; sys.path.insert(0, '.')\n"
            "_imp = builtins.__import__\n"
            "def _blocked(n, *a, **k):\n"
            "    if n in ('solin_core', 'training_runtime') or n.split('.')[0] == 'torch':\n"
            "        raise ModuleNotFoundError(\"No module named '%s'\" % n)\n"
            "    return _imp(n, *a, **k)\n"
            "builtins.__import__ = _blocked\n"
            "_find = ilu.find_spec\n"
            "ilu.find_spec = lambda n, *a, **k: None if n.split('.')[0]=='torch' else _find(n,*a,**k)\n"
            "import greyiq_api as g\n"
            "assert g._ensure_ml_runtime() is False\n"
            "assert g._ml_runtime_status()[0] is False\n"
            "st = g.runtime.status()\n"
            "assert st['local_model_available'] is False\n"
            "assert 'unavailable' in st['engine_error'].lower()\n"
            "print('DEGRADED_OK')\n"
        )
        proc = _run(code)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("DEGRADED_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
