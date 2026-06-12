"""Settings shim for the vendored code_scanner.

The upstream scanner read a single field from GN Slop's global settings:
``code_scan_base_path``. GreyIQ doesn't share that settings object, so this
shim supplies just that field.

- Empty (default): no path containment — matches the local CLI/Electron
  behavior the scanner expects when run on a developer's own machine.
- Set ``GREYIQ_CODE_SCAN_BASE_PATH`` to an absolute path to refuse any local
  scan target outside that root. Use this to lock the API down to a single
  workspace when GreyIQ is exposed beyond localhost.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerSettings:
    code_scan_base_path: str = ""


def get_settings() -> ScannerSettings:
    return ScannerSettings(
        code_scan_base_path=os.getenv("GREYIQ_CODE_SCAN_BASE_PATH", "").strip(),
    )
