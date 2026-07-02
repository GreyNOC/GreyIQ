"""Point Playwright at the Chromium bundled inside a frozen release build.

A packaged (PyInstaller-frozen) install runs on an end-user machine that has never run
``playwright install`` — there is no per-user ``ms-playwright`` cache, so Playwright would
look in the default location, find nothing, and every browser launch would fail. The release
build ships Chromium under ``<bundle>/playwright-browsers`` (see build/greyiq-backend.spec);
this sets ``PLAYWRIGHT_BROWSERS_PATH`` to it.

EVERY code path that launches a browser (proof screenshots AND the dynamic live-app scan)
must call :func:`ensure_bundled_browsers_path` before Playwright resolves a browser, or the
launch silently fails in the packaged app even though the correct browser IS bundled. It is a
no-op in a normal dev run (not frozen), when the bundled folder isn't present, or when the
operator already set the variable themselves — so it is safe to call unconditionally.
"""

from __future__ import annotations

import os
import sys


def ensure_bundled_browsers_path() -> None:
    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        return
    # PyInstaller sets sys._MEIPASS to the bundle's data root (the onedir ``_internal``
    # folder); fall back to the executable's own dir if only sys.frozen is set.
    base = getattr(sys, "_MEIPASS", "") or (os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else "")
    if not base:
        return
    bundled = os.path.join(base, "playwright-browsers")
    if os.path.isdir(bundled):
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = bundled
