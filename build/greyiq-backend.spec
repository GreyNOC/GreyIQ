# PyInstaller spec for the GreyIQ backend (onedir).
#
# Freezes backend/run_frozen.py into a self-contained backend the Electron shell
# launches when packaged. onedir (COLLECT) is used rather than onefile because it
# is far more reliable for a torch-heavy app and avoids slow per-launch unpacking.
#
# Invoke from the repo root:  pyinstaller build/greyiq-backend.spec
# Output:  dist/greyiq-backend/greyiq-backend.exe (+ supporting libraries)
import os
import sys

from PyInstaller.utils.hooks import collect_all, collect_dynamic_libs, collect_submodules

# SPECPATH is the directory containing this spec (i.e. <repo>/build), so the
# repo root is one level up.
ROOT = os.path.dirname(os.path.abspath(SPECPATH))  # noqa: F821 (SPECPATH injected)
BACKEND = os.path.join(ROOT, "backend")

datas = [
    (os.path.join(BACKEND, "seed"), "seed"),
    (os.path.join(ROOT, "public"), "public"),
]
binaries = []
# NOTE: the offline TinyGPT brain (solin_core / solin_typo / solin_bpe /
# training_runtime) is intentionally NOT bundled. It depends on PyTorch (~1.2 GB),
# which dominated the portable download + the ~200 s first-launch unpack while the
# bug-hunting engine and the Ollama/Claude brain never touch it. The backend imports
# that runtime lazily (greyiq_api._ensure_ml_runtime) and degrades to a clear
# "local model unavailable" message when it is absent — so the shipped app is a lean
# bug-bounty tool. Re-add the modules here + torch to the collect_all list below to
# restore the in-binary local model.
hiddenimports = [
    "document_ingest",
    "ai_core.core_store",
    "coder",
    "agent",
    "skills",
    "repomap",
    "workspace",
    "_version",
    "gn_cli",  # run_frozen imports it at function level (CLI dispatch) — force-include
]

# The ASGI stack + clients load a lot dynamically; pull everything in. numpy stays
# (document_ingest's pandas path uses it). anthropic is the Claude coding-brain client.
for package in ("numpy", "anthropic", "uvicorn", "pydantic", "pydantic_core", "pypdf"):
    pkg_datas, pkg_binaries, pkg_hidden = collect_all(package)
    datas += pkg_datas
    binaries += pkg_binaries
    hiddenimports += pkg_hidden

hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("bughunter")

# pydantic_core ships a compiled extension (_pydantic_core). collect_all does not
# reliably place it for newer versions (pulled in by anthropic), which crashes the
# frozen backend with "No module named 'pydantic_core._pydantic_core'". Force it.
binaries += collect_dynamic_libs("pydantic_core")
hiddenimports += ["pydantic_core._pydantic_core"]

# --- Playwright: proof screenshots in a headless browser --------------------------
# Two halves must both be present for screenshots to work in the shipped app:
#   1) the Python package + its Node driver (playwright/driver: node + the JS driver),
#      pulled in by collect_all, and
#   2) the Chromium browser itself, which lives OUTSIDE the package in a per-user cache
#      that an end-user machine never populates (it never runs `playwright install`).
# We ship Chromium under <bundle>/playwright-browsers and screenshot_service points
# PLAYWRIGHT_BROWSERS_PATH at it at runtime. Degrades gracefully: if the browser cache is
# absent at freeze time (e.g. `playwright install chromium` was not run), the build still
# succeeds — screenshots are simply unavailable, exactly as before this change.
pw_datas, pw_binaries, pw_hidden = collect_all("playwright")
datas += pw_datas
binaries += pw_binaries
hiddenimports += pw_hidden


def _playwright_browsers_cache():
    explicit = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if explicit and os.path.isdir(explicit):
        return explicit
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        return os.path.join(os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local")), "ms-playwright")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Caches", "ms-playwright")
    return os.path.join(home, ".cache", "ms-playwright")


_pw_cache = _playwright_browsers_cache()
_pw_shipped = 0
if os.path.isdir(_pw_cache):
    for _entry in sorted(os.listdir(_pw_cache)):
        # Only the chromium builds (headless screenshotting) — never firefox/webkit, and
        # not ffmpeg/winldd (video/dep-check, unused). `launch(headless=True)` uses the full
        # chromium build; the headless-shell build is shipped too so an explicit shell channel
        # also works. Each folder carries its own INSTALLATION_COMPLETE marker, copied along,
        # so Playwright recognizes it offline.
        if _entry.startswith(("chromium-", "chromium_headless_shell-")):
            _src = os.path.join(_pw_cache, _entry)
            if os.path.isdir(_src):
                datas.append((_src, os.path.join("playwright-browsers", _entry)))
                _pw_shipped += 1
if _pw_shipped:
    print(f"[greyiq-backend.spec] bundling {_pw_shipped} Playwright chromium build(s) from {_pw_cache}")
else:
    print(f"[greyiq-backend.spec] WARNING: no Playwright chromium build in {_pw_cache}; screenshots will be "
          "unavailable in this build. Run `python -m playwright install chromium` before freezing to include it.")

block_cipher = None

a = Analysis(  # noqa: F821
    [os.path.join(BACKEND, "run_frozen.py")],
    pathex=[BACKEND],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Hard-exclude the PyTorch family so nothing drags it back in transitively — it is
    # the offline-model dependency we deliberately drop to keep the app lean/fast.
    excludes=["tkinter", "matplotlib", "pytest", "PyQt5", "PySide2",
              "torch", "torchvision", "torchaudio", "torchgen", "functorch"],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="greyiq-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="greyiq-backend",
)
