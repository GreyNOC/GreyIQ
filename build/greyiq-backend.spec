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
    (os.path.join(ROOT, "public"), "public"),
]
# Bundle the seed tree, but EXCLUDE the TinyGPT torch checkpoints (*.pt). torch is excluded
# from this build (see the excludes list below), so solin_core can never load them — shipping
# and first-launch-copying ~13.6 MB of *.pt is pure dead weight. Everything else under seed/
# (bounty playbooks, skills, corpora, configs) is kept. Walk the tree so each surviving file
# lands under the right seed/ subdir.
_SEED_SRC = os.path.join(BACKEND, "seed")
for _root, _dirs, _files in os.walk(_SEED_SRC):
    _rel = os.path.relpath(_root, _SEED_SRC)
    _dest = "seed" if _rel == os.curdir else os.path.join("seed", _rel)
    for _fn in _files:
        # HARD CONSTRAINT: no bundled model/weight/data file may use the ".pt" extension.
        # This skip is unconditional, so a ".pt" under seed/ is dropped SILENTLY and the
        # feature that reads it degrades in the shipped app while working perfectly in
        # dev. Ship learned weights as ".json" (or any non-.pt extension) instead.
        if _fn.lower().endswith(".pt"):
            continue
        datas.append((os.path.join(_root, _fn), _dest))
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
    "yaml",    # api_discovery_service parses YAML OpenAPI specs; import is guarded, force-include so it's bundled
]

# Optional offline modules added by later work. Each is imported at FUNCTION level (guarded
# by try/except), so PyInstaller's static analysis cannot see it and would leave it out of
# the bundle — the feature would then work in dev and silently degrade in the shipped exe.
# Force-include each ONLY if it exists, so this spec stays valid at every point in the
# rollout (before the module lands, after it lands, and if it is later dropped).
#
# gn_dash / gn_tui / gn_sysmon are the `gn dash` cockpit. gn_cli imports gn_dash INSIDE
# _cmd_dash (unguarded, like _cmd_fx does with gn_fx) so the renderer stays off every other
# verb's startup path — which is exactly the function-level import the analysis cannot see.
# Without these three names the verb parses in the frozen exe and then dies on the import,
# and no test can catch it: they are not _VERB_PLUGINS, so the loader's fail-closed skip
# (and the test that pins it) never sees them. Flat modules, so the isfile guard matches;
# a package under backend/gn_dash/ would not, which is why they are flat.
for _opt in ("edit_ops", "offline_repair", "edit_mine", "solin_domain",
             "gn_dash", "gn_tui", "gn_sysmon"):
    if os.path.isfile(os.path.join(BACKEND, _opt + ".py")):
        hiddenimports.append(_opt)

# --- gn CLI verb plugins -----------------------------------------------------------
# Every module in gn_cli._VERB_PLUGINS is loaded by NAME through importlib at
# parser-build time, and the loader is fail-closed: an ImportError silently DROPS that
# verb. A dropped verb does not error — `greyiq-backend.exe wardrive ...` simply falls
# through run_frozen's dispatch test and boots the API server instead, which reads as
# "the feature was never built".
#
# This bit us for real: `collect_submodules("bughunter")` below returns
# bughunter.wardrive.cli and bughunter.hunt_train at spec-eval time, yet neither reached
# the v2.6.0 bundle, so both new verbs vanished from the shipped exe while working
# perfectly from source. Never rely on a broad package sweep to carry a DYNAMIC entry
# point — name it.
#
# The list is PARSED from gn_cli.py's own `_VERB_PLUGINS` tuple (stdlib ast, no import,
# so the spec stays side-effect free) rather than duplicated here, because a hand-copied
# second list is exactly the drift that made CLI_COMMANDS wrong for seven verbs.
def _verb_plugin_modules():
    import ast

    try:
        with open(os.path.join(BACKEND, "gn_cli.py"), encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
    except (OSError, SyntaxError):
        return []
    for node in ast.walk(tree):
        # `_VERB_PLUGINS: tuple[str, ...] = (...)` is an AnnAssign, NOT an Assign — handle
        # both, or a type annotation silently turns this whole guard back into a no-op.
        if isinstance(node, ast.AnnAssign):
            targets = [node.target]
        elif isinstance(node, ast.Assign):
            targets = list(node.targets)
        else:
            continue
        if not any(getattr(t, "id", "") == "_VERB_PLUGINS" for t in targets):
            continue
        if node.value is None:
            return []
        try:
            names = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):
            return []
        return [str(n) for n in names if isinstance(n, str)]
    return []


for _plugin in _verb_plugin_modules():
    # Only if the module actually exists on disk — the tuple deliberately names modules
    # that may not have landed yet (the loader tolerates that, and so must this).
    _rel = os.path.join(BACKEND, *_plugin.split("."))
    if os.path.isfile(_rel + ".py") or os.path.isfile(os.path.join(_rel, "__init__.py")):
        hiddenimports.append(_plugin)
        print(f"[greyiq-backend.spec] force-including gn verb plugin: {_plugin}")

# The ASGI stack + clients load a lot dynamically; pull everything in. numpy stays
# (document_ingest's pandas path uses it). anthropic is the Claude coding-brain client.
for package in ("numpy", "anthropic", "uvicorn", "pydantic", "pydantic_core", "pypdf", "cryptography"):
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
# Ship ONLY the newest revision of each chromium family (never firefox/webkit, and not
# ffmpeg/winldd — video/dep-check, unused). A dev machine that has run `playwright install`
# across upgrades accumulates STALE revisions in the shared cache (e.g. chromium-1223 next to
# chromium-1228); bundling all of them doubles the payload and — with the per-exe signing
# electron-builder does — broke the portable packaging. CI runners are clean (one revision
# each), so this is a no-op there. `launch(headless=True)` uses the full chromium build; the
# headless-shell build is kept too so an explicit shell channel also works. Each folder carries
# its own INSTALLATION_COMPLETE marker (copied along) so Playwright recognizes it offline.
_pw_newest = {}  # family ("chromium" / "chromium_headless_shell") -> (revision:int, dir_name)
if os.path.isdir(_pw_cache):
    for _entry in os.listdir(_pw_cache):
        if not _entry.startswith(("chromium-", "chromium_headless_shell-")):
            continue
        if not os.path.isdir(os.path.join(_pw_cache, _entry)):
            continue
        _family, _, _rev = _entry.rpartition("-")
        try:
            _rev_n = int(_rev)
        except ValueError:
            continue
        if _family not in _pw_newest or _rev_n > _pw_newest[_family][0]:
            _pw_newest[_family] = (_rev_n, _entry)
for _rev_n, _entry in _pw_newest.values():
    datas.append((os.path.join(_pw_cache, _entry), os.path.join("playwright-browsers", _entry)))
_pw_shipped = len(_pw_newest)
if _pw_shipped:
    print(f"[greyiq-backend.spec] bundling {_pw_shipped} Playwright chromium build(s) from {_pw_cache}: "
          + ", ".join(sorted(e for _, e in _pw_newest.values())))
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
    excludes=["tkinter", "matplotlib", "pytest",
              # Qt bindings: Pillow's ImageQt references BOTH 6-series bindings, and
              # PyInstaller refuses to collect two Qt binding packages -- it aborts the
              # whole build. A clean CI runner has none installed so this never fired
              # there, but any dev machine carrying PyQt6+PySide6 could not freeze at
              # all, which matters because the local build is the ONLY path while
              # Actions is unavailable. GreyIQ itself never imports Qt.
              "PyQt5", "PySide2", "PyQt6", "PySide6", "shiboken6", "qtpy",
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
