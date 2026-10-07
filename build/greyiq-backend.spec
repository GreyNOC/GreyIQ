# PyInstaller spec for the GreyIQ backend (onedir).
#
# Freezes backend/run_frozen.py into a self-contained backend the Electron shell
# launches when packaged. onedir (COLLECT) is used rather than onefile because it
# is far more reliable for a large backend and avoids slow per-launch unpacking.
#
# Invoke from the repo root:  pyinstaller build/greyiq-backend.spec
# Output:  dist/greyiq-backend/greyiq-backend.exe (+ supporting libraries)
import importlib.util
import json
import os
import sys

from PyInstaller.utils.hooks import collect_all, collect_dynamic_libs, collect_submodules

# SPECPATH is the directory containing this spec (i.e. <repo>/build), so the
# repo root is one level up.
ROOT = os.path.dirname(os.path.abspath(SPECPATH))  # noqa: F821 (SPECPATH injected)
BACKEND = os.path.join(ROOT, "backend")
BUNDLE_TINYGPT = os.environ.get("GREYIQ_BUNDLE_TINYGPT", "0") == "1"

datas = [
    (os.path.join(ROOT, "public"), "public"),
]
# Keep the ordinary release lean. The opt-in local TinyGPT build also carries the seed
# checkpoint so a fresh install can load its model before any operator training.
_SEED_SRC = os.path.join(BACKEND, "seed")
for _root, _dirs, _files in os.walk(_SEED_SRC):
    _rel = os.path.relpath(_root, _SEED_SRC)
    _dest = "seed" if _rel == os.curdir else os.path.join("seed", _rel)
    for _fn in _files:
        if _fn.lower().endswith(".pt") and not BUNDLE_TINYGPT:
            continue
        datas.append((os.path.join(_root, _fn), _dest))
binaries = []
# The ordinary build omits the PyTorch-backed TinyGPT runtime. A local build may
# opt in with GREYIQ_BUNDLE_TINYGPT=1; CI release builds leave it unset.
hiddenimports = [
    "document_ingest",
    "ai_core.core_store",
    "coder",
    "hf_gguf_import",
    "agent",
    "skills",
    "repomap",
    "workspace",
    "_version",
    "gn_cli",  # run_frozen imports it at function level (CLI dispatch) — force-include
    "terminal_dashboard",  # gn dashboard is imported lazily by the frozen CLI
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

if BUNDLE_TINYGPT:
    if importlib.util.find_spec("torch") is None:
        raise RuntimeError("TinyGPT bundle requested, but torch is missing from the build Python")
    if not os.path.isfile(os.path.join(_SEED_SRC, "best_model.pt")):
        raise RuntimeError("TinyGPT bundle requested, but seed/best_model.pt is missing")
    # greyiq_api imports these lazily, so PyInstaller cannot discover them from
    # run_frozen.py. collect_all carries torch's compiled CPU DLLs and metadata.
    hiddenimports += ["solin_core", "solin_typo", "solin_bpe", "solin_persona",
                      "solin_intent_learn", "training_runtime"]
    torch_datas, torch_binaries, torch_hidden = collect_all("torch")
    datas += torch_datas
    binaries += torch_binaries
    hiddenimports += torch_hidden
    print("[greyiq-backend.spec] bundling TinyGPT, CPU torch, and seed checkpoint")

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
# Bundle the MCP SDK modules GreyIQ uses. collect_all("mcp") also imports the
# optional mcp.cli package, whose Typer extra is intentionally not installed
# and aborts PyInstaller's isolated module scan.
hiddenimports += [
    "mcp.client.stdio", "mcp.client.streamable_http",
    "mcp.server.fastmcp", "mcp.shared.memory",
]

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
# Playwright resolves exact revisions from its installed driver manifest. A shared cache
# can contain newer browsers from another venv; choosing the newest would produce a bundle
# that passes the API smoke test but cannot launch a browser. On macOS, the full
# Chromium .app contains nested frameworks that PyInstaller cannot ad-hoc sign
# during COLLECT; every bundled caller launches headless Chromium, so ship only
# Playwright's headless shell there. The release build installs the browsers
# immediately before freezing.
_pw_spec = importlib.util.find_spec("playwright")
if not _pw_spec or not _pw_spec.origin:
    raise RuntimeError("Playwright is not installed in the build environment")
_pw_manifest = os.path.join(os.path.dirname(_pw_spec.origin), "driver", "package", "browsers.json")
with open(_pw_manifest, encoding="utf-8") as _pw_handle:
    _pw_browsers = json.load(_pw_handle)["browsers"]
_pw_names = {"chromium-headless-shell"} if sys.platform == "darwin" else {
    "chromium", "chromium-headless-shell"
}
_pw_required = {
    _browser["name"]: str(_browser["revision"])
    for _browser in _pw_browsers
    if _browser["name"] in _pw_names
}
if set(_pw_required) != _pw_names:
    raise RuntimeError(f"Playwright manifest lacks Chromium builds: {_pw_manifest}")
_pw_shipped = []
for _name, _revision in _pw_required.items():
    _entry = f"{_name.replace('-', '_')}-{_revision}"
    _source = os.path.join(_pw_cache, _entry)
    if os.path.isfile(os.path.join(_source, "INSTALLATION_COMPLETE")):
        datas.append((_source, os.path.join("playwright-browsers", _entry)))
        _pw_shipped.append(_entry)
    else:
        raise RuntimeError(
            f"Playwright requires {_entry}, but it is missing from {_pw_cache}. "
            "Run `python -m playwright install chromium` in the build environment."
        )
print(f"[greyiq-backend.spec] bundling Playwright browsers from {_pw_cache}: "
      + ", ".join(sorted(_pw_shipped)))

block_cipher = None

_excludes = ["tkinter", "matplotlib", "pytest",
             "PyQt5", "PySide2", "PyQt6", "PySide6", "shiboken6", "qtpy"]
if not BUNDLE_TINYGPT:
    _excludes += ["torch", "torchvision", "torchaudio", "torchgen", "functorch"]

a = Analysis(  # noqa: F821
    [os.path.join(BACKEND, "run_frozen.py")],
    pathex=[BACKEND],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Qt bindings are unused and PyInstaller refuses to collect two families.
    # The ordinary release also excludes PyTorch; the explicit local opt-in keeps it.
    excludes=_excludes,
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
