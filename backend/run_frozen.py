"""Entry point for the PyInstaller-frozen GreyIQ backend.

The normal launcher (`python -m backend.greyiq_api`) hands uvicorn the import
string ``backend.greyiq_api:app``, which a frozen bundle cannot re-import. Here
we import the ASGI ``app`` instance directly and run it, which works both frozen
and as a plain script. Host/port/runtime dir are taken from the environment that
the Electron shell (electron/main.cjs) sets before spawning this process.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# When run as a plain script (dev), make sibling modules importable the same way
# greyiq_api does. When frozen, PyInstaller has already wired up the import path.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

def main() -> None:
    # Frozen release: point Playwright at the Chromium bundled under the app before any
    # browser launch site runs (screenshots, live scan). Set once at startup so every
    # current and future launch path is covered regardless of ordering; no-op in dev.
    try:
        from bughunter.playwright_env import ensure_bundled_browsers_path
        ensure_bundled_browsers_path()
    except Exception:  # noqa: BLE001 - never let a browser-path hint block startup
        pass

    # Dual-purpose binary: with a CLI verb as the first argument, dispatch to the
    # `gn` CLI (importing ONLY the torch-free bughunter engine — no uvicorn/API);
    # with no arguments, run the API server. So the shipped backend exe is also the
    # `gn` command (the gn.cmd / gn shims call `greyiq-backend(.exe) <verb> ...`).
    import gn_cli

    argv = sys.argv[1:]
    if argv and (argv[0] in gn_cli.CLI_COMMANDS or argv[0] in ("-V", "--version", "-h", "--help")):
        raise SystemExit(gn_cli.main(argv))

    import uvicorn  # noqa: E402 - server-only deps, imported lazily so CLI mode stays light

    from greyiq_api import GREYIQ_ACCESS_KEY, _is_loopback_bind, app  # noqa: E402

    host = os.getenv("GREYIQ_HOST", "127.0.0.1")
    port = int(os.getenv("GREYIQ_PORT", os.getenv("PORT", "8766")))
    # Same fail-closed check as greyiq_api.main() -- this frozen entry point has its
    # OWN uvicorn.run() call (it can't reuse that one; see the module docstring), so
    # the guard has to be duplicated here too or a packaged/frozen deployment could
    # be exposed beyond loopback without it.
    if not _is_loopback_bind(host) and not GREYIQ_ACCESS_KEY and os.getenv("GREYIQ_ALLOW_INSECURE_PUBLIC_BIND", "").strip() != "1":
        print(
            f"Refusing to start: GREYIQ_HOST={host!r} is not loopback-only, but no GREYIQ_ACCESS_KEY is set.\n"
            "Set GREYIQ_ACCESS_KEY to a strong secret before exposing this server, or set "
            "GREYIQ_ALLOW_INSECURE_PUBLIC_BIND=1 if you already have an equivalent auth layer in front of it.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    # Pass the app instance (not an import string) so this works inside a frozen
    # bundle where re-importing "backend.greyiq_api" is not possible.
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=False,
        log_level="info",
        server_header=False,
    )


if __name__ == "__main__":
    main()
