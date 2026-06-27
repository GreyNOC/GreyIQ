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
    # Dual-purpose binary: with a CLI verb as the first argument, dispatch to the
    # `gn` CLI (importing ONLY the torch-free bughunter engine — no uvicorn/API);
    # with no arguments, run the API server. So the shipped backend exe is also the
    # `gn` command (the gn.cmd / gn shims call `greyiq-backend(.exe) <verb> ...`).
    import gn_cli

    argv = sys.argv[1:]
    if argv and (argv[0] in gn_cli.CLI_COMMANDS or argv[0] in ("-V", "--version", "-h", "--help")):
        raise SystemExit(gn_cli.main(argv))

    import uvicorn  # noqa: E402 - server-only deps, imported lazily so CLI mode stays light

    from greyiq_api import app  # noqa: E402

    host = os.getenv("GREYIQ_HOST", "127.0.0.1")
    port = int(os.getenv("GREYIQ_PORT", os.getenv("PORT", "8766")))
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
