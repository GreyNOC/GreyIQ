"""Single source of the backend version string (imported by greyiq_api and gn_cli).

MUST equal ``package.json`` ``version`` — the Release commit bumps both, and
``scripts/check-devops.cjs`` fails CI if they drift (this string is stamped into every
delivered bug-bounty report, so a stale value misrepresents the build to a triager)."""

VERSION = "1.8.0"
