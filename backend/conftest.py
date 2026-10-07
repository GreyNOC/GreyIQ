"""Keep browser/recon fixture hosts independent of external DNS in pytest."""

from __future__ import annotations

import ipaddress
import socket

import pytest


_DNS_FIXTURE_MODULES = {
    "test_live_scan_service.py",
    "test_playwright_guard.py",
    "test_recon.py",
    "test_recon_all_knowing.py",
    "test_recon_api_expansion.py",
    "test_web_scan_guards.py",
}
_PUBLIC_FIXTURE_IP = "8.8.8.8"


@pytest.fixture(autouse=True)
def fixture_host_dns(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve only these modules' public fixture hosts without changing URL guards.

    Their fetchers and browsers are stubbed, but the real private-address check
    still resolves the seed host. DNS rebinding tests manage their own resolver
    and are intentionally outside this fixture.
    """
    if request.node.path.name not in _DNS_FIXTURE_MODULES:
        return

    from bughunter import web_ingest

    previous_resolver = web_ingest._real_getaddrinfo

    def resolve_fixture_host(host, port, *args, **kwargs):
        name = str(host or "").strip("[]").lower()
        if name == "example.com" or name.endswith(".example.com") or name == "xn--mnchen-3ya.de":
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (_PUBLIC_FIXTURE_IP, int(port or 0)))]
        if name in {"localhost", ""}:
            return previous_resolver(host, port, *args, **kwargs)
        try:
            ipaddress.ip_address(name)
        except ValueError:
            raise socket.gaierror(f"No DNS fixture for {host!r}") from None
        return previous_resolver(host, port, *args, **kwargs)

    monkeypatch.setattr(web_ingest, "_real_getaddrinfo", resolve_fixture_host)
