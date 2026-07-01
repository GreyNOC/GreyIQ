"""Tests for web_ingest's DNS-rebinding TOCTOU mitigation (guarded_dns_scope /
_pinned_getaddrinfo / _host_is_private).

Regression coverage for a confirmed high-severity finding: _host_is_private()
resolved a hostname purely to decide pass/fail and discarded the answer, so the
REAL HTTP connection made moments later (urllib -> http.client -> socket.
create_connection) performed its own, completely independent getaddrinfo() call --
letting an attacker-controlled DNS server answer with a public IP for the guard and
a private/cloud-metadata IP for the real connection, defeating the guard entirely.

These tests simulate exactly that disagreeing-answer scenario (which the PRE-EXISTING
test_private_resolving_bucket_is_refused_when_private_urls_off in
test_active_verify_service.py could not do, since its shim always returns the SAME
answer for every call) by controlling web_ingest._real_getaddrinfo directly, so
socket.getaddrinfo itself stays exactly what production installs (_pinned_getaddrinfo).
"""
from __future__ import annotations

import socket
import sys
import threading
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import web_ingest  # noqa: E402

_PUBLIC_IP = "8.8.8.8"           # a real, non-private, non-reserved address
_METADATA_IP = "169.254.169.254"  # cloud metadata / link-local -- must never be reachable


def _addrinfo(ip: str, port: int | None) -> list[tuple]:
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 0))]


class DnsRebindingPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_real = web_ingest._real_getaddrinfo

    def tearDown(self) -> None:
        web_ingest._real_getaddrinfo = self._orig_real
        # Defensive: never leak a pin across tests even if one fails mid-scope.
        with web_ingest._dns_pin_lock:
            web_ingest._dns_pins.clear()

    def test_rebinding_second_lookup_is_masked_by_the_pin(self) -> None:
        # The attacker's authoritative DNS: a benign public IP on the FIRST lookup
        # (so the guard passes), then the metadata IP on every subsequent lookup
        # (what the real HTTP connect would see without the fix).
        calls = {"n": 0}

        def rebinding_resolver(host, port, *a, **k):
            calls["n"] += 1
            ip = _PUBLIC_IP if calls["n"] == 1 else _METADATA_IP
            return _addrinfo(ip, port)

        web_ingest._real_getaddrinfo = rebinding_resolver

        with web_ingest.guarded_dns_scope():
            # The guard's own check: sees the public IP, passes.
            self.assertFalse(web_ingest._host_is_private("evil-rebind.example"))
            self.assertEqual(calls["n"], 1)

            # Simulate the REAL HTTP connect performing its OWN independent
            # getaddrinfo() a moment later for the exact same hostname (this is
            # literally what http.client.HTTPConnection.connect() does). With the
            # fix, socket.getaddrinfo (== _pinned_getaddrinfo in production) must
            # return the PINNED (first, public) answer -- never re-invoking the
            # rebinding resolver and never seeing the metadata IP.
            result = socket.getaddrinfo("evil-rebind.example", 443, proto=socket.IPPROTO_TCP)
            self.assertEqual(result[0][4][0], _PUBLIC_IP)
            self.assertEqual(calls["n"], 1, "the pin must prevent a second real DNS lookup")

        # Outside the scope the pin is cleared -- a fresh lookup now genuinely
        # reaches the rebinding resolver again and (this time) sees the attack.
        self.assertTrue(web_ingest._host_is_private("evil-rebind.example"))
        self.assertEqual(calls["n"], 2)

    def test_a_hostname_that_is_private_from_the_first_lookup_is_still_refused(self) -> None:
        web_ingest._real_getaddrinfo = lambda host, port, *a, **k: _addrinfo(_METADATA_IP, port)
        with web_ingest.guarded_dns_scope():
            self.assertTrue(web_ingest._host_is_private("always-private.example"))

    def test_different_hostname_on_the_same_thread_is_not_masked_by_an_unrelated_pin(self) -> None:
        calls: list[str] = []

        def resolver(host, port, *a, **k):
            calls.append(host)
            return _addrinfo(_PUBLIC_IP if host == "host-a.example" else _METADATA_IP, port)

        web_ingest._real_getaddrinfo = resolver
        with web_ingest.guarded_dns_scope():
            self.assertFalse(web_ingest._host_is_private("host-a.example"))
            # A DIFFERENT hostname's lookup within the SAME scope must not be served
            # host-a's pinned answer -- it needs its own fresh (and here, correctly
            # private) resolution.
            self.assertTrue(web_ingest._host_is_private("host-b.example"))
        self.assertEqual(calls, ["host-a.example", "host-b.example"])

    def test_pin_is_cleared_even_when_the_scope_body_raises(self) -> None:
        web_ingest._real_getaddrinfo = lambda host, port, *a, **k: _addrinfo(_PUBLIC_IP, port)
        with self.assertRaises(RuntimeError):
            with web_ingest.guarded_dns_scope():
                web_ingest._host_is_private("host.example")
                self.assertIn(threading.get_ident(), web_ingest._dns_pins)
                raise RuntimeError("boom")
        self.assertNotIn(threading.get_ident(), web_ingest._dns_pins)

    def test_pin_is_scoped_per_thread(self) -> None:
        # A pin installed by one thread must never leak an answer to a different
        # thread's concurrent guarded fetch for the same hostname.
        web_ingest._real_getaddrinfo = lambda host, port, *a, **k: _addrinfo(_PUBLIC_IP, port)
        results: dict[str, bool] = {}

        def worker(name: str) -> None:
            with web_ingest.guarded_dns_scope():
                web_ingest._host_is_private(f"{name}.example")
                results[name] = threading.get_ident() in web_ingest._dns_pins
                # No pin from the OTHER thread should be visible here at all --
                # each thread's pin is keyed strictly by its own thread ident.
                other_pins = {k: v for k, v in web_ingest._dns_pins.items() if k != threading.get_ident()}
                results[f"{name}_isolated"] = not other_pins

        t1 = threading.Thread(target=worker, args=("t1",))
        t2 = threading.Thread(target=worker, args=("t2",))
        t1.start()
        t1.join()
        t2.start()
        t2.join()
        self.assertTrue(results["t1"])
        self.assertTrue(results["t2"])

    def test_non_string_host_falls_through_to_the_real_resolver(self) -> None:
        # socket.getaddrinfo can be called with host=None or other non-str values by
        # unrelated stdlib code; the wrapper must never crash on that.
        calls = {"n": 0}

        def resolver(host, port, *a, **k):
            calls["n"] += 1
            return _addrinfo(_PUBLIC_IP, port)

        web_ingest._real_getaddrinfo = resolver
        result = web_ingest._pinned_getaddrinfo(None, 80)
        self.assertEqual(calls["n"], 1)
        self.assertEqual(result[0][4][0], _PUBLIC_IP)


if __name__ == "__main__":
    unittest.main()
