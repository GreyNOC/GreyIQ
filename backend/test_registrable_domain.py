"""Tests for the shared public-suffix-aware registrable_domain helper.

Not a full Public Suffix List -- a small built-in set of common multi-label ccSLDs
(co.uk, com.au, ...) and multi-tenant PaaS hosts (herokuapp.com, github.io, ...), good
enough for the scope-naming / memory-bucketing heuristics that use it.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.registrable_domain import is_bare_public_suffix, registrable_domain  # noqa: E402


class RegistrableDomainTests(unittest.TestCase):
    def test_plain_two_label_host_unchanged(self) -> None:
        self.assertEqual(registrable_domain("example.com"), "example.com")
        self.assertEqual(registrable_domain("shop.example.com"), "example.com")

    def test_multi_label_ccsld_bumps_one_label(self) -> None:
        self.assertEqual(registrable_domain("example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("api.staging.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("foo.bar.co.uk"), "bar.co.uk")

    def test_distinct_co_uk_apexes_stay_distinct(self) -> None:
        self.assertNotEqual(registrable_domain("shop.example.co.uk"), registrable_domain("foo.bar.co.uk"))

    def test_shared_paas_host_bumps_one_label(self) -> None:
        self.assertEqual(registrable_domain("myapp.herokuapp.com"), "myapp.herokuapp.com")
        self.assertEqual(registrable_domain("victim-unrelated.herokuapp.com"), "victim-unrelated.herokuapp.com")
        self.assertNotEqual(registrable_domain("myapp.herokuapp.com"), registrable_domain("victim-unrelated.herokuapp.com"))
        self.assertEqual(registrable_domain("myteam.github.io"), "myteam.github.io")

    def test_bare_suffix_with_too_few_labels_falls_back(self) -> None:
        # Can't bump further than the host actually has -- degenerate but never crashes.
        self.assertEqual(registrable_domain("co.uk"), "co.uk")
        self.assertEqual(registrable_domain("herokuapp.com"), "herokuapp.com")

    def test_single_label_and_empty_host(self) -> None:
        self.assertEqual(registrable_domain("localhost"), "localhost")
        self.assertEqual(registrable_domain(""), "")

    def test_is_bare_public_suffix(self) -> None:
        self.assertTrue(is_bare_public_suffix("herokuapp.com"))
        self.assertTrue(is_bare_public_suffix("co.uk"))
        self.assertTrue(is_bare_public_suffix("github.io"))
        self.assertFalse(is_bare_public_suffix("example.com"))
        self.assertFalse(is_bare_public_suffix("myapp.herokuapp.com"))
        self.assertFalse(is_bare_public_suffix("example.co.uk"))
        self.assertFalse(is_bare_public_suffix(""))


if __name__ == "__main__":
    unittest.main()
