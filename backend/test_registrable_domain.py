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

    def test_multi_label_cloud_suffixes_keep_tenants_distinct(self) -> None:
        self.assertEqual(registrable_domain("victim.s3.amazonaws.com"), "victim.s3.amazonaws.com")
        self.assertEqual(registrable_domain("attacker.s3.amazonaws.com"), "attacker.s3.amazonaws.com")
        self.assertEqual(registrable_domain("myaccount.blob.core.windows.net"),
                         "myaccount.blob.core.windows.net")
        self.assertEqual(registrable_domain("other.blob.core.windows.net"),
                         "other.blob.core.windows.net")
        self.assertNotEqual(registrable_domain("victim.s3.amazonaws.com"),
                            registrable_domain("attacker.s3.amazonaws.com"))
        self.assertNotEqual(registrable_domain("myaccount.blob.core.windows.net"),
                            registrable_domain("other.blob.core.windows.net"))

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

    def test_bare_parent_of_a_multi_label_shared_host_is_also_refused(self) -> None:
        # Regression: only the full "s3.amazonaws.com" / "blob.core.windows.net" were
        # ever refused as bare scope tokens -- their OWN bare parent ("amazonaws.com",
        # "core.windows.net", "windows.net") was not, so naming just the parent in
        # free-text scope fell through to the dotted-suffix match in
        # active_verify_service.host_in_active_scope() and authorized probing ANY
        # unrelated tenant's S3 bucket / Azure Storage container.
        self.assertTrue(is_bare_public_suffix("amazonaws.com"))
        self.assertTrue(is_bare_public_suffix("core.windows.net"))
        self.assertTrue(is_bare_public_suffix("windows.net"))
        # A real owned host under these must still resolve to itself, not the suffix.
        self.assertFalse(is_bare_public_suffix("victim-secret-bucket.s3.amazonaws.com"))
        self.assertFalse(is_bare_public_suffix("myaccount.blob.core.windows.net"))


if __name__ == "__main__":
    unittest.main()
