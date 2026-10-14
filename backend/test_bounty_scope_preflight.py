"""URL hunt scope must be established before network-capable scanners run."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from urllib.parse import urlparse


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import bounty  # noqa: E402


class UrlScopePreflightTests(unittest.TestCase):
    def test_missing_ambiguous_and_unrelated_scope_never_reaches_a_scanner(self) -> None:
        cases = (
            ("", "https://app.example.com/"),
            ("we own app.example.com", "https://app.example.com/"),
            ("https://app.example.com/", "https://app.example.com/"),
            ("app.example.com/path", "https://app.example.com/"),
            ("app.example.com:443", "https://app.example.com/"),
            ("https://github.com/acme/widget", "https://app.example.com/"),
            ("https://app.example.com/ app.example.com", "https://app.example.com/"),
            ("example.com", "https://app.example.com/"),
            ("notapp.example.com", "https://app.example.com/"),
            ("app.example.com.evil", "https://app.example.com/"),
            ("*.other.com", "https://app.example.com/"),
            ("*.example.com", "https://example.com/"),
            ("*.com", "https://app.example.com/"),
            ("*.herokuapp.com", "https://tenant.herokuapp.com/"),
            ("app.example.com", "https://[broken"),
            ("app.example.com", "https://app.example.com/ evil.com"),
            ("app.example.com", "https://app.example.com\\@evil.com"),
            ("app.example.com", "https://@app.example.com/"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=AssertionError("scanner ran")) as scanners:
                for scope, target in cases:
                    with self.subTest(scope=scope, target=target):
                        result = bounty.run_bounty_hunt(
                            target, "web-app", None, None, scope, True, {},
                            default_reports_dir=Path(tmp),
                        )
                        self.assertFalse(result["ok"], result)
                scanners.assert_not_called()

    def test_authorization_and_program_exclusion_precede_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=AssertionError("scanner ran")) as scanners:
                unauthorized = bounty.run_bounty_hunt(
                    "https://app.example.com/", "web-app", None, None,
                    "app.example.com", False, {}, default_reports_dir=Path(tmp),
                )
                excluded = bounty.run_bounty_hunt(
                    "https://blocked.example.com/", "web-app", None, None,
                    "*.example.com", True, {}, default_reports_dir=Path(tmp),
                    settings=SimpleNamespace(excluded_hosts=("blocked.example.com",)),
                )
                self.assertFalse(unauthorized["ok"])
                self.assertIn("authorized", unauthorized["error"].lower())
                self.assertFalse(excluded["ok"])
                self.assertIn("excluded", excluded["error"].lower())
                scanners.assert_not_called()

    def test_exact_and_wildcard_grants_pass_the_exact_target_host(self) -> None:
        class StopBeforeNetwork(BaseException):
            pass

        captured: list[str] = []

        def scanner_spy(*_args: object, **kwargs: object) -> None:
            captured.append(str(kwargs.get("scope_host")))
            raise StopBeforeNetwork

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=scanner_spy):
                for scope in (
                    "app.example.com", "*.example.com",
                    "https://github.com/acme/widget app.example.com",
                ):
                    with self.subTest(scope=scope):
                        with self.assertRaises(StopBeforeNetwork):
                            bounty.run_bounty_hunt(
                                "https://App.Example.Com/path", "web-app", None, None,
                                scope, True, {}, default_reports_dir=Path(tmp),
                            )
        self.assertEqual(captured, ["app.example.com"] * 3)

    def test_scanner_dispatch_binds_web_and_live_to_the_preflight_host(self) -> None:
        web_result = {"ok": True, "findings": [], "risk": "low", "score": 0,
                      "status": 200, "finding_count": 0}
        live_result = {"ok": True, "findings": [], "risk": "low", "score": 0,
                       "finding_count": 0}
        with patch.object(bounty, "run_web_scan", return_value=web_result) as web:
            with patch.object(bounty, "run_live_scan", return_value=live_result) as live:
                bounty._run_scanners(
                    bounty.BOUNTY_PROFILES["web-app"], "url",
                    "https://app.example.com/", 100, True,
                    scope_host="app.example.com",
                )
        self.assertEqual(web.call_args.kwargs["scope_host"], "app.example.com")
        self.assertEqual(live.call_args.kwargs["scope_host"], "app.example.com")


class RepositoryScopePreflightTests(unittest.TestCase):
    def test_remote_clone_rejects_missing_unrelated_and_ambiguous_scope_before_scan(self) -> None:
        target = "https://github.com/acme/widget"
        cases = (
            (target, ""),
            (target, "github.com"),
            (target, "*.github.com"),
            (target, "https://github.com/acme/other"),
            (target, "https://github.com/acme/widget/tree/main"),
            (target, "we own https://github.com/acme/widget"),
            (target, "https://github.com/acme/widget https://example.com/allowed"),
            ("https://github.com:8443/acme/widget", target),
            ("https://gitlab.com/acme/widget/branch/main", "https://gitlab.com/acme/widget"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=AssertionError("clone started")) as scanners:
                for repository, scope in cases:
                    with self.subTest(repository=repository, scope=scope):
                        result = bounty.run_bounty_hunt(
                            repository, "source-code", None, None, scope, True, {},
                            default_reports_dir=Path(tmp),
                        )
                        self.assertFalse(result["ok"], result)
                scanners.assert_not_called()

    def test_matching_root_in_mixed_saved_scope_reaches_scanner(self) -> None:
        class StopBeforeNetwork(BaseException):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=StopBeforeNetwork) as scanners:
                for target in (
                    "https://GitHub.Com/acme/widget/",
                    "https://github.com/acme/widget.git",
                ):
                    with self.subTest(target=target):
                        with self.assertRaises(StopBeforeNetwork):
                            bounty.run_bounty_hunt(
                                target, "source-code", None, None,
                                "app.example.com\nhttps://github.com/acme/widget", True, {},
                                default_reports_dir=Path(tmp),
                            )
                self.assertEqual(scanners.call_count, 2)
                self.assertTrue(all(call.args[1] == "git" for call in scanners.call_args_list))

    def test_exclusion_overrides_exact_repository_grant(self) -> None:
        target = "https://github.com/acme/widget"
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=AssertionError("clone started")) as scanners:
                result = bounty.run_bounty_hunt(
                    target, "source-code", None, None, target, True, {},
                    settings=SimpleNamespace(excluded_hosts=("github.com",)),
                    default_reports_dir=Path(tmp),
                )
                self.assertFalse(result["ok"])
                self.assertIn("excluded", result["error"].lower())
                scanners.assert_not_called()

    def test_local_path_hunt_still_uses_local_scanner(self) -> None:
        class StopBeforeNetwork(BaseException):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners", side_effect=StopBeforeNetwork) as scanners:
                with self.assertRaises(StopBeforeNetwork):
                    bounty.run_bounty_hunt(
                        tmp, "source-code", None, None, "local QA fixture", True, {},
                        default_reports_dir=Path(tmp),
                    )
                scanners.assert_called_once()
                self.assertEqual(scanners.call_args.args[1], "path")


class SelfScopeGrantTests(unittest.TestCase):
    """``-y`` carries the target it was typed about into scope. What that grant may and may not be.

    The load-bearing test is :meth:`test_every_grant_it_produces_satisfies_the_preflight`: this
    function and the preflight are two readings of "what does `acme.example` mean", and the day
    they disagree the operator gets refused for a scope they never typed.
    """

    def test_a_url_grants_its_exact_host_and_nothing_wider(self) -> None:
        for target, grant in (
            ("https://acme.example", "acme.example"),
            ("https://acme.example/a/b?c=1#d", "acme.example"),
            ("acme.example", "acme.example"),
            ("http://sub.acme.example:8443/x", "sub.acme.example"),
            ("https://192.0.2.5/admin", "192.0.2.5"),
            ("https://localhost:8080/", "localhost"),
            ("https://ACME.Example/", "acme.example"),
        ):
            with self.subTest(target=target):
                self.assertEqual(bounty.self_scope_grant(target), grant)
                self.assertNotIn("*", bounty.self_scope_grant(target),
                                 "-y attests to a host, never to its subdomains")

    def test_a_repository_grants_its_own_root(self) -> None:
        self.assertEqual(bounty.self_scope_grant("https://github.com/org/repo"),
                         "https://github.com/org/repo")

    def test_what_grants_nothing_rather_than_guessing(self) -> None:
        for target in (
            "",
            "   ",
            "not a url",
            "./repo",                      # a local path needs no scope
            "C:/code/project",
            "https://herokuapp.com",       # a bare public suffix: every tenant on the platform
            "http://intranet/",            # single label: ambiguous, and the preflight says so
            "https://user:pw@acme.example/",
        ):
            with self.subTest(target=target):
                self.assertEqual(bounty.self_scope_grant(target), "")

    def test_every_grant_it_produces_satisfies_the_preflight(self) -> None:
        # Two readings of the same question. A grant this derives must be one the gate accepts for
        # that same target, or -y would hand the operator a complaint about their own scope.
        urls = ("https://acme.example", "https://acme.example/x", "acme.example",
                "http://sub.acme.example:8443/x", "https://192.0.2.5/admin",
                "https://localhost:8080/", "https://a.b.c.acme.example/")
        for target in urls:
            with self.subTest(target=target):
                grant = bounty.self_scope_grant(target)
                self.assertTrue(grant)
                host, error = bounty._url_scope_preflight(target, grant)
                self.assertEqual(error, "")
                self.assertEqual(host, grant)
        repo = "https://github.com/org/repo"
        self.assertEqual(bounty._repository_scope_preflight(repo, bounty.self_scope_grant(repo)), "")

    def test_a_forge_page_url_grants_nothing_rather_than_the_whole_forge(self) -> None:
        """A repository LINK is not an attestation about github.com.

        ``canonical_repo_root`` is strict — a query, a fragment, a ``/tree/`` path or an org with
        no repository all fail it — and ``_infer_kind`` then calls the URL a web target, so the
        host branch would hand out a grant for a shared platform with thousands of unrelated
        tenants on it. That is the harm ``is_bare_public_suffix`` exists to prevent for a token an
        operator typed; a derived one must not get there either. The canonical root still grants
        the repository, which is the form that carries no host authority at all.
        """
        for page in ("https://github.com/org/repo.git?a=b",
                     "https://github.com/org/repo/tree/main",
                     "https://github.com/org/repo#readme",
                     "https://github.com/org/repo/issues/1",
                     "https://github.com/org",
                     "https://gitlab.com/org/repo/-/tree/main",
                     "https://bitbucket.org/org/repo/src/main",
                     "https://codeberg.org/org"):
            with self.subTest(page=page):
                self.assertEqual(bounty.self_scope_grant(page), "")
        for root in ("https://github.com/org/repo", "https://github.com/org/repo.git",
                     "https://github.com/org/repo/"):
            with self.subTest(root=root):
                self.assertEqual(bounty.self_scope_grant(root), "https://github.com/org/repo")

    def test_a_grant_does_not_reach_a_neighbouring_host(self) -> None:
        grant = bounty.self_scope_grant("https://acme.example")
        for other in ("https://notacme.example", "https://acme.example.evil.test",
                      "https://sub.acme.example"):
            with self.subTest(other=other):
                _host, error = bounty._url_scope_preflight(other, grant)
                self.assertTrue(error, f"{grant} must not authorize {other}")

    def test_a_derived_grant_does_not_reach_a_subdomain_at_the_ACTIVE_gate(self) -> None:
        """The gate that authorizes live traffic, not just the preflight.

        ``host_in_active_scope`` reads a bare host token as exact-OR-proper-subdomain — long
        established, and what a wildcard program wants. But a token DERIVED from the target by
        ``-y`` is an attestation about one host, so the scope text alone cannot carry the
        difference. ``wildcard_admits_host`` is how a caller tells them apart, and the hunt's
        own recon gate and prover pin to the exact host unless a ``*.`` token asks for the host
        in hand. Without that, `gn hunt https://acme.example -y --active` could probe
        admin.acme.example.
        """
        from bughunter.active_verify_service import get_settings, host_in_active_scope
        from bughunter.active_verify_service import wildcard_admits_host

        settings = get_settings()
        derived = bounty.self_scope_grant("https://acme.example")
        self.assertEqual(derived, "acme.example")
        self.assertFalse(wildcard_admits_host(derived, "admin.acme.example"),
                         "a derived grant must not read as a wildcard request")
        self.assertTrue(wildcard_admits_host("*.acme.example", "admin.acme.example"),
                        "...and an operator-typed wildcard must")
        # The gate itself is unchanged; the caller is what pins it.
        self.assertTrue(host_in_active_scope("admin.acme.example", derived, settings))
        pinned = (lambda host: host_in_active_scope(host, derived, settings)
                  and (host == derived or wildcard_admits_host(derived, host)))
        self.assertTrue(pinned("acme.example"))
        self.assertFalse(pinned("admin.acme.example"),
                         "the hunt's gate must refuse a host the operator never named")

    def test_a_wildcard_for_one_domain_does_not_lift_the_pin_off_another(self) -> None:
        """``gn hunt https://acme.example -y -s '*.other.example'`` — the mixed scope.

        ``-y`` appends the target's own exact host, so the effective scope is
        ``*.other.example acme.example``: a wildcard the operator typed about ONE domain, beside a
        bare token that is an attestation about a DIFFERENT one. Asked of the scope text as a whole
        ("does any token carry a ``*.``"), the wildcard lifted the exact-host pin for every other
        token too, and the prover could reach ``admin.acme.example`` — a host nobody attested to,
        on the strength of a grant about somebody else's domain. The question is per host.
        """
        from bughunter.active_verify_service import get_settings, host_in_active_scope
        from bughunter.active_verify_service import wildcard_admits_host

        settings = get_settings()
        target_host = bounty.self_scope_grant("https://acme.example")
        scope = f"*.other.example {target_host}"
        # host_in_active_scope still admits the subdomain on the bare token's own semantics —
        # which is exactly why the caller's pin is what has to hold.
        self.assertTrue(host_in_active_scope("admin.acme.example", scope, settings))
        pinned = (lambda host: host_in_active_scope(host, scope, settings)
                  and (host == target_host or wildcard_admits_host(scope, host)))
        self.assertTrue(pinned("acme.example"), "the attested host is still probed")
        self.assertFalse(pinned("admin.acme.example"),
                         "a *.other.example grant must not authorize probing acme.example's "
                         "subdomains")
        # ...and the wildcard the operator DID type keeps its full reach.
        for admitted in ("other.example", "api.other.example", "deep.api.other.example"):
            with self.subTest(host=admitted):
                self.assertTrue(pinned(admitted))
        self.assertFalse(pinned("notother.example"))

    def test_a_program_exclusion_still_wins_over_the_self_grant(self) -> None:
        settings = SimpleNamespace(excluded_hosts=("acme.example",))
        _host, error = bounty._url_scope_preflight(
            "https://acme.example", bounty.self_scope_grant("https://acme.example"), settings)
        self.assertIn("excluded", error)


class TheMixedScopePinsTheRealHuntTests(unittest.TestCase):
    """``gn hunt https://acme.example -y -s '*.other.example'`` — driving ``run_bounty_hunt``.

    The tests above pin what the scope functions MEAN. This one pins what a hunt DOES with them,
    because the defect was in the call site: the wildcard question was asked of the whole scope
    text, so the one ``*.other.example`` grant the operator typed lifted the exact-host pin off the
    bare ``acme.example`` token that ``-y`` derived — and both halves of the pin went with it, the
    recon crawl's gate AND the list of endpoints handed to the prover. So rather than rebuild the
    gate here, this captures the gate the engine itself builds and the targets the prover itself
    receives. The scanners, the crawl and the prover are stubbed; the scope decisions are real.
    """

    TARGET = "https://acme.example"
    SCOPE = "*.other.example acme.example"   # what -y + -s '*.other.example' produces

    def _run(self, discovered: list[str]) -> tuple[list[Any], list[str]]:
        """Run a hunt whose crawl finds ``discovered``. Returns (captured gates, probed targets)."""
        gates: list[Any] = []
        probed: list[str] = []

        def _fake_discover(target: str, **kwargs: Any) -> dict[str, Any]:
            gates.append(kwargs.get("scope_in"))
            return {"urls": list(discovered), "params": [], "forms": [], "tech": [],
                    "hints": {}, "observations": {}, "host": "acme.example"}

        def _fake_verify(target: str, *_args: Any, **_kwargs: Any) -> tuple[list, dict]:
            probed.append(str(target))
            return ([], {"in_scope": True})

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bounty, "_run_scanners",
                              return_value=([], ["web"], {"web": {}}, "clean", 0.0, [])), \
                 patch.object(bounty.recon, "discover", side_effect=_fake_discover), \
                 patch.object(bounty.active_verify_service, "verify_active",
                              side_effect=_fake_verify):
                result = bounty.run_bounty_hunt(
                    self.TARGET, "web-app", None, tmp, self.SCOPE, True, {},
                    default_reports_dir=Path(tmp), seed_dir=BACKEND_DIR / "seed",
                    runtime_dir=Path(tmp), active=True,
                )
        self.assertTrue(result.get("ok"), result.get("error"))
        self.assertTrue(gates, "the hunt's own recon gate was never built")
        self.assertIsNotNone(gates[0], "a scope was given, so the crawl must be gated")
        return gates, probed

    def test_the_crawl_gate_refuses_a_subdomain_of_the_attested_host(self) -> None:
        gates, _probed = self._run([self.TARGET + "/"])
        gate = gates[0]
        self.assertTrue(gate("acme.example"), "the attested host is still crawled")
        self.assertFalse(gate("admin.acme.example"),
                         "a *.other.example grant must not authorize crawling acme.example's "
                         "subdomains")

    def test_the_crawl_gate_keeps_the_wildcard_the_operator_typed(self) -> None:
        gates, _probed = self._run([self.TARGET + "/"])
        gate = gates[0]
        for admitted in ("other.example", "api.other.example"):
            with self.subTest(host=admitted):
                self.assertTrue(gate(admitted), "the typed wildcard keeps its full reach")
        self.assertFalse(gate("notother.example"))

    def test_the_prover_is_never_handed_an_endpoint_off_the_pin(self) -> None:
        """The second half of the pin, and the one that actually bounds live traffic."""
        _gates, probed = self._run([
            self.TARGET + "/",
            "https://admin.acme.example/login",     # the leak: never attested to
            "https://api.other.example/v1/users",   # the typed wildcard: fair game
        ])
        self.assertTrue(probed, "the active pass never ran, so it proves nothing")
        hosts = {urlparse(url).hostname for url in probed}
        self.assertNotIn("admin.acme.example", hosts,
                         "the prover was handed a host the operator never attested to")
        self.assertIn("acme.example", hosts, "the attested host is still probed")


if __name__ == "__main__":
    unittest.main()
