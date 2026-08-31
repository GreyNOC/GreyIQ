"""Tests for the offline hunt ranker's deterministic feature extractor.

Two properties carry the whole design and both are asserted here: the extractor is a pure
function of the endpoint (so a retrain of an unchanged corpus reproduces the same model), and
no feature string can ever contain a parameter VALUE (so a weight file cannot become an
exfiltration channel for secrets the trace log already redacts)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter import hunt_features  # noqa: E402


def _feats(url: str, recon: list[str] | None = None, tech: str = "", form: dict | None = None) -> dict[str, float]:
    return hunt_features.endpoint_features(url, hunt_features.query_names(url), recon or [], tech, form)


class VersionContractTests(unittest.TestCase):
    def test_feature_version_is_pinned(self) -> None:
        # Weight files are indexed by these namespaces. Changing/adding/removing one MUST bump
        # FEATURE_VERSION (hunt_model rejects a mismatch), so this assertion is the tripwire
        # that forces the bump and a retrain rather than a silently wrong model.
        self.assertEqual(hunt_features.FEATURE_VERSION, 1)
        self.assertEqual(hunt_features.MAX_FEATURES, 64)


class DeterminismTests(unittest.TestCase):
    def test_identical_input_gives_identical_dict_and_key_order(self) -> None:
        url = "https://app.example.com/api/v1/orders/1001/download?file=a&id=2"
        first = _feats(url, ["file", "id", "url"], "php wordpress")
        second = _feats(url, ["file", "id", "url"], "php wordpress")
        self.assertEqual(first, second)
        self.assertEqual(list(first), list(second))

    def test_keys_are_returned_in_sorted_order(self) -> None:
        feats = _feats("https://t.example/search?q=1", ["q"], "flask")
        self.assertEqual(list(feats), sorted(feats))

    def test_every_feature_value_is_a_float(self) -> None:
        feats = _feats("https://t.example/login?next=/home", ["next"], "django")
        for name, value in feats.items():
            self.assertIsInstance(value, float, name)


class NoValueLeakTests(unittest.TestCase):
    """The tested contract: NAMES and keywords only, never a VALUE."""

    def test_query_value_never_appears_in_any_feature(self) -> None:
        url = "https://app.example.com/reset?token=s3cretVALUE1&next=https%3A%2F%2Fevil.example%2Fx"
        feats = _feats(url, ["token", "next"], "php")
        self.assertIn("param:name=token", feats)
        self.assertIn("param:name=next", feats)
        blob = "\n".join(feats)
        self.assertNotIn("s3cret", blob)
        self.assertNotIn("VALUE1", blob)
        self.assertNotIn("evil", blob)

    def test_a_digit_run_inside_a_query_value_cannot_forge_an_object_shape(self) -> None:
        # shape:numeric_seg is the IDOR signal and is matched against the PATH only.
        self.assertNotIn("shape:numeric_seg", _feats("https://t.example/x?next=/123/", ["next"]))
        self.assertIn("shape:numeric_seg", _feats("https://t.example/order/1001"))

    def test_hostile_param_name_cannot_inject_into_a_feature_key(self) -> None:
        url = "https://t.example/x?" + "a%3Db%0Ac=1"
        feats = _feats(url, [])
        for name in feats:
            self.assertNotIn("\n", name)
            self.assertEqual(name.count("="), 1 if "=" in name else 0)


class PathFeatureTests(unittest.TestCase):
    def test_path_keyword_and_segment_namespaces(self) -> None:
        feats = _feats("https://t.example/admin/exportUsers.json")
        self.assertIn("path:kw=admin", feats)
        self.assertIn("path:kw=export", feats)
        self.assertIn("path:kw=json", feats)
        self.assertIn("path:seg=admin", feats)   # camelCase split via hunt_brain._signal_words
        self.assertIn("path:seg=export", feats)
        self.assertIn("path:seg=users", feats)
        self.assertIn("path:ext=json", feats)
        self.assertIn("path:depth=2", feats)

    def test_depth_buckets(self) -> None:
        self.assertIn("path:depth=0", _feats("https://t.example/"))
        self.assertIn("path:depth=1", _feats("https://t.example/a"))
        self.assertIn("path:depth=3plus", _feats("https://t.example/a/b/c/d"))

    def test_uuid_segment_shape(self) -> None:
        feats = _feats("https://t.example/doc/3f1c9a2e-1111-2222-3333-444455556666")
        self.assertIn("shape:uuid_seg", feats)


class ParamAndTechFeatureTests(unittest.TestCase):
    def test_hint_tables_become_eight_boolean_inputs(self) -> None:
        feats = _feats("https://t.example/go?url=x", ["url"])
        self.assertIn("param:hint=ssrf", feats)      # "url" is in _SSRF_HINTS
        self.assertIn("param:hint=redirect", feats)  # ...and in _REDIRECT_HINTS
        self.assertIn("param:name=url", feats)

    def test_only_the_endpoints_own_query_names_become_identity_features(self) -> None:
        # A surface-wide recon name is constant across every endpoint of a hunt, so it must
        # not become a per-endpoint identity feature (it would be pure dilution).
        feats = _feats("https://t.example/x?a=1", ["zzz_surface_only"])
        self.assertIn("param:name=a", feats)
        self.assertNotIn("param:name=zzz_surface_only", feats)

    def test_tech_one_hots_and_the_explicit_none(self) -> None:
        self.assertIn("tech:php", _feats("https://t.example/x", [], "PHP 8.1 / nginx"))
        self.assertIn("tech:none", _feats("https://t.example/x", [], ""))
        self.assertNotIn("tech:none", _feats("https://t.example/x", [], "flask"))

    def test_form_cues(self) -> None:
        feats = _feats("https://t.example/login", [], "", {"method": "POST", "params": ["user", "pass"]})
        self.assertIn("form:method=post", feats)
        self.assertIn("form:field=user", feats)
        self.assertIn("form:field=pass", feats)


class TruncationTests(unittest.TestCase):
    def _monster(self) -> dict[str, float]:
        path = "/" + "/".join(hunt_features._PATH_KEYWORDS)
        query = "&".join(f"p{i}=v{i}" for i in range(40))
        url = f"https://t.example{path}?{query}"
        form = {"method": "POST", "params": [f"f{i}" for i in range(30)]}
        return _feats(url, ["url", "id", "cmd", "file", "template", "q", "user"], "php flask jinja django", form)

    def test_truncation_is_capped_deterministic_and_keeps_bias(self) -> None:
        first, second = self._monster(), self._monster()
        self.assertEqual(len(first), hunt_features.MAX_FEATURES)
        self.assertEqual(first, second)
        self.assertEqual(list(first), list(second))
        self.assertIn("bias", first)                     # sorts first, so it always survives
        self.assertEqual(list(first), sorted(first))

    def test_a_normal_endpoint_stays_far_under_the_cap(self) -> None:
        feats = _feats("https://app.example.com/api/v1/orders/1001?id=2&sort=name", ["id", "sort"], "php")
        self.assertLess(len(feats), hunt_features.MAX_FEATURES)


class PurposeBucketTests(unittest.TestCase):
    def test_buckets(self) -> None:
        cases = {
            "https://t.example/login": "auth",
            "https://t.example/files/download/report.pdf": "download",
            "https://t.example/search?q=1": "search",
            "https://t.example/api/v1/users": "api",
            "https://t.example/admin/users": "admin",
            "https://t.example/render/widget": "render",
            "https://t.example/": "other",
            "not a url at all": "other",
        }
        for url, bucket in cases.items():
            self.assertEqual(hunt_features.purpose_bucket(url), bucket, url)

    def test_declaration_order_is_the_documented_precedence(self) -> None:
        # /admin/login buckets by what it DOES (auth), not where it lives (admin).
        self.assertEqual(hunt_features.purpose_bucket("https://t.example/admin/login"), "auth")


class HelperTests(unittest.TestCase):
    def test_query_names_never_returns_values(self) -> None:
        self.assertEqual(hunt_features.query_names("https://t.example/x?a=1&b=2&a=3"), ["a", "b", "a"])

    def test_tech_key_folds_to_one_key_or_none(self) -> None:
        self.assertEqual(hunt_features.tech_key("nginx PHP 8.1"), "php")
        self.assertEqual(hunt_features.tech_key(""), "none")
        self.assertEqual(hunt_features.tech_key(None), "none")

    def test_malformed_input_is_tolerated(self) -> None:
        # Rows come off a stored trace line; one malformed endpoint must not abort a retrain.
        self.assertIn("bias", hunt_features.endpoint_features("", None, None, None, "not a dict"))  # type: ignore[arg-type]
        self.assertEqual(hunt_features.query_names(None), [])
        self.assertIn("bias", hunt_features.endpoint_features("http://[::1", [], [], ""))


if __name__ == "__main__":
    unittest.main()
