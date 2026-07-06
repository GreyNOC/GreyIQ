"""Tests for the new static sink packs (deserialize/open_redirect/ssti/xxe/jwt) and
their classification into the right bounty class."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from bughunter.bounty import _classify  # noqa: E402
from bughunter.code_scanner.rules import ALL_RULES  # noqa: E402


def _hits(text: str, lang: str, path: str = "f.src") -> list[str]:
    out: list[str] = []
    for rule in ALL_RULES:
        if rule.applies_to(lang, path):
            out.extend(f.rule_id for f in rule.scan(path=path, text=text))
    return out


class RuleRegistryTests(unittest.TestCase):
    def test_no_duplicate_rule_ids(self) -> None:
        ids = [r.rule_id for r in ALL_RULES]
        self.assertEqual(len(ids), len(set(ids)), "rule_id collision in ALL_RULES")


class DeserializeTests(unittest.TestCase):
    def test_php_unserialize_superglobal(self) -> None:
        self.assertIn("php.unserialize-superglobal", _hits('$o = unserialize($_GET["d"]);', "php", "f.php"))

    def test_php_unserialize_constant_is_safe(self) -> None:
        self.assertNotIn("php.unserialize-superglobal", _hits('$o = unserialize($cached);', "php", "f.php"))

    def test_java_readobject(self) -> None:
        self.assertIn("java.objectinputstream-readobject", _hits("Object o = new ObjectInputStream(in).readObject();", "java", "f.java"))


class OpenRedirectTests(unittest.TestCase):
    def test_flask_redirect_request(self) -> None:
        self.assertIn("py.flask-redirect-request", _hits('return redirect(request.args.get("next"))', "python"))

    def test_constant_redirect_is_safe(self) -> None:
        self.assertNotIn("py.flask-redirect-request", _hits('return redirect("/home")', "python"))

    def test_express_redirect_request(self) -> None:
        self.assertIn("js.express-redirect-request", _hits("res.redirect(req.query.url)", "javascript", "f.js"))


class SstiSourceTests(unittest.TestCase):
    def test_render_template_string_format(self) -> None:
        self.assertIn("py.render-template-string-format", _hits('return render_template_string(f"<h1>{name}</h1>")', "python"))

    def test_render_template_file_is_safe(self) -> None:
        # render_template (a fixed file) is the SAFE form and must not match.
        self.assertEqual(_hits('return render_template("page.html", name=name)', "python"), [])


class XxeTests(unittest.TestCase):
    def test_lxml_parse_flagged(self) -> None:
        self.assertIn("py.lxml-etree-parse", _hits("tree = etree.parse(user_file)", "python"))

    def test_hardened_parser_is_suppressed(self) -> None:
        safe = "p = etree.XMLParser(resolve_entities=False, no_network=True); etree.parse(f, p)"
        self.assertNotIn("py.lxml-etree-parse", _hits(safe, "python"))


class JwtWeakTests(unittest.TestCase):
    def test_alg_none(self) -> None:
        self.assertIn("jwt.alg-none", _hits('jwt.decode(t, key, algorithms=["none"])', "python"))

    def test_verify_disabled(self) -> None:
        self.assertIn("jwt.verify-disabled", _hits('jwt.decode(t, options={"verify_signature": False})', "python"))

    def test_short_hmac_secret(self) -> None:
        self.assertIn("jwt.short-hmac-secret", _hits('jwt.encode(payload, "secret123")', "python"))


class AccessControlSourceTests(unittest.TestCase):
    def test_django_request_id_lookup(self) -> None:
        code = 'order = Order.objects.get(id=request.GET["id"])'
        self.assertIn("py.django-object-by-request-id", _hits(code, "python", "views.py"))

    def test_django_owner_scoped_lookup_is_not_flagged(self) -> None:
        code = 'order = Order.objects.get(id=request.GET["id"], owner=request.user)'
        self.assertNotIn("py.django-object-by-request-id", _hits(code, "python", "views.py"))

    def test_express_request_id_lookup(self) -> None:
        code = "const order = await Order.findOne({ _id: req.params.id });"
        self.assertIn("js.mongoose-object-by-request-id", _hits(code, "javascript", "routes.js"))

    def test_express_owner_scoped_lookup_is_not_flagged(self) -> None:
        code = "const order = await Order.findOne({ _id: req.params.id, owner: req.user.id });"
        self.assertNotIn("js.mongoose-object-by-request-id", _hits(code, "javascript", "routes.js"))

    def test_request_body_mass_assignment(self) -> None:
        self.assertIn(
            "js.request-body-mass-assignment",
            _hits("await User.updateOne({ _id: req.params.id }, req.body);", "javascript", "routes.js"),
        )

    def test_drf_all_fields_serializer(self) -> None:
        self.assertIn("py.drf-modelserializer-all-fields", _hits('fields = "__all__"', "python", "serializers.py"))


class ClassificationTests(unittest.TestCase):
    def test_new_categories_map_to_accurate_classes(self) -> None:
        cases = {
            "access_control": "access-control",
            "deserialization": "rce",
            "open_redirect": "redirect",
            "ssti": "ssti",
            "xxe": "xxe",
            "jwt": "jwt",
        }
        for category, expected_class in cases.items():
            class_id, name, cwe, owasp = _classify({"category": category})
            self.assertEqual(class_id, expected_class, f"{category} misclassified as {class_id}")
            self.assertTrue(cwe and owasp, f"{category} -> {class_id} missing CWE/OWASP")


if __name__ == "__main__":
    unittest.main()
