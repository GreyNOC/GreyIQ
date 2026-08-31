"""Tests for the AST-validated edit ops (offline-coder strategy, move 4).

The contract under test is narrow and absolute: an op either returns an edit pair whose result is
already proven to parse and to have kept every existing statement, or it returns a refusal and the
file is not touched. So each case here asserts on BOTH halves — that the good transforms produce
compilable source, and that the dangerous ones are refused rather than written and hoped about.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import edit_ops  # noqa: E402


def _apply(text: str, result: "edit_ops.OpResult") -> str:
    """Apply an ok result exactly the way ToolBox._apply_one_edit will."""
    assert result.ok, result.reason
    assert text.count(result.old_string) == 1, "old_string must be unique for ToolBox to accept it"
    return text.replace(result.old_string, result.new_string, 1)


class _OpCase(unittest.TestCase):
    def realize(self, text: str, op: str, args: dict, *, suffix: str = ".py", allow_commands: bool = False):
        return edit_ops.realize(text, op, args, suffix=suffix, allow_commands=allow_commands)

    def applied(self, text: str, op: str, args: dict, **kw) -> str:
        result = self.realize(text, op, args, **kw)
        self.assertTrue(result.ok, f"{op} refused: {result.reason}")
        out = _apply(text, result)
        if kw.get("suffix", ".py") == ".py":
            compile(out, "<applied>", "exec")  # every successful op must produce compilable source
        return out


_MODULE = '''"""Module doc."""
from __future__ import annotations

import os


def alpha(value):
    """Alpha."""
    return value + 1


class Config:
    name: str
    count: int = 0
'''


class InsertAnchorTests(_OpCase):
    def test_inserts_after_anchor_with_matching_indent(self) -> None:
        out = self.applied(_MODULE, "insert_anchor", {"anchor": "return value + 1", "block": "# checked"})
        self.assertIn("    return value + 1\n    # checked\n", out)

    def test_inserts_before_anchor(self) -> None:
        out = self.applied(
            _MODULE, "insert_anchor", {"anchor": "return value + 1", "block": "# checked", "position": "before"}
        )
        self.assertIn("    # checked\n    return value + 1\n", out)

    def test_non_unique_anchor_is_refused(self) -> None:
        text = "x = 1\ny = 2\nx = 1\n"
        result = self.realize(text, "insert_anchor", {"anchor": "x = 1", "block": "z = 3"})
        self.assertFalse(result.ok)
        self.assertIn("not unique", result.reason)

    def test_missing_anchor_is_refused(self) -> None:
        result = self.realize(_MODULE, "insert_anchor", {"anchor": "nowhere_at_all", "block": "pass"})
        self.assertFalse(result.ok)
        self.assertIn("not found", result.reason)

    def test_block_that_breaks_the_parse_is_refused(self) -> None:
        # An unbalanced block would compile-fail AFTER the write; it must never reach the write.
        result = self.realize(_MODULE, "insert_anchor", {"anchor": "import os", "block": "def broken(:"})
        self.assertFalse(result.ok)
        self.assertIn("does not parse", result.reason)

    def test_js_is_refused_without_a_node_gate(self) -> None:
        # allow_commands=False means `node --check` cannot run, so verify could not gate the result.
        # Shipping unverifiable text is worse than doing nothing.
        result = self.realize(
            "const a = 1;\n", "insert_anchor", {"anchor": "const a = 1;", "block": "const b = 2;"},
            suffix=".js", allow_commands=False,
        )
        self.assertFalse(result.ok)
        self.assertIn("commands enabled", result.reason)

    def test_markdown_has_no_verify_gate_at_all(self) -> None:
        result = self.realize("# Title\n", "insert_anchor", {"anchor": "# Title", "block": "text"}, suffix=".md")
        self.assertFalse(result.ok)
        self.assertIn("no syntax gate", result.reason)

    def test_json_result_must_stay_valid_json(self) -> None:
        text = '{\n  "a": 1\n}\n'
        broken = self.realize(text, "insert_anchor", {"anchor": '"a": 1', "block": '"b": 2'}, suffix=".json")
        self.assertFalse(broken.ok, "a missing comma produces invalid JSON and must be refused")
        self.assertIn("not valid JSON", broken.reason)
        good = self.realize(text, "insert_anchor", {"anchor": '"a": 1,', "block": '"b": 2'}, suffix=".json")
        self.assertFalse(good.ok, "the anchor is not present, so this is a refusal too")
        with_comma = '{\n  "a": 1,\n  "z": 9\n}\n'
        ok = self.realize(with_comma, "insert_anchor", {"anchor": '"a": 1,', "block": '"b": 2,'}, suffix=".json")
        self.assertTrue(ok.ok, ok.reason)
        import json as _json

        self.assertEqual(_json.loads(_apply(with_comma, ok)), {"a": 1, "b": 2, "z": 9})

    def test_refuses_to_edit_a_file_that_does_not_currently_parse(self) -> None:
        result = self.realize("def broken(:\n", "insert_anchor", {"anchor": "def broken(:", "block": "pass"})
        self.assertFalse(result.ok)
        self.assertIn("does not currently parse", result.reason)


class AddImportTests(_OpCase):
    def test_inserts_after_the_last_import(self) -> None:
        out = self.applied(_MODULE, "add_import", {"module": "json"})
        self.assertIn("import os\nimport json\n", out)

    def test_is_idempotent(self) -> None:
        once = self.applied(_MODULE, "add_import", {"module": "json"})
        again = self.realize(once, "add_import", {"module": "json"})
        self.assertFalse(again.ok)
        self.assertEqual(again.reason, "already imported")

    def test_from_import_form(self) -> None:
        out = self.applied(_MODULE, "add_import", {"module": "pathlib", "names": ["Path"]})
        self.assertIn("from pathlib import Path", out)
        repeat = self.realize(out, "add_import", {"module": "pathlib", "names": ["Path"]})
        self.assertEqual(repeat.reason, "already imported")

    def test_adds_after_a_docstring_when_there_are_no_imports(self) -> None:
        text = '"""Doc."""\n\nVALUE = 1\n'
        out = self.applied(text, "add_import", {"module": "os"})
        self.assertTrue(out.startswith('"""Doc."""\n'))
        self.assertIn("import os", out)
        self.assertIn("VALUE = 1", out)

    def test_adds_to_a_file_with_neither_docstring_nor_imports(self) -> None:
        out = self.applied("VALUE = 1\n", "add_import", {"module": "os"})
        self.assertEqual(out, "import os\nVALUE = 1\n")

    def test_bad_module_name_is_refused(self) -> None:
        result = self.realize(_MODULE, "add_import", {"module": "os; import evil"})
        self.assertFalse(result.ok)
        self.assertIn("not a valid module name", result.reason)

    def test_only_applies_to_python(self) -> None:
        result = self.realize("a: 1\n", "add_import", {"module": "os"}, suffix=".yml")
        self.assertFalse(result.ok)
        self.assertIn("only applies to .py", result.reason)


class AddFunctionTests(_OpCase):
    def test_appends_after_the_last_definition_with_two_blank_lines(self) -> None:
        out = self.applied(
            _MODULE, "add_function",
            {"name": "beta", "params": "value: int", "returns": "int", "body": "return value * 2"},
        )
        self.assertIn("    count: int = 0\n\n\ndef beta(value: int) -> int:\n    return value * 2\n", out)

    def test_never_shadows_an_existing_top_level_name(self) -> None:
        result = self.realize(_MODULE, "add_function", {"name": "alpha", "params": "x", "body": "return x"})
        self.assertFalse(result.ok)
        self.assertIn("never shadows", result.reason)

    def test_a_bad_signature_fails_on_the_fragment_alone(self) -> None:
        result = self.realize(_MODULE, "add_function", {"name": "beta", "params": "x=,", "body": "pass"})
        self.assertFalse(result.ok)
        self.assertIn("fragment does not parse", result.reason)

    def test_after_symbol_targets_a_specific_definition(self) -> None:
        out = self.applied(
            _MODULE, "add_function", {"name": "beta", "params": "", "body": "pass", "after_symbol": "alpha"}
        )
        self.assertLess(out.index("def beta"), out.index("class Config"))

    def test_unknown_after_symbol_is_refused(self) -> None:
        result = self.realize(_MODULE, "add_function", {"name": "beta", "body": "pass", "after_symbol": "nope"})
        self.assertFalse(result.ok)
        self.assertIn("after_symbol", result.reason)

    def test_decorators_are_carried_through(self) -> None:
        out = self.applied(
            _MODULE, "add_function",
            {"name": "beta", "body": "return 1", "decorators": ["staticmethod"]},
        )
        self.assertIn("@staticmethod\ndef beta():", out)


_DATACLASS = """from dataclasses import dataclass


@dataclass
class Options:
    name: str
    count: int = 0
"""


class AddFieldTests(_OpCase):
    def test_adds_an_annotated_field(self) -> None:
        out = self.applied(_MODULE, "add_field", {"target_class": "Config", "field": "debug", "annotation": "bool"})
        self.assertIn("    count: int = 0\n    debug: bool\n", out)

    def test_existing_field_is_refused(self) -> None:
        result = self.realize(_MODULE, "add_field", {"target_class": "Config", "field": "count", "annotation": "int"})
        self.assertFalse(result.ok)
        self.assertIn("already exists", result.reason)

    def test_unknown_class_is_refused(self) -> None:
        result = self.realize(_MODULE, "add_field", {"target_class": "Missing", "field": "x", "annotation": "int"})
        self.assertFalse(result.ok)
        self.assertIn("not found at top level", result.reason)

    def test_nested_class_is_refused_with_that_reason(self) -> None:
        text = "class Outer:\n    class Inner:\n        a: int\n"
        result = self.realize(text, "add_field", {"target_class": "Inner", "field": "b", "annotation": "int"})
        self.assertFalse(result.ok)
        self.assertIn("nested", result.reason)

    def test_dataclass_ordering_guard_refuses_a_bare_field_after_a_defaulted_one(self) -> None:
        # `debug: bool` after `count: int = 0` is grammatically perfect — ast.parse accepts it and
        # _tool_verify's compile() would report OK — but @dataclass raises TypeError at IMPORT time.
        # This is the one class of breakage the post-parse gate structurally cannot see.
        result = self.realize(_DATACLASS, "add_field", {"target_class": "Options", "field": "debug", "annotation": "bool"})
        self.assertFalse(result.ok)
        self.assertIn("dataclass ordering", result.reason)
        compile(_DATACLASS, "<unchanged>", "exec")  # proves compile() is not the gate that caught it

    def test_dataclass_accepts_a_defaulted_field(self) -> None:
        out = self.applied(
            _DATACLASS, "add_field",
            {"target_class": "Options", "field": "debug", "annotation": "bool", "default": "False"},
        )
        self.assertIn("    debug: bool = False\n", out)
        exec(compile(out, "<dc>", "exec"), {})  # noqa: S102 - importing it is the point of the guard

    def test_plain_class_may_take_a_bare_field(self) -> None:
        out = self.applied(_MODULE, "add_field", {"target_class": "Config", "field": "debug", "annotation": "bool"})
        self.assertIn("debug: bool", out)


_WRAP_SOURCE = '''def risky(value, other=2):
    """Docstring stays put."""
    result = value + other
    return result
'''


class WrapAstTests(_OpCase):
    def test_try_except_log_keeps_the_signature_and_every_statement(self) -> None:
        out = self.applied(_WRAP_SOURCE, "wrap_ast", {"target_fn": "risky", "transform": "try_except_log"})
        self.assertIn("    try:\n        result = value + other\n        return result\n", out)
        self.assertIn("    except Exception:", out)
        self.assertIn('"""Docstring stays put."""', out)
        self.assertIn("def risky(value, other=2):", out)

    def test_guard_none_inserts_a_guard_on_the_first_parameter(self) -> None:
        out = self.applied(_WRAP_SOURCE, "wrap_ast", {"target_fn": "risky", "transform": "guard_none"})
        self.assertIn("    if value is None:\n        return None\n", out)
        self.assertIn("    result = value + other", out)

    def test_decorate_prepends_the_decorator(self) -> None:
        out = self.applied(
            _WRAP_SOURCE, "wrap_ast",
            {"target_fn": "risky", "transform": "decorate", "decorator": "unittest.skip('scaffold')"},
        )
        self.assertTrue(out.startswith("@unittest.skip('scaffold')\ndef risky("))

    def test_signature_is_byte_identical_after_a_wrap(self) -> None:
        import ast

        out = self.applied(_WRAP_SOURCE, "wrap_ast", {"target_fn": "risky", "transform": "try_except_log"})
        before = next(n for n in ast.walk(ast.parse(_WRAP_SOURCE)) if isinstance(n, ast.FunctionDef))
        after = next(n for n in ast.walk(ast.parse(out)) if isinstance(n, ast.FunctionDef))
        self.assertEqual(
            ast.dump(before.args, include_attributes=False), ast.dump(after.args, include_attributes=False)
        )

    def test_a_multiline_string_body_is_refused_rather_than_silently_rewritten(self) -> None:
        # Re-indenting the body would add four spaces INSIDE the literal, changing its value. The
        # fingerprint check sees the changed Constant and refuses instead of shipping it.
        text = 'def f():\n    s = """line one\nline two"""\n    return s\n'
        result = self.realize(text, "wrap_ast", {"target_fn": "f", "transform": "try_except_log"})
        self.assertFalse(result.ok)
        self.assertIn("drop or alter a statement", result.reason)

    def test_unknown_transform_is_refused(self) -> None:
        result = self.realize(_WRAP_SOURCE, "wrap_ast", {"target_fn": "risky", "transform": "exec_this"})
        self.assertFalse(result.ok)
        self.assertIn("unknown transform", result.reason)

    def test_ambiguous_function_name_is_refused(self) -> None:
        text = "def dup():\n    pass\n\n\nclass A:\n    def dup(self):\n        pass\n"
        result = self.realize(text, "wrap_ast", {"target_fn": "dup", "transform": "guard_none"})
        self.assertFalse(result.ok)
        self.assertIn("refusing to guess", result.reason)

    def test_guard_none_refuses_a_zero_argument_function(self) -> None:
        result = self.realize("def f():\n    return 1\n", "wrap_ast", {"target_fn": "f", "transform": "guard_none"})
        self.assertFalse(result.ok)
        self.assertIn("no parameter", result.reason)


class RealizeContractTests(_OpCase):
    def test_unknown_op_degrades_to_a_refusal(self) -> None:
        result = self.realize(_MODULE, "delete_everything", {})
        self.assertFalse(result.ok)
        self.assertIn("unknown edit op", result.reason)
        self.assertEqual(result.old_string, "")

    def test_missing_op_name_degrades_to_a_refusal(self) -> None:
        self.assertFalse(edit_ops.realize(_MODULE, "", {}, suffix=".py").ok)

    def test_garbage_args_never_raise(self) -> None:
        for op in edit_ops.OPS:
            result = edit_ops.realize(_MODULE, op, {"anchor": None, "name": 5, "target_fn": []}, suffix=".py")
            self.assertFalse(result.ok, op)
            self.assertTrue(result.reason, op)

    def test_py_parses_reports_the_error_text(self) -> None:
        self.assertEqual(edit_ops.py_parses("x = 1\n"), "")
        self.assertIn("line", edit_ops.py_parses("def f(:\n"))


if __name__ == "__main__":
    unittest.main()
