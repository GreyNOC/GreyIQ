"""coder: the Claude (Anthropic) provider request shape and key handling.

These lock the wire contract the coding brain depends on. Claude Opus 4.7 and later REJECT
``temperature``/``top_p``/``top_k`` and the old ``thinking.budget_tokens`` form with a 400, so the
request must carry adaptive thinking + ``output_config.effort`` and no sampling params at all. The
stored API key must also never reach a network call empty, and an auth failure has to surface as a
readable CoderError rather than a raw SDK exception.

Key lifecycle: the UI never receives a stored key back, so a blank ``api_key`` in an update
deliberately means "keep the stored one" — otherwise saving any other brain setting would wipe it.
That overload left no way to *remove* a key (the delete branch of ``_store_secret`` was unreachable
for coder providers, so hand-editing runtime/secrets.json was the only way out). Both halves are
pinned below: blank still means keep, and the explicit ``clear_api_key`` sentinel really deletes.
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
import greyiq_api as g  # noqa: E402

ROOT = BACKEND_DIR.parent
HTML = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "public" / "app.js").read_text(encoding="utf-8")


class _APIStatusError(Exception):
    def __init__(self, message="status", status_code=500):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class _BadRequestError(_APIStatusError):
    pass


class _AuthenticationError(_APIStatusError):
    pass


class _FakeResponse:
    def __init__(self, text="ok", model="claude-opus-5", stop_reason="end_turn"):
        self.content = [types.SimpleNamespace(type="text", text=text)]
        self.model = model
        self.stop_reason = stop_reason


class _FakeMessages:
    """Records every create() kwarg set; optionally raises a scripted error per call."""

    def __init__(self, calls, errors, response=None):
        self._calls = calls
        self._errors = errors
        self._response = response

    def create(self, **kwargs):
        # Snapshot, don't alias: the capability ladder reuses and edits one extra_body across
        # attempts, so storing the live dict would let a later rung rewrite what an earlier call
        # recorded — and the real SDK serializes at call time, so a snapshot is the honest model.
        self._calls.append(copy.deepcopy(kwargs))
        if self._errors:
            error = self._errors.pop(0)
            if error is not None:
                raise error
        return self._response or _FakeResponse()


def _install_fake_sdk(calls, errors=None, response=None):
    """Put a stand-in `anthropic` module on sys.modules for the lazy import in _generate_anthropic."""
    module = types.ModuleType("anthropic")
    module.BadRequestError = _BadRequestError
    module.AuthenticationError = _AuthenticationError
    module.APIStatusError = _APIStatusError

    class _Anthropic:
        def __init__(self, api_key=None, timeout=None, max_retries=None):
            self.api_key = api_key
            self.messages = _FakeMessages(calls, errors if errors is not None else [], response)

    module.Anthropic = _Anthropic
    sys.modules["anthropic"] = module
    return module


class AnthropicProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calls: list[dict] = []
        self._orig_sdk = sys.modules.get("anthropic")
        self.addCleanup(self._restore_sdk)

    def _restore_sdk(self) -> None:
        if self._orig_sdk is None:
            sys.modules.pop("anthropic", None)
        else:
            sys.modules["anthropic"] = self._orig_sdk

    def _config(self, **anthropic_block):
        block = {"api_key": "sk-ant-test"}
        block.update(anthropic_block)
        return {"enabled": True, "provider": "anthropic", "anthropic": block}

    def _generate(self, cfg=None, errors=None, response=None):
        _install_fake_sdk(self.calls, errors, response)
        return coder.generate([{"role": "user", "content": "hi"}], cfg or self._config())

    def test_sends_adaptive_thinking_and_effort(self) -> None:
        # budget_tokens is removed on Opus 4.7+; adaptive thinking + effort is the supported form.
        result = self._generate()
        self.assertEqual(result["provider"], "anthropic")
        extra = self.calls[0]["extra_body"]
        self.assertEqual(extra["thinking"], {"type": "adaptive"})
        self.assertEqual(extra["output_config"], {"effort": "high"})

    def test_effort_is_configurable(self) -> None:
        self._generate(self._config(effort="xhigh"))
        self.assertEqual(self.calls[0]["extra_body"]["output_config"], {"effort": "xhigh"})

    def test_thinking_can_be_turned_off_without_losing_effort(self) -> None:
        # thinking and effort are separate controls. Bundling them meant a brain with thinking off
        # also silently lost its effort level and ran at the API default.
        self._generate(self._config(thinking=False, effort="low"))
        extra = self.calls[0]["extra_body"]
        self.assertNotIn("thinking", extra)
        self.assertEqual(extra["output_config"], {"effort": "low"})

    def test_never_sends_sampling_params(self) -> None:
        # temperature/top_p/top_k are rejected with a 400 on Opus 4.7 and later.
        self._generate()
        for banned in ("temperature", "top_p", "top_k"):
            self.assertNotIn(banned, self.calls[0])

    def test_missing_key_fails_before_any_network_call(self) -> None:
        with self.assertRaises(coder.CoderError) as ctx:
            self._generate(self._config(api_key=""))
        self.assertIn("API key is not set", str(ctx.exception))
        self.assertEqual(self.calls, [])

    def test_auth_failure_surfaces_a_readable_error(self) -> None:
        with self.assertRaises(coder.CoderError) as ctx:
            self._generate(errors=[_AuthenticationError("bad key", 401)])
        self.assertIn("authentication failed", str(ctx.exception))

    def test_model_rejecting_thinking_retries_without_it(self) -> None:
        # Older models reject thinking/output_config; the retry must drop them and still answer.
        # Assert the CONTRACT (nothing unsupported is resent), not whether the kwarg is present —
        # extra_body=None and an omitted extra_body are the same request to the SDK.
        result = self._generate(errors=[_BadRequestError("unexpected field output_config", 400)])
        self.assertEqual(result["provider"], "anthropic")
        self.assertEqual(len(self.calls), 2)
        self.assertIsNotNone(self.calls[0]["extra_body"])
        self.assertFalse(self.calls[1].get("extra_body"))
        # ...but caching is INDEPENDENT and must survive: the model rejected output_config, not
        # cache_control, and throwing away a capability it never complained about is pure loss.
        self.assertIsInstance(self.calls[1]["system"], list)

    def test_the_ladder_degrades_one_capability_per_rejection(self) -> None:
        # An old model can reject caching, then the schema, then thinking. A single-shot retry would
        # surface the second rejection as a hard failure; a bundled retry would throw away
        # capabilities the model actually supports.
        cfg = self._config()
        cfg["response_schema"] = {"type": "object"}
        result = self._generate(cfg, errors=[
            _BadRequestError("cache_control not supported", 400),
            _BadRequestError("json_schema format unsupported", 400),
            _BadRequestError("unexpected field output_config", 400),
        ])
        self.assertEqual(result["provider"], "anthropic")
        self.assertEqual(len(self.calls), 4)
        self.assertIsInstance(self.calls[0]["system"], list)            # full request
        self.assertIsInstance(self.calls[1]["system"], str)             # rung 1: caching dropped
        self.assertIn("format", self.calls[1]["extra_body"]["output_config"])
        self.assertNotIn("format", self.calls[2]["extra_body"]["output_config"])  # rung 2: schema
        self.assertEqual(self.calls[2]["extra_body"]["thinking"], {"type": "adaptive"})
        self.assertFalse(self.calls[3].get("extra_body"))               # rung 3: bare

    def test_a_request_rejected_at_every_rung_is_an_error_not_a_crash(self) -> None:
        with self.assertRaises(coder.CoderError) as ctx:
            self._generate(errors=[_BadRequestError("cache bad", 400),
                                   _BadRequestError("thinking bad", 400),
                                   _BadRequestError("still bad", 400),
                                   _BadRequestError("always bad", 400)])
        self.assertIn("rejected", str(ctx.exception))

    def test_unrelated_bad_request_is_not_retried(self) -> None:
        with self.assertRaises(coder.CoderError) as ctx:
            self._generate(errors=[_BadRequestError("max_tokens is too large", 400)])
        self.assertIn("rejected the request", str(ctx.exception))
        self.assertEqual(len(self.calls), 1)

    def test_default_model_is_a_current_claude_id(self) -> None:
        self._generate()
        self.assertEqual(self.calls[0]["model"], coder.DEFAULT_ANTHROPIC_MODEL)
        self.assertTrue(coder.DEFAULT_ANTHROPIC_MODEL.startswith("claude-"))

    def test_system_prompt_is_sent_as_a_cache_breakpoint(self) -> None:
        # A brain re-sends the same large system prefix on every call; caching it is the difference
        # between paying full input price each time and ~0.1x on repeats.
        self._generate()
        system = self.calls[0]["system"]
        self.assertIsInstance(system, list)
        self.assertEqual(system[0]["cache_control"], {"type": "ephemeral"})
        self.assertIn("GreyIQ", system[0]["text"])

    def test_a_model_rejecting_caching_retries_with_a_plain_system_prompt(self) -> None:
        result = self._generate(errors=[_BadRequestError("cache_control is not supported", 400)])
        self.assertEqual(result["provider"], "anthropic")
        self.assertEqual(len(self.calls), 2)
        self.assertIsInstance(self.calls[1]["system"], str)
        # Degrading caching must NOT also throw away adaptive thinking.
        self.assertEqual(self.calls[1]["extra_body"]["thinking"], {"type": "adaptive"})

    def test_response_schema_constrains_the_output(self) -> None:
        schema = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"],
                  "additionalProperties": False}
        cfg = self._config()
        cfg["response_schema"] = schema
        self._generate(cfg)
        fmt = self.calls[0]["extra_body"]["output_config"]["format"]
        self.assertEqual(fmt["type"], "json_schema")
        self.assertEqual(fmt["schema"], schema)
        # effort must survive alongside the schema — they share output_config.
        self.assertEqual(self.calls[0]["extra_body"]["output_config"]["effort"], "high")

    def test_a_model_rejecting_the_schema_keeps_thinking_and_effort(self) -> None:
        cfg = self._config()
        cfg["response_schema"] = {"type": "object"}
        result = self._generate(cfg, errors=[_BadRequestError("output_format schema unsupported", 400)])
        self.assertEqual(result["provider"], "anthropic")
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn("format", self.calls[1]["extra_body"]["output_config"])
        self.assertEqual(self.calls[1]["extra_body"]["output_config"]["effort"], "high")

    def test_truncated_answer_is_an_error_not_a_silent_partial(self) -> None:
        # max_tokens covers thinking AND the reply, so a deep turn can return a clipped answer.
        # Returning that as success would ship a half-written attack plan or clipped JSON.
        truncated = _FakeResponse(text="Step 1: send the reque", stop_reason="max_tokens")
        with self.assertRaises(coder.CoderError) as ctx:
            self._generate(response=truncated)
        self.assertIn("cut off", str(ctx.exception))
        self.assertIn("max_tokens", str(ctx.exception))

    def test_a_refusal_is_reported_as_a_refusal(self) -> None:
        refused = _FakeResponse(text="", stop_reason="refusal")
        with self.assertRaises(coder.CoderError) as ctx:
            self._generate(response=refused)
        self.assertIn("declined", str(ctx.exception))


class KeyHandlingTests(unittest.TestCase):
    """The stored key must never reach the UI, saving other settings must not wipe it, and an
    explicit clear must actually remove it."""

    def test_public_config_strips_the_key_and_reports_presence(self) -> None:
        safe = coder.public_config({"provider": "anthropic", "anthropic": {"api_key": "sk-ant-secret"}})
        self.assertNotIn("api_key", safe["anthropic"])
        self.assertTrue(safe["anthropic"]["has_api_key"])
        self.assertNotIn("sk-ant-secret", str(safe))

    def test_blank_key_in_an_update_preserves_the_stored_key(self) -> None:
        stored = {"provider": "anthropic", "anthropic": {"api_key": "sk-ant-keep"}}
        merged = coder.merge_update(stored, {"anthropic": {"api_key": "", "effort": "max"}})
        self.assertEqual(merged["anthropic"]["api_key"], "sk-ant-keep")
        self.assertEqual(merged["anthropic"]["effort"], "max")

    def test_whitespace_only_key_also_preserves_the_stored_key(self) -> None:
        merged = coder.merge_update({"anthropic": {"api_key": "sk-ant-keep"}}, {"anthropic": {"api_key": "   "}})
        self.assertEqual(merged["anthropic"]["api_key"], "sk-ant-keep")

    def test_a_real_key_in_an_update_replaces_the_stored_key(self) -> None:
        stored = {"provider": "anthropic", "anthropic": {"api_key": "sk-ant-old"}}
        merged = coder.merge_update(stored, {"anthropic": {"api_key": "sk-ant-new"}})
        self.assertEqual(merged["anthropic"]["api_key"], "sk-ant-new")

    def test_clear_flag_empties_the_key_and_is_never_stored(self) -> None:
        merged = coder.merge_update(
            {"anthropic": {"api_key": "sk-ant-keep", "model": "claude-opus-5"}},
            {"anthropic": {"clear_api_key": True}},
        )
        self.assertEqual(merged["anthropic"]["api_key"], "")
        self.assertNotIn("clear_api_key", merged["anthropic"])  # a command, not a setting
        self.assertEqual(merged["anthropic"]["model"], "claude-opus-5")  # nothing else disturbed

    def test_clear_outranks_a_key_sent_in_the_same_update(self) -> None:
        """A contradictory update fails safe: visibly no key beats silently keeping one."""
        for block in ({"clear_api_key": True, "api_key": "sk-new"}, {"api_key": "sk-new", "clear_api_key": True}):
            with self.subTest(order=list(block)):
                merged = coder.merge_update({"anthropic": {"api_key": "sk-old"}}, {"anthropic": dict(block)})
                self.assertEqual(merged["anthropic"]["api_key"], "")

    def test_falsey_clear_flags_leave_the_key_alone(self) -> None:
        for flag in (False, None, "", "false", "False", "0", "no", "off"):
            with self.subTest(flag=flag):
                merged = coder.merge_update(
                    {"anthropic": {"api_key": "sk-ant-keep"}},
                    {"anthropic": {"clear_api_key": flag, "api_key": ""}},
                )
                self.assertEqual(merged["anthropic"]["api_key"], "sk-ant-keep")
                self.assertNotIn("clear_api_key", merged["anthropic"])

    def test_clear_is_scoped_to_the_provider_that_asked(self) -> None:
        merged = coder.merge_update(
            {"anthropic": {"api_key": "sk-ant"}, "openai": {"api_key": "sk-oai"}},
            {"anthropic": {"clear_api_key": True}},
        )
        self.assertEqual(merged["anthropic"]["api_key"], "")
        self.assertEqual(merged["openai"]["api_key"], "sk-oai")

    def test_clear_requests_names_only_the_explicit_providers(self) -> None:
        update = {
            "enabled": True,
            "provider": "anthropic",
            "anthropic": {"clear_api_key": True},
            "openai": {"api_key": ""},          # blank is "keep", not a clear request
            "local": {"api_key": "sk-local"},
        }
        self.assertEqual(coder.api_key_clear_requests(update), {"anthropic"})

    def test_clear_requests_tolerates_empty_and_missing_updates(self) -> None:
        self.assertEqual(coder.api_key_clear_requests(None), set())
        self.assertEqual(coder.api_key_clear_requests({}), set())
        self.assertEqual(coder.api_key_clear_requests({"enabled": True, "provider": "off"}), set())


class SecretStoreClearTests(unittest.TestCase):
    """End-to-end through the API runtime: does the key actually leave secrets.json?"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_runtime_dir = g.RUNTIME_DIR
        self._orig_secrets = g.SECRETS_PATH
        g.RUNTIME_DIR = Path(self._tmp.name)
        g.SECRETS_PATH = Path(self._tmp.name) / "secrets.json"

    def tearDown(self) -> None:
        g.RUNTIME_DIR = self._orig_runtime_dir
        g.SECRETS_PATH = self._orig_secrets
        self._tmp.cleanup()

    def _runtime_config_text(self) -> str:
        path = g.RUNTIME_DIR / "solin_runtime_config.json"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def _save_anthropic_key(self, key: str = "sk-ant-SECRET") -> dict:
        return g.runtime.save_coder_config(
            {"enabled": True, "provider": "anthropic", "anthropic": {"model": "claude-opus-5", "api_key": key}}
        )

    def test_saving_a_key_puts_it_in_the_secrets_store_only(self) -> None:
        public = self._save_anthropic_key()
        self.assertTrue(public["anthropic"]["has_api_key"])
        self.assertEqual(g._load_secrets()["anthropic"], "sk-ant-SECRET")
        self.assertNotIn("sk-ant-SECRET", self._runtime_config_text())

    def test_blank_key_on_a_later_save_preserves_the_stored_key(self) -> None:
        self._save_anthropic_key()
        public = g.runtime.save_coder_config(
            {"enabled": True, "provider": "anthropic", "anthropic": {"model": "claude-sonnet-5", "api_key": ""}}
        )
        self.assertTrue(public["anthropic"]["has_api_key"])
        self.assertEqual(public["anthropic"]["model"], "claude-sonnet-5")
        self.assertEqual(g._load_secrets()["anthropic"], "sk-ant-SECRET")

    def test_clear_removes_the_entry_from_the_secrets_store(self) -> None:
        self._save_anthropic_key()
        public = g.runtime.save_coder_config({"anthropic": {"clear_api_key": True}})
        self.assertFalse(public["anthropic"]["has_api_key"])
        self.assertNotIn("anthropic", g._load_secrets())
        self.assertNotIn("sk-ant-SECRET", g.SECRETS_PATH.read_text(encoding="utf-8"))
        self.assertNotIn("sk-ant-SECRET", self._runtime_config_text())

    def test_clear_does_not_disturb_the_selected_brain_or_other_fields(self) -> None:
        self._save_anthropic_key()
        public = g.runtime.save_coder_config({"anthropic": {"clear_api_key": True}})
        self.assertTrue(public["enabled"])
        self.assertEqual(public["provider"], "anthropic")
        self.assertEqual(public["anthropic"]["model"], "claude-opus-5")
        self.assertNotIn("clear_api_key", public["anthropic"])
        self.assertNotIn("clear_api_key", json.loads(self._runtime_config_text())["coder"]["anthropic"])

    def test_clear_leaves_other_providers_keys_in_place(self) -> None:
        self._save_anthropic_key()
        g.runtime.save_coder_config({"enabled": True, "provider": "openai", "openai": {"api_key": "sk-oai-SECRET"}})
        public = g.runtime.save_coder_config({"anthropic": {"clear_api_key": True}})
        self.assertFalse(public["anthropic"]["has_api_key"])
        self.assertTrue(public["openai"]["has_api_key"])
        self.assertEqual(g._load_secrets()["openai"], "sk-oai-SECRET")

    def test_clearing_a_provider_with_no_stored_key_is_a_no_op(self) -> None:
        public = g.runtime.save_coder_config({"openai": {"clear_api_key": True}})
        self.assertFalse(public["openai"]["has_api_key"])
        self.assertEqual(g._load_secrets(), {})

    def test_a_cleared_key_stays_gone_across_a_later_blank_save(self) -> None:
        """The regression that matters: "keep" must not resurrect what "clear" removed."""
        self._save_anthropic_key()
        g.runtime.save_coder_config({"anthropic": {"clear_api_key": True}})
        public = g.runtime.save_coder_config(
            {"enabled": True, "provider": "anthropic", "anthropic": {"api_key": ""}}
        )
        self.assertFalse(public["anthropic"]["has_api_key"])
        self.assertNotIn("anthropic", g._load_secrets())

    def test_a_new_key_can_be_saved_after_a_clear(self) -> None:
        self._save_anthropic_key()
        g.runtime.save_coder_config({"anthropic": {"clear_api_key": True}})
        public = self._save_anthropic_key("sk-ant-REPLACEMENT")
        self.assertTrue(public["anthropic"]["has_api_key"])
        self.assertEqual(g._load_secrets()["anthropic"], "sk-ant-REPLACEMENT")


class ClearKeyUiContractTests(unittest.TestCase):
    """The clear path has to be reachable: a button wired to the sentinel, shown only when a key
    is actually stored."""

    def test_the_brain_panel_has_a_clear_saved_key_control(self) -> None:
        self.assertIn('id="brainKeyActions"', HTML)
        self.assertIn('id="brainClearKey"', HTML)
        self.assertIn("Clear saved key", HTML)

    def test_the_control_is_hidden_until_a_key_is_stored(self) -> None:
        self.assertIn('<div class="folder-actions" id="brainKeyActions" hidden>', HTML)
        self.assertIn('els.brainKeyActions.hidden = !(fields.includes("api_key") && block.has_api_key)', JS)

    def test_the_button_posts_the_clear_sentinel_for_the_selected_provider(self) -> None:
        self.assertIn('els.brainClearKey?.addEventListener("click"', JS)
        self.assertIn("{ [provider]: { clear_api_key: true } }", JS)
        self.assertIn("window.confirm(`Remove the saved ${label} API key", JS)

    def test_a_normal_save_still_sends_a_blank_key_as_keep(self) -> None:
        self.assertIn("block.api_key = els.brainApiKey.value; // blank = keep saved", JS)
        self.assertIn('block.has_api_key ? "saved — leave blank to keep" : "paste API key"', JS)


if __name__ == "__main__":
    unittest.main()
