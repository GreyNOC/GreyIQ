"""The chat path must gate on `reasoning_brain_enabled`, never on `coder_enabled`.

The deterministic ("offline") coder is a REAL, selectable coding capability — template + AST
edits driven through the Workbench agent — so `coder_enabled` answers True for it by design.
It has no chat completion at all: `coder.generate()` raises `CoderError` for those providers
deliberately.

So a chat path gated on `coder_enabled` takes the LLM branch, `generate` raises, and the caller
returns a "could not respond" error dict for EVERY message — including plain non-coding
questions. Because that dict is non-None, it short-circuits the reply chain and shadows both the
curated offline domain brain and the TinyGPT fallback underneath it. That is strictly worse than
selecting provider "off", which routes to the fallback cleanly.

`coder.reasoning_brain_enabled`'s own docstring records this trap (the hunt planner hit it and
flew blind with an empty plan). These tests pin the CHAT end of the same contract.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import coder  # noqa: E402
import greyiq_api  # noqa: E402


class ChatBrainRoutingTests(unittest.TestCase):
    def _runtime(self, provider: str) -> greyiq_api.GreyIQRuntime:
        """A runtime stub carrying only what the gate reads.

        __new__ skips __init__ on purpose: the gate must return before touching any other
        attribute, so a bare object is enough — and if a future edit makes the gate reach
        further, this fails loudly instead of silently passing.
        """
        runtime = greyiq_api.GreyIQRuntime.__new__(greyiq_api.GreyIQRuntime)
        runtime._coder_config = lambda: {"enabled": True, "provider": provider}  # type: ignore[method-assign]
        return runtime

    def _request(self) -> greyiq_api.ChatRequest:
        # A plainly NON-coding question: the regression made even this return the coder refusal.
        return greyiq_api.ChatRequest(message="what is a subnet mask?")

    def test_deterministic_providers_do_not_intercept_chat(self) -> None:
        for provider in sorted(coder.PROVIDERS_DETERMINISTIC):
            with self.subTest(provider=provider):
                self.assertTrue(coder.coder_enabled({"enabled": True, "provider": provider}))
                self.assertIsNone(
                    self._runtime(provider)._coder_reply(self._request()),
                    "the deterministic coder has no chat completion, so _coder_reply must decline "
                    "and let the domain brain / TinyGPT fallback answer",
                )

    def test_provider_off_still_declines(self) -> None:
        for provider in ("off", "none", "disabled", ""):
            with self.subTest(provider=provider):
                self.assertIsNone(self._runtime(provider)._coder_reply(self._request()))

    def test_a_real_reasoning_brain_is_still_routed_to_the_coder(self) -> None:
        """The narrowed gate must not also turn OFF chat for the providers that can answer."""
        for provider in ("ollama", "anthropic", "openai"):
            with self.subTest(provider=provider):
                self.assertTrue(coder.reasoning_brain_enabled({"enabled": True, "provider": provider}))

    def test_the_gate_reads_the_narrow_predicate(self) -> None:
        """Pins the call itself, so swapping the predicate back fails here even if a future
        refactor changes what generate() does for the deterministic providers."""
        import inspect

        source = inspect.getsource(greyiq_api.GreyIQRuntime._coder_reply)
        self.assertIn("reasoning_brain_enabled", source)
        self.assertNotIn("if not coder.coder_enabled(raw):", source)


if __name__ == "__main__":
    unittest.main()
