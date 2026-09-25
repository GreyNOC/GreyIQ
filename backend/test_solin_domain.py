"""Contract tests for the offline domain brain.

The load-bearing one is :meth:`ComposeVerbatimTests.test_compose_answer_body_is_verbatim`:
it asserts mechanically that the answer body is a CONTIGUOUS slice of a bundled card, which
is what guarantees the tiny (well under 10M-param) TinyGPT model never authors a sentence of security
advice. The other load-bearing one is :meth:`TorchFreeTests` — the shipped build has no
torch and no solin_core, so a single stray import there would silently return every real
user to ``fallback_reply``'s canned platitude.
"""

from __future__ import annotations

import difflib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import solin_domain  # noqa: E402
from bughunter.bounty import VULN_CLASSES  # noqa: E402

SEED_DIR = BACKEND_DIR / "seed"

# --- routing fixtures ---------------------------------------------------------------
#
# THE EVIDENCE BEHIND solin_domain.MIN_SCORE / MIN_SCORE_RELAXED. Ordinary English questions
# with no security content whatsoever. Every one of them used to be answerable: before the
# out-of-vocabulary weighting fix in ``_score_card``, "what is a good name for a dog" scored
# 0.330 against a bug-bounty card (over the 0.32 bar of the day) and was answered with the
# "Proof of impact standard" playbook plus a citation and a confidence number, because "dog"
# — the one word proving the question is off-domain — was charged LESS than pack filler like
# "name". Both directions are asserted below: these must return nothing, ON_DOMAIN_QUESTIONS
# must still match. Fixing the false positives by breaking recall is not a fix.
OFF_DOMAIN_QUESTIONS = (
    "what is a good name for a dog", "what is the capital of France",
    "what is the meaning of life", "what time is the game tonight",
    "recommend a movie to watch", "how do I bake sourdough bread",
    "who won the world series last year", "what is the weather in Seattle tomorrow",
    "my cat keeps knocking things off the table", "translate good morning into spanish",
    "how far is the airport from downtown", "what should I cook for dinner tonight",
    "tell me a joke about penguins", "how do I change a flat tire",
    "what is the tallest mountain in the world", "help me write a birthday card for my mom",
    "how many ounces in a gallon", "when does daylight saving time end",
    "is it going to rain this weekend", "what movies are playing this weekend",
    "what is a good gift for a five year old", "how long does it take to boil an egg",
    "who painted the mona lisa", "what is the population of Japan",
    "my knee hurts when I run", "recommend a podcast about history",
    "how do I get rid of fruit flies", "what should I name my new kitten",
    "when is the next full moon", "how do I fold a fitted sheet",
    "what is the best time to visit Iceland", "explain photosynthesis to a child",
    "what is the difference between jam and jelly", "how do I keep basil alive indoors",
    "who wrote pride and prejudice", "what is a reasonable tip at a restaurant",
    "how do I teach my dog to sit", "what is the plot of hamlet",
    "how much water should I drink a day", "what does my dream about flying mean",
)

# Real operator questions the bundled packs genuinely answer. These must clear the STRICT
# threshold — the guard against "fixing" the noise floor by raising the bar until nothing
# matches. Three of them (scope handling, secrets in source, API BOLA) were BELOW the old
# 0.32 bar and are recall the scorer fix bought back.
ON_DOMAIN_QUESTIONS = (
    "how do I prove an IDOR with two accounts?", "what should I do next on this bounty",
    "red team rules of engagement", "what does WPS unknown mean in a survey",
    "how do I set up ollama", "how do I test for prototype pollution",
    "how do I write the bounty report", "how do I find SSRF in a webhook feature",
    "what evidence do I need for a proof of impact",
    "how should I handle scope for a bug bounty program",
    "explain the plan change verify explain loop", "how do I analyze a wardrive capture",
    "what is a good way to test for xss", "how do I escalate an open redirect",
    "what are the rules for authorized testing", "how do I check for request smuggling",
    "what should a bounty report contain", "how do I confirm a subdomain takeover",
    "what does the automated web pass cover",
    "how do I test an API for broken object level authorization",
    "how do I triage a rogue access point", "what encryption should a wifi network use",
    "what is the workbench verify step", "how do I handle secrets found in source code",
)

# A minimal airodump-ng export: one WPA2 net, one open net, one WEP net. Enough to produce
# findings AND a non-empty `undetermined` ledger (airodump CSV carries neither WPS nor PMF
# state), which is the property the chat wrapper must never drop.
AIRODUMP_FIXTURE = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication,"
    " Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
    "00:0B:85:AA:BB:01, 2026-07-30 10:00:00, 2026-07-30 10:05:00,   6,  195, WPA2, CCMP, PSK,"
    " -42,      120,        0,   0.  0.  0.  0,   8, CorpWiFi, \r\n"
    "24:0A:C4:11:22:33, 2026-07-30 10:00:10, 2026-07-30 10:05:10,  11,  130, OPN,  ,   ,"
    "  -1,       40,        0,   0.  0.  0.  0,  10, FreeCoffee, \r\n"
    "00:14:6C:DE:AD:02, 2026-07-30 10:01:00, 2026-07-30 10:06:00,   1,   54, WEP , WEP ,   ,"
    " -70,       33,       12,   0.  0.  0.  0,   0, , \r\n"
)


def _seed_pack() -> dict[str, list[solin_domain.DomainCard]]:
    return solin_domain.load_pack(SEED_DIR, None)


class TorchFreeTests(unittest.TestCase):
    def test_domain_brain_imports_without_torch(self) -> None:
        """solin_domain must never pull in torch/solin_core — the shipped build has neither,
        and this module is the only thing standing between a frozen install and a canned
        platitude."""
        src = (BACKEND_DIR / "solin_domain.py").read_text(encoding="utf-8")
        for banned in ("import torch", "import solin_core", "from solin_core", "import training_runtime"):
            self.assertNotIn(banned, src, f"solin_domain must stay free of '{banned}'")

    def test_importing_the_module_loads_no_heavy_runtime(self) -> None:
        """The source scan above catches a literal import; this catches a transitive one."""
        code = (
            "import sys; sys.path.insert(0, '.')\n"
            "import solin_domain\n"
            "solin_domain.load_pack('seed', None)\n"
            "print('torch', 'torch' in sys.modules)\n"
            "print('solin_core', 'solin_core' in sys.modules)\n"
            "print('numpy', 'numpy' in sys.modules)\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], cwd=str(BACKEND_DIR),
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("torch False", proc.stdout)
        self.assertIn("solin_core False", proc.stdout)
        self.assertIn("numpy False", proc.stdout)


class PackLoadingTests(unittest.TestCase):
    def test_seed_pack_loads_every_authored_domain(self) -> None:
        pack = _seed_pack()
        for domain in ("bounty", "webapp", "redteam", "wardrive", "coding"):
            self.assertIn(domain, pack, f"seed/domain/{domain}.md produced no cards")
            self.assertTrue(pack[domain], f"domain '{domain}' is empty")

    def test_card_order_is_deterministic(self) -> None:
        """Cards are persisted/replayed through citations, so a set-derived (hash-ordered)
        pack would make the same question cite a different card between runs.

        Run against a FIXED temp fixture rather than the live seed tree: the seed/runtime
        packs are user-editable (and edited by other tooling), and a file rewritten between
        the two loads would fail this for a reason that has nothing to do with ordering."""
        with tempfile.TemporaryDirectory() as tmp:
            for kind, names in (("domain", ("alpha.md", "beta.md")), ("bounty", ("zeta.md",))):
                directory = Path(tmp) / kind
                directory.mkdir(parents=True)
                for name in names:
                    (directory / name).write_text(
                        "# T\n\n"
                        "## Second section\nA body long enough to clear the minimum-length gate for a card.\n\n"
                        "## First section\nAnother body long enough to clear the minimum-length gate here.\n",
                        encoding="utf-8",
                    )
            first = [card.card_id for card in solin_domain.all_cards(solin_domain.load_pack(tmp, None))]
            solin_domain._PACK_CACHE.clear()
            pack = solin_domain.load_pack(tmp, None)
            second = [card.card_id for card in solin_domain.all_cards(pack)]

            self.assertEqual(first, second, "pack order must not depend on cache state or FS order")
            self.assertEqual(len(set(second)), len(second), "card ids must be unique")
            # all_cards flattens domain-by-domain in sorted domain order; within a domain the
            # cards must be sorted by id, NOT by the order the headings happened to appear.
            for domain, cards in pack.items():
                ids = [card.card_id for card in cards]
                self.assertEqual(ids, sorted(ids), domain)
            self.assertIn("first-section", second[0])

    def test_shipped_card_ids_are_unique(self) -> None:
        ids = [card.card_id for card in solin_domain.all_cards(_seed_pack())]
        self.assertTrue(ids)
        self.assertEqual(len(set(ids)), len(ids), "two shipped sections collide on one card id")

    def test_missing_seed_dir_degrades_to_empty_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(solin_domain.load_pack(Path(tmp) / "nope", None), {})
            self.assertEqual(solin_domain.match_cards("how do I prove an IDOR", {}), [])

    def test_corrupt_markdown_degrades_silently(self) -> None:
        """A garbled/binary pack file must cost that file only — never the whole pack."""
        with tempfile.TemporaryDirectory() as tmp:
            domain_dir = Path(tmp) / "domain"
            domain_dir.mkdir(parents=True)
            (domain_dir / "broken.md").write_bytes(b"\xff\xfe\x00\x00 not markdown at all")
            (domain_dir / "good.md").write_text(
                "# Good\n\n## Prove an IDOR\n"
                "Replay the request as a second account and swap the object identifier.\n"
                "- Capture both request/response pairs and the data class exposed.\n",
                encoding="utf-8",
            )
            pack = solin_domain.load_pack(tmp, None)
            self.assertIn("good", pack)
            self.assertEqual([card.title for card in pack["good"]], ["Prove an IDOR"])

    def test_runtime_override_replaces_the_seed_copy(self) -> None:
        with tempfile.TemporaryDirectory() as seed, tempfile.TemporaryDirectory() as runtime:
            for base, body in ((seed, "Bundled wording."), (runtime, "Operator wording.")):
                directory = Path(base) / "domain"
                directory.mkdir(parents=True)
                (directory / "bounty.md").write_text(
                    f"# B\n\n## Scope first\n{body}\n"
                    "- Record allowed hosts, accounts, methods, and rate limits before testing.\n",
                    encoding="utf-8",
                )
            cards = solin_domain.load_pack(seed, runtime)["bounty"]
            self.assertEqual(len(cards), 1)
            self.assertIn("Operator wording.", cards[0].body)
            self.assertNotIn("Bundled wording.", cards[0].body)


class MatchingTests(unittest.TestCase):
    def test_on_topic_question_matches_the_right_card(self) -> None:
        cards = solin_domain.match_cards("how do I prove an IDOR with two accounts?", _seed_pack())
        self.assertTrue(cards)
        self.assertIn("idor", cards[0].card_id.lower())

    def test_off_topic_and_casual_input_returns_nothing(self) -> None:
        """Below threshold the caller must fall through to EXACTLY today's pipeline."""
        pack = _seed_pack()
        for query in ("hi", "hello there", "thanks!", "ok", "what is the capital of France", "tell me a joke"):
            self.assertEqual(solin_domain.match_cards(query, pack), [], f"{query!r} should not match")

    def test_ranking_is_stable_across_calls(self) -> None:
        pack = _seed_pack()
        query = "what should I do next on this bounty"
        self.assertEqual(
            [c.card_id for c in solin_domain.match_cards(query, pack)],
            [c.card_id for c in solin_domain.match_cards(query, pack)],
        )


class ScorerNoiseFloorTests(unittest.TestCase):
    """The scorer must not have a noise floor at or above its own threshold.

    Regression cover for the defect where an ordinary English sentence was answered with a
    security playbook. Two independent roots, both asserted here: out-of-vocabulary tokens
    were charged less than pack boilerplate, and the character-similarity terms could carry a
    match with zero token overlap."""

    def test_the_reported_question_no_longer_matches(self) -> None:
        """The exact reproducer: 'what is a good name for a dog' -> bounty playbook @ 0.330."""
        pack = _seed_pack()
        scored = solin_domain.match_cards_scored(
            "what is a good name for a dog", pack, min_score=0.0
        )
        self.assertTrue(scored, "fixture sanity: the pack must have loaded")
        self.assertLess(
            scored[0][1], solin_domain.MIN_SCORE_RELAXED,
            f"an off-domain question still scores {scored[0][1]:.3f} against {scored[0][0].card_id}",
        )

    def test_off_domain_questions_match_nothing_at_either_threshold(self) -> None:
        """Both bars matter: the STRICT one guards a working engine's answer, and the RELAXED
        one is what greyiq_api's except handler uses — the normal path on every shipped
        torch-free build, where it previously answered 5 of these with a playbook."""
        pack = _seed_pack()
        for threshold in (solin_domain.MIN_SCORE, solin_domain.MIN_SCORE_RELAXED):
            for query in OFF_DOMAIN_QUESTIONS:
                matched = solin_domain.match_cards_scored(query, pack, min_score=threshold)
                self.assertEqual(
                    matched, [],
                    f"{query!r} matched {[c.card_id for c, _ in matched]} at min_score={threshold}",
                )

    def test_on_domain_questions_all_still_match(self) -> None:
        """The other direction. A scorer that answers nothing has no false positives either."""
        pack = _seed_pack()
        for query in ON_DOMAIN_QUESTIONS:
            self.assertTrue(
                solin_domain.match_cards(query, pack),
                f"{query!r} is a real operator question and must still reach a card",
            )

    def test_relaxed_threshold_stays_above_the_measured_off_domain_ceiling(self) -> None:
        """The tuning invariant, enforced rather than commented.

        ``MIN_SCORE * 0.75`` used to put the relaxed bar BELOW the scorer's own off-domain
        noise floor, which is what made the shipped path the WORST-behaved one. Any future
        retune of either constant has to keep this ordering or fail here."""
        pack = _seed_pack()
        ceiling = 0.0
        worst = ""
        for query in OFF_DOMAIN_QUESTIONS:
            scored = solin_domain.match_cards_scored(query, pack, min_score=0.0)
            if scored and scored[0][1] > ceiling:
                ceiling, worst = scored[0][1], query
        self.assertLess(
            ceiling, solin_domain.MIN_SCORE_RELAXED,
            f"off-domain ceiling {ceiling:.3f} ({worst!r}) reaches the relaxed bar "
            f"{solin_domain.MIN_SCORE_RELAXED}",
        )
        self.assertLessEqual(solin_domain.MIN_SCORE_RELAXED, solin_domain.MIN_SCORE)

    def test_unknown_token_outweighs_every_word_the_pack_knows(self) -> None:
        """The root cause in one assertion. 'dog' appears in no card, so it is the most
        informative word in the question and is definitionally uncovered; charging it a flat
        1.0 put it BELOW pack filler ('name' scored 2.96) and inverted coverage."""
        cards = solin_domain.all_cards(_seed_pack())
        idf = solin_domain._pack_idf(cards)
        self.assertTrue(idf.weights)
        self.assertGreater(
            idf.unseen, max(idf.weights.values()),
            "an out-of-vocabulary token must weigh more than the pack's rarest known token",
        )
        self.assertNotIn("dog", idf.weights, "fixture assumption: the pack never says 'dog'")

    def test_character_similarity_alone_cannot_carry_a_match(self) -> None:
        """A card sharing NO content word with the query scores exactly zero, however similar
        the two strings look character by character.

        char_jaccard (0.25) + sequence_ratio (0.20) are worth 0.45 of the score and both are
        computed over raw text, so ungated they clear even the strict bar on their own: this
        fixture measures 0.282 of pure lexical similarity with an empty token intersection."""
        title = "abcdefghijklmnopqrs3"
        body = "abcdefghijklmnopqrs4 abcdefghijklmnopqrs5 abcdefghijklmnopqrs6"
        query = ("abcdefghijklmnopqrs1 abcdefghijklmnopqrs2 "
                 "abcdefghijklmnopqrs9 abcdefghijklmnopqrs0")
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "domain"
            directory.mkdir(parents=True)
            (directory / "lex.md").write_text(f"# L\n\n## {title}\n{body}\n", encoding="utf-8")
            pack = solin_domain.load_pack(tmp, None)
            card = solin_domain.all_cards(pack)[0]
            features = solin_domain._features(card)
            tokens = frozenset(solin_domain.tokenize(query))

            # Fixture integrity: no token overlap, no title hit, no trigger — the ONLY thing
            # that could score this pair is character similarity.
            self.assertEqual(tokens & features.tokens, frozenset())
            self.assertEqual(tokens & features.title_tokens, frozenset())
            self.assertEqual(card.triggers, ())
            lexical = (
                solin_domain._jaccard(solin_domain._char_grams(query), features.head_grams) * 0.25
                + difflib.SequenceMatcher(None, query, features.head.lower()).ratio() * 0.20
            )
            self.assertGreater(
                lexical, solin_domain.MIN_SCORE,
                "fixture is too weak to prove anything: lexical similarity must exceed the bar",
            )

            scored = solin_domain.match_cards_scored(query, pack, min_score=0.0)
            self.assertEqual([score for _card, score in scored], [0.0])
            self.assertEqual(solin_domain.match_cards(query, pack), [])

    def test_boilerplate_overlap_alone_does_not_open_the_gate(self) -> None:
        """Sharing only a word the pack uses everywhere is not overlap: it cannot say WHICH
        card answers the question, so it must not license the lexical terms either."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "domain"
            directory.mkdir(parents=True)
            for index in range(4):
                (directory / f"pack{index}.md").write_text(
                    f"# P{index}\n\n## Section {index} heading\n"
                    "pervasive filler wording repeated across every single card in this pack.\n"
                    f"marker{index} distinguishes this one from the others in the pack.\n",
                    encoding="utf-8",
                )
            pack = solin_domain.load_pack(tmp, None)
            cards = solin_domain.all_cards(pack)
            idf = solin_domain._pack_idf(cards)
            # "pervasive" is in every card -> boilerplate; "marker0" is in exactly one.
            # (Deliberately not a word ending in s/es/ies: `_fold` would rewrite the token
            # and the fixture would be asserting something other than what it reads as.)
            self.assertEqual(idf.document_frequency.get("pervasive"), len(cards))
            self.assertEqual(idf.document_frequency.get("marker0"), 1)
            scored = solin_domain.match_cards_scored(
                "pervasive pervasive filler", pack, limit=len(cards), min_score=0.0
            )
            self.assertEqual(len(scored), len(cards))
            self.assertEqual(
                [score for _card, score in scored], [0.0] * len(cards),
                "boilerplate-only overlap must score zero on every card",
            )
            # The distinguishing token still routes, so the gate did not break retrieval.
            matched = solin_domain.match_cards("marker0 pervasive wording", pack)
            self.assertTrue(matched)
            self.assertIn("pack0", matched[0].card_id)


class ExactClassNameTests(unittest.TestCase):
    """A bare class name is a closed-vocabulary lookup, not a fuzzy one-word guess.

    ``MIN_QUERY_TERMS = 2`` rejects any single-token message, which is right for the card
    matcher (one word cannot pick between 73 playbooks) but wrong for ``VULN_CLASSES``:
    typing "SSRF" used to fall through to the tiny model's platitude while "explain SSRF"
    got a real answer."""

    def test_bare_class_names_route_to_the_class_table(self) -> None:
        for message, expected in (
            ("SSRF", "ssrf"), ("ssrf", "ssrf"), ("ssrf?", "ssrf"), ("  XXE  ", "xxe"),
            ("idor", "access-control"), ("IDOR", "access-control"),
            ("prototype pollution", "prototype-pollution"),
            ("prototype-pollution", "prototype-pollution"),
            ("sql injection", "sqli"), ("jwt", "jwt"),
        ):
            self.assertEqual(solin_domain.detect_class_query(message), expected, message)

    def test_greetings_and_ordinary_words_still_fall_through(self) -> None:
        """The guard MIN_QUERY_TERMS exists for these; the exception must not readmit them."""
        for message in (
            "hi", "ok", "thanks", "thanks!", "hello there", "yes", "hey", "sup", "cool",
            "what is a good name for a dog", "dog", "France", "help",
        ):
            self.assertIsNone(solin_domain.exact_class_name(message), message)
            self.assertIsNone(solin_domain.detect_class_query(message), message)

    def test_every_vuln_class_id_is_reachable_as_a_bare_message(self) -> None:
        """A class added to VULN_CLASSES is typeable on its own from day one."""
        for class_id in VULN_CLASSES:
            self.assertEqual(solin_domain.exact_class_name(class_id), class_id, class_id)
            self.assertEqual(
                solin_domain.exact_class_name(class_id.replace("-", " ")), class_id, class_id
            )

    def test_a_sentence_containing_a_class_is_not_an_exact_match(self) -> None:
        """Exact means exact — a methodology question still belongs to the card matcher."""
        for message in ("how do I find XSS on this app", "ssrf on example.com", "xss payload"):
            self.assertIsNone(solin_domain.exact_class_name(message), message)


class ComposeVerbatimTests(unittest.TestCase):
    def test_verbatim_excerpt_is_a_substring_of_every_card(self) -> None:
        for card in solin_domain.all_cards(_seed_pack()):
            excerpt = solin_domain.verbatim_excerpt(card, "scope proof impact request response")
            self.assertTrue(excerpt.strip(), card.card_id)
            self.assertIn(excerpt, card.body, f"{card.card_id}: excerpt is not verbatim")

    def test_compose_answer_body_is_verbatim(self) -> None:
        """THE load-bearing assertion: the composed answer's body is copied out of the card
        character for character, so no model can generate security advice on this path."""
        pack = _seed_pack()
        for query in (
            "how do I prove an IDOR with two accounts?",
            "what should I do next on this bounty",
            "red team rules of engagement",
            "what does WPS unknown mean in a survey",
            "how do I set up ollama",
            "how do I test for prototype pollution",
        ):
            cards = solin_domain.match_cards(query, pack)
            self.assertTrue(cards, query)
            answer = solin_domain.compose_answer(query, cards)
            excerpt = solin_domain.verbatim_excerpt(cards[0], query)
            self.assertIn(excerpt, cards[0].body, query)
            self.assertIn(excerpt, answer, query)

    def test_composed_answer_lines_all_come_from_the_card_or_the_fixed_frame(self) -> None:
        """Stronger than substring: EVERY non-blank line is either a card line or one of the
        composer's authored frame lines. Nothing in between can be model output."""
        pack = _seed_pack()
        query = "how do I write the bounty report"
        cards = solin_domain.match_cards(query, pack)
        self.assertTrue(cards)
        answer = solin_domain.compose_answer(query, cards, "bug_bounty_hunt")
        card_lines = {line.strip() for line in cards[0].body.split("\n")}
        frame = set(solin_domain._OPENERS.values())
        frame.add(f"**{cards[0].title}**")
        frame.add(f"Source: {cards[0].source_path}")
        for extra in cards[1:3]:
            frame.add(f"Also in the offline pack: {extra.title} — {extra.source_path}")
        for line in answer.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            self.assertTrue(
                stripped in card_lines or stripped in frame,
                f"line is neither card content nor the fixed frame: {stripped!r}",
            )

    def test_every_composed_answer_carries_a_source_line(self) -> None:
        pack = _seed_pack()
        for domain, cards in pack.items():
            answer = solin_domain.compose_answer("scope proof impact", cards[:1])
            self.assertIn("\nSource: ", answer, domain)
            self.assertIn(cards[0].source_path, answer, domain)

    def test_compose_answer_with_no_cards_is_empty(self) -> None:
        self.assertEqual(solin_domain.compose_answer("anything", []), "")


class VulnClassTests(unittest.TestCase):
    def test_explain_class_covers_every_vuln_class(self) -> None:
        """A class added to VULN_CLASSES for the hunt engine cannot silently lose chat
        coverage."""
        for class_id, meta in VULN_CLASSES.items():
            rendered = solin_domain.explain_class(class_id)
            self.assertTrue(rendered, class_id)
            self.assertIn(str(meta["name"]), rendered, class_id)
            self.assertIn(str(meta["cwe"]), rendered, class_id)
            for step in meta.get("checklist") or []:
                self.assertIn(str(step), rendered, class_id)

    def test_explain_class_rejects_an_unknown_id(self) -> None:
        self.assertEqual(solin_domain.explain_class("not-a-class"), "")
        self.assertEqual(solin_domain.explain_class(""), "")

    def test_detect_class_query_is_narrow(self) -> None:
        self.assertEqual(solin_domain.detect_class_query("what is SSRF"), "ssrf")
        self.assertEqual(solin_domain.detect_class_query("explain xxe"), "xxe")
        self.assertEqual(solin_domain.detect_class_query("what is an IDOR"), "access-control")
        # A methodology question belongs to the card matcher, not the class table.
        self.assertIsNone(solin_domain.detect_class_query("how do I find XSS on this app"))
        # Two classes named at once is ambiguous — fall through rather than pick one.
        self.assertIsNone(solin_domain.detect_class_query("explain sqli and xss"))

    def test_webapp_pack_is_generated_from_vuln_classes(self) -> None:
        """seed/domain/webapp.md is the generator's output, byte for byte. Adding a class
        without regenerating fails HERE instead of quietly losing offline coverage."""
        on_disk = (SEED_DIR / "domain" / "webapp.md").read_text(encoding="utf-8")
        self.assertEqual(on_disk, solin_domain.generate_webapp_pack())
        for class_id, meta in VULN_CLASSES.items():
            self.assertIn(f"`{class_id}`", on_disk, class_id)
            self.assertIn(str(meta["name"]), on_disk, class_id)

    def test_recommend_tools_never_raises(self) -> None:
        self.assertEqual(solin_domain.recommend_tools([], SEED_DIR, None), [])
        self.assertEqual(solin_domain.recommend_tools(["ssrf"], Path("/no/such/dir"), None), [])
        tools = solin_domain.recommend_tools(["ssrf"], SEED_DIR, None)
        self.assertTrue(all(isinstance(tool, dict) for tool in tools))


class CapabilityTests(unittest.TestCase):
    def test_capability_statement_is_honest_for_every_domain(self) -> None:
        for domain in ("", "bounty", "webapp", "redteam", "wardrive", "coding", "unknown-domain"):
            statement = solin_domain.capability_statement(domain)
            self.assertTrue(statement)
            self.assertIn("offline", statement.lower())

    def test_wardrive_capability_states_the_read_only_envelope(self) -> None:
        statement = solin_domain.capability_statement("wardrive")
        self.assertIn("READ-ONLY", statement)
        self.assertIn("never transmits", statement)


class ApiRouterTests(unittest.TestCase):
    """The pre-router in GreyIQRuntime.chat — the only path a frozen install ever takes."""

    @classmethod
    def setUpClass(cls) -> None:
        import greyiq_api  # noqa: PLC0415 - heavy import, only for this class

        cls.api = greyiq_api
        cls.runtime = greyiq_api.GreyIQRuntime()

    def _reply(self, message: str) -> dict | None:
        return self.runtime._domain_brain_reply(self.api.ChatRequest(message=message))

    def _pack_text(self, source_path: str) -> str:
        for base in (self.api.RUNTIME_DIR, self.api.SEED_DIR):
            candidate = Path(base) / source_path
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8")
        self.fail(f"cited pack file not found: {source_path}")

    def test_bounty_question_quotes_a_shipped_pack_verbatim_with_a_citation(self) -> None:
        reply = self._reply("how do I prove an IDOR with two accounts?")
        self.assertIsNotNone(reply)
        self.assertEqual(reply["model_name"], "offline:domain-brain")
        self.assertEqual(reply["device"], "cpu")
        self.assertFalse(reply["used_fallback"])
        self.assertEqual(reply["diagnostics"]["strategy"], "domain_pack")
        self.assertTrue(reply["citations"])
        source_path = reply["citations"][0]["source"]
        self.assertIn(f"Source: {source_path}", reply["message"])
        # The quoted body must appear, character for character, in the shipped file.
        pack_text = self._pack_text(source_path)
        quoted = reply["message"].split("**", 2)[2].split("\nSource: ")[0].strip()
        self.assertTrue(quoted)
        self.assertIn(quoted, pack_text, "the reply is not a verbatim quote of the pack file")

    def test_definition_question_routes_to_the_class_explainer(self) -> None:
        reply = self._reply("what is SSRF")
        self.assertIsNotNone(reply)
        self.assertEqual(reply["diagnostics"]["strategy"], "class_explainer")
        self.assertIn(VULN_CLASSES["ssrf"]["name"], reply["message"])
        self.assertIn("CWE-918", reply["message"])

    def test_tool_question_routes_to_the_toolkit(self) -> None:
        reply = self._reply("which tools help me test for SSRF")
        self.assertIsNotNone(reply)
        self.assertIn(reply["diagnostics"]["strategy"], ("toolkit_recommend", "class_explainer"))

    def test_naming_a_target_prepends_the_honest_capability_statement(self) -> None:
        reply = self._reply("how do I prove an IDOR with two accounts on https://example.com/app")
        self.assertIsNotNone(reply)
        self.assertEqual(reply["diagnostics"]["strategy"], "offline_capability")
        self.assertIn("has not looked at your target", reply["message"])

    def test_off_topic_message_falls_through_unchanged(self) -> None:
        for message in ("hi", "thanks", "what is the capital of France"):
            self.assertIsNone(self._reply(message), message)

    def test_deterministic_coder_does_not_intercept_chat(self) -> None:
        """Workbench-only providers must leave chat to the offline fallback pipeline."""
        from unittest import mock  # noqa: PLC0415

        request = self.api.ChatRequest(message="what is SSRF")
        for provider in ("offline", "deterministic"):
            with self.subTest(provider=provider), \
                 mock.patch.object(self.runtime, "_coder_config",
                                   return_value={"enabled": True, "provider": provider}), \
                 mock.patch.object(self.api.coder, "generate") as generate:
                self.assertIsNone(self.runtime._coder_reply(request))
                generate.assert_not_called()

    def test_off_domain_questions_fall_through_on_both_router_paths(self) -> None:
        """End-to-end cover for the reported defect, at BOTH thresholds the router uses."""
        for message in OFF_DOMAIN_QUESTIONS:
            self.assertIsNone(self._reply(message), f"strict router answered {message!r}")
            self.assertIsNone(
                self.runtime._domain_brain_reply(
                    self.api.ChatRequest(message=message),
                    min_score=self.api.solin_domain.MIN_SCORE_RELAXED,
                ),
                f"relaxed router answered {message!r}",
            )

    def test_shipped_torch_free_chat_does_not_answer_a_dog_question_with_a_playbook(self) -> None:
        """The whole turn, on the path a frozen install actually takes.

        ``get_engine`` raises on every shipped (torch-free) build, so chat lands in the
        except handler with the relaxed threshold. This exact call used to return the
        bug-bounty "Proof of impact standard" card with a citation and confidence 0.330."""
        from unittest import mock  # noqa: PLC0415

        with mock.patch.object(self.api.GreyIQRuntime, "get_engine", side_effect=RuntimeError("no torch")):
            for message in ("what is a good name for a dog", "what is the capital of France",
                            "what time is the game tonight", "when is the next full moon"):
                reply = self.runtime.chat(self.api.ChatRequest(message=message))
                self.assertNotEqual(reply["model_name"], "offline:domain-brain", message)
                self.assertEqual(reply["citations"], [], message)

    def test_a_bare_class_name_reaches_the_class_explainer(self) -> None:
        """'explain SSRF' worked and 'SSRF' did not — see ExactClassNameTests for why the
        MIN_QUERY_TERMS guard does not apply to a closed-vocabulary lookup."""
        for message in ("SSRF", "ssrf", "idor"):
            reply = self._reply(message)
            self.assertIsNotNone(reply, message)
            self.assertEqual(reply["diagnostics"]["strategy"], "class_explainer", message)
        self.assertIn(VULN_CLASSES["ssrf"]["name"], self._reply("SSRF")["message"])

    def test_greetings_do_not_reach_the_class_explainer(self) -> None:
        for message in ("hi", "ok", "thanks", "hey"):
            self.assertIsNone(self._reply(message), message)


    def test_router_returns_none_when_the_pack_is_unavailable(self) -> None:
        """Absent pack == behave exactly as before this change."""
        from unittest import mock  # noqa: PLC0415

        with mock.patch.object(self.api.solin_domain, "load_pack", return_value={}):
            self.assertIsNone(self._reply("how do I prove an IDOR with two accounts?"))

    def test_router_swallows_an_internal_failure(self) -> None:
        from unittest import mock  # noqa: PLC0415

        with mock.patch.object(self.api.solin_domain, "load_pack", side_effect=RuntimeError("boom")):
            self.assertIsNone(self._reply("how do I prove an IDOR with two accounts?"))

    def test_ensure_runtime_copies_the_domain_packs(self) -> None:
        self.api.ensure_runtime()
        runtime_domain = Path(self.api.RUNTIME_DIR) / "domain"
        self.assertTrue(runtime_domain.is_dir())
        seeded = {path.name for path in (Path(self.api.SEED_DIR) / "domain").glob("*.md")}
        copied = {path.name for path in runtime_domain.glob("*.md")}
        self.assertTrue(seeded.issubset(copied), f"missing runtime copies: {seeded - copied}")

    def test_names_concrete_target_ignores_prose_slashes(self) -> None:
        self.assertFalse(self.api._names_concrete_target("explain read/write access control"))
        self.assertTrue(self.api._names_concrete_target("scan https://example.com now"))
        self.assertTrue(self.api._names_concrete_target("look at ./src/app.py"))


class WardriveChatCommandTests(unittest.TestCase):
    """``wardrive <path>`` from chat — the offline surface's route to the RF engine.

    The chat surface could already reach the scanners (`scan web <url>`) but not the wardrive
    analyzer, so an operator with a capture had no offline path to it."""

    @classmethod
    def setUpClass(cls) -> None:
        import greyiq_api  # noqa: PLC0415 - heavy import, only for this class

        from bughunter import chat_commands  # noqa: PLC0415

        cls.api = greyiq_api
        cls.runtime = greyiq_api.GreyIQRuntime()
        cls.cmd = chat_commands

    def _fixture(self, tmp: str) -> str:
        path = Path(tmp) / "survey.csv"
        path.write_text(AIRODUMP_FIXTURE, encoding="utf-8")
        return str(path)

    def test_detects_the_command_and_its_authorization_flag(self) -> None:
        self.assertEqual(self.cmd.detect_wardrive_command("wardrive -y ./capture/"), ("./capture/", True))
        self.assertEqual(self.cmd.detect_wardrive_command("wardrive ./capture/"), ("./capture/", False))
        self.assertEqual(self.cmd.detect_wardrive_command("wardrive --authorize ./cap"), ("./cap", True))
        self.assertEqual(self.cmd.detect_wardrive_command("scan wardrive -y ./cap"), ("./cap", True))
        self.assertEqual(self.cmd.detect_wardrive_command("rf survey -y survey.csv"), ("survey.csv", True))
        self.assertEqual(self.cmd.detect_wardrive_command("wardrive -y `C:/caps/a.netxml`"),
                         ("C:/caps/a.netxml", True))

    def test_ambiguous_input_is_left_to_normal_chat(self) -> None:
        """Anything that is not unmistakably the command must return None, or adding this
        route would have changed what ordinary chat does."""
        for message in (
            "", "wardrive", "wardrive best practices", "what is wardriving",
            "how do I analyze a wardrive capture", "tell me about rf survey methodology",
            # Read-only FILE analysis: a URL is not something this engine fetches.
            "wardrive -y https://example.com/survey.csv",
            # The scanners keep their own commands.
            "scan web https://example.com", "scan code ./src", "hi",
        ):
            self.assertIsNone(self.cmd.detect_wardrive_command(message), repr(message))

    def test_chat_alone_is_never_treated_as_authorization(self) -> None:
        """Without the explicit flag NOTHING is read: the refusal must not depend on the file
        even existing, which is how we know no analysis happened."""
        result = self.cmd.run_wardrive("C:/no/such/capture.csv", False)
        self.assertFalse(result["ok"])
        self.assertFalse(result["authorized"])
        self.assertIn("-y", result["error"])
        self.assertIn("Nothing was read", result["error"])
        self.assertNotIn("findings", result)

    def test_authorized_run_reuses_the_engine_and_keeps_the_undetermined_ledger(self) -> None:
        """The ledger is the point of the RF engine: an airodump CSV carries neither WPS nor
        PMF state, so 'no WPS finding' must never read as 'WPS is fine'."""
        with tempfile.TemporaryDirectory() as tmp:
            result = self.cmd.run_wardrive(self._fixture(tmp), True)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["scan_type"], "wardrive")
        self.assertEqual(result["access_points"], 3)
        self.assertGreater(result["finding_count"], 0)
        self.assertGreater(result["undetermined_count"], 0)
        self.assertIn(result["risk"], ("critical", "high", "medium", "low", "info", "none"))
        self.assertIn("undetermined", result["summary"].lower())

    def test_a_truncated_summary_says_so_and_restates_the_undetermined_ledger(self) -> None:
        """Silent truncation is the failure mode that matters here.

        The full assessment does not fit a chat bubble, and the cut lands wherever it lands —
        including through the section that says which facts the export could NOT establish.
        So the chat wrapper states the truncation, names the CLI path to the full report, and
        re-appends the ledger AFTER the cut. A reader must never be able to scroll to the end
        of a truncated RF assessment and see no undetermined facts."""
        with tempfile.TemporaryDirectory() as tmp:
            result = self.cmd.run_wardrive(self._fixture(tmp), True)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertTrue(result["summary_truncated"], "fixture no longer exercises the cut")
        self.assertGreater(result["undetermined_count"], 0)

        marker = "truncated for chat"
        self.assertIn(marker, result["summary"])
        self.assertIn("gn wardrive", result["summary"], "must name how to get the full report")
        tail = result["summary"].split(marker, 1)[1]
        self.assertIn("absence is NOT a clean result", tail)
        for row in ("wps", "pmf"):
            self.assertIn(row, tail, f"undetermined fact {row!r} was dropped by the cut")

    def test_a_missing_or_unreadable_export_answers_instead_of_raising(self) -> None:
        result = self.cmd.run_wardrive("C:/no/such/capture.csv", True)
        self.assertFalse(result["ok"])
        self.assertIn("not found", result["error"])
        self.assertEqual(self.cmd.run_wardrive("", True)["ok"], False)

    def test_risk_is_the_highest_severity_observed_not_an_invented_grade(self) -> None:
        self.assertEqual(self.cmd._wardrive_risk([]), "none")
        self.assertEqual(self.cmd._wardrive_risk([{"severity": "low"}, {"severity": "high"}]), "high")
        self.assertEqual(self.cmd._wardrive_risk([{"severity": "info"}]), "info")

    def test_chat_routes_the_command_to_the_wardrive_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._fixture(tmp)
            reply = self.runtime.chat(self.api.ChatRequest(message=f"wardrive -y {path}"))
            self.assertEqual(reply["model_name"], "bughunter:wardrive")
            self.assertTrue(reply["scan"]["ok"])
            self.assertEqual(reply["scan"]["scan_type"], "wardrive")
            self.assertTrue(reply["scan"]["authorized"])

            # Unauthorized: answered with the refusal, and nothing was analyzed.
            refusal = self.runtime.chat(self.api.ChatRequest(message=f"wardrive {path}"))
            self.assertEqual(refusal["model_name"], "bughunter:wardrive")
            self.assertFalse(refusal["scan"]["ok"])
            self.assertFalse(refusal["scan"]["authorized"])
            self.assertIn("-y", refusal["message"])

    def test_scan_wardrive_does_not_fall_into_the_source_code_scanner(self) -> None:
        """``scan wardrive <path>`` also satisfies detect_scan_command (unknown subtype ->
        path -> CODE scan), so the wardrive route has to be checked FIRST."""
        self.assertEqual(
            self.cmd.detect_scan_command("scan wardrive -y ./cap"), ("code", "wardrive -y ./cap"),
            "assumption behind the ordering in GreyIQRuntime.chat changed",
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self._fixture(tmp)
            reply = self.runtime.chat(self.api.ChatRequest(message=f"scan wardrive -y {path}"))
            self.assertEqual(reply["model_name"], "bughunter:wardrive")

    def test_normal_scan_commands_are_unaffected(self) -> None:
        self.assertEqual(self.cmd.detect_scan_command("scan web https://example.com"),
                         ("web", "https://example.com"))
        self.assertEqual(self.cmd.detect_scan_command("scan code ./src"), ("code", "./src"))

    def test_the_wardrive_engine_is_not_imported_on_the_chat_hot_path(self) -> None:
        """chat_commands is imported at greyiq_api module scope and hit on every turn; the
        parsers/analyzer/renderer must stay behind the command body."""
        code = (
            "import sys; sys.path.insert(0, '.')\n"
            "from bughunter import chat_commands\n"
            "chat_commands.detect_wardrive_command('hello there')\n"
            "print('analyze', 'bughunter.wardrive.analyze' in sys.modules)\n"
            "print('parsers', 'bughunter.wardrive.parsers' in sys.modules)\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], cwd=str(BACKEND_DIR),
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("analyze False", proc.stdout)
        self.assertIn("parsers False", proc.stdout)


if __name__ == "__main__":
    unittest.main()
