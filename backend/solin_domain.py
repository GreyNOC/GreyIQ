"""GreyIQ offline domain brain — curated cards, extractive composition, ZERO generation.

WHY THIS EXISTS. The shipped build excludes PyTorch (``build/greyiq-backend.spec``
``excludes=[..., "torch", ...]``) and deliberately does not bundle ``solin_core``. So in
the frozen app ``greyiq_api._ensure_ml_runtime()`` returns False, ``get_engine()`` raises,
``chat()`` falls into its ``except`` handler, and every offline chat turn a real user ever
sees is ONE hardcoded platitude from ``fallback_reply``. TinyGPT, the KnowledgeBase, the
CPU short-circuit and its quality gates are all dead code out there. Improving the offline
chat answer therefore cannot mean improving the model — it has to mean answering from
curated content on a path that runs BEFORE the engine and needs none of its dependencies.

That is this module. It is deliberately **torch-free, numpy-free and solin_core-free** —
stdlib only (``re``/``difflib``/``math``/``pathlib``/``dataclasses``) — because the one
machine that needs it most is precisely the machine that has none of those. ``solin_core``
may import ``solin_domain``; ``solin_domain`` must never import ``solin_core``, and
``test_solin_domain`` asserts that mechanically by scanning this file's source.

THE CONTRACT, restated from ``bughunter/offline_hunt.py``: it can raise USEFULNESS, never
TRUTHFULNESS. :func:`compose_answer` performs no generation of any kind — the answer body
is a CONTIGUOUS slice of a bundled card, so ``excerpt in card.body`` is literally true and
the test suite asserts it. The tiny (well under 10M-param) char model cannot smuggle a hallucinated security
claim through this path because nothing on this path can author a sentence. Everything the
composer adds around the excerpt is a fixed, authored template line and a ``Source:`` cite.

Content comes from three already-shipped trees under ``seed/`` (and their user-editable
``runtime/`` overrides): ``domain/*.md`` (this change), ``bounty/*.md`` (the hunt playbooks)
and ``skills/*.md`` (the coder playbooks). ``bughunter.bounty.VULN_CLASSES`` and
``bughunter.toolkit`` are torch-free and are read LAZILY inside the functions that need
them, so chat and the reports cannot drift apart and an import failure costs a feature
rather than the whole reply.

Fail-closed everywhere: a missing ``seed/domain`` directory, an unreadable file, a corrupt
card or an absent ``bughunter`` package all degrade to "no match", which makes the caller
fall through to exactly the behaviour it had before this module existed. Absent never means
crash.
"""

from __future__ import annotations

import difflib
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# --- Pack layout -----------------------------------------------------------------

# (subdirectory under the seed/runtime base, domain label applied to its cards). Ordered
# so a `sorted()` over card ids stays stable regardless of filesystem iteration order.
PACK_DIRS: tuple[tuple[str, str], ...] = (
    ("domain", ""),   # "" == derive the domain from the file stem (bounty/webapp/redteam/...)
    ("bounty", "bounty"),
    ("skills", "skills"),
)

# A section shorter than this is a heading with no content (or a stub) — indexing it would
# let a title match win and then compose an empty answer.
_MIN_BODY_CHARS = 60
# Answers stay readable: at most this many VERBATIM lines from the card. The window is
# contiguous, so the cap never splices unrelated advice together.
MAX_EXCERPT_LINES = 16
# Below this the curated pack has nothing on topic and the caller must fall through
# unchanged.
#
# TUNED AGAINST EVIDENCE, NOT FEEL. ``OFF_DOMAIN_QUESTIONS`` (40 ordinary English questions
# with no security content) and ``ON_DOMAIN_QUESTIONS`` (24 real operator questions) in
# test_solin_domain are the fixture; the measured separation on the bundled 73-card pack is
# an off-domain ceiling of 0.211 and an on-domain floor of 0.293. 0.28 sits in that gap with
# margin on both sides. It is LOWER than the 0.32 it replaces because the old number was
# compensating for a scorer bug (see :func:`_score_card`): once out-of-vocabulary tokens are
# weighted honestly, 0.32 only cost recall — it never bought precision.
MIN_SCORE = 0.28
# The threshold the caller uses when there is no engine answer to protect (greyiq_api's
# except handler — the NORMAL path on every shipped torch-free build, see the module
# docstring). A weaker-but-real card beats the canned platitude there, so the bar drops —
# but it must NEVER drop below the measured off-domain ceiling, which is exactly the bug the
# old ``MIN_SCORE * 0.75`` had. 0.24 keeps ~0.03 of margin above that ceiling, and
# test_solin_domain asserts the whole off-domain fixture still returns nothing AT THIS
# THRESHOLD, so a future retune cannot silently reopen the hole.
MIN_SCORE_RELAXED = 0.24
# One content word ("xss") is not a question; it is also exactly what a greeting looks
# like after stopword removal. Requiring two keeps "hi"/"thanks"/"ok" out of the pack.
# EXCEPTION: a message that is EXACTLY a known vuln class is a closed-vocabulary lookup, not
# a fuzzy guess, and routes around this guard — see :func:`detect_class_query`.
MIN_QUERY_TERMS = 2
# A token the pack uses in more than this fraction of its cards ("is", "the", "testing") is
# boilerplate: it says nothing about WHICH card answers the question. Sharing only
# boilerplate does not count as overlap — see the lexical gate in :func:`_score_card`.
_BOILERPLATE_DF_FRACTION = 0.5

_HEADING_RE = re.compile(r"^(#{1,3})[ \t]+(.+?)[ \t]*#*[ \t]*$")
# Triggers ride in an HTML comment so they are invisible in rendered markdown AND are
# stripped from the body before it is ever quoted back to the user.
_TRIGGER_RE = re.compile(r"<!--\s*triggers:\s*(.*?)-->", re.IGNORECASE | re.DOTALL)
_WORD_RE = re.compile(r"[a-z0-9_+#.-]{2,}")
_SLUG_RE = re.compile(r"[^a-z0-9]+")

# Deliberately small and hand-picked rather than a borrowed NLP list: these are the words
# that carry no signal in an operator's security question. Anything security-flavoured
# ("scope", "proof", "token") is intentionally NOT here.
_STOPWORDS = frozenset({
    "the", "and", "for", "are", "but", "not", "you", "your", "with", "this", "that", "from",
    "have", "has", "had", "was", "were", "will", "would", "should", "could", "can", "does",
    "did", "how", "what", "when", "where", "which", "who", "why", "into", "onto", "about",
    "there", "their", "them", "then", "than", "some", "any", "all", "its", "it's", "get",
    "got", "out", "off", "our", "ours", "his", "her", "hers", "him", "she", "they", "were",
    "been", "being", "just", "like", "make", "made", "want", "need", "know", "tell", "give",
    "please", "help", "explain", "show", "let", "using", "use", "used", "way", "one", "two",
    "more", "most", "very", "much", "many", "such", "also", "only", "over", "under", "here",
    "now", "new", "old", "good", "best", "bad", "still", "yet", "back", "down", "next",
    "each", "own", "same", "few", "both", "between", "through", "during", "before", "after",
    "again", "further", "once", "because", "while", "these", "those", "doing", "done",
})

# Cheap morphological folding so "injections" hits a card that says "injection". Applied to
# the tail of a token only; deliberately conservative (no Porter stemmer — a wrong stem
# silently changes which curated card an operator is shown).
_SUFFIXES = ("ies", "es", "s")


@dataclass(slots=True)
class DomainCard:
    """One ``## section`` of one bundled markdown pack — the atom of an offline answer.

    ``body`` is the section text EXACTLY as it appears on disk (newline-normalized, trigger
    comment stripped). Nothing downstream is allowed to rewrite it: the verbatim guarantee
    is what makes this module safe to put in front of a security answer."""

    card_id: str
    domain: str
    title: str
    body: str
    triggers: tuple[str, ...]
    source_path: str


@dataclass(slots=True)
class _CardFeatures:
    """Derived scoring state for one card. Never persisted, never user-visible."""

    tokens: frozenset[str]
    title_tokens: frozenset[str]
    head: str
    head_grams: frozenset[str]


# Pack cache keyed by "<seed>|<runtime>" -> {"sig": <file signature>, "pack": ...}. The
# signature is (path, mtime, size) over every candidate file, so a user editing their
# runtime copy is picked up on the next turn without a restart — the same mtime discipline
# ``bughunter.toolkit._CACHE`` uses.
_PACK_CACHE: dict[str, dict[str, Any]] = {}
_PACK_CACHE_MAX = 32
# Feature memo keyed by (card_id, body hash): recomputing token/char-gram sets for ~60 cards
# on every chat turn is pure waste, and the key changes whenever the body does.
_FEATURE_CACHE: dict[tuple[str, int], _CardFeatures] = {}
_FEATURE_CACHE_MAX = 4000


# --- Stdlib-local tokenization + similarity ---------------------------------------
# Same algorithm SHAPE as solin_core's _tokenize_search_terms/_hybrid_similarity (token-set
# plus character n-gram Jaccard, coverage-dominant blend) so behaviour is comparable, but
# owned here: reaching into solin_core would drag in the whole torch runtime and defeat the
# entire point of this module (test_solin_domain scans this file for exactly that mistake).


def _fold(term: str) -> str:
    """Fold a trivial plural so 'injections'/'injection' and 'headers'/'header' agree."""
    for suffix in _SUFFIXES:
        if len(term) > len(suffix) + 2 and term.endswith(suffix):
            return term[: -len(suffix)]
    return term


def tokenize(text: str) -> list[str]:
    """Lowercase content words, stopwords dropped, trivial plurals folded. Order preserved
    (callers that need a set build one) so this stays usable for phrase work later."""
    lowered = str(text or "").lower()
    out: list[str] = []
    for raw in _WORD_RE.findall(lowered):
        term = raw.strip("._-")
        if len(term) < 2 or term in _STOPWORDS:
            continue
        out.append(_fold(term))
    return out


def _char_grams(text: str, size: int = 4) -> frozenset[str]:
    normalized = re.sub(r"\s+", " ", str(text or "").lower()).strip()
    if not normalized:
        return frozenset()
    if len(normalized) <= size:
        return frozenset({normalized})
    padded = f" {normalized} "
    return frozenset(padded[index : index + size] for index in range(len(padded) - size + 1))


def _jaccard(left: frozenset[str] | set[str], right: frozenset[str] | set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / max(len(left | right), 1)


def _features(card: DomainCard) -> _CardFeatures:
    key = (card.card_id, hash(card.body))
    cached = _FEATURE_CACHE.get(key)
    if cached is not None:
        return cached
    # Char-grams and the sequence ratio only ever look at the HEAD of a card (title + lead):
    # running them over a 4 KB playbook body drowns the query in noise and costs real time
    # on every chat turn. Token coverage is what carries the long tail.
    head = f"{card.title}. {card.body[:400]}"
    features = _CardFeatures(
        tokens=frozenset(tokenize(f"{card.title}\n{card.body[:4000]}\n{' '.join(card.triggers)}")),
        title_tokens=frozenset(tokenize(card.title)),
        head=head,
        head_grams=_char_grams(head),
    )
    if len(_FEATURE_CACHE) >= _FEATURE_CACHE_MAX:
        _FEATURE_CACHE.clear()
    _FEATURE_CACHE[key] = features
    return features


@dataclass(slots=True, frozen=True)
class _PackIdf:
    """Corpus statistics for one pack, computed once per :func:`match_cards_scored` call.

    ``unseen`` is the load-bearing field and the reason this is a dataclass rather than the
    plain ``{token: idf}`` dict it used to be: the scorer needs to know what to charge for a
    word the pack has NEVER used, and that number cannot be recovered from the dict."""

    weights: dict[str, float]
    document_frequency: dict[str, int]
    unseen: float
    card_count: int


def _pack_idf(cards: list[DomainCard]) -> _PackIdf:
    """Inverse document frequency over the pack. Without it 'testing' (in every single
    playbook) would count as much as 'ssrf' (in one), and the operator's actual keyword
    would be outvoted by boilerplate.

    ``unseen`` is the idf a token with a document frequency of ZERO earns — strictly greater
    than every value in ``weights``, because a word the pack has never used is the most
    informative word in the question. See :func:`_score_card` for why that matters."""
    total = max(len(cards), 1)
    document_frequency: dict[str, int] = {}
    for card in cards:
        for token in _features(card).tokens:
            document_frequency[token] = document_frequency.get(token, 0) + 1
    return _PackIdf(
        weights={
            token: math.log(1.0 + total / (1.0 + count))
            for token, count in document_frequency.items()
        },
        document_frequency=document_frequency,
        unseen=math.log(1.0 + total / 1.0),
        card_count=total,
    )


def _score_card(
    query: str,
    query_tokens: list[str],
    query_grams: frozenset[str],
    card: DomainCard,
    idf: _PackIdf,
) -> float:
    features = _features(card)
    query_set = frozenset(query_tokens)
    if not query_set:
        return 0.0

    # IDF-weighted coverage: what fraction of the query's INFORMATION the card carries.
    #
    # THE NOISE FLOOR THIS FIXES. An out-of-vocabulary token used to be charged a flat 1.0 —
    # BELOW the idf of ordinary pack filler ("name" 2.96, "time" 2.96, "of" 1.67 on the
    # bundled 73-card pack). That inverts the meaning of the ratio: "what is a good name for
    # a dog" scored coverage 0.80 against a bug-bounty card because "dog" (the only word that
    # proves the question is off-domain) was worth less than "name", and the whole question
    # was then answered with a security playbook carrying a citation and a confidence number.
    # An unseen token is definitionally UNCOVERED and maximally informative, so it is charged
    # the zero-document-frequency idf — the ceiling. Same query now scores coverage 0.48.
    weights = {token: idf.weights.get(token, idf.unseen) for token in query_set}
    total_weight = sum(weights.values()) or 1.0
    covered = sum(weight for token, weight in weights.items() if token in features.tokens)
    coverage = covered / total_weight

    # Explicit trigger phrases and title words are the card author's own routing signal —
    # scored like skills.select_skills (+3 trigger / +1 token), rescaled onto 0..1.
    lowered_query = str(query or "").lower()
    trigger_hits = sum(1 for trigger in card.triggers if trigger and trigger in lowered_query)
    title_hits = len(query_set & features.title_tokens)

    # THE LEXICAL GATE. char_jaccard + sequence_ratio are worth 0.45 of the score and both are
    # computed over raw English against the card head, so on their own they can clear any sane
    # threshold for a card that shares NOT ONE content word with the question. Character
    # similarity between two English sentences is a statement about English, not about whether
    # this card answers this question, so it is only ever allowed to REFINE a ranking that real
    # overlap already earned. "Real" excludes pack boilerplate on purpose: a token the pack
    # uses in over half its cards cannot distinguish one card from another.
    boilerplate_df = _BOILERPLATE_DF_FRACTION * idf.card_count
    has_real_overlap = trigger_hits > 0 or title_hits > 0 or any(
        token in features.tokens and idf.document_frequency.get(token, 0) <= boilerplate_df
        for token in query_set
    )
    if not has_real_overlap:
        return 0.0

    token_jaccard = _jaccard(query_set, features.tokens)
    char_jaccard = _jaccard(query_grams, features.head_grams)
    sequence_ratio = difflib.SequenceMatcher(
        None, str(query or "").lower()[:280], features.head.lower()[:420]
    ).ratio()

    score = coverage * 0.40 + token_jaccard * 0.15 + char_jaccard * 0.25 + sequence_ratio * 0.20
    score += min(trigger_hits, 2) * 0.15 + min(title_hits, 3) * 0.04
    return max(0.0, min(score, 1.0))


# --- Pack loading ------------------------------------------------------------------


def _slug(text: str) -> str:
    return _SLUG_RE.sub("-", str(text or "").lower()).strip("-")[:60] or "section"


def _parse_markdown(text: str, *, kind: str, file_name: str, domain: str) -> list[DomainCard]:
    """Split one pack file into cards on its ``##``/``###`` headings.

    Content above the first heading is intentionally dropped: in every bundled pack it is
    the H1 title plus the authorized-testing preamble, which reads as boilerplate when
    quoted back as an answer. A card's body is preserved byte-for-byte apart from newline
    normalization and the LEADING trigger comment, because :func:`compose_answer` quotes
    it straight back at the operator."""
    normalized = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    cards: list[DomainCard] = []
    title = ""
    buffer: list[str] = []

    def flush() -> None:
        if not title:
            return
        # Triggers are read ONLY from the comment block at the very top of a section, and
        # only that leading block is removed. That is what keeps ``body`` a CONTIGUOUS slice
        # of the file on disk: deleting a comment from the middle would splice two
        # non-adjacent runs together and quietly break the verbatim guarantee that makes
        # this whole module safe. A trigger comment placed anywhere else is left in the body
        # (harmless — markdown hides it) and simply does not route.
        found: list[str] = []
        rest = "\n".join(buffer).lstrip("\n")
        while True:
            leading = _TRIGGER_RE.match(rest)
            if leading is None:
                break
            found.extend(part.strip().lower() for part in str(leading.group(1)).split(","))
            rest = rest[leading.end() :].lstrip("\n")
        triggers = tuple(sorted({part for part in found if part}))
        body = rest.strip()
        if len(body) < _MIN_BODY_CHARS:
            return
        cards.append(
            DomainCard(
                card_id=f"{kind}/{file_name}#{_slug(title)}",
                domain=domain,
                title=title,
                body=body,
                triggers=triggers,
                source_path=f"{kind}/{file_name}",
            )
        )

    for line in normalized.split("\n"):
        heading = _HEADING_RE.match(line)
        if heading is not None and len(heading.group(1)) >= 2:
            flush()
            title = heading.group(2).strip()
            buffer = []
            continue
        if title:
            buffer.append(line)
    flush()
    return cards


def _candidate_files(seed_dir: Path | str | None, runtime_dir: Path | str | None) -> list[tuple[str, str, Path]]:
    """Every (kind, file name, path) the pack could be built from, runtime LAST so it wins.
    Sorted per directory so pack order never depends on filesystem iteration order."""
    found: list[tuple[str, str, Path]] = []
    for base in (seed_dir, runtime_dir):
        if base is None:
            continue
        for kind, _domain in PACK_DIRS:
            try:
                directory = Path(base) / kind
                if not directory.is_dir():
                    continue
                for path in sorted(directory.glob("*.md")):
                    if path.is_file():
                        found.append((kind, path.name, path))
            except OSError:
                continue
    return found


def _signature(files: list[tuple[str, str, Path]]) -> tuple[tuple[str, float, int], ...]:
    signature: list[tuple[str, float, int]] = []
    for _kind, _name, path in files:
        try:
            stat = path.stat()
            signature.append((str(path), stat.st_mtime, stat.st_size))
        except OSError:
            signature.append((str(path), 0.0, -1))
    return tuple(signature)


def load_pack(
    seed_dir: Path | str | None,
    runtime_dir: Path | str | None = None,
) -> dict[str, list[DomainCard]]:
    """Curated cards grouped by domain, runtime override winning per file name.

    Returns ``{}`` — never raises — when the directories are missing, unreadable, or every
    file is corrupt. ``{}`` is the signal the caller uses to fall through to exactly the
    behaviour it had before the domain brain existed."""
    try:
        files = _candidate_files(seed_dir, runtime_dir)
    except Exception:  # noqa: BLE001 - a bad path must cost a feature, never the reply
        return {}
    if not files:
        return {}

    key = f"{seed_dir}|{runtime_dir}"
    signature = _signature(files)
    cached = _PACK_CACHE.get(key)
    if cached is not None and cached.get("sig") == signature:
        return cached["pack"]

    # Keyed by (kind, file name) so the runtime copy of a file REPLACES the seed copy's
    # cards wholesale — a user who deletes a section from their override must not keep
    # being answered from the bundled version of it.
    by_file: dict[tuple[str, str], list[DomainCard]] = {}
    for kind, name, path in files:
        domain = dict(PACK_DIRS).get(kind) or Path(name).stem.lower()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue  # unreadable/locked file: skip it, keep every other card
        try:
            cards = _parse_markdown(text, kind=kind, file_name=name, domain=domain)
        except Exception:  # noqa: BLE001 - one corrupt pack must never empty the whole pack
            continue
        if cards:
            by_file[(kind, name)] = cards

    pack: dict[str, list[DomainCard]] = {}
    for _file_key in sorted(by_file):
        for card in by_file[_file_key]:
            pack.setdefault(card.domain, []).append(card)
    for domain in pack:
        pack[domain] = sorted(pack[domain], key=lambda card: card.card_id)

    # In the app there are only ever one or two keys (seed|runtime); the cap only matters
    # for a long-lived process that keeps pointing this at fresh directories (tests).
    if len(_PACK_CACHE) >= _PACK_CACHE_MAX:
        _PACK_CACHE.clear()
    _PACK_CACHE[key] = {"sig": signature, "pack": pack}
    return pack


def all_cards(pack: dict[str, list[DomainCard]] | None) -> list[DomainCard]:
    """Flatten the pack in a stable order (domain, then card id)."""
    out: list[DomainCard] = []
    for domain in sorted(pack or {}):
        out.extend(pack[domain])
    return out


# --- Matching ----------------------------------------------------------------------


def match_cards_scored(
    query: str,
    pack: dict[str, list[DomainCard]] | None,
    limit: int = 3,
    min_score: float = MIN_SCORE,
) -> list[tuple[DomainCard, float]]:
    """Ranked (card, score) pairs above ``min_score``; ``[]`` when the pack has nothing
    on topic. Ties break on ``card_id`` so the same question always cites the same card —
    a chat answer that shuffles between runs is indistinguishable from a made-up one."""
    try:
        cards = all_cards(pack)
        if not cards:
            return []
        query_tokens = tokenize(query)
        if len(set(query_tokens)) < MIN_QUERY_TERMS:
            return []  # a greeting/ack, not a question the pack can answer
        query_grams = _char_grams(query)
        idf = _pack_idf(cards)
        scored = [
            (card, _score_card(query, query_tokens, query_grams, card, idf))
            for card in cards
        ]
        ranked = [pair for pair in scored if pair[1] >= min_score]
        ranked.sort(key=lambda pair: (-pair[1], pair[0].card_id))
        return ranked[: max(int(limit), 0)]
    except Exception:  # noqa: BLE001 - scoring must never break a chat turn
        return []


def match_cards(
    query: str,
    pack: dict[str, list[DomainCard]] | None,
    limit: int = 3,
) -> list[DomainCard]:
    """Ranked cards above :data:`MIN_SCORE`, best first; ``[]`` below threshold."""
    return [card for card, _score in match_cards_scored(query, pack, limit=limit)]


# --- Extractive composition (no generation, ever) ------------------------------------


def _block_starts(lines: list[str]) -> list[int]:
    starts = [0]
    for index in range(1, len(lines)):
        if not lines[index - 1].strip() and lines[index].strip():
            starts.append(index)
    return starts


def verbatim_excerpt(card: DomainCard, query: str = "", max_lines: int = MAX_EXCERPT_LINES) -> str:
    """A CONTIGUOUS slice of ``card.body`` — the whole safety argument in one function.

    Because the result is a contiguous run of lines joined by the same ``\\n`` they were
    split on, ``verbatim_excerpt(card) in card.body`` is always true, which is exactly what
    ``test_solin_domain`` asserts. The query only chooses WHICH window (highest token
    overlap, earliest on a tie) when the card is longer than the cap; it never edits one."""
    body = card.body.strip()
    lines = body.split("\n")
    if len(lines) <= max_lines:
        return body

    query_tokens = frozenset(tokenize(query))
    best_index = 0
    best_score = -1.0
    for start in _block_starts(lines):
        window = lines[start : start + max_lines]
        if not any(line.strip() for line in window):
            continue
        overlap = len(query_tokens & frozenset(tokenize("\n".join(window)))) if query_tokens else 0
        # Earlier windows win ties: the top of a curated section is its thesis.
        score = overlap - start * 1e-6
        if score > best_score:
            best_score, best_index = score, start
    window = lines[best_index : best_index + max_lines]
    while window and not window[-1].strip():
        window.pop()
    return "\n".join(window)


# Fixed, authored opener per intent. This is the ONLY prose the composer contributes and it
# is a constant — no query echo, no template interpolation of model output, nothing that
# could read as an assertion about the user's target.
# Keyed by BOTH the solin_core intent label and the pack's own domain name, so a caller can
# pass whichever it has without a translation table (an unknown key just gets the neutral
# opener — never a wrong claim about which pack answered).
_OPENERS: dict[str, str] = {
    "": "From GreyIQ's bundled offline knowledge (quoted verbatim, not generated):",
    "bug_bounty_hunt": "From GreyIQ's bundled bug-bounty playbooks (quoted verbatim, not generated):",
    "bounty": "From GreyIQ's bundled bug-bounty playbooks (quoted verbatim, not generated):",
    "webapp_security": "From GreyIQ's bundled web-application playbooks (quoted verbatim, not generated):",
    "webapp": "From GreyIQ's bundled web-application playbooks (quoted verbatim, not generated):",
    "red_team_ops": "From GreyIQ's bundled red-team playbooks (quoted verbatim, not generated):",
    "redteam": "From GreyIQ's bundled red-team playbooks (quoted verbatim, not generated):",
    "rf_survey": "From GreyIQ's bundled RF-survey playbooks (quoted verbatim, not generated):",
    "wardrive": "From GreyIQ's bundled RF-survey playbooks (quoted verbatim, not generated):",
    "coding": "From GreyIQ's bundled coding-workflow playbooks (quoted verbatim, not generated):",
}


def compose_answer(query: str, cards: list[DomainCard], intent_label: str = "") -> str:
    """A fixed template around a verbatim excerpt. Returns ``''`` when there is nothing
    to quote. NO paraphrase, NO summarization, NO generation — the body between the header
    and the ``Source:`` line is copied out of the card character for character."""
    if not cards:
        return ""
    try:
        primary = cards[0]
        excerpt = verbatim_excerpt(primary, query)
        if not excerpt.strip():
            return ""
        lines = [
            _OPENERS.get(str(intent_label or ""), _OPENERS[""]),
            "",
            f"**{primary.title}**",
            "",
            excerpt,
            "",
            f"Source: {primary.source_path}",
        ]
        for extra in cards[1:3]:
            lines.append(f"Also in the offline pack: {extra.title} — {extra.source_path}")
        return "\n".join(lines).strip()
    except Exception:  # noqa: BLE001 - a composition failure must degrade to "no answer"
        return ""


# --- bughunter-backed answers (lazy, torch-free, optional) ----------------------------


def _vuln_classes() -> dict[str, Any]:
    """``bughunter.bounty.VULN_CLASSES`` read at call time so chat and the report writer
    cannot drift. Lazy + guarded: the bughunter package is torch-free but an import failure
    (partial install, frozen-build omission) must cost this feature only."""
    try:
        from bughunter.bounty import VULN_CLASSES  # noqa: PLC0415 - lazy by design

        return VULN_CLASSES if isinstance(VULN_CLASSES, dict) else {}
    except Exception:  # noqa: BLE001 - no class table just means no class explainer
        return {}


def explain_class(class_id: str) -> str:
    """Render ONE vuln class straight out of ``VULN_CLASSES`` — name, CWE, OWASP, and the
    3-step authorized-testing checklist, all copied from the dict. ``''`` for an unknown id
    (the caller then falls through rather than inventing a class)."""
    classes = _vuln_classes()
    meta = classes.get(str(class_id or "").strip())
    if not isinstance(meta, dict):
        return ""
    try:
        lines = [f"**{meta.get('name') or class_id}** (`{class_id}`)"]
        cwe = str(meta.get("cwe") or "").strip()
        owasp = str(meta.get("owasp") or "").strip()
        if cwe:
            lines.append(f"- CWE: {cwe}")
        if owasp:
            lines.append(f"- OWASP: {owasp}")
        checklist = [str(step).strip() for step in (meta.get("checklist") or []) if str(step).strip()]
        if checklist:
            lines.append("")
            lines.append("Authorized-testing checklist (stay inside the program's scope):")
            for index, step in enumerate(checklist, start=1):
                lines.append(f"{index}. {step}")
        lines.append("")
        lines.append(f"Source: bughunter.bounty.VULN_CLASSES['{class_id}']")
        return "\n".join(lines)
    except Exception:  # noqa: BLE001 - a malformed class entry must not break the reply
        return ""


def class_aliases() -> dict[str, str]:
    """Lowercase phrase -> class id. Built from ``VULN_CLASSES`` itself (ids, names, and the
    parenthetical acronym a name carries) plus a small hand table for the spellings operators
    actually type. Deterministic ordering is irrelevant here — it is an exact-phrase lookup."""
    aliases: dict[str, str] = {}
    for class_id, meta in _vuln_classes().items():
        cid = str(class_id).strip().lower()
        if not cid:
            continue
        aliases[cid] = class_id
        aliases[cid.replace("-", " ")] = class_id
        name = str((meta or {}).get("name") or "").strip().lower()
        if name:
            aliases[name] = class_id
            head = name.split("/")[0].strip()
            if head:
                aliases[head] = class_id
            inner = re.search(r"\(([^)]+)\)", name)
            if inner:
                aliases[inner.group(1).strip().lower()] = class_id
    # Spellings the table cannot derive. Every value must be a real VULN_CLASSES key, so
    # filter against the table rather than trusting this literal.
    hand = {
        "idor": "access-control", "bola": "access-control", "bfla": "access-control",
        "broken access control": "access-control", "privilege escalation": "access-control",
        "sql injection": "sqli", "sqli": "sqli", "nosql injection": "nosqli",
        "cross site scripting": "xss", "cross-site scripting": "xss",
        "cross site request forgery": "csrf", "cross-site request forgery": "csrf",
        "server side request forgery": "ssrf", "server-side request forgery": "ssrf",
        "server side template injection": "ssti", "template injection": "ssti",
        "command injection": "rce", "remote code execution": "rce",
        "open redirect": "redirect", "unvalidated redirect": "redirect",
        "xml external entity": "xxe", "json web token": "jwt", "jwt": "jwt",
        "http request smuggling": "request-smuggling", "desync": "request-smuggling",
        "subdomain takeover": "subdomain-takeover", "dangling dns": "subdomain-takeover",
        "prototype pollution": "prototype-pollution", "race condition": "race-condition",
        "file upload": "file-upload", "business logic": "business-logic",
        "hardcoded secret": "secrets", "leaked credential": "secrets",
        "cswsh": "websocket", "websocket hijacking": "websocket",
        "cloud storage": "cloud-exposure", "s3 bucket": "cloud-exposure",
    }
    known = set(_vuln_classes())
    for phrase, class_id in hand.items():
        if class_id in known:
            aliases[phrase] = class_id
    return aliases


def classes_mentioned(message: str) -> list[str]:
    """Every vuln class named in the message, in ``VULN_CLASSES`` order (stable, and it is
    the same order the report writer uses). Longest alias wins per class."""
    lowered = f" {re.sub(r'[^a-z0-9+#-]+', ' ', str(message or '').lower())} "
    aliases = class_aliases()
    hit: set[str] = set()
    for phrase, class_id in aliases.items():
        if len(phrase) < 3:
            continue
        if f" {phrase} " in lowered:
            hit.add(class_id)
    return [cid for cid in _vuln_classes() if cid in hit]


_DEFINITION_RE = re.compile(
    r"^\s*(?:what(?:'s| is| are)|whats|explain|define|describe|tell me about)\b",
    re.IGNORECASE,
)
_TOOL_RE = re.compile(r"\btool(?:s|ing|kit)?\b", re.IGNORECASE)


def exact_class_name(message: str) -> str | None:
    """The class id for a message that is EXACTLY a known class id/name/alias and nothing
    else — "SSRF", "idor", "prototype pollution", "xxe?" — else ``None``.

    WHY THIS IS ALLOWED TO SKIP :data:`MIN_QUERY_TERMS`. That guard exists because ONE
    content word is an ambiguous fuzzy match against a 73-card pack: the scorer would be
    guessing which card the operator meant, and a greeting ("hi", "ok") looks identical to it
    after stopword removal. An exact hit on the ``VULN_CLASSES`` vocabulary is not a fuzzy
    match at all — it is a lookup in a closed, authored table, so the ambiguity the guard
    protects against does not exist and a bare "SSRF" can be answered from the class table
    instead of falling through to the tiny model's platitude. Anything NOT in that table
    (every greeting, every ordinary sentence) still returns ``None`` and is untouched."""
    normalized = re.sub(r"\s+", " ", re.sub(r"[^a-z0-9+#-]+", " ", str(message or "").lower())).strip()
    # Same 3-char floor classes_mentioned uses: a 1-2 char fragment is never a class name and
    # matching one would be exactly the ambiguity this function claims not to have.
    if len(normalized) < 3:
        return None
    return class_aliases().get(normalized)


def detect_class_query(message: str) -> str | None:
    """The class id for an explicit definition question ("what is SSRF", "explain IDOR") or
    for a bare class name ("SSRF"), else ``None``. Deliberately narrow: "how do I find XSS on
    this app" is a playbook question and belongs to the card matcher, not to the class
    table."""
    text = str(message or "")
    exact = exact_class_name(text)
    if exact:
        return exact
    if not _DEFINITION_RE.match(text):
        return None
    found = classes_mentioned(text)
    return found[0] if len(found) == 1 else None


def looks_like_tool_request(message: str) -> bool:
    """True for "which tools help with SSRF" — a catalog lookup, not a playbook question."""
    return bool(_TOOL_RE.search(str(message or "")))


def recommend_tools(
    class_ids: list[str] | None,
    seed_dir: Path | str | None,
    runtime_dir: Path | str | None = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Delegate to ``bughunter.toolkit.recommended_tools`` (a reference index of tool NAMES
    and links — no payloads, no exploit code). ``[]`` on any failure."""
    try:
        from bughunter import toolkit  # noqa: PLC0415 - lazy by design

        return toolkit.recommended_tools(
            [str(c) for c in (class_ids or []) if str(c).strip()],
            Path(seed_dir) if seed_dir else None,
            Path(runtime_dir) if runtime_dir else None,
            limit=limit,
        )
    except Exception:  # noqa: BLE001 - a missing catalog costs the recommendation only
        return []


def format_tools(tools: list[dict[str, Any]]) -> str:
    """Render the toolkit rows as a plain list. Names/one-liners/links only."""
    lines: list[str] = []
    for tool in tools or []:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name") or "").strip()
        if not name:
            continue
        description = str(tool.get("description") or "").strip()
        url = str(tool.get("url") or "").strip()
        suffix = f" — {description}" if description else ""
        suffix += f" ({url})" if url else ""
        lines.append(f"- **{name}**{suffix}")
    return "\n".join(lines)


# --- Honest capability statements ------------------------------------------------------

# Every one of these is a statement about GreyIQ, not about the operator's target. The
# offline brain has never seen their target and must say so rather than implying analysis.
_CAPABILITY: dict[str, str] = {
    "": (
        "Heads up on what this answer is: with no Local-model or Claude brain configured, "
        "GreyIQ answers offline by quoting its bundled playbooks. It has not looked at your "
        "target and cannot reason about it. To actually test something, run a scan "
        "(`scan web <url>`, `scan code <path>`) or configure a brain in Settings."
    ),
    "bounty": (
        "Heads up on what this answer is: offline, GreyIQ quotes its bundled bug-bounty "
        "playbooks. It has not looked at your target and every claim below is generic "
        "methodology, not a finding. Confirmation only ever comes from the deterministic, "
        "scope-gated prover — run `scan web <url>` or a bounty hunt to get real evidence."
    ),
    "webapp": (
        "Heads up on what this answer is: offline, GreyIQ quotes its bundled web-app "
        "playbooks and the vuln-class table. Nothing here has been observed on your target. "
        "Run `scan web <url>` for an authorized passive pass, or configure a brain."
    ),
    "redteam": (
        "Heads up on what this answer is: offline, GreyIQ quotes its bundled red-team "
        "playbooks. It is engagement methodology for authorized, scoped work only — it has "
        "not looked at your environment and produces no operational capability."
    ),
    "wardrive": (
        "Heads up on what this answer is: offline, GreyIQ quotes its bundled RF-survey "
        "playbooks. GreyIQ's wardrive support is READ-ONLY analysis of capture exports you "
        "supply — it never transmits, attacks, or cracks anything."
    ),
    "coding": (
        "Heads up on what this answer is: offline, GreyIQ quotes its bundled coding "
        "playbooks. The offline model cannot write or edit code — for that, configure a "
        "Local model (Ollama) or a Claude brain and use the Workbench agent, whose writes "
        "go through the ToolBox and a verify step and can be rolled back."
    ),
}


def capability_statement(domain: str) -> str:
    """What the offline brain can and cannot do for ``domain`` — stated up front so an
    operator never mistakes a quoted playbook for analysis of their target."""
    return _CAPABILITY.get(str(domain or "").strip().lower(), _CAPABILITY[""])


# --- Generated pack content ------------------------------------------------------------


def generate_webapp_pack() -> str:
    """Render ``seed/domain/webapp.md`` FROM ``bughunter.bounty.VULN_CLASSES``.

    Hand-writing a web-app pack guarantees drift: a class added to the table for the hunt
    engine would silently have no chat coverage. So the file on disk is this function's
    output, and ``test_solin_domain`` asserts they are byte-identical — adding a class
    without regenerating fails the suite instead of quietly losing coverage. Returns ``''``
    if the class table is unavailable, so a caller can tell "cannot generate" from "empty"."""
    classes = _vuln_classes()
    if not classes:
        return ""
    lines = [
        "# Web application security — vuln classes",
        "",
        "<!-- GENERATED by solin_domain.generate_webapp_pack() from",
        "     bughunter.bounty.VULN_CLASSES. Do not hand-edit: test_solin_domain asserts",
        "     this file matches the generator byte for byte, so a class added to the hunt",
        "     engine can never silently lose offline chat coverage. -->",
        "",
        "**Authorized testing only.** Every checklist below is written for work inside a",
        "program's signed scope (named hosts, allowed accounts, allowed methods, rate",
        "limits). GreyIQ's automated passes are passive; anything active is a manual step",
        "you perform in scope, and confirmation always comes from the deterministic prover,",
        "never from this text.",
        "",
    ]
    for class_id, meta in classes.items():
        if not isinstance(meta, dict):
            continue
        name = str(meta.get("name") or class_id).strip()
        lines.append(f"## {name}")
        # The id, its spaced spelling, and the acronym the name carries in parentheses —
        # deduped and sorted so regenerating the file is byte-stable.
        acronym = re.search(r"\(([^)]+)\)", name)
        triggers = sorted({
            str(class_id).lower(),
            str(class_id).replace("-", " ").lower(),
            *([acronym.group(1).strip().lower()] if acronym else []),
        })
        lines.append(f"<!-- triggers: {', '.join(triggers)} -->")
        cwe = str(meta.get("cwe") or "").strip()
        owasp = str(meta.get("owasp") or "").strip()
        lines.append(f"GreyIQ tracks this as vuln class `{class_id}`.")
        if cwe:
            lines.append(f"- CWE: {cwe}")
        if owasp:
            lines.append(f"- OWASP: {owasp}")
        checklist = [str(step).strip() for step in (meta.get("checklist") or []) if str(step).strip()]
        if checklist:
            lines.append("")
            lines.append("How to test it inside scope:")
            for index, step in enumerate(checklist, start=1):
                lines.append(f"{index}. {step}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
