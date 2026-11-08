"""Structural PII detection, vendored from presidio-hardened-x402 0.14.0 (MIT, same authors).

Source: ``presidio_x402/pii_filter.py``: the Unicode normalisation, the bounded
percent-escape and HTML character-reference decoding with its span map, the six regex
patterns, and the span de-duplication of ``PIIFilter._scan_regex``. Vendored rather than
imported because x402's base dependencies include presidio-analyzer and spaCy, too heavy
for a lab that only verifies a release (docs/adr/0003). ``tests/test_detect.py``
checks that this copy and the installed x402 agree, whenever x402 is installed.

Matched text never leaves this module: callers get the redacted string and counts.
"""

from __future__ import annotations

import html.entities
import re
import unicodedata
from collections import Counter

# Invisible codepoints are stripped before matching: every Unicode format character
# (general category Cf). That covers zero-width space/non-joiner/joiner, byte-order
# mark, soft hyphen and word joiner, and also the BiDi embeddings, overrides and
# isolates (U+202A-U+202E, U+2066-U+2069) and the tag characters (U+E0001-U+E007F).
# A fixed list missed the BiDi controls, which split an address so that no fragment
# matched; the category test closes that class rather than one codepoint at a time.


def _is_invisible(c: str) -> bool:
    return unicodedata.category(c) == "Cf"


# Cyrillic → ASCII homoglyph map. Manual (no external dep) coverage of the
# Latin-lookalike Cyrillic letters commonly used in evasion.
_HOMOGLYPH_FOLD = str.maketrans(
    {
        "а": "a",
        "А": "A",
        "е": "e",
        "Е": "E",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "с": "c",
        "С": "C",
        "х": "x",
        "Х": "X",
        "у": "y",
        "У": "Y",
        "і": "i",
        "І": "I",
        "ј": "j",
        "Ј": "J",
        "ѕ": "s",
        "Ѕ": "S",
        "к": "k",
        "К": "K",
        "н": "H",
        "М": "M",
        "Т": "T",
        "В": "B",
    }
)

# Hyphen-like characters folded to ASCII hyphen-minus.
_HYPHEN_FOLD = str.maketrans(
    {
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
        "\ufe58": "-",
        "\ufe63": "-",
        "\uff0d": "-",
    }
)


# Maximum number of decoding rounds applied before matching. Each round decodes
# percent-escapes, then HTML character references. One round recovers ordinary
# escapes (``%40`` or ``&#64;`` → ``@``); two recover double-encoded ones
# (``%2540`` → ``%40`` → ``@``, ``&amp;#64;`` → ``&#64;`` → ``@``). The cap is
# hard rather than "decode until stable" — unbounded iteration would turn the
# decoder into an amplification vector on hostile input.
_MAX_DECODE_ROUNDS = 2

# A well-formed percent escape. Used as a cheap presence test so input without
# escapes — the common case — skips the decoding pass entirely.
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# An HTML character reference: decimal (``&#64;``), hex (``&#x40;``) or named
# (``&commat;``). Metadata that passed through an HTML or XML layer carries these,
# and ``alice&#64;example.com`` reaches the email pattern in no form it can match.
# Only terminated references are decoded; a bare ``&`` or an unknown name is
# copied through verbatim.
_CHAR_REF = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")


def _normalise(text: str) -> str:
    """Canonicalise *text* to foil regex-evasion via Unicode encoding tricks.

    Steps: NFKC → strip invisible codepoints → fold Cyrillic homoglyphs and
    hyphen-like characters to ASCII equivalents.

    Percent- and character-reference decoding are deliberately *not* among these
    steps: the result of ``_normalise`` is returned to the caller, and decoding
    there would rewrite benign escapes and change URL semantics (``%2F`` is not
    ``/``, ``&amp;`` is not ``&`` in markup). Both are handled separately by
    :func:`_decode_for_matching`, whose output is used for matching only.
    """
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if not _is_invisible(c))
    text = text.translate(_HOMOGLYPH_FOLD)
    text = text.translate(_HYPHEN_FOLD)
    return text


def _decode_percent_once(text: str) -> tuple[str, list[int]]:
    """Apply one round of percent-decoding, returning the result and an index map.

    ``index_map[i]`` is the offset in *text* at which decoded character ``i``
    originates, and ``index_map[len(decoded)] == len(text)``. A decoded span
    ``[a, b)`` therefore maps back to ``[index_map[a], index_map[b])``.

    Malformed escapes (``%zz``, a trailing ``%``) are copied through verbatim
    rather than raising: the filter is fail-closed on exceptions, so a decode
    error would block an otherwise legitimate payment.
    """
    out: list[str] = []
    index_map: list[int] = []
    i = 0
    n = len(text)
    while i < n:
        if (
            text[i] == "%"
            and i + 2 < n
            and text[i + 1] in _HEX_DIGITS
            and text[i + 2] in _HEX_DIGITS
        ):
            # Consume the maximal run of consecutive escapes: percent-encoding
            # encodes bytes, so one non-ASCII character can span several of them.
            starts: list[int] = []
            raw = bytearray()
            j = i
            while (
                j + 2 < n
                and text[j] == "%"
                and text[j + 1] in _HEX_DIGITS
                and text[j + 2] in _HEX_DIGITS
            ):
                raw.append(int(text[j + 1 : j + 3], 16))
                starts.append(j)
                j += 3
            try:
                run = raw.decode("utf-8")
            except UnicodeDecodeError:
                run = raw.decode("latin-1")
            last = len(starts) - 1
            for k, ch in enumerate(run):
                out.append(ch)
                # Exact for single-byte escapes. A multi-byte sequence decodes to
                # fewer characters than it had escapes; clamping keeps the map
                # monotone and keeps every mapped span inside the run.
                index_map.append(starts[k if k <= last else last])
            i = j
        else:
            out.append(text[i])
            index_map.append(i)
            i += 1
    index_map.append(n)
    return "".join(out), index_map


def _char_ref_value(ref: str) -> str | None:
    """Return the text a character reference such as ``&#64;`` stands for.

    ``None`` for an unknown name or a codepoint that is not a valid scalar value
    (zero, a surrogate, or above U+10FFFF); the caller then keeps the reference.
    """
    body = ref[1:-1]
    if body.startswith(("#x", "#X")):
        codepoint = int(body[2:], 16)
    elif body.startswith("#"):
        codepoint = int(body[1:])
    else:
        return html.entities.html5.get(body + ";")
    if codepoint == 0 or codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
        return None
    return chr(codepoint)


def _decode_char_refs_once(text: str) -> tuple[str, list[int]]:
    """Decode HTML character references once, with the same index map as
    :func:`_decode_percent_once`.

    Every character a reference expands to maps to the reference's ``&``, so a
    match that covers the decoded character covers the whole reference in *text*.
    """
    out: list[str] = []
    index_map: list[int] = []
    pos = 0
    for m in _CHAR_REF.finditer(text):
        value = _char_ref_value(m.group(0))
        if value is None:
            continue
        for i in range(pos, m.start()):
            out.append(text[i])
            index_map.append(i)
        for ch in value:
            out.append(ch)
            index_map.append(m.start())
        pos = m.end()
    for i in range(pos, len(text)):
        out.append(text[i])
        index_map.append(i)
    index_map.append(len(text))
    return "".join(out), index_map


def _has_encoding(text: str) -> bool:
    return bool(_PERCENT_ESCAPE.search(text) or _CHAR_REF.search(text))


def _decode_for_matching(text: str) -> tuple[str, list[int]] | None:
    """Decode percent-escapes and HTML character references in *text* for
    matching, with a span map back to *text*.

    Returns ``None`` when *text* carries neither encoding, or when decoding
    leaves it unchanged, so the caller can skip the second scan entirely.
    Otherwise returns ``(decoded, index_map)`` — see :func:`_decode_percent_once`
    for the map's meaning. Each round runs the percent pass and then the
    character-reference pass, so a percent-encoded reference (``%26%2364%3B``)
    is recovered in one round.
    """
    if not _has_encoding(text):
        return None

    decoded = text
    index_map = list(range(len(text) + 1))
    for _ in range(_MAX_DECODE_ROUNDS):
        before = decoded
        for decode_once in (_decode_percent_once, _decode_char_refs_once):
            candidate, step = decode_once(decoded)
            if candidate != decoded:
                decoded = candidate
                # step maps new offsets to the previous pass's; compose back to *text*.
                index_map = [index_map[offset] for offset in step]
        if decoded == before or not _has_encoding(decoded):
            break

    if decoded == text:
        return None
    return decoded, index_map


# ---------------------------------------------------------------------------
# Regex-mode PII patterns
# Ordered: most specific first to avoid overlapping matches.
# All digit classes are ASCII-only ([0-9]) to avoid false positives on
# Unicode decimal-digit codepoints (Arabic-Indic, Devanagari, etc.).
# ---------------------------------------------------------------------------
_CC_SEP = r"[-\s]?"


def _cc_tail(n: int) -> str:
    """Match *n* ASCII card digits, each optionally preceded by a common separator."""
    return rf"(?:{_CC_SEP}[0-9]){{{n}}}"


_REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Structural: emails
    (
        "EMAIL_ADDRESS",
        # deident change: the lookbehind starts a match only at the start of a run of
        # local-part characters. Upstream tries every position and is quadratic on a long
        # run without "@" (40k characters: seconds). Matches are unchanged.
        re.compile(
            r"(?<![a-zA-Z0-9._%+\-])[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            re.IGNORECASE,
        ),
    ),
    # Structural: US SSNs (with or without dashes)
    (
        "US_SSN",
        re.compile(r"\b(?!000|666|9[0-9]{2})[0-9]{3}[-\s]?(?!00)[0-9]{2}[-\s]?(?!0000)[0-9]{4}\b"),
    ),
    # Structural: credit/debit card numbers (13–19 digit, major networks)
    (
        "CREDIT_CARD",
        re.compile(
            r"(?<![0-9])(?:"
            r"4"
            + _cc_tail(12)
            + rf"(?:{_CC_SEP}[0-9]){{0,6}}"
            + r"|5[1-5]"
            + _cc_tail(14)
            + r"|3[47]"
            + _cc_tail(13)
            + r"|3(?:0[0-5]|[68][0-9])"
            + _cc_tail(11)
            + r"|6(?:011|5[0-9]{2})"
            + _cc_tail(12)
            + r"|(?:2131|1800|35[0-9]{3})"
            + _cc_tail(11)
            + r")(?![-\s]?[0-9])"
        ),
    ),
    # Structural: US phone numbers. The area code is matched as a whole unit —
    # either ``(NNN)`` or ``NNN`` followed by a separator — so the span includes the
    # leading ``(`` / ``+1`` instead of starting mid-number (a leading ``\b`` with an
    # optional ``\(?`` truncated ``(415) 555-0182`` to ``415) 555-0182``, mis-aligning
    # the redaction span). Digit lookarounds replace ``\b`` so the parens don't break it.
    (
        "PHONE_NUMBER",
        re.compile(
            r"(?<![0-9])(?:\+?1[-.\s]?)?"
            r"(?:\([0-9]{3}\)[-.\s]?|[0-9]{3}[-.\s])"
            r"[0-9]{3}[-.\s][0-9]{4}(?![0-9])"
        ),
    ),
    # Structural: IBAN (EU bank accounts)
    (
        "IBAN_CODE",
        re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,16})\b"),
    ),
    # Structural: IPv4 addresses (common in resource URLs, may be PII in some contexts)
    (
        "IP_ADDRESS",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
    ),
]


ENTITY_TYPES = tuple(name for name, _ in _REGEX_PATTERNS)
TEMPLATE = "<{entity_type}>"
# Stable identifier of this detector in signed records. Bump the suffix when matches change.
DETECTOR_ID = "presidio-regex-pii/1"


def _spans(text: str) -> list[tuple[str, int, int]]:
    decoded = _decode_for_matching(text)
    spans: list[tuple[str, int, int]] = []
    for entity_type, pattern in _REGEX_PATTERNS:
        for m in pattern.finditer(text):
            spans.append((entity_type, m.start(), m.end()))
    if decoded is not None:
        decoded_text, index_map = decoded
        for entity_type, pattern in _REGEX_PATTERNS:
            for m in pattern.finditer(decoded_text):
                start, end = index_map[m.start()], index_map[m.end()]
                if end > start:
                    spans.append((entity_type, start, end))
    ordered = sorted(enumerate(spans), key=lambda t: (t[1][1], t[0]))
    kept: list[tuple[str, int, int]] = []
    last_end = -1
    for _rank, (entity_type, start, end) in ordered:
        if start >= last_end:
            kept.append((entity_type, start, end))
            last_end = end
    return kept


def scrub(text: str) -> tuple[str, Counter]:
    """Normalise ``text``, redact every detected entity as ``<TYPE>``, count per type.

    As in x402, the returned text is the normalised form even when nothing is found.
    """
    if not text:
        return text, Counter()
    text = _normalise(text)
    parts: list[str] = []
    counts: Counter = Counter()
    pos = 0
    for entity_type, start, end in _spans(text):
        parts.append(text[pos:start])
        parts.append(TEMPLATE.format(entity_type=entity_type))
        counts[entity_type] += 1
        pos = end
    parts.append(text[pos:])
    return "".join(parts), counts


def detect(text: str) -> Counter:
    """Counts per entity type, without redaction."""
    if not text:
        return Counter()
    return Counter(t for t, _, _ in _spans(_normalise(text)))
