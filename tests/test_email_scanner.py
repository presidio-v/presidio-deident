"""The email scanner finds exactly the matches of the upstream regex, in linear time.

0.2.0 to 0.7.0 anchored the regex with a lookbehind instead. That was linear but missed an
address that directly follows another one through a local-part character, so
"a@b.cc+victim@example.com" left "victim@example.com" unredacted.
"""

import random
import re
import time

import pytest

from presidio_deident import _detect
from presidio_deident._detect import EMAIL_PATTERN, _EmailScanner

REFERENCE = re.compile(EMAIL_PATTERN, re.IGNORECASE)
ALPHABET = "aZ09._%+-@-..@ xKſKİı,;<>\nmc"


def test_same_matches_as_the_regex():
    rnd = random.Random(20261108)
    scanner = _EmailScanner()
    for _ in range(50_000):
        s = "".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(0, 60)))
        assert [m.span() for m in scanner.finditer(s)] == [
            m.span() for m in REFERENCE.finditer(s)
        ], s


@pytest.mark.parametrize(
    "text",
    [
        "a@b.cc+victim@example.com",
        "x@y.io-victim@example.com",
        "a@b.cc_victim@example.com",
        "a@b.cc%victim@example.com",
    ],
)
def test_adjacent_addresses_are_both_redacted(text):
    redacted, counts = _detect.scrub(text)
    assert "victim" not in redacted and counts["EMAIL_ADDRESS"] == 2


@pytest.mark.parametrize(
    "text",
    [
        "a" * (1 << 18),
        "a@" + "a." * (1 << 17),
        "@" * (1 << 18),
        "x." * (1 << 17) + "@",
        "a@b" * 80_000,
    ],
)
def test_linear_time(text):
    start = time.perf_counter()
    list(_EmailScanner().finditer(text))
    assert time.perf_counter() - start < 1.0
