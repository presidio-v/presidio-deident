import pytest

from presidio_deident import _detect
from presidio_deident.inspect import inspect_file

SAMPLES = [
    "",
    "nothing to see here",
    "mail alice@example.com today",
    "escaped alice%40example.com and alice&#64;example.org and %2540x@y.com",
    "call (415) 555-0182 or +1 415-555-0183",
    "SSN 123-45-6789, card 4111-1111-1111-1111",
    "IBAN DE89370400440532013000 from 192.168.10.20",
    "zero​width al​ice@example.com, fullwidth ａｌｉｃｅ@example.com",
    "cyrillic аlice@example.com",
    "bad escapes %zz &unknown; &#0; tail%",
]


def test_scrub_and_detect():
    text, counts = _detect.scrub("mail alice@example.com, call 415-555-0182")
    assert text == "mail <EMAIL_ADDRESS>, call <PHONE_NUMBER>"
    assert counts == {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 1}
    assert _detect.detect("") == {}
    assert _detect.scrub("") == ("", {})
    assert _detect.detect("escaped alice%40example.com") == {"EMAIL_ADDRESS": 1}


def test_parity_with_x402():
    """The vendored copy must agree with the installed x402 PIIFilter (regex mode)."""
    x402 = pytest.importorskip("presidio_x402.pii_filter")
    flt = x402.PIIFilter(mode="regex", redaction_template=_detect.TEMPLATE)
    for text in SAMPLES:
        expected, hits = flt.scan_and_redact(text)
        got, counts = _detect.scrub(text)
        assert got == expected, text
        assert sum(counts.values()) == len(hits)


def test_inspect_jsonl_and_suggestions(tmp_path):
    f = tmp_path / "x.jsonl"
    f.write_text(
        '{"user_id": 1, "note": "write to alice@example.com about it", "birth_date": "1990", "flag": true}\n'
        '{"user_id": 2, "note": null}\n'
        '{"user_id": 3, "code": "4111111111111111"}\n'
    )
    reports, n = inspect_file(f, sample=10)
    by = {r.name: r for r in reports}
    assert n == 3
    assert by["user_id"].suggestion() == "pseudonymise"
    assert by["note"].suggestion() == "scrub_text" and by["note"].missing == 2
    assert by["birth_date"].suggestion() == "drop"
    assert by["flag"].suggestion() == "keep"
    assert by["code"].suggestion() == "drop"
    reports, n = inspect_file(f, sample=1, detect=False)
    assert n == 1 and not any(r.entities for r in reports)
