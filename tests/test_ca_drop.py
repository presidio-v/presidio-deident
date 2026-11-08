"""California DROP deletion lists, checked against the official CalPrivacy test vectors.

Source: privacy.ca.gov, DROP for data brokers, Technical specifications, Working with the data.
"""

import json
from pathlib import Path

import pytest
from conftest import POLICY

from presidio_deident.errors import DeidentError
from presidio_deident.release import _normalise, drop_hash, run_release

ROOT = Path(__file__).resolve().parent.parent

VECTORS = [
    ("drop-email", "Anna.Smith@Domain.com", "KA18MT/ph6IHYjzT9zwETySDQyvSh87YuoSBpOQtkhE="),
    (
        "drop-email",
        "danielle.johnson12@example.com",
        "mKDnDvwF2inxrKcK1hJN2TRkxPfL6kzNNTtU12eH8Bw=",
    ),
    ("drop-phone", "+1(415)555-9317", "vGM7y5n+hBXRSEAklhHDPCbysyNgYTmXdMcagGUOY8E="),
    ("drop-phone", "+84(90)123 4567", "ptzVkgbv9DonwvPCHmXmJ2SEOaolSh37z3ZzY/Gmm+U="),
    ("drop-phone", "+354(123)4567", "Btrzydf5K6ALAKKXJGFHSx7u5bDzHC9WlVYtpq1n2rY="),
    ("drop-phone", "5551273811", "jr/RAWYVN+ODBf2vRxwBASPwiO4x27OGI1y3IDhcwLo="),
]


@pytest.mark.parametrize(("step", "value", "expected"), VECTORS)
def test_official_vectors(step, value, expected):
    assert drop_hash(_normalise(value, (step,))) == expected


def test_email_whitespace_and_phone_digits():
    assert _normalise(" Anna .Smith@Domain.com\t", ("drop-email",)) == "anna.smith@domain.com"
    assert _normalise("٤١٥ 555", ("drop-phone",)) == "555"  # ASCII digits only


def _policy(ws, norm='["drop-email"]', fmt="ca-drop"):
    ws.policy(
        POLICY + '\n[[suppression]]\nname = "drop-email"\nfile = "drop.csv"\n'
        f'column = "email"\nformat = "{fmt}"\nnormalise = {norm}\nas_of = "2026-11-01"\n'
    )


def _run(ws):
    return run_release(
        ws.policy(), ws.data, ws.root / "rel", sign_key=ws.sign_key, pseudonym_key=ws.pseudo_key
    )


def test_drop_list_suppresses_rows(ws):
    h = drop_hash("carol@example.net")
    (ws.root / "drop.csv").write_text(f"﻿Id,Hash\r\nA7kP2xQ9Lm4R,{h}\r\n")
    _policy(ws)
    record = _run(ws)
    assert record["rows"] == {"in": 3, "suppressed": 2, "out": 1}
    entry = next(s for s in record["suppression"] if s["name"] == "drop-email")
    assert entry["format"] == "ca-drop" and entry["rows_matched"] == 1 and entry["entries"] == 1
    assert h not in (ws.root / "rel" / "release.json").read_text()
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "schemas" / "dataset-release.v1.json").read_text())
    jsonschema.validate(record, schema)


def test_empty_drop_list(ws):
    (ws.root / "drop.csv").write_text("Id,Hash\n")
    _policy(ws)
    assert _run(ws)["rows"]["suppressed"] == 1


@pytest.mark.parametrize(
    ("content", "match"),
    [
        ("", 'header "Id,Hash"'),
        ("Id,Hash,ListType\nA,KA18MT/ph6IHYjzT9zwETySDQyvSh87YuoSBpOQtkhE=,Email\n", "header"),
        ("Id,Hash\nA,KA18MT/ph6IHYjzT9zwETySDQyvSh87YuoSBpOQtkhE\n", "line 2"),
        ("Id,Hash\nA," + "a" * 64 + "\n", "line 2"),
        ("Id,Hash\nA,not base64!\n", "line 2"),
    ],
)
def test_bad_drop_list(ws, content, match):
    (ws.root / "drop.csv").write_text(content)
    _policy(ws)
    with pytest.raises(DeidentError, match=match):
        _run(ws)


@pytest.mark.parametrize(
    ("norm", "fmt", "match"),
    [
        ('["strip", "lower"]', "ca-drop", "needs normalise"),
        ('["drop-email", "drop-phone"]', "ca-drop", "needs normalise"),
        ('["drop-phone"]', "sha256", "apply to format"),
    ],
)
def test_drop_normaliser_rules(ws, norm, fmt, match):
    (ws.root / "drop.csv").write_text("Id,Hash\n")
    with pytest.raises(DeidentError, match=match):
        _policy(ws, norm, fmt)
