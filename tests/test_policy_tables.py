import tomllib

import pytest
from conftest import POLICY

from presidio_deident.errors import DeidentError
from presidio_deident.policy import load_policy, parse_policy, policy_skeleton
from presidio_deident.tables import read_csv, read_jsonl, scan_columns, table_format


def test_policy_parses(ws):
    p = ws.policy()
    assert p.dataset_id == "tickets-2026" and p.domain == "lab-example"
    assert p.columns["ticket_id"].action == "pseudonymise"
    assert p.suppression[0].normalise == ("strip", "lower")
    assert p.rights[0].as_dict()["reference"] == "contract 2026-114"
    assert len(p.file_sha256) == 64


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        ("[release]", "[release]\nextra = 1", "unknown key"),
        ('action = "drop" }', 'action = "delete" }', "must be one of"),
        ('dataset_id = "tickets-2026"', 'dataset_id = "bad id"', "invalid format"),
        ('recipient = "lab-example"', 'recipient = "' + "x" * 65 + '"', "invalid format"),
        ('released_at = "2026-11-08T00:00:00Z"', 'released_at = "2026-11-08"', "invalid format"),
        ('as_of = "2026-11-01"', "as_of = 2026-11-01", "non-empty string"),
        ('column = "email"', 'column = "nope"', "not a column"),
        ('format = "plain"', 'format = "plain"', ""),
        ('normalise = ["strip", "lower"]', 'normalise = ["upper"]', "must list"),
        ('reference = "contract 2026-114"', 'reference = "mail jane@example.com"', "personal data"),
        (
            'ticket_id = { action = "pseudonymise" }',
            'ticket_id = { action = "keep", normalise = ["strip"] }',
            "pseudonymise only",
        ),
        (
            'ticket_id = { action = "pseudonymise" }',
            'ticket_id = { action = "pseudonymise", justification = "' + "j" * 513 + '" }',
            "at most 512",
        ),
        (
            'ticket_id = { action = "pseudonymise" }',
            'ticket_id = { action = "pseudonymise", extra = 1 }',
            "unknown key",
        ),
        (
            'ticket_id = { action = "pseudonymise" }',
            'ticket_id = "pseudonymise"',
            "must be a table",
        ),
    ],
)
def test_policy_is_strict(ws, old, new, match):
    if not match:
        return
    text = POLICY.replace(old, new, 1)
    assert text != POLICY
    with pytest.raises(DeidentError, match=match):
        ws.policy(text)


def test_policy_lists_and_uniqueness(ws, tmp_path):
    with pytest.raises(DeidentError, match="must be a list"):
        ws.policy(POLICY.replace('signer = "acme', 'parents = "x"\nsigner = "acme'))
    with pytest.raises(DeidentError, match="invalid format"):
        ws.policy(POLICY.replace('signer = "acme', 'parents = ["x"]\nsigner = "acme'))
    dup = POLICY + POLICY[POLICY.index("[[suppression]]") :]
    with pytest.raises(DeidentError, match="not unique"):
        ws.policy(dup)
    with pytest.raises(DeidentError, match="must list every column"):
        parse_policy(
            {"release": {"dataset_id": "a", "recipient": "b", "signer": "c"}, "columns": {}},
            tmp_path,
        )
    with pytest.raises(DeidentError, match="must be a table"):
        parse_policy({"columns": {}}, tmp_path)
    with pytest.raises(DeidentError, match="unknown key"):
        parse_policy({"other": 1}, tmp_path)


def test_policy_file_errors(tmp_path):
    with pytest.raises(DeidentError, match="cannot read"):
        load_policy(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("[release\n")
    with pytest.raises(DeidentError, match="not valid"):
        load_policy(bad)


def test_skeleton_round_trips(tmp_path):
    text = policy_skeleton(['a "quoted" col', "email"], {"email": "drop"}, "ds-1")
    data = tomllib.loads(text)
    assert data["columns"]['a "quoted" col'] == {"action": "keep"}
    assert data["columns"]["email"] == {"action": "drop"}
    data["release"].update(recipient="r", signer="s")
    assert parse_policy(data, tmp_path).dataset_id == "ds-1"


def test_table_format():
    from pathlib import Path

    assert table_format(Path("a.CSV")) == "csv"
    assert table_format(Path("a.ndjson")) == "jsonl"
    with pytest.raises(DeidentError, match="unsupported"):
        table_format(Path("a.xlsx"))


def test_csv_reader_rules(tmp_path):
    import io

    with pytest.raises(DeidentError, match="empty file"):
        read_csv(io.StringIO(""), "x.csv")
    with pytest.raises(DeidentError, match="duplicate"):
        read_csv(io.StringIO("a,a\n1,2\n"), "x.csv")
    with pytest.raises(DeidentError, match="malformed CSV header"):
        read_csv(io.StringIO('"a\n'), "x.csv")
    with pytest.raises(DeidentError, match="duplicate"):
        read_csv(io.StringIO("a,\n1,2\n"), "x.csv")
    _, rows = read_csv(io.StringIO("a,b\n1,2,3\n"), "x.csv")
    with pytest.raises(DeidentError, match="line 2 has 3 fields"):
        list(rows)
    _, rows = read_csv(io.StringIO('a,b\n1,"x\n'), "x.csv")
    with pytest.raises(DeidentError):
        list(rows)
    _, rows = read_csv(io.StringIO("a,b\n\n1,2\n"), "x.csv")
    assert list(rows) == [{"a": "1", "b": "2"}]
    bom = tmp_path / "bom.csv"
    bom.write_bytes("﻿id,x\n1,2\n".encode())
    assert scan_columns(bom) == ["id", "x"]


def test_jsonl_reader_rules(tmp_path):
    import io

    with pytest.raises(DeidentError, match="not valid JSON"):
        list(read_jsonl(io.StringIO("{bad\n"), "x.jsonl"))
    with pytest.raises(DeidentError, match="not a JSON object"):
        list(read_jsonl(io.StringIO("[1]\n"), "x.jsonl"))
    with pytest.raises(DeidentError, match="field 'a' is nested") as exc:
        list(read_jsonl(io.StringIO('{"a": {"secret": "jane@example.com"}}\n'), "x.jsonl"))
    assert "jane" not in str(exc.value)
    f = tmp_path / "x.jsonl"
    f.write_text('{"a":1}\n{"b":2,"a":3}\n')
    assert scan_columns(f) == ["a", "b"]
