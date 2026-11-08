import hashlib
import json

import pytest
from conftest import POLICY, SECRETS, leaks

from presidio_deident import RECORD_SCHEMA
from presidio_deident.errors import DeidentError
from presidio_deident.release import (
    EVIDENCE_FILE,
    RECORD_FILE,
    derive_pseudonym_key,
    pseudonymise,
    run_release,
)
from presidio_deident.verify import verify_release


def _run(ws, out="release", **kw):
    kw.setdefault("pseudonym_key", ws.pseudo_key)
    return run_release(ws.policy(), ws.data, ws.root / out, sign_key=ws.sign_key, **kw)


def test_release_end_to_end(ws):
    record = _run(ws)
    out = ws.root / "release"
    assert sorted(p.name for p in out.iterdir()) == [EVIDENCE_FILE, RECORD_FILE, "tickets.csv"]
    assert record["schema"] == RECORD_SCHEMA
    assert record["rows"] == {"in": 3, "suppressed": 1, "out": 2}
    assert record["suppression"][0]["rows_matched"] == 1
    assert record["suppression"][0]["entries"] == 1
    cols = {c["name"]: c for c in record["columns"]}
    assert cols["body"]["entities"] == {"PHONE_NUMBER": 1}
    assert cols["ticket_id"]["changed"] == 2
    assert cols["country"]["entities"] == {}
    assert record["pseudonyms"] == {"scheme": "hmac-sha256-128/v1", "domain": "lab-example"}
    assert "parents" not in record
    lines = (out / "tickets.csv").read_text().splitlines()
    assert lines[0] == "ticket_id,country,body,opened"
    assert "<PHONE_NUMBER>" in lines[1]
    assert verify_release(out, ws.trust).ok


def test_no_source_value_reaches_the_release(ws):
    _run(ws)
    out = ws.root / "release"
    blob = "".join(p.read_text() for p in out.iterdir())
    assert leaks(blob) == []
    assert leaks("x 1001 y") == ["1001"] and leaks("ab1001cd") == []


def test_release_is_deterministic(ws):
    a = _run(ws, "a")
    b = _run(ws, "b")
    assert a == b
    assert (ws.root / "a" / "tickets.csv").read_bytes() == (
        ws.root / "b" / "tickets.csv"
    ).read_bytes()


def test_policy_hash_is_the_file_hash(ws):
    record = _run(ws)
    assert record["policy_sha256"] == hashlib.sha256(ws.policy_file.read_bytes()).hexdigest()


def test_pseudonyms_depend_on_the_domain(ws):
    key = ws.pseudo_key
    a = pseudonymise(derive_pseudonym_key(key, "lab-a"), "1001")
    b = pseudonymise(derive_pseudonym_key(key, "lab-b"), "1001")
    assert a != b and len(a) == 32
    ws.policy(
        POLICY.replace('signer = "acme', 'pseudonym_domain = "shared-domain"\nsigner = "acme')
    )
    rec = _run(ws)
    assert rec["pseudonyms"]["domain"] == "shared-domain"


def test_normalised_pseudonyms(ws):
    text = POLICY.replace(
        'email = { action = "drop" }',
        'email = { action = "pseudonymise", normalise = ["strip", "lower"] }',
    )
    ws.data.write_text(
        "ticket_id,email,customer_name,country,body,opened\n"
        "1,A@x.com,n,DE,t,d\n2, a@x.com ,n,DE,t,d\n"
    )
    ws.policy(text)
    _run(ws)
    rows = (ws.root / "release" / "tickets.csv").read_text().splitlines()[1:]
    assert rows[0].split(",")[1] == rows[1].split(",")[1]


def test_jsonl_release(ws):
    ws.data = ws.root / "t.jsonl"
    ws.data.write_text(
        json.dumps(
            {
                "ticket_id": 7,
                "email": "a@x.com",
                "customer_name": "n",
                "country": "DE",
                "body": "mail a@x.com",
                "opened": "2026",
            }
        )
        + "\n\n"
        + json.dumps(
            {
                "ticket_id": 8,
                "email": None,
                "country": "FR",
                "body": None,
                "customer_name": "m",
                "opened": "2026",
            }
        )
        + "\n"
    )
    record = _run(ws)
    lines = (ws.root / "release" / "t.jsonl").read_text().splitlines()
    first = json.loads(lines[0])
    assert set(first) == {"ticket_id", "country", "body", "opened"}
    assert first["body"] == "mail <EMAIL_ADDRESS>"
    assert json.loads(lines[1])["body"] is None
    cols = {c["name"]: c for c in record["columns"]}
    assert cols["email"]["missing"] == 1


def test_jsonl_row_missing_a_key_stays_missing(ws):
    ws.data = ws.root / "t.jsonl"
    ws.data.write_text(
        '{"ticket_id":"1","email":"a@x.com","customer_name":"n","country":"DE","body":"b","opened":"o"}\n'
        '{"ticket_id":"2","customer_name":"n","country":"DE","body":"b","opened":"o"}\n'
    )
    _run(ws)
    second = json.loads((ws.root / "release" / "t.jsonl").read_text().splitlines()[1])
    assert "email" not in second


def test_sha256_suppression_list(ws):
    digest = hashlib.sha256(b"carol@example.net").hexdigest()
    (ws.root / "drop.txt").write_text(digest.upper() + "\n")
    ws.policy(
        POLICY + '\n[[suppression]]\nname = "drop"\nfile = "drop.txt"\ncolumn = "email"\n'
        'format = "sha256"\nnormalise = ["strip", "lower"]\nas_of = "2026-11-01"\n'
    )
    record = _run(ws)
    assert record["rows"] == {"in": 3, "suppressed": 2, "out": 1}


def test_bad_sha256_list_entry(ws):
    (ws.root / "drop.txt").write_text("not-a-hash\n")
    ws.policy(
        POLICY + '\n[[suppression]]\nname = "drop"\nfile = "drop.txt"\ncolumn = "email"\n'
        'format = "sha256"\nas_of = "2026-11-01"\n'
    )
    with pytest.raises(DeidentError, match="line 1 is not hex"):
        _run(ws)


def test_missing_and_non_utf8_suppression_list(ws):
    (ws.root / "optout.txt").unlink()
    with pytest.raises(DeidentError, match="cannot read"):
        _run(ws)
    (ws.root / "optout.txt").write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(DeidentError, match="not UTF-8"):
        _run(ws)


@pytest.mark.parametrize(
    ("change", "match"),
    [
        (lambda t: t.replace('opened = { action = "keep" }\n', ""), "without a policy entry"),
        (
            lambda t: t.replace(
                'opened = { action = "keep" }',
                'opened = { action = "keep" }\nghost = { action = "drop" }',
            ),
            "not in the input",
        ),
    ],
)
def test_policy_must_match_the_columns(ws, change, match):
    ws.policy(change(POLICY))
    with pytest.raises(DeidentError, match=match):
        _run(ws)
    assert not (ws.root / "release").exists()
    assert not (ws.root / "release.partial").exists()


def test_pseudonym_key_required(ws):
    with pytest.raises(DeidentError, match="pseudonym key is required"):
        _run(ws, pseudonym_key=None)


def test_never_overwrites(ws):
    (ws.root / "release").mkdir()
    with pytest.raises(DeidentError, match="never overwritten"):
        _run(ws)


@pytest.mark.parametrize("kind", ["dir", "file"])
def test_leftover_partial_is_refused_not_deleted(ws, kind):
    partial = ws.root / "release.partial"
    if kind == "dir":
        partial.mkdir()
        (partial / "keep-me").write_text("x")
    else:
        partial.write_text("x")
    with pytest.raises(DeidentError, match="interrupted run"):
        _run(ws)
    assert partial.exists()


def test_kept_column_with_pii_needs_a_justification(ws):
    ws.policy(POLICY.replace('body = { action = "scrub_text" }', 'body = { action = "keep" }'))
    with pytest.raises(DeidentError, match="contain detected PII") as exc:
        _run(ws)
    for value in SECRETS:
        assert value not in str(exc.value)
    assert not (ws.root / "release").exists()


def test_justified_kept_column_records_residual_counts(ws):
    ws.policy(
        POLICY.replace(
            'body = { action = "scrub_text" }',
            'body = { action = "keep", justification = "Support text is needed verbatim for the task" }',
        )
    )
    record = _run(ws)
    cols = {c["name"]: c for c in record["columns"]}
    assert cols["body"]["entities"] == {"PHONE_NUMBER": 1}
    assert cols["body"]["justification"].startswith("Support text")


def test_residual_scan_can_be_skipped_and_is_recorded(ws):
    ws.policy(POLICY.replace('body = { action = "scrub_text" }', 'body = { action = "keep" }'))
    record = _run(ws, residual_scan=False)
    assert record["residual_scan"] is False
    assert "entities" not in {c["name"]: c for c in record["columns"]}["body"]


def test_non_text_values_are_refused(ws):
    ws.data = ws.root / "t.jsonl"
    base = {
        "ticket_id": "1",
        "email": "a@x.com",
        "customer_name": "n",
        "country": "DE",
        "body": "b",
        "opened": "o",
    }
    ws.data.write_text(json.dumps({**base, "body": 5}) + "\n")
    with pytest.raises(DeidentError, match="text values only"):
        _run(ws)
    ws.data.write_text(json.dumps({**base, "ticket_id": 1.5}) + "\n")
    with pytest.raises(DeidentError, match="string or integer"):
        _run(ws)
    ws.data.write_text(json.dumps({**base, "email": True}) + "\n")
    with pytest.raises(DeidentError, match="string or integer"):
        _run(ws)


def test_policy_from_file_is_required(ws):
    from dataclasses import replace

    with pytest.raises(DeidentError, match="loaded from its file"):
        run_release(
            replace(ws.policy(), file_sha256=""),
            ws.data,
            ws.root / "r",
            sign_key=ws.sign_key,
            pseudonym_key=ws.pseudo_key,
        )


def test_parents_are_recorded(ws):
    parent = "a" * 64
    ws.policy(
        POLICY.replace(
            'released_at = "2026-11-08T00:00:00Z"',
            f'released_at = "2026-11-08T00:00:00Z"\nparents = ["{parent}"]',
        )
    )
    record = _run(ws)
    assert record["parents"] == [parent]
    assert verify_release(ws.root / "release", ws.trust).ok


def test_released_at_argument_is_validated(ws):
    with pytest.raises(DeidentError, match="released_at"):
        _run(ws, released_at="yesterday")


def test_files_are_private(ws):
    _run(ws)
    out = ws.root / "release"
    assert out.stat().st_mode & 0o077 == 0
    for p in out.iterdir():
        assert p.stat().st_mode & 0o077 == 0


def test_record_matches_the_draft_schema(ws):
    import pathlib

    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (pathlib.Path(__file__).parent.parent / "schemas" / "dataset-release.v1.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    ws.policy(POLICY.replace('signer = "acme', f'parents = ["{"b" * 64}"]\nsigner = "acme'))
    jsonschema.validate(_run(ws), schema)
