"""Regression tests for the v0.1 code review."""

import json
import time

import pytest

from presidio_deident import _detect
from presidio_deident.cli import main
from presidio_deident.errors import DeidentError
from presidio_deident.release import RECORD_FILE, run_release
from presidio_deident.verify import verify_release


def _run(ws, out="rel"):
    return run_release(
        ws.policy(), ws.data, ws.root / out, sign_key=ws.sign_key, pseudonym_key=ws.pseudo_key
    )


def test_detector_is_linear_on_long_runs():
    for text in ("4" * 200_000, "a" * 100_000 + "@" + "b." * 50_000, "a.b" * 60_000):
        start = time.perf_counter()
        _detect.detect(text)
        assert time.perf_counter() - start < 2.0
    assert _detect.scrub("x" * 5000 + " a@b.co")[1] == {"EMAIL_ADDRESS": 1}
    assert _detect.detect("ab.c+d@example.com") == {"EMAIL_ADDRESS": 1}


def _jsonl(ws, line):
    ws.data = ws.root / "t.jsonl"
    ws.data.write_text(line + "\n")


BASE = '"ticket_id":"1","email":"a@x.com","customer_name":"n","body":"b","opened":"o"'


@pytest.mark.parametrize(
    ("country", "match"),
    [
        ('"D\\ud800"', "not valid Unicode"),
        ("NaN", "not valid JSON"),
        ("Infinity", "not valid JSON"),
        ("1e400", "not valid JSON"),
    ],
)
def test_jsonl_values_that_cannot_be_written_are_refused(ws, country, match):
    _jsonl(ws, "{" + BASE + f',"country":{country}' + "}")
    with pytest.raises(DeidentError, match=match):
        _run(ws)
    assert not (ws.root / "rel").exists()


def test_jsonl_key_with_lone_surrogate(ws):
    _jsonl(ws, "{" + BASE + ',"country":"DE","\\udc00":1}')
    with pytest.raises(DeidentError, match="key that is not valid Unicode"):
        _run(ws)


def test_deep_jsonl_is_refused(ws):
    _jsonl(ws, "[" * 100_000 + "]" * 100_000)
    with pytest.raises(DeidentError, match="not valid JSON"):
        _run(ws)


def test_non_utf8_input_is_an_error_without_bytes(ws, capsys):
    ws.data.write_bytes(ws.data.read_bytes().replace(b"Carol Test", b"Carol T\xe9st"))
    with pytest.raises(DeidentError, match="not UTF-8") as exc:
        _run(ws)
    assert "xe9" not in str(exc.value) and "Carol" not in str(exc.value)
    assert main(["inspect", str(ws.data)]) == 2
    bad_header = ws.root / "h.csv"
    bad_header.write_bytes(b"id,n\xe9\n1,2\n")
    assert main(["inspect", str(bad_header)]) == 2
    jl = ws.root / "b.jsonl"
    jl.write_bytes(b'{"a":"ok"}\n{"a":"\xe9"}\n')
    assert main(["inspect", str(jl)]) == 2
    assert "not UTF-8" in capsys.readouterr().err


def test_trailing_newline_in_ids_and_timestamps_is_refused(ws):
    with pytest.raises(DeidentError, match="invalid format"):
        ws.policy(ws.policy_file.read_text().replace('"tickets-2026"', '"tickets-2026\\n"'))
    ws.policy_file.write_text(
        ws.policy_file.read_text().replace('"tickets-2026\\n"', '"tickets-2026"')
    )
    with pytest.raises(DeidentError, match="released_at"):
        run_release(
            ws.policy(),
            ws.data,
            ws.root / "r",
            sign_key=ws.sign_key,
            pseudonym_key=ws.pseudo_key,
            released_at="2026-11-08T00:00:00Z\n",
        )


@pytest.fixture
def rel(ws):
    _run(ws)
    return ws.root / "rel"


def _edit(rel, fn):
    p = rel / RECORD_FILE
    p.chmod(0o644)
    doc = json.loads(p.read_text())
    fn(doc)
    p.write_text(json.dumps(doc))


@pytest.mark.parametrize("rows", ["2", None, True])
def test_non_integer_output_rows_fail_cleanly(ws, rel, rows):
    _edit(rel, lambda d: d["outputs"][0].update(rows=rows))
    v = verify_release(rel, ws.trust)
    assert not v.ok and "row counts add up" in [n for n, ok, _ in v.checks if not ok]


def test_deeply_nested_release_json_fails_cleanly(ws, rel):
    p = rel / RECORD_FILE
    p.chmod(0o644)
    p.write_text("[" * 200_000 + "]" * 200_000)
    v = verify_release(rel, ws.trust)
    assert not v.ok and v.checks[0][0] == "release files readable"


def test_release_id_is_checked(ws, rel):
    _edit(rel, lambda d: d.pop("release_id"))
    failed = [n for n, ok, _ in verify_release(rel, ws.trust).checks if not ok]
    assert "release id names the dataset and time" in failed


def test_parent_with_trailing_newline_fails(ws, rel):
    _edit(rel, lambda d: d.update(parents=["a" * 64 + "\n"]))
    failed = [n for n, ok, _ in verify_release(rel, ws.trust).checks if not ok]
    assert "parents are record hashes" in failed


def test_croissant_with_bad_trust_store_is_a_clean_error(ws, rel, capsys):
    assert (
        main(
            [
                "croissant",
                str(rel),
                "--trust",
                str(ws.root / "missing.json"),
                "--out",
                str(ws.root / "c.json"),
            ]
        )
        == 2
    )
    assert "trust store" in capsys.readouterr().err


# Second review (v0.3.1)


@pytest.mark.parametrize(
    ("edit", "check"),
    [
        (lambda d: d.pop("recipient"), "record recipient is an identifier"),
        (lambda d: d.update(recipient=["lab"]), "record recipient is an identifier"),
        (lambda d: d.update(dataset_id="x@2026"), "record dataset_id is an identifier"),
        (lambda d: d.update(signer=""), "record signer is an identifier"),
        (
            lambda d: d.update(released_at="later", release_id=f"{d['dataset_id']}@later"),
            "record released_at is a UTC timestamp",
        ),
        (
            lambda d: d.update(rows={"in": True, "suppressed": False, "out": True}),
            "row counts add up",
        ),
        (lambda d: d["outputs"].append(dict(d["outputs"][0], rows=0)), "tickets.csv listed once"),
        (lambda d: d["outputs"][0].update(name="release.json"), "output file name is plain"),
    ],
)
def test_record_fields_are_checked(ws, rel, edit, check):
    _edit(rel, edit)
    failed = [n for n, ok, _ in verify_release(rel, ws.trust).checks if not ok]
    assert check in failed


def test_unreadable_data_file_is_a_failed_check(ws, rel, monkeypatch):
    import presidio_deident.verify as vmod

    def boom(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(vmod, "sha256_file", boom)
    failed = [n for n, ok, _ in verify_release(rel, ws.trust).checks if not ok]
    assert failed == ["tickets.csv readable"]


def test_os_errors_are_clean_cli_errors(ws, capsys):
    r = ws.root
    for args in (
        ["inspect", r / "missing.csv"],
        ["risk", r / "missing.csv", "--qi", "a"],
        ["policy-init", ws.data, "--out", r / "no" / "dir" / "p.toml"],
        ["keygen", "--signer", "s", "--sign-key", r / "no" / "k", "--pseudonym-key", r / "k2"],
    ):
        assert main([str(a) for a in args]) == 2
        err = capsys.readouterr().err
        assert err.startswith("error: ") and "Traceback" not in err


def test_parent_to_another_recipient_is_refused(ws, rel, capsys):
    ws.policy_file.write_text(ws.policy_file.read_text().replace('"lab-example"', '"lab-other"'))
    args = [
        "run",
        "--policy",
        ws.policy_file,
        "--input",
        ws.data,
        "--out",
        ws.root / "child",
        "--sign-key",
        ws.root / "sign.key",
        "--pseudonym-key",
        ws.root / "pseudo.key",
        "--parent",
        rel,
    ]
    assert main([str(a) for a in args]) == 2
    assert "another recipient" in capsys.readouterr().err


def test_scrub_keeps_text_without_findings_unchanged(ws):
    ws.data.write_text(
        "ticket_id,email,customer_name,country,body,opened\n1,a@x.com,n,DE,café ﬁne – ok​,d\n"
    )
    record = _run(ws)
    body = {c["name"]: c for c in record["columns"]}["body"]
    assert body["changed"] == 0 and body["entities"] == {}
    assert "café ﬁne – ok​" in (ws.root / "rel" / "tickets.csv").read_text()


def test_generalise_accepts_ascii_digits_only():
    from presidio_deident.generalise import generalise

    with pytest.raises(DeidentError):
        generalise({"date": "year"}, "٢٠٢٦-٠٣-٠١", "w")
    with pytest.raises(DeidentError):
        generalise({"bin": 10}, "٣٤", "w")


def test_min_l_cap_is_recorded():
    from presidio_deident.risk import L_CAP, RiskAccumulator

    acc = RiskAccumulator(["a"], ["s"])
    acc.add({"a": 1, "s": 1})
    assert acc.report()["min_l_cap"] == L_CAP
