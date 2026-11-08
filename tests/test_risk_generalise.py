import csv
import json
import random

import pytest

from presidio_deident.cli import main
from presidio_deident.errors import DeidentError
from presidio_deident.generalise import generalise
from presidio_deident.release import run_release
from presidio_deident.risk import L_CAP, RiskAccumulator
from presidio_deident.verify import verify_release

POLICY = """[release]
dataset_id = "patients-2026"
recipient = "lab-example"
signer = "acme-data-release"
released_at = "2026-11-08T00:00:00Z"

[columns]
patient_id = {{ action = "pseudonymise" }}
age = {age}
postcode = {postcode}
visit = {visit}
diagnosis = {{ action = "keep" }}

[risk]
quasi_identifiers = ["age", "postcode", "visit"]
sensitive = ["diagnosis"]
{extra}
"""

COARSE = dict(
    age='{ action = "generalise", bin = 20, bottom = 20, top = 80 }',
    postcode='{ action = "generalise", prefix = 1 }',
    visit='{ action = "generalise", date = "year" }',
)
RAW = dict(age='{ action = "keep" }', postcode='{ action = "keep" }', visit='{ action = "keep" }')


def _synthetic(path, n=300, seed=7):
    rnd = random.Random(seed)
    with path.open("w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["patient_id", "age", "postcode", "visit", "diagnosis"])
        for i in range(n):
            w.writerow(
                [
                    f"P{i:05d}",
                    rnd.randint(18, 95),
                    f"{rnd.randint(1, 9)}{rnd.randint(0, 9999):04d}",
                    f"202{rnd.randint(4, 6)}-{rnd.randint(1, 12):02d}-{rnd.randint(1, 28):02d}",
                    rnd.choice(["A", "B", "C", "D"]),
                ]
            )


def _policy(ws, cols, extra=""):
    ws.policy_file.write_text(POLICY.format(extra=extra, **cols))
    return ws.policy()


def _run(ws, policy, out="rel"):
    return run_release(
        policy, ws.data, ws.root / out, sign_key=ws.sign_key, pseudonym_key=ws.pseudo_key
    )


@pytest.fixture
def pws(ws):
    ws.data = ws.root / "patients.csv"
    _synthetic(ws.data)
    return ws


def test_generalisation_reduces_risk(pws):
    raw = _run(pws, _policy(pws, RAW), "raw")["risk"]
    coarse_record = _run(pws, _policy(pws, COARSE), "coarse")
    coarse = coarse_record["risk"]
    assert raw["unique_rows"] == 300 and raw["min_k"] == 1
    assert coarse["unique_rows"] < raw["unique_rows"]
    assert coarse["classes"] < raw["classes"]
    assert sum(coarse["rows_by_class_size"].values()) == 300
    assert coarse["sensitive"]["diagnosis"]["min_l"] >= 1
    cols = {c["name"]: c for c in coarse_record["columns"]}
    assert cols["age"]["generalise"] == {"bin": 20, "bottom": 20, "top": 80}
    assert cols["visit"]["changed"] == 300
    rows = list(csv.DictReader((pws.root / "coarse" / "patients.csv").open()))
    assert {r["visit"] for r in rows} <= {"2024", "2025", "2026"}
    assert {r["age"] for r in rows} <= {"<20", "20-39", "40-59", "60-79", "80+"}
    assert all(len(r["postcode"]) == 1 for r in rows)
    assert verify_release(pws.root / "coarse", pws.trust).ok


def test_record_with_risk_matches_the_schema(pws):
    import pathlib

    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (pathlib.Path(__file__).parent.parent / "schemas" / "dataset-release.v1.json").read_text()
    )
    record = _run(pws, _policy(pws, COARSE))
    jsonschema.validate(record, schema)


def test_require_min_k_gate(pws):
    with pytest.raises(DeidentError, match="smallest quasi-identifier class has 1 row"):
        _run(pws, _policy(pws, RAW, "require_min_k = 5"))
    assert not (pws.root / "rel").exists()
    coarse = dict(COARSE, postcode='{ action = "generalise", prefix = 0 }')
    with pytest.raises(DeidentError, match="prefix must be an integer >= 1"):
        _policy(pws, coarse)
    loose = dict(COARSE, postcode='{ action = "drop" }')
    with pytest.raises(DeidentError, match="is dropped"):
        _policy(pws, loose)


def test_generalise_values():
    assert generalise({"date": "year"}, "2026-03-04", "w") == "2026"
    assert generalise({"date": "month"}, "2026-03-04T10:00:00Z", "w") == "2026-03"
    assert generalise({"date": "month"}, "2026-03", "w") == "2026-03"
    assert generalise({"prefix": 3}, "10115", "w") == "101"
    assert generalise({"prefix": 3}, 10115, "w") == "101"
    assert generalise({"bin": 10}, "34", "w") == "30-39"
    assert generalise({"bin": 10}, -5, "w") == "-10--1"
    assert generalise({"bin": 1}, 7, "w") == "7"
    spec = {"bin": 20, "bottom": 20, "top": 80}
    assert [generalise(spec, v, "w") for v in (5, 20, 39, 79, 80, 95)] == [
        "<20",
        "20-39",
        "20-39",
        "60-79",
        "80+",
        "80+",
    ]
    assert generalise({"bin": 25, "top": 90}, 80, "w") == "75-89"


@pytest.mark.parametrize(
    ("spec", "value", "match"),
    [
        ({"date": "year"}, "03/04/2026", "ISO date"),
        ({"date": "year"}, "2026-13-01", "ISO date"),
        ({"date": "year"}, 2026, "ISO date"),
        ({"prefix": 2}, 1.5, "text or an integer"),
        ({"bin": 10}, "3.5", "integer"),
        ({"bin": 10}, True, "integer"),
        ({"bin": 10}, None, "integer"),
    ],
)
def test_generalise_refuses_without_printing_the_value(spec, value, match):
    with pytest.raises(DeidentError, match=match) as exc:
        generalise(spec, value, "f row 1, c")
    assert str(value) not in str(exc.value).replace("f row 1, c", "")


@pytest.mark.parametrize(
    ("age", "match"),
    [
        ('{ action = "generalise" }', "exactly one of"),
        ('{ action = "generalise", date = "year", bin = 5 }', "exactly one of"),
        ('{ action = "generalise", date = "week" }', "must be one of"),
        ('{ action = "generalise", prefix = 2, top = 5 }', "bin only"),
        ('{ action = "generalise", bin = 5, bottom = 10, top = 10 }', "greater than bottom"),
        ('{ action = "generalise", bin = true }', "integer"),
        ('{ action = "keep", bin = 5 }', "generalise only"),
    ],
)
def test_generalise_policy_errors(pws, age, match):
    with pytest.raises(DeidentError, match=match):
        _policy(pws, dict(COARSE, age=age))


@pytest.mark.parametrize(
    ("extra_block", "match"),
    [
        ("[risk]\nquasi_identifiers = []\n", "at least one"),
        ('[risk]\nquasi_identifiers = ["ghost"]\n', "not a column"),
        ('[risk]\nquasi_identifiers = ["age", "age"]\n', "twice"),
        ('[risk]\nquasi_identifiers = "age"\n', "list of column names"),
        ('[risk]\nquasi_identifiers = ["age"]\nsensitive = ["age"]\n', "both"),
        ('[risk]\nquasi_identifiers = ["age"]\nrequire_min_k = 1\n', ">= 2"),
        ('[risk]\nquasi_identifiers = ["age"]\nother = 1\n', "unknown key"),
    ],
)
def test_risk_policy_errors(pws, extra_block, match):
    text = POLICY.format(extra="", **COARSE)
    text = text[: text.index("[risk]")] + extra_block
    pws.policy_file.write_text(text)
    with pytest.raises(DeidentError, match=match):
        pws.policy()


def test_risk_accumulator_counts():
    acc = RiskAccumulator(["a", "b"], ["s"])
    for row in (
        {"a": 1, "b": "x", "s": "p"},
        {"a": 1, "b": "x", "s": "q"},
        {"a": 2, "b": "x", "s": "p"},
        {"a": 2, "b": None, "s": "p"},
        {"a": 2, "s": "p"},
    ):
        acc.add(row)
    r = acc.report()
    assert r["classes"] == 3 and r["min_k"] == 1 and r["unique_rows"] == 1
    assert r["rows_by_class_size"]["2"] == 4  # (1,x) and (2,None) incl. the missing key
    assert r["sensitive"]["s"] == {"min_l": 1, "classes_with_one_value": 2}
    empty = RiskAccumulator(["a"]).report()
    assert empty["min_k"] == 0 and empty["classes"] == 0 and "sensitive" not in empty


def test_l_is_capped():
    acc = RiskAccumulator(["a"], ["s"])
    for i in range(L_CAP + 5):
        acc.add({"a": 1, "s": i})
    assert acc.report()["sensitive"]["s"]["min_l"] == L_CAP


def test_risk_cli(pws, capsys):
    assert main(["risk", str(pws.data), "--qi", "age,postcode", "--sensitive", "diagnosis"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["rows"] == 300
    assert main(["risk", str(pws.data), "--qi", "ghost"]) == 2
    assert main(["risk", str(pws.data), "--qi", " , "]) == 2
    jl = pws.root / "x.jsonl"
    jl.write_text('{"a": 1}\n{"a": 1}\n')
    capsys.readouterr()
    assert main(["risk", str(jl), "--qi", "a"]) == 0
    assert json.loads(capsys.readouterr().out)["min_k"] == 2
