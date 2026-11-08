import datetime as dt
import json

import pytest

pa = pytest.importorskip("pyarrow")
pq = pytest.importorskip("pyarrow.parquet")

from presidio_deident.cli import main  # noqa: E402
from presidio_deident.errors import DeidentError  # noqa: E402
from presidio_deident.release import RECORD_FILE, run_release  # noqa: E402
from presidio_deident.verify import verify_release  # noqa: E402

POLICY = """[release]
dataset_id = "visits-2026"
recipient = "lab-example"
signer = "acme-data-release"
released_at = "2026-11-08T00:00:00Z"

[columns]
patient_id = { action = "pseudonymise" }
email = { action = "drop" }
age = { action = "generalise", bin = 10 }
visit = { action = "generalise", date = "month" }
note = { action = "scrub_text" }
score = { action = "keep" }
seen = { action = "keep" }
when = { action = "keep" }

[[suppression]]
name = "opt-out"
file = "optout.txt"
column = "email"
normalise = ["strip", "lower"]
as_of = "2026-11-01"

[risk]
quasi_identifiers = ["age", "visit"]
"""

TABLE = {
    "patient_id": [101, 102, 103],
    "email": ["a@example.com", "B@example.com", None],
    "age": [34, 47, 51],
    "visit": [dt.date(2026, 3, 1), dt.date(2026, 3, 9), None],
    "note": ["call 415-555-0182", "fine", None],
    "score": [0.5, float("nan"), 2.25],
    "seen": [True, False, None],
    "when": [dt.datetime(2026, 3, 1, 10, 0), None, dt.datetime(2026, 3, 2, 11, 30)],
}


@pytest.fixture
def pws(ws):
    ws.data = ws.root / "visits.parquet"
    pq.write_table(pa.table(TABLE), ws.data)
    (ws.root / "optout.txt").write_text("b@example.com\n")
    ws.policy_file.write_text(POLICY)
    return ws


def _run(ws, out="rel"):
    return run_release(
        ws.policy(), ws.data, ws.root / out, sign_key=ws.sign_key, pseudonym_key=ws.pseudo_key
    )


def test_parquet_release(pws):
    record = _run(pws)
    assert record["rows"] == {"in": 3, "suppressed": 1, "out": 2}
    assert "pyarrow" in record["tools"]
    out = pq.read_table(pws.root / "rel" / "visits.parquet")
    schema = {f.name: f.type for f in out.schema}
    assert "email" not in schema
    assert schema["patient_id"] == pa.string() and schema["age"] == pa.string()
    assert schema["score"] == pa.float64() and schema["seen"] == pa.bool_()
    assert pa.types.is_timestamp(schema["when"])
    rows = out.to_pylist()
    assert rows[0]["age"] == "30-39" and rows[0]["visit"] == "2026-03"
    assert rows[0]["note"] == "call <PHONE_NUMBER>"
    assert rows[1]["visit"] is None and rows[1]["note"] is None
    assert len(rows[0]["patient_id"]) == 32
    assert record["risk"]["rows"] == 2
    assert verify_release(pws.root / "rel", pws.trust).ok


def test_parquet_is_deterministic(pws):
    _run(pws, "a")
    _run(pws, "b")
    a = (pws.root / "a" / "visits.parquet").read_bytes()
    assert a == (pws.root / "b" / "visits.parquet").read_bytes()
    ra = json.loads((pws.root / "a" / RECORD_FILE).read_text())
    rb = json.loads((pws.root / "b" / RECORD_FILE).read_text())
    assert ra == rb


def test_parquet_large_file_is_batched(pws):
    n = 10_000
    pq.write_table(
        pa.table(
            {
                "patient_id": list(range(n)),
                "email": [None] * n,
                "age": [30] * n,
                "visit": [dt.date(2026, 1, 1)] * n,
                "note": ["x"] * n,
                "score": [1.0] * n,
                "seen": [True] * n,
                "when": [None] * n,
            }
        ),
        pws.data,
    )
    record = _run(pws)
    assert record["rows"]["out"] == n and record["risk"]["min_k"] == n
    assert pq.read_table(pws.root / "rel" / "visits.parquet").num_rows == n


def test_unsupported_parquet_types_are_refused(pws):
    pq.write_table(pa.table({"patient_id": [[1, 2]]}), pws.data)
    with pytest.raises(DeidentError, match="only strings, integers"):
        _run(pws)
    pq.write_table(pa.table({"a": [1]}).rename_columns([""]), pws.data)
    with pytest.raises(DeidentError, match="empty or duplicate"):
        _run(pws)


def test_float_cannot_be_pseudonymised(pws):
    pws.policy_file.write_text(
        POLICY.replace('score = { action = "keep" }', 'score = { action = "pseudonymise" }')
    )
    with pytest.raises(DeidentError, match="string or integer"):
        _run(pws)
    assert not (pws.root / "rel").exists()


def test_corrupt_parquet_is_refused(pws, capsys):
    pws.data.write_bytes(b"PAR1 not really parquet PAR1")
    with pytest.raises(DeidentError, match="not a readable Parquet file"):
        _run(pws)
    good = pws.root / "g.parquet"
    pq.write_table(pa.table(TABLE), good)
    data = bytearray(good.read_bytes())
    data[200:260] = b"\x00" * 60
    pws.data.write_bytes(bytes(data))
    with pytest.raises(DeidentError, match="not a readable Parquet file"):
        _run(pws, "r2")
    assert main(["inspect", str(pws.data)]) == 2


def test_inspect_and_risk_on_parquet(pws, capsys):
    assert main(["inspect", str(pws.data)]) == 0
    out = capsys.readouterr().out
    assert "PHONE_NUMBER 1" in out and "8 columns" in out
    assert main(["risk", str(pws.data), "--qi", "age,visit"]) == 0
    assert json.loads(capsys.readouterr().out)["classes"] == 3
    assert main(["risk", str(pws.data), "--qi", "ghost"]) == 2


def test_missing_pyarrow_is_a_clear_error(pws, monkeypatch):
    import builtins

    real = builtins.__import__

    def fake(name, *a, **kw):
        if name.startswith("pyarrow"):
            raise ImportError(name)
        return real(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(DeidentError, match="'parquet' extra"):
        _run(pws)
