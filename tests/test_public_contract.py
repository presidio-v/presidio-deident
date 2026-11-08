"""The public contract: the committed sample release, `verify --json`, check names, exit codes.

A failure here means a change that breaks labs' scripts or records already in circulation.
Change it only together with SEMVER.md and a new `verify-result@N` or record schema.
"""

import json
import re
import shutil
from pathlib import Path

import presidio_evidence as pe
import pytest

from presidio_deident.cli import VERIFY_RESULT, main
from presidio_deident.release import run_release
from presidio_deident.verify import read_json, verify_release

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SAMPLE = EXAMPLES / "sample-release"
TRUST = EXAMPLES / "sample-trust.json"

RESULT_KEYS = {
    "result",
    "ok",
    "schema",
    "release_id",
    "record_hash",
    "checks",
    "extra_files",
    "verifier",
}

# Check names are part of the contract; per-file checks repeat for every listed file.
RECORD_CHECKS = [
    "record schema",
    "record dataset_id is an identifier",
    "record recipient is an identifier",
    "record signer is an identifier",
    "record released_at is a UTC timestamp",
    "exactly one signed ref",
    "signature (evidence-ref@3, trusted signer)",
    "ref signs this record",
    "ref names this dataset",
    "ref signer is the record signer",
    "ref points at release.json",
    "unsigned envelope fields match the record",
    "row counts add up",
    "parents are record hashes",
    "release id names the dataset and time",
    "record lists output files",
]
FILE_CHECKS = [
    "output file name is plain",
    "{f} listed once",
    "{f} present",
    "{f} sha256",
    "{f} size",
]


def _trust():
    return pe.load_trust_store(TRUST.read_text(encoding="utf-8"))


def test_committed_sample_verifies():
    v = verify_release(SAMPLE, _trust())
    assert v.ok, [c for c in v.checks if not c[1]]
    assert v.record["schema"] == "presidio-deident/dataset-release@1"
    assert v.record["detector"]["name"] == "presidio-regex-pii/1"


def test_check_names_are_stable():
    """Names are frozen; their order is not (ADR-0009)."""
    v = verify_release(SAMPLE, _trust())
    expected = RECORD_CHECKS + [c.format(f="tickets.csv") for c in FILE_CHECKS]
    assert sorted(n for n, _, _ in v.checks) == sorted(expected)


def test_verify_json_contract(capsys, tmp_path):
    assert main(["verify", str(SAMPLE), "--trust", str(TRUST), "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert set(doc) == RESULT_KEYS
    assert doc["result"] == VERIFY_RESULT == "presidio-deident/verify-result@1"
    assert doc["ok"] is True and doc["schema"] == "presidio-deident/dataset-release@1"
    assert doc["release_id"] == "tickets-2026@2026-11-08T00:00:00Z"
    assert re.fullmatch(r"[0-9a-f]{64}", doc["record_hash"])
    assert set(doc["verifier"]) == {"presidio-deident", "presidio-evidence"}
    assert all(set(c) == {"check", "ok", "detail"} for c in doc["checks"])

    copy = tmp_path / "rel"
    shutil.copytree(SAMPLE, copy)
    (copy / "tickets.csv").write_text("tampered\n")
    assert main(["verify", str(copy), "--trust", str(TRUST), "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert set(doc) == RESULT_KEYS
    assert doc["ok"] is False and doc["schema"] is None and doc["release_id"] is None
    assert re.fullmatch(r"[0-9a-f]{64}", doc["record_hash"])
    assert [c["check"] for c in doc["checks"] if not c["ok"]] == [
        "tickets.csv sha256",
        "tickets.csv size",
    ]


def test_exit_code_2_when_verification_cannot_start(capsys, tmp_path):
    assert main(["verify", str(SAMPLE), "--trust", str(tmp_path / "missing.json")]) == 2


def test_keygen_keys_sign_and_verify(ws, capsys, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    assert main(["keygen", "--signer", "s", "--sign-key", str(a), "--pseudonym-key", str(b)]) == 0
    trust = pe.load_trust_store(capsys.readouterr().out)
    pseudo = b.read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{64}", pseudo)
    assert pseudo != a.read_text().strip()
    # a release signed with the written keys verifies under the printed trust store
    ws.policy_file.write_text(
        ws.policy_file.read_text().replace('signer = "acme-data-release"', 'signer = "s"')
    )
    out = tmp_path / "rel"
    run_release(ws.policy(), ws.data, out, sign_key=pe.load_private_key(a), pseudonym_key=pseudo)
    assert verify_release(out, trust).ok


@pytest.mark.parametrize("name", ["release.json", "release.evidence.json"])
def test_sample_record_holds_no_values(name):
    text = (SAMPLE / name).read_text()
    for value in ("alice", "bob", "carol", "@example", "555"):
        assert value not in text.lower()
    read_json(SAMPLE / name)


def test_spec_lists_the_schema_required_keys():
    root = EXAMPLES.parent
    schema = json.loads((root / "schemas" / "dataset-release.v1.json").read_text())
    spec = (root / "docs" / "SPEC.md").read_text()
    table = spec.split("### Record hash")[0].split("## 2. The record")[1]
    keys = set(re.findall(r"^\| `([a-z0-9_]+)` \|", table, re.M))
    assert keys == set(schema["required"])


VECTORS = Path(__file__).resolve().parent.parent / "src" / "presidio_deident" / "vectors"
_EXPECT = json.loads((VECTORS / "expectations.json").read_text())["vectors"]


@pytest.mark.parametrize("vec", _EXPECT, ids=[v["name"] for v in _EXPECT])
def test_vectors(vec):
    trust = pe.load_trust_store((VECTORS / vec["trust"]).read_text(encoding="utf-8"))
    v = verify_release(VECTORS / vec["release"], trust)
    assert v.ok is vec["ok"]
    assert sorted(n for n, ok, _ in v.checks if not ok) == sorted(vec["failing"])


def test_vector_sample_equals_the_example():
    for f in ("release.json", "release.evidence.json", "tickets.csv"):
        assert (VECTORS / "sample-release" / f).read_bytes() == (SAMPLE / f).read_bytes()
