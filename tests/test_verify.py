import json
import os

import presidio_evidence as pe
import pytest

from presidio_deident.release import EVIDENCE_FILE, RECORD_FILE, run_release
from presidio_deident.verify import MAX_JSON_BYTES, verify_record, verify_release


@pytest.fixture
def release(ws):
    run_release(
        ws.policy(), ws.data, ws.root / "release", sign_key=ws.sign_key, pseudonym_key=ws.pseudo_key
    )
    out = ws.root / "release"
    for p in out.iterdir():
        p.chmod(0o644)
    return out


def _failed(v):
    return [name for name, ok, _ in v.checks if not ok]


def _edit_record(path, fn):
    doc = json.loads((path / RECORD_FILE).read_text())
    fn(doc)
    (path / RECORD_FILE).write_text(json.dumps(doc))


def test_valid_release_verifies(ws, release):
    v = verify_release(release, ws.trust)
    assert v.ok, _failed(v)
    assert v.extra_files == []
    assert len(v.record_hash) == 64


def test_extra_files_are_noted_not_failed(ws, release):
    (release / "README.txt").write_text("notes")
    v = verify_release(release, ws.trust)
    assert v.ok and v.extra_files == ["README.txt"]


def test_tampered_data_file_fails(ws, release):
    with (release / "tickets.csv").open("a") as fh:
        fh.write("x,DE,y,z\n")
    assert _failed(verify_release(release, ws.trust)) == ["tickets.csv sha256", "tickets.csv size"]


def test_missing_data_file_fails(ws, release):
    (release / "tickets.csv").unlink()
    assert "tickets.csv present" in _failed(verify_release(release, ws.trust))


def test_symlinked_data_file_fails(ws, release, tmp_path):
    target = release / "tickets.csv"
    moved = tmp_path / "elsewhere.csv"
    os.replace(target, moved)
    target.symlink_to(moved)
    assert "tickets.csv present" in _failed(verify_release(release, ws.trust))


def test_edited_record_fails(ws, release):
    _edit_record(release, lambda d: d["rows"].update(suppressed=0))
    failed = _failed(verify_release(release, ws.trust))
    assert "ref signs this record" in failed and "row counts add up" in failed


def test_untrusted_signer_fails(ws, release):
    _, other = pe.generate_ed25519_keypair()
    trust = pe.load_trust_store({"acme-data-release": {"alg": "ed25519", "public_key": other}})
    assert "signature (evidence-ref@3, trusted signer)" in _failed(verify_release(release, trust))


def test_path_traversal_in_outputs_is_refused(ws, release):
    for bad in ("../tickets.csv", "/etc/passwd", "a\\b", "", None):
        _edit_record(release, lambda d, b=bad: d["outputs"][0].update(name=b))
        assert "output file name is plain" in _failed(verify_release(release, ws.trust))


def test_empty_outputs_fail(ws, release):
    _edit_record(release, lambda d: d.update(outputs=[]))
    assert "record lists output files" in _failed(verify_release(release, ws.trust))


def test_record_only_verification(ws, release):
    (release / "tickets.csv").unlink()
    assert verify_record(release, ws.trust).ok
    assert verify_release(release, ws.trust, check_files=False).ok


@pytest.mark.parametrize("name", [RECORD_FILE, EVIDENCE_FILE])
def test_missing_or_bad_json_fails(ws, release, name):
    (release / name).write_text("[1, 2]")
    assert not verify_release(release, ws.trust).ok
    (release / name).write_text("{not json")
    assert not verify_release(release, ws.trust).ok
    (release / name).unlink()
    assert not verify_release(release, ws.trust).ok


def test_oversized_json_fails(ws, release):
    (release / RECORD_FILE).write_text(" " * (MAX_JSON_BYTES + 1))
    assert "release files readable" in _failed(verify_release(release, ws.trust))


def test_float_in_record_fails(ws, release):
    _edit_record(release, lambda d: d.update(score=0.5))
    assert "record canonical" in _failed(verify_release(release, ws.trust))


def test_malformed_envelope_fails(ws, release):
    (release / EVIDENCE_FILE).write_text(json.dumps({"schema": "x", "evidence": []}))
    assert "envelope well-formed" in _failed(verify_release(release, ws.trust))


def test_envelope_with_two_refs_fails(ws, release):
    env = json.loads((release / EVIDENCE_FILE).read_text())
    env["evidence"].append(dict(env["evidence"][0]))
    (release / EVIDENCE_FILE).write_text(json.dumps(env))
    assert "exactly one signed ref" in _failed(verify_release(release, ws.trust))


def test_bad_parents_fail(ws, release):
    _edit_record(release, lambda d: d.update(parents=["nothex"]))
    assert "parents are record hashes" in _failed(verify_release(release, ws.trust))
    _edit_record(release, lambda d: d.update(parents=[]))
    assert "parents are record hashes" in _failed(verify_release(release, ws.trust))


def test_wrong_schema_fails(ws, release):
    _edit_record(release, lambda d: d.update(schema="other@1"))
    assert "record schema" in _failed(verify_release(release, ws.trust))


def test_bad_rows_fail(ws, release):
    _edit_record(release, lambda d: d.update(rows={"in": -1}))
    assert "row counts add up" in _failed(verify_release(release, ws.trust))
    _edit_record(
        release, lambda d: d.update(rows={"in": 1, "suppressed": 0, "out": 1}, outputs="x")
    )
    assert "row counts add up" in _failed(verify_release(release, ws.trust))
