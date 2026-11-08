import csv

import presidio_evidence as pe
import pytest

from presidio_deident.cli import main
from presidio_deident.release import RECORD_FILE, run_release
from presidio_deident.verify import read_json, verify_history


def _release(ws, out, at, parents=(), extra_optout=""):
    if extra_optout:
        (ws.root / "optout.txt").write_text(f"BOB@example.org\n{extra_optout}\n")
    run_release(
        ws.policy(),
        ws.data,
        ws.root / out,
        sign_key=ws.sign_key,
        pseudonym_key=ws.pseudo_key,
        released_at=at,
        parents=parents,
    )
    return ws.root / out


def _hash(d):
    return pe.content_hash(read_json(d / RECORD_FILE))


@pytest.fixture
def chain(ws):
    a = _release(ws, "a", "2026-11-01T00:00:00Z")
    b = _release(ws, "b", "2026-12-15T00:00:00Z", (_hash(a),), "carol@example.net")
    return a, b


def test_re_release_chain_verifies(ws, chain):
    a, b = chain
    h = verify_history([b, a], ws.trust)
    assert h.ok, [c for c in h.checks if not c[1]]
    assert h.order == ["tickets-2026@2026-11-01T00:00:00Z", "tickets-2026@2026-12-15T00:00:00Z"]
    assert read_json(b / RECORD_FILE)["rows"]["suppressed"] == 2


def test_pseudonyms_are_stable_across_re_releases(ws, chain):
    a, b = chain
    ids_a = [r["ticket_id"] for r in csv.DictReader((a / "tickets.csv").open())]
    ids_b = [r["ticket_id"] for r in csv.DictReader((b / "tickets.csv").open())]
    assert ids_b == ids_a[:1]  # carol's row is suppressed in the second release


def _failed(h):
    return [n for n, ok, _ in h.checks if not ok]


def test_missing_parent_fails(ws, chain):
    _, b = chain
    assert any("is in the set" in n for n in _failed(verify_history([b], ws.trust)))


def test_two_roots_fail(ws, chain):
    a, b = chain
    c = _release(ws, "c", "2026-11-02T00:00:00Z")
    assert "exactly one root release" in _failed(verify_history([a, b, c], ws.trust))


def test_listed_twice_fails(ws, chain):
    a, b = chain
    assert "no release is listed twice" in _failed(verify_history([a, a, b], ws.trust))


def test_parent_must_be_older(ws, chain):
    a, _ = chain
    old = _release(ws, "old", "2026-10-01T00:00:00Z", (_hash(a),))
    assert any("released earlier" in n for n in _failed(verify_history([a, old], ws.trust)))


def test_other_dataset_fails(ws, chain):
    a, b = chain
    ws.policy_file.write_text(ws.policy_file.read_text().replace("tickets-2026", "other-2026"))
    other = _release(ws, "other", "2026-11-03T00:00:00Z")
    assert "one dataset" in _failed(verify_history([a, b, other], ws.trust))


def test_other_recipient_fails(ws, chain):
    a, b = chain
    ws.policy_file.write_text(ws.policy_file.read_text().replace('"lab-example"', '"lab-other"'))
    other = _release(ws, "other", "2026-11-03T00:00:00Z", (_hash(a),))
    assert "one recipient" in _failed(verify_history([a, b, other], ws.trust))


def test_a_broken_release_stops_the_history(ws, chain):
    a, b = chain
    (b / "tickets.csv").chmod(0o644)
    (b / "tickets.csv").write_text("tampered\n")
    h = verify_history([a, b], ws.trust)
    assert _failed(h) == ["b verifies"]
    (b / "tickets.csv").unlink()
    assert verify_history([a, b], ws.trust, check_files=False).ok


def test_history_and_parent_cli(ws, chain, capsys):
    a, b = chain
    trust = str(ws.trust_file)
    assert main(["history", str(a), str(b), "--trust", trust]) == 0
    assert "VERIFIED history" in capsys.readouterr().out
    assert main(["history", str(b), "--trust", trust]) == 1
    (b / "tickets.csv").chmod(0o644)
    (b / "tickets.csv").write_text("x\n")
    assert main(["history", str(a), str(b), "--trust", trust]) == 1
    assert "FAIL b: tickets.csv sha256" in capsys.readouterr().out

    args = [
        "run",
        "--policy",
        str(ws.policy_file),
        "--input",
        str(ws.data),
        "--sign-key",
        str(ws.root / "sign.key"),
        "--pseudonym-key",
        str(ws.root / "pseudo.key"),
        "--released-at",
        "2027-01-01T00:00:00Z",
    ]
    assert main([*args, "--out", str(ws.root / "c"), "--parent", str(a)]) == 0
    assert read_json(ws.root / "c" / RECORD_FILE)["parents"] == [_hash(a)]
    assert main([*args, "--out", str(ws.root / "d"), "--parent", str(ws.root / "nope")]) == 2
    ws.policy_file.write_text(ws.policy_file.read_text().replace("tickets-2026", "other-2026"))
    assert main([*args, "--out", str(ws.root / "e"), "--parent", str(a)]) == 2
    assert "another dataset" in capsys.readouterr().err


def test_rotated_signing_key_keeps_old_releases_verifiable(ws):
    """Rotation: the trust store lists the old and the new public key for one signer."""
    old_public = ws.trust[next(iter(ws.trust))]
    a = _release(ws, "a", "2026-11-01T00:00:00Z")
    new_private, new_public = pe.generate_ed25519_keypair()
    run_release(
        ws.policy(),
        ws.data,
        ws.root / "b",
        sign_key=new_private,
        pseudonym_key=ws.pseudo_key,
        released_at="2026-12-15T00:00:00Z",
        parents=(_hash(a),),
    )
    b = ws.root / "b"
    signer = next(iter(ws.trust))
    old_keys = old_public["keys"]  # normalised form: a list of hex public keys
    rotated = pe.load_trust_store(
        {signer: {"alg": "ed25519", "public_key": [*old_keys, new_public]}}
    )
    assert verify_history([a, b], rotated).ok
    only_new = pe.load_trust_store({signer: {"alg": "ed25519", "public_key": new_public}})
    h = verify_history([a, b], only_new)
    assert [n for n, ok, _ in h.checks if not ok] == ["a verifies"]
