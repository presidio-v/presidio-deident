import json

import pytest
from conftest import leaks

from presidio_deident.cli import main


def _cli(capsys, *args):
    code = main([str(a) for a in args])
    out, err = capsys.readouterr()
    return code, out, err


def test_full_cli_flow(ws, capsys, tmp_path):
    r = ws.root
    code, out, err = _cli(capsys, "inspect", ws.data)
    assert code == 0 and "EMAIL_ADDRESS 3" in out
    code, out, err = _cli(capsys, "policy-init", ws.data, "--out", r / "p2.toml")
    assert code == 0 and (r / "p2.toml").exists()
    code, *_ = _cli(capsys, "policy-init", ws.data, "--out", r / "p2.toml")
    assert code == 2

    code, out, err = _cli(
        capsys, "keygen", "--signer", "s", "--sign-key", r / "k1", "--pseudonym-key", r / "k2"
    )
    assert code == 0 and json.loads(out)["s"]["alg"] == "ed25519"
    code, *_ = _cli(
        capsys, "keygen", "--signer", "s", "--sign-key", r / "k1", "--pseudonym-key", r / "k3"
    )
    assert code == 2

    code, out, err = _cli(
        capsys,
        "run",
        "--policy",
        ws.policy_file,
        "--input",
        ws.data,
        "--out",
        r / "rel",
        "--sign-key",
        r / "sign.key",
        "--pseudonym-key",
        r / "pseudo.key",
    )
    assert code == 0 and "1 suppressed" in out
    code, out, err = _cli(capsys, "verify", r / "rel", "--trust", ws.trust_file)
    assert code == 0 and "VERIFIED" in out
    code, out, err = _cli(capsys, "verify", r / "rel", "--trust", ws.trust_file, "--json")
    assert code == 0 and json.loads(out)["ok"] is True
    code, out, err = _cli(
        capsys, "croissant", r / "rel", "--trust", ws.trust_file, "--out", r / "c.json"
    )
    assert code == 0
    doc = json.loads((r / "c.json").read_text())
    assert doc["distribution"][0]["sha256"] and doc["identifier"].startswith(
        "dataset-release:sha256:"
    )
    code, *_ = _cli(capsys, "croissant", r / "rel", "--trust", ws.trust_file, "--out", r / "c.json")
    assert code == 2

    (r / "rel" / "extra.txt").write_text("x")
    code, out, err = _cli(capsys, "verify", r / "rel", "--trust", ws.trust_file)
    assert code == 0 and "note extra.txt" in out
    with (r / "rel" / "tickets.csv").open("a") as fh:
        fh.write("tamper\n")
    code, out, err = _cli(capsys, "verify", r / "rel", "--trust", ws.trust_file)
    assert code == 1 and "FAIL tickets.csv sha256" in out
    code, out, err = _cli(
        capsys, "croissant", r / "rel", "--trust", ws.trust_file, "--out", r / "c2.json"
    )
    assert code == 1 and not (r / "c2.json").exists()


def test_cli_never_prints_values(ws, capsys):
    r = ws.root
    ws.policy_file.write_text(
        ws.policy_file.read_text().replace(
            'body = { action = "scrub_text" }', 'body = { action = "keep" }'
        )
    )
    outputs = []
    for args in (
        ("inspect", ws.data),
        (
            "run",
            "--policy",
            ws.policy_file,
            "--input",
            ws.data,
            "--out",
            r / "rel",
            "--sign-key",
            r / "sign.key",
            "--pseudonym-key",
            r / "pseudo.key",
        ),
    ):
        outputs.append(_cli(capsys, *args))
    assert outputs[1][0] == 2
    text = "".join(o + e for _, o, e in outputs)
    assert leaks(text) == []


def test_cli_errors(ws, capsys, tmp_path):
    r = ws.root
    code, out, err = _cli(
        capsys,
        "run",
        "--policy",
        ws.policy_file,
        "--input",
        ws.data,
        "--out",
        r / "rel",
        "--sign-key",
        r / "missing.key",
    )
    assert code == 2 and "signing key" in err
    (r / "bad.json").write_text("{")
    code, out, err = _cli(capsys, "verify", r, "--trust", r / "bad.json")
    assert code == 2 and "trust store" in err
    code, out, err = _cli(capsys, "verify", r, "--trust", ws.trust_file)
    assert code == 1
    with pytest.raises(SystemExit):
        main(["--version"])
