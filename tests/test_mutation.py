"""Seeded mutation tests: corrupted inputs fail cleanly and never verify by accident.

These stand in for the Atheris fuzzers (Linux-only) until CI runs them: every mutation must
either be rejected with a DeidentError (run, policy) or a failed check (verify), or leave
the parsed content unchanged. No other exception may escape.
"""

import contextlib
import json
import random

import pytest
from conftest import POLICY

from presidio_deident.errors import DeidentError
from presidio_deident.policy import parse_policy
from presidio_deident.release import EVIDENCE_FILE, RECORD_FILE, run_release
from presidio_deident.verify import verify_release

N = 300


def _mutate(rnd: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rnd.randint(1, 4)):
        op = rnd.random()
        i = rnd.randrange(len(b)) if b else 0
        if op < 0.4 and b:
            b[i] = rnd.randrange(256)
        elif op < 0.7:
            b[i:i] = bytes([rnd.randrange(256)])
        elif b:
            del b[i : i + rnd.randint(1, 8)]
    return bytes(b)


@pytest.fixture
def release(ws):
    run_release(
        ws.policy(), ws.data, ws.root / "rel", sign_key=ws.sign_key, pseudonym_key=ws.pseudo_key
    )
    out = ws.root / "rel"
    for p in out.iterdir():
        p.chmod(0o644)
    return out


@pytest.mark.parametrize("name", [RECORD_FILE, EVIDENCE_FILE, "tickets.csv"])
def test_mutated_release_never_verifies_by_accident(ws, release, name):
    rnd = random.Random(f"verify-{name}")
    path = release / name
    original = path.read_bytes()
    parsed = json.loads(original) if name.endswith(".json") else None
    for _ in range(N):
        mutated = _mutate(rnd, original)
        path.write_bytes(mutated)
        v = verify_release(release, ws.trust)  # must not raise
        if v.ok:
            if parsed is None:
                assert mutated == original
            else:
                assert json.loads(mutated) == parsed
    path.write_bytes(original)
    assert verify_release(release, ws.trust).ok


def test_mutated_input_fails_cleanly(ws):
    rnd = random.Random("run")
    original = ws.data.read_bytes()
    policy = ws.policy()
    for i in range(N):
        ws.data.write_bytes(_mutate(rnd, original))
        try:
            run_release(
                policy,
                ws.data,
                ws.root / f"r{i}",
                sign_key=ws.sign_key,
                pseudonym_key=ws.pseudo_key,
            )
        except DeidentError:
            assert not (ws.root / f"r{i}").exists()
        assert not (ws.root / f"r{i}.partial").exists()


def test_mutated_policy_fails_cleanly(tmp_path):
    import tomllib

    rnd = random.Random("policy")
    for _ in range(N):
        text = _mutate(rnd, POLICY.encode()).decode("utf-8", "replace")
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            continue
        with contextlib.suppress(DeidentError):
            parse_policy(data, tmp_path)
