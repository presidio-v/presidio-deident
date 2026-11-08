"""Atheris harness: verify never raises and never accepts a record it was not given.

A fixed release is built once; each input replaces release.json. Verification must return
a result (no exception), and may pass only if the input parses to the original record.
Run on Linux: python fuzz/fuzz_verify.py -max_total_time=60
"""

import json
import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    import presidio_evidence as pe

    from presidio_deident.policy import load_policy
    from presidio_deident.release import RECORD_FILE, run_release
    from presidio_deident.verify import verify_release

ROOT = Path(tempfile.mkdtemp())
SIGN, PUBLIC = pe.generate_ed25519_keypair()
TRUST = pe.load_trust_store({"s": {"alg": "ed25519", "public_key": PUBLIC}})
(ROOT / "d.csv").write_text("id,v\n1,a\n2,b\n")
(ROOT / "p.toml").write_text(
    '[release]\ndataset_id = "d"\nrecipient = "r"\nsigner = "s"\n'
    'released_at = "2026-01-01T00:00:00Z"\n[columns]\nid = { action = "drop" }\n'
    'v = { action = "keep" }\n'
)
run_release(load_policy(ROOT / "p.toml"), ROOT / "d.csv", ROOT / "rel", sign_key=SIGN)
RECORD = ROOT / "rel" / RECORD_FILE
RECORD.chmod(0o644)
ORIGINAL = json.loads(RECORD.read_text())


def TestOneInput(data: bytes) -> None:
    RECORD.write_bytes(data)
    v = verify_release(ROOT / "rel", TRUST)
    if v.ok:
        assert json.loads(data) == ORIGINAL


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
