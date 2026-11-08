"""Synthetic fixtures only. No real personal data is used anywhere in the tests."""

from __future__ import annotations

import json
from pathlib import Path

import presidio_evidence as pe
import pytest

from presidio_deident.policy import load_policy

CSV = """ticket_id,email,customer_name,country,body,opened
1001,alice@example.com,Alice Example,DE,"Please call me at 415-555-0182 about the invoice",2026-03-01
1002,bob@example.org,Bob Sample,FR,"Card 4111 1111 1111 1111 was charged twice",2026-03-02
1003,carol@example.net,Carol Test,DE,"Thanks, all good",2026-03-04
"""

# Values that must never appear in a record, an envelope, or any output line.
SECRETS = [
    "alice@example.com",
    "bob@example.org",
    "Alice Example",
    "Bob Sample",
    "Carol Test",
    "415-555-0182",
    "4111 1111 1111 1111",
    "1001",
    "1002",
    "1003",
]


def leaks(text: str) -> list[str]:
    """Secrets found in ``text``. A secret only counts where it is not part of a longer
    hex run, so a random hash or signature that happens to contain "1001" is no leak."""
    import re

    return [
        v
        for v in SECRETS
        if re.search(r"(?<![0-9a-fA-F])" + re.escape(v) + r"(?![0-9a-fA-F])", text)
    ]


POLICY = """[release]
dataset_id = "tickets-2026"
recipient = "lab-example"
signer = "acme-data-release"
released_at = "2026-11-08T00:00:00Z"

[[release.rights]]
source = "Acme support system export, October 2026"
basis = "Customer terms section 7: licence for AI training"
reference = "contract 2026-114"

[columns]
ticket_id = { action = "pseudonymise" }
email = { action = "drop" }
customer_name = { action = "drop" }
country = { action = "keep" }
body = { action = "scrub_text" }
opened = { action = "keep" }

[[suppression]]
name = "opt-out-2026-11"
file = "optout.txt"
column = "email"
normalise = ["strip", "lower"]
as_of = "2026-11-01"
"""


class Workspace:
    def __init__(self, root: Path):
        self.root = root
        self.sign_key, public = pe.generate_ed25519_keypair()
        self.pseudo_key, _ = pe.generate_ed25519_keypair()
        self.trust = pe.load_trust_store(
            {"acme-data-release": {"alg": "ed25519", "public_key": public}}
        )
        self.trust_file = root / "trust.json"
        self.trust_file.write_text(
            json.dumps({"acme-data-release": {"alg": "ed25519", "public_key": public}})
        )
        pe.write_private_key(root / "sign.key", self.sign_key)
        pe.write_private_key(root / "pseudo.key", self.pseudo_key)
        self.data = root / "tickets.csv"
        self.data.write_text(CSV)
        (root / "optout.txt").write_text("# opt-outs\nBOB@example.org \n")
        self.policy_file = root / "policy.toml"
        self.policy_file.write_text(POLICY)

    def policy(self, text: str | None = None):
        if text is not None:
            self.policy_file.write_text(text)
        return load_policy(self.policy_file)


@pytest.fixture
def ws(tmp_path) -> Workspace:
    return Workspace(tmp_path)
