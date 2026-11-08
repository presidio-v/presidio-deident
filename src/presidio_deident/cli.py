"""``deident`` command line. Exit codes: 0 ok, 1 verification failed, 2 the run could not start.

Output names columns, files and counts. It never prints a cell value.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path

import presidio_evidence as pe

from . import __version__
from .croissant import croissant
from .errors import DeidentError
from .inspect import inspect_file
from .policy import load_policy, policy_skeleton
from .release import RECORD_FILE, run_release
from .risk import RiskAccumulator
from .tables import open_table
from .verify import read_json, verify_history, verify_release

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def _load_key(path: str, label: str) -> str:
    try:
        return pe.load_private_key(path)
    except pe.EvidenceError as exc:
        raise DeidentError(f"{label}: {exc}") from exc


def cmd_inspect(args) -> int:
    reports, n = inspect_file(Path(args.file), sample=args.sample)
    print(f"{Path(args.file).name}: {len(reports)} columns, {n} rows sampled")
    print(f"{'column':30} {'missing':>8} {'rows with PII':>14}  suggested   detected types")
    for r in reports:
        types = ", ".join(f"{t} {c}" for t, c in sorted(r.entities.items()))
        print(f"{r.name[:30]:30} {r.missing:>8} {r.rows_with_pii:>14}  {r.suggestion():11} {types}")
    return EXIT_OK


def cmd_policy_init(args) -> int:
    src = Path(args.file)
    reports, _ = inspect_file(src, sample=args.sample)
    text = policy_skeleton(
        [r.name for r in reports],
        {r.name: r.suggestion() for r in reports},
        args.dataset_id or src.stem.replace("_", "-"),
    )
    out = Path(args.out)
    if out.exists():
        raise DeidentError(f"{out} exists; not overwritten")
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out}: review every action before a release")
    return EXIT_OK


def _names(text: str | None) -> list[str]:
    return [c.strip() for c in (text or "").split(",") if c.strip()]


def cmd_risk(args) -> int:
    path = Path(args.file)
    qi, sensitive = _names(args.qi), _names(args.sensitive)
    if not qi:
        raise DeidentError("--qi must name at least one column")
    acc = RiskAccumulator(qi, sensitive)
    with open_table(path) as table:
        if table.columns is not None:
            missing = [c for c in qi + sensitive if c not in table.columns]
            if missing:
                raise DeidentError(f"column(s) not in {path.name}: {', '.join(missing)}")
        for row in table.rows:
            acc.add(row)
    print(json.dumps(acc.report(), indent=2))
    return EXIT_OK


def cmd_keygen(args) -> int:
    for path in (args.sign_key, args.pseudonym_key):
        if Path(path).exists():
            raise DeidentError(f"{path} exists; a key is never overwritten")
    private_hex, public_hex = pe.generate_ed25519_keypair()
    pseudonym_hex = secrets.token_bytes(32).hex()  # HMAC key, not a signing key
    pe.write_private_key(args.sign_key, private_hex)
    pe.write_private_key(args.pseudonym_key, pseudonym_hex)
    trust = {args.signer: {"alg": "ed25519", "public_key": public_hex}}
    print(json.dumps(trust, indent=2))
    print(
        f"signing key: {args.sign_key}; pseudonym key: {args.pseudonym_key} (both 0600). "
        "Give the buyer the trust store above, never the keys.",
        file=sys.stderr,
    )
    return EXIT_OK


def _parent_hash(directory: str, dataset_id: str, recipient: str) -> str:
    """The record hash of an earlier release of the same dataset (verified later by history)."""
    try:
        record = read_json(Path(directory) / RECORD_FILE)
        digest = pe.content_hash(record)
    except (OSError, ValueError, TypeError, pe.EvidenceError) as exc:
        raise DeidentError(f"--parent {directory}: not a readable release ({exc})") from exc
    if record.get("dataset_id") != dataset_id:
        raise DeidentError(f"--parent {directory}: a release of another dataset")
    if record.get("recipient") != recipient:
        raise DeidentError(f"--parent {directory}: a release to another recipient")
    return digest


def cmd_run(args) -> int:
    policy = load_policy(Path(args.policy))
    parents = tuple(_parent_hash(d, policy.dataset_id, policy.recipient) for d in args.parent)
    sign_key = _load_key(args.sign_key, "signing key")
    pseudonym_key = _load_key(args.pseudonym_key, "pseudonym key") if args.pseudonym_key else None
    record = run_release(
        policy,
        Path(args.input),
        Path(args.out),
        sign_key=sign_key,
        pseudonym_key=pseudonym_key,
        released_at=args.released_at,
        residual_scan=not args.no_residual_scan,
        parents=parents,
    )
    rows = record["rows"]
    print(
        f"release {record['release_id']} for {record['recipient']}: "
        f"{rows['in']} rows in, {rows['suppressed']} suppressed, {rows['out']} out -> {args.out}"
    )
    return EXIT_OK


def _load_trust(path: str) -> dict:
    try:
        return pe.load_trust_store(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, pe.EvidenceError) as exc:
        raise DeidentError(f"trust store: {exc}") from exc


# The JSON contract of `verify --json`; bump the suffix on any incompatible change.
VERIFY_RESULT = "presidio-deident/verify-result@1"


def cmd_verify(args) -> int:
    trust = _load_trust(args.trust)
    v = verify_release(Path(args.release), trust)
    if args.json:
        print(
            json.dumps(
                {
                    "result": VERIFY_RESULT,
                    "ok": v.ok,
                    # Read from the record only once it verified; null otherwise.
                    "schema": v.record["schema"] if v.ok else None,
                    "release_id": v.record["release_id"] if v.ok else None,
                    "record_hash": v.record_hash,
                    "checks": [{"check": n, "ok": ok, "detail": d} for n, ok, d in v.checks],
                    "extra_files": v.extra_files,
                    "verifier": {
                        "presidio-deident": __version__,
                        "presidio-evidence": importlib.metadata.version("presidio-evidence"),
                    },
                },
                indent=2,
            )
        )
    else:
        for name, ok, detail in v.checks:
            print(
                f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and not ok else "")
            )
        for name in v.extra_files:
            print(f"note {name}: not part of the release")
        if v.ok:
            print(f"VERIFIED release {v.record['release_id']} (record sha256 {v.record_hash})")
    return EXIT_OK if v.ok else EXIT_FAIL


def cmd_history(args) -> int:
    trust = _load_trust(args.trust)
    h = verify_history([Path(d) for d in args.releases], trust, check_files=not args.records_only)
    for path, v in h.releases:
        if not v.ok:
            for name, ok, detail in v.checks:
                if not ok:
                    print(f"FAIL {Path(path).name}: {name}" + (f": {detail}" if detail else ""))
    for name, ok, detail in h.checks:
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and not ok else ""))
    if h.ok:
        print("VERIFIED history, oldest first:")
        for rid in h.order:
            print(f"  {rid}")
    return EXIT_OK if h.ok else EXIT_FAIL


def cmd_croissant(args) -> int:
    trust = _load_trust(args.trust)
    v = verify_release(Path(args.release), trust)
    if not v.ok:
        print("FAIL: the release does not verify; no Croissant file written", file=sys.stderr)
        return EXIT_FAIL
    out = Path(args.out)
    if out.exists():
        raise DeidentError(f"{out} exists; not overwritten")
    out.write_text(
        json.dumps(croissant(v.record, v.record_hash), indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {out}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="deident", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"presidio-deident {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser(
        "inspect", help="columns, missing values and detected PII types (counts only)"
    )
    s.add_argument("file")
    s.add_argument("--sample", type=int, default=1000)
    s.set_defaults(func=cmd_inspect)

    s = sub.add_parser("policy-init", help="write a policy skeleton with suggested actions")
    s.add_argument("file")
    s.add_argument("--out", required=True)
    s.add_argument("--dataset-id")
    s.add_argument("--sample", type=int, default=1000)
    s.set_defaults(func=cmd_policy_init)

    s = sub.add_parser("risk", help="quasi-identifier classes over a file (integer counts only)")
    s.add_argument("file")
    s.add_argument("--qi", required=True, help="comma-separated quasi-identifier columns")
    s.add_argument("--sensitive", help="comma-separated sensitive columns (l-diversity)")
    s.set_defaults(func=cmd_risk)

    s = sub.add_parser("keygen", help="create a signing key and a pseudonym key (0600)")
    s.add_argument("--signer", required=True)
    s.add_argument("--sign-key", required=True)
    s.add_argument("--pseudonym-key", required=True)
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("run", help="produce a signed release directory")
    s.add_argument("--policy", required=True)
    s.add_argument("--input", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--sign-key", required=True)
    s.add_argument("--pseudonym-key")
    s.add_argument(
        "--released-at", help="UTC timestamp YYYY-MM-DDTHH:MM:SSZ, for reproducible runs"
    )
    s.add_argument(
        "--parent",
        action="append",
        default=[],
        metavar="DIR",
        help="an earlier release of the same dataset; its record hash becomes a parent",
    )
    s.add_argument(
        "--no-residual-scan",
        action="store_true",
        help="do not scan kept columns for PII (recorded in the release)",
    )
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("verify", help="verify a release directory offline")
    s.add_argument("release")
    s.add_argument("--trust", required=True)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("history", help="verify several releases of one dataset as a chain")
    s.add_argument("releases", nargs="+")
    s.add_argument("--trust", required=True)
    s.add_argument(
        "--records-only",
        action="store_true",
        help="do not require the data files of every release",
    )
    s.set_defaults(func=cmd_history)

    s = sub.add_parser("croissant", help="write a minimal Croissant file for a verified release")
    s.add_argument("release")
    s.add_argument("--trust", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_croissant)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except DeidentError as exc:
        print(f"error: {exc}", file=sys.stderr)
    except OSError as exc:  # names the file, never its content
        print(f"error: {exc.filename or ''}: {exc.strerror or type(exc).__name__}", file=sys.stderr)
    except pe.EvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
    return EXIT_ERROR
