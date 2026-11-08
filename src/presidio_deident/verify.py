"""Verify a release directory offline: signature, subject binding, record hash and file hashes.

Fail-closed: every check must pass, and anything malformed is a failure, not a warning.
Files in the directory that the record does not list are reported but do not fail the
release; a buyer may keep other files beside it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import presidio_evidence as pe

from . import FRAMEWORK, RECORD_SCHEMA
from .policy import ID_RE, TIMESTAMP_RE
from .release import EVIDENCE_FILE, RECORD_FILE, sha256_file

MAX_JSON_BYTES = 8 << 20
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
REF_KEYS = set(pe.EVIDENCE_REF_FIELDS) | {"framework"}


@dataclass
class Verification:
    ok: bool = True
    checks: list[tuple[str, bool, str]] = field(default_factory=list)
    extra_files: list[str] = field(default_factory=list)
    record: dict | None = None
    record_hash: str | None = None

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.checks.append((name, bool(passed), detail))
        self.ok = self.ok and bool(passed)
        return bool(passed)


def _plain_name(name: object) -> bool:
    return (
        isinstance(name, str)
        and name not in ("", ".", "..")
        and "/" not in name
        and "\\" not in name
        and "\x00" not in name
    )


def read_json(path: Path) -> dict:
    """A JSON object from a regular file of bounded size; ValueError otherwise."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path.name} is missing or not a regular file")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"{path.name} is too large")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except RecursionError:
        raise ValueError(f"{path.name} is nested too deeply") from None
    if not isinstance(doc, dict):
        raise ValueError(f"{path.name} is not a JSON object")
    return doc


def _count(x: object) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _rows_add_up(record: dict) -> bool:
    rows = record.get("rows")
    outs = record.get("outputs")
    if not isinstance(rows, dict) or not all(
        _count(rows.get(k)) for k in ("in", "suppressed", "out")
    ):
        return False
    if not isinstance(outs, list) or not all(
        isinstance(o, dict) and _count(o.get("rows")) for o in outs
    ):
        return False
    listed = sum(o["rows"] for o in outs)
    return rows["in"] == rows["suppressed"] + rows["out"] and listed == rows["out"]


def verify_record(directory: Path, trust: dict) -> Verification:
    """Signature and record checks only (no data files)."""
    v = Verification()
    try:
        record = read_json(directory / RECORD_FILE)
        envelope = read_json(directory / EVIDENCE_FILE)
    except (OSError, ValueError) as exc:
        v.check("release files readable", False, str(exc))
        return v
    v.record = record
    v.check("record schema", record.get("schema") == RECORD_SCHEMA, str(record.get("schema")))
    for key in ("dataset_id", "recipient", "signer"):
        value = record.get(key)
        v.check(
            f"record {key} is an identifier",
            isinstance(value, str) and bool(ID_RE.fullmatch(value)),
        )
    released = record.get("released_at")
    v.check(
        "record released_at is a UTC timestamp",
        isinstance(released, str) and bool(TIMESTAMP_RE.fullmatch(released)),
    )
    try:
        digest = pe.content_hash(record)
    except (pe.EvidenceError, TypeError, ValueError) as exc:
        v.check("record canonical", False, str(exc))
        return v
    v.record_hash = digest
    try:
        results = pe.verify_envelope(envelope, trust, expected_framework=FRAMEWORK)
    except pe.EvidenceError as exc:
        v.check("envelope well-formed", False, str(exc))
        return v
    if not v.check("exactly one signed ref", len(results) == 1, f"{len(results)} refs"):
        return v
    (res,) = results
    ref = res.ref
    v.check("signature (evidence-ref@3, trusted signer)", res.verified, res.reason)
    v.check("ref signs this record", ref.content_hash == digest)
    v.check("ref names this dataset", ref.item_id == record.get("dataset_id"))
    v.check("ref signer is the record signer", ref.signer == record.get("signer"))
    v.check("ref points at release.json", ref.ledger_ref == RECORD_FILE)
    # evidence-ref@3 signs the hash, signer, framework, item and tier only. The other
    # envelope fields are unsigned, so they must repeat what the signed record says.
    tools = record.get("tools") if isinstance(record.get("tools"), dict) else {}
    v.check(
        "unsigned envelope fields match the record",
        ref.claimed_at == record.get("released_at")
        and envelope.get("generated_at") == record.get("released_at")
        and ref.source == envelope.get("source") == "presidio-deident"
        and ref.source_version == envelope.get("source_version") == tools.get("presidio-deident")
        and set(envelope) == {"schema", "source", "source_version", "generated_at", "evidence"}
        and set(envelope["evidence"][0]) == REF_KEYS,
    )
    v.check("row counts add up", _rows_add_up(record))
    parents = record.get("parents", [])
    v.check(
        "parents are record hashes",
        isinstance(parents, list)
        and bool(parents) == ("parents" in record)
        and all(isinstance(p, str) and _HEX64.fullmatch(p) for p in parents),
    )
    v.check(
        "release id names the dataset and time",
        isinstance(record.get("release_id"), str)
        and record["release_id"] == f"{record.get('dataset_id')}@{record.get('released_at')}",
    )
    return v


def verify_release(directory: Path, trust: dict, *, check_files: bool = True) -> Verification:
    v = verify_record(directory, trust)
    if not check_files or v.record is None:
        return v
    outputs = v.record.get("outputs")
    if not v.check("record lists output files", isinstance(outputs, list) and bool(outputs)):
        return v
    listed = set()
    for entry in outputs:
        name = entry.get("name") if isinstance(entry, dict) else None
        plain = _plain_name(name) and name not in (RECORD_FILE, EVIDENCE_FILE)
        if not v.check("output file name is plain", plain, repr(name)):
            continue
        if not v.check(f"{name} listed once", name not in listed):
            continue
        listed.add(name)
        path = directory / name
        if not v.check(f"{name} present", path.is_file() and not path.is_symlink()):
            continue
        try:
            got, size = sha256_file(path)
        except OSError as exc:
            v.check(f"{name} readable", False, exc.strerror or "")
            continue
        v.check(f"{name} sha256", got == entry.get("sha256"))
        v.check(f"{name} size", size == entry.get("bytes"))
    v.extra_files = sorted(
        p.name for p in directory.iterdir() if p.name not in listed | {RECORD_FILE, EVIDENCE_FILE}
    )
    return v


@dataclass
class History(Verification):
    releases: list[tuple[str, Verification]] = field(default_factory=list)
    order: list[str] = field(default_factory=list)  # release ids, oldest first


def verify_history(directories: list[Path], trust: dict, *, check_files: bool = True) -> History:
    """Verify releases of one dataset to one recipient as a chain.

    Every release must verify on its own, all must carry the same dataset id and recipient, every
    ``parents`` entry must be the record hash of a release in the set, and a parent must be
    released before its child. Releases without parents are roots; a chain has exactly one.
    """
    h = History()
    by_hash: dict[str, dict] = {}
    for d in directories:
        v = verify_release(d, trust, check_files=check_files)
        h.releases.append((str(d), v))
        h.check(f"{d.name} verifies", v.ok)
        if v.ok:
            by_hash[v.record_hash] = v.record
    if not h.ok:
        return h
    h.check("no release is listed twice", len(by_hash) == len(directories))
    datasets = {r["dataset_id"] for r in by_hash.values()}
    h.check("one dataset", len(datasets) == 1, ", ".join(sorted(datasets)))
    recipients = {r["recipient"] for r in by_hash.values()}
    h.check("one recipient", len(recipients) == 1, ", ".join(sorted(recipients)))
    roots = [x for x, r in by_hash.items() if not r.get("parents")]
    h.check("exactly one root release", len(roots) == 1, f"{len(roots)} roots")
    for r in by_hash.values():
        for p in r.get("parents", []):
            parent = by_hash.get(p)
            if h.check(f"{r['release_id']}: parent {p[:12]} is in the set", parent is not None):
                h.check(
                    f"{r['release_id']}: parent released earlier",
                    parent["released_at"] < r["released_at"],
                )
    h.order = [r["release_id"] for r in sorted(by_hash.values(), key=lambda r: r["released_at"])]
    return h
