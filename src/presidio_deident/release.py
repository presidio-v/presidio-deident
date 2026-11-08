"""Run a release: read, suppress, transform, write, then sign the record.

A release directory holds the transformed data file, ``release.json`` (the record) and
``release.evidence.json`` (an ``evidence-ref@3`` envelope signing the record's content
hash). The run writes into ``<out>.partial`` and renames it to ``<out>`` only after the
record is signed, so a failed run never leaves a directory that looks like a release.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.metadata
import json
import os
import shutil
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import presidio_evidence as pe

from . import FRAMEWORK, RECORD_SCHEMA, __version__, _detect
from .errors import DeidentError
from .generalise import generalise
from .policy import TIMESTAMP_RE, Policy, Suppression
from .risk import RiskAccumulator
from .tables import TableWriter, is_missing, open_table, scan_columns, table_format

RECORD_FILE = "release.json"
EVIDENCE_FILE = "release.evidence.json"
PSEUDONYM_HEX = 32  # 128 bits of the HMAC output
KEY_CONTEXT = b"presidio-deident/v1/pseudonym\x00"
PSEUDONYM_SCHEME = "hmac-sha256-128/v1"


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def derive_pseudonym_key(master_hex: str, domain: str) -> bytes:
    """One key per pseudonym domain (by default the recipient), so releases to different
    recipients cannot be joined on their pseudonyms. ``domain`` cannot contain NUL."""
    return hmac.new(bytes.fromhex(master_hex), KEY_CONTEXT + domain.encode(), "sha256").digest()


def _as_text(value: object, where: str) -> str:
    """Strings as they are; integers as their decimal form. Anything else is refused."""
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise DeidentError(f"{where}: only string or integer values can be matched or pseudonymised")


_DIGITS = frozenset("0123456789")


def _normalise(value: str, steps: tuple[str, ...]) -> str:
    for step in steps:
        if step == "strip":
            value = value.strip()
        elif step == "lower":
            value = value.lower()
        elif step == "drop-email":  # DROP: remove whitespace, lowercase, keep dots and plus
            value = "".join(value.split()).lower()
        else:  # drop-phone. DROP: digits only, the last 10 (ASCII digits only)
            value = "".join(c for c in value if c in _DIGITS)[-10:]
    return value


def drop_hash(text: str) -> str:
    """California DROP hash: SHA-256 over UTF-8, Base64 output."""
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def pseudonymise(key: bytes, text: str) -> str:
    return hmac.new(key, text.encode("utf-8"), "sha256").hexdigest()[:PSEUDONYM_HEX]


@dataclass
class _List:
    spec: Suppression
    entries: frozenset[str]
    sha256: str
    matched: int = 0

    def matches(self, value: object, where: str) -> bool:
        if is_missing(value):
            return False
        text = _normalise(_as_text(value, where), self.spec.normalise)
        if self.spec.format == "sha256":
            text = hashlib.sha256(text.encode("utf-8")).hexdigest()
        elif self.spec.format == "ca-drop":
            if not text:
                return False
            text = drop_hash(text)
        return text in self.entries


def _load_list(spec: Suppression) -> _List:
    try:
        raw = spec.file.read_bytes()
    except OSError as exc:
        raise DeidentError(f"suppression list {spec.name}: cannot read its file") from exc
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise DeidentError(f"suppression list {spec.name}: not UTF-8") from exc
    if spec.format == "ca-drop":
        return _List(spec, _drop_entries(spec.name, lines), hashlib.sha256(raw).hexdigest())
    entries = set()
    for n, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if spec.format == "sha256":
            entry = line.strip().lower()
            if len(entry) != 64 or any(c not in "0123456789abcdef" for c in entry):
                raise DeidentError(f"suppression list {spec.name}: line {n} is not hex SHA-256")
        else:
            entry = _normalise(line, spec.normalise)
        entries.add(entry)
    return _List(spec, frozenset(entries), hashlib.sha256(raw).hexdigest())


def _drop_entries(name: str, lines: list[str]) -> frozenset[str]:
    """One DROP deletion-list CSV, as extracted from the download ZIP: header ``Id,Hash``."""
    if not lines or lines[0].strip() != "Id,Hash":
        raise DeidentError(f'suppression list {name}: a DROP list starts with the header "Id,Hash"')
    entries = set()
    for n, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        parts = line.strip().split(",")
        try:
            ok = len(parts) == 2 and len(base64.b64decode(parts[1], validate=True)) == 32
        except ValueError:
            ok = False
        if not ok or len(parts[1]) != 44:
            raise DeidentError(f"suppression list {name}: line {n} is not Id,<Base64 SHA-256>")
        entries.add(parts[1])
    return frozenset(entries)


@dataclass
class _ColumnStats:
    action: str
    justification: str | None
    normalise: tuple[str, ...]
    generalise: dict | None = None
    changed: int = 0
    missing: int = 0
    entities: Counter | None = None

    def as_dict(self, name: str) -> dict:
        out: dict = {
            "name": name,
            "action": self.action,
            "changed": self.changed,
            "missing": self.missing,
        }
        if self.normalise:
            out["normalise"] = list(self.normalise)
        if self.generalise:
            out["generalise"] = dict(self.generalise)
        if self.entities is not None:  # found and redacted (scrub_text) or found and kept (keep)
            out["entities"] = dict(sorted(self.entities.items()))
        if self.justification:
            out["justification"] = self.justification
        return out


def _tools(fmt: str) -> dict[str, str]:
    out = {
        "presidio-deident": __version__,
        "presidio-evidence": importlib.metadata.version("presidio-evidence"),
    }
    if fmt == "parquet":
        out["pyarrow"] = importlib.metadata.version("pyarrow")
    return out


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json(path: Path, doc: dict) -> None:
    text = json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def run_release(
    policy: Policy,
    source: Path,
    out: Path,
    *,
    sign_key: str,
    pseudonym_key: str | None = None,
    released_at: str | None = None,
    residual_scan: bool = True,
    parents: tuple[str, ...] = (),
) -> dict:
    """Produce a release directory at ``out``. Returns the record.

    ``parents`` (record hashes of earlier releases) are added to the policy's own."""
    if not policy.file_sha256:
        raise DeidentError("the policy must be loaded from its file (load_policy)")
    if released_at is not None and not TIMESTAMP_RE.fullmatch(released_at):
        raise DeidentError("released_at must be a UTC timestamp YYYY-MM-DDTHH:MM:SSZ")
    fmt = table_format(source)
    if out.exists() or out.is_symlink():
        raise DeidentError(f"{out} already exists; a release is never overwritten")
    columns = scan_columns(source)
    unknown = [c for c in columns if c not in policy.columns]
    if unknown:
        raise DeidentError(f"input column(s) without a policy entry: {', '.join(unknown)}")
    stale = [c for c in policy.columns if c not in columns]
    if stale:
        raise DeidentError(f"policy lists column(s) not in the input: {', '.join(stale)}")

    actions = {c: policy.columns[c].action for c in columns}
    key = None
    if "pseudonymise" in actions.values():
        if pseudonym_key is None:
            raise DeidentError("the policy pseudonymises a column: a pseudonym key is required")
        key = derive_pseudonym_key(pseudonym_key, policy.domain)

    lists = [_load_list(s) for s in policy.suppression]
    stats = {
        c: _ColumnStats(
            actions[c],
            policy.columns[c].justification,
            policy.columns[c].normalise,
            policy.columns[c].generalise,
        )
        for c in columns
    }
    risk = (
        RiskAccumulator(list(policy.risk.quasi_identifiers), list(policy.risk.sensitive))
        if policy.risk
        else None
    )
    for s in stats.values():
        if s.action == "scrub_text" or (s.action == "keep" and residual_scan):
            s.entities = Counter()
    out_columns = [c for c in columns if actions[c] != "drop"]

    partial = out.with_name(out.name + ".partial")
    if partial.exists() or partial.is_symlink():
        raise DeidentError(f"{partial} exists, probably from an interrupted run; remove it first")
    partial.mkdir(mode=0o700, parents=True)
    rows_in = rows_out = 0
    try:
        target = partial / source.name
        with open_table(source) as table:
            kept_types = {c: t for c, t in (table.types or {}).items() if actions.get(c) == "keep"}
            with TableWriter(target, fmt, out_columns, kept_types) as writer:
                for row in table.rows:
                    rows_in += 1
                    where = f"{source.name} row {rows_in}"
                    extra = [k for k in row if k not in stats]
                    if extra:
                        raise DeidentError(
                            f"{where}: column(s) without a policy entry: {', '.join(extra)}"
                        )
                    hit = [lst for lst in lists if lst.matches(row.get(lst.spec.column), where)]
                    for lst in hit:
                        lst.matched += 1
                    if hit:
                        continue
                    out_row = _transform(row, columns, stats, key, fmt, where)
                    writer.write(out_row)
                    if risk is not None:
                        risk.add(out_row)
                    rows_out += 1

        _check_residual(stats)
        risk_report = risk.report() if risk is not None else None
        _check_risk(policy, risk_report)
        digest, size = sha256_file(target)
        src_digest, src_size = sha256_file(source)
        rel_at = released_at or policy.released_at or _now()
        record = {
            "schema": RECORD_SCHEMA,
            "release_id": f"{policy.dataset_id}@{rel_at}",
            "dataset_id": policy.dataset_id,
            "recipient": policy.recipient,
            "signer": policy.signer,
            "released_at": rel_at,
            "tools": _tools(fmt),
            "policy_sha256": policy.file_sha256,
            "detector": {"name": _detect.DETECTOR_ID, "entities": list(_detect.ENTITY_TYPES)},
            "residual_scan": residual_scan,
            "sources": [
                {"name": source.name, "sha256": src_digest, "bytes": src_size, "rows": rows_in}
            ],
            "outputs": [{"name": source.name, "sha256": digest, "bytes": size, "rows": rows_out}],
            "rows": {"in": rows_in, "suppressed": rows_in - rows_out, "out": rows_out},
            "columns": [stats[c].as_dict(c) for c in columns],
            "suppression": [
                {
                    "name": lst.spec.name,
                    "column": lst.spec.column,
                    "format": lst.spec.format,
                    "normalise": list(lst.spec.normalise),
                    "as_of": lst.spec.as_of,
                    "sha256": lst.sha256,
                    "entries": len(lst.entries),
                    "rows_matched": lst.matched,
                }
                for lst in lists
            ],
            "rights": [r.as_dict() for r in policy.rights],
        }
        if key is not None:
            record["pseudonyms"] = {"scheme": PSEUDONYM_SCHEME, "domain": policy.domain}
        all_parents = list(dict.fromkeys(policy.parents + tuple(parents)))
        if all_parents:
            record["parents"] = all_parents
        if risk_report is not None:
            if policy.risk.require_min_k is not None:
                risk_report["require_min_k"] = policy.risk.require_min_k
            record["risk"] = risk_report
        _write_json(partial / RECORD_FILE, record)
        _write_json(partial / EVIDENCE_FILE, sign_record(record, sign_key))
        os.replace(partial, out)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    return record


def _check_residual(stats: dict[str, _ColumnStats]) -> None:
    flagged = [
        c for c, s in stats.items() if s.action == "keep" and s.entities and not s.justification
    ]
    if flagged:
        raise DeidentError(
            "kept column(s) contain detected PII and have no justification: "
            + ", ".join(flagged)
            + ". Change the action, or add a justification to keep them."
        )


def _check_risk(policy: Policy, report: dict | None) -> None:
    if report is None or policy.risk.require_min_k is None:
        return
    if report["min_k"] < policy.risk.require_min_k:
        raise DeidentError(
            f"the smallest quasi-identifier class has {report['min_k']} row(s); the policy "
            f"requires at least {policy.risk.require_min_k} ({report['unique_rows']} unique "
            "rows). Generalise or suppress further."
        )


def _transform(row, columns, stats, key, fmt, where) -> dict:
    out = {}
    for c in columns:
        s = stats[c]
        present = c in row
        value = row.get(c)
        if is_missing(value):
            s.missing += 1
        if s.action == "drop":
            if not is_missing(value):
                s.changed += 1
            continue
        if not present and fmt == "jsonl":
            continue
        if not is_missing(value):
            if s.action == "pseudonymise":
                value = pseudonymise(key, _normalise(_as_text(value, f"{where}, {c}"), s.normalise))
                s.changed += 1
            elif s.action == "generalise":
                new = generalise(s.generalise, value, f"{where}, {c}")
                s.changed += new != value
                value = new
            elif s.action == "scrub_text":
                if not isinstance(value, str):
                    raise DeidentError(f"{where}, {c}: scrub_text applies to text values only")
                new, counts = _detect.scrub(value)
                if counts:  # otherwise keep the original, not its Unicode-normalised form
                    s.changed += 1
                    s.entities.update(counts)
                    value = new
            elif s.entities is not None and isinstance(value, str):
                s.entities.update(_detect.detect(value))
        out[c] = value
    return out


def sign_record(record: dict, sign_key: str) -> dict:
    """The ``evidence-ref@3`` envelope over the record: framework ``dataset-release``,
    item = dataset id, ``ledger_ref`` = the record's file name."""
    digest = pe.content_hash(record)
    signer = record["signer"]
    signature = pe.sign_evidence_v3(digest, signer, FRAMEWORK, record["dataset_id"], key=sign_key)
    ref = {
        "item_id": record["dataset_id"],
        "source": "presidio-deident",
        "source_version": __version__,
        "ledger_ref": RECORD_FILE,
        "content_hash": digest,
        "signer": signer,
        "signature": signature,
        "claimed_at": record["released_at"],
        "framework": FRAMEWORK,
    }
    return pe.build_envelope(
        [ref],
        schema=pe.EVIDENCE_REF_SCHEMA_ID_V3,
        source="presidio-deident",
        source_version=__version__,
        generated_at=record["released_at"],
    )
