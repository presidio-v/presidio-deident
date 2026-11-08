"""The release policy: a TOML file naming the release, each column's action and suppression.

Validation is strict and fail-closed. An unknown key, a column without an action or a
malformed value stops the run before any data is read.
"""

from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import _detect
from .errors import DeidentError

ACTIONS = ("drop", "keep", "pseudonymise", "scrub_text", "generalise")
DATE_LEVELS = ("year", "month")
NORMALISERS = ("strip", "lower", "drop-email", "drop-phone")
LIST_FORMATS = ("plain", "sha256", "ca-drop")
DROP_NORMALISERS = ("drop-email", "drop-phone")  # California DROP standardisation

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_TEXT = 512
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


@dataclass(frozen=True)
class Column:
    action: str
    justification: str | None = None
    normalise: tuple[str, ...] = ()
    generalise: dict | None = None  # exactly one of {"date": level}, {"prefix": n}, {"bin": w, ...}


@dataclass(frozen=True)
class Suppression:
    name: str
    file: Path
    column: str
    format: str
    normalise: tuple[str, ...]
    as_of: str


@dataclass(frozen=True)
class Right:
    source: str
    basis: str
    reference: str | None = None

    def as_dict(self) -> dict[str, str]:
        out = {"source": self.source, "basis": self.basis}
        if self.reference:
            out["reference"] = self.reference
        return out


@dataclass(frozen=True)
class Risk:
    quasi_identifiers: tuple[str, ...]
    sensitive: tuple[str, ...] = ()
    require_min_k: int | None = None


@dataclass(frozen=True)
class Policy:
    dataset_id: str
    recipient: str
    signer: str
    columns: dict[str, Column]
    pseudonym_domain: str = ""
    rights: tuple[Right, ...] = ()
    parents: tuple[str, ...] = ()
    released_at: str | None = None
    suppression: tuple[Suppression, ...] = ()
    risk: Risk | None = None
    file_sha256: str = field(default="", compare=False)

    @property
    def domain(self) -> str:
        """The pseudonym domain: the recipient unless the policy names another one."""
        return self.pseudonym_domain or self.recipient


def _table(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        raise DeidentError(f"{where} must be a table")
    return value


def _string(value: object, where: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise DeidentError(f"{where} must be a non-empty string of at most {MAX_TEXT} characters")
    if pattern is not None and not pattern.fullmatch(value):
        raise DeidentError(f"{where} has an invalid format")
    return value


def _free_text(value: object, where: str) -> str:
    """Human-written text that goes into the record: bounded, and refused if it holds PII."""
    text = _string(value, where)
    if _detect.detect(text):
        raise DeidentError(f"{where} contains what looks like personal data; rephrase it")
    return text


def _normalisers(value: object, where: str, default: list[str]) -> tuple[str, ...]:
    norm = default if value is None else value
    if not isinstance(norm, list) or any(n not in NORMALISERS for n in norm):
        raise DeidentError(f"{where} must list some of {', '.join(NORMALISERS)}")
    return tuple(norm)


def _only(table: dict, allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise DeidentError(f"{where}: unknown key(s) {', '.join(unknown)}")


def _int(value: object, where: str, low: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low:
        raise DeidentError(f"{where} must be an integer >= {low}")
    return value


def _generalise(spec: dict, action: str, where: str) -> dict | None:
    given = [k for k in ("date", "prefix", "bin", "bottom", "top") if k in spec]
    if action != "generalise":
        if given:
            raise DeidentError(f"{where}: {', '.join(given)} apply to action generalise only")
        return None
    kinds = [k for k in ("date", "prefix", "bin") if k in spec]
    if len(kinds) != 1:
        raise DeidentError(f"{where}: generalise needs exactly one of date, prefix or bin")
    kind = kinds[0]
    if kind != "bin" and ("bottom" in spec or "top" in spec):
        raise DeidentError(f"{where}: bottom and top apply to bin only")
    if kind == "date":
        if spec["date"] not in DATE_LEVELS:
            raise DeidentError(f"{where}.date must be one of {', '.join(DATE_LEVELS)}")
        return {"date": spec["date"]}
    if kind == "prefix":
        return {"prefix": _int(spec["prefix"], f"{where}.prefix", 1)}
    out = {"bin": _int(spec["bin"], f"{where}.bin", 1)}
    for edge in ("bottom", "top"):
        if edge in spec:
            out[edge] = _int(spec[edge], f"{where}.{edge}", -(10**12))
    if "bottom" in out and "top" in out and out["top"] <= out["bottom"]:
        raise DeidentError(f"{where}: top must be greater than bottom")
    return out


def _risk(value: object, columns: dict[str, Column]) -> Risk | None:
    if value is None:
        return None
    r = _table(value, "[risk]")
    _only(r, {"quasi_identifiers", "sensitive", "require_min_k"}, "[risk]")
    names = {}
    for key in ("quasi_identifiers", "sensitive"):
        items = r.get(key, [])
        if not isinstance(items, list) or not all(isinstance(c, str) for c in items):
            raise DeidentError(f"risk.{key} must be a list of column names")
        for c in items:
            if c not in columns:
                raise DeidentError(f"risk.{key}: {c} is not a column of the policy")
            if columns[c].action == "drop":
                raise DeidentError(f"risk.{key}: {c} is dropped, so it is not in the output")
        if len(set(items)) != len(items):
            raise DeidentError(f"risk.{key} lists a column twice")
        names[key] = tuple(items)
    if not names["quasi_identifiers"]:
        raise DeidentError("risk.quasi_identifiers must name at least one column")
    if set(names["quasi_identifiers"]) & set(names["sensitive"]):
        raise DeidentError("a column cannot be both quasi-identifier and sensitive")
    k = r.get("require_min_k")
    return Risk(
        names["quasi_identifiers"],
        names["sensitive"],
        _int(k, "risk.require_min_k", 2) if k is not None else None,
    )


def parse_policy(data: dict, base_dir: Path) -> Policy:
    _only(data, {"release", "columns", "suppression", "risk"}, "policy")
    rel = _table(data.get("release"), "[release]")
    _only(
        rel,
        {
            "dataset_id",
            "recipient",
            "signer",
            "released_at",
            "rights",
            "parents",
            "pseudonym_domain",
        },
        "[release]",
    )
    domain = rel.get("pseudonym_domain")
    if domain is not None:
        _string(domain, "release.pseudonym_domain", ID_RE)
    released_at = rel.get("released_at")
    if released_at is not None:
        _string(released_at, "release.released_at", TIMESTAMP_RE)

    rights = []
    for i, r in enumerate(rel.get("rights", [])):
        r = _table(r, f"release.rights[{i}]")
        _only(r, {"source", "basis", "reference"}, f"release.rights[{i}]")
        ref = r.get("reference")
        rights.append(
            Right(
                _free_text(r.get("source"), f"release.rights[{i}].source"),
                _free_text(r.get("basis"), f"release.rights[{i}].basis"),
                _free_text(ref, f"release.rights[{i}].reference") if ref is not None else None,
            )
        )
    parents = rel.get("parents", [])
    if not isinstance(parents, list):
        raise DeidentError("release.parents must be a list")
    for i, p in enumerate(parents):
        _string(p, f"release.parents[{i}]", _HEX64_RE)

    cols_raw = _table(data.get("columns"), "[columns]")
    if not cols_raw:
        raise DeidentError("[columns] must list every column of the input")
    columns = {}
    for name, spec in cols_raw.items():
        spec = _table(spec, f"columns.{name}")
        _only(
            spec,
            {"action", "justification", "normalise", "date", "prefix", "bin", "bottom", "top"},
            f"columns.{name}",
        )
        action = spec.get("action")
        if action not in ACTIONS:
            raise DeidentError(f"columns.{name}.action must be one of {', '.join(ACTIONS)}")
        just = spec.get("justification")
        if just is not None:
            just = _free_text(just, f"columns.{name}.justification")
        norm = spec.get("normalise")
        if norm is not None and action != "pseudonymise":
            raise DeidentError(f"columns.{name}.normalise applies to pseudonymise only")
        gen = _generalise(spec, action, f"columns.{name}")
        columns[name] = Column(
            action, just, _normalisers(norm, f"columns.{name}.normalise", []), gen
        )

    suppression = []
    seen = set()
    for i, s in enumerate(data.get("suppression", [])):
        where = f"suppression[{i}]"
        s = _table(s, where)
        _only(s, {"name", "file", "column", "format", "normalise", "as_of"}, where)
        name = _string(s.get("name"), f"{where}.name", ID_RE)
        if name in seen:
            raise DeidentError(f"{where}.name is not unique")
        seen.add(name)
        column = _string(s.get("column"), f"{where}.column")
        if column not in columns:
            raise DeidentError(f"{where}.column is not a column of the policy")
        fmt = s.get("format", "plain")
        if fmt not in LIST_FORMATS:
            raise DeidentError(f"{where}.format must be one of {', '.join(LIST_FORMATS)}")
        norm = _normalisers(s.get("normalise"), f"{where}.normalise", ["strip"])
        if fmt == "ca-drop" and (len(norm) != 1 or norm[0] not in DROP_NORMALISERS):
            raise DeidentError(
                f'{where}: format "ca-drop" needs normalise = ["drop-email"] or ["drop-phone"]'
            )
        if fmt != "ca-drop" and any(n in DROP_NORMALISERS for n in norm):
            raise DeidentError(f'{where}: drop-email and drop-phone apply to format "ca-drop"')
        file_name = _string(s.get("file"), f"{where}.file")
        suppression.append(
            Suppression(
                name=name,
                file=base_dir / file_name,
                column=column,
                format=fmt,
                normalise=norm,
                as_of=_string(s.get("as_of"), f"{where}.as_of", _DATE_RE),
            )
        )

    risk = _risk(data.get("risk"), columns)

    return Policy(
        risk=risk,
        dataset_id=_string(rel.get("dataset_id"), "release.dataset_id", ID_RE),
        recipient=_string(rel.get("recipient"), "release.recipient", ID_RE),
        signer=_string(rel.get("signer"), "release.signer", ID_RE),
        columns=columns,
        pseudonym_domain=domain or "",
        rights=tuple(rights),
        parents=tuple(parents),
        released_at=released_at,
        suppression=tuple(suppression),
    )


def load_policy(path: Path) -> Policy:
    """Parse and validate a policy file. ``file_sha256`` is the hash of the file's bytes."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DeidentError(f"cannot read policy {path}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise DeidentError(f"policy {path.name} is not valid UTF-8 TOML: {exc}") from exc
    policy = parse_policy(data, path.parent)
    return replace(policy, file_sha256=hashlib.sha256(raw).hexdigest())


def _toml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def policy_skeleton(columns: list[str], suggestions: dict[str, str], dataset_id: str) -> str:
    """A policy with every column listed. Suggested actions are a starting point to review."""
    lines = [
        "# presidio-deident release policy. Review every action before a release.",
        "[release]",
        f"dataset_id = {_toml_str(dataset_id)}",
        'recipient = "CHANGE-ME"',
        'signer = "CHANGE-ME"',
        '# pseudonym_domain = "CHANGE-ME"  # default: the recipient (docs/adr/0005)',
        '# released_at = "2026-01-01T00:00:00Z"  # fix it for a reproducible release',
        "",
        "# [[release.rights]]",
        '# source = "where the data came from"',
        '# basis = "the right under which it may be licensed for AI training"',
        '# reference = "contract or consent reference"',
        "",
        "[columns]",
    ]
    for name in columns:
        action = suggestions.get(name, "keep")
        lines.append(f"{_toml_str(name)} = {{ action = {_toml_str(action)} }}")
    lines += [
        "",
        "# [[suppression]]",
        '# name = "opt-out-2026-11"',
        '# file = "opt-out.txt"',
        '# column = "email"',
        '# format = "plain"  # or "sha256": entries are hex SHA-256 of the normalised value',
        '# normalise = ["strip", "lower"]',
        '# as_of = "2026-11-01"',
        "",
    ]
    return "\n".join(lines)
