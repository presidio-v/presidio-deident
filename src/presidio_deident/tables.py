"""Streaming readers and writers for CSV and JSONL.

CSV: UTF-8 (a BOM is accepted), a header row is required, every value is a string and
an empty string counts as missing. JSONL: one JSON object per line with scalar values
(string, number, boolean, null). Nested objects and arrays are rejected in this version.
Output is deterministic: ``\\n`` line endings, the input's column order, compact JSON.
"""

from __future__ import annotations

import csv
import json
import math
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from .errors import DeidentError

FORMATS = {".csv": "csv", ".jsonl": "jsonl", ".ndjson": "jsonl", ".parquet": "parquet"}
PARQUET_BATCH = 4096


def table_format(path: Path) -> str:
    fmt = FORMATS.get(path.suffix.lower())
    if fmt is None:
        raise DeidentError(f"{path.name}: unsupported format (use .csv, .jsonl or .parquet)")
    return fmt


def is_missing(value: object) -> bool:
    return value is None or value == ""


def read_csv(fh: IO[str], name: str) -> tuple[list[str], Iterator[dict]]:
    reader = csv.reader(fh, strict=True)
    try:
        header = next(reader)
    except StopIteration:
        raise DeidentError(f"{name}: empty file, a header row is required") from None
    except csv.Error as exc:
        raise DeidentError(f"{name}: malformed CSV header") from exc
    except UnicodeDecodeError:
        raise DeidentError(f"{name}: not UTF-8") from None
    if len(set(header)) != len(header) or any(not h for h in header):
        raise DeidentError(f"{name}: header has empty or duplicate column names")

    def rows() -> Iterator[dict]:
        try:
            for n, values in enumerate(reader, start=2):
                if not values:
                    continue
                if len(values) != len(header):
                    raise DeidentError(
                        f"{name}: line {n} has {len(values)} fields, the header has {len(header)}"
                    )
                yield dict(zip(header, values, strict=True))
        except csv.Error as exc:
            raise DeidentError(f"{name}: malformed CSV near line {reader.line_num}") from exc
        except UnicodeDecodeError:
            raise DeidentError(f"{name}: not UTF-8 near line {reader.line_num + 1}") from None

    return header, rows()


_SCALARS = (str, int, float, bool, type(None))


def _no_constant(_: str) -> None:
    raise ValueError("NaN and Infinity are not JSON")


def _finite(text: str) -> float:
    value = float(text)
    if math.isinf(value):
        raise ValueError("number out of range")
    return value


def _lines(fh: IO[str], name: str) -> Iterator[tuple[int, str]]:
    n = 0
    try:
        for n, line in enumerate(fh, start=1):  # noqa: B007 - n is read in the except
            yield n, line
    except UnicodeDecodeError:
        raise DeidentError(f"{name}: not UTF-8 near line {n + 1}") from None


def _valid_text(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def read_jsonl(fh: IO[str], name: str) -> Iterator[dict]:
    for n, line in _lines(fh, name):
        if not line.strip():
            continue
        try:
            obj = json.loads(line, parse_constant=_no_constant, parse_float=_finite)
        except (ValueError, RecursionError):
            raise DeidentError(f"{name}: line {n} is not valid JSON") from None
        if not isinstance(obj, dict):
            raise DeidentError(f"{name}: line {n} is not a JSON object")
        for key, value in obj.items():
            if not _valid_text(key):
                raise DeidentError(f"{name}: line {n} has a key that is not valid Unicode")
            if not isinstance(value, _SCALARS):
                raise DeidentError(
                    f"{name}: line {n}, field {key!r} is nested; only scalar values are supported"
                )
            if isinstance(value, str) and not _valid_text(value):
                raise DeidentError(f"{name}: line {n}, field {key!r} is not valid Unicode")
        yield obj


@dataclass
class Table:
    fmt: str
    columns: list[str] | None  # None for JSONL: known only after a full pass
    rows: Iterator[dict]
    types: dict | None = None  # Parquet column types, kept for unchanged columns


def _pyarrow():
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise DeidentError(
            "Parquet needs the 'parquet' extra: pip install 'presidio-deident[parquet]'"
        ) from exc
    return pa, pq


def _parquet_types(schema, name: str) -> dict:
    pa, _ = _pyarrow()
    t = pa.types
    allowed = (
        t.is_string,
        t.is_large_string,
        t.is_integer,
        t.is_floating,
        t.is_boolean,
        t.is_date,
        t.is_timestamp,
        t.is_null,
    )
    names = list(schema.names)
    if len(set(names)) != len(names) or any(not n for n in names):
        raise DeidentError(f"{name}: empty or duplicate column names")
    for field in schema:
        if not any(check(field.type) for check in allowed):
            raise DeidentError(
                f"{name}: column {field.name!r} has type {field.type}; only strings, integers, "
                "floats, booleans, dates and timestamps are supported"
            )
    return {f.name: f.type for f in schema}


def _parquet_rows(pf, name: str) -> Iterator[dict]:
    pa, _ = _pyarrow()
    try:
        for batch in pf.iter_batches(batch_size=PARQUET_BATCH):
            yield from batch.to_pylist()
    except (pa.ArrowException, UnicodeDecodeError, OSError):
        raise DeidentError(f"{name}: not a readable Parquet file") from None


@contextmanager
def open_table(path: Path) -> Iterator[Table]:
    """Open any supported file for streaming rows."""
    fmt = table_format(path)
    if fmt == "parquet":
        pa, pq = _pyarrow()
        try:
            pf = pq.ParquetFile(path)
            schema = pf.schema_arrow
        except (pa.ArrowException, OSError):
            raise DeidentError(f"{path.name}: not a readable Parquet file") from None
        types = _parquet_types(schema, path.name)
        yield Table(fmt, list(schema.names), _parquet_rows(pf, path.name), types)
        return
    with path.open(encoding="utf-8-sig", newline="") as fh:
        if fmt == "csv":
            header, rows = read_csv(fh, path.name)
            yield Table(fmt, header, rows)
        else:
            yield Table(fmt, None, read_jsonl(fh, path.name))


def scan_columns(path: Path) -> list[str]:
    """Every column of the file, in order of first appearance."""
    with open_table(path) as table:
        if table.columns is not None:
            return table.columns
        seen: dict[str, None] = {}
        for row in table.rows:
            for key in row:
                seen.setdefault(key, None)
        return list(seen)


class TableWriter:
    """Writes rows to a new ``0600`` file. Parquet columns that the policy changed are strings;
    unchanged ones keep their input type."""

    def __init__(self, path: Path, fmt: str, columns: list[str], types: dict | None = None):
        self.fmt = fmt
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        if fmt == "parquet":
            pa, pq = _pyarrow()
            self._fh = os.fdopen(fd, "wb")
            self._schema = pa.schema([(c, (types or {}).get(c, pa.string())) for c in columns])
            self._pq = pq.ParquetWriter(self._fh, self._schema)
            self._buffer: list[dict] = []
            return
        self._fh = os.fdopen(fd, "w", encoding="utf-8", newline="")
        if fmt == "csv":
            self._csv = csv.DictWriter(self._fh, fieldnames=columns, lineterminator="\n")
            self._csv.writeheader()

    def write(self, row: dict) -> None:
        if self.fmt == "csv":
            self._csv.writerow(row)
        elif self.fmt == "jsonl":
            line = json.dumps(row, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            self._fh.write(line + "\n")
        else:
            self._buffer.append(row)
            if len(self._buffer) >= PARQUET_BATCH:
                self._flush()

    def _flush(self) -> None:
        if self._buffer:
            pa, _ = _pyarrow()
            self._pq.write_table(pa.Table.from_pylist(self._buffer, schema=self._schema))
            self._buffer = []

    def close(self) -> None:
        try:
            if self.fmt == "parquet":
                self._flush()
                self._pq.close()
        finally:
            self._fh.close()

    def __enter__(self) -> TableWriter:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
