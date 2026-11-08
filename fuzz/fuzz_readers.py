"""Atheris harness: the CSV/JSONL readers and the policy parser raise only DeidentError.

Run on Linux (Atheris has no macOS wheel): python fuzz/fuzz_readers.py -max_total_time=60
"""

import io
import sys
import tomllib
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from presidio_deident.errors import DeidentError
    from presidio_deident.policy import parse_policy
    from presidio_deident.tables import read_csv, read_jsonl


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", "replace")
    for read in (
        lambda: list(read_csv(io.StringIO(text), "f.csv")[1]),
        lambda: list(read_jsonl(io.StringIO(text), "f.jsonl")),
    ):
        try:
            read()
        except DeidentError:
            pass
    try:
        parse_policy(tomllib.loads(text), Path("."))
    except (tomllib.TOMLDecodeError, DeidentError):
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
