"""Look at a file before writing its policy: columns, missing values, detected PII types.

Reads at most ``sample`` rows. Reports counts and suggested actions only, never values.
Suggestions are a starting point; the policy author decides.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import _detect
from .tables import is_missing, open_table

_DIRECT = re.compile(
    r"(e-?mail|phone|mobile|fax|ssn|social.?security|passport|iban|account.?no|"
    r"first.?name|last.?name|full.?name|surname|street|address|ip.?addr|(^|_)name$|birth|dob)",
    re.IGNORECASE,
)
_IDENTIFIER = re.compile(r"(^id$|_id$|^uid$|uuid|customer|user|patient|member)", re.IGNORECASE)
LONG_TEXT = 20


@dataclass
class ColumnReport:
    name: str
    values: int = 0
    missing: int = 0
    text_chars: int = 0
    entities: Counter = field(default_factory=Counter)
    rows_with_pii: int = 0

    @property
    def mean_length(self) -> int:
        present = self.values - self.missing
        return self.text_chars // present if present else 0

    def suggestion(self) -> str:
        if _DIRECT.search(self.name):
            return "drop"
        if self.rows_with_pii:
            return "scrub_text" if self.mean_length >= LONG_TEXT else "drop"
        if _IDENTIFIER.search(self.name):
            return "pseudonymise"
        return "keep"


def inspect_file(
    path: Path, *, sample: int = 1000, detect: bool = True
) -> tuple[list[ColumnReport], int]:
    reports: dict[str, ColumnReport] = {}
    n = 0
    with open_table(path) as table:
        for h in table.columns or []:
            reports[h] = ColumnReport(h)
        for row in table.rows:
            if n >= sample:
                break
            n += 1
            for key, value in row.items():
                rep = reports.setdefault(key, ColumnReport(key))
                rep.values += 1
                if is_missing(value):
                    rep.missing += 1
                    continue
                if isinstance(value, str):
                    rep.text_chars += len(value)
                    if detect:
                        found = _detect.detect(value)
                        if found:
                            rep.rows_with_pii += 1
                            rep.entities.update(found)
    for rep in reports.values():
        rep.missing += n - rep.values  # JSONL rows without the key
        rep.values = n
    return list(reports.values()), n
