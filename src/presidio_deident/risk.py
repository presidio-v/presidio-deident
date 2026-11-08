"""Quasi-identifier risk: equivalence classes over declared columns, as integer counts.

A row's class is the tuple of its quasi-identifier values (missing values form their own
value). The report gives the number of classes, the smallest class (k), how many rows sit
in classes of each size band, and per sensitive column the smallest number of distinct
values in any class (l). It reports distributions and claims nothing about identifiability.
All numbers are integers, because the record is canonical JSON without floats.
"""

from __future__ import annotations

import json
from collections import Counter

# Size bands for the row histogram: a row in a class of size 1 is unique.
BANDS = (
    ("1", 1, 1),
    ("2", 2, 2),
    ("3-4", 3, 4),
    ("5-9", 5, 9),
    ("10-99", 10, 99),
    ("100+", 100, None),
)
L_CAP = 10  # distinct sensitive values tracked per class; min_l is exact below this


def _key(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)  # default: Parquet dates


class RiskAccumulator:
    def __init__(self, quasi_identifiers: list[str], sensitive: list[str] | None = None):
        self.qi = list(quasi_identifiers)
        self.sensitive = list(sensitive or [])
        self.classes: Counter = Counter()
        self.values: dict[str, dict[tuple, set]] = {s: {} for s in self.sensitive}
        self.rows = 0

    def add(self, row: dict) -> None:
        key = tuple(_key(row.get(c)) for c in self.qi)
        self.classes[key] += 1
        self.rows += 1
        for s in self.sensitive:
            seen = self.values[s].setdefault(key, set())
            if len(seen) < L_CAP:
                seen.add(_key(row.get(s)))

    def report(self) -> dict:
        sizes = Counter(self.classes.values())
        bands = {}
        for label, lo, hi in BANDS:
            bands[label] = sum(
                n * size for size, n in sizes.items() if size >= lo and (hi is None or size <= hi)
            )
        out = {
            "quasi_identifiers": self.qi,
            "rows": self.rows,
            "classes": len(self.classes),
            "min_k": min(self.classes.values(), default=0),
            "unique_rows": bands["1"],
            "rows_by_class_size": bands,
        }
        if self.sensitive:
            out["min_l_cap"] = L_CAP
            out["sensitive"] = {
                s: {
                    "min_l": min((len(v) for v in self.values[s].values()), default=0),
                    "classes_with_one_value": sum(
                        1 for v in self.values[s].values() if len(v) == 1
                    ),
                }
                for s in self.sensitive
            }
        return out
