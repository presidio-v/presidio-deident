"""Generalisation transforms: coarsen a value so that more rows share it.

- ``date = "year" | "month"``: an ISO date or timestamp becomes ``YYYY`` or ``YYYY-MM``.
- ``prefix = n``: keep the first ``n`` characters (for example postcodes).
- ``bin = w`` with optional ``bottom`` and ``top``: an integer becomes the label of its
  band, ``"30-39"``. Values below ``bottom`` become ``"<bottom"`` and values at or above
  ``top`` become ``"top+"`` (bottom and top coding).

A value that does not fit the transform stops the run. Error messages name the row and
column, never the value. Missing values stay missing.
"""

from __future__ import annotations

import re
from datetime import date

from .errors import DeidentError

_DATE = re.compile(r"([0-9]{4})-([0-9]{2})(?:-([0-9]{2}))?(?:[T ].*)?")  # ASCII digits only
_INT = re.compile(r"-?[0-9]{1,18}")


def generalise(spec: dict, value: object, where: str) -> str:
    if isinstance(value, date):  # Parquet dates and timestamps (datetime is a date)
        value = value.isoformat()
    if "date" in spec:
        m = _DATE.fullmatch(value) if isinstance(value, str) else None
        if m is None or not 1 <= int(m.group(2)) <= 12:
            raise DeidentError(f"{where}: generalise date expects an ISO date (YYYY-MM[-DD])")
        return m.group(1) if spec["date"] == "year" else f"{m.group(1)}-{m.group(2)}"
    if "prefix" in spec:
        if isinstance(value, int) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str):
            raise DeidentError(f"{where}: generalise prefix expects text or an integer")
        return value[: spec["prefix"]]
    if isinstance(value, bool) or not (
        isinstance(value, int) or (isinstance(value, str) and _INT.fullmatch(value.strip()))
    ):
        raise DeidentError(f"{where}: generalise bin expects an integer")
    n = int(value)
    bottom, top, width = spec.get("bottom"), spec.get("top"), spec["bin"]
    if bottom is not None and n < bottom:
        return f"<{bottom}"
    if top is not None and n >= top:
        return f"{top}+"
    origin = bottom if bottom is not None else 0
    lo = origin + ((n - origin) // width) * width
    hi = lo + width - 1
    if top is not None:
        hi = min(hi, top - 1)
    return str(lo) if lo == hi else f"{lo}-{hi}"
