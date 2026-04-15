"""Parse short duration strings like 24h, 7d, 2w into timedeltas."""

from __future__ import annotations

import re
from datetime import timedelta

_PATTERN = re.compile(r"^(\d+)([hdw])$")
_UNITS = {
    "h": lambda n: timedelta(hours=n),
    "d": lambda n: timedelta(days=n),
    "w": lambda n: timedelta(weeks=n),
}


def parse_duration(value: str) -> timedelta:
    """Parse '24h', '7d', '2w' into a timedelta. Raises ValueError on bad input."""
    match = _PATTERN.match(value.strip().lower())
    if match is None:
        raise ValueError(f"invalid duration {value!r}, expected like '24h', '7d', '2w'")
    n, unit = int(match.group(1)), match.group(2)
    return _UNITS[unit](n)
