"""Output parsing utilities for external tool results."""

from __future__ import annotations

import json
from typing import Any


def parse_lines(output: str) -> list[str]:
    """Parse line-delimited tool output. Strips whitespace and drops empty lines."""
    return [line.strip() for line in output.splitlines() if line.strip()]


def parse_jsonl(output: str) -> list[dict[str, Any]]:
    """Parse JSON Lines output (one JSON object per line). Invalid lines are skipped."""
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            results.append(obj)
    return results
