"""Output parsing utilities for external tool results."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def parse_lines(output: str) -> list[str]:
    """Parse line-delimited tool output. Strips whitespace and drops empty lines."""
    return [line.strip() for line in output.splitlines() if line.strip()]


def normalize_hosts(hosts: list[str]) -> list[str]:
    """Lowercase, strip whitespace, drop trailing dots, dedupe, sort."""
    seen: set[str] = set()
    out: list[str] = []
    for h in hosts:
        h = h.strip().lower().rstrip(".")
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return sorted(out)


_ALLOWED_SCHEMES = {"http", "https"}


def normalize_url(url: str) -> str | None:
    """Normalize a URL for consistent storage and deduplication.

    Returns None if the URL should be discarded (non-http scheme, unparseable).
    - lowercases scheme and host
    - strips fragment
    - strips trailing slash from path (unless path is just "/")
    - sorts query parameters
    """
    try:
        p = urlparse(url.strip())
    except ValueError:
        return None
    if p.scheme not in _ALLOWED_SCHEMES:
        return None
    host = (p.hostname or "").lower()
    if not host:
        return None
    path = p.path.rstrip("/") or "/"
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    netloc = host + (f":{p.port}" if p.port else "")
    return urlunparse((p.scheme.lower(), netloc, path, "", query, ""))


def normalize_urls(urls: list[str]) -> list[str]:
    """Normalize and deduplicate a list of URLs, dropping invalid ones."""
    seen: set[str] = set()
    out: list[str] = []
    for url in urls:
        normalized = normalize_url(url)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


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
