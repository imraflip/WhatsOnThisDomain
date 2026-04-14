"""Keep the trickest resolvers list fresh. Trickest publishes daily updates."""

from __future__ import annotations

import time
from pathlib import Path

import httpx

TRICKEST_RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"


async def ensure_resolvers_fresh(path: Path, max_age_hours: float = 24.0) -> bool:
    """Re-download the resolvers list if missing or older than max_age_hours.

    Returns True if the file was refreshed, False if it was already fresh.
    On download failure with an existing stale file, keeps the stale copy.
    """
    if path.exists():
        age_hours = (time.time() - path.stat().st_mtime) / 3600.0
        if age_hours < max_age_hours:
            return False

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            response = await client.get(TRICKEST_RESOLVERS_URL)
            response.raise_for_status()
            tmp.write_bytes(response.content)
        tmp.replace(path)
        return True
    except (httpx.HTTPError, OSError):
        tmp.unlink(missing_ok=True)
        if path.exists():
            return False
        raise
