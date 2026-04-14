"""Mocks httpx here because we're testing the freshness/skip branches,
not the network path. Real network hit happens in module tests."""

from __future__ import annotations

import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from wotd.utils.resolvers import ensure_resolvers_fresh


def _fake_response(content: bytes = b"1.1.1.1\n8.8.8.8\n") -> httpx.Response:
    return httpx.Response(200, content=content, request=httpx.Request("GET", "http://x"))


async def test_downloads_when_missing(tmp_path: Path) -> None:
    target = tmp_path / "resolvers.txt"
    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=_fake_response())):
        refreshed = await ensure_resolvers_fresh(target)
    assert refreshed is True
    assert target.read_bytes() == b"1.1.1.1\n8.8.8.8\n"


async def test_skips_when_fresh(tmp_path: Path) -> None:
    target = tmp_path / "resolvers.txt"
    target.write_bytes(b"cached")
    with patch("httpx.AsyncClient.get", new=AsyncMock()) as mock_get:
        refreshed = await ensure_resolvers_fresh(target, max_age_hours=24)
    assert refreshed is False
    mock_get.assert_not_called()


async def test_refreshes_when_stale(tmp_path: Path) -> None:
    target = tmp_path / "resolvers.txt"
    target.write_bytes(b"old")
    stale_time = time.time() - 48 * 3600
    os.utime(target, (stale_time, stale_time))

    with patch(
        "httpx.AsyncClient.get", new=AsyncMock(return_value=_fake_response(b"new"))
    ):
        refreshed = await ensure_resolvers_fresh(target, max_age_hours=24)
    assert refreshed is True
    assert target.read_bytes() == b"new"


async def test_keeps_stale_on_download_failure(tmp_path: Path) -> None:
    target = tmp_path / "resolvers.txt"
    target.write_bytes(b"stale-but-usable")
    stale_time = time.time() - 48 * 3600
    os.utime(target, (stale_time, stale_time))

    with patch(
        "httpx.AsyncClient.get",
        new=AsyncMock(side_effect=httpx.ConnectError("boom")),
    ):
        refreshed = await ensure_resolvers_fresh(target, max_age_hours=24)
    assert refreshed is False
    assert target.read_bytes() == b"stale-but-usable"


async def test_raises_when_missing_and_download_fails(tmp_path: Path) -> None:
    target = tmp_path / "resolvers.txt"
    with patch(
        "httpx.AsyncClient.get",
        new=AsyncMock(side_effect=httpx.ConnectError("boom")),
    ):
        with pytest.raises(httpx.ConnectError):
            await ensure_resolvers_fresh(target)
    assert not target.exists()
