"""Web crawling and endpoint discovery module."""

from __future__ import annotations

import asyncio
import os
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.parsers import normalize_urls, parse_lines
from wotd.scope import Scope
from wotd.store import upsert_endpoints
from wotd.tools import ToolNotFoundError, ToolResult, run_tool

_SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".css", ".scss", ".less",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp", ".tiff",
    ".mp4", ".mp3", ".wav", ".ogg", ".webm", ".avi", ".mov",
})


def _skip_ext(url: str) -> bool:
    _, ext = os.path.splitext(urlparse(url).path.lower())
    return ext in _SKIP_EXTENSIONS


async def _run_gau(domain: str) -> ToolResult:
    return await run_tool(
        "gau",
        ["--subs", domain],
        timeout=None,
    )


async def _run_waymore(domain: str) -> ToolResult:
    return await run_tool(
        "waymore",
        ["-i", domain, "-mode", "U", "-nlf"],
        timeout=None,
    )


async def _run_katana(url: str) -> ToolResult:
    return await run_tool(
        "katana",
        [
            "-u",
            url,
            "-d",
            "5",
            "-jc",
            "-kf",
            "all",
            "-fs",
            "rdn",
            "-silent",
            "-c",
            "50",
            "-rl",
            "300",
        ],
        timeout=None,
    )


async def _run_gospider(url: str) -> ToolResult:
    return await run_tool(
        "gospider",
        ["-s", url, "-d", "3", "-c", "50", "--js", "--sitemap", "--robots", "-q"],
        timeout=None,
    )


async def _run_hakrawler(url: str) -> ToolResult:
    return await run_tool(
        "hakrawler",
        ["-d", "3", "-subs", "-t", "20"],
        stdin_data=url + "\n",
        timeout=None,
    )


class CrawlModule(Module):
    name = "crawl"

    def __init__(self, session: AsyncSession, target: Target, scope: Scope, url: str) -> None:
        super().__init__(session, target, scope)
        self.url = url

    async def run(self) -> ModuleResult:
        parsed = urlparse(self.url)
        domain = parsed.hostname or parsed.netloc

        tasks = {
            "gau": _run_gau(domain),
            "waymore": _run_waymore(domain),
            "katana": _run_katana(self.url),
            "gospider": _run_gospider(self.url),
            "hakrawler": _run_hakrawler(self.url),
        }
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        url_to_sources: dict[str, set[str]] = {}
        per_tool: dict[str, int] = {}
        errors: dict[str, str] = {}

        for tool_name, result in zip(tasks.keys(), results, strict=True):
            if isinstance(result, BaseException):
                errors[tool_name] = (
                    "not installed" if isinstance(result, ToolNotFoundError) else str(result)
                )
                continue
            urls = [u for u in normalize_urls(parse_lines(result.stdout)) if not _skip_ext(u)]
            per_tool[tool_name] = len(urls)
            self._collect(url_to_sources, urls, tool_name)

        in_scope = self._filter_urls(url_to_sources)
        endpoints = [
            {"url": url, "host": urlparse(url).hostname or "", "source": ",".join(sorted(srcs))}
            for url, srcs in in_scope.items()
        ]
        new_count, existing_count, new_urls = await upsert_endpoints(
            self.session, self.target.id, endpoints
        )

        stats: dict[str, object] = {
            "total": len(url_to_sources),
            "in_scope": len(in_scope),
            "new_endpoints": new_count,
            "existing_endpoints": existing_count,
            "new_urls": new_urls,
            **{t: per_tool.get(t, 0) for t in tasks},
        }
        if errors:
            stats["errors"] = errors
        return ModuleResult(module=self.name, stats=stats)

    def _collect(self, url_to_sources: dict[str, set[str]], urls: list[str], source: str) -> None:
        for url in urls:
            url_to_sources.setdefault(url, set()).add(source)

    def _filter_urls(self, url_to_sources: dict[str, set[str]]) -> dict[str, set[str]]:
        result = {}
        for url, sources in url_to_sources.items():
            host = urlparse(url).hostname or ""
            if host and self.scope.is_in_scope(host):
                result[url] = sources
        return result
