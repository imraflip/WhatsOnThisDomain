"""JS file collection — pulls .js URLs from endpoints table, subjs, and getjs."""

from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.parsers import parse_lines
from wotd.scope import Scope
from wotd.store import (
    get_http_service_urls,
    get_js_urls_from_endpoints,
    upsert_js_files,
)
from wotd.tools import ToolNotFoundError, run_tool


async def _run_subjs(urls: list[str]) -> list[str]:
    result = await run_tool(
        "subjs",
        ["-c", "40"],
        stdin_data="\n".join(urls) + "\n",
        timeout=300.0,
    )
    return parse_lines(result.stdout)


async def _run_getjs(urls: list[str]) -> list[str]:
    result = await run_tool(
        "getjs",
        [],
        stdin_data="\n".join(urls) + "\n",
        timeout=300.0,
    )
    return parse_lines(result.stdout)


class JsDiscoveryModule(Module):
    name = "js_discovery"

    def __init__(
        self,
        session: AsyncSession,
        target: Target,
        scope: Scope,
        seed_urls: list[str] | None = None,
    ) -> None:
        super().__init__(session, target, scope)
        self.seed_urls = seed_urls or []

    async def run(self) -> ModuleResult:
        url_to_sources: dict[str, set[str]] = {}
        errors: dict[str, str] = {}

        for url in await get_js_urls_from_endpoints(self.session, self.target.id):
            url_to_sources.setdefault(url, set()).add("endpoints")

        db_service_urls = await get_http_service_urls(self.session, self.target.id)
        all_seed_urls = list(dict.fromkeys(db_service_urls + self.seed_urls))

        if all_seed_urls:
            try:
                for url in await _run_subjs(all_seed_urls):
                    url_to_sources.setdefault(url, set()).add("subjs")
            except ToolNotFoundError:
                errors["subjs"] = "not installed"

            try:
                for url in await _run_getjs(all_seed_urls):
                    url_to_sources.setdefault(url, set()).add("getjs")
            except ToolNotFoundError:
                errors["getjs"] = "not installed"

        in_scope: dict[str, set[str]] = {}
        for url, sources in url_to_sources.items():
            host = urlparse(url).hostname or ""
            if host and self.scope.is_in_scope(host):
                in_scope[url] = sources

        files = [
            {
                "url": url,
                "host": urlparse(url).hostname or "",
                "sources": ",".join(sorted(srcs)),
            }
            for url, srcs in in_scope.items()
        ]

        new_count, existing_count, new_urls = await upsert_js_files(
            self.session, self.target.id, files
        )

        stats: dict[str, object] = {
            "total": len(url_to_sources),
            "in_scope": len(in_scope),
            "new": new_count,
            "existing": existing_count,
            "new_urls": new_urls,
        }
        if errors:
            stats["errors"] = errors
        return ModuleResult(module=self.name, stats=stats)
