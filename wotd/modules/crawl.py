"""Web crawling and endpoint discovery module."""

from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.scope import Scope
from wotd.store import upsert_endpoints


class CrawlModule(Module):
    name = "crawl"

    def __init__(self, session: AsyncSession, target: Target, scope: Scope, url: str) -> None:
        super().__init__(session, target, scope)
        self.url = url

    async def run(self) -> ModuleResult:
        url_to_sources: dict[str, set[str]] = {}

        # Tool runners will be added in M17 and M18.
        # Each will call _collect(results, source_name) below.

        in_scope = self._filter_urls(url_to_sources)
        endpoints = [
            {"url": url, "host": urlparse(url).hostname or "", "source": ",".join(sorted(srcs))}
            for url, srcs in in_scope.items()
        ]
        new_count, existing_count = await upsert_endpoints(
            self.session, self.target.id, endpoints
        )

        return ModuleResult(
            module=self.name,
            stats={
                "total": len(url_to_sources),
                "in_scope": len(in_scope),
                "new_endpoints": new_count,
                "existing_endpoints": existing_count,
            },
        )

    def _collect(
        self, url_to_sources: dict[str, set[str]], urls: list[str], source: str
    ) -> None:
        for url in urls:
            url_to_sources.setdefault(url, set()).add(source)

    def _filter_urls(
        self, url_to_sources: dict[str, set[str]]
    ) -> dict[str, set[str]]:
        result = {}
        for url, sources in url_to_sources.items():
            host = urlparse(url).hostname or ""
            if host and self.scope.is_in_scope(host):
                result[url] = sources
        return result
