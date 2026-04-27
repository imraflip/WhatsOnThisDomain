"""Passive API surface extraction from existing endpoints + js_endpoints.

Reads previously discovered URLs and pattern-matches anything that looks like
an API route — `/api/`, `/rest/`, `/rpc/`, `/graphql`, `/v[123]/`, `/trpc/`,
`/.well-known/openapi`, or non-static `*.json`. Upserts matches into api_routes.
No tool runs, no network — purely a database transformation.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from wotd.modules.base import Module, ModuleResult
from wotd.store import list_endpoints, list_js_endpoints, upsert_api_routes

_API_PATH_RE = re.compile(
    r"(?:/api/|/rest/|/rpc/|/graphql|/v[123]/|/api/trpc/|/trpc/|/\.well-known/openapi)"
)
_STATIC_DENY_SUFFIX = (".min.js.map", ".bundle.json")


def _is_api_url(url: str) -> bool:
    try:
        p = urlparse(url)
    except ValueError:
        return False
    path = p.path
    if not path:
        return False
    for suf in _STATIC_DENY_SUFFIX:
        if path.endswith(suf):
            return False
    if _API_PATH_RE.search(path):
        return True
    if path.endswith(".json"):
        return True
    return False


def _is_trpc(url: str) -> bool:
    try:
        p = urlparse(url)
    except ValueError:
        return False
    return "/trpc/" in p.path


class ApiPassiveModule(Module):
    name = "api_passive"

    async def run(self) -> ModuleResult:
        endpoints = await list_endpoints(self.session, self.target.id, limit=None)
        js_endpoints = await list_js_endpoints(self.session, self.target.id, limit=None)

        routes: list[dict[str, Any]] = []
        trpc_hits = 0

        for ep in endpoints:
            if not _is_api_url(ep.url):
                continue
            host = urlparse(ep.url).hostname or ep.host
            if not self.scope.is_in_scope(host):
                continue
            is_trpc = _is_trpc(ep.url)
            if is_trpc:
                trpc_hits += 1
            routes.append(
                {
                    "url": ep.url,
                    "host": host,
                    "method": "GET",
                    "status_code": ep.status_code,
                    "content_type": ep.content_type,
                    "source": "trpc_passive" if is_trpc else "endpoints_passive",
                }
            )

        for jr in js_endpoints:
            if not _is_api_url(jr.url):
                continue
            host = urlparse(jr.url).hostname or jr.host
            if not self.scope.is_in_scope(host):
                continue
            is_trpc = _is_trpc(jr.url)
            if is_trpc:
                trpc_hits += 1
            method = (jr.method or "GET").upper()
            routes.append(
                {
                    "url": jr.url,
                    "host": host,
                    "method": method,
                    "status_code": None,
                    "content_type": None,
                    "source": "trpc_passive" if is_trpc else "js_passive",
                }
            )

        new_count, existing_count, new_keys = await upsert_api_routes(
            self.session, self.target.id, routes
        )

        return ModuleResult(
            module=self.name,
            stats={
                "endpoints_scanned": len(endpoints),
                "js_endpoints_scanned": len(js_endpoints),
                "new_routes": new_count,
                "existing_routes": existing_count,
                "trpc_hits": trpc_hits,
                "new_keys": new_keys,
            },
        )
