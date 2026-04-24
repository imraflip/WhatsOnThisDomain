"""JS file collection and endpoint extraction via subjs, getjs, jsluice, and gf."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.parsers import parse_lines
from wotd.scope import Scope
from wotd.store import (
    get_http_service_urls,
    get_js_file_urls,
    get_js_urls_from_endpoints,
    upsert_js_endpoints,
    upsert_js_files,
    upsert_js_secrets,
)
from wotd.tools import ToolNotFoundError, run_gf, run_tool

_JSLUICE_CONCURRENCY = 10
_WORDLIST_JS = "/opt/wotd/wordlists/httparchive_js.txt"

_GF_JS_PATTERNS: tuple[str, ...] = (
    "aws-keys",
    "s3-buckets",
    "firebase",
    "base64",
    "generic-api-key",
    "json-sec",
    "php-errors",
)


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


async def _fetch_js(js_url: str) -> str:
    """Fetch a JS file with curl and return its content."""
    curl = await run_tool(
        "curl",
        ["-s", "--max-time", "15", "--", js_url],
        timeout=20.0,
    )
    return curl.stdout


async def _jsluice_urls(js_url: str, content: str) -> list[dict[str, Any]]:
    """Extract URLs from already-fetched JS content via jsluice."""
    if not content.strip():
        return []
    jsluice = await run_tool(
        "jsluice",
        ["urls", "-R", js_url],
        stdin_data=content,
        timeout=30.0,
    )
    out: list[dict[str, Any]] = []
    for line in parse_lines(jsluice.stdout):
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


async def _jsluice_secrets(content: str) -> list[dict[str, Any]]:
    """Extract secrets from already-fetched JS content via jsluice."""
    if not content.strip():
        return []
    jsluice = await run_tool(
        "jsluice",
        ["secrets"],
        stdin_data=content,
        timeout=30.0,
    )
    out: list[dict[str, Any]] = []
    for line in parse_lines(jsluice.stdout):
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


async def _ffuf_js_pass(base_url: str) -> list[str]:
    """Discover JS files on base_url via ffuf bruteforce."""
    result = await run_tool(
        "ffuf",
        [
            "-u", f"{base_url}/FUZZ",
            "-w", _WORDLIST_JS,
            "-rate", "150",
            "-t", "50",
            "-mc", "200,204",
            "-json",
        ],
        timeout=None,
    )
    urls = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url", "")
        if url:
            urls.append(url)
    return urls


async def _gf_js_content(js_url: str, content: str) -> list[dict[str, Any]]:
    """Run gf secret patterns against already-fetched JS content."""
    if not content.strip():
        return []
    lines = [line for line in content.splitlines() if line.strip()]
    if not lines:
        return []
    pattern_results = await asyncio.gather(
        *[run_gf(p, lines) for p in _GF_JS_PATTERNS],
        return_exceptions=True,
    )
    findings: list[dict[str, Any]] = []
    for pattern, res in zip(_GF_JS_PATTERNS, pattern_results, strict=True):
        if isinstance(res, BaseException):
            continue
        for match in res:
            match = match.strip()
            if match:
                findings.append(
                    {
                        "source_js_url": js_url,
                        "kind": f"gf:{pattern}",
                        "data": json.dumps(match),
                        "severity": None,
                        "context": None,
                    }
                )
    return findings


class JsDiscoveryModule(Module):
    name = "js_discovery"

    def __init__(
        self,
        session: AsyncSession,
        target: Target,
        scope: Scope,
        seed_urls: list[str] | None = None,
        bruteforce_js: bool = False,
    ) -> None:
        super().__init__(session, target, scope)
        self.seed_urls = seed_urls or []
        self.bruteforce_js = bruteforce_js

    async def run(self) -> ModuleResult:
        url_to_sources: dict[str, set[str]] = {}
        errors: dict[str, str] = {}

        for url in await get_js_urls_from_endpoints(self.session, self.target.id):
            url_to_sources.setdefault(url, set()).add("endpoints")

        if self.seed_urls:
            try:
                for url in await _run_subjs(self.seed_urls):
                    url_to_sources.setdefault(url, set()).add("subjs")
            except ToolNotFoundError:
                errors["subjs"] = "not installed"

            try:
                for url in await _run_getjs(self.seed_urls):
                    url_to_sources.setdefault(url, set()).add("getjs")
            except ToolNotFoundError:
                errors["getjs"] = "not installed"

        if self.bruteforce_js:
            svc_urls = await get_http_service_urls(self.session, self.target.id)
            base_urls: set[str] = set()
            for svc_url in svc_urls:
                parsed = urlparse(svc_url)
                if parsed.scheme and parsed.hostname:
                    base_urls.add(f"{parsed.scheme}://{parsed.hostname}")
            for base_url in sorted(base_urls):
                for url in await _ffuf_js_pass(base_url):
                    url_to_sources.setdefault(url, set()).add("ffuf")

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

        new_js, existing_js, new_js_urls = await upsert_js_files(
            self.session, self.target.id, files
        )

        all_js_urls = await get_js_file_urls(self.session, self.target.id)
        sem = asyncio.Semaphore(_JSLUICE_CONCURRENCY)

        async def _process(
            js_url: str,
        ) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
            async with sem:
                try:
                    content = await _fetch_js(js_url)
                    urls_out, secrets_out, gf_out = await asyncio.gather(
                        _jsluice_urls(js_url, content),
                        _jsluice_secrets(content),
                        _gf_js_content(js_url, content),
                    )
                    return js_url, urls_out, secrets_out, gf_out
                except Exception:
                    return js_url, [], [], []

        js_results = await asyncio.gather(*[_process(u) for u in all_js_urls])

        endpoint_dicts: list[dict[str, Any]] = []
        secret_dicts: list[dict[str, Any]] = []

        for js_url, url_items, secret_items, gf_items in js_results:
            for item in url_items:
                raw_url = item.get("url", "")
                if not raw_url:
                    continue
                host = urlparse(raw_url).hostname or ""
                if not host or not self.scope.is_in_scope(host):
                    continue
                query_params = item.get("queryParams") or []
                body_params = item.get("bodyParams") or []
                all_params = query_params + body_params
                endpoint_dicts.append(
                    {
                        "url": raw_url,
                        "host": host,
                        "method": item.get("method") or None,
                        "params": json.dumps(all_params) if all_params else None,
                        "source_js_url": js_url,
                    }
                )

            for item in secret_items:
                kind = item.get("kind", "")
                data = item.get("data")
                if not kind or data is None:
                    continue
                secret_dicts.append(
                    {
                        "source_js_url": js_url,
                        "kind": kind,
                        "data": json.dumps(data, sort_keys=True),
                        "severity": item.get("severity"),
                        "context": json.dumps(item["context"]) if item.get("context") else None,
                    }
                )

            secret_dicts.extend(gf_items)

        new_ep, existing_ep, new_ep_urls = await upsert_js_endpoints(
            self.session, self.target.id, endpoint_dicts
        )
        new_sec, existing_sec = await upsert_js_secrets(
            self.session, self.target.id, secret_dicts
        )

        stats: dict[str, object] = {
            "js_files_total": len(url_to_sources),
            "js_files_in_scope": len(in_scope),
            "js_files_new": new_js,
            "js_files_existing": existing_js,
            "js_endpoints_new": new_ep,
            "js_endpoints_existing": existing_ep,
            "js_secrets_new": new_sec,
            "js_secrets_existing": existing_sec,
            "new_js_urls": new_js_urls,
            "new_ep_urls": new_ep_urls,
        }
        if errors:
            stats["errors"] = errors
        return ModuleResult(module=self.name, stats=stats)
