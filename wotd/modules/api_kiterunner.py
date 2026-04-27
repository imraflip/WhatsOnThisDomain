"""Active API route discovery via kiterunner and tRPC probing."""

from __future__ import annotations

import json as json_lib
from typing import Any
from urllib.parse import urlparse

from wotd.modules.base import Module, ModuleResult
from wotd.store import list_api_routes, upsert_api_routes
from wotd.tools import run_tool


class ApiKiterunnerModule(Module):
    name = "api_kiterunner"

    def __init__(
        self,
        session: Any,
        target: Any,
        scope: Any,
        skip_brute: bool = False,
        skip_trpc: bool = False,
        force_trpc: bool = False,
    ):
        super().__init__(session, target, scope)
        self.skip_brute = skip_brute
        self.skip_trpc = skip_trpc
        self.force_trpc = force_trpc

    async def run(self) -> ModuleResult:
        from wotd.store import get_http_service_urls

        # Fetch all live HTTP service URLs for the target
        urls = await get_http_service_urls(self.session, self.target.id)
        if not urls:
            return ModuleResult(
                module=self.name,
                stats={
                    "services_scanned": 0,
                    "scan_new": 0,
                    "brute_new": 0,
                    "trpc_new": 0,
                    "errors": 0,
                },
            )

        routes: list[dict[str, Any]] = []
        errors = 0
        scan_new = 0
        brute_new = 0
        trpc_new = 0

        # Determine if tRPC is present by checking api_routes for trpc_passive source
        trpc_hit_count = 0
        if not self.force_trpc:
            existing = await list_api_routes(
                self.session, self.target.id, source="trpc_passive", limit=None
            )
            trpc_hit_count = len(existing)

        should_run_trpc = self.force_trpc or trpc_hit_count > 0

        for url in urls:
            try:
                scan_routes = await self._run_kr_scan(url)
                for r in scan_routes:
                    host = urlparse(r["url"]).hostname or url.split("/")[2]
                    if not self.scope.is_in_scope(host):
                        continue
                    routes.append({**r, "host": host, "source": "kiterunner"})
                scan_new += len(scan_routes)
            except Exception as e:
                self.logger.error(f"kr scan failed for {url}: {e}")
                errors += 1

            if not self.skip_brute:
                try:
                    brute_routes = await self._run_kr_brute(url)
                    for r in brute_routes:
                        host = urlparse(r["url"]).hostname or url.split("/")[2]
                        if not self.scope.is_in_scope(host):
                            continue
                        routes.append({**r, "host": host, "source": "kiterunner_brute"})
                    brute_new += len(brute_routes)
                except Exception as e:
                    self.logger.error(f"kr brute failed for {url}: {e}")
                    errors += 1

            if should_run_trpc and not self.skip_trpc:
                try:
                    trpc_routes = await self._run_trpc_probe(url)
                    for r in trpc_routes:
                        host = urlparse(r["url"]).hostname or url.split("/")[2]
                        if not self.scope.is_in_scope(host):
                            continue
                        routes.append({**r, "host": host, "source": "trpc_active"})
                    trpc_new += len(trpc_routes)
                except Exception as e:
                    self.logger.error(f"tRPC probe failed for {url}: {e}")
                    errors += 1

        new_count, existing_count, new_keys = await upsert_api_routes(
            self.session, self.target.id, routes
        )

        return ModuleResult(
            module=self.name,
            stats={
                "services_scanned": len(urls),
                "scan_new": scan_new,
                "brute_new": brute_new,
                "trpc_new": trpc_new,
                "errors": errors,
                "routes_upserted": new_count,
                "new_keys": new_keys,
            },
        )

    async def _run_kr_scan(self, url: str) -> list[dict[str, Any]]:
        """Run kr scan (method-aware, primary pass)."""
        cmd = [
            "kr",
            "scan",
            url,
            "-w",
            "/opt/wotd/wordlists/routes-large.kite",
            "--json",
            "-x",
            "20",
            "--ignore-length",
            "34",
            "-q",
        ]
        output = await run_tool(cmd, timeout=300, binary_check=True)

        routes: list[dict[str, Any]] = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                item = json_lib.loads(line)
                req = item.get("Request", {})
                path = req.get("Path", "")
                method = req.get("Method", "GET")
                status_code = item.get("StatusCode")
                if path:
                    routes.append(
                        {
                            "url": url.rstrip("/") + path,
                            "method": method,
                            "status_code": status_code,
                            "content_type": None,
                        }
                    )
            except (json_lib.JSONDecodeError, ValueError):
                continue

        return routes

    async def _run_kr_brute(self, url: str) -> list[dict[str, Any]]:
        """Run kr brute (path-only, secondary pass)."""
        cmd = [
            "kr",
            "brute",
            url,
            "-w",
            "/opt/wotd/wordlists/api_routes.txt",
            "--json",
            "-x",
            "20",
            "-d",
            "0",
            "-q",
        ]
        output = await run_tool(cmd, timeout=300, binary_check=True)

        routes: list[dict[str, Any]] = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                item = json_lib.loads(line)
                req = item.get("Request", {})
                path = req.get("Path", "")
                method = req.get("Method", "GET")
                status_code = item.get("StatusCode")
                if path:
                    routes.append(
                        {
                            "url": url.rstrip("/") + path,
                            "method": method,
                            "status_code": status_code,
                            "content_type": None,
                        }
                    )
            except (json_lib.JSONDecodeError, ValueError):
                continue

        return routes

    async def _run_trpc_probe(self, url: str) -> list[dict[str, Any]]:
        """Run tRPC active probe via ffuf."""
        cmd = [
            "ffuf",
            "-u",
            url.rstrip("/") + "/FUZZ",
            "-w",
            "/opt/wotd/wordlists/trpc_paths.txt",
            "-X",
            "POST",
            "-d",
            '{"input":{}}',
            "-H",
            "Content-Type: application/json",
            "-mc",
            "200,400",
            "-fc",
            "404",
            "-json",
            "-t",
            "30",
        ]
        output = await run_tool(cmd, timeout=300, binary_check=True)

        routes: list[dict[str, Any]] = []
        try:
            data = json_lib.loads(output)
            for result in data.get("results", []):
                url_str = result.get("url", "")
                status = result.get("status", 400)
                if url_str:
                    routes.append(
                        {
                            "url": url_str,
                            "method": "POST",
                            "status_code": status,
                            "content_type": None,
                        }
                    )
        except (json_lib.JSONDecodeError, ValueError):
            pass

        return routes
