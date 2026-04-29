"""GraphQL endpoint detection, introspection, and fingerprinting."""

from __future__ import annotations

import json as json_lib
from typing import Any
from urllib.parse import urlparse

from wotd.modules.base import Module, ModuleResult
from wotd.store import upsert_api_routes, upsert_graphql_endpoints
from wotd.tools import run_tool
from wotd.orchestrator import ModuleContext, dispatcher
from wotd.tasks import ApiRouteTask, Task, UrlTask


class ApiGraphqlModule(Module):
    name = "api_graphql"

    async def run(self) -> ModuleResult:
        from wotd.store import get_http_service_urls

        urls = await get_http_service_urls(self.session, self.target.id)
        if not urls:
            return ModuleResult(
                module=self.name,
                stats={
                    "candidates_found": 0,
                    "introspection_enabled": 0,
                    "introspection_blocked": 0,
                    "routes_extracted": 0,
                    "errors": 0,
                },
            )

        candidates_found = 0
        introspection_enabled_count = 0
        introspection_blocked_count = 0
        routes_extracted = 0
        errors = 0
        graphql_endpoints: list[dict[str, Any]] = []
        routes: list[dict[str, Any]] = []

        for url in urls:
            try:
                # Phase 1: Detection via ffuf
                detected = await self._detect_graphql_endpoints(url)
                candidates_found += len(detected)

                for gql_url in detected:
                    host = urlparse(gql_url).hostname or url.split("/")[2]
                    if not self.scope.is_in_scope(host):
                        continue

                    endpoint_data: dict[str, Any] = {
                        "url": gql_url,
                        "host": host,
                        "introspection_enabled": False,
                        "server_type": None,
                        "schema_json": None,
                    }

                    # Phase 2: Introspection
                    introspection_result = await self._introspect(gql_url)
                    if introspection_result["enabled"]:
                        endpoint_data["introspection_enabled"] = True
                        endpoint_data["schema_json"] = introspection_result.get("schema")
                        introspection_enabled_count += 1

                        # Extract routes from introspection schema
                        if introspection_result.get("schema"):
                            extracted = await self._extract_routes_from_introspection(
                                gql_url, introspection_result["schema"], host
                            )
                            routes.extend(extracted)
                            routes_extracted += len(extracted)
                    elif introspection_result.get("blocked"):
                        introspection_blocked_count += 1

                    # Phase 3: Fingerprinting
                    try:
                        server_type = await self._fingerprint_server(gql_url)
                        if server_type:
                            endpoint_data["server_type"] = server_type
                    except Exception as e:
                        self.logger.debug(f"graphw00f fingerprinting failed for {gql_url}: {e}")

                    graphql_endpoints.append(endpoint_data)

            except Exception as e:
                self.logger.error(f"GraphQL detection failed for {url}: {e}")
                errors += 1

        # Upsert GraphQL endpoints
        gql_new, gql_existing, gql_urls = await upsert_graphql_endpoints(
            self.session, self.target.id, graphql_endpoints
        )

        # Upsert extracted routes
        routes_new, routes_existing, route_keys = await upsert_api_routes(
            self.session, self.target.id, routes
        )

        return ModuleResult(
            module=self.name,
            stats={
                "candidates_found": candidates_found,
                "introspection_enabled": introspection_enabled_count,
                "introspection_blocked": introspection_blocked_count,
                "routes_extracted": routes_extracted,
                "errors": errors,
                "graphql_endpoints_new": gql_new,
                "routes_new": routes_new,
                "new_urls": gql_urls,
                "new_route_keys": route_keys,
            },
        )


@dispatcher.register(UrlTask, module_name=ApiGraphqlModule.name)
async def handle_url_api_graphql(task: UrlTask, ctx: ModuleContext) -> list[Task]:
    module = ApiGraphqlModule(ctx.session, ctx.target, ctx.scope, task=task)
    result = await ctx.run_module(module)
    route_keys = result.stats.get("new_route_keys", [])
    output: list[Task] = []
    for key in route_keys:
        if not isinstance(key, str):
            continue
        parts = key.split(" ", 1)
        if len(parts) != 2:
            continue
        method, url = parts
        output.append(
            ApiRouteTask(
                url=url,
                method=method,
                parent_task_id=task.id,
                source_module=module.name,
            )
        )
    return output

    async def _detect_graphql_endpoints(self, base_url: str) -> list[str]:
        """Phase 1: Detect GraphQL endpoints via ffuf + probe."""
        endpoints: list[str] = []

        # First, use ffuf with graphql_paths.txt to find candidates
        cmd = [
            "ffuf",
            "-u",
            base_url.rstrip("/") + "/FUZZ",
            "-w",
            "/opt/wotd/wordlists/graphql_paths.txt",
            "-mc",
            "200,201,400",
            "-json",
            "-t",
            "20",
            "-s",  # silent
        ]

        try:
            output = await run_tool(cmd, timeout=120, binary_check=True)
            try:
                data = json_lib.loads(output)
                for result in data.get("results", []):
                    candidate_url = result.get("url", "")
                    if candidate_url:
                        endpoints.append(candidate_url)
            except (json_lib.JSONDecodeError, ValueError):
                pass
        except Exception as e:
            self.logger.debug(f"ffuf GraphQL detection failed: {e}")

        # Manual probe of potential endpoints to reduce false positives
        confirmed: list[str] = []
        for endpoint in endpoints:
            try:
                if await self._manual_graphql_probe(endpoint):
                    confirmed.append(endpoint)
            except Exception:
                pass

        return confirmed

    async def _manual_graphql_probe(self, url: str) -> bool:
        """Manual POST probe to confirm GraphQL endpoint."""
        cmd = [
            "curl",
            "-s",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            '{"query":"{ __typename }"}',
            url,
        ]

        try:
            output = await run_tool(cmd, timeout=10, binary_check=False)
            # Successful GraphQL endpoints return JSON (even if it's an error about introspection)
            try:
                json_lib.loads(output)
                # Check if response contains GraphQL-specific structure
                return "data" in output or "errors" in output
            except (json_lib.JSONDecodeError, ValueError):
                return False
        except Exception:
            return False

    async def _introspect(self, url: str) -> dict[str, Any]:
        """Phase 2: Try to introspect the GraphQL schema."""
        introspection_query = (
            '{"query":"{ __schema { queryType { name } mutationType { name } '
            "subscriptionType { name } types { name kind fields { name type { name kind ofType "
            '{ name kind } } args { name } } } } }"}'
        )

        cmd = [
            "curl",
            "-s",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            introspection_query,
            url,
        ]

        try:
            output = await run_tool(cmd, timeout=10, binary_check=False)
            data = json_lib.loads(output)

            # Check if introspection succeeded
            if "data" in data and data["data"].get("__schema"):
                return {
                    "enabled": True,
                    "schema": output,
                }

            # Check if introspection is blocked
            if "errors" in data:
                for err in data["errors"]:
                    if "introspection" in str(err).lower():
                        return {"blocked": True, "enabled": False}

            return {"enabled": False}
        except Exception as e:
            self.logger.debug(f"Introspection failed for {url}: {e}")
            return {"enabled": False}

    async def _extract_routes_from_introspection(
        self, url: str, schema_json: str, host: str
    ) -> list[dict[str, Any]]:
        """Extract API routes from introspection schema."""
        routes: list[dict[str, Any]] = []

        try:
            schema = json_lib.loads(schema_json)
            schema_data = schema.get("data", {})
            schema_obj = schema_data.get("__schema", {})

            # Extract Query type fields
            query_type = schema_obj.get("queryType", {})
            if query_type:
                for field in query_type.get("fields", []):
                    field_name = field.get("name")
                    if field_name:
                        routes.append(
                            {
                                "url": url,
                                "host": host,
                                "method": "POST",
                                "status_code": 200,
                                "content_type": "application/json",
                                "source": "graphql_introspection",
                                "spec_url": None,
                            }
                        )

            # Extract Mutation type fields
            mutation_type = schema_obj.get("mutationType", {})
            if mutation_type:
                for field in mutation_type.get("fields", []):
                    field_name = field.get("name")
                    if field_name:
                        routes.append(
                            {
                                "url": url,
                                "host": host,
                                "method": "POST",
                                "status_code": 200,
                                "content_type": "application/json",
                                "source": "graphql_introspection",
                                "spec_url": None,
                            }
                        )
        except Exception as e:
            self.logger.debug(f"Failed to extract routes from introspection: {e}")

        return routes

    async def _fingerprint_server(self, url: str) -> str | None:
        """Phase 3: Fingerprint GraphQL server implementation via graphw00f."""
        cmd = [
            "graphw00f",
            "-t",
            url,
            "-d",
            "-f",
            "json",
        ]

        try:
            output = await run_tool(cmd, timeout=30, binary_check=True)
            data = json_lib.loads(output)
            engine = data.get("engine")
            if engine:
                return engine
        except Exception as e:
            self.logger.debug(f"graphw00f fingerprinting failed: {e}")

        return None
