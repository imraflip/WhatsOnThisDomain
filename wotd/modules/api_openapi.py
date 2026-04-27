"""OpenAPI/Swagger spec harvesting and route extraction."""

from __future__ import annotations

import json as json_lib
from typing import Any
from urllib.parse import urlparse

import yaml

from wotd.modules.base import Module, ModuleResult
from wotd.store import upsert_api_routes, upsert_api_specs
from wotd.tools import run_tool


class ApiOpenApiModule(Module):
    name = "api_openapi"

    async def run(self) -> ModuleResult:
        from wotd.store import get_http_service_urls

        urls = await get_http_service_urls(self.session, self.target.id)
        if not urls:
            return ModuleResult(
                module=self.name,
                stats={
                    "candidates_found": 0,
                    "specs_valid": 0,
                    "routes_new": 0,
                    "routes_existing": 0,
                    "sj_extra_routes": 0,
                    "errors": 0,
                },
            )

        candidates_found = 0
        specs_valid = 0
        sj_extra_routes = 0
        errors = 0
        specs: list[dict[str, Any]] = []
        routes: list[dict[str, Any]] = []

        for url in urls:
            try:
                # Step 1: Discovery via ffuf
                spec_urls = await self._discover_specs(url)
                candidates_found += len(spec_urls)

                for spec_url in spec_urls:
                    host = urlparse(spec_url).hostname or url.split("/")[2]
                    if not self.scope.is_in_scope(host):
                        continue

                    # Step 2: Validation
                    spec_data = await self._validate_spec(spec_url)
                    if not spec_data:
                        continue
                    specs_valid += 1

                    # Step 3: Route extraction
                    raw_spec = spec_data.get("raw_spec", "")
                    spec_type = spec_data.get("spec_type", "unknown")
                    routes_count = spec_data.get("routes_count", 0)

                    specs.append(
                        {
                            "url": spec_url,
                            "host": host,
                            "spec_type": spec_type,
                            "routes_count": routes_count,
                            "raw_spec": raw_spec,
                        }
                    )

                    # Extract routes from the spec
                    extracted = await self._extract_routes(spec_url, spec_data, host)
                    routes.extend(extracted)

                    # Step 5: sj cross-validation (if available)
                    try:
                        sj_routes = await self._run_sj(spec_url, host)
                        sj_extra_routes += len(sj_routes)
                        routes.extend(sj_routes)
                    except Exception as e:
                        self.logger.debug(f"sj cross-validation failed: {e}")

            except Exception as e:
                self.logger.error(f"OpenAPI discovery failed for {url}: {e}")
                errors += 1

        # Upsert specs
        specs_new, specs_existing, spec_urls = await upsert_api_specs(
            self.session, self.target.id, specs
        )

        # Upsert routes
        routes_new, routes_existing, route_keys = await upsert_api_routes(
            self.session, self.target.id, routes
        )

        return ModuleResult(
            module=self.name,
            stats={
                "candidates_found": candidates_found,
                "specs_valid": specs_valid,
                "routes_new": routes_new,
                "routes_existing": routes_existing,
                "sj_extra_routes": sj_extra_routes,
                "errors": errors,
                "specs_new": specs_new,
                "new_spec_urls": spec_urls,
            },
        )

    async def _discover_specs(self, base_url: str) -> list[str]:
        """Step 1: Discovery via ffuf with openapi_paths.txt."""
        cmd = [
            "ffuf",
            "-u",
            base_url.rstrip("/") + "/FUZZ",
            "-w",
            "/opt/wotd/wordlists/openapi_paths.txt",
            "-mc",
            "200",
            "-t",
            "20",
            "-json",
            "-s",  # silent
        ]

        specs: list[str] = []
        try:
            output = await run_tool(cmd, timeout=120, binary_check=True)
            try:
                data = json_lib.loads(output)
                for result in data.get("results", []):
                    spec_url = result.get("url", "")
                    content_type = result.get("content-type", "")
                    if spec_url and self._looks_like_spec(content_type):
                        specs.append(spec_url)
            except (json_lib.JSONDecodeError, ValueError):
                pass
        except Exception as e:
            self.logger.debug(f"ffuf OpenAPI discovery failed: {e}")

        return specs

    def _looks_like_spec(self, content_type: str) -> bool:
        """Check if content type looks like OpenAPI spec."""
        return any(
            ct in content_type
            for ct in [
                "application/json",
                "application/yaml",
                "text/yaml",
                "text/plain",
            ]
        )

    async def _validate_spec(self, spec_url: str) -> dict[str, Any] | None:
        """Step 2: Download and validate spec."""
        cmd = ["curl", "-s", spec_url]

        try:
            output = await run_tool(cmd, timeout=10, binary_check=False)
            if not output.strip():
                return None

            # Try JSON parsing first
            try:
                spec = json_lib.loads(output)
            except (json_lib.JSONDecodeError, ValueError):
                # Try YAML parsing
                try:
                    spec = yaml.safe_load(output)
                except Exception:
                    return None

            if not isinstance(spec, dict):
                return None

            # Validate required keys
            if "paths" not in spec:
                return None

            # Determine spec type
            spec_type = "unknown"
            if "openapi" in spec:
                spec_type = "openapi3"
            elif "swagger" in spec:
                spec_type = "openapi2"

            # Count routes
            paths = spec.get("paths", {})
            routes_count = len(paths)

            return {
                "spec_type": spec_type,
                "routes_count": routes_count,
                "raw_spec": output,
                "spec_obj": spec,
            }
        except Exception as e:
            self.logger.debug(f"Spec validation failed for {spec_url}: {e}")
            return None

    async def _extract_routes(
        self, spec_url: str, spec_data: dict[str, Any], host: str
    ) -> list[dict[str, Any]]:
        """Step 3: Extract routes from spec."""
        routes: list[dict[str, Any]] = []
        spec_obj = spec_data.get("spec_obj", {})
        spec_type = spec_data.get("spec_type", "unknown")

        try:
            paths = spec_obj.get("paths", {})
            for path, path_obj in paths.items():
                if not isinstance(path_obj, dict):
                    continue

                # Find all HTTP methods
                for method in ["get", "post", "put", "delete", "patch", "head", "options"]:
                    if method not in path_obj:
                        continue

                    method_obj = path_obj[method]
                    if not isinstance(method_obj, dict):
                        continue

                    # Extract content type if available
                    content_type = None
                    if spec_type == "openapi2":
                        produces = method_obj.get("produces", [])
                        if produces:
                            content_type = produces[0]
                    elif spec_type == "openapi3":
                        responses = method_obj.get("responses", {})
                        for resp_code, resp_obj in responses.items():
                            if resp_code == "200" and isinstance(resp_obj, dict):
                                resp_content = resp_obj.get("content", {})
                                if resp_content:
                                    content_type = list(resp_content.keys())[0]
                                break

                    route_url = spec_url.rstrip("/") + path
                    routes.append(
                        {
                            "url": route_url,
                            "host": host,
                            "method": method.upper(),
                            "status_code": 200,
                            "content_type": content_type,
                            "source": "openapi_spec",
                            "spec_url": spec_url,
                        }
                    )
        except Exception as e:
            self.logger.debug(f"Route extraction failed: {e}")

        return routes

    async def _run_sj(self, spec_url: str, host: str) -> list[dict[str, Any]]:
        """Step 5: sj cross-validation for additional routes."""
        cmd = [
            "sj",
            "endpoints",
            "-u",
            spec_url,
            "-j",
        ]

        routes: list[dict[str, Any]] = []

        try:
            output = await run_tool(cmd, timeout=30, binary_check=True)
            try:
                data = json_lib.loads(output)
                endpoints = data.get("endpoints", [])
                for ep in endpoints:
                    if not isinstance(ep, dict):
                        continue
                    method = ep.get("method", "GET").upper()
                    path = ep.get("path", "")
                    if path:
                        routes.append(
                            {
                                "url": spec_url.rstrip("/") + path,
                                "host": host,
                                "method": method,
                                "status_code": 200,
                                "content_type": None,
                                "source": "sj",
                                "spec_url": spec_url,
                            }
                        )
            except (json_lib.JSONDecodeError, ValueError):
                pass
        except Exception as e:
            self.logger.debug(f"sj execution failed: {e}")

        return routes
