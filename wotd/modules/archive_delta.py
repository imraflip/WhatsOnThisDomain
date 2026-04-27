"""Archive delta module — tracks state drift on already-known endpoints."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.scope import Scope
from wotd.store import (
    insert_endpoint_snapshots,
    list_endpoint_deltas,
    list_endpoints,
)
from wotd.tools import run_tool


class ArchiveDeltaModule(Module):
    """Re-probe known endpoints and track state changes.

    Reads all endpoints for a target from the database, re-probes them via httpx-pd,
    stores snapshots of the current state, and generates delta reports for changed fields
    (status, content_type, title, body_hash, unreachable).
    """

    name = "archive_delta"

    def __init__(self, session: AsyncSession, target: Target, scope: Scope) -> None:
        super().__init__(session, target, scope)

    async def _compute_body_hash(self, body: str) -> str:
        """Compute SHA256 hash of response body."""
        return hashlib.sha256(body.encode()).hexdigest()

    async def _probe_endpoints(self, urls: list[str]) -> dict[str, dict[str, Any]]:
        """Probe a list of endpoint URLs via httpx-pd.

        Returns a dict mapping URL to probe result (status, content_type, title, body_hash).
        """
        if not urls:
            return {}

        # Build httpx-pd command.
        # httpx-pd supports -json output with status, content-type, title, body.
        result = await run_tool(
            "httpx-pd",
            [
                "-json",
                "-silent",
                "-timeout",
                "10",
            ],
            input_data="\n".join(urls),
            timeout=None,
        )

        probes: dict[str, dict[str, Any]] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = obj.get("url")
            if not url:
                continue

            body = obj.get("body", "")
            body_hash = await self._compute_body_hash(body) if body else None

            probes[url] = {
                "status_code": obj.get("status_code"),
                "content_type": obj.get("content_type"),
                "title": obj.get("title"),
                "body_hash": body_hash,
            }

        return probes

    async def run(self) -> ModuleResult:
        """Execute the archive delta module.

        1. Read all known endpoints for this target from the database.
        2. Re-probe them via httpx-pd.
        3. Store snapshots of the current state.
        4. Query deltas to generate statistics.
        5. Return stats for the scan run.
        """
        # Read all endpoints for this target
        endpoints = await list_endpoints(
            self.session,
            target_id=self.target.id,
            limit=None,
        )

        if not endpoints:
            return ModuleResult(
                module=self.name,
                stats={
                    "total_endpoints": 0,
                    "snapshots_stored": 0,
                    "deltas_detected": 0,
                },
            )

        urls = [ep.url for ep in endpoints]

        # Re-probe all endpoints
        probes = await self._probe_endpoints(urls)

        # Build snapshot list from probes
        snapshots: list[dict[str, Any]] = []
        for url, probe in probes.items():
            snapshots.append(
                {
                    "url": url,
                    "status_code": probe.get("status_code"),
                    "content_type": probe.get("content_type"),
                    "title": probe.get("title"),
                    "body_hash": probe.get("body_hash"),
                }
            )

        # Scope-check hosts in snapshots before writing
        filtered_snapshots = []
        for snap in snapshots:
            url: str = snap["url"]
            # Extract host from URL
            try:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                host = parsed.hostname or ""
                if host and self.scope.is_in_scope(host):
                    filtered_snapshots.append(snap)
            except Exception:
                pass

        # Store snapshots
        count_stored = await insert_endpoint_snapshots(
            self.session,
            self.target.id,
            filtered_snapshots,
        )

        # Query deltas to count changes
        deltas = await list_endpoint_deltas(
            self.session,
            target_id=self.target.id,
            limit=None,
        )

        # Tally deltas by kind
        delta_counts: dict[str, int] = {}
        for delta in deltas:
            delta_counts[delta.kind] = delta_counts.get(delta.kind, 0) + 1

        return ModuleResult(
            module=self.name,
            stats={
                "total_endpoints": len(endpoints),
                "snapshots_stored": count_stored,
                "deltas_detected": len(deltas),
                "delta_breakdown": delta_counts,
            },
        )
