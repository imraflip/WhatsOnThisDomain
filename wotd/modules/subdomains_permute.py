"""Subdomain permutation via alterx with resumable candidate resolution."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.parsers import normalize_hosts, parse_jsonl, parse_lines
from wotd.scope import Scope
from wotd.store import (
    count_pending_subdomain_candidates,
    get_pending_subdomain_candidates,
    get_subdomain_hosts,
    update_subdomain_candidate_statuses,
    upsert_dns_records,
    upsert_subdomain_candidates,
    upsert_subdomains,
)
from wotd.tools import ToolNotFoundError, ToolTimeoutError, run_tool
from wotd.utils.resolvers import ensure_resolvers_fresh
from wotd.orchestrator import ModuleContext, dispatcher
from wotd.tasks import DomainTask, HostnameTask, Task

DEFAULT_RESOLVERS = "/opt/wotd/resolvers.txt"


@dataclass(frozen=True)
class _PermutationProfile:
    generation_chunk_size: int
    resolution_chunk_size: int
    enrich: bool


_PROFILES: dict[str, _PermutationProfile] = {
    "quick": _PermutationProfile(
        generation_chunk_size=250,
        resolution_chunk_size=250,
        enrich=False,
    ),
    "balanced": _PermutationProfile(
        generation_chunk_size=750,
        resolution_chunk_size=500,
        enrich=True,
    ),
    "deep": _PermutationProfile(
        generation_chunk_size=1500,
        resolution_chunk_size=1000,
        enrich=True,
    ),
}


def _extract_resolved_records(entry: dict[str, object]) -> list[tuple[str, str, str]]:
    host = entry.get("host")
    if not isinstance(host, str):
        return []

    records: list[tuple[str, str, str]] = []
    for key in ("a", "aaaa", "cname"):
        values = entry.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value:
                records.append((host, key.upper(), value))
    return records


class SubdomainsPermuteModule(Module):
    name = "subdomains_permute"

    def __init__(
        self,
        session: AsyncSession,
        target: Target,
        scope: Scope,
        mode: str,
        max_candidates: int,
        budget_minutes: int,
        resolvers_path: str = DEFAULT_RESOLVERS,
        task: object | None = None,
    ) -> None:
        super().__init__(session, target, scope, task=task)
        self.mode = mode
        self.max_candidates = max_candidates
        self.budget_minutes = budget_minutes
        self.resolvers_path = resolvers_path
        self.profile = _PROFILES[mode]
        self.generator = f"alterx:{mode}"

    async def _generate_candidates(
        self,
        seeds: list[str],
        deadline: datetime,
    ) -> tuple[int, int, int, int, list[str], list[str], dict[str, str]]:
        generated_batches = 0
        generated_seen: set[str] = set()
        generated_in_scope = 0
        inserted_new = 0
        inserted_existing = 0
        new_candidates: list[str] = []
        existing_hosts = set(seeds)
        errors: dict[str, str] = {}

        total_batches = math.ceil(len(seeds) / self.profile.generation_chunk_size)
        for batch_index in range(total_batches):
            if len(generated_seen) >= self.max_candidates or datetime.now(UTC) >= deadline:
                break

            start = batch_index * self.profile.generation_chunk_size
            batch = seeds[start : start + self.profile.generation_chunk_size]
            args = ["-silent", "-limit", str(max(self.max_candidates - len(generated_seen), 1))]
            if self.profile.enrich:
                args.append("-enrich")

            try:
                result = await run_tool(
                    "alterx",
                    args,
                    stdin_data="\n".join(batch) + "\n",
                    timeout=max(60.0, self.budget_minutes * 60.0),
                )
            except ToolNotFoundError:
                errors["alterx"] = "not installed"
                break
            except ToolTimeoutError as exc:
                errors[f"alterx_batch_{batch_index + 1}"] = str(exc)
                continue
            except Exception as exc:
                errors[f"alterx_batch_{batch_index + 1}"] = str(exc)
                continue

            generated_batches += 1
            candidates: list[dict[str, str]] = []
            for fqdn in normalize_hosts(parse_lines(result.stdout)):
                if fqdn in existing_hosts or fqdn in generated_seen:
                    continue
                generated_seen.add(fqdn)
                if not self.scope.is_in_scope(fqdn):
                    continue
                generated_in_scope += 1
                candidates.append(
                    {
                        "fqdn": fqdn,
                        "source": "alterx",
                        "generator": self.generator,
                        "status": "generated",
                    }
                )
                if len(generated_seen) >= self.max_candidates:
                    break

            new_count, existing_count, new_fqdns = await upsert_subdomain_candidates(
                self.session, self.target.id, candidates
            )
            inserted_new += new_count
            inserted_existing += existing_count
            new_candidates.extend(new_fqdns)

        return (
            generated_batches,
            len(generated_seen),
            generated_in_scope,
            inserted_new,
            new_candidates,
            sorted(generated_seen),
            errors,
        )

    async def _resolve_candidates(
        self,
        deadline: datetime,
    ) -> tuple[int, int, int, int, int, list[str], dict[str, str]]:
        errors: dict[str, str] = {}
        resolved_this_run = 0
        unresolved_this_run = 0
        resolution_chunks = 0
        new_subdomains = 0
        existing_subdomains = 0
        new_hosts: list[str] = []

        try:
            await ensure_resolvers_fresh(path=Path(self.resolvers_path))
        except Exception as exc:
            errors["resolvers"] = str(exc)
            return (0, 0, 0, 0, 0, [], errors)

        while datetime.now(UTC) < deadline:
            batch = await get_pending_subdomain_candidates(
                self.session,
                self.target.id,
                self.generator,
                self.profile.resolution_chunk_size,
            )
            if not batch:
                break

            resolution_chunks += 1
            try:
                result = await run_tool(
                    "dnsx",
                    ["-a", "-aaaa", "-cname", "-resp", "-silent", "-json", "-t", "500"],
                    stdin_data="\n".join(batch) + "\n",
                    timeout=1800.0,
                )
            except ToolNotFoundError:
                errors["dnsx"] = "not installed"
                break
            except ToolTimeoutError as exc:
                errors[f"dnsx_chunk_{resolution_chunks}"] = str(exc)
                break
            except Exception as exc:
                errors[f"dnsx_chunk_{resolution_chunks}"] = str(exc)
                break

            records: list[tuple[str, str, str]] = []
            resolved_hosts: set[str] = set()
            for entry in parse_jsonl(result.stdout):
                extracted = _extract_resolved_records(entry)
                if extracted:
                    resolved_hosts.add(extracted[0][0])
                    records.extend(extracted)

            unresolved_hosts = [host for host in batch if host not in resolved_hosts]
            now = datetime.now(UTC)
            await upsert_dns_records(self.session, self.target.id, records)
            if resolved_hosts:
                await update_subdomain_candidate_statuses(
                    self.session,
                    self.target.id,
                    self.generator,
                    sorted(resolved_hosts),
                    status="resolved",
                    resolved_at=now,
                )
            if unresolved_hosts:
                await update_subdomain_candidate_statuses(
                    self.session,
                    self.target.id,
                    self.generator,
                    unresolved_hosts,
                    status="unresolved",
                    resolved_at=None,
                )

            host_to_sources = {host: {"alterx"} for host in sorted(resolved_hosts)}
            new_count, existing_count, new_host_rows = await upsert_subdomains(
                self.session,
                self.target.id,
                host_to_sources,
            )
            resolved_this_run += len(resolved_hosts)
            unresolved_this_run += len(unresolved_hosts)
            new_subdomains += new_count
            existing_subdomains += existing_count
            new_hosts.extend(new_host_rows)

        pending_remaining = await count_pending_subdomain_candidates(
            self.session,
            self.target.id,
            self.generator,
        )
        return (
            resolution_chunks,
            resolved_this_run,
            unresolved_this_run,
            new_subdomains,
            existing_subdomains,
            new_hosts,
            {"pending_remaining": str(pending_remaining), **errors},
        )

    async def run(self) -> ModuleResult:
        seeds = normalize_hosts(await get_subdomain_hosts(self.session, self.target.id))
        if not seeds:
            return ModuleResult(
                module=self.name,
                stats={
                    "mode": self.mode,
                    "seed_hosts": 0,
                    "generated": 0,
                    "resolved": 0,
                    "new": 0,
                    "existing": 0,
                    "errors": {},
                },
            )

        deadline = datetime.now(UTC) + timedelta(minutes=self.budget_minutes)
        pending_before = await count_pending_subdomain_candidates(
            self.session,
            self.target.id,
            self.generator,
        )
        (
            generation_batches,
            generated_total,
            generated_in_scope,
            candidate_new,
            new_candidates,
            _generated_hosts,
            generation_errors,
        ) = await self._generate_candidates(seeds, deadline)
        (
            resolution_chunks,
            resolved_total,
            unresolved_total,
            subdomain_new,
            subdomain_existing,
            new_hosts,
            resolution_errors,
        ) = await self._resolve_candidates(deadline)

        errors = {**generation_errors, **resolution_errors}
        pending_remaining = int(resolution_errors.get("pending_remaining", "0"))
        errors.pop("pending_remaining", None)

        return ModuleResult(
            module=self.name,
            stats={
                "mode": self.mode,
                "seed_hosts": len(seeds),
                "pending_before": pending_before,
                "generation_batches": generation_batches,
                "resolution_chunks": resolution_chunks,
                "generated": generated_total,
                "generated_in_scope": generated_in_scope,
                "candidate_new": candidate_new,
                "resolved": resolved_total,
                "unresolved": unresolved_total,
                "pending_remaining": pending_remaining,
                "new": subdomain_new,
                "existing": subdomain_existing,
                "new_hosts": new_hosts,
                "new_candidates": new_candidates,
                "errors": errors,
            },
        )


@dispatcher.register(DomainTask, module_name=SubdomainsPermuteModule.name)
async def handle_domain_permute(task: DomainTask, ctx: ModuleContext) -> list[Task]:
    module = SubdomainsPermuteModule(
        ctx.session,
        ctx.target,
        ctx.scope,
        mode="balanced",
        max_candidates=20000,
        budget_minutes=30,
        task=task,
    )
    result = await ctx.run_module(module)
    new_hosts = result.stats.get("new_hosts", [])
    return [
        HostnameTask(fqdn=host, parent_task_id=task.id, source_module=module.name)
        for host in new_hosts
    ]

