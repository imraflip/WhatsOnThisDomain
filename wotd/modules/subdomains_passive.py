"""Passive subdomain enumeration using subfinder and assetfinder."""

from __future__ import annotations

import asyncio

from wotd.modules.base import Module, ModuleResult
from wotd.parsers import normalize_hosts, parse_lines
from wotd.orchestrator import ModuleContext, dispatcher
from wotd.store import get_subdomain_hosts, upsert_subdomains
from wotd.tasks import DomainTask, HostnameTask, Task
from wotd.tools import ToolNotFoundError, ToolResult, run_tool


async def _run_subfinder(root: str) -> ToolResult:
    return await run_tool("subfinder", ["-d", root, "-silent"], timeout=None)


async def _run_assetfinder(root: str) -> ToolResult:
    return await run_tool("assetfinder", ["--subs-only", root], timeout=None)


class SubdomainsPassiveModule(Module):
    name = "subdomains_passive"

    async def run(self) -> ModuleResult:
        root = self.target.name
        tasks = {
            "subfinder": _run_subfinder(root),
            "assetfinder": _run_assetfinder(root),
        }
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        host_to_sources: dict[str, set[str]] = {}
        per_tool: dict[str, int] = {}
        errors: dict[str, str] = {}

        for tool_name, result in zip(tasks.keys(), results, strict=True):
            if isinstance(result, BaseException):
                errors[tool_name] = (
                    "not installed" if isinstance(result, ToolNotFoundError) else str(result)
                )
                per_tool[tool_name] = 0
                continue
            hosts = normalize_hosts(parse_lines(result.stdout))
            per_tool[tool_name] = len(hosts)
            for h in hosts:
                host_to_sources.setdefault(h, set()).add(tool_name)

        in_scope = {h: srcs for h, srcs in host_to_sources.items() if self.scope.is_in_scope(h)}

        new_count, existing_count, new_hosts = await upsert_subdomains(
            self.session, self.target.id, in_scope
        )

        return ModuleResult(
            module=self.name,
            stats={
                "per_tool": per_tool,
                "total_unique": len(host_to_sources),
                "in_scope": len(in_scope),
                "new": new_count,
                "existing": existing_count,
                "new_hosts": new_hosts,
                "errors": errors,
            },
        )


@dispatcher.register(DomainTask, module_name=SubdomainsPassiveModule.name)
async def handle_domain_passive(task: DomainTask, ctx: ModuleContext) -> list[Task]:
    module = SubdomainsPassiveModule(ctx.session, ctx.target, ctx.scope, task=task)
    await ctx.run_module(module)
    hosts = await get_subdomain_hosts(ctx.session, ctx.target.id)
    return [
        HostnameTask(fqdn=host, parent_task_id=task.id, source_module=module.name)
        for host in hosts
    ]

