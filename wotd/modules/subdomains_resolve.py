"""DNS resolution of known subdomains via dnsx."""

from __future__ import annotations

from typing import Any

from wotd.modules.base import Module, ModuleResult
from wotd.parsers import parse_jsonl
from wotd.store import get_subdomain_hosts, upsert_dns_records
from wotd.tools import ToolNotFoundError, run_tool
from wotd.orchestrator import ModuleContext, dispatcher
from wotd.tasks import HostnameTask, ResolvedHostTask, Task

RECORD_TYPES = ("a", "aaaa", "cname")


def _extract_records(entry: dict[str, object]) -> list[tuple[str, str, str]]:
    host = entry.get("host")
    if not isinstance(host, str):
        return []
    out: list[tuple[str, str, str]] = []
    for key in RECORD_TYPES:
        values = entry.get(key)
        if not isinstance(values, list):
            continue
        for v in values:
            if isinstance(v, str) and v:
                out.append((host, key.upper(), v))
    return out


class SubdomainsResolveModule(Module):
    name = "subdomains_resolve"

    def __init__(
        self,
        session: Any,
        target: Any,
        scope: Any,
        hosts: list[str] | None = None,
        task: Any | None = None,
    ) -> None:
        super().__init__(session, target, scope, task=task)
        self.hosts = hosts

    async def run(self) -> ModuleResult:
        hosts = self.hosts or await get_subdomain_hosts(self.session, self.target.id)
        if not hosts:
            return ModuleResult(
                module=self.name,
                stats={
                    "input_hosts": 0,
                    "resolved": 0,
                    "new": 0,
                    "existing": 0,
                    "errors": {},
                },
            )

        errors: dict[str, str] = {}
        records: list[tuple[str, str, str]] = []
        resolved_hosts: set[str] = set()
        ips_by_host: dict[str, set[str]] = {}

        try:
            result = await run_tool(
                "dnsx",
                ["-a", "-aaaa", "-cname", "-resp", "-silent", "-json", "-t", "500"],
                stdin_data="\n".join(hosts) + "\n",
                timeout=1800.0,
            )
            for entry in parse_jsonl(result.stdout):
                extracted = _extract_records(entry)
                if extracted:
                    resolved_hosts.add(extracted[0][0])
                records.extend(extracted)
                for host, _, value in extracted:
                    ips_by_host.setdefault(host, set()).add(value)
        except ToolNotFoundError:
            errors["dnsx"] = "not installed"

        new_count, existing_count = await upsert_dns_records(self.session, self.target.id, records)

        return ModuleResult(
            module=self.name,
            stats={
                "input_hosts": len(hosts),
                "resolved": len(resolved_hosts),
                "records": len(records),
                "new": new_count,
                "existing": existing_count,
                "resolved_hosts": sorted(resolved_hosts),
                "ips_by_host": {k: sorted(v) for k, v in ips_by_host.items()},
                "errors": errors,
            },
        )


@dispatcher.register(
    HostnameTask,
    module_name=SubdomainsResolveModule.name,
    batch=True,
    buffer_size=50,
    buffer_seconds=5.0,
)
async def handle_hostname_resolve(tasks: list[HostnameTask], ctx: ModuleContext) -> list[Task]:
    hostnames = [t.fqdn for t in tasks]
    module = SubdomainsResolveModule(ctx.session, ctx.target, ctx.scope, hosts=hostnames)
    result = await ctx.run_module(module)
    ips_by_host = result.stats.get("ips_by_host", {})
    parent_by_host = {t.fqdn: t.id for t in tasks}
    resolved_hosts = result.stats.get("resolved_hosts", [])
    output: list[Task] = []
    for host in resolved_hosts:
        ips = ips_by_host.get(host, [])
        output.append(
            ResolvedHostTask(
                fqdn=host,
                ips=ips,
                parent_task_id=parent_by_host.get(host),
                source_module=module.name,
            )
        )
    return output

