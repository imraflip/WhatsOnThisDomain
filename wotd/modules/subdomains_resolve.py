"""DNS resolution of known subdomains via dnsx."""

from __future__ import annotations

from wotd.modules.base import Module, ModuleResult
from wotd.parsers import parse_jsonl
from wotd.store import get_subdomain_hosts, upsert_dns_records
from wotd.tools import ToolNotFoundError, run_tool

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

    async def run(self) -> ModuleResult:
        hosts = await get_subdomain_hosts(self.session, self.target.id)
        if not hosts:
            return ModuleResult(
                module=self.name,
                stats={"input_hosts": 0, "resolved": 0, "new": 0, "existing": 0, "errors": {}},
            )

        errors: dict[str, str] = {}
        records: list[tuple[str, str, str]] = []
        resolved_hosts: set[str] = set()

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
                "errors": errors,
            },
        )
