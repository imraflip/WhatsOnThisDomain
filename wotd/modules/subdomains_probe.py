"""HTTP probing of resolved hosts via httpx."""

from __future__ import annotations

from typing import Any

from wotd.modules.base import Module, ModuleResult
from wotd.parsers import parse_jsonl
from wotd.store import get_resolved_hosts, upsert_http_services
from wotd.tools import ToolNotFoundError, run_tool


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _int_or_none(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _extract_service(entry: dict[str, Any]) -> dict[str, Any] | None:
    url = entry.get("url")
    if not isinstance(url, str) or not url:
        return None

    input_host = entry.get("input")
    host = input_host if isinstance(input_host, str) and input_host else url

    tech_list = entry.get("tech")
    tech: str | None = None
    if isinstance(tech_list, list):
        joined = ",".join(t for t in tech_list if isinstance(t, str))
        tech = joined or None

    return {
        "host": host,
        "url": url,
        "status_code": _int_or_none(entry.get("status_code")),
        "title": _str_or_none(entry.get("title")),
        "tech": tech,
        "content_length": _int_or_none(entry.get("content_length")),
        "final_url": _str_or_none(entry.get("final_url")),
    }


class SubdomainsProbeModule(Module):
    name = "subdomains_probe"

    async def run(self) -> ModuleResult:
        hosts = await get_resolved_hosts(self.session, self.target.id)
        if not hosts:
            return ModuleResult(
                module=self.name,
                stats={"input_hosts": 0, "alive": 0, "new": 0, "existing": 0, "errors": {}},
            )

        errors: dict[str, str] = {}
        services: list[dict[str, Any]] = []

        try:
            result = await run_tool(
                "httpx-pd",
                [
                    "-silent",
                    "-json",
                    "-title",
                    "-tech-detect",
                    "-status-code",
                    "-content-length",
                    "-follow-redirects",
                ],
                stdin_data="\n".join(hosts) + "\n",
                timeout=1800.0,
            )
            for entry in parse_jsonl(result.stdout):
                svc = _extract_service(entry)
                if svc is not None:
                    services.append(svc)
        except ToolNotFoundError:
            errors["httpx"] = "not installed"

        new_count, existing_count = await upsert_http_services(
            self.session, self.target.id, services
        )

        return ModuleResult(
            module=self.name,
            stats={
                "input_hosts": len(hosts),
                "alive": len(services),
                "new": new_count,
                "existing": existing_count,
                "errors": errors,
            },
        )
