"""Active subdomain enumeration via shuffledns bruteforce."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.parsers import normalize_hosts, parse_lines
from wotd.scope import Scope
from wotd.store import upsert_subdomains
from wotd.tools import ToolNotFoundError, run_tool
from wotd.utils.resolvers import ensure_resolvers_fresh

DEFAULT_WORDLIST = Path("/opt/wotd/wordlists/httparchive_subdomains.txt")
DEFAULT_RESOLVERS = Path("/opt/wotd/resolvers.txt")


class SubdomainsActiveModule(Module):
    name = "subdomains_active"

    def __init__(
        self,
        session: AsyncSession,
        target: Target,
        scope: Scope,
        wordlist: Path = DEFAULT_WORDLIST,
        resolvers: Path = DEFAULT_RESOLVERS,
    ) -> None:
        super().__init__(session, target, scope)
        self.wordlist = wordlist
        self.resolvers = resolvers

    async def run(self) -> ModuleResult:
        root = self.target.name
        errors: dict[str, str] = {}

        if not self.wordlist.exists():
            errors["wordlist"] = f"missing: {self.wordlist}"

        try:
            await ensure_resolvers_fresh(self.resolvers)
        except Exception as e:
            errors["resolvers"] = f"refresh failed: {e}"

        hosts: list[str] = []
        if not errors:
            try:
                result = await run_tool(
                    "shuffledns",
                    [
                        "-d",
                        root,
                        "-w",
                        str(self.wordlist),
                        "-r",
                        str(self.resolvers),
                        "-mode",
                        "bruteforce",
                        "-silent",
                        "-t",
                        "10000",
                    ],
                    timeout=1800.0,
                )
                hosts = normalize_hosts(parse_lines(result.stdout))
            except ToolNotFoundError:
                errors["shuffledns"] = "not installed"

        in_scope = [h for h in hosts if self.scope.is_in_scope(h)]
        host_to_sources: dict[str, set[str]] = {h: {"shuffledns"} for h in in_scope}

        new_count, existing_count, new_hosts = await upsert_subdomains(
            self.session, self.target.id, host_to_sources
        )

        return ModuleResult(
            module=self.name,
            stats={
                "found": len(hosts),
                "in_scope": len(in_scope),
                "new": new_count,
                "existing": existing_count,
                "new_hosts": new_hosts,
                "errors": errors,
            },
        )
