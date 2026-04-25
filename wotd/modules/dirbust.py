"""Directory bruteforcing via ffuf."""

from __future__ import annotations

import json
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import Target
from wotd.modules.base import Module, ModuleResult
from wotd.scope import Scope
from wotd.store import upsert_dir_results
from wotd.tools import run_tool

_WORDLISTS_PRIMARY = [
    "/opt/wotd/wordlists/httparchive_directories.txt",
    "/opt/wotd/wordlists/raft-large-directories.txt",
    "/opt/wotd/wordlists/raft-large-files.txt",
]


class DirBruteModule(Module):
    name = "dirbust"

    def __init__(
        self,
        session: AsyncSession,
        target: Target,
        scope: Scope,
        base_url: str,
        tech: str | None = None,
    ) -> None:
        super().__init__(session, target, scope)
        self.base_url = base_url.rstrip("/")
        self.tech = tech

    async def _ffuf_pass(self, wordlist: str) -> list[dict[str, object]]:
        fuzz_url = f"{self.base_url}/FUZZ"
        result = await run_tool(
            "ffuf",
            [
                "-u", fuzz_url,
                "-w", wordlist,
                "-rate", "150",
                "-t", "50",
                "-mc", "200,201,204,301,302,307,401,403,405",
                "-json",
            ],
            timeout=None,
        )
        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url", "")
            status = obj.get("status")
            if not url or status is None:
                continue
            hit_host = urlparse(url).hostname or ""
            if not hit_host or not self.scope.is_in_scope(hit_host):
                continue
            findings.append(
                {
                    "url": url,
                    "base_url": self.base_url,
                    "status_code": int(status),
                }
            )
        return findings

    async def run(self) -> ModuleResult:
        wordlists = list(_WORDLISTS_PRIMARY)
        if self.tech:
            wordlists.append(f"/opt/wotd/wordlists/tech_{self.tech}.txt")

        all_findings: list[dict[str, object]] = []
        for wl in wordlists:
            all_findings.extend(await self._ffuf_pass(wl))

        new_count, existing_count, new_urls, changed_urls = await upsert_dir_results(
            self.session, self.target.id, all_findings
        )

        return ModuleResult(
            module=self.name,
            stats={
                "total_hits": len(all_findings),
                "new": new_count,
                "existing": existing_count,
                "changed": len(changed_urls),
                "new_urls": new_urls,
                "changed_urls": changed_urls,
            },
        )
