"""Re-detect technologies on all live HTTP services for a target.

Runs httpx-pd -tech-detect against every URL in http_services, giving fresher results
than the subdomains pipeline (which only probes newly-found hosts). Populates
wordlist_key via the tech_map normalization, so dirbust auto-tech can pick it up.
"""

from __future__ import annotations

from typing import Any

from wotd.modules.base import Module, ModuleResult
from wotd.parsers import parse_jsonl
from wotd.store import get_http_service_urls, upsert_tech_detections
from wotd.orchestrator import ModuleContext, dispatcher
from wotd.tasks import Task, TechTag, UrlTask
from wotd.tech_map import tech_to_wordlist_key
from wotd.tools import ToolNotFoundError, run_tool


class TechDetectModule(Module):
    name = "tech_detect"

    def __init__(
        self,
        session: AsyncSession,
        target: Target,
        scope: Scope,
        single_url: str | None = None,
        urls: list[str] | None = None,
        task: Any | None = None,
    ) -> None:
        super().__init__(session, target, scope, task=task)
        self.single_url = single_url
        self.urls = urls

    async def run(self) -> ModuleResult:
        if self.urls:
            urls = self.urls
        elif self.single_url:
            urls = [self.single_url]
        else:
            urls = await get_http_service_urls(self.session, self.target.id)

        if not urls:
            return ModuleResult(
                module=self.name,
                stats={
                    "input_urls": 0,
                    "detections": 0,
                    "new": 0,
                    "existing": 0,
                    "errors": {},
                },
            )

        errors: dict[str, str] = {}
        detections: list[dict[str, Any]] = []

        try:
            result = await run_tool(
                "httpx-pd",
                [
                    "-silent",
                    "-json",
                    "-tech-detect",
                    "-threads",
                    "150",
                    "-rate-limit",
                    "300",
                ],
                stdin_data="\n".join(urls) + "\n",
                timeout=1800.0,
            )
            for entry in parse_jsonl(result.stdout):
                url = entry.get("url")
                if not isinstance(url, str) or not url:
                    continue
                tech_list = entry.get("tech")
                if not isinstance(tech_list, list):
                    continue
                for t in tech_list:
                    if not isinstance(t, str):
                        continue
                    name = t.strip()
                    if not name:
                        continue
                    detections.append(
                        {
                            "url": url,
                            "tech": name,
                            "source": "tech_detect",
                            "wordlist_key": tech_to_wordlist_key(name),
                        }
                    )
        except ToolNotFoundError:
            errors["httpx"] = "not installed"

        new_count, existing_count = await upsert_tech_detections(
            self.session, self.target.id, detections
        )

        return ModuleResult(
            module=self.name,
            stats={
                "input_urls": len(urls),
                "detections": len(detections),
                "detections_list": detections,
                "new": new_count,
                "existing": existing_count,
                "errors": errors,
            },
        )


@dispatcher.register(UrlTask, module_name=TechDetectModule.name)
async def handle_url_tech(task: UrlTask, ctx: ModuleContext) -> list[Task]:
    module = TechDetectModule(ctx.session, ctx.target, ctx.scope, urls=[task.url], task=task)
    result = await ctx.run_module(module)
    detections = result.stats.get("detections_list", [])
    by_url: dict[str, list[str]] = {}
    for item in detections:
        url = item.get("url")
        tech = item.get("tech")
        if isinstance(url, str) and isinstance(tech, str):
            by_url.setdefault(url, []).append(tech)
    return [
        TechTag(url=url, techs=sorted(set(techs)), parent_task_id=task.id, source_module=module.name)
        for url, techs in by_url.items()
    ]

