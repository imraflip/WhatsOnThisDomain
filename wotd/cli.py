from __future__ import annotations

import asyncio

import typer
from rich.console import Console

from wotd.db import get_session_factory, init_db
from wotd.modules.subdomains_active import SubdomainsActiveModule
from wotd.modules.subdomains_passive import SubdomainsPassiveModule
from wotd.modules.subdomains_probe import SubdomainsProbeModule
from wotd.modules.subdomains_resolve import SubdomainsResolveModule
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import (
    create_target,
    finish_scan_run,
    get_target_by_name,
    start_scan_run,
)

app = typer.Typer(
    name="wotd",
    help="Recon and attack surface monitoring pipeline for bug bounty and authorized pentesting.",
    no_args_is_help=True,
)
console = Console()


async def _run_subdomains_passive(target_name: str) -> None:
    await init_db()
    session_factory = get_session_factory()

    async with session_factory() as session:
        target = await get_target_by_name(session, target_name)
        if target is None:
            target = await create_target(session, name=target_name, root_domains=[target_name])

        scope = Scope(
            includes=[
                ScopeRule(pattern=f"*.{target_name}", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern=target_name, rule_type=RuleType.EXACT),
            ],
        )

        for module_cls in (
            SubdomainsPassiveModule,
            SubdomainsActiveModule,
            SubdomainsResolveModule,
            SubdomainsProbeModule,
        ):
            scan_run = await start_scan_run(session, target.id, module_cls.name)
            module = module_cls(session, target, scope)
            try:
                result = await module.run()
                await finish_scan_run(session, scan_run, "completed", summary=result.stats)
                console.print(f"[green]{module_cls.name}[/green] {result.stats}")
            except Exception as e:
                await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
                raise


@app.command()
def subdomains(
    target: str = typer.Argument(..., help="Target domain (e.g. acme.com)"),
) -> None:
    """Run passive subdomain enumeration against a target."""
    asyncio.run(_run_subdomains_passive(target))


@app.command()
def crawl(
    url: str = typer.Argument(..., help="Full URL including scheme (e.g. https://acme.com)"),
) -> None:
    """Run endpoint discovery against a target URL."""
    if "://" not in url:
        console.print(
            "[red]error:[/red] crawl requires a full URL with scheme (e.g. https://acme.com)"
        )
        raise typer.Exit(code=2)
    console.print(f"[yellow]crawl module not implemented yet[/yellow] (url: {url})")
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
