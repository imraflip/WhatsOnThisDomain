from __future__ import annotations

import asyncio
import json as json_lib
from datetime import timedelta

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wotd.db import get_session_factory, init_db
from wotd.models import HttpService
from wotd.modules.base import ModuleResult
from wotd.modules.subdomains_active import SubdomainsActiveModule
from wotd.modules.subdomains_passive import SubdomainsPassiveModule
from wotd.modules.subdomains_probe import SubdomainsProbeModule
from wotd.modules.subdomains_resolve import SubdomainsResolveModule
from wotd.notify import (
    NewHost,
    NotifyPayload,
    dispatch,
    format_cli_summary,
    format_message,
)
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import (
    SubdomainRow,
    create_target,
    finish_scan_run,
    get_resolved_hosts,
    get_target_by_name,
    list_subdomains,
    start_scan_run,
)
from wotd.utils.duration import parse_duration

app = typer.Typer(
    name="wotd",
    help=(
        "Recon and attack surface monitoring pipeline for bug bounty and authorized "
        "pentesting. Enumerates subdomains, resolves DNS, probes HTTP services, and "
        "diffs against previous scans so new assets surface automatically."
    ),
    epilog=(
        "**Examples:**\n\n"
        "- `wotd subdomains acme.com` — passive + active + resolve + probe\n\n"
        "- `wotd subdomains acme.com --notify` — also send a discord / smtp summary\n\n"
        "- `wotd show subdomains acme.com` — inspect hosts stored in the db\n\n"
        "- `wotd show subdomains --since 24h` — rows first seen in the last day"
    ),
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="markdown",
)
console = Console()


async def _run_subdomains(target_name: str, notify: bool = False) -> None:
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

        results: dict[str, ModuleResult] = {}
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
                results[module_cls.name] = result
            except Exception as e:
                await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
                raise

        payload = await _build_notify_payload(session, target.id, target_name, results)

    summary = format_cli_summary(payload)
    if summary:
        console.print()
        console.print(summary, markup=False)

    if notify:
        message = format_message(payload)
        if message:
            sent = await dispatch(message)
            if sent:
                console.print("[dim]notification sent[/dim]")


async def _build_notify_payload(
    session: AsyncSession,
    target_id: int,
    target_name: str,
    results: dict[str, ModuleResult],
) -> NotifyPayload:
    new_subs_set: set[str] = set()
    for module_name in ("subdomains_passive", "subdomains_active"):
        module_result = results.get(module_name)
        if module_result:
            new_subs_set.update(module_result.stats.get("new_hosts", []))

    resolved_hosts = set(await get_resolved_hosts(session, target_id))

    probe_rows = await session.execute(
        select(HttpService.host, HttpService.status_code, HttpService.url).where(
            HttpService.target_id == target_id
        )
    )
    probed_by_host: dict[str, tuple[int | None, str]] = {}
    for host, code, url in probe_rows.all():
        existing = probed_by_host.get(host)
        if existing is None:
            probed_by_host[host] = (code, url)
            continue
        existing_code, existing_url = existing
        if existing_code is None and code is not None:
            probed_by_host[host] = (code, url)
        elif (
            code is not None
            and url.startswith("https://")
            and not existing_url.startswith("https://")
        ):
            probed_by_host[host] = (code, url)

    new_hosts: list[NewHost] = []
    resolved_count = 0
    live_count = 0
    for host in sorted(new_subs_set):
        if host in probed_by_host:
            code, url = probed_by_host[host]
            new_hosts.append(
                NewHost(host=host, status="probed", status_code=code, url=url)
            )
            live_count += 1
            resolved_count += 1
        elif host in resolved_hosts:
            new_hosts.append(NewHost(host=host, status="resolved"))
            resolved_count += 1
        else:
            new_hosts.append(NewHost(host=host, status="found"))

    return NotifyPayload(
        target=target_name,
        discovered_count=len(new_subs_set),
        resolved_count=resolved_count,
        live_count=live_count,
        new_hosts=new_hosts,
    )


@app.command()
def subdomains(
    target: str = typer.Argument(..., help="Target domain (e.g. acme.com)"),
    notify: bool = typer.Option(
        False, "--notify", help="Send notifications after the scan finishes."
    ),
) -> None:
    """Run subdomain enumeration against a target."""
    asyncio.run(_run_subdomains(target, notify))


show_app = typer.Typer(
    name="show",
    help="Inspect data stored in the local db.",
    no_args_is_help=True,
)
app.add_typer(show_app)


def _render_table(rows: list[SubdomainRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("host", overflow="fold")
    table.add_column("status", justify="right")
    table.add_column("title", overflow="fold")
    table.add_column("first seen", style="dim")

    for r in rows:
        status = str(r.status_code) if r.status_code is not None else "-"
        title = r.title or ""
        first_seen = r.first_seen_at.strftime("%Y-%m-%d %H:%M")
        table.add_row(r.host, status, title, first_seen)
    return table


def _render_json(rows: list[SubdomainRow]) -> str:
    return json_lib.dumps(
        [
            {
                "host": r.host,
                "sources": r.sources.split(","),
                "status_code": r.status_code,
                "title": r.title,
                "url": r.url,
                "first_seen_at": r.first_seen_at.isoformat(),
                "last_seen_at": r.last_seen_at.isoformat(),
            }
            for r in rows
        ],
        indent=2,
    )


async def _show_subdomains(
    target_name: str | None,
    since: timedelta | None,
    source: str | None,
    include_unprobed: bool,
    limit: int | None,
    as_json: bool,
) -> None:
    await init_db()
    session_factory = get_session_factory()
    async with session_factory() as session:
        target_id: int | None = None
        if target_name is not None:
            target = await get_target_by_name(session, target_name)
            if target is None:
                console.print(f"[red]no target named {target_name!r} in the db[/red]")
                raise typer.Exit(code=1)
            target_id = target.id

        rows = await list_subdomains(
            session,
            target_id,
            since=since,
            source=source,
            probed_only=not include_unprobed,
            limit=limit,
        )

    if as_json:
        print(_render_json(rows))
        return

    if not rows:
        console.print("[yellow]no matching subdomains[/yellow]")
        return

    console.print(_render_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("subdomains")
def show_subdomains(
    target: str | None = typer.Argument(
        None, help="Target domain (e.g. hackerone.com). Omit to show across all targets."
    ),
    since: str | None = typer.Option(
        None, "--since", help="Only rows first seen within this window (e.g. 24h, 7d, 2w)."
    ),
    source: str | None = typer.Option(
        None, "--source", help="Filter by a specific source (e.g. subfinder, shuffledns)."
    ),
    include_unprobed: bool = typer.Option(
        False, "--include-unprobed", help="Include hosts with no probe data."
    ),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(
        False, "--all", help="Ignore --since and --limit, show everything."
    ),
    as_json: bool = typer.Option(
        False, "--json", help="Output raw JSON instead of a table."
    ),
) -> None:
    """Show subdomains stored in the db for a target."""
    since_td: timedelta | None
    effective_limit: int | None
    if all_rows:
        since_td = None
        effective_limit = None
    else:
        if since is None:
            since_td = None
        else:
            try:
                since_td = parse_duration(since)
            except ValueError as e:
                console.print(f"[red]{e}[/red]")
                raise typer.Exit(code=2) from e
        effective_limit = None if limit == 0 else limit

    asyncio.run(
        _show_subdomains(target, since_td, source, include_unprobed, effective_limit, as_json)
    )


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
