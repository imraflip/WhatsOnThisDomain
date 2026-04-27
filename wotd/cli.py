from __future__ import annotations

import asyncio
import json as json_lib
from datetime import timedelta
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wotd.db import get_session_factory, init_db
from wotd.models import HttpService
from wotd.modules.api_graphql import ApiGraphqlModule
from wotd.modules.api_kiterunner import ApiKiterunnerModule
from wotd.modules.api_openapi import ApiOpenApiModule
from wotd.modules.api_passive import ApiPassiveModule
from wotd.modules.base import ModuleResult
from wotd.modules.crawl import CrawlModule
from wotd.modules.subdomains_active import SubdomainsActiveModule
from wotd.modules.subdomains_passive import SubdomainsPassiveModule
from wotd.modules.subdomains_probe import SubdomainsProbeModule
from wotd.modules.subdomains_resolve import SubdomainsResolveModule
from wotd.modules.tech_detect import TechDetectModule
from wotd.notify import (
    NewHost,
    NotifyPayload,
    dispatch,
    format_cli_summary,
    format_message,
)
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import (
    ApiRouteRow,
    ApiSpecRow,
    DirResultRow,
    EndpointRow,
    GraphqlEndpointRow,
    InterestingEndpointRow,
    InterestingSubdomainRow,
    JsEndpointRow,
    JsFileRow,
    JsSecretRow,
    SubdomainRow,
    TechDetectionRow,
    create_target,
    finish_scan_run,
    get_http_service_urls,
    get_resolved_hosts,
    get_subdomain_hosts,
    get_target_by_name,
    get_tech_wordlist_keys,
    has_prior_scan,
    list_api_routes,
    list_api_specs,
    list_dir_results,
    list_graphql_endpoints,
    list_endpoints,
    list_interesting_endpoints,
    list_interesting_subdomains,
    list_js_endpoints,
    list_js_files,
    list_js_secrets,
    list_subdomains,
    list_tech_detections,
    start_scan_run,
    upsert_interesting_subdomains,
)
from wotd.tools import ToolNotFoundError, run_gf
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
        "- `wotd crawl https://acme.com` — crawl endpoints from all sources\n\n"
        "- `wotd show subdomains acme.com` — inspect hosts stored in the db\n\n"
        "- `wotd show endpoints acme.com` — inspect crawled endpoints\n\n"
        "- `wotd examples` — full cheat-sheet"
    ),
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="markdown",
)
console = Console()


def _meta(stats: dict) -> dict:  # type: ignore[type-arg]
    """Strip list values from stats — CLI shows counts only."""
    return {k: v for k, v in stats.items() if not isinstance(v, list)}


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

        is_first = not await has_prior_scan(session, target.id, SubdomainsPassiveModule.name)

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
                console.print(f"[green]{module_cls.name}[/green] {_meta(result.stats)}")
                results[module_cls.name] = result
            except Exception as e:
                await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
                raise

        payload = await _build_notify_payload(session, target.id, target_name, results)

        int_new = 0
        int_existing = 0
        try:
            all_hosts = await get_subdomain_hosts(session, target.id)
            _SUB_PATTERNS = ("s3-buckets", "takeovers", "wotd-subdomains")
            gf_results = await asyncio.gather(
                *[run_gf(p, all_hosts) for p in _SUB_PATTERNS],
                return_exceptions=True,
            )
            interesting = []
            for pattern, res in zip(_SUB_PATTERNS, gf_results, strict=True):
                if isinstance(res, BaseException):
                    continue
                for fqdn in res:
                    if fqdn.strip():
                        interesting.append({"fqdn": fqdn.strip(), "pattern": pattern})
            int_new, int_existing = await upsert_interesting_subdomains(
                session, target.id, interesting
            )
            console.print(
                f"[green]interesting_subdomains[/green] "
                f"{{'new': {int_new}, 'existing': {int_existing}}}"
            )
        except ToolNotFoundError:
            pass

    new_techs = results.get("subdomains_probe", None)
    new_techs_count = new_techs.stats.get("new_techs", 0) if new_techs else 0

    summary = format_cli_summary(payload)
    if summary:
        console.print()
        console.print(summary, markup=False)

    if is_first:
        console.print("[dim]first scan — baseline established, skipping notify[/dim]")
    elif notify:
        message = format_message(payload)
        if message:
            if int_new:
                message += f"\n\n{int_new} interesting subdomains flagged"
            if new_techs_count:
                message += f"\n\n{new_techs_count} new tech detections"
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
            new_hosts.append(NewHost(host=host, status="probed", status_code=code, url=url))
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
    """Enumerate subdomains for a target domain.

    Runs the full pipeline in order: passive sources (subfinder), active
    brute-force (shuffledns), DNS resolution, and HTTP probing (httpx). New
    hosts are diffed against the previous scan and persisted to the local db.
    """
    asyncio.run(_run_subdomains(target, notify))


async def _run_tech_detect(target_name: str, notify: bool = False) -> None:
    await init_db()
    session_factory = get_session_factory()
    async with session_factory() as session:
        target = await get_target_by_name(session, target_name)
        if target is None:
            console.print(
                f"[red]error:[/red] target {target_name!r} not found — "
                "run wotd subdomains first"
            )
            raise typer.Exit(code=1)

        scope = Scope(
            includes=[
                ScopeRule(pattern=f"*.{target_name}", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern=target_name, rule_type=RuleType.EXACT),
            ],
        )

        is_first = not await has_prior_scan(session, target.id, TechDetectModule.name)

        scan_run = await start_scan_run(session, target.id, TechDetectModule.name)
        module = TechDetectModule(session, target, scope)
        try:
            result = await module.run()
            await finish_scan_run(session, scan_run, "completed", summary=result.stats)
            console.print(f"[green]{TechDetectModule.name}[/green] {_meta(result.stats)}")
        except Exception as e:
            await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
            raise

    new_count = result.stats.get("new", 0)
    if is_first:
        console.print("[dim]first scan — baseline established, skipping notify[/dim]")
    elif notify and new_count:
        message = f"[wotd] {target_name} tech-detect — {new_count} new tech detections"
        sent = await dispatch(message)
        if sent:
            console.print("[dim]notification sent[/dim]")


@app.command("tech-detect")
def tech_detect(
    target: str = typer.Argument(..., help="Target domain (e.g. acme.com)"),
    notify: bool = typer.Option(
        False, "--notify", help="Send notifications after the scan finishes."
    ),
) -> None:
    """Re-detect technologies on all live HTTP services for a target.

    Runs httpx-pd with -tech-detect against every URL stored in http_services and
    upserts findings into tech_detections, populating wordlist_key for techs
    that have a mapped wordlist (PHP, Java, Apache, Nginx, etc.). Use after
    subdomains to get fresher data — subdomains only probes newly-found hosts.
    """
    asyncio.run(_run_tech_detect(target, notify))


show_app = typer.Typer(
    name="show",
    help="Query data stored in the local database.",
    no_args_is_help=True,
)
app.add_typer(show_app)
app.add_typer(show_app, name="ls")


def _render_interesting_subdomains_table(rows: list[InterestingSubdomainRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("fqdn", overflow="fold")
    table.add_column("pattern", style="bold yellow")
    table.add_column("first seen", style="dim")
    for r in rows:
        table.add_row(r.fqdn, r.pattern, r.first_seen_at.strftime("%Y-%m-%d %H:%M"))
    return table


async def _show_interesting_subdomains(
    target_name: str | None,
    pattern: str | None,
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
        rows = await list_interesting_subdomains(session, target_id, pattern=pattern, limit=limit)

    if as_json:
        print(
            json_lib.dumps(
                [
                    {
                        "fqdn": r.fqdn,
                        "pattern": r.pattern,
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no interesting subdomains found[/yellow]")
        return

    console.print(_render_interesting_subdomains_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("interesting-subdomains")
def show_interesting_subdomains(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    pattern: str | None = typer.Option(
        None, "--pattern", help="Filter by gf pattern (e.g. takeovers, wotd-subdomains)."
    ),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(False, "--all", help="Ignore --limit, show everything."),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List subdomains flagged by gf pattern matching."""
    effective_limit: int | None = None if all_rows or limit == 0 else limit
    asyncio.run(_show_interesting_subdomains(target, pattern, effective_limit, as_json))


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
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List subdomains stored in the database.

    Defaults to probed hosts only (HTTP data available). Use --include-unprobed
    to also show DNS-only results. Omit TARGET to query across all targets.
    """
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


def _render_endpoints_table(rows: list[EndpointRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("url", overflow="fold")
    table.add_column("host", overflow="fold")
    table.add_column("source", style="dim")
    table.add_column("first seen", style="dim")
    for r in rows:
        table.add_row(r.url, r.host, r.source, r.first_seen_at.strftime("%Y-%m-%d %H:%M"))
    return table


async def _show_endpoints(
    target_name: str | None,
    since: timedelta | None,
    source: str | None,
    host: str | None,
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
        rows = await list_endpoints(
            session, target_id, since=since, source=source, host=host, limit=limit
        )

    if as_json:
        import json as json_lib

        print(
            json_lib.dumps(
                [
                    {
                        "url": r.url,
                        "host": r.host,
                        "source": r.source,
                        "status_code": r.status_code,
                        "content_type": r.content_type,
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no matching endpoints[/yellow]")
        return

    console.print(_render_endpoints_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("endpoints")
def show_endpoints(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    since: str | None = typer.Option(
        None, "--since", help="Only rows first seen within this window (e.g. 24h, 7d)."
    ),
    source: str | None = typer.Option(
        None, "--source", help="Filter by source tool (e.g. gau, katana)."
    ),
    host: str | None = typer.Option(None, "--host", help="Filter by exact host."),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(
        False, "--all", help="Ignore --since and --limit, show everything."
    ),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List endpoints stored in the database."""
    if all_rows:
        since_td: timedelta | None = None
        effective_limit: int | None = None
    else:
        since_td = None
        if since:
            try:
                since_td = parse_duration(since)
            except ValueError as e:
                console.print(f"[red]{e}[/red]")
                raise typer.Exit(code=2) from e
        effective_limit = None if limit == 0 else limit

    asyncio.run(_show_endpoints(target, since_td, source, host, effective_limit, as_json))


def _render_interesting_endpoints_table(rows: list[InterestingEndpointRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("url", overflow="fold")
    table.add_column("pattern", style="bold yellow")
    table.add_column("host", overflow="fold", style="dim")
    table.add_column("first seen", style="dim")
    for r in rows:
        table.add_row(r.url, r.pattern, r.host, r.first_seen_at.strftime("%Y-%m-%d %H:%M"))
    return table


async def _show_interesting_endpoints(
    target_name: str | None,
    pattern: str | None,
    host: str | None,
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
        rows = await list_interesting_endpoints(
            session, target_id, pattern=pattern, host=host, limit=limit
        )

    if as_json:
        print(
            json_lib.dumps(
                [
                    {
                        "url": r.url,
                        "host": r.host,
                        "pattern": r.pattern,
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no interesting endpoints found[/yellow]")
        return

    console.print(_render_interesting_endpoints_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("interesting-endpoints")
def show_interesting_endpoints(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    pattern: str | None = typer.Option(None, "--pattern", help="Filter by gf pattern (e.g. xss)."),
    host: str | None = typer.Option(None, "--host", help="Filter by exact host."),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(False, "--all", help="Ignore --limit, show everything."),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List endpoints flagged by gf pattern matching."""
    effective_limit: int | None = None if all_rows or limit == 0 else limit
    asyncio.run(_show_interesting_endpoints(target, pattern, host, effective_limit, as_json))


async def _run_crawl(url: str, notify: bool = False) -> None:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    root = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host

    await init_db()
    session_factory = get_session_factory()
    async with session_factory() as session:
        target = await get_target_by_name(session, root)
        if target is None:
            target = await create_target(session, name=root, root_domains=[root])

        scope = Scope(
            includes=[
                ScopeRule(pattern=f"*.{root}", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern=root, rule_type=RuleType.EXACT),
            ],
        )

        is_first = not await has_prior_scan(session, target.id, CrawlModule.name)

        scan_run = await start_scan_run(session, target.id, CrawlModule.name)
        module = CrawlModule(session, target, scope, url)
        try:
            result = await module.run()
            await finish_scan_run(session, scan_run, "completed", summary=result.stats)
            console.print(f"[green]{CrawlModule.name}[/green] {_meta(result.stats)}")
        except Exception as e:
            await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
            raise

    new_count = result.stats.get("new_endpoints", 0)
    int_new = result.stats.get("interesting_new", 0)
    new_urls: list[str] = result.stats.get("new_urls", [])
    if is_first:
        console.print("[dim]first scan — baseline established, skipping notify[/dim]")
    elif notify and (new_count or int_new):
        parts = []
        if new_count:
            parts.append(f"{new_count} new endpoints")
        if int_new:
            parts.append(f"{int_new} interesting matches")
        message = f"[wotd] {root} — " + ", ".join(parts)
        if new_urls:
            message += "\n\n" + "\n".join(new_urls[:8])
        sent = await dispatch(message)
        if sent:
            console.print("[dim]notification sent[/dim]")


@app.command()
def crawl(
    url: str = typer.Argument(..., help="Full URL including scheme (e.g. https://acme.com)"),
    notify: bool = typer.Option(
        False, "--notify", help="Send notifications after the crawl finishes."
    ),
) -> None:
    """Crawl endpoints on a live target URL.

    Runs passive and active crawlers against the target, deduplicates discovered
    URLs, and stores new endpoints in the local database.
    """
    if "://" not in url:
        console.print(
            "[red]error:[/red] crawl requires a full URL with scheme (e.g. https://acme.com)"
        )
        raise typer.Exit(code=2)
    asyncio.run(_run_crawl(url, notify))


async def _run_discover_js(url: str, notify: bool = False, bruteforce_js: bool = False) -> None:
    from urllib.parse import urlparse

    from wotd.modules.js_discovery import JsDiscoveryModule

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    root = ".".join(hostname.split(".")[-2:]) if hostname.count(".") >= 1 else hostname

    await init_db()
    session_factory = get_session_factory()
    async with session_factory() as session:
        target = await get_target_by_name(session, root)
        if target is None:
            target = await create_target(session, name=root, root_domains=[root])

        scope = Scope(
            includes=[
                ScopeRule(pattern=f"*.{root}", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern=root, rule_type=RuleType.EXACT),
            ],
        )

        is_first = not await has_prior_scan(session, target.id, JsDiscoveryModule.name)

        scan_run = await start_scan_run(session, target.id, JsDiscoveryModule.name)
        module = JsDiscoveryModule(
            session, target, scope, seed_urls=[url], bruteforce_js=bruteforce_js
        )
        try:
            result = await module.run()
            await finish_scan_run(session, scan_run, "completed", summary=result.stats)
            console.print(f"[green]{JsDiscoveryModule.name}[/green] {_meta(result.stats)}")
        except Exception as e:
            await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
            raise

    new_js = result.stats.get("js_files_new", 0)
    new_ep = result.stats.get("js_endpoints_new", 0)
    new_sec = result.stats.get("js_secrets_new", 0)
    new_js_urls: list[str] = result.stats.get("new_js_urls", [])
    new_ep_urls: list[str] = result.stats.get("new_ep_urls", [])

    if is_first:
        console.print("[dim]first scan — baseline established, skipping notify[/dim]")
    elif notify and (new_js or new_ep or new_sec):
        parts = []
        if new_js:
            parts.append(f"{new_js} new JS files")
        if new_ep:
            parts.append(f"{new_ep} new JS endpoints")
        if new_sec:
            parts.append(f"{new_sec} new JS secrets")
        message = f"[wotd] {root} — " + ", ".join(parts)
        if new_js_urls:
            message += "\n\nJS files:\n" + "\n".join(new_js_urls[:8])
        if new_ep_urls:
            message += "\n\nEndpoints:\n" + "\n".join(new_ep_urls[:8])
        sent = await dispatch(message)
        if sent:
            console.print("[dim]notification sent[/dim]")


async def _resolve_tech_wordlists(
    session: AsyncSession,
    target_id: int,
    manual_tech: str | None,
) -> tuple[list[str], list[str], bool]:
    """Resolve tech wordlists from tech_detections + optional manual --tech.

    Returns (wordlist paths, auto-detected keys included, has_any_detections).
    Auto keys come from tech_detections; manual_tech is added on top if provided.
    Filters to wordlists that exist on disk. has_any_detections lets the caller
    decide whether to print the 'run tech-detect first' hint.
    """
    auto_keys = set(await get_tech_wordlist_keys(session, target_id))
    has_any_detections = bool(auto_keys)
    all_keys = auto_keys | ({manual_tech} if manual_tech else set())

    paths: list[str] = []
    auto_included: list[str] = []
    for key in sorted(all_keys):
        path = f"/opt/wotd/wordlists/tech_{key}.txt"
        if not Path(path).exists():
            continue
        paths.append(path)
        if key in auto_keys:
            auto_included.append(key)
    return paths, auto_included, has_any_detections


async def _run_api_passive(target_name: str, notify: bool = False) -> None:
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

        is_first = not await has_prior_scan(session, target.id, ApiPassiveModule.name)

        scan_run = await start_scan_run(session, target.id, ApiPassiveModule.name)
        module = ApiPassiveModule(session, target, scope)
        try:
            result = await module.run()
            await finish_scan_run(session, scan_run, "completed", summary=result.stats)
            console.print(f"[green]{ApiPassiveModule.name}[/green] {_meta(result.stats)}")
        except Exception as e:
            await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
            raise

        new_routes: int = result.stats.get("new_routes", 0)
        new_keys: list[str] = result.stats.get("new_keys", [])

        if is_first:
            console.print("[dim]first scan — baseline established, skipping notify[/dim]")
        elif notify and new_routes:
            message = f"[wotd] {target_name} api-passive — {new_routes} new API routes"
            if new_keys:
                message += "\n\n" + "\n".join(new_keys[:10])
            sent = await dispatch(message)
            if sent:
                console.print("[dim]notification sent[/dim]")


async def _run_api_kiterunner(
    target_name: str,
    notify: bool = False,
    skip_brute: bool = False,
    skip_trpc: bool = False,
    force_trpc: bool = False,
) -> None:
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

        is_first = not await has_prior_scan(session, target.id, ApiKiterunnerModule.name)

        scan_run = await start_scan_run(session, target.id, ApiKiterunnerModule.name)
        module = ApiKiterunnerModule(
            session, target, scope, skip_brute=skip_brute, skip_trpc=skip_trpc, force_trpc=force_trpc
        )
        try:
            result = await module.run()
            await finish_scan_run(session, scan_run, "completed", summary=result.stats)
            console.print(f"[green]{ApiKiterunnerModule.name}[/green] {_meta(result.stats)}")
        except Exception as e:
            await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
            raise

        new_routes: int = result.stats.get("routes_upserted", 0)
        new_keys: list[str] = result.stats.get("new_keys", [])

        if is_first:
            console.print("[dim]first scan — baseline established, skipping notify[/dim]")
        elif notify and new_routes:
            message = f"[wotd] {target_name} api-kiterunner — {new_routes} new API routes"
            if new_keys:
                message += "\n\n" + "\n".join(new_keys[:10])
            sent = await dispatch(message)
            if sent:
                console.print("[dim]notification sent[/dim]")


async def _run_api_graphql(target_name: str, notify: bool = False) -> None:
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

        is_first = not await has_prior_scan(session, target.id, ApiGraphqlModule.name)

        scan_run = await start_scan_run(session, target.id, ApiGraphqlModule.name)
        module = ApiGraphqlModule(session, target, scope)
        try:
            result = await module.run()
            await finish_scan_run(session, scan_run, "completed", summary=result.stats)
            console.print(f"[green]{ApiGraphqlModule.name}[/green] {_meta(result.stats)}")
        except Exception as e:
            await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
            raise

        new_gql: int = result.stats.get("graphql_endpoints_new", 0)
        new_routes: int = result.stats.get("routes_new", 0)
        new_urls: list[str] = result.stats.get("new_urls", [])

        if is_first:
            console.print("[dim]first scan — baseline established, skipping notify[/dim]")
        elif notify and (new_gql or new_routes):
            parts = []
            if new_gql:
                parts.append(f"{new_gql} new GraphQL endpoint(s)")
            if new_routes:
                parts.append(f"{new_routes} new route(s) from introspection")
            message = f"[wotd] {target_name} api-graphql — " + ", ".join(parts)
            if new_urls:
                message += "\n\n" + "\n".join(new_urls[:8])
            sent = await dispatch(message)
            if sent:
                console.print("[dim]notification sent[/dim]")


async def _run_api_openapi(target_name: str, notify: bool = False) -> None:
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

        is_first = not await has_prior_scan(session, target.id, ApiOpenApiModule.name)

        scan_run = await start_scan_run(session, target.id, ApiOpenApiModule.name)
        module = ApiOpenApiModule(session, target, scope)
        try:
            result = await module.run()
            await finish_scan_run(session, scan_run, "completed", summary=result.stats)
            console.print(f"[green]{ApiOpenApiModule.name}[/green] {_meta(result.stats)}")
        except Exception as e:
            await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
            raise

        new_specs: int = result.stats.get("specs_new", 0)
        new_routes: int = result.stats.get("routes_new", 0)
        sj_extra: int = result.stats.get("sj_extra_routes", 0)
        new_spec_urls: list[str] = result.stats.get("new_spec_urls", [])

        if is_first:
            console.print("[dim]first scan — baseline established, skipping notify[/dim]")
        elif notify and (new_specs or new_routes or sj_extra):
            parts = []
            if new_specs:
                parts.append(f"{new_specs} new spec(s)")
            if new_routes:
                parts.append(f"{new_routes} new route(s)")
            if sj_extra:
                parts.append(f"{sj_extra} extra route(s) via sj")
            message = f"[wotd] {target_name} api-openapi — " + ", ".join(parts)
            if new_spec_urls:
                message += "\n\n" + "\n".join(new_spec_urls[:8])
            sent = await dispatch(message)
            if sent:
                console.print("[dim]notification sent[/dim]")


async def _run_dirbust(url: str, notify: bool = False, tech: str | None = None) -> None:
    from urllib.parse import urlparse

    from wotd.modules.dirbust import DirBruteModule

    parsed = urlparse(url)
    host = parsed.hostname or ""
    root = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host

    await init_db()
    session_factory = get_session_factory()
    async with session_factory() as session:
        target = await get_target_by_name(session, root)
        if target is None:
            target = await create_target(session, name=root, root_domains=[root])

        scope = Scope(
            includes=[
                ScopeRule(pattern=f"*.{root}", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern=root, rule_type=RuleType.EXACT),
            ],
        )

        tech_paths, auto_keys, has_detections = await _resolve_tech_wordlists(
            session, target.id, tech
        )
        if auto_keys:
            console.print(f"[dim][auto-tech] {' '.join(auto_keys)}[/dim]")
        elif tech is None and not has_detections:
            console.print(
                "[dim]no tech detections — "
                "run `wotd tech-detect` first for tech-specific passes[/dim]"
            )

        is_first = not await has_prior_scan(session, target.id, DirBruteModule.name)

        scan_run = await start_scan_run(session, target.id, DirBruteModule.name)
        module = DirBruteModule(session, target, scope, url, tech_wordlists=tech_paths)
        try:
            result = await module.run()
            await finish_scan_run(session, scan_run, "completed", summary=result.stats)
            console.print(f"[green]{DirBruteModule.name}[/green] {_meta(result.stats)}")
        except Exception as e:
            await finish_scan_run(session, scan_run, "failed", summary={"error": str(e)})
            raise

    new_count = result.stats.get("new", 0)
    changed_count = result.stats.get("changed", 0)
    new_urls: list[str] = result.stats.get("new_urls", [])
    changed_urls: list[str] = result.stats.get("changed_urls", [])
    if is_first:
        console.print("[dim]first scan — baseline established, skipping notify[/dim]")
    elif notify and (new_count or changed_count):
        parts = []
        if new_count:
            parts.append(f"{new_count} new paths")
        if changed_count:
            parts.append(f"{changed_count} status changes")
        message = f"[wotd] {root} dirbust — " + ", ".join(parts)
        sample = (new_urls + changed_urls)[:8]
        if sample:
            message += "\n\n" + "\n".join(sample)
        sent = await dispatch(message)
        if sent:
            console.print("[dim]notification sent[/dim]")


async def _run_dirbust_target(
    target_name: str, notify: bool = False, tech: str | None = None
) -> None:
    from wotd.modules.dirbust import DirBruteModule

    await init_db()
    session_factory = get_session_factory()
    async with session_factory() as session:
        target = await get_target_by_name(session, target_name)
        if target is None:
            console.print(
                f"[red]error:[/red] target {target_name!r} not found — "
                "run wotd subdomains first"
            )
            raise SystemExit(1)

        scope = Scope(
            includes=[
                ScopeRule(pattern=f"*.{target_name}", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern=target_name, rule_type=RuleType.EXACT),
            ],
        )

        service_urls = await get_http_service_urls(session, target.id)
        if not service_urls:
            console.print("[yellow]no live HTTP services found for this target[/yellow]")
            return

        tech_paths, auto_keys, has_detections = await _resolve_tech_wordlists(
            session, target.id, tech
        )
        if auto_keys:
            console.print(f"[dim][auto-tech] {' '.join(auto_keys)}[/dim]")
        elif tech is None and not has_detections:
            console.print(
                "[dim]no tech detections — "
                "run `wotd tech-detect` first for tech-specific passes[/dim]"
            )

        is_first = not await has_prior_scan(session, target.id, DirBruteModule.name)

        total_new = 0
        total_changed = 0
        all_new_urls: list[str] = []
        all_changed_urls: list[str] = []

        for svc_url in sorted(service_urls):
            scan_run = await start_scan_run(session, target.id, DirBruteModule.name)
            module = DirBruteModule(
                session, target, scope, svc_url, tech_wordlists=tech_paths
            )
            try:
                result = await module.run()
                await finish_scan_run(
                    session, scan_run, "completed", summary=result.stats
                )
                console.print(
                    f"[green]dirbust[/green] {svc_url} {_meta(result.stats)}"
                )
                total_new += result.stats.get("new", 0)
                total_changed += result.stats.get("changed", 0)
                all_new_urls.extend(result.stats.get("new_urls", []))
                all_changed_urls.extend(result.stats.get("changed_urls", []))
            except Exception as e:
                await finish_scan_run(
                    session, scan_run, "failed", summary={"error": str(e)}
                )
                console.print(f"[yellow]dirbust {svc_url} failed: {e}[/yellow]")

    if is_first:
        console.print("[dim]first scan — baseline established, skipping notify[/dim]")
    elif notify and (total_new or total_changed):
        parts = []
        if total_new:
            parts.append(f"{total_new} new paths")
        if total_changed:
            parts.append(f"{total_changed} status changes")
        message = f"[wotd] {target_name} dirbust — " + ", ".join(parts)
        sample = (all_new_urls + all_changed_urls)[:8]
        if sample:
            message += "\n\n" + "\n".join(sample)
        sent = await dispatch(message)
        if sent:
            console.print("[dim]notification sent[/dim]")


@app.command("dirbust")
def dirbust(
    target_or_url: str = typer.Argument(
        ...,
        help=(
            "Target domain (e.g. acme.com) or full URL with scheme "
            "(e.g. https://acme.com). Domain mode scans all live HTTP services "
            "stored for that target; URL mode scans only the given URL."
        ),
    ),
    notify: bool = typer.Option(
        False, "--notify", help="Send notifications after bruteforcing finishes."
    ),
    tech: str | None = typer.Option(
        None, "--tech",
        help=(
            "Force an extra tech-specific wordlist pass on top of auto-tech "
            "(e.g. php, java, dotnet, apache, nginx, grafana, kubernetes)."
        ),
    ),
) -> None:
    """Bruteforce directories and files on a target.

    Always runs three primary passes: httparchive directories, raft-large-directories,
    and raft-large-files. Auto-appends tech_{key}.txt passes for every distinct
    wordlist_key in the target's tech_detections (populated by subdomains and
    tech-detect). Use --tech to force-add an additional pass not in the store.

    Pass a bare domain to scan all live HTTP services stored for that target
    (requires a prior subdomains scan). Pass a full URL to scan only that
    specific service.
    """
    if tech is not None and not Path(f"/opt/wotd/wordlists/tech_{tech}.txt").exists():
        console.print(
            f"[red]error:[/red] no wordlist for --tech {tech!r} "
            f"(expected /opt/wotd/wordlists/tech_{tech}.txt)"
        )
        raise typer.Exit(code=2)
    if "://" in target_or_url:
        asyncio.run(_run_dirbust(target_or_url, notify, tech))
    else:
        asyncio.run(_run_dirbust_target(target_or_url, notify, tech))


@app.command("api-passive")
def api_passive(
    target: str = typer.Argument(..., help="Target domain (e.g. acme.com)"),
    notify: bool = typer.Option(
        False, "--notify", help="Send notifications after the scan finishes."
    ),
) -> None:
    """Extract passive API surface from existing endpoints + JS endpoints.

    Reads previously discovered URLs from the endpoints and js_endpoints tables
    and pattern-matches anything that looks like an API route. No tool runs,
    no network — purely a database transformation. Results upserted into api_routes.
    """
    asyncio.run(_run_api_passive(target, notify))


@app.command("api-kiterunner")
def api_kiterunner(
    target: str = typer.Argument(..., help="Target domain (e.g. acme.com)"),
    notify: bool = typer.Option(
        False, "--notify", help="Send notifications after the scan finishes."
    ),
    skip_brute: bool = typer.Option(
        False, "--skip-brute", help="Skip kr brute (path-only) pass."
    ),
    skip_trpc: bool = typer.Option(
        False, "--skip-trpc", help="Skip tRPC procedure probing via ffuf."
    ),
    force_trpc: bool = typer.Option(
        False, "--force-trpc", help="Force tRPC probing even if no trpc_passive routes found."
    ),
) -> None:
    """Run active API route discovery against live HTTP services.

    Runs three passes: kr scan (method-aware, primary), kr brute (path-only),
    and tRPC probe via ffuf (only if trpc_passive routes detected or --force-trpc).
    Requires prior subdomains scan to populate http_services table.
    """
    asyncio.run(_run_api_kiterunner(target, notify, skip_brute, skip_trpc, force_trpc))


@app.command("api-graphql")
def api_graphql(
    target: str = typer.Argument(..., help="Target domain (e.g. acme.com)"),
    notify: bool = typer.Option(
        False, "--notify", help="Send notifications after the scan finishes."
    ),
) -> None:
    """Detect GraphQL endpoints, enable introspection, extract routes, and fingerprint servers.

    Runs ffuf against live HTTP services with common GraphQL paths, attempts introspection
    queries to extract schema and routes, and fingerprints the GraphQL implementation
    (Apollo, Hasura, AWS AppSync, etc.) via graphw00f.
    """
    asyncio.run(_run_api_graphql(target, notify))


@app.command("api-openapi")
def api_openapi(
    target: str = typer.Argument(..., help="Target domain (e.g. acme.com)"),
    notify: bool = typer.Option(
        False, "--notify", help="Send notifications after the scan finishes."
    ),
) -> None:
    """Harvest OpenAPI/Swagger specs and extract API routes.

    Discovers spec files via ffuf with common paths, validates and parses them,
    extracts routes, and cross-validates with sj for additional routes captured
    via $ref resolution and parameterized-path expansion.
    """
    asyncio.run(_run_api_openapi(target, notify))


@app.command("api-discover")
def api_discover(
    target: str = typer.Argument(..., help="Target domain (e.g. acme.com)"),
    notify: bool = typer.Option(
        False, "--notify", help="Send notifications after the scan finishes."
    ),
    skip: list[str] = typer.Option(
        None, "--skip",
        help="Skip a phase: passive, kiterunner, graphql, openapi (repeatable).",
    ),
    skip_brute: bool = typer.Option(
        False, "--skip-brute", help="Skip kr brute pass (applies to api-kiterunner)."
    ),
    skip_trpc: bool = typer.Option(
        False, "--skip-trpc", help="Skip tRPC probing (applies to api-kiterunner)."
    ),
    force_trpc: bool = typer.Option(
        False, "--force-trpc", help="Force tRPC probing (applies to api-kiterunner)."
    ),
) -> None:
    """Master command orchestrating all API discovery phases.

    Runs api-passive → api-kiterunner → api-graphql → api-openapi in sequence.
    Each phase wrapped in try/except so a missing tool doesn't abort the rest.
    Use --skip to disable individual phases (repeatable). Sub-pass flags forwarded
    to api-kiterunner.
    """
    skip_phases = set(skip) if skip else set()
    asyncio.run(
        _run_api_discover(
            target,
            notify,
            skip_phases,
            skip_brute,
            skip_trpc,
            force_trpc,
        )
    )


async def _run_api_discover(
    target_name: str,
    notify: bool,
    skip_phases: set[str],
    skip_brute: bool = False,
    skip_trpc: bool = False,
    force_trpc: bool = False,
) -> None:
    """Orchestrate all API discovery phases with unified notification."""
    await init_db()
    session_factory = get_session_factory()

    async with session_factory() as session:
        target = await get_target_by_name(session, target_name)
        if target is None:
            target = await create_target(session, name=target_name, root_domains=[target_name])

        is_first_overall = True
        total_api_routes = 0
        total_graphql_endpoints = 0
        total_specs = 0
        all_errors = []

        # Phase 1: api-passive
        if "passive" not in skip_phases:
            try:
                await _run_api_passive(target_name, notify=False)
                is_first_overall = False
            except Exception as e:
                all_errors.append(f"api-passive: {e}")
                console.print(f"[yellow]api-passive warning: {e}[/yellow]")

        # Phase 2: api-kiterunner
        if "kiterunner" not in skip_phases:
            try:
                await _run_api_kiterunner(target_name, notify=False, skip_brute=skip_brute, skip_trpc=skip_trpc, force_trpc=force_trpc)
                is_first_overall = False
            except Exception as e:
                all_errors.append(f"api-kiterunner: {e}")
                console.print(f"[yellow]api-kiterunner warning: {e}[/yellow]")

        # Phase 3: api-graphql
        if "graphql" not in skip_phases:
            try:
                await _run_api_graphql(target_name, notify=False)
                is_first_overall = False
            except Exception as e:
                all_errors.append(f"api-graphql: {e}")
                console.print(f"[yellow]api-graphql warning: {e}[/yellow]")

        # Phase 4: api-openapi
        if "openapi" not in skip_phases:
            try:
                await _run_api_openapi(target_name, notify=False)
                is_first_overall = False
            except Exception as e:
                all_errors.append(f"api-openapi: {e}")
                console.print(f"[yellow]api-openapi warning: {e}[/yellow]")

        # Unified notification
        if notify and not is_first_overall:
            async with session_factory() as session_for_counts:
                target = await get_target_by_name(session_for_counts, target_name)
                if target:
                    route_rows = await list_api_routes(session_for_counts, target.id, limit=None)
                    gql_rows = await list_graphql_endpoints(session_for_counts, target.id, limit=None)
                    spec_rows = await list_api_specs(session_for_counts, target.id, limit=None)

                    total_api_routes = len(route_rows)
                    total_graphql_endpoints = len(gql_rows)
                    total_specs = len(spec_rows)

                    if total_api_routes or total_graphql_endpoints or total_specs:
                        parts = []
                        if total_api_routes:
                            parts.append(f"{total_api_routes} API routes")
                        if total_graphql_endpoints:
                            gql_introspect = sum(1 for r in gql_rows if r.introspection_enabled)
                            parts.append(f"{total_graphql_endpoints} GraphQL endpoints ({gql_introspect} introspectable)")
                        if total_specs:
                            parts.append(f"{total_specs} specs")

                        message = f"[wotd] {target_name} api-discover — " + ", ".join(parts)
                        if all_errors:
                            message += f"\n\n⚠️ Warnings: {'; '.join(all_errors)}"
                        sent = await dispatch(message)
                        if sent:
                            console.print("[dim]notification sent[/dim]")


@app.command("discover-js")
def discover_js(
    target: str = typer.Argument(..., help="Target domain (e.g. acme.com)"),
    notify: bool = typer.Option(
        False, "--notify", help="Send notifications after the scan finishes."
    ),
    bruteforce_js: bool = typer.Option(
        False, "--bruteforce-js",
        help="Run ffuf against live HTTP services to find unlinked JS files.",
    ),
) -> None:
    """Discover JavaScript files for a target URL.

    Collects .js URLs from the endpoints table and by running subjs and getjs
    against the provided URL. With --bruteforce-js, also runs ffuf against
    every live HTTP service using httparchive_js.txt to surface unlinked files.
    """
    if "://" not in target:
        console.print(
            "[red]error:[/red] discover-js requires a full URL with scheme (e.g. https://acme.com)"
        )
        raise typer.Exit(code=2)
    asyncio.run(_run_discover_js(target, notify, bruteforce_js))


def _render_dir_results_table(rows: list[DirResultRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("url", overflow="fold")
    table.add_column("status", justify="right")
    table.add_column("wordlist", style="dim")
    table.add_column("first seen", style="dim")
    for r in rows:
        table.add_row(
            r.url,
            str(r.status_code),
            r.wordlist or "-",
            r.first_seen_at.strftime("%Y-%m-%d %H:%M"),
        )
    return table


async def _show_dir_results(
    target_name: str | None,
    since: timedelta | None,
    status_code: int | None,
    host: str | None,
    wordlist: str | None,
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
        rows = await list_dir_results(
            session,
            target_id,
            since=since,
            status_code=status_code,
            host=host,
            wordlist=wordlist,
            limit=limit,
        )

    if as_json:
        print(
            json_lib.dumps(
                [
                    {
                        "url": r.url,
                        "base_url": r.base_url,
                        "status_code": r.status_code,
                        "wordlist": r.wordlist,
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no dir results found[/yellow]")
        return

    console.print(_render_dir_results_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("dir-results")
def show_dir_results(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    status: int | None = typer.Option(None, "--status", help="Filter by HTTP status code."),
    host: str | None = typer.Option(None, "--host", help="Filter by exact host."),
    wordlist: str | None = typer.Option(
        None, "--wordlist",
        help="Filter by wordlist that found the path (e.g. httparchive_directories, tech_php).",
    ),
    since: str | None = typer.Option(
        None, "--since", help="Only rows first seen within this window (e.g. 24h, 7d)."
    ),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(
        False, "--all", help="Ignore --since and --limit, show everything."
    ),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List directory bruteforce results stored in the database."""
    if all_rows:
        since_td: timedelta | None = None
        effective_limit: int | None = None
    else:
        since_td = None
        if since:
            try:
                since_td = parse_duration(since)
            except ValueError as e:
                console.print(f"[red]{e}[/red]")
                raise typer.Exit(code=2) from e
        effective_limit = None if limit == 0 else limit

    asyncio.run(
        _show_dir_results(target, since_td, status, host, wordlist, effective_limit, as_json)
    )


def _render_js_files_table(rows: list[JsFileRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("url", overflow="fold")
    table.add_column("sources", style="dim")
    table.add_column("first seen", style="dim")
    for r in rows:
        table.add_row(r.url, r.sources, r.first_seen_at.strftime("%Y-%m-%d %H:%M"))
    return table


async def _show_js_files(
    target_name: str | None,
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
        rows = await list_js_files(session, target_id, limit=limit)

    if as_json:
        print(
            json_lib.dumps(
                [
                    {
                        "url": r.url,
                        "host": r.host,
                        "sources": r.sources.split(","),
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no JS files found[/yellow]")
        return

    console.print(_render_js_files_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


def _render_js_endpoints_table(rows: list[JsEndpointRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("url", overflow="fold")
    table.add_column("method", style="dim", justify="right")
    table.add_column("host", overflow="fold")
    table.add_column("first seen", style="dim")
    for r in rows:
        table.add_row(r.url, r.method or "-", r.host, r.first_seen_at.strftime("%Y-%m-%d %H:%M"))
    return table


async def _show_js_endpoints(
    target_name: str | None,
    host: str | None,
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
        rows = await list_js_endpoints(session, target_id, host=host, limit=limit)

    if as_json:
        print(
            json_lib.dumps(
                [
                    {
                        "url": r.url,
                        "host": r.host,
                        "method": r.method,
                        "params": json_lib.loads(r.params) if r.params else [],
                        "source_js_url": r.source_js_url,
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no JS endpoints found[/yellow]")
        return

    console.print(_render_js_endpoints_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("js-endpoints")
def show_js_endpoints(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    host: str | None = typer.Option(None, "--host", help="Filter by exact host."),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(False, "--all", help="Ignore --limit, show everything."),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List JS endpoints extracted from discovered JS files."""
    effective_limit: int | None = None if all_rows or limit == 0 else limit
    asyncio.run(_show_js_endpoints(target, host, effective_limit, as_json))


def _render_js_secrets_table(rows: list[JsSecretRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("kind", style="bold red")
    table.add_column("severity", justify="right")
    table.add_column("data", overflow="fold")
    table.add_column("first seen", style="dim")
    for r in rows:
        sev = r.severity
        severity_style = "red" if sev == "high" else "yellow" if sev == "medium" else "dim"
        table.add_row(
            r.kind,
            f"[{severity_style}]{r.severity or '-'}[/{severity_style}]",
            r.data,
            r.first_seen_at.strftime("%Y-%m-%d %H:%M"),
        )
    return table


async def _show_js_secrets(
    target_name: str | None,
    kind: str | None,
    severity: str | None,
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
        rows = await list_js_secrets(session, target_id, kind=kind, severity=severity, limit=limit)

    if as_json:
        print(
            json_lib.dumps(
                [
                    {
                        "kind": r.kind,
                        "data": json_lib.loads(r.data),
                        "severity": r.severity,
                        "context": json_lib.loads(r.context) if r.context else None,
                        "source_js_url": r.source_js_url,
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no JS secrets found[/yellow]")
        return

    console.print(_render_js_secrets_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("js-secrets")
def show_js_secrets(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    kind: str | None = typer.Option(None, "--kind", help="Filter by secret kind."),
    severity: str | None = typer.Option(None, "--severity", help="Filter by severity."),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(False, "--all", help="Ignore --limit, show everything."),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List secrets extracted from discovered JS files."""
    effective_limit: int | None = None if all_rows or limit == 0 else limit
    asyncio.run(_show_js_secrets(target, kind, severity, effective_limit, as_json))


@show_app.command("js-files")
def show_js_files(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(False, "--all", help="Ignore --limit, show everything."),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List JS files stored in the database."""
    effective_limit: int | None = None if all_rows or limit == 0 else limit
    asyncio.run(_show_js_files(target, effective_limit, as_json))


def _render_api_routes_table(rows: list[ApiRouteRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("method", style="bold")
    table.add_column("url", overflow="fold")
    table.add_column("status", style="dim")
    table.add_column("source", style="dim")
    table.add_column("host", style="dim", overflow="fold")
    table.add_column("first seen", style="dim")
    for r in rows:
        table.add_row(
            r.method,
            r.url,
            str(r.status_code) if r.status_code else "-",
            r.source,
            r.host,
            r.first_seen_at.strftime("%Y-%m-%d %H:%M"),
        )
    return table


async def _show_api_routes(
    target_name: str | None,
    host: str | None,
    method: str | None,
    source: str | None,
    status_code: int | None,
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
        rows = await list_api_routes(
            session, target_id, host=host, method=method, source=source, status_code=status_code, limit=limit
        )

    if as_json:
        print(
            json_lib.dumps(
                [
                    {
                        "url": r.url,
                        "host": r.host,
                        "method": r.method,
                        "status_code": r.status_code,
                        "content_type": r.content_type,
                        "source": r.source,
                        "spec_url": r.spec_url,
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no API routes found[/yellow]")
        return

    console.print(_render_api_routes_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("api-routes")
def show_api_routes(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    host: str | None = typer.Option(None, "--host", help="Filter by exact host."),
    method: str | None = typer.Option(None, "--method", help="Filter by HTTP method (GET, POST, etc.)."),
    source: str | None = typer.Option(None, "--source", help="Filter by source (endpoints_passive, js_passive, etc.)."),
    status_code: int | None = typer.Option(None, "--status", help="Filter by HTTP status code."),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(False, "--all", help="Ignore --limit, show everything."),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List API routes discovered via passive pattern matching."""
    effective_limit: int | None = None if all_rows or limit == 0 else limit
    asyncio.run(_show_api_routes(target, host, method, source, status_code, effective_limit, as_json))


def _render_graphql_endpoints_table(rows: list[GraphqlEndpointRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("url", overflow="fold")
    table.add_column("introspection", style="bold")
    table.add_column("server", style="dim")
    table.add_column("host", style="dim", overflow="fold")
    table.add_column("first seen", style="dim")
    for r in rows:
        introspection = "✓" if r.introspection_enabled else "✗"
        table.add_row(
            r.url,
            introspection,
            r.server_type or "-",
            r.host,
            r.first_seen_at.strftime("%Y-%m-%d %H:%M"),
        )
    return table


async def _show_graphql_endpoints(
    target_name: str | None,
    host: str | None,
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
        rows = await list_graphql_endpoints(session, target_id, host=host, limit=limit)

    if as_json:
        print(
            json_lib.dumps(
                [
                    {
                        "url": r.url,
                        "host": r.host,
                        "introspection_enabled": r.introspection_enabled,
                        "server_type": r.server_type,
                        "schema_json": r.schema_json,
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no GraphQL endpoints found[/yellow]")
        return

    console.print(_render_graphql_endpoints_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("graphql-endpoints")
def show_graphql_endpoints(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    host: str | None = typer.Option(None, "--host", help="Filter by exact host."),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(False, "--all", help="Ignore --limit, show everything."),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List GraphQL endpoints with introspection and server type info."""
    effective_limit: int | None = None if all_rows or limit == 0 else limit
    asyncio.run(_show_graphql_endpoints(target, host, effective_limit, as_json))


def _render_api_specs_table(rows: list[ApiSpecRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("url", overflow="fold")
    table.add_column("type", style="bold")
    table.add_column("routes", style="dim", justify="right")
    table.add_column("host", style="dim", overflow="fold")
    table.add_column("first seen", style="dim")
    for r in rows:
        table.add_row(
            r.url,
            r.spec_type,
            str(r.routes_count),
            r.host,
            r.first_seen_at.strftime("%Y-%m-%d %H:%M"),
        )
    return table


async def _show_api_specs(
    target_name: str | None,
    host: str | None,
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
        rows = await list_api_specs(session, target_id, host=host, limit=limit)

    if as_json:
        print(
            json_lib.dumps(
                [
                    {
                        "url": r.url,
                        "host": r.host,
                        "spec_type": r.spec_type,
                        "routes_count": r.routes_count,
                        "raw_spec": r.raw_spec,
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no OpenAPI specs found[/yellow]")
        return

    console.print(_render_api_specs_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("api-specs")
def show_api_specs(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    host: str | None = typer.Option(None, "--host", help="Filter by exact host."),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(False, "--all", help="Ignore --limit, show everything."),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List OpenAPI/Swagger specs with extracted route counts."""
    effective_limit: int | None = None if all_rows or limit == 0 else limit
    asyncio.run(_show_api_specs(target, host, effective_limit, as_json))


def _render_tech_detections_table(rows: list[TechDetectionRow]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("url", overflow="fold")
    table.add_column("tech", style="bold cyan")
    table.add_column("source", style="dim")
    table.add_column("wordlist key", style="dim")
    table.add_column("first seen", style="dim")
    for r in rows:
        table.add_row(
            r.url,
            r.tech,
            r.source,
            r.wordlist_key or "-",
            r.first_seen_at.strftime("%Y-%m-%d %H:%M"),
        )
    return table


async def _show_tech_detections(
    target_name: str | None,
    tech: str | None,
    url: str | None,
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
        rows = await list_tech_detections(
            session, target_id, tech=tech, url=url, limit=limit
        )

    if as_json:
        print(
            json_lib.dumps(
                [
                    {
                        "url": r.url,
                        "tech": r.tech,
                        "source": r.source,
                        "wordlist_key": r.wordlist_key,
                        "first_seen_at": r.first_seen_at.isoformat(),
                        "last_seen_at": r.last_seen_at.isoformat(),
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return

    if not rows:
        console.print("[yellow]no tech detections found[/yellow]")
        return

    console.print(_render_tech_detections_table(rows))
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@show_app.command("tech-detections")
def show_tech_detections(
    target: str | None = typer.Argument(
        None, help="Target domain. Omit to show across all targets."
    ),
    tech: str | None = typer.Option(None, "--tech", help="Filter by exact tech name (e.g. PHP)."),
    url: str | None = typer.Option(None, "--url", help="Filter by exact URL."),
    limit: int = typer.Option(25, "--limit", help="Max rows to show. 0 = no limit."),
    all_rows: bool = typer.Option(False, "--all", help="Ignore --limit, show everything."),
    as_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of a table."),
) -> None:
    """List technology detections stored in the database."""
    effective_limit: int | None = None if all_rows or limit == 0 else limit
    asyncio.run(_show_tech_detections(target, tech, url, effective_limit, as_json))


_EXAMPLES = """\
[bold]Subdomain enumeration[/bold]
  wotd subdomains acme.com               full pipeline (passive → active → resolve → probe)
  wotd subdomains acme.com --notify      also dispatch discord / smtp notification

[bold]Crawl endpoints[/bold]
  wotd crawl https://acme.com            passive + active crawlers, stores new endpoints
  wotd crawl https://acme.com --notify   also dispatch notification on new endpoints

[bold]Inspect subdomains[/bold]
  wotd show subdomains acme.com                    probed hosts, last 25
  wotd show subdomains acme.com --all              every row, no limit
  wotd show subdomains acme.com --since 24h        found in the last day
  wotd show subdomains acme.com --include-unprobed include dns-only hosts
  wotd show subdomains acme.com --source subfinder filter by discovery source
  wotd show subdomains acme.com --json             raw json output
  wotd show subdomains                             across all targets

[bold]Inspect endpoints[/bold]
  wotd show endpoints acme.com                     latest 25 endpoints
  wotd show endpoints acme.com --all               every endpoint, no limit
  wotd show endpoints acme.com --since 24h         found in the last day
  wotd show endpoints acme.com --source katana     filter by crawler
  wotd show endpoints acme.com --host sub.acme.com filter by host
  wotd show endpoints acme.com --json              raw json output

[bold]Shortcuts[/bold]
  wotd ls subdomains acme.com            alias for wotd show subdomains
  wotd ls endpoints acme.com             alias for wotd show endpoints

[bold]Directory bruteforcing[/bold]
  wotd dirbust acme.com                      scan all live HTTP services + auto-tech passes
  wotd dirbust https://acme.com              scan only this URL + auto-tech passes
  wotd dirbust acme.com --tech grafana       force a specific tech pass on top of auto-tech
  wotd dirbust acme.com --notify             also dispatch notification on new/changed paths
  wotd show dir-results acme.com             latest 25 results
  wotd show dir-results acme.com --all       every result, no limit
  wotd show dir-results acme.com --status 200  filter by status code
  wotd show dir-results acme.com --wordlist tech_php  filter by wordlist pass
  wotd show dir-results acme.com --since 24h  found in the last day
  wotd show dir-results acme.com --json      raw json output

[bold]Tech detections[/bold]
  wotd tech-detect acme.com                     re-run httpx -tech-detect on all live hosts
  wotd tech-detect acme.com --notify            also dispatch notification on new detections
  wotd show tech-detections acme.com            latest 25 detections
  wotd show tech-detections acme.com --all      every row, no limit
  wotd show tech-detections acme.com --tech PHP filter by tech name
  wotd show tech-detections acme.com --json     raw json output

[bold]JS file discovery[/bold]
  wotd discover-js acme.com                    collect JS files from endpoints + subjs
  wotd discover-js acme.com --bruteforce-js    also ffuf every live host for unlinked JS
  wotd discover-js acme.com --notify           also dispatch notification on new JS files
  wotd show js-files acme.com           inspect downloaded JS files

[bold]Notifications[/bold]
  set WOTD_NOTIFY_DISCORD_WEBHOOK_URL in .env, then pass --notify
  set WOTD_NOTIFY_SMTP_* vars for email delivery
"""


@app.command()
def examples() -> None:
    """Print a cheat-sheet of common commands."""
    console.print(_EXAMPLES)


if __name__ == "__main__":
    app()
