from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from wotd.models import (
    DirResult,
    DnsRecord,
    Endpoint,
    HttpService,
    InterestingEndpoint,
    InterestingSubdomain,
    JsEndpoint,
    JsFile,
    JsSecret,
    ScanRun,
    Subdomain,
    Target,
)


@dataclass
class JsFileRow:
    url: str
    host: str
    sources: str
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass
class JsSecretRow:
    kind: str
    data: str
    severity: str | None
    context: str | None
    source_js_url: str
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass
class JsEndpointRow:
    url: str
    host: str
    method: str | None
    params: str | None
    source_js_url: str
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass
class InterestingSubdomainRow:
    fqdn: str
    pattern: str
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass
class InterestingEndpointRow:
    url: str
    host: str
    pattern: str
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass
class EndpointRow:
    url: str
    host: str
    source: str
    status_code: int | None
    content_type: str | None
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass
class SubdomainRow:
    host: str
    sources: str
    first_seen_at: datetime
    last_seen_at: datetime
    status_code: int | None
    title: str | None
    url: str | None


async def list_subdomains(
    session: AsyncSession,
    target_id: int | None = None,
    since: timedelta | None = None,
    source: str | None = None,
    probed_only: bool = True,
    limit: int | None = None,
) -> list[SubdomainRow]:
    """Query subdomains joined with probe data, most recently seen first.

    target_id: restrict to one target, or None for all targets
    since: only include rows first seen within this window
    source: only include rows whose sources column contains this tool name
    probed_only: drop rows with no matching http_services entry
    limit: cap results (None = no cap)
    """
    h = aliased(HttpService)
    stmt = (
        select(
            Subdomain.host,
            Subdomain.sources,
            Subdomain.first_seen_at,
            Subdomain.last_seen_at,
            h.status_code,
            h.title,
            h.url,
        )
        .select_from(Subdomain)
        .outerjoin(h, (h.target_id == Subdomain.target_id) & (h.host == Subdomain.host))
        .order_by(Subdomain.last_seen_at.desc())
    )

    if target_id is not None:
        stmt = stmt.where(Subdomain.target_id == target_id)
    if since is not None:
        cutoff = datetime.now(UTC) - since
        stmt = stmt.where(Subdomain.first_seen_at >= cutoff)
    if source is not None:
        stmt = stmt.where(Subdomain.sources.contains(source))
    if probed_only:
        stmt = stmt.where(h.id.isnot(None))
    if limit is not None:
        stmt = stmt.limit(limit)

    result = await session.execute(stmt)
    return [
        SubdomainRow(
            host=row[0],
            sources=row[1],
            first_seen_at=row[2],
            last_seen_at=row[3],
            status_code=row[4],
            title=row[5],
            url=row[6],
        )
        for row in result.all()
    ]


async def create_target(
    session: AsyncSession,
    name: str,
    root_domains: list[str],
    scope_config: dict | None = None,  # type: ignore[type-arg]
) -> Target:
    target = Target(
        name=name,
        root_domains=json.dumps(root_domains),
        scope_config=json.dumps(scope_config) if scope_config else None,
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


async def get_target(session: AsyncSession, target_id: int) -> Target | None:
    return await session.get(Target, target_id)


async def get_target_by_name(session: AsyncSession, name: str) -> Target | None:
    result = await session.execute(select(Target).where(Target.name == name))
    return result.scalar_one_or_none()


async def start_scan_run(
    session: AsyncSession,
    target_id: int,
    module: str,
) -> ScanRun:
    scan_run = ScanRun(target_id=target_id, module=module, status="running")
    session.add(scan_run)
    await session.commit()
    await session.refresh(scan_run)
    return scan_run


async def finish_scan_run(
    session: AsyncSession,
    scan_run: ScanRun,
    status: str = "completed",
    summary: dict | None = None,  # type: ignore[type-arg]
) -> None:
    scan_run.finished_at = datetime.now(UTC)
    scan_run.status = status
    if summary:
        scan_run.summary = json.dumps(summary)
    await session.commit()


async def upsert_subdomains(
    session: AsyncSession,
    target_id: int,
    host_to_sources: dict[str, set[str]],
) -> tuple[int, int, list[str]]:
    """Insert new subdomains, update sources and last_seen on existing ones.

    Returns (new_count, existing_count, new_hosts).
    """
    if not host_to_sources:
        return (0, 0, [])

    hosts = list(host_to_sources.keys())
    existing: dict[str, Subdomain] = {}
    for i in range(0, len(hosts), _SQLITE_MAX_VARS):
        chunk = hosts[i : i + _SQLITE_MAX_VARS]
        result = await session.execute(
            select(Subdomain).where(
                Subdomain.target_id == target_id,
                Subdomain.host.in_(chunk),
            )
        )
        for sd in result.scalars().all():
            existing[sd.host] = sd

    now = datetime.now(UTC)
    new_hosts: list[str] = []
    for host, sources in host_to_sources.items():
        row: Subdomain | None = existing.get(host)
        if row is None:
            session.add(
                Subdomain(
                    target_id=target_id,
                    host=host,
                    sources=",".join(sorted(sources)),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_hosts.append(host)
        else:
            merged = set(row.sources.split(",")) | sources
            row.sources = ",".join(sorted(merged))
            row.last_seen_at = now

    await session.commit()
    return (len(new_hosts), len(existing), new_hosts)


async def get_subdomain_hosts(session: AsyncSession, target_id: int) -> list[str]:
    """Return every known subdomain host for a target."""
    result = await session.execute(select(Subdomain.host).where(Subdomain.target_id == target_id))
    return [row[0] for row in result.all()]


async def upsert_dns_records(
    session: AsyncSession,
    target_id: int,
    records: list[tuple[str, str, str]],
) -> tuple[int, int]:
    """Insert new DNS records, refresh last_seen on existing ones.

    records is a list of (host, record_type, value) tuples.
    Returns (new_count, existing_count).
    """
    if not records:
        return (0, 0)

    unique_records = {(h, t, v) for h, t, v in records}

    result = await session.execute(select(DnsRecord).where(DnsRecord.target_id == target_id))
    existing = {(row.host, row.record_type, row.value): row for row in result.scalars().all()}

    now = datetime.now(UTC)
    new_count = 0
    existing_count = 0
    for host, record_type, value in unique_records:
        row = existing.get((host, record_type, value))
        if row is None:
            session.add(
                DnsRecord(
                    target_id=target_id,
                    host=host,
                    record_type=record_type,
                    value=value,
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_count += 1
        else:
            row.last_seen_at = now
            existing_count += 1

    await session.commit()
    return (new_count, existing_count)


async def get_resolved_hosts(session: AsyncSession, target_id: int) -> list[str]:
    """Return distinct hosts that have at least one DNS record for this target."""
    result = await session.execute(
        select(DnsRecord.host).where(DnsRecord.target_id == target_id).distinct()
    )
    return [row[0] for row in result.all()]


async def get_unprobed_hosts(session: AsyncSession, target_id: int) -> list[str]:
    """Return resolved hosts that have no http_services entry yet."""
    probed = await session.execute(
        select(HttpService.host).where(HttpService.target_id == target_id).distinct()
    )
    probed_set = {row[0] for row in probed.all()}
    all_resolved = await get_resolved_hosts(session, target_id)
    return [h for h in all_resolved if h not in probed_set]


async def get_http_service_urls(session: AsyncSession, target_id: int) -> list[str]:
    """Return all live HTTP service URLs for a target."""
    result = await session.execute(
        select(HttpService.url).where(HttpService.target_id == target_id).distinct()
    )
    return [row[0] for row in result.all()]


async def upsert_http_services(
    session: AsyncSession,
    target_id: int,
    services: list[dict[str, Any]],
) -> tuple[int, int]:
    """Insert or refresh http_service rows.

    Each dict must contain 'host' and 'url'; other fields are optional.
    Returns (new_count, existing_count).
    """
    if not services:
        return (0, 0)

    urls = [str(s["url"]) for s in services]
    result = await session.execute(
        select(HttpService).where(
            HttpService.target_id == target_id,
            HttpService.url.in_(urls),
        )
    )
    existing = {row.url: row for row in result.scalars().all()}

    now = datetime.now(UTC)
    new_count = 0
    for svc in services:
        url = str(svc["url"])
        row = existing.get(url)
        if row is None:
            session.add(
                HttpService(
                    target_id=target_id,
                    host=str(svc["host"]),
                    url=url,
                    status_code=svc.get("status_code"),
                    title=svc.get("title"),
                    tech=svc.get("tech"),
                    content_length=svc.get("content_length"),
                    final_url=svc.get("final_url"),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_count += 1
        else:
            row.status_code = svc.get("status_code")
            row.title = svc.get("title")
            row.tech = svc.get("tech")
            row.content_length = svc.get("content_length")
            row.final_url = svc.get("final_url")
            row.last_seen_at = now

    await session.commit()
    return (new_count, len(existing))


_SQLITE_MAX_VARS = 500


async def upsert_endpoints(
    session: AsyncSession,
    target_id: int,
    endpoints: list[dict[str, Any]],
) -> tuple[int, int, list[str]]:
    """Insert new endpoints, refresh last_seen on existing ones.

    Each dict must contain 'url', 'host', and 'source'; other fields optional.
    Returns (new_count, existing_count, new_urls).
    """
    if not endpoints:
        return (0, 0, [])

    # Fetch existing rows in batches to stay under SQLite's variable limit.
    existing: dict[str, Endpoint | None] = {}
    urls = [str(e["url"]) for e in endpoints]
    for i in range(0, len(urls), _SQLITE_MAX_VARS):
        chunk = urls[i : i + _SQLITE_MAX_VARS]
        result = await session.execute(
            select(Endpoint).where(
                Endpoint.target_id == target_id,
                Endpoint.url.in_(chunk),
            )
        )
        for row in result.scalars().all():
            existing[row.url] = row

    now = datetime.now(UTC)
    new_urls: list[str] = []
    for ep in endpoints:
        url = str(ep["url"])
        existing_row: Endpoint | None = existing.get(url)
        if existing_row is None:
            session.add(
                Endpoint(
                    target_id=target_id,
                    url=url,
                    host=str(ep["host"]),
                    source=str(ep["source"]),
                    status_code=ep.get("status_code"),
                    content_type=ep.get("content_type"),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_urls.append(url)
        else:
            existing_row.last_seen_at = now

    await session.commit()
    return (len(new_urls), len(existing), new_urls)


async def list_endpoints(
    session: AsyncSession,
    target_id: int | None = None,
    since: timedelta | None = None,
    source: str | None = None,
    host: str | None = None,
    limit: int | None = None,
) -> list[EndpointRow]:
    stmt = select(
        Endpoint.url,
        Endpoint.host,
        Endpoint.source,
        Endpoint.status_code,
        Endpoint.content_type,
        Endpoint.first_seen_at,
        Endpoint.last_seen_at,
    ).order_by(Endpoint.first_seen_at.desc())
    if target_id is not None:
        stmt = stmt.where(Endpoint.target_id == target_id)
    if since is not None:
        stmt = stmt.where(Endpoint.first_seen_at >= datetime.now(UTC) - since)
    if source is not None:
        stmt = stmt.where(Endpoint.source.contains(source))
    if host is not None:
        stmt = stmt.where(Endpoint.host == host)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return [
        EndpointRow(
            url=r[0],
            host=r[1],
            source=r[2],
            status_code=r[3],
            content_type=r[4],
            first_seen_at=r[5],
            last_seen_at=r[6],
        )
        for r in result.all()
    ]


async def has_prior_scan(session: AsyncSession, target_id: int, module: str) -> bool:
    """Return True if at least one completed scan run exists for this target+module."""
    result = await session.execute(
        select(ScanRun.id)
        .where(
            ScanRun.target_id == target_id,
            ScanRun.module == module,
            ScanRun.status == "completed",
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def get_previous_scan_run(
    session: AsyncSession,
    target_id: int,
    module: str,
    before: int | None = None,
) -> ScanRun | None:
    """Get the most recent completed scan run for a target+module,
    optionally before a given run id."""
    query = (
        select(ScanRun)
        .where(
            ScanRun.target_id == target_id,
            ScanRun.module == module,
            ScanRun.status == "completed",
        )
        .order_by(ScanRun.started_at.desc())
    )
    if before is not None:
        query = query.where(ScanRun.id < before)
    query = query.limit(1)
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def get_js_urls_from_endpoints(session: AsyncSession, target_id: int) -> list[str]:
    """Return .js endpoint URLs already discovered for this target."""
    result = await session.execute(
        select(Endpoint.url).where(
            Endpoint.target_id == target_id,
            Endpoint.url.like("%.js"),
        )
    )
    return [row[0] for row in result.all()]


async def upsert_js_files(
    session: AsyncSession,
    target_id: int,
    files: list[dict[str, Any]],
) -> tuple[int, int, list[str]]:
    """Insert new JS files, refresh last_seen and update content on existing ones.

    Each dict must contain 'url', 'host', 'sources'; other fields optional.
    Returns (new_count, existing_count, new_urls).
    """
    if not files:
        return (0, 0, [])

    urls = [str(f["url"]) for f in files]
    existing: dict[str, JsFile] = {}
    for i in range(0, len(urls), _SQLITE_MAX_VARS):
        chunk = urls[i : i + _SQLITE_MAX_VARS]
        result = await session.execute(
            select(JsFile).where(
                JsFile.target_id == target_id,
                JsFile.url.in_(chunk),
            )
        )
        for jf in result.scalars().all():
            existing[jf.url] = jf

    now = datetime.now(UTC)
    new_urls: list[str] = []
    for f in files:
        url = str(f["url"])
        row: JsFile | None = existing.get(url)
        if row is None:
            session.add(
                JsFile(
                    target_id=target_id,
                    url=url,
                    host=str(f["host"]),
                    sources=str(f.get("sources", "")),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_urls.append(url)
        else:
            merged = set(row.sources.split(",")) | set(str(f.get("sources", "")).split(","))
            merged.discard("")
            row.sources = ",".join(sorted(merged))
            row.last_seen_at = now

    await session.commit()
    return (len(new_urls), len(existing), new_urls)


async def get_js_file_urls(session: AsyncSession, target_id: int) -> list[str]:
    """Return all JS file URLs stored for this target."""
    result = await session.execute(
        select(JsFile.url).where(JsFile.target_id == target_id)
    )
    return [row[0] for row in result.all()]


async def upsert_js_endpoints(
    session: AsyncSession,
    target_id: int,
    endpoints: list[dict[str, Any]],
) -> tuple[int, int, list[str]]:
    """Insert new JS endpoints, refresh last_seen on existing ones.

    Each dict must contain 'url', 'host', 'source_js_url'; other fields optional.
    Returns (new_count, existing_count, new_urls).
    """
    if not endpoints:
        return (0, 0, [])

    urls = [str(e["url"]) for e in endpoints]
    existing: dict[str, JsEndpoint] = {}
    for i in range(0, len(urls), _SQLITE_MAX_VARS):
        chunk = urls[i : i + _SQLITE_MAX_VARS]
        result = await session.execute(
            select(JsEndpoint).where(
                JsEndpoint.target_id == target_id,
                JsEndpoint.url.in_(chunk),
            )
        )
        for ep in result.scalars().all():
            existing[ep.url] = ep

    now = datetime.now(UTC)
    new_urls: list[str] = []
    for e in endpoints:
        url = str(e["url"])
        row: JsEndpoint | None = existing.get(url)
        if row is None:
            session.add(
                JsEndpoint(
                    target_id=target_id,
                    url=url,
                    host=str(e["host"]),
                    method=e.get("method"),
                    params=e.get("params"),
                    source_js_url=str(e["source_js_url"]),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_urls.append(url)
        else:
            row.method = e.get("method")
            row.params = e.get("params")
            row.last_seen_at = now

    await session.commit()
    return (len(new_urls), len(existing), new_urls)


async def list_js_endpoints(
    session: AsyncSession,
    target_id: int | None = None,
    host: str | None = None,
    limit: int | None = None,
) -> list[JsEndpointRow]:
    stmt = select(
        JsEndpoint.url,
        JsEndpoint.host,
        JsEndpoint.method,
        JsEndpoint.params,
        JsEndpoint.source_js_url,
        JsEndpoint.first_seen_at,
        JsEndpoint.last_seen_at,
    ).order_by(JsEndpoint.first_seen_at.desc())
    if target_id is not None:
        stmt = stmt.where(JsEndpoint.target_id == target_id)
    if host is not None:
        stmt = stmt.where(JsEndpoint.host == host)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return [
        JsEndpointRow(
            url=r[0],
            host=r[1],
            method=r[2],
            params=r[3],
            source_js_url=r[4],
            first_seen_at=r[5],
            last_seen_at=r[6],
        )
        for r in result.all()
    ]


async def upsert_js_secrets(
    session: AsyncSession,
    target_id: int,
    secrets: list[dict[str, Any]],
) -> tuple[int, int]:
    """Insert new JS secrets, refresh last_seen on existing ones.

    Each dict must contain 'source_js_url', 'kind', 'data'; other fields optional.
    Returns (new_count, existing_count).
    """
    if not secrets:
        return (0, 0)

    keys = [(str(s["source_js_url"]), str(s["kind"]), str(s["data"])) for s in secrets]
    result = await session.execute(
        select(JsSecret).where(JsSecret.target_id == target_id)
    )
    existing = {
        (r.source_js_url, r.kind, r.data): r for r in result.scalars().all()
    }

    now = datetime.now(UTC)
    new_count = 0
    existing_count = 0
    for s, key in zip(secrets, keys, strict=True):
        row: JsSecret | None = existing.get(key)
        if row is None:
            session.add(
                JsSecret(
                    target_id=target_id,
                    source_js_url=key[0],
                    kind=key[1],
                    data=key[2],
                    severity=s.get("severity"),
                    context=s.get("context"),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_count += 1
        else:
            row.last_seen_at = now
            existing_count += 1

    await session.commit()
    return (new_count, existing_count)


async def list_js_secrets(
    session: AsyncSession,
    target_id: int | None = None,
    kind: str | None = None,
    severity: str | None = None,
    limit: int | None = None,
) -> list[JsSecretRow]:
    stmt = select(
        JsSecret.kind,
        JsSecret.data,
        JsSecret.severity,
        JsSecret.context,
        JsSecret.source_js_url,
        JsSecret.first_seen_at,
        JsSecret.last_seen_at,
    ).order_by(JsSecret.first_seen_at.desc())
    if target_id is not None:
        stmt = stmt.where(JsSecret.target_id == target_id)
    if kind is not None:
        stmt = stmt.where(JsSecret.kind == kind)
    if severity is not None:
        stmt = stmt.where(JsSecret.severity == severity)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return [
        JsSecretRow(
            kind=r[0],
            data=r[1],
            severity=r[2],
            context=r[3],
            source_js_url=r[4],
            first_seen_at=r[5],
            last_seen_at=r[6],
        )
        for r in result.all()
    ]


async def upsert_interesting_subdomains(
    session: AsyncSession,
    target_id: int,
    findings: list[dict[str, Any]],
) -> tuple[int, int]:
    """Insert new interesting subdomain pattern matches, refresh last_seen on existing ones.

    Each dict must contain 'fqdn' and 'pattern'.
    Returns (new_count, existing_count).
    """
    if not findings:
        return (0, 0)

    seen: set[tuple[str, str]] = set()
    unique = []
    for f in findings:
        key = (str(f["fqdn"]), str(f["pattern"]))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    result = await session.execute(
        select(InterestingSubdomain).where(InterestingSubdomain.target_id == target_id)
    )
    existing = {(r.fqdn, r.pattern): r for r in result.scalars().all()}

    now = datetime.now(UTC)
    new_count = 0
    existing_count = 0
    for f in unique:
        key = (str(f["fqdn"]), str(f["pattern"]))
        row: InterestingSubdomain | None = existing.get(key)
        if row is None:
            session.add(
                InterestingSubdomain(
                    target_id=target_id,
                    fqdn=key[0],
                    pattern=key[1],
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_count += 1
        else:
            row.last_seen_at = now
            existing_count += 1

    await session.commit()
    return (new_count, existing_count)


async def list_interesting_subdomains(
    session: AsyncSession,
    target_id: int | None = None,
    pattern: str | None = None,
    limit: int | None = None,
) -> list[InterestingSubdomainRow]:
    stmt = select(
        InterestingSubdomain.fqdn,
        InterestingSubdomain.pattern,
        InterestingSubdomain.first_seen_at,
        InterestingSubdomain.last_seen_at,
    ).order_by(InterestingSubdomain.first_seen_at.desc())
    if target_id is not None:
        stmt = stmt.where(InterestingSubdomain.target_id == target_id)
    if pattern is not None:
        stmt = stmt.where(InterestingSubdomain.pattern == pattern)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return [
        InterestingSubdomainRow(
            fqdn=r[0],
            pattern=r[1],
            first_seen_at=r[2],
            last_seen_at=r[3],
        )
        for r in result.all()
    ]


async def upsert_interesting_endpoints(
    session: AsyncSession,
    target_id: int,
    findings: list[dict[str, Any]],
) -> tuple[int, int]:
    """Insert new interesting endpoint pattern matches, refresh last_seen on existing ones.

    Each dict must contain 'url', 'host', 'pattern'.
    Returns (new_count, existing_count).
    """
    if not findings:
        return (0, 0)

    seen: set[tuple[str, str]] = set()
    unique = []
    for f in findings:
        key = (str(f["url"]), str(f["pattern"]))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    result = await session.execute(
        select(InterestingEndpoint).where(InterestingEndpoint.target_id == target_id)
    )
    existing = {(r.url, r.pattern): r for r in result.scalars().all()}

    now = datetime.now(UTC)
    new_count = 0
    existing_count = 0
    for f in unique:
        key = (str(f["url"]), str(f["pattern"]))
        row: InterestingEndpoint | None = existing.get(key)
        if row is None:
            session.add(
                InterestingEndpoint(
                    target_id=target_id,
                    url=key[0],
                    host=str(f.get("host", "")),
                    pattern=key[1],
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_count += 1
        else:
            row.last_seen_at = now
            existing_count += 1

    await session.commit()
    return (new_count, existing_count)


async def list_interesting_endpoints(
    session: AsyncSession,
    target_id: int | None = None,
    pattern: str | None = None,
    host: str | None = None,
    limit: int | None = None,
) -> list[InterestingEndpointRow]:
    stmt = select(
        InterestingEndpoint.url,
        InterestingEndpoint.host,
        InterestingEndpoint.pattern,
        InterestingEndpoint.first_seen_at,
        InterestingEndpoint.last_seen_at,
    ).order_by(InterestingEndpoint.first_seen_at.desc())
    if target_id is not None:
        stmt = stmt.where(InterestingEndpoint.target_id == target_id)
    if pattern is not None:
        stmt = stmt.where(InterestingEndpoint.pattern == pattern)
    if host is not None:
        stmt = stmt.where(InterestingEndpoint.host == host)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return [
        InterestingEndpointRow(
            url=r[0],
            host=r[1],
            pattern=r[2],
            first_seen_at=r[3],
            last_seen_at=r[4],
        )
        for r in result.all()
    ]


async def list_js_files(
    session: AsyncSession,
    target_id: int | None = None,
    limit: int | None = None,
) -> list[JsFileRow]:
    stmt = select(
        JsFile.url,
        JsFile.host,
        JsFile.sources,
        JsFile.first_seen_at,
        JsFile.last_seen_at,
    ).order_by(JsFile.first_seen_at.desc())
    if target_id is not None:
        stmt = stmt.where(JsFile.target_id == target_id)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return [
        JsFileRow(
            url=r[0],
            host=r[1],
            sources=r[2],
            first_seen_at=r[3],
            last_seen_at=r[4],
        )
        for r in result.all()
    ]


@dataclass
class DirResultRow:
    url: str
    base_url: str
    status_code: int
    first_seen_at: datetime
    last_seen_at: datetime
    wordlist: str | None = None


async def upsert_dir_results(
    session: AsyncSession,
    target_id: int,
    findings: list[dict[str, Any]],
) -> tuple[int, int, list[str], list[str]]:
    """Upsert dir bruteforce results. Returns (new, existing, new_urls, changed_urls).

    changed_urls contains URLs whose HTTP status code changed since last scan.
    """
    if not findings:
        return 0, 0, [], []

    existing_rows = await session.execute(
        select(DirResult.url, DirResult.status_code).where(DirResult.target_id == target_id)
    )
    existing: dict[str, int] = {row[0]: row[1] for row in existing_rows.all()}

    now = datetime.now(UTC)
    new_count = 0
    existing_count = 0
    new_urls: list[str] = []
    changed_urls: list[str] = []

    for f in findings:
        url = f["url"]
        new_status = int(f["status_code"])
        if url not in existing:
            session.add(
                DirResult(
                    target_id=target_id,
                    url=url,
                    base_url=f["base_url"],
                    status_code=new_status,
                    wordlist=f.get("wordlist"),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_count += 1
            new_urls.append(url)
        else:
            row = (
                await session.execute(
                    select(DirResult).where(
                        DirResult.target_id == target_id, DirResult.url == url
                    )
                )
            ).scalar_one()
            if row.status_code != new_status:
                changed_urls.append(url)
            row.status_code = new_status
            row.last_seen_at = now
            existing_count += 1

    await session.commit()
    return new_count, existing_count, new_urls, changed_urls


async def list_dir_results(
    session: AsyncSession,
    target_id: int | None,
    since: timedelta | None = None,
    status_code: int | None = None,
    host: str | None = None,
    wordlist: str | None = None,
    limit: int | None = 25,
) -> list[DirResultRow]:
    stmt = select(
        DirResult.url,
        DirResult.base_url,
        DirResult.status_code,
        DirResult.first_seen_at,
        DirResult.last_seen_at,
        DirResult.wordlist,
    ).order_by(DirResult.first_seen_at.desc())

    if target_id is not None:
        stmt = stmt.where(DirResult.target_id == target_id)
    if since is not None:
        stmt = stmt.where(DirResult.first_seen_at >= datetime.now(UTC) - since)
    if status_code is not None:
        stmt = stmt.where(DirResult.status_code == status_code)
    if host is not None:
        stmt = stmt.where(DirResult.url.like(f"%://{host}/%"))
    if wordlist is not None:
        stmt = stmt.where(DirResult.wordlist == wordlist)
    if limit is not None:
        stmt = stmt.limit(limit)

    result = await session.execute(stmt)
    return [
        DirResultRow(
            url=r[0],
            base_url=r[1],
            status_code=r[2],
            first_seen_at=r[3],
            last_seen_at=r[4],
            wordlist=r[5],
        )
        for r in result.all()
    ]
