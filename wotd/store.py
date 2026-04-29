from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from wotd.models import (
    ApiRoute,
    ApiSpec,
    DirResult,
    DnsRecord,
    Endpoint,
    EndpointSnapshot,
    GraphqlEndpoint,
    HttpService,
    InterestingEndpoint,
    InterestingSubdomain,
    JsEndpoint,
    JsFile,
    JsSecret,
    ScanRun,
    ServiceFingerprint,
    ServiceScreenshot,
    Subdomain,
    SubdomainCandidate,
    TaskRunLog,
    Target,
    TechDetection,
    VhostService,
    WebProfile,
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


@dataclass
class SubdomainCandidateRow:
    fqdn: str
    source: str
    generator: str
    status: str
    generated_at: datetime
    resolved_at: datetime | None


@dataclass
class EndpointSnapshotRow:
    url: str
    status_code: int | None
    content_type: str | None
    body_hash: str | None
    title: str | None
    observed_at: datetime


@dataclass
class EndpointDeltaRow:
    url: str
    kind: str
    old_value: str | None
    new_value: str | None
    observed_at: datetime


@dataclass
class WebProfileRow:
    url: str
    status_code: int | None
    title: str | None
    server: str | None
    csp: str | None
    hsts: str | None
    cors: str | None
    set_cookie_raw: str | None
    cookie_flags_json: str | None
    headers_json: str | None
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass
class ServiceFingerprintRow:
    url: str
    favicon_hash: str | None
    body_hash: str | None
    title_hash: str | None
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass
class VhostServiceRow:
    base_url: str
    vhost: str
    url: str
    status_code: int | None
    title: str | None
    content_length: int | None
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass
class ServiceScreenshotRow:
    host: str
    url: str
    screenshot_path: str
    phash: str
    width: int
    height: int
    first_seen_at: datetime
    last_seen_at: datetime


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


async def log_task_run(
    session: AsyncSession,
    *,
    task_id: str,
    parent_task_id: str | None,
    source_module: str | None,
    input_hash: str,
    output_count: int,
    status: str,
    started_at: datetime,
    finished_at: datetime | None,
) -> None:
    session.add(
        TaskRunLog(
            task_id=task_id,
            parent_task_id=parent_task_id,
            source_module=source_module,
            input_hash=input_hash,
            output_count=output_count,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
        )
    )
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


async def upsert_subdomain_candidates(
    session: AsyncSession,
    target_id: int,
    candidates: list[dict[str, str]],
) -> tuple[int, int, list[str]]:
    """Insert new subdomain candidates, preserving existing statuses for resume support."""
    if not candidates:
        return (0, 0, [])

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for candidate in candidates:
        key = (candidate["fqdn"], candidate["generator"])
        if key not in seen:
            seen.add(key)
            unique.append(candidate)

    fqdns = [candidate["fqdn"] for candidate in unique]
    existing: dict[tuple[str, str], SubdomainCandidate] = {}
    for i in range(0, len(fqdns), _SQLITE_MAX_VARS):
        chunk = fqdns[i : i + _SQLITE_MAX_VARS]
        result = await session.execute(
            select(SubdomainCandidate).where(
                SubdomainCandidate.target_id == target_id,
                SubdomainCandidate.fqdn.in_(chunk),
            )
        )
        for row in result.scalars().all():
            existing[(row.fqdn, row.generator)] = row

    now = datetime.now(UTC)
    new_fqdns: list[str] = []
    for candidate in unique:
        key = (candidate["fqdn"], candidate["generator"])
        row = existing.get(key)
        if row is None:
            session.add(
                SubdomainCandidate(
                    target_id=target_id,
                    fqdn=candidate["fqdn"],
                    source=candidate["source"],
                    generator=candidate["generator"],
                    status=candidate["status"],
                    generated_at=now,
                    resolved_at=None,
                )
            )
            new_fqdns.append(candidate["fqdn"])
        else:
            row.source = candidate["source"]

    await session.commit()
    return (len(new_fqdns), len(existing), new_fqdns)


async def list_subdomain_candidates(
    session: AsyncSession,
    target_id: int | None = None,
    status: str | None = None,
    source: str | None = None,
    generator: str | None = None,
    since: timedelta | None = None,
    limit: int | None = 25,
) -> list[SubdomainCandidateRow]:
    stmt = select(
        SubdomainCandidate.fqdn,
        SubdomainCandidate.source,
        SubdomainCandidate.generator,
        SubdomainCandidate.status,
        SubdomainCandidate.generated_at,
        SubdomainCandidate.resolved_at,
    ).order_by(SubdomainCandidate.generated_at.desc())

    if target_id is not None:
        stmt = stmt.where(SubdomainCandidate.target_id == target_id)
    if status is not None:
        stmt = stmt.where(SubdomainCandidate.status == status)
    if source is not None:
        stmt = stmt.where(SubdomainCandidate.source == source)
    if generator is not None:
        stmt = stmt.where(SubdomainCandidate.generator == generator)
    if since is not None:
        stmt = stmt.where(SubdomainCandidate.generated_at >= datetime.now(UTC) - since)
    if limit is not None:
        stmt = stmt.limit(limit)

    result = await session.execute(stmt)
    return [
        SubdomainCandidateRow(
            fqdn=row[0],
            source=row[1],
            generator=row[2],
            status=row[3],
            generated_at=row[4],
            resolved_at=row[5],
        )
        for row in result.all()
    ]


async def get_pending_subdomain_candidates(
    session: AsyncSession,
    target_id: int,
    generator: str,
    limit: int,
) -> list[str]:
    stmt = (
        select(SubdomainCandidate.fqdn)
        .where(
            SubdomainCandidate.target_id == target_id,
            SubdomainCandidate.generator == generator,
            SubdomainCandidate.status == "generated",
        )
        .order_by(SubdomainCandidate.generated_at.asc(), SubdomainCandidate.fqdn.asc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    return [row[0] for row in result.all()]


async def count_pending_subdomain_candidates(
    session: AsyncSession,
    target_id: int,
    generator: str,
) -> int:
    stmt = select(SubdomainCandidate.id).where(
        SubdomainCandidate.target_id == target_id,
        SubdomainCandidate.generator == generator,
        SubdomainCandidate.status == "generated",
    )
    result = await session.execute(stmt)
    return len(result.all())


async def update_subdomain_candidate_statuses(
    session: AsyncSession,
    target_id: int,
    generator: str,
    fqdns: list[str],
    status: str,
    resolved_at: datetime | None = None,
) -> int:
    if not fqdns:
        return 0

    updated = 0
    for i in range(0, len(fqdns), _SQLITE_MAX_VARS):
        chunk = fqdns[i : i + _SQLITE_MAX_VARS]
        result = await session.execute(
            select(SubdomainCandidate).where(
                SubdomainCandidate.target_id == target_id,
                SubdomainCandidate.generator == generator,
                SubdomainCandidate.fqdn.in_(chunk),
            )
        )
        for row in result.scalars().all():
            row.status = status
            row.resolved_at = resolved_at
            updated += 1

    await session.commit()
    return updated


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
    result = await session.execute(select(JsFile.url).where(JsFile.target_id == target_id))
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
    result = await session.execute(select(JsSecret).where(JsSecret.target_id == target_id))
    existing = {(r.source_js_url, r.kind, r.data): r for r in result.scalars().all()}

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
                    select(DirResult).where(DirResult.target_id == target_id, DirResult.url == url)
                )
            ).scalar_one()
            if row.status_code != new_status:
                changed_urls.append(url)
            row.status_code = new_status
            row.last_seen_at = now
            existing_count += 1

    await session.commit()
    return new_count, existing_count, new_urls, changed_urls


async def upsert_vhost_services(
    session: AsyncSession,
    target_id: int,
    services: list[dict[str, Any]],
) -> tuple[int, int, list[str]]:
    """Upsert vhost_service rows. Returns (new_count, existing_count, new_urls)."""
    if not services:
        return (0, 0, [])

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for svc in services:
        key = (str(svc["base_url"]), str(svc["vhost"]))
        if key not in seen:
            seen.add(key)
            unique.append(svc)

    existing = await session.execute(
        select(VhostService).where(VhostService.target_id == target_id)
    )
    by_key = {(row.base_url, row.vhost): row for row in existing.scalars().all()}

    now = datetime.now(UTC)
    new_urls: list[str] = []
    existing_count = 0
    for svc in unique:
        base_url = str(svc["base_url"])
        vhost = str(svc["vhost"])
        row = by_key.get((base_url, vhost))
        if row is None:
            session.add(
                VhostService(
                    target_id=target_id,
                    base_url=base_url,
                    vhost=vhost,
                    url=str(svc["url"]),
                    status_code=svc.get("status_code"),
                    title=svc.get("title"),
                    content_length=svc.get("content_length"),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_urls.append(str(svc["url"]))
        else:
            row.url = str(svc["url"])
            row.status_code = svc.get("status_code")
            row.title = svc.get("title")
            row.content_length = svc.get("content_length")
            row.last_seen_at = now
            existing_count += 1

    await session.commit()
    return (len(new_urls), existing_count, new_urls)


async def list_vhost_services(
    session: AsyncSession,
    target_id: int | None = None,
    base_url: str | None = None,
    vhost: str | None = None,
    status_code: int | None = None,
    since: timedelta | None = None,
    limit: int | None = 25,
) -> list[VhostServiceRow]:
    stmt = select(
        VhostService.base_url,
        VhostService.vhost,
        VhostService.url,
        VhostService.status_code,
        VhostService.title,
        VhostService.content_length,
        VhostService.first_seen_at,
        VhostService.last_seen_at,
    ).order_by(VhostService.first_seen_at.desc())

    if target_id is not None:
        stmt = stmt.where(VhostService.target_id == target_id)
    if base_url is not None:
        stmt = stmt.where(VhostService.base_url == base_url)
    if vhost is not None:
        stmt = stmt.where(VhostService.vhost == vhost)
    if status_code is not None:
        stmt = stmt.where(VhostService.status_code == status_code)
    if since is not None:
        stmt = stmt.where(VhostService.first_seen_at >= datetime.now(UTC) - since)
    if limit is not None:
        stmt = stmt.limit(limit)

    result = await session.execute(stmt)
    return [
        VhostServiceRow(
            base_url=r[0],
            vhost=r[1],
            url=r[2],
            status_code=r[3],
            title=r[4],
            content_length=r[5],
            first_seen_at=r[6],
            last_seen_at=r[7],
        )
        for r in result.all()
    ]


@dataclass
class TechDetectionRow:
    url: str
    tech: str
    source: str
    wordlist_key: str | None
    first_seen_at: datetime
    last_seen_at: datetime


async def upsert_tech_detections(
    session: AsyncSession,
    target_id: int,
    detections: list[dict[str, Any]],
) -> tuple[int, int]:
    """Upsert tech detection rows. Returns (new_count, existing_count).

    Each dict must contain 'url' and 'tech'; 'source' and 'wordlist_key' are optional.
    """
    if not detections:
        return (0, 0)

    seen: set[tuple[str, str]] = set()
    unique = []
    for d in detections:
        key = (str(d["url"]), str(d["tech"]))
        if key not in seen:
            seen.add(key)
            unique.append(d)

    result = await session.execute(
        select(TechDetection).where(TechDetection.target_id == target_id)
    )
    existing = {(r.url, r.tech): r for r in result.scalars().all()}

    now = datetime.now(UTC)
    new_count = 0
    existing_count = 0
    for d in unique:
        key = (str(d["url"]), str(d["tech"]))
        row: TechDetection | None = existing.get(key)
        if row is None:
            session.add(
                TechDetection(
                    target_id=target_id,
                    url=key[0],
                    tech=key[1],
                    source=str(d.get("source", "")),
                    wordlist_key=d.get("wordlist_key"),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_count += 1
        else:
            row.last_seen_at = now
            new_wordlist_key = d.get("wordlist_key")
            if row.wordlist_key is None and new_wordlist_key is not None:
                row.wordlist_key = new_wordlist_key
            existing_count += 1

    await session.commit()
    return (new_count, existing_count)


async def get_tech_wordlist_keys(session: AsyncSession, target_id: int) -> list[str]:
    """Return distinct non-null wordlist_key values for a target's tech detections."""
    result = await session.execute(
        select(TechDetection.wordlist_key)
        .where(
            TechDetection.target_id == target_id,
            TechDetection.wordlist_key.isnot(None),
        )
        .distinct()
    )
    return sorted({row[0] for row in result.all() if row[0]})


async def list_tech_detections(
    session: AsyncSession,
    target_id: int | None = None,
    tech: str | None = None,
    source: str | None = None,
    url: str | None = None,
    limit: int | None = 25,
) -> list[TechDetectionRow]:
    stmt = select(
        TechDetection.url,
        TechDetection.tech,
        TechDetection.source,
        TechDetection.wordlist_key,
        TechDetection.first_seen_at,
        TechDetection.last_seen_at,
    ).order_by(TechDetection.first_seen_at.desc())
    if target_id is not None:
        stmt = stmt.where(TechDetection.target_id == target_id)
    if tech is not None:
        stmt = stmt.where(TechDetection.tech == tech)
    if source is not None:
        stmt = stmt.where(TechDetection.source == source)
    if url is not None:
        stmt = stmt.where(TechDetection.url == url)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return [
        TechDetectionRow(
            url=r[0],
            tech=r[1],
            source=r[2],
            wordlist_key=r[3],
            first_seen_at=r[4],
            last_seen_at=r[5],
        )
        for r in result.all()
    ]


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


@dataclass
class ApiRouteRow:
    url: str
    host: str
    method: str
    status_code: int | None
    content_type: str | None
    source: str
    spec_url: str | None
    first_seen_at: datetime
    last_seen_at: datetime


async def upsert_api_routes(
    session: AsyncSession,
    target_id: int,
    routes: list[dict[str, Any]],
) -> tuple[int, int, list[str]]:
    """Upsert api_route rows. Unique on (target_id, url, method).

    Source is preserved on existing rows so the first-discovery source wins;
    status_code, content_type, and spec_url refresh on each call.
    Returns (new_count, existing_count, new_keys) where each entry in new_keys
    is "METHOD url" for the newly inserted row.
    """
    if not routes:
        return (0, 0, [])

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for r in routes:
        key = (str(r["url"]), str(r["method"]).upper())
        if key not in seen:
            seen.add(key)
            unique.append(r)

    urls = list({k[0] for k in seen})
    existing: dict[tuple[str, str], ApiRoute] = {}
    for i in range(0, len(urls), _SQLITE_MAX_VARS):
        chunk = urls[i : i + _SQLITE_MAX_VARS]
        result = await session.execute(
            select(ApiRoute).where(
                ApiRoute.target_id == target_id,
                ApiRoute.url.in_(chunk),
            )
        )
        for ar in result.scalars().all():
            existing[(ar.url, ar.method)] = ar

    now = datetime.now(UTC)
    new_count = 0
    new_keys: list[str] = []
    for r in unique:
        url = str(r["url"])
        method = str(r["method"]).upper()
        row: ApiRoute | None = existing.get((url, method))
        if row is None:
            session.add(
                ApiRoute(
                    target_id=target_id,
                    url=url,
                    host=str(r["host"]),
                    method=method,
                    status_code=r.get("status_code"),
                    content_type=r.get("content_type"),
                    source=str(r["source"]),
                    spec_url=r.get("spec_url"),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_count += 1
            new_keys.append(f"{method} {url}")
        else:
            row.last_seen_at = now
            new_status = r.get("status_code")
            if new_status is not None:
                row.status_code = int(new_status)
            new_ct = r.get("content_type")
            if new_ct is not None:
                row.content_type = str(new_ct)
            new_spec_url = r.get("spec_url")
            if new_spec_url is not None and row.spec_url is None:
                row.spec_url = str(new_spec_url)

    await session.commit()
    return (new_count, len(existing), new_keys)


async def list_api_routes(
    session: AsyncSession,
    target_id: int | None = None,
    host: str | None = None,
    method: str | None = None,
    source: str | None = None,
    status_code: int | None = None,
    since: timedelta | None = None,
    limit: int | None = 25,
) -> list[ApiRouteRow]:
    stmt = select(
        ApiRoute.url,
        ApiRoute.host,
        ApiRoute.method,
        ApiRoute.status_code,
        ApiRoute.content_type,
        ApiRoute.source,
        ApiRoute.spec_url,
        ApiRoute.first_seen_at,
        ApiRoute.last_seen_at,
    ).order_by(ApiRoute.first_seen_at.desc())
    if target_id is not None:
        stmt = stmt.where(ApiRoute.target_id == target_id)
    if host is not None:
        stmt = stmt.where(ApiRoute.host == host)
    if method is not None:
        stmt = stmt.where(ApiRoute.method == method.upper())
    if source is not None:
        stmt = stmt.where(ApiRoute.source == source)
    if status_code is not None:
        stmt = stmt.where(ApiRoute.status_code == status_code)
    if since is not None:
        stmt = stmt.where(ApiRoute.first_seen_at >= datetime.now(UTC) - since)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return [
        ApiRouteRow(
            url=r[0],
            host=r[1],
            method=r[2],
            status_code=r[3],
            content_type=r[4],
            source=r[5],
            spec_url=r[6],
            first_seen_at=r[7],
            last_seen_at=r[8],
        )
        for r in result.all()
    ]


@dataclass
class GraphqlEndpointRow:
    url: str
    host: str
    introspection_enabled: bool
    server_type: str | None
    schema_json: str | None
    first_seen_at: datetime
    last_seen_at: datetime


async def upsert_graphql_endpoints(
    session: AsyncSession,
    target_id: int,
    endpoints: list[dict[str, Any]],
) -> tuple[int, int, list[str]]:
    """Upsert graphql_endpoint rows. Unique on (target_id, url).

    Returns (new_count, existing_count, new_urls).
    """
    if not endpoints:
        return (0, 0, [])

    urls = [str(e["url"]) for e in endpoints]
    existing: dict[str, GraphqlEndpoint] = {}
    for i in range(0, len(urls), _SQLITE_MAX_VARS):
        chunk = urls[i : i + _SQLITE_MAX_VARS]
        result = await session.execute(
            select(GraphqlEndpoint).where(
                GraphqlEndpoint.target_id == target_id,
                GraphqlEndpoint.url.in_(chunk),
            )
        )
        for ge in result.scalars().all():
            existing[ge.url] = ge

    now = datetime.now(UTC)
    new_urls: list[str] = []
    for e in endpoints:
        url = str(e["url"])
        row: GraphqlEndpoint | None = existing.get(url)
        if row is None:
            session.add(
                GraphqlEndpoint(
                    target_id=target_id,
                    url=url,
                    host=str(e["host"]),
                    introspection_enabled=bool(e.get("introspection_enabled", False)),
                    server_type=e.get("server_type"),
                    schema_json=e.get("schema_json"),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_urls.append(url)
        else:
            row.last_seen_at = now
            if "introspection_enabled" in e:
                row.introspection_enabled = bool(e["introspection_enabled"])
            new_st = e.get("server_type")
            if new_st is not None:
                row.server_type = str(new_st)
            new_sj = e.get("schema_json")
            if new_sj is not None:
                row.schema_json = str(new_sj)

    await session.commit()
    return (len(new_urls), len(existing), new_urls)


async def list_graphql_endpoints(
    session: AsyncSession,
    target_id: int | None = None,
    host: str | None = None,
    limit: int | None = 25,
) -> list[GraphqlEndpointRow]:
    stmt = select(
        GraphqlEndpoint.url,
        GraphqlEndpoint.host,
        GraphqlEndpoint.introspection_enabled,
        GraphqlEndpoint.server_type,
        GraphqlEndpoint.schema_json,
        GraphqlEndpoint.first_seen_at,
        GraphqlEndpoint.last_seen_at,
    ).order_by(GraphqlEndpoint.first_seen_at.desc())
    if target_id is not None:
        stmt = stmt.where(GraphqlEndpoint.target_id == target_id)
    if host is not None:
        stmt = stmt.where(GraphqlEndpoint.host == host)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return [
        GraphqlEndpointRow(
            url=r[0],
            host=r[1],
            introspection_enabled=bool(r[2]),
            server_type=r[3],
            schema_json=r[4],
            first_seen_at=r[5],
            last_seen_at=r[6],
        )
        for r in result.all()
    ]


@dataclass
class ApiSpecRow:
    url: str
    host: str
    spec_type: str
    routes_count: int
    raw_spec: str
    first_seen_at: datetime
    last_seen_at: datetime


async def upsert_api_specs(
    session: AsyncSession,
    target_id: int,
    specs: list[dict[str, Any]],
) -> tuple[int, int, list[str]]:
    """Upsert api_spec rows. Unique on (target_id, url).

    Returns (new_count, existing_count, new_urls).
    """
    if not specs:
        return (0, 0, [])

    urls = [str(s["url"]) for s in specs]
    existing: dict[str, ApiSpec] = {}
    for i in range(0, len(urls), _SQLITE_MAX_VARS):
        chunk = urls[i : i + _SQLITE_MAX_VARS]
        result = await session.execute(
            select(ApiSpec).where(
                ApiSpec.target_id == target_id,
                ApiSpec.url.in_(chunk),
            )
        )
        for sp in result.scalars().all():
            existing[sp.url] = sp

    now = datetime.now(UTC)
    new_urls: list[str] = []
    for s in specs:
        url = str(s["url"])
        row: ApiSpec | None = existing.get(url)
        if row is None:
            session.add(
                ApiSpec(
                    target_id=target_id,
                    url=url,
                    host=str(s["host"]),
                    spec_type=str(s.get("spec_type", "unknown")),
                    routes_count=int(s.get("routes_count", 0)),
                    raw_spec=str(s.get("raw_spec", "")),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_urls.append(url)
        else:
            row.last_seen_at = now
            new_type = s.get("spec_type")
            if new_type is not None:
                row.spec_type = str(new_type)
            new_count = s.get("routes_count")
            if new_count is not None:
                row.routes_count = int(new_count)
            new_raw = s.get("raw_spec")
            if new_raw is not None:
                row.raw_spec = str(new_raw)

    await session.commit()
    return (len(new_urls), len(existing), new_urls)


async def list_api_specs(
    session: AsyncSession,
    target_id: int | None = None,
    host: str | None = None,
    spec_type: str | None = None,
    limit: int | None = 25,
) -> list[ApiSpecRow]:
    stmt = select(
        ApiSpec.url,
        ApiSpec.host,
        ApiSpec.spec_type,
        ApiSpec.routes_count,
        ApiSpec.raw_spec,
        ApiSpec.first_seen_at,
        ApiSpec.last_seen_at,
    ).order_by(ApiSpec.first_seen_at.desc())
    if target_id is not None:
        stmt = stmt.where(ApiSpec.target_id == target_id)
    if host is not None:
        stmt = stmt.where(ApiSpec.host == host)
    if spec_type is not None:
        stmt = stmt.where(ApiSpec.spec_type == spec_type)
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return [
        ApiSpecRow(
            url=r[0],
            host=r[1],
            spec_type=r[2],
            routes_count=r[3],
            raw_spec=r[4],
            first_seen_at=r[5],
            last_seen_at=r[6],
        )
        for r in result.all()
    ]


async def get_latest_endpoint_snapshot(
    session: AsyncSession,
    target_id: int,
    url: str,
) -> EndpointSnapshot | None:
    """Get the most recent snapshot for a specific endpoint URL."""
    result = await session.execute(
        select(EndpointSnapshot)
        .where(EndpointSnapshot.target_id == target_id, EndpointSnapshot.url == url)
        .order_by(EndpointSnapshot.observed_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def insert_endpoint_snapshots(
    session: AsyncSession,
    target_id: int,
    snapshots: list[dict[str, Any]],
    scan_run_id: int | None = None,
) -> int:
    """Bulk insert endpoint snapshots and return count inserted."""
    if not snapshots:
        return 0

    now = datetime.now(UTC)
    for snapshot in snapshots:
        session.add(
            EndpointSnapshot(
                target_id=target_id,
                url=snapshot["url"],
                status_code=snapshot.get("status_code"),
                content_type=snapshot.get("content_type"),
                body_hash=snapshot.get("body_hash"),
                title=snapshot.get("title"),
                observed_at=now,
                scan_run_id=scan_run_id,
            )
        )

    await session.commit()
    return len(snapshots)


async def list_endpoint_deltas(
    session: AsyncSession,
    target_id: int | None = None,
    url: str | None = None,
    kind: str | None = None,
    since: timedelta | None = None,
    limit: int | None = 25,
) -> list[EndpointDeltaRow]:
    """Query endpoint deltas. Each row represents one changed field for one URL from one probe.

    Rows ordered by observed_at desc (most recent first).

    kind filter values: status_changed, content_type_changed, title_changed,
    body_hash_changed, unreachable
    """
    # Subquery to find prior snapshot for each URL
    p = aliased(EndpointSnapshot)

    stmt = select(
        EndpointSnapshot.url,
        EndpointSnapshot.status_code,
        EndpointSnapshot.content_type,
        EndpointSnapshot.body_hash,
        EndpointSnapshot.title,
        EndpointSnapshot.observed_at,
        p.status_code,
        p.content_type,
        p.body_hash,
        p.title,
    ).select_from(EndpointSnapshot)

    # Left join to previous snapshot (ordered by observed_at, take the one just before current)
    stmt = stmt.outerjoin(
        p,
        (p.target_id == EndpointSnapshot.target_id)
        & (p.url == EndpointSnapshot.url)
        & (p.observed_at < EndpointSnapshot.observed_at),
    )

    if target_id is not None:
        stmt = stmt.where(EndpointSnapshot.target_id == target_id)
    if url is not None:
        stmt = stmt.where(EndpointSnapshot.url == url)
    if since is not None:
        cutoff = datetime.now(UTC) - since
        stmt = stmt.where(EndpointSnapshot.observed_at >= cutoff)

    stmt = stmt.order_by(EndpointSnapshot.observed_at.desc())
    if limit is not None:
        stmt = stmt.limit(limit)

    result = await session.execute(stmt)
    rows: list[EndpointDeltaRow] = []

    for row in result.all():
        current_url = row[0]
        current_status = row[1]
        current_content_type = row[2]
        current_body_hash = row[3]
        current_title = row[4]
        observed_at = row[5]
        prior_status = row[6]
        prior_content_type = row[7]
        prior_body_hash = row[8]
        prior_title = row[9]

        # If no prior snapshot, can't determine change type
        if (
            prior_status is None
            and prior_content_type is None
            and prior_body_hash is None
            and prior_title is None
        ):
            # This is the first snapshot or all priors are null
            continue

        # Classify changes
        if current_status is None and prior_status is not None:
            rows.append(
                EndpointDeltaRow(
                    url=current_url,
                    kind="unreachable",
                    old_value=str(prior_status) if prior_status else None,
                    new_value=None,
                    observed_at=observed_at,
                )
            )
        elif current_status != prior_status and prior_status is not None:
            rows.append(
                EndpointDeltaRow(
                    url=current_url,
                    kind="status_changed",
                    old_value=str(prior_status) if prior_status else None,
                    new_value=str(current_status) if current_status else None,
                    observed_at=observed_at,
                )
            )

        if current_content_type != prior_content_type and (
            kind is None or kind == "content_type_changed"
        ):
            rows.append(
                EndpointDeltaRow(
                    url=current_url,
                    kind="content_type_changed",
                    old_value=prior_content_type,
                    new_value=current_content_type,
                    observed_at=observed_at,
                )
            )

        if current_title != prior_title and (kind is None or kind == "title_changed"):
            rows.append(
                EndpointDeltaRow(
                    url=current_url,
                    kind="title_changed",
                    old_value=prior_title,
                    new_value=current_title,
                    observed_at=observed_at,
                )
            )

        if current_body_hash != prior_body_hash and (kind is None or kind == "body_hash_changed"):
            rows.append(
                EndpointDeltaRow(
                    url=current_url,
                    kind="body_hash_changed",
                    old_value=prior_body_hash,
                    new_value=current_body_hash,
                    observed_at=observed_at,
                )
            )

    # Filter by kind if requested
    if kind is not None:
        rows = [r for r in rows if r.kind == kind]

    return rows


async def upsert_web_profiles(
    session: AsyncSession,
    target_id: int,
    profiles: list[dict[str, Any]],
) -> int:
    """Upsert web profiles for a target.
    New rows set first_seen_at, existing refresh last_seen_at.
    """
    if not profiles:
        return 0

    count = 0
    for profile in profiles:
        url = profile.get("url")
        if not url:
            continue

        stmt = select(WebProfile).where(
            (WebProfile.target_id == target_id) & (WebProfile.url == url)
        )
        existing = await session.scalar(stmt)

        if existing:
            existing.status_code = profile.get("status_code")
            existing.title = profile.get("title")
            existing.server = profile.get("server")
            existing.csp = profile.get("csp")
            existing.hsts = profile.get("hsts")
            existing.cors = profile.get("cors")
            existing.set_cookie_raw = profile.get("set_cookie_raw")
            existing.cookie_flags_json = profile.get("cookie_flags_json")
            existing.headers_json = profile.get("headers_json")
            existing.last_seen_at = datetime.now(UTC)
            await session.merge(existing)
        else:
            new_profile = WebProfile(
                target_id=target_id,
                url=url,
                status_code=profile.get("status_code"),
                title=profile.get("title"),
                server=profile.get("server"),
                csp=profile.get("csp"),
                hsts=profile.get("hsts"),
                cors=profile.get("cors"),
                set_cookie_raw=profile.get("set_cookie_raw"),
                cookie_flags_json=profile.get("cookie_flags_json"),
                headers_json=profile.get("headers_json"),
            )
            session.add(new_profile)

        count += 1

    await session.commit()
    return count


async def upsert_service_fingerprints(
    session: AsyncSession,
    target_id: int,
    fingerprints: list[dict[str, Any]],
) -> int:
    """Upsert service fingerprints for a target.
    New rows set first_seen_at, existing refresh last_seen_at.
    """
    if not fingerprints:
        return 0

    count = 0
    for fingerprint in fingerprints:
        url = fingerprint.get("url")
        if not url:
            continue

        stmt = select(ServiceFingerprint).where(
            (ServiceFingerprint.target_id == target_id) & (ServiceFingerprint.url == url)
        )
        existing = await session.scalar(stmt)

        if existing:
            existing.favicon_hash = fingerprint.get("favicon_hash")
            existing.body_hash = fingerprint.get("body_hash")
            existing.title_hash = fingerprint.get("title_hash")
            existing.last_seen_at = datetime.now(UTC)
            await session.merge(existing)
        else:
            new_fingerprint = ServiceFingerprint(
                target_id=target_id,
                url=url,
                favicon_hash=fingerprint.get("favicon_hash"),
                body_hash=fingerprint.get("body_hash"),
                title_hash=fingerprint.get("title_hash"),
            )
            session.add(new_fingerprint)

        count += 1

    await session.commit()
    return count


async def list_web_profiles(
    session: AsyncSession,
    target_id: int | None = None,
    url: str | None = None,
    since: timedelta | None = None,
    limit: int | None = None,
) -> list[WebProfileRow]:
    """Query web profiles, most recently seen first."""
    stmt = select(WebProfile)

    if target_id is not None:
        stmt = stmt.where(WebProfile.target_id == target_id)

    if url is not None:
        stmt = stmt.where(WebProfile.url == url)

    if since is not None:
        cutoff = datetime.now(UTC) - since
        stmt = stmt.where(WebProfile.first_seen_at >= cutoff)

    stmt = stmt.order_by(WebProfile.last_seen_at.desc())

    if limit is not None:
        stmt = stmt.limit(limit)

    rows = await session.scalars(stmt)
    return [
        WebProfileRow(
            url=r.url,
            status_code=r.status_code,
            title=r.title,
            server=r.server,
            csp=r.csp,
            hsts=r.hsts,
            cors=r.cors,
            set_cookie_raw=r.set_cookie_raw,
            cookie_flags_json=r.cookie_flags_json,
            headers_json=r.headers_json,
            first_seen_at=r.first_seen_at,
            last_seen_at=r.last_seen_at,
        )
        for r in rows
    ]


async def list_service_fingerprints(
    session: AsyncSession,
    target_id: int | None = None,
    url: str | None = None,
    since: timedelta | None = None,
    limit: int | None = None,
) -> list[ServiceFingerprintRow]:
    """Query service fingerprints, most recently seen first."""
    stmt = select(ServiceFingerprint)

    if target_id is not None:
        stmt = stmt.where(ServiceFingerprint.target_id == target_id)

    if url is not None:
        stmt = stmt.where(ServiceFingerprint.url == url)

    if since is not None:
        cutoff = datetime.now(UTC) - since
        stmt = stmt.where(ServiceFingerprint.first_seen_at >= cutoff)

    stmt = stmt.order_by(ServiceFingerprint.last_seen_at.desc())

    if limit is not None:
        stmt = stmt.limit(limit)

    rows = await session.scalars(stmt)
    return [
        ServiceFingerprintRow(
            url=r.url,
            favicon_hash=r.favicon_hash,
            body_hash=r.body_hash,
            title_hash=r.title_hash,
            first_seen_at=r.first_seen_at,
            last_seen_at=r.last_seen_at,
        )
        for r in rows
    ]


async def upsert_service_screenshots(
    session: AsyncSession,
    target_id: int,
    screenshots: list[dict[str, Any]],
) -> tuple[int, int]:
    """Upsert service screenshots keyed by target, url, and phash."""
    if not screenshots:
        return (0, 0)

    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for shot in screenshots:
        url = str(shot["url"])
        phash = str(shot["phash"])
        key = (url, phash)
        if key in seen:
            continue
        seen.add(key)
        unique.append(shot)

    urls = [str(shot["url"]) for shot in unique]
    existing: dict[tuple[str, str], ServiceScreenshot] = {}
    for i in range(0, len(urls), _SQLITE_MAX_VARS):
        chunk = urls[i : i + _SQLITE_MAX_VARS]
        result = await session.execute(
            select(ServiceScreenshot).where(
                ServiceScreenshot.target_id == target_id,
                ServiceScreenshot.url.in_(chunk),
            )
        )
        for row in result.scalars().all():
            existing[(row.url, row.phash)] = row

    now = datetime.now(UTC)
    new_count = 0
    existing_count = 0
    for shot in unique:
        url = str(shot["url"])
        phash = str(shot["phash"])
        row = existing.get((url, phash))
        if row is None:
            session.add(
                ServiceScreenshot(
                    target_id=target_id,
                    host=str(shot["host"]),
                    url=url,
                    screenshot_path=str(shot["screenshot_path"]),
                    phash=phash,
                    width=int(shot["width"]),
                    height=int(shot["height"]),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            new_count += 1
        else:
            row.host = str(shot["host"])
            row.screenshot_path = str(shot["screenshot_path"])
            row.width = int(shot["width"])
            row.height = int(shot["height"])
            row.last_seen_at = now
            existing_count += 1

    await session.commit()
    return (new_count, existing_count)


async def get_latest_service_screenshot(
    session: AsyncSession,
    target_id: int,
    url: str,
) -> ServiceScreenshotRow | None:
    stmt = (
        select(ServiceScreenshot)
        .where(ServiceScreenshot.target_id == target_id, ServiceScreenshot.url == url)
        .order_by(ServiceScreenshot.last_seen_at.desc(), ServiceScreenshot.first_seen_at.desc())
        .limit(1)
    )
    row = await session.scalar(stmt)
    if row is None:
        return None
    return ServiceScreenshotRow(
        host=row.host,
        url=row.url,
        screenshot_path=row.screenshot_path,
        phash=row.phash,
        width=row.width,
        height=row.height,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
    )


async def list_service_screenshots(
    session: AsyncSession,
    target_id: int | None = None,
    url: str | None = None,
    host: str | None = None,
    since: timedelta | None = None,
    limit: int | None = None,
) -> list[ServiceScreenshotRow]:
    stmt = select(ServiceScreenshot).order_by(
        ServiceScreenshot.last_seen_at.desc(),
        ServiceScreenshot.first_seen_at.desc(),
    )

    if target_id is not None:
        stmt = stmt.where(ServiceScreenshot.target_id == target_id)
    if url is not None:
        stmt = stmt.where(ServiceScreenshot.url == url)
    if host is not None:
        stmt = stmt.where(ServiceScreenshot.host == host)
    if since is not None:
        stmt = stmt.where(ServiceScreenshot.first_seen_at >= datetime.now(UTC) - since)
    if limit is not None:
        stmt = stmt.limit(limit)

    rows = await session.scalars(stmt)
    return [
        ServiceScreenshotRow(
            host=row.host,
            url=row.url,
            screenshot_path=row.screenshot_path,
            phash=row.phash,
            width=row.width,
            height=row.height,
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
        )
        for row in rows
    ]
