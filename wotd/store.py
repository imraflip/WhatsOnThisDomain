from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wotd.models import ScanRun, Subdomain, Target


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
) -> tuple[int, int]:
    """Insert new subdomains, update sources and last_seen on existing ones.

    Returns (new_count, existing_count).
    """
    if not host_to_sources:
        return (0, 0)

    hosts = list(host_to_sources.keys())
    result = await session.execute(
        select(Subdomain).where(
            Subdomain.target_id == target_id,
            Subdomain.host.in_(hosts),
        )
    )
    existing = {row.host: row for row in result.scalars().all()}

    now = datetime.now(UTC)
    new_count = 0
    for host, sources in host_to_sources.items():
        row = existing.get(host)
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
            new_count += 1
        else:
            merged = set(row.sources.split(",")) | sources
            row.sources = ",".join(sorted(merged))
            row.last_seen_at = now

    await session.commit()
    return (new_count, len(existing))


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
