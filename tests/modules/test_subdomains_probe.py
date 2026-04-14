"""Probes a seeded resolved host for hackerone.com with real httpx and asserts
at least one service returns a reasonable status code. Needs httpx on PATH."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from wotd.models import Base, HttpService
from wotd.modules.subdomains_probe import SubdomainsProbeModule
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import create_target, upsert_dns_records


@pytest.mark.flaky(retries=3, delay=10)
async def test_probe() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        target = await create_target(session, name="hackerone.com", root_domains=["hackerone.com"])
        await upsert_dns_records(session, target.id, [("www.hackerone.com", "A", "0.0.0.0")])

        scope = Scope(
            includes=[
                ScopeRule(pattern="*.hackerone.com", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern="hackerone.com", rule_type=RuleType.EXACT),
            ],
        )
        module = SubdomainsProbeModule(session, target, scope)
        result = await module.run()

        assert result.stats["errors"] == {}, f"tool errors: {result.stats['errors']}"
        assert result.stats["alive"] >= 1, f"no live services: {result.stats}"

        rows = (await session.execute(HttpService.__table__.select())).all()
        assert any(
            r.status_code is not None and 200 <= r.status_code < 400 for r in rows
        ), f"no 2xx/3xx found: {[(r.url, r.status_code) for r in rows]}"

    await engine.dispose()
