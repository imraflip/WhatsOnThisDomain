"""Runs the real passive subdomains module against hackerone.com and asserts
api.hackerone.com shows up. Needs subfinder + assetfinder on PATH."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from wotd.models import Base, Subdomain
from wotd.modules.subdomains_passive import SubdomainsPassiveModule
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import create_target


@pytest.mark.flaky(retries=3, delay=10)
async def test_passive_enum() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        target = await create_target(
            session, name="hackerone.com", root_domains=["hackerone.com"]
        )
        scope = Scope(
            includes=[
                ScopeRule(pattern="*.hackerone.com", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern="hackerone.com", rule_type=RuleType.EXACT),
            ],
        )
        module = SubdomainsPassiveModule(session, target, scope)
        result = await module.run()

        assert result.stats["errors"] == {}, f"tool errors: {result.stats['errors']}"
        assert result.stats["in_scope"] > 0

        rows = (await session.execute(Subdomain.__table__.select())).all()
        hosts = {row.host for row in rows}
        assert "api.hackerone.com" in hosts, (
            f"expected api.hackerone.com in results, got sample: {sorted(hosts)[:20]}"
        )

    await engine.dispose()
