"""Resolves a seeded subdomain for hackerone.com with real dnsx and asserts
at least one A record comes back. Needs dnsx on PATH."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from wotd.models import Base, DnsRecord
from wotd.modules.subdomains_resolve import SubdomainsResolveModule
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import create_target, upsert_subdomains


@pytest.mark.flaky(retries=3, delay=10)
async def test_resolve_known_host() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        target = await create_target(
            session, name="hackerone.com", root_domains=["hackerone.com"]
        )
        await upsert_subdomains(
            session, target.id, {"api.hackerone.com": {"seed"}}
        )

        scope = Scope(
            includes=[
                ScopeRule(pattern="*.hackerone.com", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern="hackerone.com", rule_type=RuleType.EXACT),
            ],
        )
        module = SubdomainsResolveModule(session, target, scope)
        result = await module.run()

        assert result.stats["errors"] == {}, f"tool errors: {result.stats['errors']}"
        assert result.stats["resolved"] >= 1, f"nothing resolved: {result.stats}"

        rows = (await session.execute(DnsRecord.__table__.select())).all()
        assert any(r.host == "api.hackerone.com" and r.record_type == "A" for r in rows)

    await engine.dispose()
