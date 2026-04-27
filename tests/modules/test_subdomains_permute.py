"""Runs the real subdomain permutation module against hackerone.com.

Needs alterx, dnsx, and the resolvers list on PATH.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from wotd.models import Base, Subdomain
from wotd.modules.subdomains_permute import SubdomainsPermuteModule
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import create_target, get_subdomain_hosts, list_subdomain_candidates

pytestmark = pytest.mark.flaky(retries=3, delay=10)

if shutil.which("alterx") is None or shutil.which("dnsx") is None:
    pytest.skip(
        "alterx and dnsx must be installed for integration testing",
        allow_module_level=True,
    )


async def test_subdomain_permute_real_tools() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        target = await create_target(session, name="hackerone.com", root_domains=["hackerone.com"])
        now = datetime.now(UTC)
        session.add_all(
            [
                Subdomain(
                    target_id=target.id,
                    host="api.hackerone.com",
                    sources="subfinder",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
                Subdomain(
                    target_id=target.id,
                    host="www.hackerone.com",
                    sources="subfinder",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
                Subdomain(
                    target_id=target.id,
                    host="help.hackerone.com",
                    sources="subfinder",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
            ]
        )
        await session.commit()

        scope = Scope(
            includes=[
                ScopeRule(pattern="*.hackerone.com", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern="hackerone.com", rule_type=RuleType.EXACT),
            ],
        )
        module = SubdomainsPermuteModule(
            session,
            target,
            scope,
            mode="quick",
            max_candidates=100,
            budget_minutes=10,
        )
        result = await module.run()

        assert result.stats["errors"] == {}, f"tool errors: {result.stats['errors']}"
        assert result.stats["generated"] > 0, f"no candidates generated: {result.stats}"
        assert result.stats["resolution_chunks"] >= 1, f"no resolution work ran: {result.stats}"

        rows = await list_subdomain_candidates(session, target.id, limit=None)
        assert rows, "expected candidate rows to be stored"

        hosts = await get_subdomain_hosts(session, target.id)
        assert hosts, "expected subdomains to remain present"

    await engine.dispose()
