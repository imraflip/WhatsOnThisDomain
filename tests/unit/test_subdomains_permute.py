from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from wotd.models import Base, Subdomain, SubdomainCandidate
from wotd.modules.subdomains_permute import SubdomainsPermuteModule
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import create_target, get_subdomain_hosts, list_subdomain_candidates
from wotd.tools import ToolResult


async def _seed() -> async_sessionmaker:  # type: ignore[type-arg]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)


async def test_subdomains_permute_generates_and_resolves(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session_factory = await _seed()
    async with session_factory() as session:
        target = await create_target(session, name="acme.com", root_domains=["acme.com"])
        now = datetime.now(UTC)
        session.add_all(
            [
                Subdomain(
                    target_id=target.id,
                    host="api.acme.com",
                    sources="subfinder",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
                Subdomain(
                    target_id=target.id,
                    host="www.acme.com",
                    sources="subfinder",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
            ]
        )
        await session.commit()

        async def fake_run_tool(  # type: ignore[no-untyped-def]
            binary: str,
            args: list[str],
            stdin_data: str | None = None,
            timeout: float | None = None,
            check_exists: bool = True,
        ) -> ToolResult:
            if binary == "alterx":
                return ToolResult(
                    command=[binary, *args],
                    returncode=0,
                    stdout="\n".join(
                        [
                            "api.acme.com",
                            "admin.acme.com",
                            "dev.acme.com",
                            "outside.net",
                        ]
                    ),
                    stderr="",
                )
            if binary == "dnsx":
                lines = [
                    {
                        "host": "admin.acme.com",
                        "a": ["1.2.3.4"],
                    }
                ]
                return ToolResult(
                    command=[binary, *args],
                    returncode=0,
                    stdout="\n".join(json.dumps(line) for line in lines),
                    stderr="",
                )
            raise AssertionError(binary)

        async def fake_resolvers(*args, **kwargs) -> bool:  # type: ignore[no-untyped-def]
            return False

        monkeypatch.setattr("wotd.modules.subdomains_permute.run_tool", fake_run_tool)
        monkeypatch.setattr(
            "wotd.modules.subdomains_permute.ensure_resolvers_fresh",
            fake_resolvers,
        )

        scope = Scope(
            includes=[
                ScopeRule(pattern="*.acme.com", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern="acme.com", rule_type=RuleType.EXACT),
            ]
        )
        module = SubdomainsPermuteModule(
            session,
            target,
            scope,
            mode="balanced",
            max_candidates=20,
            budget_minutes=5,
        )
        result = await module.run()

        assert result.stats["candidate_new"] == 2
        assert result.stats["resolved"] == 1
        assert result.stats["unresolved"] == 1
        assert result.stats["new"] == 1
        assert result.stats["new_hosts"] == ["admin.acme.com"]

        candidate_rows = await list_subdomain_candidates(session, target.id, limit=None)
        by_host = {row.fqdn: row for row in candidate_rows}
        assert by_host["admin.acme.com"].status == "resolved"
        assert by_host["dev.acme.com"].status == "unresolved"

        all_hosts = await get_subdomain_hosts(session, target.id)
        assert "admin.acme.com" in all_hosts


async def test_subdomains_permute_resumes_pending_candidates(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session_factory = await _seed()
    async with session_factory() as session:
        target = await create_target(session, name="acme.com", root_domains=["acme.com"])
        now = datetime.now(UTC)
        session.add(
            Subdomain(
                target_id=target.id,
                host="www.acme.com",
                sources="subfinder",
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        session.add(
            SubdomainCandidate(
                target_id=target.id,
                fqdn="resume.acme.com",
                source="alterx",
                generator="alterx:quick",
                status="generated",
                generated_at=now,
                resolved_at=None,
            )
        )
        await session.commit()

        async def fake_run_tool(  # type: ignore[no-untyped-def]
            binary: str,
            args: list[str],
            stdin_data: str | None = None,
            timeout: float | None = None,
            check_exists: bool = True,
        ) -> ToolResult:
            if binary == "alterx":
                return ToolResult(command=[binary, *args], returncode=0, stdout="", stderr="")
            if binary == "dnsx":
                return ToolResult(
                    command=[binary, *args],
                    returncode=0,
                    stdout=json.dumps({"host": "resume.acme.com", "a": ["5.6.7.8"]}),
                    stderr="",
                )
            raise AssertionError(binary)

        async def fake_resolvers(*args, **kwargs) -> bool:  # type: ignore[no-untyped-def]
            return False

        monkeypatch.setattr("wotd.modules.subdomains_permute.run_tool", fake_run_tool)
        monkeypatch.setattr(
            "wotd.modules.subdomains_permute.ensure_resolvers_fresh",
            fake_resolvers,
        )

        scope = Scope(
            includes=[
                ScopeRule(pattern="*.acme.com", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern="acme.com", rule_type=RuleType.EXACT),
            ]
        )
        module = SubdomainsPermuteModule(
            session,
            target,
            scope,
            mode="quick",
            max_candidates=10,
            budget_minutes=5,
        )
        result = await module.run()

        assert result.stats["pending_before"] == 1
        assert result.stats["resolved"] == 1
        rows = await list_subdomain_candidates(session, target.id, status="resolved", limit=None)
        assert [row.fqdn for row in rows] == ["resume.acme.com"]


async def test_list_subdomain_candidates_filters() -> None:
    session_factory = await _seed()
    async with session_factory() as session:
        target = await create_target(session, name="acme.com", root_domains=["acme.com"])
        now = datetime.now(UTC)
        old = now - timedelta(days=3)
        session.add_all(
            [
                SubdomainCandidate(
                    target_id=target.id,
                    fqdn="old.acme.com",
                    source="alterx",
                    generator="alterx:quick",
                    status="unresolved",
                    generated_at=old,
                    resolved_at=None,
                ),
                SubdomainCandidate(
                    target_id=target.id,
                    fqdn="new.acme.com",
                    source="alterx",
                    generator="alterx:balanced",
                    status="resolved",
                    generated_at=now,
                    resolved_at=now,
                ),
            ]
        )
        await session.commit()

        recent = await list_subdomain_candidates(
            session,
            target_id=target.id,
            status="resolved",
            source="alterx",
            since=timedelta(days=1),
            limit=None,
        )
        assert [row.fqdn for row in recent] == ["new.acme.com"]
