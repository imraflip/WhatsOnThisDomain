from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from wotd.models import Base, HttpService, Subdomain
from wotd.store import create_target, list_subdomains


async def _seed() -> async_sessionmaker:  # type: ignore[type-arg]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)


async def test_probed_only_filter() -> None:
    session_factory = await _seed()
    async with session_factory() as session:
        target = await create_target(session, name="acme.com", root_domains=["acme.com"])
        now = datetime.now(UTC)

        session.add_all(
            [
                Subdomain(
                    target_id=target.id,
                    host="a.acme.com",
                    sources="subfinder",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
                Subdomain(
                    target_id=target.id,
                    host="b.acme.com",
                    sources="subfinder",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
                HttpService(
                    target_id=target.id,
                    host="a.acme.com",
                    url="https://a.acme.com",
                    status_code=200,
                    title="A",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
            ]
        )
        await session.commit()

        probed = await list_subdomains(session, target.id, probed_only=True)
        assert [r.host for r in probed] == ["a.acme.com"]

        both = await list_subdomains(session, target.id, probed_only=False)
        assert {r.host for r in both} == {"a.acme.com", "b.acme.com"}


async def test_since_filter() -> None:
    session_factory = await _seed()
    async with session_factory() as session:
        target = await create_target(session, name="acme.com", root_domains=["acme.com"])
        now = datetime.now(UTC)
        old = now - timedelta(days=5)

        session.add_all(
            [
                Subdomain(
                    target_id=target.id,
                    host="fresh.acme.com",
                    sources="subfinder",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
                Subdomain(
                    target_id=target.id,
                    host="stale.acme.com",
                    sources="subfinder",
                    first_seen_at=old,
                    last_seen_at=old,
                ),
            ]
        )
        await session.commit()

        recent = await list_subdomains(
            session, target.id, since=timedelta(hours=24), probed_only=False
        )
        assert [r.host for r in recent] == ["fresh.acme.com"]


async def test_source_filter() -> None:
    session_factory = await _seed()
    async with session_factory() as session:
        target = await create_target(session, name="acme.com", root_domains=["acme.com"])
        now = datetime.now(UTC)

        session.add_all(
            [
                Subdomain(
                    target_id=target.id,
                    host="a.acme.com",
                    sources="assetfinder,subfinder",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
                Subdomain(
                    target_id=target.id,
                    host="b.acme.com",
                    sources="shuffledns",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
            ]
        )
        await session.commit()

        subf = await list_subdomains(session, target.id, source="subfinder", probed_only=False)
        assert [r.host for r in subf] == ["a.acme.com"]

        shuf = await list_subdomains(session, target.id, source="shuffledns", probed_only=False)
        assert [r.host for r in shuf] == ["b.acme.com"]


async def test_limit() -> None:
    session_factory = await _seed()
    async with session_factory() as session:
        target = await create_target(session, name="acme.com", root_domains=["acme.com"])
        now = datetime.now(UTC)
        session.add_all(
            [
                Subdomain(
                    target_id=target.id,
                    host=f"h{i}.acme.com",
                    sources="subfinder",
                    first_seen_at=now - timedelta(minutes=i),
                    last_seen_at=now,
                )
                for i in range(5)
            ]
        )
        await session.commit()

        rows = await list_subdomains(session, target.id, limit=3, probed_only=False)
        assert len(rows) == 3
        assert [r.host for r in rows] == ["h0.acme.com", "h1.acme.com", "h2.acme.com"]
