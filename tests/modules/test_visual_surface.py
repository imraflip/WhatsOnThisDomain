"""Runs the real visual surface module when the screenshot toolchain is available."""

from __future__ import annotations

import shutil

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from wotd.models import Base, HttpService
from wotd.modules.visual_surface import VisualSurfaceModule
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import create_target, list_service_screenshots

pytestmark = pytest.mark.flaky(retries=2, delay=10)

if shutil.which("gowitness") is None and shutil.which("httpx-pd") is None:
    pytest.skip(
        "gowitness or httpx-pd must be installed for integration testing",
        allow_module_level=True,
    )

if (
    shutil.which("chromium") is None
    and shutil.which("chromium-browser") is None
    and shutil.which("google-chrome") is None
    and shutil.which("chrome") is None
):
    pytest.skip(
        "a system browser is required for screenshot integration testing",
        allow_module_level=True,
    )


async def test_visual_surface_real_tools() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        target = await create_target(session, name="example.com", root_domains=["example.com"])
        url = "https://example.com/"
        session.add(
            HttpService(
                target_id=target.id,
                host="example.com",
                url=url,
                status_code=200,
                title="Example Domain",
                tech=None,
                content_length=0,
                final_url=url,
            )
        )
        await session.commit()

        scope = Scope(
            includes=[
                ScopeRule(pattern="*.example.com", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern="example.com", rule_type=RuleType.EXACT),
            ],
        )
        module = VisualSurfaceModule(session, target, scope, phash_distance_threshold=8)
        result = await module.run()

        assert result.stats["errors"] == {}, f"tool errors: {result.stats['errors']}"
        assert result.stats["captured"] >= 1, f"no screenshots captured: {result.stats}"

        rows = await list_service_screenshots(session, target_id=target.id, limit=None)
        assert rows, "expected service screenshot rows to be stored"

    await engine.dispose()
