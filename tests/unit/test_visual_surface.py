from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from wotd.models import Base, HttpService, ServiceScreenshot
from wotd.modules.visual_surface import (
    VisualSurfaceModule,
    _phash_distance,
    _phash_from_image,
    _ScreenshotCapture,
)
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import create_target, list_service_screenshots


def _make_image(path: Path, left: int, top: int, right: int, bottom: int) -> None:
    image = Image.new("RGB", (128, 128), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((left, top, right, bottom), fill="black")
    image.save(path)


def test_phash_helpers(tmp_path: Path) -> None:
    base = tmp_path / "base.png"
    same = tmp_path / "same.png"
    different = tmp_path / "different.png"
    _make_image(base, 16, 16, 80, 80)
    _make_image(same, 16, 16, 80, 80)
    _make_image(different, 64, 16, 112, 80)

    base_hash = _phash_from_image(base)
    same_hash = _phash_from_image(same)
    different_hash = _phash_from_image(different)

    assert base_hash == same_hash
    assert _phash_distance(base_hash, different_hash) > 0


async def test_visual_surface_tracks_changes(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        target = await create_target(session, name="acme.com", root_domains=["acme.com"])
        url = "https://app.acme.com/"
        session.add(
            HttpService(
                target_id=target.id,
                host="app.acme.com",
                url=url,
                status_code=200,
                title="App",
                tech=None,
                content_length=1234,
                final_url=url,
            )
        )
        session.add(
            ServiceScreenshot(
                target_id=target.id,
                host="app.acme.com",
                url=url,
                screenshot_path=str(tmp_path / "old.png"),
                phash="0000000000000000",
                width=128,
                height=128,
            )
        )
        await session.commit()

        shot_path = tmp_path / "shot.png"
        _make_image(shot_path, 64, 16, 112, 80)

        async def fake_capture(self, url: str, host: str) -> _ScreenshotCapture:  # type: ignore[no-untyped-def]
            return _ScreenshotCapture(
                host=host,
                url=url,
                screenshot_path=shot_path,
                phash="ffffffffffffffff",
                width=128,
                height=128,
            )

        monkeypatch.setattr(
            "wotd.modules.visual_surface.VisualSurfaceModule._capture_url",
            fake_capture,
        )

        scope = Scope(
            includes=[
                ScopeRule(pattern="*.acme.com", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern="acme.com", rule_type=RuleType.EXACT),
            ],
        )
        module = VisualSurfaceModule(session, target, scope, phash_distance_threshold=4)
        result = await module.run()

        assert result.stats["captured"] == 1
        assert result.stats["new_services_screenshoted"] == 1
        assert result.stats["visual_changes_detected"] == 1
        assert result.stats["changed_urls"] == [url]

        rows = await list_service_screenshots(session, target_id=target.id, url=url, limit=None)
        assert len(rows) == 2

    await engine.dispose()
