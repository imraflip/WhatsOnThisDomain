from __future__ import annotations

from pathlib import Path

from platformdirs import user_data_dir
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

DEFAULT_DB_DIR = Path(user_data_dir("wotd"))
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "wotd.db"


def get_engine(db_path: Path | None = None) -> AsyncEngine:
    path = db_path or DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return create_async_engine(f"sqlite+aiosqlite:///{path}", echo=False)


def get_session_factory(db_path: Path | None = None) -> async_sessionmaker[AsyncSession]:
    engine = get_engine(db_path)
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_db(db_path: Path | None = None) -> None:
    """Create all tables from SQLAlchemy models. Safe to call on every startup."""
    from sqlalchemy import text

    from wotd.models import Base

    engine = get_engine(db_path)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # M42: add wordlist column to existing dir_results tables created before this milestone
        result = await conn.execute(text("PRAGMA table_info(dir_results)"))
        if "wordlist" not in {row[1] for row in result}:
            await conn.execute(
                text("ALTER TABLE dir_results ADD COLUMN wordlist TEXT")
            )
    await engine.dispose()
