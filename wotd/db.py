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
