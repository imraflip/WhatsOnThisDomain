from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from wotd.models import Base, Subdomain
from wotd.modules.vhost_enum import (
    VhostEnumModule,
    _build_vhost_url,
    _extract_ffuf_vhost,
    _is_baseline_like,
    _load_wordlist_candidates,
    _ResponseFingerprint,
)
from wotd.scope import RuleType, Scope, ScopeRule
from wotd.store import create_target, list_vhost_services
from wotd.tools import ToolResult


def test_extract_ffuf_vhost() -> None:
    assert _extract_ffuf_vhost({"input": {"FUZZ": "Admin.Acme.com"}}) == "admin.acme.com"
    assert _extract_ffuf_vhost({"host": "Portal.Acme.com"}) == "portal.acme.com"
    assert _extract_ffuf_vhost({"input": {"OTHER": "x"}}) is None


def test_build_vhost_url() -> None:
    assert _build_vhost_url("https://app.acme.com", "admin.acme.com") == "https://admin.acme.com/"
    assert (
        _build_vhost_url("https://app.acme.com:8443/login", "admin.acme.com")
        == "https://admin.acme.com:8443/login"
    )


def test_load_wordlist_candidates(tmp_path: Path) -> None:
    wordlist = tmp_path / "hosts.txt"
    wordlist.write_text("admin\nportal.acme.com\n#comment\nhttps://api.acme.com/path\n")
    assert _load_wordlist_candidates(wordlist, "acme.com") == [
        "admin.acme.com",
        "api.acme.com",
        "portal.acme.com",
    ]


def test_is_baseline_like() -> None:
    baseline = [
        _ResponseFingerprint(status_code=200, title="welcome", content_length=1000),
        _ResponseFingerprint(status_code=302, title=None, content_length=0),
    ]
    assert _is_baseline_like(200, "Welcome", 1010, baseline)
    assert _is_baseline_like(302, None, 10, baseline)
    assert not _is_baseline_like(200, "Admin", 1600, baseline)


async def test_vhost_module_filters_baseline_and_scope(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        target = await create_target(session, name="acme.com", root_domains=["acme.com"])
        now = datetime.now(UTC)
        session.add_all(
            [
                Subdomain(
                    target_id=target.id,
                    host="admin.acme.com",
                    sources="subfinder",
                    first_seen_at=now,
                    last_seen_at=now,
                ),
                Subdomain(
                    target_id=target.id,
                    host="portal.acme.com",
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
            if binary == "curl":
                return ToolResult(
                    command=[binary, *args],
                    returncode=0,
                    stdout="<html><title>Welcome</title></html>\nWOTD_META:200:1000\n",
                    stderr="",
                )
            if binary == "ffuf":
                lines = [
                    {
                        "input": {"FUZZ": "admin.acme.com"},
                        "status": 200,
                        "length": 1005,
                        "title": "Welcome",
                    },
                    {
                        "input": {"FUZZ": "portal.acme.com"},
                        "status": 200,
                        "length": 1540,
                        "title": "Portal",
                    },
                    {
                        "input": {"FUZZ": "evil.net"},
                        "status": 200,
                        "length": 1500,
                        "title": "Evil",
                    },
                ]
                return ToolResult(
                    command=[binary, *args],
                    returncode=0,
                    stdout="\n".join(json.dumps(line) for line in lines),
                    stderr="",
                )
            raise AssertionError(f"unexpected tool: {binary}")

        monkeypatch.setattr("wotd.modules.vhost_enum.run_tool", fake_run_tool)

        scope = Scope(
            includes=[
                ScopeRule(pattern="*.acme.com", rule_type=RuleType.WILDCARD),
                ScopeRule(pattern="acme.com", rule_type=RuleType.EXACT),
            ],
        )
        module = VhostEnumModule(
            session,
            target,
            scope,
            base_urls=["https://app.acme.com"],
        )
        result = await module.run()

        assert result.stats["baseline_filtered"] == 1
        assert result.stats["out_of_scope_filtered"] == 1
        assert result.stats["hits"] == 1
        assert result.stats["new"] == 1

        rows = await list_vhost_services(session, target_id=target.id)
        assert len(rows) == 1
        assert rows[0].vhost == "portal.acme.com"

        recent = await list_vhost_services(
            session,
            target_id=target.id,
            since=timedelta(hours=1),
            status_code=200,
        )
        assert len(recent) == 1

    await engine.dispose()
