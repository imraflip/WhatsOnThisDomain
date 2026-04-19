from __future__ import annotations

import os
from unittest.mock import patch

from wotd.notify import (
    NewHost,
    NotifyPayload,
    build_provider_config,
    chunk_message,
    format_message,
)


class TestBuildProviderConfig:
    def test_returns_none_when_no_env_vars(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            assert build_provider_config() is None

    def test_discord_minimal(self) -> None:
        env = {"WOTD_NOTIFY_DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/123"}
        with patch.dict(os.environ, env, clear=True):
            config = build_provider_config()
            assert config is not None
            assert len(config["discord"]) == 1
            entry = config["discord"][0]
            assert entry["id"] == "wotd"
            assert entry["discord_webhook_url"] == env["WOTD_NOTIFY_DISCORD_WEBHOOK_URL"]
            assert "discord_channel" not in entry

    def test_discord_with_optionals(self) -> None:
        env = {
            "WOTD_NOTIFY_DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/123",
            "WOTD_NOTIFY_DISCORD_CHANNEL": "recon",
            "WOTD_NOTIFY_DISCORD_USERNAME": "wotd",
        }
        with patch.dict(os.environ, env, clear=True):
            config = build_provider_config()
            assert config is not None
            entry = config["discord"][0]
            assert entry["discord_channel"] == "recon"
            assert entry["discord_username"] == "wotd"

    def test_smtp_requires_all_fields(self) -> None:
        env = {
            "WOTD_NOTIFY_SMTP_SERVER": "mail.example.com",
            "WOTD_NOTIFY_SMTP_USERNAME": "me@example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            assert build_provider_config() is None

    def test_smtp_complete(self) -> None:
        env = {
            "WOTD_NOTIFY_SMTP_SERVER": "mail.example.com",
            "WOTD_NOTIFY_SMTP_USERNAME": "me@example.com",
            "WOTD_NOTIFY_SMTP_PASSWORD": "secret",
            "WOTD_NOTIFY_SMTP_FROM": "me@example.com",
            "WOTD_NOTIFY_SMTP_TO": "you@example.com, other@example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            config = build_provider_config()
            assert config is not None
            entry = config["smtp"][0]
            assert entry["smtp_server"] == "mail.example.com"
            assert entry["smtp_cc"] == ["you@example.com", "other@example.com"]
            assert entry["subject"] == "wotd recon update"
            assert entry["smtp_html"] is False

    def test_both_providers(self) -> None:
        env = {
            "WOTD_NOTIFY_DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/123",
            "WOTD_NOTIFY_SMTP_SERVER": "mail.example.com",
            "WOTD_NOTIFY_SMTP_USERNAME": "me@example.com",
            "WOTD_NOTIFY_SMTP_PASSWORD": "secret",
            "WOTD_NOTIFY_SMTP_FROM": "me@example.com",
            "WOTD_NOTIFY_SMTP_TO": "you@example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            config = build_provider_config()
            assert config is not None
            assert "discord" in config
            assert "smtp" in config

    def test_empty_string_treated_as_unset(self) -> None:
        env = {"WOTD_NOTIFY_DISCORD_WEBHOOK_URL": "  "}
        with patch.dict(os.environ, env, clear=True):
            assert build_provider_config() is None


class TestFormatMessage:
    def test_returns_none_when_nothing_new(self) -> None:
        payload = NotifyPayload(
            target="acme.com", new_count=0, resolved_count=0, probed_count=0
        )
        assert format_message(payload) is None

    def test_new_hosts_with_mixed_status(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            new_count=3,
            resolved_count=2,
            probed_count=1,
            new_hosts=[
                NewHost(host="a.acme.com", status="probed", status_code=200),
                NewHost(host="b.acme.com", status="resolved"),
                NewHost(host="c.acme.com", status="found"),
            ],
        )
        msg = format_message(payload)
        assert msg is not None
        assert "[wotd] acme.com" in msg
        assert "3 new subdomain(s) found" in msg
        assert "2 resolved" in msg
        assert "1 live (HTTP)" in msg
        assert "a.acme.com (probed 200)" in msg
        assert "b.acme.com (resolved)" in msg
        assert "c.acme.com (found)" in msg

    def test_probed_hosts_sorted_first(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            new_count=3,
            resolved_count=2,
            probed_count=1,
            new_hosts=[
                NewHost(host="c.acme.com", status="found"),
                NewHost(host="b.acme.com", status="resolved"),
                NewHost(host="a.acme.com", status="probed", status_code=200),
            ],
        )
        msg = format_message(payload)
        assert msg is not None
        probed_idx = msg.index("a.acme.com")
        resolved_idx = msg.index("b.acme.com")
        found_idx = msg.index("c.acme.com")
        assert probed_idx < resolved_idx < found_idx

    def test_includes_all_hosts(self) -> None:
        hosts = [NewHost(host=f"h{i}.acme.com", status="found") for i in range(40)]
        payload = NotifyPayload(
            target="acme.com",
            new_count=40,
            resolved_count=0,
            probed_count=0,
            new_hosts=hosts,
        )
        msg = format_message(payload)
        assert msg is not None
        for i in range(40):
            assert f"h{i}.acme.com (found)" in msg
        assert "more)" not in msg

    def test_probed_without_status_code(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            new_count=1,
            resolved_count=1,
            probed_count=1,
            new_hosts=[NewHost(host="a.acme.com", status="probed", status_code=None)],
        )
        msg = format_message(payload)
        assert msg is not None
        assert "a.acme.com (probed)" in msg


class TestChunkMessage:
    def test_short_message_stays_single_chunk(self) -> None:
        chunks = chunk_message("hello\nworld", max_chars=100)
        assert chunks == ["hello\nworld"]

    def test_splits_on_newline_boundary(self) -> None:
        msg = "\n".join(f"line{i}" for i in range(20))
        chunks = chunk_message(msg, max_chars=30)
        assert len(chunks) > 1
        for chunk in chunks:
            assert len(chunk) <= 30
        assert "\n".join(chunks).replace("\n\n", "\n") == msg or sum(
            c.count("\n") + 1 for c in chunks
        ) == 20

    def test_preserves_every_line(self) -> None:
        lines = [f"host{i}.example.com (found)" for i in range(100)]
        msg = "\n".join(lines)
        chunks = chunk_message(msg, max_chars=200)
        rejoined = "\n".join(chunks)
        for line in lines:
            assert line in rejoined
