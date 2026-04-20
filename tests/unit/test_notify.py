from __future__ import annotations

import os
from unittest.mock import patch

from wotd.notify import (
    NewHost,
    NotifyPayload,
    build_provider_config,
    chunk_message,
    format_cli_summary,
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
    def test_returns_none_when_nothing_resolved(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=5,
            resolved_count=0,
            live_count=0,
        )
        assert format_message(payload) is None

    def test_sections_with_resolved_and_live(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=4,
            resolved_count=3,
            live_count=2,
            new_hosts=[
                NewHost(
                    host="a.acme.com",
                    status="probed",
                    status_code=200,
                    url="https://a.acme.com",
                ),
                NewHost(host="b.acme.com", status="resolved"),
                NewHost(host="c.acme.com", status="found"),
                NewHost(
                    host="d.acme.com",
                    status="probed",
                    status_code=301,
                    url="http://d.acme.com",
                ),
            ],
        )
        msg = format_message(payload)
        assert msg is not None
        assert msg.startswith("[wotd] acme.com — 3 newly resolved, 2 newly live")
        assert "\nresolved:\na.acme.com\nb.acme.com\nd.acme.com" in msg
        assert "\nlive:\nhttps://a.acme.com [200]\nhttp://d.acme.com [301]" in msg
        assert "c.acme.com" not in msg

    def test_live_hosts_also_appear_in_resolved(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=1,
            resolved_count=1,
            live_count=1,
            new_hosts=[
                NewHost(
                    host="a.acme.com",
                    status="probed",
                    status_code=200,
                    url="https://a.acme.com",
                ),
            ],
        )
        msg = format_message(payload)
        assert msg is not None
        assert "resolved:\na.acme.com" in msg
        assert "live:\nhttps://a.acme.com [200]" in msg

    def test_live_section_omitted_when_no_live(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=2,
            resolved_count=1,
            live_count=0,
            new_hosts=[
                NewHost(host="a.acme.com", status="resolved"),
                NewHost(host="b.acme.com", status="found"),
            ],
        )
        msg = format_message(payload)
        assert msg is not None
        assert "newly live" not in msg
        assert "\nlive:" not in msg
        assert "resolved:\na.acme.com" in msg

    def test_includes_every_listed_host_without_truncation(self) -> None:
        hosts = [NewHost(host=f"h{i:02d}.acme.com", status="resolved") for i in range(40)]
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=40,
            resolved_count=40,
            live_count=0,
            new_hosts=hosts,
        )
        msg = format_message(payload)
        assert msg is not None
        for i in range(40):
            assert f"h{i:02d}.acme.com" in msg
        assert "more)" not in msg

    def test_probed_without_status_code_or_url(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=1,
            resolved_count=1,
            live_count=1,
            new_hosts=[NewHost(host="a.acme.com", status="probed", status_code=None)],
        )
        msg = format_message(payload)
        assert msg is not None
        assert "live:\na.acme.com [?]" in msg


class TestFormatCliSummary:
    def test_returns_none_when_nothing_resolved(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=5,
            resolved_count=0,
            live_count=0,
        )
        assert format_cli_summary(payload) is None

    def test_header_without_live(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=3,
            resolved_count=2,
            live_count=0,
            new_hosts=[
                NewHost(host="a.acme.com", status="resolved"),
                NewHost(host="b.acme.com", status="found"),
                NewHost(host="c.acme.com", status="resolved"),
            ],
        )
        summary = format_cli_summary(payload)
        assert summary is not None
        assert summary.startswith("[wotd] acme.com — 2 newly resolved")
        assert "newly live" not in summary
        assert "live:" not in summary
        assert "resolved: a.acme.com, c.acme.com" in summary
        assert "b.acme.com" not in summary

    def test_header_with_live(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=3,
            resolved_count=3,
            live_count=2,
            new_hosts=[
                NewHost(
                    host="a.acme.com",
                    status="probed",
                    status_code=200,
                    url="https://a.acme.com",
                ),
                NewHost(host="b.acme.com", status="resolved"),
                NewHost(
                    host="c.acme.com",
                    status="probed",
                    status_code=301,
                    url="http://c.acme.com",
                ),
            ],
        )
        summary = format_cli_summary(payload)
        assert summary is not None
        assert "[wotd] acme.com — 3 newly resolved, 2 newly live" in summary
        assert "resolved: a.acme.com, b.acme.com, c.acme.com" in summary
        assert "live: https://a.acme.com [200], http://c.acme.com [301]" in summary

    def test_live_hosts_also_appear_in_resolved_line(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=1,
            resolved_count=1,
            live_count=1,
            new_hosts=[
                NewHost(
                    host="a.acme.com",
                    status="probed",
                    status_code=200,
                    url="https://a.acme.com",
                ),
            ],
        )
        summary = format_cli_summary(payload)
        assert summary is not None
        assert "resolved: a.acme.com" in summary
        assert "live: https://a.acme.com [200]" in summary

    def test_truncates_long_resolved_list(self) -> None:
        hosts = [NewHost(host=f"h{i:02d}.acme.com", status="resolved") for i in range(15)]
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=15,
            resolved_count=15,
            live_count=0,
            new_hosts=hosts,
        )
        summary = format_cli_summary(payload)
        assert summary is not None
        assert "(+7 more)" in summary
        assert "h00.acme.com" in summary
        assert "h14.acme.com" not in summary

    def test_probed_without_code_or_url(self) -> None:
        payload = NotifyPayload(
            target="acme.com",
            discovered_count=1,
            resolved_count=1,
            live_count=1,
            new_hosts=[NewHost(host="a.acme.com", status="probed")],
        )
        summary = format_cli_summary(payload)
        assert summary is not None
        assert "live: a.acme.com [?]" in summary


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
