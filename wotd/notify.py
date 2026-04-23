"""Build a notify provider-config from env vars and dispatch messages."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from wotd.tools import ToolNotFoundError, run_tool

logger = logging.getLogger(__name__)

NOTIFY_CONFIG_DIR = Path("/root/.config/notify")
NOTIFY_CONFIG_PATH = NOTIFY_CONFIG_DIR / "provider-config.yaml"


@dataclass
class NewHost:
    host: str
    status: str
    status_code: int | None = None
    url: str | None = None


@dataclass
class NotifyPayload:
    target: str
    discovered_count: int
    resolved_count: int
    live_count: int
    new_hosts: list[NewHost] = field(default_factory=list)


def _env(key: str) -> str | None:
    val = os.environ.get(key)
    if val is not None:
        val = val.strip()
    return val if val else None


def build_provider_config() -> dict[str, Any] | None:
    config: dict[str, Any] = {}

    discord_url = _env("WOTD_NOTIFY_DISCORD_WEBHOOK_URL")
    if discord_url:
        entry: dict[str, Any] = {
            "id": "wotd",
            "discord_webhook_url": discord_url,
            "discord_format": "{{data}}",
        }
        channel = _env("WOTD_NOTIFY_DISCORD_CHANNEL")
        if channel:
            entry["discord_channel"] = channel
        username = _env("WOTD_NOTIFY_DISCORD_USERNAME")
        if username:
            entry["discord_username"] = username
        config["discord"] = [entry]

    smtp_server = _env("WOTD_NOTIFY_SMTP_SERVER")
    smtp_user = _env("WOTD_NOTIFY_SMTP_USERNAME")
    smtp_pass = _env("WOTD_NOTIFY_SMTP_PASSWORD")
    smtp_from = _env("WOTD_NOTIFY_SMTP_FROM")
    smtp_to = _env("WOTD_NOTIFY_SMTP_TO")
    if all((smtp_server, smtp_user, smtp_pass, smtp_from, smtp_to)):
        smtp_entry: dict[str, Any] = {
            "id": "wotd",
            "smtp_server": smtp_server,
            "smtp_username": smtp_user,
            "smtp_password": smtp_pass,
            "from_address": smtp_from,
            "smtp_cc": [addr.strip() for addr in (smtp_to or "").split(",") if addr.strip()],
            "smtp_format": "{{data}}",
        }
        subject = _env("WOTD_NOTIFY_SMTP_SUBJECT")
        if subject:
            smtp_entry["subject"] = subject
        else:
            smtp_entry["subject"] = "wotd recon update"
        html_val = _env("WOTD_NOTIFY_SMTP_HTML")
        if html_val and html_val.lower() == "true":
            smtp_entry["smtp_html"] = True
        else:
            smtp_entry["smtp_html"] = False
        starttls_val = _env("WOTD_NOTIFY_SMTP_DISABLE_STARTTLS")
        if starttls_val and starttls_val.lower() == "true":
            smtp_entry["smtp_disable_starttls"] = True
        else:
            smtp_entry["smtp_disable_starttls"] = False
        config["smtp"] = [smtp_entry]

    return config if config else None


DISCORD_CHUNK_LIMIT = 1900
CLI_DISPLAY_LIMIT = 8


def _header(payload: NotifyPayload) -> str:
    bits = [f"{payload.resolved_count} newly resolved"]
    if payload.live_count > 0:
        bits.append(f"{payload.live_count} newly live")
    return f"[wotd] {payload.target} — {', '.join(bits)}"


def _split_resolved_and_live(
    payload: NotifyPayload,
) -> tuple[list[NewHost], list[NewHost]]:
    resolved = sorted(
        (h for h in payload.new_hosts if h.status in ("resolved", "probed")),
        key=lambda h: h.host,
    )
    live = sorted((h for h in payload.new_hosts if h.status == "probed"), key=lambda h: h.host)
    return resolved, live


def _format_live_item(h: NewHost) -> str:
    code = h.status_code if h.status_code is not None else "?"
    target = h.url or h.host
    return f"{target} [{code}]"


def format_cli_summary(payload: NotifyPayload) -> str | None:
    """Compact multi-line summary for the CLI (caps each section at CLI_DISPLAY_LIMIT)."""
    if payload.resolved_count == 0:
        return None

    resolved, live = _split_resolved_and_live(payload)
    parts = [_header(payload)]

    if resolved:
        shown = resolved[:CLI_DISPLAY_LIMIT]
        line = ", ".join(h.host for h in shown)
        remaining = len(resolved) - len(shown)
        if remaining > 0:
            line += f", … (+{remaining} more)"
        parts.append(f"  resolved: {line}")

    if live:
        shown = live[:CLI_DISPLAY_LIMIT]
        line = ", ".join(_format_live_item(h) for h in shown)
        remaining = len(live) - len(shown)
        if remaining > 0:
            line += f", … (+{remaining} more)"
        parts.append(f"  live: {line}")

    return "\n".join(parts)


def format_message(payload: NotifyPayload) -> str | None:
    """Full vertical host list for notifications (chunked at dispatch)."""
    if payload.resolved_count == 0:
        return None

    resolved, live = _split_resolved_and_live(payload)
    parts = [_header(payload)]

    if resolved:
        parts.append("")
        parts.append("resolved:")
        for h in resolved:
            parts.append(h.host)

    if live:
        parts.append("")
        parts.append("live:")
        for h in live:
            parts.append(_format_live_item(h))

    return "\n".join(parts)


def chunk_message(message: str, max_chars: int = DISCORD_CHUNK_LIMIT) -> list[str]:
    """Split a message into newline-aligned chunks that fit max_chars each."""
    lines = message.split("\n")
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for line in lines:
        line_len = len(line) + 1
        if current and current_len + line_len > max_chars:
            chunks.append("\n".join(current))
            current = [line]
            current_len = line_len
        else:
            current.append(line)
            current_len += line_len
    if current:
        chunks.append("\n".join(current))
    return chunks


def write_provider_config(config: dict[str, Any]) -> Path:
    NOTIFY_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    NOTIFY_CONFIG_PATH.write_text(yaml.dump(config, default_flow_style=False))
    return NOTIFY_CONFIG_PATH


async def dispatch(message: str) -> bool:
    config = build_provider_config()
    if config is None:
        logger.info("no notify providers configured, skipping notification")
        return False

    write_provider_config(config)

    for chunk in chunk_message(message):
        try:
            result = await run_tool(
                "notify",
                ["-silent", "-bulk", "-provider-config", str(NOTIFY_CONFIG_PATH)],
                stdin_data=chunk + "\n",
                timeout=30.0,
            )
            if not result.ok:
                logger.warning("notify exited %d: %s", result.returncode, result.stderr.strip())
                return False
        except ToolNotFoundError:
            logger.warning("notify tool not installed, skipping notification")
            return False
        except Exception:
            logger.exception("notify dispatch failed")
            return False

    return True
