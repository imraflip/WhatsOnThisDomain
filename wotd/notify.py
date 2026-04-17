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


@dataclass
class NotifyPayload:
    target: str
    new_count: int
    resolved_count: int
    probed_count: int
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


MAX_HOST_DISPLAY = 25

STATUS_ORDER = {"probed": 0, "resolved": 1, "found": 2}


def format_message(payload: NotifyPayload) -> str | None:
    if payload.new_count == 0:
        return None

    parts: list[str] = []
    parts.append(f"[wotd] {payload.target}")
    parts.append(f"{payload.new_count} new subdomain(s) found")
    parts.append(f"{payload.resolved_count} resolved")
    parts.append(f"{payload.probed_count} live (HTTP)")

    if payload.new_hosts:
        ordered = sorted(
            payload.new_hosts, key=lambda h: (STATUS_ORDER.get(h.status, 99), h.host)
        )
        shown = ordered[:MAX_HOST_DISPLAY]
        parts.append("")
        for h in shown:
            if h.status == "probed" and h.status_code is not None:
                parts.append(f"{h.host} (probed {h.status_code})")
            else:
                parts.append(f"{h.host} ({h.status})")
        remaining = len(ordered) - len(shown)
        if remaining > 0:
            parts.append(f"(+{remaining} more)")

    return "\n".join(parts)


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

    try:
        result = await run_tool(
            "notify",
            ["-silent", "-provider-config", str(NOTIFY_CONFIG_PATH)],
            stdin_data=message + "\n",
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
