from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from platformdirs import user_config_dir

DEFAULT_CONFIG_DIR = Path(user_config_dir("wotd"))
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yaml"


def load_config(
    config_path: Path | None = None,
    env_file: Path | None = None,
) -> dict[str, Any]:
    """Load configuration with precedence: env vars > .env > config.yaml."""
    config: dict[str, Any] = {}

    yaml_path = config_path or DEFAULT_CONFIG_FILE
    if yaml_path.exists():
        with open(yaml_path) as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                config = loaded

    dotenv_path = env_file or Path(".env")
    if dotenv_path.exists():
        load_dotenv(dotenv_path, override=True)

    _apply_env_overrides(config)

    return config


def _apply_env_overrides(config: dict[str, Any]) -> None:
    """Override config values with WOTD_ prefixed environment variables.

    Env var names map to nested keys with __ as separator.
    Example: WOTD_TOOLS__SUBFINDER_PATH -> config["tools"]["subfinder_path"]
    """
    prefix = "WOTD_"
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix) :].lower().split("__")
        target = config
        for part in parts[:-1]:
            if part not in target or not isinstance(target[part], dict):
                target[part] = {}
            target = target[part]
        target[parts[-1]] = value
