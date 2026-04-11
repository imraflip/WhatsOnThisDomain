import os
from pathlib import Path

from wotd.config import load_config


def test_load_yaml_config(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "tools:\n  subfinder_path: /usr/local/bin/subfinder\nwordlists:\n  dns: /opt/words.txt\n"
    )
    config = load_config(config_path=config_file)
    assert config["tools"]["subfinder_path"] == "/usr/local/bin/subfinder"
    assert config["wordlists"]["dns"] == "/opt/words.txt"


def test_load_missing_yaml_returns_empty(tmp_path: Path) -> None:
    config = load_config(config_path=tmp_path / "nope.yaml")
    assert config == {}


def test_dotenv_loading(tmp_path: Path, monkeypatch: object) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("WOTD_TOOLS__SUBFINDER_PATH=/from/dotenv\n")
    config = load_config(config_path=tmp_path / "nope.yaml", env_file=env_file)
    assert config["tools"]["subfinder_path"] == "/from/dotenv"


def test_env_vars_override_yaml(tmp_path: Path, monkeypatch: object) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("tools:\n  subfinder_path: /from/yaml\n")

    os.environ["WOTD_TOOLS__SUBFINDER_PATH"] = "/from/env"
    try:
        config = load_config(config_path=config_file)
        assert config["tools"]["subfinder_path"] == "/from/env"
    finally:
        del os.environ["WOTD_TOOLS__SUBFINDER_PATH"]
