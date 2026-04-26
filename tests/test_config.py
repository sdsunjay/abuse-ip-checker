from pathlib import Path

import pytest
import yaml

from abuse_ip_checker.config.config import get_api_key, load_config, save_config


def test_get_api_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "env_key_123")
    assert get_api_key("abuseipdb") == "env_key_123"


def test_get_api_key_from_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump({"api_keys": {"abuseipdb": "file_key_456"}}))
    assert get_api_key("abuseipdb", config_path=str(config_file)) == "file_key_456"


def test_get_api_key_env_overrides_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "env_key")
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump({"api_keys": {"abuseipdb": "file_key"}}))
    assert get_api_key("abuseipdb", config_path=str(config_file)) == "env_key"


def test_get_api_key_returns_none_when_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump({"api_keys": {}}))
    assert get_api_key("virustotal", config_path=str(config_file)) is None


def test_get_api_key_no_config_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    config_file = tmp_path / "nonexistent.yaml"
    assert get_api_key("shodan", config_path=str(config_file)) is None


def test_save_and_load_config(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    save_config({"api_keys": {"abuseipdb": "test_key"}}, config_path=str(config_file))
    loaded = load_config(config_path=str(config_file))
    assert loaded["api_keys"]["abuseipdb"] == "test_key"
