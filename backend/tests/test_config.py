"""Configuration, path resolution and logging behaviour."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from app.config.logging_config import redact, setup_logging
from app.config.paths import AppPaths, HOME_ENV, default_paths, resolve_home
from app.config.settings import Settings, reset_settings_cache


class TestPaths:
    def test_home_env_override_wins(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv(HOME_ENV, str(tmp_path))
        assert resolve_home() == tmp_path

    def test_repository_root_is_detected_without_override(self, monkeypatch) -> None:
        monkeypatch.delenv(HOME_ENV, raising=False)
        home = resolve_home()
        assert (home / "backend").is_dir()

    def test_ensure_creates_every_writable_directory(self, tmp_path: Path) -> None:
        paths = AppPaths(home=tmp_path / "soc").ensure()
        for directory in (paths.data, paths.logs, paths.secrets, paths.artifacts):
            assert directory.is_dir()

    def test_sqlite_file_resolution(self, tmp_path: Path) -> None:
        paths = AppPaths(home=tmp_path)
        assert paths.sqlite_file("sqlite+pysqlite:///./data/soc.db") == (tmp_path / "data/soc.db").resolve()
        assert paths.sqlite_file("postgresql+psycopg://user@host/db") is None
        assert paths.sqlite_file("sqlite+pysqlite:///:memory:") is None

    def test_default_paths_are_absolute(self) -> None:
        assert default_paths().home.is_absolute()


class TestSettings:
    def test_severity_bands_are_configurable(self) -> None:
        settings = Settings(risk_low_max=10, risk_medium_max=20, risk_high_max=30)
        assert settings.severity_for(5) == "LOW"
        assert settings.severity_for(15) == "MEDIUM"
        assert settings.severity_for(25) == "HIGH"
        assert settings.severity_for(100) == "CRITICAL"

    def test_invalid_bands_are_rejected(self) -> None:
        with pytest.raises(ValueError):
            Settings(risk_low_max=70, risk_medium_max=40, risk_high_max=90)

    def test_production_requires_a_jwt_secret(self) -> None:
        with pytest.raises(ValueError):
            Settings(env="production", jwt_secret="")

    def test_production_accepts_an_explicit_secret(self) -> None:
        settings = Settings(env="production", jwt_secret="x" * 64)
        assert settings.is_production
        assert settings.resolved_jwt_secret() == "x" * 64

    def test_list_settings_parse_from_comma_separated_strings(self) -> None:
        settings = Settings(cors_origins="https://a.example, https://b.example")
        assert settings.cors_origins == ["https://a.example", "https://b.example"]

    def test_invalid_log_level_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            Settings(log_level="SHOUTING")

    def test_secret_is_generated_once_and_reused(self, tmp_path: Path) -> None:
        settings = Settings(home=str(tmp_path))
        first = settings.resolved_jwt_secret()
        second = Settings(home=str(tmp_path)).resolved_jwt_secret()
        assert first == second
        assert len(first) > 40
        assert (tmp_path / "data" / "secrets" / "jwt.key").exists()

    def test_settings_cache_can_be_reset(self) -> None:
        reset_settings_cache()
        assert Settings().app_name == "Mini SOC"


class TestLogging:
    def test_redaction_removes_credentials(self) -> None:
        payload = '{"password": "hunter2", "username": "admin"}'
        assert "hunter2" not in redact(payload)
        assert redact("token=abcdef123") == "token=***"

    def test_logging_writes_structured_records(self, tmp_path: Path) -> None:
        settings = Settings(home=str(tmp_path), log_level="INFO", log_json=True)
        setup_logging(settings, force=True)
        logger = logging.getLogger("mini_soc.test")
        logger.info("unit test line", extra={"component": "tests"})

        for handler in logging.getLogger().handlers:
            handler.flush()
        log_file = tmp_path / "logs" / "mini_soc.log"
        assert log_file.exists()
        entry = json.loads(log_file.read_text(encoding="utf-8").strip().splitlines()[-1])
        assert entry["message"] == "unit test line"
        assert entry["component"] == "tests"
        assert entry["level"] == "INFO"

    def test_reserved_extra_keys_do_not_break_logging(self, tmp_path: Path) -> None:
        # ``created``/``name`` collide with LogRecord attributes; the logger must
        # rename them instead of raising inside a request handler.
        settings = Settings(home=str(tmp_path), log_level="INFO")
        setup_logging(settings, force=True)
        logging.getLogger("mini_soc.test").info("collision", extra={"created": 1, "name": "x"})
        for handler in logging.getLogger().handlers:
            handler.flush()
        assert (tmp_path / "logs" / "mini_soc.log").exists()
