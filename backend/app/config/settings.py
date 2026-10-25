"""Typed, environment-driven configuration for Mini SOC.

All secrets come from the environment or from a per-install generated file -
none are hard-coded (spec section 25).  Invalid values fail fast with a clear
message instead of producing a half-configured security tool.
"""

from __future__ import annotations

import os
import secrets
import stat
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, get_origin

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_settings.sources import DotEnvSettingsSource

from .paths import AppPaths, default_paths

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

#: Fixed order used by every severity comparison in the code base.
SEVERITY_ORDER: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_SEQUENCE_ORIGINS = (list, set, frozenset, tuple)


class _LenientDotEnvSource(DotEnvSettingsSource):
    """Read comma-separated values in ``.env`` for sequence fields.

    pydantic-settings requires JSON for complex fields, so
    ``MINI_SOC_CORS_ORIGINS=http://a,http://b`` would abort startup with a
    parse error.  Operators write comma-separated lists; accept both that and
    JSON (which still wins when the value starts with ``[``).
    """

    def prepare_field_value(  # type: ignore[override]
        self,
        field_name: str,
        field: Any,
        value: Any,
        value_is_complex: bool,
    ) -> Any:
        annotation = getattr(field, "annotation", None)
        if (
            isinstance(value, str)
            and (value_is_complex or self.field_is_complex(field))
            and get_origin(annotation) in _SEQUENCE_ORIGINS
            and not value.strip().startswith("[")
        ):
            return [item.strip() for item in value.split(",") if item.strip()]
        return super().prepare_field_value(field_name, field, value, value_is_complex)


class Settings(BaseSettings):
    """Runtime settings for the whole platform."""

    model_config = SettingsConfigDict(
        env_prefix="MINI_SOC_",
        env_file=(str(default_paths().home / ".env"),),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- application -------------------------------------------------------
    env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"
    log_json: bool = True
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 5
    app_name: str = "Mini SOC"
    version: str = "1.0.0"
    host: str = "127.0.0.1"
    port: int = 8000
    api_prefix: str = "/api/v1"
    home: str = ""

    # --- database ----------------------------------------------------------
    database_url: str = "sqlite+pysqlite:///./data/mini_soc.db"
    db_echo: bool = False
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_write_batch_size: int = 100

    # --- secrets / tokens --------------------------------------------------
    jwt_secret: str = ""
    access_token_minutes: int = 30
    refresh_token_days: int = 7
    jwt_algorithm: str = "HS256"

    # --- bootstrap admin ---------------------------------------------------
    admin_username: str = "admin"
    admin_password: str = ""
    admin_email: str = "admin@example.invalid"

    # --- collectors --------------------------------------------------------
    collector_network_enabled: bool = True
    collector_interface: str = ""
    collector_bpf_filter: str = "tcp or udp or icmp or arp"
    collector_snaplen: int = 128
    collector_promiscuous: bool = False
    collector_syslog_enabled: bool = True
    collector_syslog_host: str = "0.0.0.0"
    collector_syslog_port: int = 5514
    collector_system_enabled: bool = False
    collector_system_interval_seconds: int = 15
    simulator_enabled: bool = False
    simulator_eps: float = 5.0
    simulator_seed: int = 1337
    simulator_scenario: Literal[
        "normal", "port_scan", "brute_force", "connection_flood", "dns_anomaly", "volume_anomaly"
    ] = "normal"

    # --- pipeline ----------------------------------------------------------
    pipeline_queue_size: int = 20000
    pipeline_workers: int = 2
    pipeline_dedupe_window_seconds: int = 5
    pipeline_dedupe_max_entries: int = 50000
    pipeline_feature_window_seconds: int = 300
    pipeline_retention_days: int = 30

    # --- detection ---------------------------------------------------------
    rules_path: str = str(default_paths().rules)
    rules_reload_seconds: int = 60
    anomaly_enabled: bool = True
    anomaly_model: str = "isolation_forest"
    anomaly_threshold: float = -0.05
    correlation_window_seconds: int = 600

    # --- risk bands --------------------------------------------------------
    risk_low_max: int = 30
    risk_medium_max: int = 60
    risk_high_max: int = 80
    risk_weights: dict[str, float] = Field(
        default_factory=lambda: {
            "rule": 0.45,
            "ml": 0.25,
            "frequency": 0.15,
            "confidence": 0.10,
            "asset": 0.05,
        }
    )

    # --- api / security ----------------------------------------------------
    rate_limit_per_minute: int = 240
    login_rate_limit_per_minute: int = 10
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )
    secure_headers: bool = True
    trusted_hosts: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"]
    )
    audit_log_enabled: bool = True
    ws_max_connections: int = 200

    # ------------------------------------------------------------------ init
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: Any,
        env_settings: Any,
        dotenv_settings: Any,
        file_secret_settings: Any,
    ) -> tuple[Any, ...]:
        """Keep the default precedence, but accept comma-separated ``.env`` lists."""
        return (
            init_settings,
            env_settings,
            _LenientDotEnvSource(settings_cls),
            file_secret_settings,
        )

    @field_validator("cors_origins", "trusted_hosts", mode="before")
    @classmethod
    def _split_list(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("log_level")
    @classmethod
    def _valid_log_level(cls, value: str) -> str:
        level = value.upper().strip()
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        if level not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return level

    @model_validator(mode="after")
    def _validate(self) -> "Settings":
        if not (0 <= self.risk_low_max < self.risk_medium_max < self.risk_high_max <= 100):
            raise ValueError(
                "risk bands must satisfy 0 <= LOW < MEDIUM < HIGH <= 100 "
                f"(got {self.risk_low_max}/{self.risk_medium_max}/{self.risk_high_max})"
            )
        if self.env == "production" and not self.jwt_secret:
            raise ValueError(
                "MINI_SOC_JWT_SECRET is required in production; "
                "generate one with `python -m app.services.secrets generate`"
            )
        if self.env == "production" and not self.admin_password:
            # Not fatal: production admins are usually created out of band.
            pass
        if self.pipeline_workers < 1:
            raise ValueError("pipeline_workers must be >= 1")
        return self

    # --------------------------------------------------------------- helpers
    @property
    def paths(self) -> AppPaths:
        if self.home.strip():
            return AppPaths(home=Path(os.path.abspath(os.path.expanduser(self.home.strip()))))
        return default_paths()

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def severity_for(self, score: float) -> Severity:
        """Map a 0-100 risk score to a severity band (configurable)."""
        score = max(0.0, min(100.0, float(score)))
        if score <= self.risk_low_max:
            return "LOW"
        if score <= self.risk_medium_max:
            return "MEDIUM"
        if score <= self.risk_high_max:
            return "HIGH"
        return "CRITICAL"

    def severity_at_least(self, severity: str, threshold: str) -> bool:
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)

    def resolved_jwt_secret(self) -> str:
        """Return the JWT signing secret, generating one if necessary.

        Development convenience only: in production the secret must be
        supplied through the environment (enforced by the model validator).
        When auto-generated it is persisted to ``data/secrets/jwt.key`` so
        tokens survive a restart.  The file is created with restrictive
        permissions where the platform supports it.
        """
        if self.jwt_secret:
            return self.jwt_secret

        key_file = self.paths.secrets / "jwt.key"
        key_file.parent.mkdir(parents=True, exist_ok=True)
        if key_file.exists():
            existing = key_file.read_text(encoding="utf-8").strip()
            if existing:
                return existing

        generated = secrets.token_urlsafe(64)
        key_file.write_text(generated, encoding="utf-8")
        try:
            os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:  # pragma: no cover - best effort on Windows
            pass
        return generated

    def ensure_directories(self) -> AppPaths:
        """Create data/log/secrets directories and return the resolved paths."""
        paths = self.paths.ensure()
        sqlite_file = paths.sqlite_file(self.database_url)
        if sqlite_file is not None:
            sqlite_file.parent.mkdir(parents=True, exist_ok=True)
        return paths


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton (see :func:`reset_settings_cache` for tests)."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear the cached settings (used by tests and by `--reload` runs)."""
    get_settings.cache_clear()


__all__ = [
    "SEVERITY_ORDER",
    "Settings",
    "Severity",
    "get_settings",
    "reset_settings_cache",
]
