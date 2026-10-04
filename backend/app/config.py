"""Application settings.

Everything configurable comes from environment variables (or a local ``.env`` file) so that
no secret ever lives in source control. See ``.env.example`` for the documented list.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_csv(value: object) -> list[str]:
    """Turn ``"a, b,c"`` into ``["a", "b", "c"]``; pass lists through."""
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return list(value) if value else []  # type: ignore[call-overload]


class Settings(BaseSettings):
    """Typed view over the environment. One instance is shared via :func:`get_settings`."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", env_ignore_empty=True
    )

    # --- general -----------------------------------------------------------------------
    app_env: str = "dev"
    log_level: str = "INFO"

    # --- API surface -------------------------------------------------------------------
    # NoDecode: pydantic-settings would otherwise insist on JSON for list fields.
    api_tokens: Annotated[list[str], NoDecode] = []
    auth_disabled: bool = False
    cors_allowed_origins: Annotated[list[str], NoDecode] = []
    max_upload_bytes: int = 25 * 1024 * 1024
    rate_limit_per_minute: int = 30
    report_ttl_seconds: int = 900
    report_store_max: int = 200

    # --- cache -------------------------------------------------------------------------
    cache_backend: str = "sqlite"  # "sqlite" | "memory"
    cache_path: str = "data/cache.sqlite3"
    cache_ttl_vt_seconds: int = 24 * 3600
    cache_ttl_urlscan_seconds: int = 6 * 3600
    cache_ttl_rdap_seconds: int = 7 * 24 * 3600

    # --- enrichment --------------------------------------------------------------------
    vt_api_key: str = ""
    vt_requests_per_minute: int = 4
    vt_daily_quota: int = 500
    vt_max_lookups_per_report: int = 4
    vt_max_wait_seconds: float = 20.0
    urlscan_api_key: str = ""
    urlscan_visibility: str = "unlisted"  # "public" | "unlisted" | "private"
    urlscan_max_scans_per_report: int = 2
    urlscan_max_wait_seconds: float = 30.0
    rdap_enabled: bool = True
    rdap_base_url: str = "https://rdap.org"
    rdap_max_lookups_per_report: int = 8

    # --- network analysis --------------------------------------------------------------
    live_auth_checks: bool = True
    dns_timeout_seconds: float = 4.0
    expand_shorteners: bool = True
    hop_asn_lookup_enabled: bool = False
    http_timeout_seconds: float = 8.0

    # --- scoring -----------------------------------------------------------------------
    scoring_rules_path: str = ""  # empty = use the bundled app/scoring/rules.yaml
    score_suspicious_threshold: int | None = None
    score_phishing_threshold: int | None = None

    @field_validator("api_tokens", "cors_allowed_origins", mode="before")
    @classmethod
    def _csv(cls, value: object) -> list[str]:
        return _split_csv(value)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings (cached; tests override via dependency_overrides)."""
    return Settings()
