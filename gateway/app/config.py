"""Central configuration, loaded from environment / .env.

Everything tunable about Raqib lives here so the platform's behaviour is
auditable from one place — the way a real detection stack keeps its policy
in config, not scattered through code.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    # ── Model backend ────────────────────────────────────────────────
    llm_backend: Literal["mock", "ollama"] = "mock"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"

    # ── LLM-as-judge detection layer ────────────────────────────────
    llm_judge_mode: Literal["off", "suspicious", "always"] = "suspicious"
    judge_model: str = "llama3"

    # ── Event store ─────────────────────────────────────────────────
    db_path: str = "raqib_events.db"

    # ── SOAR policy ─────────────────────────────────────────────────
    block_severities: list[str] = ["high", "critical"]
    quarantine_threshold: int = 5
    rate_limit_per_min: int = 60

    # ── Wazuh SIEM forwarding ───────────────────────────────────────
    wazuh_enabled: bool = False
    # how events reach Wazuh: "file" (Wazuh reads a JSON log — recommended) or
    # "syslog" (UDP). File mode is more robust and is the documented default.
    wazuh_mode: Literal["file", "syslog"] = "file"
    wazuh_log_file: str = "../wazuh/logs/raqib-events.json"
    wazuh_host: str = "127.0.0.1"
    wazuh_port: int = 514

    @field_validator("block_severities", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            return [s.strip().lower() for s in v.split(",") if s.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    """Cached singleton so config is parsed once per process."""
    return Settings()
