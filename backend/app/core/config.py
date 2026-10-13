import json
from functools import lru_cache
from typing import Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables and defaults."""

    app_name: str = Field(
        default="SentinelAI",
        description="Application title displayed in docs and root endpoint",
    )
    app_version: str = Field(
        default="0.1.0",
        description="Semantic application version",
    )
    app_description: str = Field(
        default="Intelligent Cloud Security & DevSecOps Platform",
        description="Application description displayed in Swagger documentation",
    )
    environment: str = Field(
        default="development",
        description="Current operational environment: development, staging, production",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode for diagnostic error responses",
    )
    api_v1_prefix: str = Field(
        default="/api/v1",
        description="Prefix for modular API version 1 endpoints",
    )
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"],
        description="Explicit allowed CORS origins",
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Union[str, list[str]]) -> list[str]:
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
