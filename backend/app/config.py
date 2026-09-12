from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str

    SECRET_KEY: str

    OTX_API_KEY: str = ""
    PHISHTANK_APP_KEY: str = ""
    SENDGRID_API_KEY: str = ""

    INGESTION_INTERVAL_MINUTES: int = 60
    FREE_TIER_WINDOW_HOURS: int = 24

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()