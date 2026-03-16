# app/core/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # ==========================================
    # ENVIRONMENT
    # ==========================================
    ENV: str = "dev"

    # ==========================================
    # KEYCLOAK SETTINGS
    # ==========================================
    KEYCLOAK_REALM: str
    KEYCLOAK_SERVER_URL: str
    KEYCLOAK_EXTERNAL_URL: str
    KEYCLOAK_REFRESH_URL: str
    KEYCLOAK_CLIENT_ID: str
    KEYCLOAK_CLIENT_SECRET: str

    # ==========================================
    # ADMIN CLIENT
    # ==========================================
    KEYCLOAK_ADMIN_CLIENT_ID: str | None = None
    KEYCLOAK_ADMIN_CLIENT_SECRET: str | None = None

    # ==========================================
    # FRONTEND / GATEWAY
    # ==========================================
    FRONTEND_URL: str
    GATEWAY_URL: str

    # ==========================================
    # SECURITY
    # ==========================================
    SESSION_SECRET_KEY: str
    ACCESS_TOKEN_MAX_AGE: int
    REFRESH_TOKEN_MAX_AGE: int
    OAUTH_STATE_MAX_AGE: int

    # ==========================================
    # JWT VALIDATOR
    # ==========================================
    JWKS_URL: str
    JWT_ISSUER_1: str
    JWT_ISSUER_2: str
    JWKS_CACHE_TTL: int

    # ==========================================
    # KEYCLOAK ADMIN (for docker-compose)
    # ==========================================
    KEYCLOAK_ADMIN: str | None = None
    KEYCLOAK_ADMIN_PASSWORD: str | None = None

    # ==========================================
    # PROPERTIES
    # ==========================================
    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    @property
    def metadata_url(self) -> str:
        return (
            f"{self.KEYCLOAK_SERVER_URL}/realms/"
            f"{self.KEYCLOAK_REALM}/.well-known/openid-configuration"
        )


settings = Settings()