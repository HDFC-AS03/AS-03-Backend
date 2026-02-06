from pydantic_settings import BaseSettings
from pydantic import validator


class Settings(BaseSettings):
    """Application settings loaded from environment (or .env).

    Required in production: `SESSION_SECRET_KEY`, Keycloak client credentials.
    """
    # App Config
    ENV: str = "dev"
    SESSION_SECRET_KEY: str | None = None

    # Keycloak Config
    KEYCLOAK_CLIENT_ID: str | None = None
    KEYCLOAK_CLIENT_SECRET: str | None = None
    KEYCLOAK_REALM: str | None = None
    KEYCLOAK_SERVER_URL: str = "http://localhost:8080"
    # Optional: allow overriding metadata/jwks url explicitly
    KEYCLOAK_METADATA_URL: str | None = None
    # Optional admin client for Keycloak Admin REST API (used for user sync)
    KEYCLOAK_ADMIN_CLIENT_ID: str | None = None
    KEYCLOAK_ADMIN_CLIENT_SECRET: str | None = None

    @property
    def metadata_url(self) -> str:
        if self.KEYCLOAK_METADATA_URL:
            return self.KEYCLOAK_METADATA_URL
        if not (self.KEYCLOAK_SERVER_URL and self.KEYCLOAK_REALM):
            return ""
        return f"{self.KEYCLOAK_SERVER_URL}/realms/{self.KEYCLOAK_REALM}/.well-known/openid-configuration"

    @validator("SESSION_SECRET_KEY", pre=True, always=True)
    def ensure_session_secret(cls, v, values):
        env = values.get("ENV", "dev")
        if env == "prod" and not v:
            raise ValueError("SESSION_SECRET_KEY must be set in production")
        # In dev, generate a default weak secret if not provided (not for prod)
        return v or "dev-secret-change-me"

    class Config:
        env_file = ".env"


# Instantiate settings to be imported elsewhere
settings = Settings()