from pydantic_settings import BaseSettings
from pydantic import field_validator


class Settings(BaseSettings):
    ENV: str = "dev"
    SESSION_SECRET_KEY: str | None = None

    KEYCLOAK_CLIENT_ID: str
    KEYCLOAK_CLIENT_SECRET: str
    KEYCLOAK_REALM: str
    KEYCLOAK_SERVER_URL: str = "http://localhost:8080"

    KEYCLOAK_ADMIN_CLIENT_ID: str | None = None
    KEYCLOAK_ADMIN_CLIENT_SECRET: str | None = None

    FRONTEND_URL: str = "http://localhost:5173"

    @property
    def metadata_url(self) -> str:
        return (
            f"{self.KEYCLOAK_SERVER_URL}/realms/"
            f"{self.KEYCLOAK_REALM}/.well-known/openid-configuration"
        )

    @field_validator("SESSION_SECRET_KEY", mode="before")
    def validate_secret(cls, v, info):
        env = info.data.get("ENV", "dev")
        if env == "prod" and not v:
            raise ValueError("SESSION_SECRET_KEY must be set in production")
        return v or "dev-secret-change-me"

    class Config:
        env_file = ".env"


settings = Settings()
