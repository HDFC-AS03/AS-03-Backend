from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    ENV: str = "dev"

    KEYCLOAK_CLIENT_ID: str
    KEYCLOAK_CLIENT_SECRET: str
    KEYCLOAK_REALM: str
    KEYCLOAK_SERVER_URL: str = "http://localhost:8080"

    KEYCLOAK_ADMIN_CLIENT_ID: str | None = None
    KEYCLOAK_ADMIN_CLIENT_SECRET: str | None = None

    FRONTEND_URL: str = "http://localhost:5173"
    GATEWAY_URL: str = "http://localhost"  # API gateway URL for OAuth callbacks

    @property
    def metadata_url(self) -> str:
        return (
            f"{self.KEYCLOAK_SERVER_URL}/realms/"
            f"{self.KEYCLOAK_REALM}/.well-known/openid-configuration"
        )


settings = Settings()
