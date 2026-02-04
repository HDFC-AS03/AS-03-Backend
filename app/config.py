from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # App Config
    ENV: str = "dev"
    SESSION_SECRET_KEY: str

    # Keycloak Config
    KEYCLOAK_CLIENT_ID: str
    KEYCLOAK_CLIENT_SECRET: str
    KEYCLOAK_REALM: str
    KEYCLOAK_SERVER_URL: str

    @property
    def metadata_url(self) -> str:
        return f"{self.KEYCLOAK_SERVER_URL}/realms/{self.KEYCLOAK_REALM}/.well-known/openid-configuration"

    class Config:
        env_file = ".env"

# Instantiate settings to be imported elsewhere
settings = Settings()