from authlib.integrations.starlette_client import OAuth
from app.core.config import settings
import os

oauth = OAuth()

# Get the Keycloak URL for browser redirects (external)
# In Docker, backend uses keycloak:8080, but browser needs localhost:8080
KEYCLOAK_EXTERNAL_URL = os.getenv("KEYCLOAK_EXTERNAL_URL", "http://localhost:8080")
realm = settings.KEYCLOAK_REALM

oauth.register(
    name="keycloak",
    client_id=settings.KEYCLOAK_CLIENT_ID,
    client_secret=settings.KEYCLOAK_CLIENT_SECRET,
    # Use external URL for browser-facing endpoints
    authorize_url=f"{KEYCLOAK_EXTERNAL_URL}/realms/{realm}/protocol/openid-connect/auth",
    access_token_url=f"{settings.KEYCLOAK_SERVER_URL}/realms/{realm}/protocol/openid-connect/token",
    jwks_uri=f"{settings.KEYCLOAK_SERVER_URL}/realms/{realm}/protocol/openid-connect/certs",
    client_kwargs={"scope": "openid email profile"},
)
