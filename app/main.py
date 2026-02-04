import logging
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from .config import settings
from .routes import router

# Configure logging for production
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Keycloak Auth Service")

# Security: Ensure cookies are Secure (HTTPS only) in production
is_production = settings.ENV == "prod"

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET_KEY,
    https_only=is_production, # True in Prod, False in Dev
    same_site="lax"
)

# Register Routes
app.include_router(router)