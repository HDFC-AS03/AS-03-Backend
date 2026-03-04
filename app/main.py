from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from app.core.logging_config import setup_logging
from app.core.config import settings
from app.api.routes import router

setup_logging()

app = FastAPI(title="Keycloak Auth Service")

# CORS is handled by the API gateway - no middleware needed here

# SessionMiddleware is required by Authlib for OAuth state storage during login flow
# This is NOT for user session auth - we use stateless JWT bearer tokens
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET_KEY)

app.include_router(router)
