from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from app.core.config import settings
from app.core.logging_config import setup_logging
from app.api.routes import router

setup_logging()

app = FastAPI(title="Keycloak Auth Service")

# CORS is handled by the API gateway - no middleware needed here

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET_KEY,
    https_only=settings.ENV == "prod",
    same_site="lax",
)

app.include_router(router)
