from fastapi import FastAPI
from app.core.logging_config import setup_logging
from app.api.routes import router

setup_logging()

app = FastAPI(title="Keycloak Auth Service")

# CORS is handled by the API gateway - no middleware needed here
# Auth is stateless (JWT bearer tokens only) - no session middleware needed

app.include_router(router)
