import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from .config import settings
from .routes import router

# Configure logging for production
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Keycloak Auth Service")

# CORS Configuration: Allow frontend to call auth endpoints
# In development, allow all origins; in production, specify exact frontend origin
if settings.ENV == "dev":
    allow_origins = ["*"]
else:
    # Production: Replace with your actual frontend domain(s)
    allow_origins = ["https://app.example.com", "https://admin.example.com"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,  # Allow cookies and auth headers
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

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