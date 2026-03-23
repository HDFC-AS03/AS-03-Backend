# tests/conftest.py
import os
import pytest

# ── Minimal env so pydantic-settings can build Settings ─────────────────────
os.environ.setdefault("ENV", "test")
os.environ.setdefault("KEYCLOAK_REALM", "test-realm")
os.environ.setdefault("KEYCLOAK_SERVER_URL", "http://keycloak:8080")
os.environ.setdefault("KEYCLOAK_EXTERNAL_URL", "http://localhost:8080")
os.environ.setdefault("KEYCLOAK_REFRESH_URL", "http://keycloak:8080")
os.environ.setdefault("KEYCLOAK_CLIENT_ID", "test-client")
os.environ.setdefault("KEYCLOAK_CLIENT_SECRET", "test-secret")
os.environ.setdefault("FRONTEND_URL", "http://localhost:3000")
os.environ.setdefault("GATEWAY_URL", "http://localhost:80")
os.environ.setdefault("SESSION_SECRET_KEY", "test-key")
os.environ.setdefault("ACCESS_TOKEN_MAX_AGE", "900")
os.environ.setdefault("REFRESH_TOKEN_MAX_AGE", "86400")
os.environ.setdefault("OAUTH_STATE_MAX_AGE", "300")
os.environ.setdefault("JWKS_URL", "http://keycloak:8080/realms/test-realm/protocol/openid-connect/certs")
os.environ.setdefault("JWT_ISSUER_1", "http://keycloak:8080/realms/test-realm")
os.environ.setdefault("JWT_ISSUER_2", "http://localhost:8080/realms/test-realm")
os.environ.setdefault("JWKS_CACHE_TTL", "300")


@pytest.fixture
def admin_user():
    return {
        "sub": "admin-uuid",
        "email": "admin@example.com",
        "preferred_username": "admin",
        "roles": ["admin"],
        "exp": 9999999999,
    }


@pytest.fixture
def regular_user():
    return {
        "sub": "user-uuid",
        "email": "user@example.com",
        "preferred_username": "user",
        "roles": ["user"],
        "exp": 9999999999,
    }


@pytest.fixture
def mock_keycloak_token_response():
    return {
        "access_token": "fake-access-token",
        "refresh_token": "fake-refresh-token",
        "token_type": "Bearer",
        "expires_in": 900,
    }