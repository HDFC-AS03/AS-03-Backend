import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth.dependencies import require_auth

@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def fake_user():
    return {
        "sub": "123",
        "email": "test@example.com",
        "preferred_username": "testuser",
        "name": "Test User",
        "roles": ["admin"],
        "exp": 9999999999,
    }


@pytest.fixture
def override_auth(fake_user):
    app.dependency_overrides[require_auth] = lambda: fake_user
    yield
    app.dependency_overrides = {}