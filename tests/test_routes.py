# tests/test_routes.py
import pytest
import json
import secrets
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import FastAPI

# ---------------------------------------------------------------------------
# App bootstrap (minimal, avoids importing real settings)
# ---------------------------------------------------------------------------
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Provide all required env vars before any app import
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
os.environ.setdefault(
    "JWKS_URL", "http://keycloak:8080/realms/test-realm/protocol/openid-connect/certs"
)
os.environ.setdefault("JWT_ISSUER_1", "http://keycloak:8080/realms/test-realm")
os.environ.setdefault("JWT_ISSUER_2", "http://localhost:8080/realms/test-realm")
os.environ.setdefault("JWKS_CACHE_TTL", "300")

from app.api.routes import router
from app.auth.dependencies import get_gateway_user, require_auth, require_role

app = FastAPI()
app.include_router(router)
client = TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_admin_user():
    return {
        "sub": "admin-uuid",
        "email": "admin@example.com",
        "preferred_username": "admin",
        "roles": ["admin"],
        "exp": 9999999999,
    }


def make_regular_user():
    return {
        "sub": "user-uuid",
        "email": "user@example.com",
        "preferred_username": "user",
        "roles": ["user"],
        "exp": 9999999999,
    }


# ===========================================================================
# 1. ROOT
# ===========================================================================
class TestRoot:
    def test_root_returns_200(self):
        r = client.get("/")
        assert r.status_code == 200

    def test_root_message(self):
        r = client.get("/")
        assert r.json()["message"] == "Auth Service Running"


# ===========================================================================
# 2. HEALTH
# ===========================================================================
class TestHealth:
    def test_health_ok(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


# ===========================================================================
# 3. LOGIN
# ===========================================================================
class TestLogin:
    def test_login_redirects(self):
        r = client.get("/login", follow_redirects=False)
        assert r.status_code in (302, 307)

    def test_login_redirect_points_to_keycloak(self):
        r = client.get("/login", follow_redirects=False)
        location = r.headers.get("location", "")
        assert "openid-connect/auth" in location

    def test_login_sets_state_cookie(self):
        r = client.get("/login", follow_redirects=False)
        assert "oauth_state" in r.cookies

    def test_login_sets_pkce_verifier_cookie(self):
        r = client.get("/login", follow_redirects=False)
        assert "pkce_verifier" in r.cookies

    def test_login_redirect_contains_code_challenge(self):
        r = client.get("/login", follow_redirects=False)
        location = r.headers.get("location", "")
        assert "code_challenge=" in location
        assert "code_challenge_method=S256" in location

    def test_login_state_in_redirect_matches_cookie(self):
        r = client.get("/login", follow_redirects=False)
        location = r.headers.get("location", "")
        cookie_state = r.cookies.get("oauth_state")
        assert cookie_state and f"state={cookie_state}" in location

    def test_login_redirect_contains_correct_client_id(self):
        r = client.get("/login", follow_redirects=False)
        location = r.headers.get("location", "")
        assert "client_id=test-client" in location

    def test_login_redirect_contains_scope(self):
        r = client.get("/login", follow_redirects=False)
        location = r.headers.get("location", "")
        assert "scope=" in location


# ===========================================================================
# 4. CALLBACK
# ===========================================================================
class TestCallback:
    def _get_state_and_verifier(self):
        r = client.get("/login", follow_redirects=False)
        state = r.cookies.get("oauth_state")
        verifier = r.cookies.get("pkce_verifier")
        return state, verifier

    def test_callback_missing_code_returns_400(self):
        state, verifier = self._get_state_and_verifier()
        r = client.get(
            f"/callback?state={state}",
            cookies={"oauth_state": state, "pkce_verifier": verifier},
        )
        assert r.status_code == 400

    def test_callback_missing_state_returns_400(self):
        state, verifier = self._get_state_and_verifier()
        r = client.get(
            "/callback?code=abc123",
            cookies={"oauth_state": state, "pkce_verifier": verifier},
        )
        assert r.status_code == 400

    def test_callback_oauth_error_returns_400(self):
        r = client.get("/callback?error=access_denied")
        assert r.status_code == 400
        assert "OAuth error" in r.json().get("detail", "")

    def test_callback_invalid_state_returns_400(self):
        state, verifier = self._get_state_and_verifier()
        r = client.get(
            "/callback?code=abc&state=WRONG_STATE",
            cookies={"oauth_state": state, "pkce_verifier": verifier},
        )
        assert r.status_code == 400

    def test_callback_missing_state_cookie_returns_400(self):
        r = client.get("/callback?code=abc&state=somestate")
        assert r.status_code == 400
        assert "state" in r.json().get("detail", "").lower()
    def test_callback_missing_pkce_verifier_returns_400(self):
    # Clear previous cookies
        client.cookies.clear()
    # Get fresh state + verifier
        state, _ = self._get_state_and_verifier()
    # Remove PKCE to simulate missing cookie
        client.cookies.pop("pkce_verifier", None)
    # Make request
        r = client.get(
            f"/callback?code=abc&state={state}"
    )
    # Assertions
        assert r.status_code == 400
        assert "PKCE" in r.json().get("detail", "")

    @patch("app.api.routes.httpx.AsyncClient")
    def test_callback_token_exchange_failure_returns_401(self, mock_http):
        state, verifier = self._get_state_and_verifier()

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
        mock_http.return_value = mock_client

        r = client.get(
            f"/callback?code=bad_code&state={state}",
            cookies={"oauth_state": state, "pkce_verifier": verifier},
        )
        assert r.status_code == 401

    @patch("app.api.routes.httpx.AsyncClient")
    def test_callback_success_sets_cookies_and_redirects(self, mock_http):
        state, verifier = self._get_state_and_verifier()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "fake-access",
            "refresh_token": "fake-refresh",
        }
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
        mock_http.return_value = mock_client

        r = client.get(
            f"/callback?code=valid_code&state={state}",
            cookies={"oauth_state": state, "pkce_verifier": verifier},
            follow_redirects=False,
        )
        assert r.status_code in (302, 307)
        assert "access_token" in r.cookies
        assert "refresh_token" in r.cookies
        assert "csrf_token" in r.cookies

    @patch("app.api.routes.httpx.AsyncClient")
    def test_callback_clears_oauth_state_cookie(self, mock_http):
        state, verifier = self._get_state_and_verifier()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"access_token": "t", "refresh_token": "r"}
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
        mock_http.return_value = mock_client

        r = client.get(
            f"/callback?code=code&state={state}",
            cookies={"oauth_state": state, "pkce_verifier": verifier},
            follow_redirects=False,
        )
        # oauth_state and pkce_verifier must be deleted (empty or absent)
        assert r.cookies.get("oauth_state", "") == ""
        assert r.cookies.get("pkce_verifier", "") == ""


# ===========================================================================
# 5. LOGOUT
# ===========================================================================
class TestLogout:
    def test_logout_redirects(self):
        r = client.get("/logout", follow_redirects=False)
        assert r.status_code in (302, 307)

    def test_logout_redirect_points_to_keycloak(self):
        r = client.get("/logout", follow_redirects=False)
        location = r.headers.get("location", "")
        assert "openid-connect/logout" in location

    def test_logout_clears_access_token_cookie(self):
        r = client.get("/logout", follow_redirects=False)
        # Cookie deleted = set to empty string with max-age=0
        assert r.cookies.get("access_token", "") == ""

    def test_logout_clears_refresh_token_cookie(self):
        r = client.get("/logout", follow_redirects=False)
        assert r.cookies.get("refresh_token", "") == ""

    def test_logout_clears_csrf_cookie(self):
        r = client.get("/logout", follow_redirects=False)
        assert r.cookies.get("csrf_token", "") == ""


# ===========================================================================
# 6. /ME
# ===========================================================================
class TestGetCurrentUser:
    def test_me_unauthenticated_returns_401(self):
        r = client.get("/me")
        assert r.status_code == 401

    def test_me_authenticated_returns_user_data(self):
        user = make_regular_user()
        app.dependency_overrides[get_gateway_user] = lambda: user
        try:
            r = client.get("/me")
            assert r.status_code == 200
            data = r.json()
            assert data["success"] is True
            assert data["data"]["email"] == "user@example.com"
            assert data["data"]["sub"] == "user-uuid"
        finally:
            app.dependency_overrides.pop(get_gateway_user, None)

    def test_me_response_contains_metadata(self):
        user = make_regular_user()
        app.dependency_overrides[get_gateway_user] = lambda: user
        try:
            r = client.get("/me")
            assert "metadata" in r.json()
            assert "timestamp" in r.json()["metadata"]
        finally:
            app.dependency_overrides.pop(get_gateway_user, None)

    def test_me_response_includes_ttl(self):
        user = make_regular_user()
        app.dependency_overrides[get_gateway_user] = lambda: user
        try:
            r = client.get("/me")
            meta = r.json()["metadata"]
            assert "ttl" in meta
        finally:
            app.dependency_overrides.pop(get_gateway_user, None)

    def test_me_returns_roles(self):
        user = make_regular_user()
        app.dependency_overrides[get_gateway_user] = lambda: user
        try:
            r = client.get("/me")
            assert r.json()["data"]["roles"] == ["user"]
        finally:
            app.dependency_overrides.pop(get_gateway_user, None)


# ===========================================================================
# 7. /ADMIN
# ===========================================================================
class TestAdminRoute:
    def test_admin_requires_auth(self):
        r = client.get("/admin")
        assert r.status_code == 401

    def test_admin_requires_admin_role(self):
        user = make_regular_user()
        app.dependency_overrides[get_gateway_user] = lambda: user
        try:
            r = client.get("/admin")
            assert r.status_code == 403
        finally:
            app.dependency_overrides.pop(get_gateway_user, None)

    def test_admin_grants_access_with_admin_role(self):
        user = make_admin_user()
        app.dependency_overrides[get_gateway_user] = lambda: user
        try:
            r = client.get("/admin")
            assert r.status_code == 200
            assert "Admin access granted" in r.json()["message"]
        finally:
            app.dependency_overrides.pop(get_gateway_user, None)


# ===========================================================================
# 8. /REFRESH
# ===========================================================================
class TestRefreshToken:
    def _csrf_headers(self, token="csrf123"):
        return {"X-CSRF-Token": token}

    def test_refresh_missing_csrf_header_returns_403(self):
        r = client.post(
            "/refresh", cookies={"csrf_token": "csrf123", "refresh_token": "rt"}
        )
        assert r.status_code == 403

    def test_refresh_missing_csrf_cookie_returns_403(self):
        r = client.post(
            "/refresh",
            headers={"X-CSRF-Token": "csrf123"},
            cookies={"refresh_token": "rt"},
        )
        assert r.status_code == 403

    def test_refresh_csrf_mismatch_returns_403(self):
        r = client.post(
            "/refresh",
            headers={"X-CSRF-Token": "wrong"},
            cookies={"csrf_token": "correct", "refresh_token": "rt"},
        )
        assert r.status_code == 403

    def test_refresh_no_refresh_cookie_returns_401(self):
        r = client.post(
            "/refresh",
            headers=self._csrf_headers(),
            cookies={"csrf_token": "csrf123"},
        )
        assert r.status_code == 401

    @patch("app.api.routes.httpx.AsyncClient")
    def test_refresh_success_rotates_tokens(self, mock_http):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
        }
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
        mock_http.return_value = mock_client

        r = client.post(
            "/refresh",
            headers={"X-CSRF-Token": "csrf123"},
            cookies={"csrf_token": "csrf123", "refresh_token": "old-rt"},
        )
        assert r.status_code == 200
        assert r.json()["success"] is True
        assert "access_token" in r.cookies
        assert "csrf_token" in r.cookies

    @patch("app.api.routes.httpx.AsyncClient")
    def test_refresh_failure_clears_cookies(self, mock_http):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
        mock_http.return_value = mock_client

        r = client.post(
            "/refresh",
            headers={"X-CSRF-Token": "csrf123"},
            cookies={"csrf_token": "csrf123", "refresh_token": "expired-rt"},
        )
        assert r.status_code == 401
        assert r.cookies.get("access_token", "") == ""
        assert r.cookies.get("refresh_token", "") == ""


# ===========================================================================
# 9. ADMIN USER MANAGEMENT ROUTES
# ===========================================================================
class TestAdminUsers:
    def setup_method(self):
        app.dependency_overrides[get_gateway_user] = lambda: make_admin_user()

    def teardown_method(self):
        app.dependency_overrides.pop(get_gateway_user, None)

    @patch("app.api.routes.app_admin_service.get_all_users", new_callable=AsyncMock)
    def test_view_users_excludes_current_admin(self, mock_get):
        mock_get.return_value = [
            {"id": "admin-uuid", "username": "admin"},
            {"id": "other-uuid", "username": "other"},
        ]
        r = client.get("/admin/users")
        assert r.status_code == 200
        users = r.json()["data"]
        assert all(u["id"] != "admin-uuid" for u in users)

    @patch("app.api.routes.app_admin_service.get_all_users", new_callable=AsyncMock)
    def test_view_users_returns_wrapped_response(self, mock_get):
        mock_get.return_value = []
        r = client.get("/admin/users")
        assert r.json()["success"] is True
        assert "data" in r.json()

    @patch("app.api.routes.app_admin_service.bulk_create_users", new_callable=AsyncMock)
    def test_bulk_users_returns_wrapped_result(self, mock_bulk):
        mock_bulk.return_value = [{"username": "u1", "status": "created"}]
        r = client.post(
            "/admin/bulk-users", json=[{"username": "u1", "email": "u1@x.com"}]
        )
        assert r.status_code == 200
        assert r.json()["success"] is True

    @patch("app.api.routes.app_admin_service.delete_user", new_callable=AsyncMock)
    def test_delete_user_calls_service(self, mock_del):
        r = client.delete("/admin/users/some-user-id")
        assert r.status_code == 200
        mock_del.assert_awaited_once_with("some-user-id")

    @patch("app.api.routes.app_admin_service.assign_role", new_callable=AsyncMock)
    def test_assign_role_returns_200(self, mock_assign):
        r = client.post("/admin/users/uid123/roles?role_name=editor")
        assert r.status_code == 200
        mock_assign.assert_awaited_once()

    @patch("app.api.routes.app_admin_service.remove_role", new_callable=AsyncMock)
    def test_remove_role_returns_200(self, mock_remove):
        r = client.delete("/admin/users/uid123/roles?role_name=editor")
        assert r.status_code == 200
        mock_remove.assert_awaited_once()

    @patch("app.api.routes.app_admin_service.update_role", new_callable=AsyncMock)
    def test_update_role_returns_200(self, mock_update):
        r = client.put("/admin/users/uid123/roles?old_role=editor&new_role=admin")
        assert r.status_code == 200
        mock_update.assert_awaited_once()

    @patch("app.api.routes.app_admin_service.get_user_roles", new_callable=AsyncMock)
    def test_get_user_roles_returns_wrapped(self, mock_roles):
        mock_roles.return_value = [{"name": "user"}]
        r = client.get("/admin/users/uid123/roles")
        assert r.status_code == 200
        assert r.json()["data"] == [{"name": "user"}]

    def test_admin_routes_require_admin_role(self):
        app.dependency_overrides[get_gateway_user] = lambda: make_regular_user()
        r = client.get("/admin/users")
        assert r.status_code == 403
        app.dependency_overrides[get_gateway_user] = lambda: make_admin_user()


# ===========================================================================
# 10. /INTROSPECT
# ===========================================================================
class TestIntrospect:
    @patch("app.api.routes.httpx.AsyncClient")
    def test_introspect_success(self, mock_http):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"active": True, "sub": "uid"}
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
        mock_http.return_value = mock_client

        r = client.post("/introspect?token=sometoken")
        assert r.status_code == 200
        assert r.json()["active"] is True

    @patch("app.api.routes.httpx.AsyncClient")
    def test_introspect_keycloak_error_returns_500(self, mock_http):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)
        mock_http.return_value = mock_client

        r = client.post("/introspect?token=bad")
        assert r.status_code == 500


# ===========================================================================
# 11. ACCOUNT / ADMIN CONSOLE REDIRECTS
# ===========================================================================
class TestConsoleRedirects:
    def test_account_redirect_requires_auth(self):
        r = client.get("/account", follow_redirects=False)
        assert r.status_code == 401

    def test_account_redirect_for_auth_user(self):
        app.dependency_overrides[get_gateway_user] = lambda: make_regular_user()
        try:
            r = client.get("/account", follow_redirects=False)
            assert r.status_code in (302, 307)
            assert "account" in r.headers.get("location", "")
        finally:
            app.dependency_overrides.pop(get_gateway_user, None)

    def test_admin_console_requires_admin_role(self):
        app.dependency_overrides[get_gateway_user] = lambda: make_regular_user()
        try:
            r = client.get("/admin/console", follow_redirects=False)
            assert r.status_code == 403
        finally:
            app.dependency_overrides.pop(get_gateway_user, None)

    def test_admin_console_redirects_for_admin(self):
        app.dependency_overrides[get_gateway_user] = lambda: make_admin_user()
        try:
            r = client.get("/admin/console", follow_redirects=False)
            assert r.status_code in (302, 307)
            assert "console" in r.headers.get("location", "")
        finally:
            app.dependency_overrides.pop(get_gateway_user, None)
