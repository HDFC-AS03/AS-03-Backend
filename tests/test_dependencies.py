# tests/test_dependencies.py
import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from fastapi.testclient import TestClient
from fastapi import FastAPI, Depends, Request

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

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
os.environ.setdefault("JWKS_URL", "http://k:8080/certs")
os.environ.setdefault("JWT_ISSUER_1", "http://k:8080/realms/r")
os.environ.setdefault("JWT_ISSUER_2", "http://localhost:8080/realms/r")
os.environ.setdefault("JWKS_CACHE_TTL", "300")

from app.auth.dependencies import get_gateway_user, require_auth, require_role


# ===========================================================================
# get_gateway_user
# ===========================================================================

class TestGetGatewayUser:
    """Unit tests for the get_gateway_user dependency."""

    @pytest.mark.asyncio
    async def test_returns_none_without_user_id_header(self):
        request = MagicMock(spec=Request)
        request.headers = {}
        request.cookies = {}
        result = await get_gateway_user(request)
        assert result is None

    @pytest.mark.asyncio
    async def test_parses_user_id_from_header(self):
        request = MagicMock(spec=Request)
        request.headers = {
            "X-User-ID": "uid-123",
            "X-User-Email": "u@test.com",
            "X-User-Preferred-Username": "user123",
            "X-User-Roles": '["user"]',
        }
        result = await get_gateway_user(request)
        assert result["sub"] == "uid-123"
        assert result["email"] == "u@test.com"
        assert result["preferred_username"] == "user123"
        assert result["roles"] == ["user"]

    @pytest.mark.asyncio
    async def test_parses_roles_from_header(self):
        request = MagicMock(spec=Request)
        request.headers = {
            "X-User-ID": "uid-456",
            "X-User-Roles": '["admin","user"]',
        }
        result = await get_gateway_user(request)
        assert "admin" in result["roles"]
        assert "user" in result["roles"]

    @pytest.mark.asyncio
    async def test_defaults_to_empty_roles_on_bad_json(self):
        request = MagicMock(spec=Request)
        request.headers = {
            "X-User-ID": "uid-789",
            "X-User-Roles": "not-valid-json",
        }
        result = await get_gateway_user(request)
        assert result["roles"] == []

    @pytest.mark.asyncio
    async def test_parses_exp_from_header(self):
        request = MagicMock(spec=Request)
        request.headers = {
            "X-User-ID": "uid-000",
            "X-Token-Exp": "9999999999",
        }
        result = await get_gateway_user(request)
        assert result["exp"] == 9999999999

    @pytest.mark.asyncio
    async def test_exp_none_on_invalid_header(self):
        request = MagicMock(spec=Request)
        request.headers = {
            "X-User-ID": "uid-000",
            "X-Token-Exp": "not-a-number",
        }
        result = await get_gateway_user(request)
        assert result["exp"] is None

    @pytest.mark.asyncio
    async def test_missing_roles_header_defaults_to_empty(self):
        request = MagicMock(spec=Request)
        request.headers = {"X-User-ID": "uid-111"}
        result = await get_gateway_user(request)
        assert result["roles"] == []


# ===========================================================================
# require_auth
# ===========================================================================

class TestRequireAuth:
    @pytest.mark.asyncio
    async def test_raises_401_when_user_is_none(self):
        with pytest.raises(HTTPException) as exc_info:
            await require_auth(None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_returns_user_when_present(self):
        user = {"sub": "uid", "roles": ["user"]}
        result = await require_auth(user)
        assert result == user


# ===========================================================================
# require_role
# ===========================================================================

class TestRequireRole:
    def _make_checker(self, role: str):
        """Create a synchronous checker for unit-testing the closure."""
        return require_role(role)

    def test_allows_user_with_required_role(self):
        checker = require_role("admin")
        user = {"sub": "uid", "roles": ["admin", "user"]}
        result = checker.__wrapped__(user) if hasattr(checker, "__wrapped__") else None
        # Use the inner function directly
        inner = checker.__closure__[0].cell_contents if checker.__closure__ else None
        # Simulate dependency execution
        try:
            # Access the inner checker function via inspect
            import inspect
            src = inspect.getsource(require_role)
            assert "checker" in src
        except Exception:
            pass
        # Direct call simulation
        result = _call_checker("admin", {"sub": "uid", "roles": ["admin"]})
        assert result["sub"] == "uid"

    def test_raises_403_when_role_missing(self):
        with pytest.raises(HTTPException) as exc_info:
            _call_checker("admin", {"sub": "uid", "roles": ["user"]})
        assert exc_info.value.status_code == 403

    def test_raises_403_when_roles_empty(self):
        with pytest.raises(HTTPException) as exc_info:
            _call_checker("admin", {"sub": "uid", "roles": []})
        assert exc_info.value.status_code == 403

    def test_error_detail_contains_role_name(self):
        with pytest.raises(HTTPException) as exc_info:
            _call_checker("superuser", {"sub": "uid", "roles": []})
        assert "superuser" in exc_info.value.detail


def _call_checker(role: str, user: dict):
    """Helper: execute require_role inner checker synchronously."""
    checker_factory = require_role(role)
    # The inner function is `checker(user)` — call it directly
    import inspect
    for cell in (checker_factory.__closure__ or []):
        try:
            val = cell.cell_contents
            if val == role:
                continue
        except ValueError:
            pass
    # Build a minimal FastAPI app to test the dependency end-to-end
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    mini = FastAPI()

    @mini.get("/protected")
    def protected_route(u: dict = Depends(require_role(role))):
        return u

    from app.auth.dependencies import get_gateway_user
    mini.dependency_overrides[get_gateway_user] = lambda: user

    tc = TestClient(mini, raise_server_exceptions=False)
    r = tc.get("/protected")
    if r.status_code == 403:
        raise HTTPException(status_code=403, detail=r.json().get("detail", ""))
    return r.json()


# ===========================================================================
# tests/test_response_wrapper.py   (inline, same file for simplicity)
# ===========================================================================

from app.core.response_wrapper import wrap_response
from datetime import datetime, timezone


class TestWrapResponse:
    def test_success_true_by_default(self):
        result = wrap_response({"key": "val"})
        assert result["success"] is True

    def test_message_included(self):
        result = wrap_response({}, message="Done")
        assert result["message"] == "Done"

    def test_data_preserved(self):
        data = [1, 2, 3]
        result = wrap_response(data)
        assert result["data"] == data

    def test_metadata_has_timestamp(self):
        result = wrap_response({})
        assert "timestamp" in result["metadata"]
        # Verify it is a valid ISO-format string
        ts = result["metadata"]["timestamp"]
        datetime.fromisoformat(ts.replace("Z", "+00:00"))

    def test_metadata_has_version(self):
        result = wrap_response({}, version="2.0")
        assert result["metadata"]["version"] == "2.0"

    def test_ttl_absent_when_not_provided(self):
        result = wrap_response({})
        assert "ttl" not in result["metadata"]

    def test_ttl_present_when_provided(self):
        result = wrap_response({}, ttl=60)
        assert "ttl" in result["metadata"]
        assert result["metadata"]["ttl"]["value"] == 60
        assert result["metadata"]["ttl"]["unit"] == "seconds"

    def test_ttl_expires_at_is_future(self):
        result = wrap_response({}, ttl=3600)
        expires_str = result["metadata"]["ttl"]["expires_at"]
        expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
        assert expires > datetime.now(timezone.utc)

    def test_success_false_passthrough(self):
        result = wrap_response({}, success=False)
        assert result["success"] is False

    def test_default_version_is_1_0(self):
        result = wrap_response({})
        assert result["metadata"]["version"] == "1.0"

    def test_none_data_is_preserved(self):
        result = wrap_response(None)
        assert result["data"] is None

    def test_nested_data_preserved(self):
        data = {"user": {"id": 1, "roles": ["admin"]}}
        result = wrap_response(data)
        assert result["data"]["user"]["roles"] == ["admin"]


# ===========================================================================
# tests/test_admin_services.py  (inline)
# ===========================================================================

from app.services import app_admin_service


class TestBulkCreateUsers:
    @pytest.mark.asyncio
    @patch("app.services.app_admin_service.get_admin_token", new_callable=AsyncMock)
    @patch("app.services.app_admin_service.httpx.AsyncClient")
    async def test_bulk_create_success(self, mock_http, mock_token):
        mock_token.return_value = "admin-token"

        create_resp = MagicMock()
        create_resp.status_code = 201
        create_resp.headers = {"Location": "http://kc/users/new-user-id"}
        create_resp.raise_for_status = MagicMock()

        role_resp = MagicMock()
        role_resp.status_code = 200
        role_resp.json.return_value = {"id": "role-id", "name": "user"}
        role_resp.raise_for_status = MagicMock()

        assign_resp = MagicMock()
        assign_resp.status_code = 204
        assign_resp.raise_for_status = MagicMock()

        email_resp = MagicMock()
        email_resp.status_code = 200
        email_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[create_resp, assign_resp])
        mock_client.get = AsyncMock(return_value=role_resp)
        mock_client.put = AsyncMock(return_value=email_resp)
        mock_http.return_value.__aenter__.return_value = mock_client

        result = await app_admin_service.bulk_create_users(
            [{"username": "newuser", "email": "new@test.com", "role": "user"}]
        )
        assert result[0]["status"] == "created"

    @pytest.mark.asyncio
    @patch("app.services.app_admin_service.get_admin_token", new_callable=AsyncMock)
    @patch("app.services.app_admin_service.httpx.AsyncClient")
    async def test_bulk_create_handles_conflict(self, mock_http, mock_token):
        mock_token.return_value = "admin-token"

        conflict_resp = MagicMock()
        conflict_resp.status_code = 409

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=conflict_resp)
        mock_http.return_value.__aenter__.return_value = mock_client

        result = await app_admin_service.bulk_create_users(
            [{"username": "existing", "email": "e@test.com"}]
        )
        assert result[0]["status"] == "failed"
        assert "already exists" in result[0]["error"]


class TestDeleteUser:
    @pytest.mark.asyncio
    @patch("app.services.app_admin_service.get_admin_token", new_callable=AsyncMock)
    @patch("app.services.app_admin_service.httpx.AsyncClient")
    async def test_delete_user_calls_correct_endpoint(self, mock_http, mock_token):
        mock_token.return_value = "admin-token"
        del_resp = MagicMock()
        del_resp.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.delete = AsyncMock(return_value=del_resp)
        mock_http.return_value.__aenter__.return_value = mock_client

        await app_admin_service.delete_user("user-id-123")
        mock_client.delete.assert_awaited_once()
        call_url = mock_client.delete.call_args[0][0]
        assert "user-id-123" in call_url


class TestGetAllUsers:
    @pytest.mark.asyncio
    @patch("app.services.app_admin_service.get_admin_token", new_callable=AsyncMock)
    @patch("app.services.app_admin_service.httpx.AsyncClient")
    async def test_excludes_service_accounts(self, mock_http, mock_token):
        mock_token.return_value = "admin-token"
        users_resp = MagicMock()
        users_resp.json.return_value = [
            {"id": "u1", "username": "human"},
            {"id": "sa1", "username": "svc", "serviceAccountClientId": "some-client"},
        ]
        users_resp.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=users_resp)
        mock_http.return_value.__aenter__.return_value = mock_client

        result = await app_admin_service.get_all_users()
        assert len(result) == 1
        assert result[0]["username"] == "human"


class TestAssignRole:
    @pytest.mark.asyncio
    @patch("app.services.app_admin_service.get_admin_token", new_callable=AsyncMock)
    @patch("app.services.app_admin_service.httpx.AsyncClient")
    async def test_assign_role_posts_role_mapping(self, mock_http, mock_token):
        mock_token.return_value = "admin-token"
        role_resp = MagicMock()
        role_resp.json.return_value = {"id": "rid", "name": "editor"}
        role_resp.raise_for_status = MagicMock()
        assign_resp = MagicMock()
        assign_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=role_resp)
        mock_client.post = AsyncMock(return_value=assign_resp)
        mock_http.return_value.__aenter__.return_value = mock_client

        await app_admin_service.assign_role("uid", "editor")
        mock_client.post.assert_awaited_once()
        call_url = mock_client.post.call_args[0][0]
        assert "uid" in call_url
        assert "role-mappings/realm" in call_url


class TestUpdateRole:
    @pytest.mark.asyncio
    @patch("app.services.app_admin_service.assign_role", new_callable=AsyncMock)
    @patch("app.services.app_admin_service.remove_role", new_callable=AsyncMock)
    async def test_update_role_removes_then_assigns(self, mock_remove, mock_assign):
        await app_admin_service.update_role("uid", "old", "new")
        mock_remove.assert_awaited_once_with("uid", "old")
        mock_assign.assert_awaited_once_with("uid", "new")


class TestGetUserRoles:
    @pytest.mark.asyncio
    @patch("app.services.app_admin_service.get_admin_token", new_callable=AsyncMock)
    @patch("app.services.app_admin_service.httpx.AsyncClient")
    async def test_returns_role_list(self, mock_http, mock_token):
        mock_token.return_value = "admin-token"
        roles_resp = MagicMock()
        roles_resp.json.return_value = [{"name": "user"}, {"name": "editor"}]
        roles_resp.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=roles_resp)
        mock_http.return_value.__aenter__.return_value = mock_client

        result = await app_admin_service.get_user_roles("uid")
        assert len(result) == 2
        assert result[0]["name"] == "user"


# ===========================================================================
# tests/test_csrf.py  (inline)
# ===========================================================================

from app.api.routes import generate_csrf_token, validate_csrf


class TestGenerateCsrfToken:
    def test_generates_string(self):
        token = generate_csrf_token()
        assert isinstance(token, str)

    def test_token_min_length(self):
        token = generate_csrf_token()
        assert len(token) >= 32

    def test_tokens_are_unique(self):
        tokens = {generate_csrf_token() for _ in range(10)}
        assert len(tokens) == 10


class TestValidateCsrf:
    @pytest.mark.asyncio
    async def test_raises_403_missing_cookie(self):
        request = MagicMock(spec=Request)
        request.cookies = {}
        with pytest.raises(HTTPException) as exc:
            await validate_csrf(request, x_csrf_token="token")
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_raises_403_missing_header(self):
        request = MagicMock(spec=Request)
        request.cookies = {"csrf_token": "token"}
        with pytest.raises(HTTPException) as exc:
            await validate_csrf(request, x_csrf_token=None)
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_raises_403_on_mismatch(self):
        request = MagicMock(spec=Request)
        request.cookies = {"csrf_token": "correct"}
        with pytest.raises(HTTPException) as exc:
            await validate_csrf(request, x_csrf_token="wrong")
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_returns_true_on_match(self):
        request = MagicMock(spec=Request)
        request.cookies = {"csrf_token": "match"}
        result = await validate_csrf(request, x_csrf_token="match")
        assert result is True