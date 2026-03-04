import pytest
from unittest.mock import Mock, AsyncMock, patch
from fastapi import HTTPException, Request
from app.auth.dependencies import (
    get_session_user,
    get_bearer_user,
    require_auth,
    require_role,
)


class TestGetSessionUser:
    def test_get_session_user_returns_user_from_session(self):
        """Test that session user is retrieved from request.session"""
        request = Mock(spec=Request)
        request.session = {"user": {"id": "123", "name": "John"}}
        
        result = get_session_user(request)
        
        assert result == {"id": "123", "name": "John"}

    def test_get_session_user_returns_none_when_no_user(self):
        """Test that None is returned when no user in session"""
        request = Mock(spec=Request)
        request.session = {}
        
        result = get_session_user(request)
        
        assert result is None


class TestGetBearerUser:
    @pytest.mark.asyncio
    async def test_get_bearer_user_returns_none_without_auth_header(self):
        """Test that None is returned when no Authorization header"""
        request = Mock(spec=Request)
        request.headers = {}
        
        result = await get_bearer_user(request)
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_bearer_user_returns_none_with_invalid_auth_header(self):
        """Test that None is returned with non-Bearer auth header"""
        request = Mock(spec=Request)
        request.headers = {"Authorization": "Basic xyz"}
        
        result = await get_bearer_user(request)
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_bearer_user_returns_none_with_malformed_bearer_header(self):
        """Test that None is returned with malformed Bearer header"""
        request = Mock(spec=Request)
        request.headers = {"Authorization": "Bearer"}
        
        with patch("app.auth.dependencies.validate_bearer_token", new_callable=AsyncMock) as mock_validate:
            mock_validate.side_effect = ValueError("Invalid token")
            
            result = await get_bearer_user(request)
            
            assert result is None

    @pytest.mark.asyncio
    async def test_get_bearer_user_extracts_claims_from_valid_token(self):
        """Test that bearer user is extracted from valid token"""
        request = Mock(spec=Request)
        request.headers = {"Authorization": "Bearer valid_token"}
        
        mock_claims = {
            "sub": "user123",
            "email": "user@example.com",
            "preferred_username": "john",
            "name": "John Doe",
            "realm_access": {"roles": ["admin", "user"]},
        }
        
        with patch("app.auth.dependencies.validate_bearer_token", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_claims
            
            result = await get_bearer_user(request)
            
            assert result["sub"] == "user123"
            assert result["email"] == "user@example.com"
            assert result["preferred_username"] == "john"
            assert result["name"] == "John Doe"
            assert result["roles"] == ["admin", "user"]
            assert result["claims"] == mock_claims

    @pytest.mark.asyncio
    async def test_get_bearer_user_returns_none_on_invalid_token(self):
        """Test that None is returned when token validation fails"""
        request = Mock(spec=Request)
        request.headers = {"Authorization": "Bearer invalid_token"}
        
        with patch("app.auth.dependencies.validate_bearer_token", new_callable=AsyncMock) as mock_validate:
            mock_validate.side_effect = ValueError("Invalid token")
            
            result = await get_bearer_user(request)
            
            assert result is None

    @pytest.mark.asyncio
    async def test_get_bearer_user_handles_missing_realm_access(self):
        """Test that missing realm_access is handled gracefully"""
        request = Mock(spec=Request)
        request.headers = {"Authorization": "Bearer token"}
        
        mock_claims = {
            "sub": "user123",
            "email": "user@example.com",
        }
        
        with patch("app.auth.dependencies.validate_bearer_token", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_claims
            
            result = await get_bearer_user(request)
            
            assert result["roles"] == []

    @pytest.mark.asyncio
    async def test_get_bearer_user_case_insensitive_bearer_prefix(self):
        """Test that Bearer prefix is case-insensitive"""
        request = Mock(spec=Request)
        request.headers = {"Authorization": "bearer valid_token"}
        
        mock_claims = {"sub": "user123", "realm_access": {"roles": []}}
        
        with patch("app.auth.dependencies.validate_bearer_token", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_claims
            
            result = await get_bearer_user(request)
            
            assert result is not None
            assert result["sub"] == "user123"


class TestRequireAuth:
    @pytest.mark.asyncio
    async def test_require_auth_returns_session_user_when_available(self):
        """Test that session user is returned when available"""
        session_user = {"id": "123", "name": "John"}
        bearer_user = None
        
        result = await require_auth(session_user, bearer_user)
        
        assert result == session_user

    @pytest.mark.asyncio
    async def test_require_auth_returns_bearer_user_when_session_unavailable(self):
        """Test that bearer user is returned when session user is None"""
        session_user = None
        bearer_user = {"id": "456", "name": "Jane"}
        
        result = await require_auth(session_user, bearer_user)
        
        assert result == bearer_user

    @pytest.mark.asyncio
    async def test_require_auth_raises_401_when_no_user(self):
        """Test that 401 is raised when neither session nor bearer user exists"""
        session_user = None
        bearer_user = None
        
        with pytest.raises(HTTPException) as exc_info:
            await require_auth(session_user, bearer_user)
        
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Not authenticated"


class TestRequireRole:
    def test_require_role_allows_user_with_realm_role(self):
        """Test that user with required realm role is allowed"""
        user = {
            "id": "123",
            "roles": ["admin", "user"],
            "claims": {},
        }
        
        checker = require_role("admin")
        result = checker(user)
        
        assert result == user

    def test_require_role_allows_user_with_client_role(self):
        """Test that user with required client role is allowed"""
        user = {
            "id": "123",
            "roles": [],
            "claims": {
                "resource_access": {
                    "my-client": {"roles": ["admin"]},
                }
            },
        }
        
        checker = require_role("admin")
        result = checker(user)
        
        assert result == user

    def test_require_role_denies_user_without_role(self):
        """Test that user without required role is denied"""
        user = {
            "id": "123",
            "preferred_username": "john",
            "roles": ["user"],
            "claims": {},
        }
        
        checker = require_role("admin")
        
        with pytest.raises(HTTPException) as exc_info:
            checker(user)
        
        assert exc_info.value.status_code == 403
        assert "admin" in exc_info.value.detail

    def test_require_role_combines_realm_and_client_roles(self):
        """Test that both realm and client roles are checked"""
        user = {
            "id": "123",
            "roles": ["user"],
            "claims": {
                "resource_access": {
                    "my-client": {"roles": ["admin"]},
                }
            },
        }
        
        checker = require_role("admin")
        result = checker(user)
        
        assert result == user

    def test_require_role_handles_empty_resource_access(self):
        """Test that empty resource_access is handled gracefully"""
        user = {
            "id": "123",
            "roles": ["admin"],
            "claims": {"resource_access": {}},
        }
        
        checker = require_role("admin")
        result = checker(user)
        
        assert result == user

    def test_require_role_handles_multiple_client_roles(self):
        """Test that roles from multiple clients are combined"""
        user = {
            "id": "123",
            "roles": [],
            "claims": {
                "resource_access": {
                    "client1": {"roles": ["user"]},
                    "client2": {"roles": ["admin"]},
                }
            },
        }
        
        checker = require_role("admin")
        result = checker(user)
        
        assert result == user

    def test_require_role_handles_none_roles_in_user(self):
        """Test that None roles are handled gracefully"""
        user = {
            "id": "123",
            "roles": None,
            "claims": {},
        }
        
        checker = require_role("admin")
        
        with pytest.raises(HTTPException) as exc_info:
            checker(user)
        
        assert exc_info.value.status_code == 403
