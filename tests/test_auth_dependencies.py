"""
Tests for authentication dependencies.
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch
from fastapi import HTTPException, Request
from app.auth.dependencies import (
    get_gateway_user,
    require_auth,
    require_role,
)


class TestGetGatewayUser:
    """Tests for get_gateway_user function."""
    
    @pytest.mark.asyncio
    async def test_get_gateway_user_returns_none_without_user_id_header(self):
        """Test that None is returned when X-User-ID header is missing."""
        request = Mock(spec=Request)
        request.headers = {}
        
        result = await get_gateway_user(request)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_gateway_user_extracts_basic_user_info(self):
        """Test extraction of basic user information from headers."""
        request = Mock(spec=Request)
        request.headers = {
            "X-User-ID": "user123",
            "X-User-Email": "user@example.com",
            "X-User-Preferred-Username": "testuser",
            "X-User-Roles": '["user", "admin"]'
        }
        
        result = await get_gateway_user(request)
        
        assert result is not None
        assert result["sub"] == "user123"
        assert result["email"] == "user@example.com"
        assert result["preferred_username"] == "testuser"
        assert result["roles"] == ["user", "admin"]
    
    @pytest.mark.asyncio
    async def test_get_gateway_user_handles_malformed_roles_json(self):
        """Test that malformed roles JSON falls back to empty list."""
        request = Mock(spec=Request)
        request.headers = {
            "X-User-ID": "user123",
            "X-User-Roles": "malformed-json"
        }
        
        result = await get_gateway_user(request)
        
        assert result is not None
        assert result["sub"] == "user123"
        assert result["roles"] == []
    
    @pytest.mark.asyncio
    async def test_get_gateway_user_parses_token_expiry(self):
        """Test that token expiry is parsed from header."""
        request = Mock(spec=Request)
        request.headers = {
            "X-User-ID": "user123",
            "X-Token-Exp": "1234567890"
        }
        
        result = await get_gateway_user(request)
        
        assert result is not None
        assert result["exp"] == 1234567890
    
    @pytest.mark.asyncio
    async def test_get_gateway_user_handles_invalid_token_expiry(self):
        """Test that invalid token expiry is handled gracefully."""
        request = Mock(spec=Request)
        request.headers = {
            "X-User-ID": "user123",
            "X-Token-Exp": "not-a-number"
        }
        
        result = await get_gateway_user(request)
        
        assert result is not None
        assert result["exp"] is None
    
    @pytest.mark.asyncio
    async def test_get_gateway_user_returns_empty_roles_when_header_missing(self):
        """Test default behavior when X-User-Roles header is missing."""
        request = Mock(spec=Request)
        request.headers = {
            "X-User-ID": "user123"
        }
        
        result = await get_gateway_user(request)
        
        assert result is not None
        assert result["roles"] == []
    
    @pytest.mark.asyncio
    async def test_get_gateway_user_with_all_optional_headers(self):
        """Test with all possible headers provided."""
        request = Mock(spec=Request)
        request.headers = {
            "X-User-ID": "user456",
            "X-User-Email": "user456@example.com",
            "X-User-Preferred-Username": "testuser456",
            "X-User-Roles": '["admin", "moderator"]',
            "X-Token-Exp": "9999999999"
        }
        
        result = await get_gateway_user(request)
        
        assert result["sub"] == "user456"
        assert result["email"] == "user456@example.com"
        assert result["preferred_username"] == "testuser456"
        assert result["roles"] == ["admin", "moderator"]
        assert result["exp"] == 9999999999


class TestRequireAuth:
    """Tests for require_auth dependency."""
    
    @pytest.mark.asyncio
    async def test_require_auth_succeeds_with_valid_user(self):
        """Test that require_auth succeeds when user is provided."""
        valid_user = {
            "sub": "user123",
            "email": "user@example.com",
            "roles": ["user"]
        }
        
        result = await require_auth(valid_user)
        
        assert result == valid_user
    
    @pytest.mark.asyncio
    async def test_require_auth_raises_401_when_user_is_none(self):
        """Test that require_auth raises 401 Unauthorized when user is None."""
        with pytest.raises(HTTPException) as exc_info:
            await require_auth(None)
        
        assert exc_info.value.status_code == 401
        assert "Not authenticated" in exc_info.value.detail


class TestRequireRole:
    """Tests for require_role dependency."""
    
    def test_require_role_succeeds_when_user_has_role(self):
        """Test that user with required role is allowed."""
        user = {
            "sub": "user123",
            "roles": ["admin", "user"]
        }
        
        checker = require_role("admin")
        result = checker(user)
        
        assert result == user
    
    def test_require_role_raises_403_when_user_lacks_role(self):
        """Test that user without required role gets 403 Forbidden."""
        user = {
            "sub": "user123",
            "roles": ["user"]  # No admin role
        }
        
        checker = require_role("admin")
        
        with pytest.raises(HTTPException) as exc_info:
            checker(user)
        
        assert exc_info.value.status_code == 403
        assert "admin" in exc_info.value.detail
        assert "Forbidden" in exc_info.value.detail
    
    def test_require_role_with_empty_roles_list(self):
        """Test that user with empty roles list cannot access protected resource."""
        user = {
            "sub": "user123",
            "roles": []
        }
        
        checker = require_role("admin")
        
        with pytest.raises(HTTPException) as exc_info:
            checker(user)
        
        assert exc_info.value.status_code == 403
    
    def test_require_role_with_multiple_roles(self):
        """Test role checking with multiple required checks."""
        user = {
            "sub": "user123",
            "roles": ["editor", "moderator", "user"]
        }
        
        # User has editor role
        checker1 = require_role("editor")
        result1 = checker1(user)
        assert result1 == user
        
        # User lacks admin role
        checker2 = require_role("admin")
        with pytest.raises(HTTPException) as exc_info:
            checker2(user)
        assert exc_info.value.status_code == 403
    
    def test_require_role_case_sensitive(self):
        """Test that role names are case-sensitive."""
        user = {
            "sub": "user123",
            "roles": ["Admin"]  # uppercase A
        }
        
        # Checking for lowercase "admin"
        checker = require_role("admin")
        
        with pytest.raises(HTTPException) as exc_info:
            checker(user)
        
        assert exc_info.value.status_code == 403
    
    def test_require_role_with_none_roles_list(self):
        """Test behavior when roles is None instead of list."""
        user = {
            "sub": "user123",
            "roles": None
        }
        
        checker = require_role("admin")
        
        # roles could be None or empty
        with pytest.raises((TypeError, AttributeError, HTTPException)):
            checker(user)


class TestAuthDependenciesIntegration:
    """Integration tests for auth dependencies."""
    
    @pytest.mark.asyncio
    async def test_gateway_user_to_require_auth_flow(self):
        """Test complete flow from gateway user extraction to auth requirement."""
        # Simulate gateway providing user
        request = Mock(spec=Request)
        request.headers = {
            "X-User-ID": "user123",
            "X-User-Email": "user@example.com",
            "X-User-Roles": '["user"]'
        }
        
        # Extract user
        user = await get_gateway_user(request)
        
        # Then require auth
        result = await require_auth(user)
        
        assert result is not None
        assert result["sub"] == "user123"
    
    def test_admin_endpoint_flow(self):
        """Test complete flow for admin endpoint."""
        user = {
            "sub": "admin123",
            "roles": ["admin"]
        }
        
        # Require role check
        checker = require_role("admin")
        final_result = checker(user)
        
        assert final_result["sub"] == "admin123"
        assert "admin" in final_result["roles"]
