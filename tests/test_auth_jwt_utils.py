import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from jose import JWTError
from app.auth.jwt_utils import validate_bearer_token, _fetch_jwks
from app.core.config import settings


class TestFetchJwks:
    @pytest.mark.asyncio
    async def test_fetch_jwks_returns_cached_jwks(self):
        """Test that JWKS is returned from cache when available"""
        cached_jwks = {"keys": [{"kid": "key1"}]}
        
        with patch("app.auth.jwt_utils._jwks_cache", {"jwks": cached_jwks}):
            result = await _fetch_jwks()
            
            assert result == cached_jwks

    @pytest.mark.asyncio
    async def test_fetch_jwks_fetches_from_keycloak_when_not_cached(self):
        """Test that JWKS is fetched from Keycloak when not in cache"""
        mock_jwks = {"keys": [{"kid": "key1", "kty": "RSA"}]}
        
        with patch("app.auth.jwt_utils._jwks_cache", {}):
            with patch("app.auth.jwt_utils.httpx.AsyncClient") as mock_client_class:
                mock_response = MagicMock()
                mock_response.json.return_value = mock_jwks
                mock_client = MagicMock()
                mock_client.__aenter__.return_value = mock_client
                mock_client.__aexit__.return_value = None
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client_class.return_value = mock_client
                
                result = await _fetch_jwks()
                
                assert result == mock_jwks
                mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_jwks_raises_on_network_error(self):
        """Test that network errors are propagated"""
        with patch("app.auth.jwt_utils._jwks_cache", {}):
            with patch("app.auth.jwt_utils.httpx.AsyncClient") as mock_client_class:
                mock_client = MagicMock()
                mock_client.__aenter__.return_value = mock_client
                mock_client.__aexit__.return_value = None
                mock_client.get = AsyncMock(side_effect=Exception("Network error"))
                mock_client_class.return_value = mock_client
                
                with pytest.raises(Exception) as exc_info:
                    await _fetch_jwks()
                
                assert "Network error" in str(exc_info.value)


class TestValidateBearerToken:
    @pytest.mark.asyncio
    async def test_validate_bearer_token_returns_claims_for_valid_token(self):
        """Test that claims are returned for valid token"""
        mock_token = "valid.jwt.token"
        mock_claims = {
            "sub": "user123",
            "email": "user@example.com",
            "iat": 1234567890,
            "exp": 9999999999,
        }
        mock_jwks = {"keys": []}
        
        with patch("app.auth.jwt_utils._fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_jwks
            with patch("app.auth.jwt_utils.jwt.decode") as mock_decode:
                mock_decode.return_value = mock_claims
                
                result = await validate_bearer_token(mock_token)
                
                assert result == mock_claims
                mock_decode.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_bearer_token_with_audience(self):
        """Test that audience validation is enabled when provided"""
        mock_token = "valid.jwt.token"
        mock_claims = {"sub": "user123", "aud": "my-client"}
        mock_jwks = {"keys": []}
        
        with patch("app.auth.jwt_utils._fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_jwks
            with patch("app.auth.jwt_utils.jwt.decode") as mock_decode:
                mock_decode.return_value = mock_claims
                
                result = await validate_bearer_token(mock_token, audience="my-client")
                
                assert result == mock_claims
                call_kwargs = mock_decode.call_args[1]
                assert call_kwargs["options"]["verify_aud"] is True

    @pytest.mark.asyncio
    async def test_validate_bearer_token_raises_on_jwt_error(self):
        """Test that ValueError is raised on JWT validation error"""
        mock_token = "invalid.jwt.token"
        mock_jwks = {"keys": []}
        
        with patch("app.auth.jwt_utils._fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_jwks
            with patch("app.auth.jwt_utils.jwt.decode") as mock_decode:
                mock_decode.side_effect = JWTError("Invalid signature")
                
                with pytest.raises(ValueError) as exc_info:
                    await validate_bearer_token(mock_token)
                
                assert "Invalid token" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_validate_bearer_token_raises_on_unexpected_error(self):
        """Test that ValueError is raised on unexpected error"""
        mock_token = "token"
        
        with patch("app.auth.jwt_utils._fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.side_effect = Exception("Network error")
            
            with pytest.raises(ValueError) as exc_info:
                await validate_bearer_token(mock_token)
            
            assert "Token validation failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_validate_bearer_token_sets_correct_issuer(self):
        """Test that issuer is set correctly from settings"""
        mock_token = "valid.jwt.token"
        mock_claims = {"sub": "user123"}
        mock_jwks = {"keys": []}
        
        with patch("app.auth.jwt_utils._fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_jwks
            with patch("app.auth.jwt_utils.jwt.decode") as mock_decode:
                mock_decode.return_value = mock_claims
                
                await validate_bearer_token(mock_token)
                
                call_kwargs = mock_decode.call_args[1]
                expected_issuer = f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}"
                assert call_kwargs["issuer"] == expected_issuer
